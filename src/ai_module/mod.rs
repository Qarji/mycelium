use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::collections::{HashMap, VecDeque};
use serde_json;
use crate::node::{Mode, Node, NodeSignal, NeighborHistory};

#[derive(Debug, Serialize)]
pub struct AIInput {
    pub self_load: u8,
    pub self_temperature: i8,
    pub active_connections: u8,
    pub failed_auth_count: u8,
    pub last_sync_age_sec: u64,
    pub threat_score_history: VecDeque<f32>,

    pub neighbor_count: usize,
    pub neighbors_isolated: usize,
    pub neighbors_degraded: usize,
    pub neighbors_reconnecting: usize,
    pub neighbors_avg_load: f32,
    pub neighbors_max_threat: f32,
    pub neighbors_failed_auth_avg: f32,
    pub neighbors_avg_connections: f32,

    pub peer_suspicion_count: usize,

    pub ai_state_reason: String,
    pub time_in_state_sec: u64,
    pub previous_threat_score: f32,
}

impl AIInput {
    pub fn to_raw_metrics(&self) -> crate::persistence::RawMetrics {
        crate::persistence::RawMetrics {
            self_load: self.self_load,
            self_temperature: self.self_temperature,
            active_connections: self.active_connections,
            failed_auth_count: self.failed_auth_count,
            last_sync_age_sec: self.last_sync_age_sec,
            neighbor_count: self.neighbor_count,
            neighbors_isolated: self.neighbors_isolated,
            neighbors_degraded: self.neighbors_degraded,
            neighbors_reconnecting: self.neighbors_reconnecting,
            neighbors_avg_load: self.neighbors_avg_load,
            neighbors_max_threat: self.neighbors_max_threat,
            neighbors_failed_auth_avg: self.neighbors_failed_auth_avg,
            neighbors_avg_connections: self.neighbors_avg_connections,
            peer_suspicion_count: self.peer_suspicion_count,
            time_in_state_sec: self.time_in_state_sec,
            previous_threat_score: self.previous_threat_score,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AIOutput {
    pub threat_score: f32,
    pub predicted_state: String,
    pub recommended_action: String,
    pub event_reason: String,
    pub confidence: f32,
}

#[derive(Debug, Serialize)]
pub struct NeighborAIInput {
    pub load: u8,
    pub active_connections: u8,
    pub failed_auth_count: u8,
    pub threat_score: f32,
    pub mode: String,
    pub signal_type: String,

    pub ai_state_reason: String,
    pub signal_age_ticks: u64,
    pub time_in_mode_ticks: u64,

    pub load_delta: i16,
    pub failed_auth_delta: i16,
    pub active_connections_delta: i32,
    pub threat_score_delta: f32,
    pub mode_changed: bool,
    pub signals_seen_recent: u32,

    pub prior_suspicion_votes_against: u32,
    pub times_isolated_historically: u32,
    pub network_avg_load: f32,
    pub network_avg_failed_auth: f32,
}

#[derive(Debug, Deserialize)]
pub struct NeighborAIOutput {
    pub threat_score: f32,
}


pub struct AIFeatureBuilder;

impl AIFeatureBuilder {
    pub fn build(node: &Node, current_tick: u64) -> AIInput {
        let neighbor_count = node.neighbor_ids.len();

        let neighbors_isolated = node
            .neighbor_signals.values().flatten()
            .filter(|s| s.mode == Mode::Isolated)
            .count();

        let neighbors_degraded = node
            .neighbor_signals.values().flatten()
            .filter(|s| s.mode == Mode::Degraded)
            .count();

        let neighbors_reconnecting = node
            .neighbor_signals.values().flatten()
            .filter(|s| s.mode == Mode::Reconnecting)
            .count();

        let neighbors_avg_load = if !node.neighbor_signals.is_empty() {
            node.neighbor_signals.values().flatten().map(|s| s.load as f32).sum::<f32>()
                / node.neighbor_signals.len() as f32
        } else {
            0.0
        };

        let neighbors_avg_connections = if !node.neighbor_signals.is_empty() {
            node.neighbor_signals.values().flatten().map(|s| s.active_connections as f32).sum::<f32>()
                / node.neighbor_signals.len() as f32
        } else {
            0.0
        };

        let neighbors_max_threat = node
            .neighbor_signals.values().flatten()
            .map(|s| s.threat_score)
            .fold(0.0f32, f32::max);

        let neighbors_failed_auth_avg = if !node.neighbor_signals.is_empty() {
            node.neighbor_signals.values().flatten().map(|s| s.failed_auth_count as f32).sum::<f32>()
                / node.neighbor_signals.len() as f32
        } else {
            0.0
        };

        let peer_suspicion_count = node
            .neighbor_signals.values().flatten()
            .filter(|s| {
                use crate::node::SignalType;
                s.signal_type == SignalType::PeerSuspicion
                    && s.target_id == Some(node.id)
                    && s.timestamp == current_tick
            })
            .count();

        let last_sync_age_sec = current_tick.saturating_sub(node.state.last_sync_time);

        AIInput {
            self_load: node.state.load,
            self_temperature: node.state.temperature,
            active_connections: node.state.active_connections,
            failed_auth_count: node.state.failed_auth_count,
            last_sync_age_sec,
            threat_score_history: node.state.threat_score_history.clone(),

            neighbor_count,
            neighbors_isolated,
            neighbors_degraded,
            neighbors_reconnecting,
            neighbors_avg_load,
            neighbors_max_threat,
            neighbors_failed_auth_avg,
            neighbors_avg_connections,

            peer_suspicion_count,

            ai_state_reason: node.state.ai_state_reason.clone(),
            time_in_state_sec: current_tick.saturating_sub(node.state.state_entered_tick),
            previous_threat_score: node.state.last_threat_score,
        }
    }

    pub fn build_neighbour_signs(signal: &NodeSignal, current_tick: u64, history: &NeighborHistory, all_signals: &HashMap<u32, VecDeque<NodeSignal>>, stale_ttl: u64,) -> NeighborAIInput {
        let prev = history.last_signal.as_ref();

        let others: Vec<&NodeSignal> = all_signals.values().flatten()
            .filter(|s| {
                s.source_id != signal.source_id
                    && current_tick.saturating_sub(s.timestamp) <= stale_ttl
            })
            .collect();

        let (network_avg_load, network_avg_failed_auth) = if others.is_empty() {
            (signal.load as f32, signal.failed_auth_count as f32)
        } else {
            let n = others.len() as f32;
            (
                others.iter().map(|s| s.load as f32).sum::<f32>() / n,
                others.iter().map(|s| s.failed_auth_count as f32).sum::<f32>() / n,
            )
        };

        NeighborAIInput {
            load: signal.load,
            active_connections: signal.active_connections,
            failed_auth_count: signal.failed_auth_count,
            threat_score: signal.threat_score,
            mode: format!("{:?}", signal.mode),
            signal_type: format!("{:?}", signal.signal_type),

            ai_state_reason: signal.ai_state_reason.clone(),
            signal_age_ticks: current_tick.saturating_sub(signal.timestamp),
            time_in_mode_ticks: current_tick.saturating_sub(history.mode_entered_tick),

            load_delta: prev.map_or(0, |p| signal.load as i16 - p.load as i16),
            failed_auth_delta: prev.map_or(0, |p| signal.failed_auth_count as i16 - p.failed_auth_count as i16),
            active_connections_delta: prev.map_or(0, |p| signal.active_connections as i32 - p.active_connections as i32),
            threat_score_delta: prev.map_or(0.0, |p| signal.threat_score - p.threat_score),
            mode_changed: prev.map_or(false, |p| p.mode != signal.mode),
            signals_seen_recent: history.recent_timestamps.len() as u32,

            prior_suspicion_votes_against: history.suspicion_votes_cast,
            times_isolated_historically: history.times_isolated,

            network_avg_load,
            network_avg_failed_auth,
        }
    }
}

struct AiProcess {
    interpreter: PathBuf,
    path: PathBuf,
    process: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl AiProcess {
    /// `interpreter` — путь к python-исполняемому файлу (portable-дистрибутив
    /// рядом с exe в релизе, либо системный "python"/"python3" при разработке).
    /// `path` — путь к .py-скрипту, который будет выполнен этим интерпретатором.
    fn spawn(interpreter: PathBuf, path: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let mut process = Command::new(&interpreter)
            .arg(&path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| -> Box<dyn std::error::Error> {
                format!(
                    "Не удалось запустить Python-процесс (интерпретатор: {:?}, скрипт: {:?}): {}",
                    interpreter, path, e
                ).into()
            })?;

        let stdin = process.stdin.take().unwrap();
        let stdout = BufReader::new(process.stdout.take().unwrap());

        Ok(Self { interpreter, path, process, stdin, stdout })
    }

    /// Универсальный метод для отправки JSON и получения ответа
    fn ask(&mut self, line: &str) -> Result<String, Box<dyn std::error::Error>> {
        if let Err(_e) = writeln!(self.stdin, "{}", line) {
            self.restart()?;
            writeln!(self.stdin, "{}", line)?;
        }

        let mut response = String::new();
        let bytes_read = self.stdout.read_line(&mut response)?;

        if bytes_read == 0 {
            self.restart()?;
            return Err("Python AI process died unexpectedly, restarted".into());
        }

        Ok(response)
    }

    fn restart(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let _ = self.process.kill();
        let _ = self.process.wait();
        *self = Self::spawn(self.interpreter.clone(), self.path.clone())?;
        Ok(())
    }
}


pub struct AIModelPool {
    node_model: Mutex<AiProcess>,
    neighbor_model: Mutex<AiProcess>,
}

impl AIModelPool {
    /// `interpreter` — единый путь к Python-интерпретатору, используемый
    /// для запуска обоих скриптов (self-модель и neighbor-модель).
    pub fn new(interpreter: PathBuf, node_path: PathBuf, neighbor_path: PathBuf) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        Ok(Arc::new(Self {
            node_model: Mutex::new(AiProcess::spawn(interpreter.clone(), node_path)?),
            neighbor_model: Mutex::new(AiProcess::spawn(interpreter, neighbor_path)?),
        }))
    }

    /// запрос к self-модели 
    fn predict(&self, input: &AIInput) -> Result<AIOutput, Box<dyn std::error::Error>> {
        let line = serde_json::to_string(input)?;
        let mut guard = self.node_model.lock().map_err(|_| "node_model mutex poisoned")?;
        let response = guard.ask(&line)?;
        Ok(serde_json::from_str(response.trim())?)
    }

    /// запрос к neighbor-модели.
    fn evaluate_neighbor(&self, input: &NeighborAIInput) -> Result<f32, Box<dyn std::error::Error>> {
        let line = serde_json::to_string(input)?;
        let mut guard = self.neighbor_model.lock().map_err(|_| "neighbor_model mutex poisoned")?;
        let response = guard.ask(&line)?;
        let output: NeighborAIOutput = serde_json::from_str(response.trim())?;
        Ok(output.threat_score)
    }
}

#[derive(Clone)]
pub struct AIModel {
    pool: Arc<AIModelPool>,
    overridden: bool
}

impl AIModel {
    pub fn from_pool(pool: Arc<AIModelPool>) -> Self {
        Self { pool, overridden: false }
    }

    pub fn is_overridden(&self) -> bool { self.overridden }
    pub fn set_overridden(&mut self, value: bool) { self.overridden = value; }

    pub fn predict(&mut self, input: &AIInput) -> Result<AIOutput, Box<dyn std::error::Error>> {
        if self.overridden {
            return Err("AI process unresponsive (scenario override active)".into());
        }
        self.pool.predict(input)
    }

    pub fn evaluate_neighbor(&mut self, input: &NeighborAIInput) -> Result<f32, Box<dyn std::error::Error>> {
        self.pool.evaluate_neighbor(input)
    }
}

impl Drop for AiProcess {
    fn drop(&mut self) {
        let _ = self.process.kill();
    }
}
