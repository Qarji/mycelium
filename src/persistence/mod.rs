use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

// КАТЕГОРИЯ 1: ЖИЗНЕННЫЙ ЦИКЛ УЗЛА  [AI predict] - [Proposal] - [allowed] - [change]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum DecisionSource {
    AiPredict {
        predicted_state: String,
        threat_score: f32,
        confidence: f32,
    },
    AiError { error_reason: String },
    ForcedByPeerConsensus,
    HeuristicLoadAdvisory,
    HeuristicOverloadRedistribution,
    HeuristicIsolationRedistribution,
    DeterministicReconnectComplete,
    DeterministicReconnectTimeout,
    WaitingForReconnectAcks,
    CalibrationHold,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct StateSnapshot {
    pub mode: String,
    pub load: u8,
    pub active_connections: u8,
    pub failed_auth_count: u8,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct StateChange {
    pub mode: Option<(String, String)>, // (before, after)
    pub load: Option<(u8, u8)>,
    pub active_connections: Option<(u8, u8)>,
    pub failed_auth_count: Option<(u8, u8)>,
}

impl StateChange {
    pub fn diff(before: &StateSnapshot, after: &StateSnapshot) -> Self {
        Self {
            mode: (before.mode != after.mode).then(|| (before.mode.clone(), after.mode.clone())),
            load: (before.load != after.load).then_some((before.load, after.load)),
            active_connections: (before.active_connections != after.active_connections)
                .then_some((before.active_connections, after.active_connections)),
            failed_auth_count: (before.failed_auth_count != after.failed_auth_count)
                .then_some((before.failed_auth_count, after.failed_auth_count)),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.mode.is_none()
            && self.load.is_none()
            && self.active_connections.is_none()
            && self.failed_auth_count.is_none()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LifecycleEntry {
    pub tick: u64,
    pub node_id: u32,

    pub ai_predict: DecisionSource,

    pub proposal_action: String,       // "ReduceLoad" | "EnterIsolation" | ...
    pub proposal_predicted_state: String,
    pub proposal_event_reason: String,
    pub proposal_threat_score: f32,
    pub proposal_confidence: f32,

    pub allowed: bool,
    pub supervisor_reason: String,
    pub change: StateChange,
    pub recorded_at: u64,
}

impl LifecycleEntry {
    pub fn now(
        tick: u64,
        node_id: u32,
        ai_predict: DecisionSource,
        proposal_action: String,
        proposal_predicted_state: String,
        proposal_event_reason: String,
        proposal_threat_score: f32,
        proposal_confidence: f32,
        allowed: bool,
        supervisor_reason: String,
        change: StateChange,
    ) -> Self {
        Self {
            tick,
            node_id,
            ai_predict,
            proposal_action,
            proposal_predicted_state,
            proposal_event_reason,
            proposal_threat_score,
            proposal_confidence,
            allowed,
            supervisor_reason,
            change,
            recorded_at: now_secs(),
        }
    }
}

// КАТЕГОРИЯ 2: СИГНАЛЫ  [отправитель] - [получатель] - [тип сигнала] - [содержимое] - [threat получателя]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignalContent {
    pub mode: String,
    pub load: u8,
    pub active_connections: u8,
    pub failed_auth_count: u8,
    pub ai_state_reason: String,
    pub signal_threat_score: f32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignalEntry {
    pub tick: u64,
    pub sender_id: u32,
    pub receiver_id: u32,
    pub signal_type: String,
    pub content: SignalContent,
    pub receiver_threat_level: f32,
    pub recorded_at: u64,
}

impl SignalEntry {
    pub fn now(tick: u64, sender_id: u32, receiver_id: u32, signal_type: String, content: SignalContent, receiver_threat_level: f32,) -> Self {
        Self {
            tick,
            sender_id,
            receiver_id,
            signal_type,
            content,
            receiver_threat_level,
            recorded_at: now_secs(),
        }
    }
}

// КАТЕГОРИЯ 3: РЕШЕНИЕ ИИ  [метрики (не синтетические)] - [class_name] - [reason] - [threat] - [confidence]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RawMetrics {
    pub self_load: u8,
    pub self_temperature: i8,
    pub active_connections: u8,
    pub failed_auth_count: u8,
    pub last_sync_age_sec: u64,

    pub neighbor_count: usize,
    pub neighbors_isolated: usize,
    pub neighbors_degraded: usize,
    pub neighbors_reconnecting: usize,
    pub neighbors_avg_load: f32,
    pub neighbors_max_threat: f32,
    pub neighbors_failed_auth_avg: f32,
    pub neighbors_avg_connections: f32,

    pub peer_suspicion_count: usize,

    pub time_in_state_sec: u64,
    pub previous_threat_score: f32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AiDecisionEntry {
    pub tick: u64,
    pub node_id: u32,
    pub metrics: RawMetrics,
    pub class_name: String,   // predicted_state
    pub reason: String,       // event_reason
    pub threat: f32,
    pub confidence: f32,

    pub recorded_at: u64,
}

impl AiDecisionEntry {
    pub fn now(tick: u64, node_id: u32, metrics: RawMetrics, class_name: String, reason: String, threat: f32, confidence: f32,) -> Self {
        Self {
            tick,
            node_id,
            metrics,
            class_name,
            reason,
            threat,
            confidence,
            recorded_at: now_secs(),
        }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ОБЩИЙ БУФЕРИЗОВАННЫЙ JSONL-WRITER (generic по типу записи)
pub trait TickIndexed {
    fn tick(&self) -> u64;
}

impl TickIndexed for LifecycleEntry {
    fn tick(&self) -> u64 { self.tick }
}
impl TickIndexed for SignalEntry {
    fn tick(&self) -> u64 { self.tick }
}
impl TickIndexed for AiDecisionEntry {
    fn tick(&self) -> u64 { self.tick }
}

pub struct JsonlLogger<T> {
    file_path: PathBuf,
    buffer: Vec<T>,
    flush_every: u64,
    last_flush: u64,
}

impl<T> JsonlLogger<T>
where
    T: Serialize + for<'de> Deserialize<'de> + TickIndexed,
{
    pub fn open(log_dir: impl AsRef<Path>, log_file: impl AsRef<Path>, flush_every: u64,) -> Result<Self, std::io::Error> {
        let dir = log_dir.as_ref();
        fs::create_dir_all(dir)?;

        let file_path = dir.join(log_file);
        OpenOptions::new().create(true).append(true).open(&file_path)?;

        println!("✓ Log opened: {}", file_path.display());

        Ok(Self {
            file_path,
            buffer: Vec::new(),
            flush_every,
            last_flush: 0,
        })
    }

    pub fn push(&mut self, entry: T, current_tick: u64) {
        self.buffer.push(entry);

        if current_tick.saturating_sub(self.last_flush) >= self.flush_every {
            if let Err(e) = self.flush(current_tick) {
                eprintln!("⚠ Log flush error ({}): {}", self.file_path.display(), e);
            }
        }
    }

    pub fn flush(&mut self, current_tick: u64) -> Result<(), std::io::Error> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        let mut file = OpenOptions::new().create(true).append(true).open(&self.file_path)?;

        for entry in &self.buffer {
            let line = serde_json::to_string(entry)
                .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e));
            writeln!(file, "{}", line)?;
        }

        self.buffer.clear();
        self.last_flush = current_tick;
        Ok(())
    }

    pub fn load_all(&self) -> Result<Vec<T>, LoadError> {
        let file = File::open(&self.file_path).map_err(LoadError::Io)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();
        let mut errors = 0usize;

        for (line_no, line) in reader.lines().enumerate() {
            let line = line.map_err(LoadError::Io)?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<T>(trimmed) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    eprintln!("⚠ Log line {} parse error ({}): {}", line_no + 1, self.file_path.display(), e);
                    errors += 1;
                }
            }
        }

        if errors > 0 {
            eprintln!("⚠ {} corrupted log lines skipped ({})", errors, self.file_path.display());
        }

        Ok(entries)
    }

    pub fn last_tick(&self) -> Result<Option<u64>, LoadError> {
        Ok(self.load_all()?.into_iter().map(|e| e.tick()).max())
    }

    pub fn path(&self) -> &Path {
        &self.file_path
    }
}

// ОБЪЕДИНЯЮЩИЙ ЛОГГЕР: три файла, три категории
pub struct NetworkLogger {
    pub lifecycle: JsonlLogger<LifecycleEntry>,
    pub signals: JsonlLogger<SignalEntry>,
    pub ai_decisions: JsonlLogger<AiDecisionEntry>,
}

impl NetworkLogger {
    pub fn open(log_dir: impl AsRef<Path>, flush_every: u64) -> Result<Self, std::io::Error> {
        let dir = log_dir.as_ref();
        Ok(Self {
            lifecycle: JsonlLogger::open(dir, "lifecycle.jsonl", flush_every)?,
            signals: JsonlLogger::open(dir, "signals.jsonl", flush_every)?,
            ai_decisions: JsonlLogger::open(dir, "ai_decisions.jsonl", flush_every)?,
        })
    }

    pub fn flush_all(&mut self, current_tick: u64) {
        if let Err(e) = self.lifecycle.flush(current_tick) {
            eprintln!("⚠ lifecycle log flush error: {}", e);
        }
        if let Err(e) = self.signals.flush(current_tick) {
            eprintln!("⚠ signals log flush error: {}", e);
        }
        if let Err(e) = self.ai_decisions.flush(current_tick) {
            eprintln!("⚠ ai_decisions log flush error: {}", e);
        }
    }

    pub fn last_tick(&self) -> Option<u64> {
        [
            self.lifecycle.last_tick().ok().flatten(),
            self.signals.last_tick().ok().flatten(),
            self.ai_decisions.last_tick().ok().flatten(),
        ]
        .into_iter()
        .flatten()
        .max()
    }
}

// ОШИБКИ
#[derive(Debug)]
pub enum LoadError {
    Io(std::io::Error),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Io(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for LoadError {}