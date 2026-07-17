use std::path::Path;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub simulation: SimulationConfig,
    pub topology: TopologyConfig,
    pub node_defaults: NodeDefaultsConfig,
    pub security: SecurityConfig,
    pub load_calibration:  LoadCalibrationConfig,
    pub ai: AiConfig,
    pub persistence: PersistenceConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SimulationConfig {
    pub max_ticks: u64,
    pub tick_interval_ms: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TopologyConfig {
    pub links: Vec<NodeLink>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NodeLink {
    pub id: u32,
    pub neighbors: Vec<u32>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NodeDefaultsConfig {
    pub load: u8,
    pub temperature: i8,
    pub active_connections: u8,
    pub failed_auth_count: u8,
    pub last_sync_time: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SecurityConfig {
    pub threat_score_normal: f32,
    pub stale_ttl: u64,
    pub node_stale_ttl: u64,
    pub max_len_neighbor_signals: usize,
    pub max_count_signals_from_neighbor: usize,
    pub peer_suspicion_threshold: usize,
    pub threat_score_isolation: f32,
    pub max_failed_auth: u8,
    pub max_reconnect_attempts: u32,
    pub min_quarantine_ticks: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LoadCalibrationConfig {
    pub reduce_factor: f32, // Шаг сброса нагрузки за один тик (% от текущей нагрузки, 0..1)
    pub boost_factor: f32, // Шаг повышения нагрузки за один тик
    pub reduce_floor: u8, // Нижняя граница нагрузки при Throttled-режиме
    pub boost_ceiling: u8, // Верхняя граница нагрузки при Boosted-режиме
    pub hold_ticks: u64, // Сколько тиков узел остаётся в Throttled/Boosted перед повторной оценкой
    pub conn_scale_factor: f32, // Коэффициент масштабирования active_connections вместе с нагрузкой (0..1)
}

#[derive(Debug, Deserialize, Clone)]
pub struct AiConfig {
    pub self_model_path: String,
    pub neighbor_model_path: String,
    pub ticks_to_degraded: u64,
    pub ticks_to_normal: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PersistenceConfig {
    pub log_dir: String,
    pub flush_every_ticks: u64,
}

// Загрузка

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| ConfigError::Io(path.as_ref().display().to_string(), e))?;

        toml::from_str(&raw)
            .map_err(ConfigError::Parse)
    }

    // ищет `network.toml`
    pub fn load_default() -> Self {
        let candidates = [
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("network.toml"))),
            Some(Path::new("network.toml").to_path_buf()),
        ];

        for candidate in candidates.into_iter().flatten() {
            if candidate.exists() {
                match Self::load(&candidate) {
                    Ok(cfg) => {
                        println!("✓ Config loaded from: {}", candidate.display());
                        return cfg;
                    }
                    Err(e) => eprintln!("⚠ Config parse error ({}): {}", candidate.display(), e),
                }
            }
        }

        eprintln!("⚠ network.toml not found, using built-in defaults");
        Self::default()
    }
}

// Дефолты (если файл не найден)

impl Default for Config {
    fn default() -> Self {
        Self {
            simulation: SimulationConfig {
                max_ticks: 20,
                tick_interval_ms: 1000,
            },
            topology: TopologyConfig {
                links: vec![
                    NodeLink { id: 1, neighbors: vec![5, 2] },
                    NodeLink { id: 2, neighbors: vec![1, 3, 4, 5] },
                    NodeLink { id: 3, neighbors: vec![2, 4] },
                    NodeLink { id: 4, neighbors: vec![2, 3] },
                    NodeLink { id: 5, neighbors: vec![1, 2] },
                ],
            },
            node_defaults: NodeDefaultsConfig {
                load: 40,
                temperature: 30,
                active_connections: 5,
                failed_auth_count: 0,
                last_sync_time: 0,
            },
            security: SecurityConfig {
                threat_score_normal: 0.4,
                stale_ttl: 5,
                node_stale_ttl: 5,
                max_len_neighbor_signals: 10,
                max_count_signals_from_neighbor: 2,
                peer_suspicion_threshold: 2,
                threat_score_isolation: 0.7,
                max_failed_auth: 5,
                max_reconnect_attempts: 5,
                min_quarantine_ticks: 4
            },
            load_calibration: LoadCalibrationConfig {
                reduce_factor: 0.20, // Сброс: каждый тик срез 20% текущей нагрузки, минимум до 20
                boost_factor: 0.15,
                reduce_floor: 20,
                boost_ceiling: 95,
                hold_ticks: 3, // Держим режим 3 тика, потом ИИ снова решает
                conn_scale_factor: 0.60, // Соединения масштабируются на 60% от изменения нагрузки
            },
            ai: AiConfig {
                self_model_path: "ai_model/self_model.py".into(),
                neighbor_model_path: "ai_model/neighbor_model.py".into(),
                ticks_to_degraded: 5,
                ticks_to_normal: 5,
            },
            persistence: PersistenceConfig {
                log_dir: "logs".into(),
                flush_every_ticks: 1,
            },
        }
    }
}

// Ошибки

#[derive(Debug)]
pub enum ConfigError {
    Io(String, std::io::Error),
    Parse(toml::de::Error),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(path, e)  => write!(f, "Cannot read '{}': {}", path, e),
            ConfigError::Parse(e)     => write!(f, "TOML parse error: {}", e),
        }
    }
}

impl std::error::Error for ConfigError {}
