mod node;
mod supervisor;
mod proposal;
mod executor;
mod network;
mod ai_module;
mod visualization;
mod config;
mod persistence;
mod control;
mod scenarios;

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use node::{Node, NodeState, Mode};
use supervisor::Supervisor;
use ai_module::{AIModel, AIModelPool};
use executor::Executor;
use network::{Network, TopologyMap};
use visualization::run_server;
use config::Config;
use persistence::NetworkLogger;
use control::SimControl;


fn create_node(id: u32, cfg: Arc<Config>, ai_pool: Arc<AIModelPool>) -> Node {
    // 2 ИИ процесса на всё приложение (не на узел)
    let ai = AIModel::from_pool(ai_pool);
    let d = &cfg.node_defaults;

    Node {
        id,
        state: NodeState {
            load: d.load,
            temperature: d.temperature,
            active_connections: d.active_connections,
            failed_auth_count: d.failed_auth_count,
            last_sync_time: d.last_sync_time,
            pending_load_signal: None,
            load_hold_ticks_left: 0,
            ai_state_reason: "normal_operation".into(),
            state_entered_tick: 1,
            last_threat_score: 0.0,
            threat_score_history: VecDeque::new(),
            mode: Mode::Normal,
        },
        ai: ai,
        supervisor: Supervisor,
        executor: Executor,
        config: cfg,
        neighbor_signals: HashMap::new(),
        last_proposal: None,
        topology_map: TopologyMap::new(),
        incoming_alerts: vec![],
        neighbor_ids: vec![],
        reconnect: None,
        neighbor_history: HashMap::new(),
        pending_lifecycle: vec![],
        pending_ai_decisions: vec![],
        virtual_bridge_attempts: HashMap::new(),
        pending_virtual_bridge_signals: vec![],
    }
}

// Сборка сети из конфигурации
pub fn build_network(cfg: Arc<Config>, ai_pool: Arc<AIModelPool>) -> Network {
    let max_ticks = cfg.simulation.max_ticks;
    let nodes: Vec<Node> = cfg.topology.links
        .iter()
        .map(|link| create_node(link.id, Arc::clone(&cfg), Arc::clone(&ai_pool)))
        .collect();

    let topology: Vec<(u32, Vec<u32>)> = cfg.topology.links
        .iter()
        .map(|l| (l.id, l.neighbors.clone()))
        .collect();

    let links = Network::build_links(&topology);

    Network::new(nodes, links, 0, cfg, max_ticks, false)
}

// Точка входа
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info") 
        .init();
    
    let cfg = Config::load_default();
    let logger = NetworkLogger::open(&cfg.persistence.log_dir, cfg.persistence.flush_every_ticks).expect("Cannot open network logs");

    match logger.last_tick() {
        Some(last) => tracing::info!("Resuming from tick {} (log history preserved)", last),
        None => tracing::info!("Starting fresh simulation"),
    }

    let model_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(&cfg.ai.self_model_path);
    let neighbor_model_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(&cfg.ai.neighbor_model_path);
    let ai_pool = match AIModelPool::new(model_path.clone(), neighbor_model_path.clone()) {
        Ok(pool) => pool,
        Err(e) => {
            eprintln!("Не удалось инициализировать ИИ-процессы. Нет необходимых '.py' файлов по путям:\n - {:?}\n - {:?}", model_path, neighbor_model_path);
            eprintln!("Техническая деталь: {}", e);
            
            std::process::exit(1); 
        }
    };
    let cfg    = Arc::new(cfg);
    let network = Arc::new(Mutex::new(build_network(cfg.clone(), ai_pool.clone())));
    let logger = Arc::new(Mutex::new(logger));
    let control = SimControl::new(false);

    let sim_network = network.clone();
    let sim_logger  = logger.clone();
    let sim_cfg     = cfg.clone();
    let sim_control = control.clone();
    let sim_ai_pool = ai_pool.clone();

    tokio::spawn(async move {
        loop {
            if sim_control.take_restart() {
                let mut net = sim_network.lock().await;
                *net = build_network(sim_cfg.clone(), sim_ai_pool.clone());
                tracing::info!("↺  Simulation restarted");
            }

            if sim_control.is_running() {
                let mut net = sim_network.lock().await;
                if !net.finished {
                    let mut log = sim_logger.lock().await;
                    net.tick(&mut log);

                    if net.finished {
                        tracing::info!("✓ Network logs flushed and closed");
                    }
                }
            }

            let interval = sim_cfg.simulation.tick_interval_ms;
            tokio::time::sleep(std::time::Duration::from_millis(interval)).await;
        }
    });

    run_server(network, control).await;
}
