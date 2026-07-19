use crate::network::Network;
use crate::control::SimControl;
use crate::scenarios::{AttackScenario, ScenarioTarget};
use std::time::Duration;
use std::sync::Arc;
use serde::Serialize;
use tokio::sync::Mutex;
use warp::Filter;
use futures_util::{StreamExt, SinkExt};

const INDEX_HTML: &str = include_str!("index.html");
const MAIN_JS: &str = include_str!("main.js");
const DASHBOARD_JS: &str = include_str!("dashboard.js");
const DASHBOARD_EXTRA_JS: &str = include_str!("dashboard-extra.js");
const STYLE_CSS: &str = include_str!("style.css");

#[derive(Serialize)]
pub struct VisualNode {
    pub id: u32,
    pub mode: String,
    pub load: u8,
    pub threat: f32,
    pub failed_auth_count: u8,
    pub active_connections: u8,
    pub confidence: f32,
    pub predicted_state: String,
    pub ai_state_reason: String,
    pub peer_suspicion_votes: usize,
}

#[derive(Serialize)]
pub struct VisualEdge {
    pub source: u32,
    pub target: u32,
    pub virtual_link: bool,
}

#[derive(Serialize)]
pub struct VisualState {
    pub tick: u64,
    pub max_ticks: u64,
    pub finished: bool,
    pub nodes: Vec<VisualNode>,
    pub network_avg_load: usize,
    pub edges: Vec<VisualEdge>,
    pub logs: Vec<String>,
    pub network_utilization: f32,
    pub network_starving: bool,
}

pub fn build_visual_state(network: &Network, since_tick: u64) -> VisualState {
    let tick = network.tick;
    let stale_ttl = network.config.security.stale_ttl;
    let boost_ceiling = network.config.load_calibration.boost_ceiling as u32;

    let nodes: Vec<VisualNode> = network.nodes.iter().map(|n| {
        let peer_suspicion_votes = n.neighbor_signals.values().flatten()
            .filter(|s| {
                s.signal_type == crate::node::SignalType::PeerSuspicion
                && s.target_id == Some(n.id)
                && s.timestamp == tick
            })
            .map(|s| s.source_id)
            .collect::<std::collections::HashSet<_>>()
            .len();

        VisualNode {
            id: n.id,
            mode: format!("{:?}", n.state.mode),
            load: n.state.load,
            threat: n.last_proposal.as_ref().map(|p| p.threat_score).unwrap_or(0.0),
            failed_auth_count: n.state.failed_auth_count,
            active_connections: n.state.active_connections,
            confidence: n.last_proposal.as_ref().map(|p| p.confidence).unwrap_or(0.0),
            predicted_state: n.last_proposal.as_ref().map(|p| p.predicted_state.clone()).unwrap_or_default(),
            ai_state_reason: n.state.ai_state_reason.clone(),
            peer_suspicion_votes,
        }
    }).collect();

    let sum: usize = network.nodes.iter().map(|node| node.state.load as usize).sum();
    let network_avg_load = if network.nodes.is_empty() { 0 } else { (sum as f32 / network.nodes.len() as f32).round() as usize };

    let mut latest_by_source: std::collections::HashMap<u32, &crate::node::NodeSignal> = std::collections::HashMap::new();
    for n in &network.nodes {
        let all_signals = &n.neighbor_signals;
        for sig in all_signals.values().flatten() {
            if tick.saturating_sub(sig.timestamp) <= stale_ttl {
                let entry = latest_by_source.entry(sig.source_id).or_insert(sig);
                if sig.timestamp > entry.timestamp {
                    *entry = sig;
                }
            }
        }
    }
    let active_count = latest_by_source.len() as u32;
    let boosted_count = latest_by_source.values().filter(|s| s.mode == crate::node::Mode::Boosted).count() as u32;
    let total_load: u32 = latest_by_source.values().map(|s| s.load as u32).sum();
    let total_capacity: u32 = active_count * boost_ceiling;
    
    let network_utilization = if total_capacity > 0 { total_load as f32 / total_capacity as f32 } else { 0.0 };
    let network_starving = active_count > 0 && boosted_count > active_count / 2;

    let edges = network.links.iter()
        .filter(|l| l.active)
        .map(|l| VisualEdge {
            source: network.nodes[l.from].id,
            target: network.nodes[l.to].id,
            virtual_link: l.virtual_link,
        })
        .collect();

    let mut logs = vec![];
    for entry in network.recent_lifecycle.iter().rev() {
        if entry.tick <= since_tick {
            break;
        }
        logs.push(format!(
            "[T{}] Node {}: {} -> {} ({})",
            entry.tick, entry.node_id, entry.proposal_action, entry.allowed, entry.supervisor_reason
        ));
    }
    logs.reverse();

    VisualState {
        tick,
        max_ticks: network.max_ticks,
        finished: network.finished,
        nodes,
        network_avg_load,
        edges,
        logs,
        network_utilization,
        network_starving,
    }
}

pub async fn run_server(network: Arc<Mutex<Network>>, control: SimControl) {
    let net_filter     = warp::any().map(move || network.clone());
    let control_filter = warp::any().map(move || control.clone());

    let ws_route = warp::path("ws")
        .and(warp::ws())
        .and(net_filter)
        .and(control_filter)
        .map(|ws: warp::ws::Ws, network, control| {
            ws.on_upgrade(move |socket| handle_connection(socket, network, control))
        });

    let index_route = warp::path::end()
        .map(|| warp::reply::html(INDEX_HTML));

    let main_js_route = warp::path("main.js")
        .map(|| warp::reply::with_header(MAIN_JS, "content-type", "application/javascript"));

    let dashboard_js_route = warp::path("dashboard.js")
        .map(|| warp::reply::with_header(DASHBOARD_JS, "content-type", "application/javascript"));

    let dashboard_extra_js_route = warp::path("dashboard-extra.js")
        .map(|| warp::reply::with_header(DASHBOARD_EXTRA_JS, "content-type", "application/javascript"));

    let style_css_route = warp::path("style.css")
        .map(|| warp::reply::with_header(STYLE_CSS, "content-type", "text/css"));

    let routes = index_route
        .or(main_js_route)
        .or(dashboard_js_route)
        .or(dashboard_extra_js_route)
        .or(style_css_route)
        .or(ws_route);

    tracing::info!("Сервер запущен на http://127.0.0.1:3030 (HTML/JS/CSS встроены в бинарник)");
    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}

async fn handle_connection(
    ws: warp::ws::WebSocket,
    network: Arc<Mutex<Network>>,
    control: SimControl,
) {
    let (mut tx, mut rx) = ws.split();
    let mut last_sent_tick = 0u64;

    loop {
        tokio::select! {
            // --- команды от клиента ---
            msg = rx.next() => {
                match msg {
                    Some(Ok(m)) if m.is_text() => {
                        let text = m.to_str().unwrap_or("");
                        match text {
                            "run" => control.run(),
                            "stop" => control.stop(),
                            "restart" => {
                                control.restart();
                                last_sent_tick = 0; 
                            }
                            // --- ПАРСИНГ КОМАНД СЦЕНАРИЕВ ---
                            cmd if cmd.starts_with("scenario:") => {
                                let parts: Vec<&str> = cmd.split(':').collect();
                                if parts.len() >= 3 {
                                    let s_name = parts[1];
                                    let t_type = parts[2];
                                    let t_val = parts.get(3).unwrap_or(&"0").parse::<u32>().unwrap_or(0);

                                    let target = match t_type {
                                        "ById" => ScenarioTarget::ById(t_val),
                                        "Random" => ScenarioTarget::Random { count: 1 },
                                        _ => ScenarioTarget::All,
                                    };

                                    // Дефолт длительности на случай, если клиент не прислал
                                    let default_duration: u64 = match s_name {
                                        "ddos" => 20,
                                        "underscale" => 20,
                                        "brute_force" => 10,
                                        "ai_crash" => 20,
                                        "node_infection" => 20,
                                        "network_partition" => 10,
                                        _ => 10,
                                    };
                                    let requested_duration = parts.get(4).and_then(|raw| raw.parse::<u64>().ok());

                                    // Один лок на всю операцию
                                    let mut net = network.lock().await;
                                    let remaining = net.max_ticks.saturating_sub(net.tick);

                                    let duration_ticks: Option<u64> = match parts.get(4) {
                                        None => Some(default_duration),
                                        Some(raw) => match requested_duration {
                                            Some(d) if d > 0 && d <= remaining => Some(d),
                                            Some(d) => {
                                                tracing::warn!(
                                                    "Scenario '{}' rejected: duration {} out of range (1..={})",
                                                    s_name, d, remaining
                                                );
                                                None
                                            }
                                            None => {
                                                tracing::warn!(
                                                    "Scenario '{}' rejected: '{}' is not a valid duration",
                                                    s_name, raw
                                                );
                                                None
                                            }
                                        },
                                    };

                                    if let Some(duration_ticks) = duration_ticks {
                                        let scenario = match s_name {
                                            "ddos" => Some(AttackScenario::ddos(target, duration_ticks)),
                                            "underscale" => Some(AttackScenario::underscale(target, duration_ticks)),
                                            "brute_force" => Some(AttackScenario::brute_force(target, duration_ticks)),
                                            "ai_crash" => Some(AttackScenario::ai_crash(target, duration_ticks)),
                                            "node_infection" => Some(AttackScenario::node_infection(target, duration_ticks)),
                                            "network_partition" => Some(AttackScenario::network_partition(target, duration_ticks)),
                                            _ => None,
                                        };

                                        if let Some(scen) = scenario {
                                            net.apply_scenario(scen);
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    Some(Ok(_)) => {}
                    _ => break, // клиент отключился
                }
            }

            // --- периодическая отправка состояния ---
            _ = tokio::time::sleep(Duration::from_millis(500)) => {
                let state = {
                    let net = network.lock().await;
                    build_visual_state(&net, last_sent_tick)
                };
                last_sent_tick = state.tick;

                let json = serde_json::to_string(&state).unwrap();
                if tx.send(warp::ws::Message::text(json)).await.is_err() {
                    break;
                }
            }
        }
    }
}
