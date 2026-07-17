import sys, json, math, os, logging
import torch
import torch.nn as nn
import torch.nn.functional as F
import yaml
from typing import Tuple
from pydantic import BaseModel


class IncidentClasses(BaseModel):
    name: str
    action: str
    base_threat: float
    reason: str

class AppConfig(BaseModel):
    classes: list[IncidentClasses]
    feature_normalization: dict[str, float]
    semantic_thresholds: dict[str, dict[str, float]]


def load_config(path: str) -> AppConfig:
    with open(path, "r") as f:
        data = yaml.safe_load(f)
    return AppConfig(**data)

try:
    config = load_config("ai_model/self_config.yaml")
except FileNotFoundError:
    config = AppConfig(classes=[], feature_normalization={}, semantic_thresholds={})

logging.basicConfig(
    filename='ai_model/neighbor_model.log',
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] NeighborAI: %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)


MODES = {
    "Normal": 0, "Throttled": 1, "Boosted": 2, 
    "Degraded": 3, "Isolated": 4, "Reconnecting": 5,
}

SIGNAL_TYPES = {
    "Normal": 0, "Alert": 1, "Isolation": 2, "LoadReduced": 3,
    "ReduceLoad": 4, "LoadBoosted": 5, "BoostLoad": 6, 
    "PeerSuspicion": 7, "ReconnectRequest": 8, "ReconnectAck": 9,
}

# 1 ПАРАМЕТРЫ ФИЧЕЙ И МОДЕЛИ
BASE_FEATURES = 23
HISTORY_SIZE = 8
MODE_END = BASE_FEATURES + len(MODES)
CLASS_NAMES = {c.name: i for i, c in enumerate(config.classes)}

TABULAR_DIM = BASE_FEATURES + len(MODES) + len(CLASS_NAMES) + len(SIGNAL_TYPES)
HISTORY_CHANNELS = 8
FLATTENED_HISTORY_DIM = HISTORY_CHANNELS * HISTORY_SIZE 
COMBINED_DIM = TABULAR_DIM + FLATTENED_HISTORY_DIM

HIDDEN1 = 64
HIDDEN2 = 32
EXPERT_WEIGHT = 0.40

def build_features(inp: dict) -> Tuple[torch.Tensor, torch.Tensor]:
    raw_load = inp.get("load", 0)
    raw_net_load = inp.get("network_avg_load", 0.0)
    raw_auth = inp.get("failed_auth_count", 0)
    raw_delta = max(0, inp.get("failed_auth_delta", 0))
    raw_net_auth = inp.get("network_avg_failed_auth", 0.0)
    
    load = min(inp.get("load", 0), 200) / 200.0
    integrity_ok = 1.0 if inp.get("integrity_ok", True) else 0.0
    active_conn = min(inp.get("active_connections", 0), 1000) / 1000.0
    failed_auth = min(inp.get("failed_auth_count", 0), 20) / 20.0
    reported_threat = inp.get("threat_score", 0.0)
    
    # Обработка истории угроз
    history = inp.get("threat_score_history", [])[-HISTORY_SIZE:]
    history = [0.0] * (HISTORY_SIZE - len(history)) + history
    
    mode = F.one_hot(torch.tensor(MODES.get(inp.get("mode"), MODES["Normal"]), dtype=torch.long), num_classes=len(MODES))
    signal_type = F.one_hot(torch.tensor(SIGNAL_TYPES.get(inp.get("signal_type"), SIGNAL_TYPES["Normal"]), dtype=torch.long), num_classes=len(SIGNAL_TYPES))
    ai_state_reason = F.one_hot(torch.tensor(CLASS_NAMES.get(inp.get("ai_state_reason"), 0), dtype=torch.long), num_classes=max(1, len(CLASS_NAMES)))
    
    signal_age = min(inp.get("signal_age_ticks", 0), 100) / 100.0
    time_in_mode = min(inp.get("time_in_mode_ticks", 0), 1000) / 1000.0
    
    load_delta = min(max(inp.get("load_delta", 0), -100), 100) / 100.0
    failed_auth_delta = min(max(inp.get("failed_auth_delta", 0), 0), 20) / 20.0
    conn_delta = (min(max(inp.get("active_connections_delta", 0), -500), 500) + 500) / 1000.0
    threat_delta = min(max(inp.get("threat_score_delta", 0.0), -1.0), 1.0) / 1.0
    mode_changed = 1.0 if inp.get("mode_changed", False) else 0.0
    recent_signals = min(inp.get("signals_seen_recent", 0), 20) / 20.0
    prior_suspicion = min(inp.get("prior_suspicion_votes_against", 0), 10) / 10.0
    times_isolated = min(inp.get("times_isolated_historically", 0), 100) / 100.0
    
    net_avg_load = min(inp.get("network_avg_load", 0.0), 200) / 200.0
    net_avg_auth = min(inp.get("network_avg_failed_auth", 0.0), 20) / 20.0
    load_deviation = math.tanh((raw_load - raw_net_load) / (raw_net_load + 10.0))
    auth_anomaly = max(min(max(0.0, (raw_auth - raw_net_auth) / (raw_net_auth + 1.0)) / 5.0, 1.0), min(raw_delta / 10.0, 1.0))
    
    sq_load_gap = load_deviation ** 2
    threat_sq = reported_threat ** 2
    load_x_auth = min(load * auth_anomaly, 1.0)
    integrity_x_threat = min((1.0 - integrity_ok) * reported_threat, 1.0)
    
    features = [
        load, integrity_ok, active_conn, failed_auth, reported_threat, 
        signal_age, time_in_mode, load_delta, failed_auth_delta, conn_delta, 
        threat_delta, mode_changed, recent_signals, prior_suspicion, times_isolated, 
        net_avg_load, net_avg_auth, load_deviation, auth_anomaly, sq_load_gap, 
        threat_sq, load_x_auth, integrity_x_threat
    ]
    
    base_features = torch.tensor(features, dtype=torch.float32)
    features_tensor = torch.cat([base_features, mode.float(), signal_type.float(), ai_state_reason.float()])

    return features_tensor, torch.tensor(history, dtype=torch.float32)


# 2 ЭКСПЕРТНАЯ СИСТЕМА
def expert_threat(f: list) -> float:
    load = f[0]
    integrity_ok = f[1]
    failed_auth = f[3]
    reported_threat = f[4]
    failed_auth_delta = f[8]
    prior_susp = f[13]
    times_iso = f[14]
    load_deviation = f[17]
    auth_anomaly = f[18]
    
    mode = max(range(len(MODES)), key=lambda i: f[BASE_FEATURES + i])
    signal_type = max(range(len(SIGNAL_TYPES)), key=lambda i: f[MODE_END + i])
    
    score = 0.0
    
    # 1. Целостность и прямые угрозы (критический фактор)
    if integrity_ok < 0.5:
        # Синергия: пробита целостность + есть внешние репорты об угрозе
        score += 0.5 + (reported_threat * 0.3) 
    else:
        score += reported_threat * 0.2
        
    # 2. Сетевые аномалии и авторизация
    auth_risk = failed_auth * 0.4 + failed_auth_delta * 0.2 + auth_anomaly * 0.2
    if load > 0.7:
        # Усиливаем вес ошибок авторизации при высокой нагрузке (вероятен DDoS/Bruteforce)
        score += auth_risk * 1.5
    else:
        score += auth_risk
        
    # 3. Социальный фактор (подозрения соседей)
    if signal_type == SIGNAL_TYPES["PeerSuspicion"]:
        score += 0.3
    score += prior_susp * 0.2
    score += times_iso * 0.1
    
    # 4. Отклонение от сети
    if mode == MODES["Degraded"]:
        score += abs(load_deviation) * 0.3 + 0.1
    else:
        score += abs(load_deviation) * 0.15
        
    return max(0.0, min(score, 1.0))

def apply_bayesian_hysteresis(mlp_prob: float, history_list: list[float]) -> float:
    if len(history_list) > 0:
        sub_hist = history_list[-HISTORY_SIZE//2:] if len(history_list) >= HISTORY_SIZE//2 else history_list
        prior = sum(sub_hist) / len(sub_hist)
        prior = max(0.1, min(0.9, prior))  # Ограничиваем от экстремумов 0 и 1
    else:
        prior = 0.5
        
    likelihood = max(1e-5, min(1.0 - 1e-5, mlp_prob))
    
    # Формула Байеса
    posterior_unnorm = likelihood * prior
    evidence = posterior_unnorm + (1.0 - likelihood) * (1.0 - prior)
    
    return posterior_unnorm / (evidence + 1e-9)

def dynamic_expert_weight(mlp_prob: float) -> float:
    eps = 1e-7
    p = max(eps, min(1.0 - eps, mlp_prob))
    
    entropy = -(p * math.log(p) + (1.0 - p) * math.log(1.0 - p)) / math.log(2.0)
    
    weight_min = 0.20  # Минимальный вес эксперта (ИИ уверен)
    weight_max = 0.80  # Максимальный вес эксперта (ИИ сомневается)
    
    return weight_min + (weight_max - weight_min) * entropy


# 3 НЕЙРОCЕТЬ (Разделенная архитектура)
class NeighborMLP(nn.Module):
    def __init__(self, seed=42):
        super().__init__()
        
        if seed is not None:
            torch.manual_seed(seed)
            
        # Временная ветвь (анализ истории угроз)
        self.history_conv = nn.Sequential(
            nn.Conv1d(in_channels=1, out_channels=HISTORY_CHANNELS, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.Conv1d(in_channels=HISTORY_CHANNELS, out_channels=HISTORY_CHANNELS, kernel_size=3, padding=1),
            nn.ReLU()
        )
        
        # Основная ветвь (после слияния табличных фичей и сглаженной истории)
        self.fc1 = nn.Linear(COMBINED_DIM, HIDDEN1)
        self.ln1 = nn.LayerNorm(HIDDEN1)
        
        self.fc2 = nn.Linear(HIDDEN1, HIDDEN2)
        self.ln2 = nn.LayerNorm(HIDDEN2)
        
        self.fc3 = nn.Linear(HIDDEN2, 1)
        
        self._init_weights()
        self._structural_init()

    def _init_weights(self):
        nn.init.xavier_uniform_(self.fc1.weight)
        nn.init.zeros_(self.fc1.bias)
        
        nn.init.xavier_uniform_(self.fc2.weight)
        nn.init.zeros_(self.fc2.bias)
        
        nn.init.xavier_uniform_(self.fc3.weight, gain=0.5)
        nn.init.zeros_(self.fc3.bias)

    @torch.no_grad()
    def _structural_init(self):
        for i in range(32):
            self.fc1.weight[i, 1] -= 1.5   # integrity_ok
            self.fc1.weight[i, 3] += 1.5   # failed_auth
            self.fc1.weight[i, 8] += 1.5   # failed_auth_delta
            self.fc1.weight[i, 13] += 1.0  # prior_suspicion
            self.fc1.weight[i, 18] += 1.5  # auth_anomaly

        for i in range(32):
            self.fc2.weight[0:8, i] += 1.0 
            
        for i in range(16):
            self.fc3.weight[0, i] += 1.0 

    def forward(self, tabular_x: torch.Tensor, history_x: torch.Tensor) -> torch.Tensor:
        # Прогон временного ряда через свертки
        h = history_x.unsqueeze(1) 
        h_out = self.history_conv(h)
        
        # Flatten выхода конволюции
        h_flat = h_out.view(h_out.size(0), -1) 
        
        # Слияние ветвей
        x = torch.cat([tabular_x, h_flat], dim=1)
        
        # MLP
        x = F.relu(self.ln1(self.fc1(x)))
        x = F.relu(self.ln2(self.fc2(x)))
        logits = self.fc3(x)
        
        return torch.sigmoid(logits).squeeze(-1)

    @torch.no_grad()
    def predict(self, tabular: torch.Tensor, history: torch.Tensor) -> float:
        self.eval()
        
        if tabular.dim() == 1: 
            tabular = tabular.unsqueeze(0)
        if history.dim() == 1: 
            history = history.unsqueeze(0)
            
        raw_mlp_threat = self.forward(tabular, history).item()
        history_list = history[0].tolist() 
        
        mlp_threat = apply_bayesian_hysteresis(raw_mlp_threat, history_list)
        expert_threat_val = expert_threat(tabular.squeeze(0).tolist())
        current_expert_weight = dynamic_expert_weight(mlp_threat)
            
        return float(current_expert_weight * expert_threat_val + (1.0 - current_expert_weight) * mlp_threat)


# 4 ГЛАВНЫЙ ЦИКЛ
def main():
    mlp = NeighborMLP()

    weights_path = os.path.join(os.path.dirname(__file__), "neighbor_weights.pth")
    if os.path.exists(weights_path):
        try:
            mlp.load_state_dict(torch.load(weights_path, weights_only=True))
            mlp.eval()
            logger.info(f"Loaded trained weights from {weights_path}")
        except Exception as e:
            logger.warning(f"Could not load weights ({e}), using initialized states")

    logger.info(
        f"[NeighborAI] Evaluator v1.1 — "
        f"expert({int(EXPERT_WEIGHT*100)}%) + MLP({int((1-EXPERT_WEIGHT)*100)}%) | "
        f"Features: {TABULAR_DIM} (Tabular) + {FLATTENED_HISTORY_DIM} (History) -> "
        f"{HIDDEN1}→{HIDDEN2}→1"
    )

    with torch.inference_mode():
        for raw in sys.stdin:
            raw = raw.strip()
            if not raw: continue
            try:
                data = json.loads(raw)
                tabular_features, threat_history = build_features(data)
                threat = mlp.predict(tabular_features, threat_history)
                
                print(json.dumps({"threat_score": round(threat, 4)}), flush=True)
                
            except Exception as e:
                print(json.dumps({"threat_score": 0.0}), flush=True)
                logger.error(f"Processing Error: {e} | Data: {raw[:200]}")

if __name__ == "__main__":
    main()