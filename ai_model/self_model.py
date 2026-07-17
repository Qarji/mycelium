import sys, json, math
import os
import logging
import torch
import torch.nn as nn
import torch.nn.functional as F
import yaml
from pydantic import BaseModel


class IncidentClasses(BaseModel):
    name: str
    action: str
    base_threat: float
    reason: str

class MlpNetwork(BaseModel):
    base_features: int
    history_size: int
    hidden1_size: int
    hidden2_size: int
    hidden3_size: int
    threat_hidden_size: int

class ExpertSystem(BaseModel):
    weight_min: float
    weight_max: float
    weight_on_error: float

class Entropy(BaseModel):
    midpoint: float
    sharpness: float

class Hyperparameters(BaseModel):
    mlp_network: MlpNetwork
    expert_system: ExpertSystem
    entropy: Entropy

class AppConfig(BaseModel):
    hyperparameters: Hyperparameters
    classes: list[IncidentClasses]
    feature_normalization: dict[str, float]
    semantic_thresholds: dict[str, dict[str, float]]


def load_config(path: str) -> AppConfig:
    with open(path, "r") as f:
        data = yaml.safe_load(f)
    return AppConfig(**data)

config = load_config("ai_model/self_config.yaml")

logging.basicConfig(
    filename='ai_model/self_model.log',
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] AI: %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)

# 1. СОБЫТИЯ
CLASS_NAMES = [c.name for c in config.classes]
CLASS_ACTIONS = {c.name: c.action for c in config.classes}
CLASS_REASONS = {c.name: c.reason for c in config.classes}
CLASS_THREATS = torch.tensor([c.base_threat for c in config.classes], dtype=torch.float32)
N_CLASSES = len(CLASS_NAMES)

# 2. ПАРАМЕТРЫ
def build_features(inp: dict) -> torch.Tensor:
    fn = config.feature_normalization
    st = config.semantic_thresholds
    
    LOAD_MAX = fn['load_max']
    TEMP_MAX = fn['temperature_max']
    TEMP_OFFSET = fn['temperature_offset']
    CONN_MAX = fn['active_connections_max']
    AUTH_MAX = fn['failed_auth_count_max']
    SYNC_MAX = fn['last_sync_age_sec_max']
    NEIGHBOR_NORM = fn['neighbor_count_norm']
    
    LOW_LOAD_MAX = st['low_load_anomaly']['self_load_max']

    raw_self_load = inp.get("self_load", 0)
    raw_n_avg_load = inp.get("neighbors_avg_load", 0.0)
    raw_reason = inp.get("ai_state_reason", "normal_operation")

    self_load = min(raw_self_load, LOAD_MAX) / LOAD_MAX
    self_temp = min(inp.get("self_temperature", 0) + TEMP_OFFSET, TEMP_MAX) / TEMP_MAX
    prev_reason = F.one_hot(torch.tensor(CLASS_NAMES.index(raw_reason) if raw_reason in CLASS_NAMES else 0, dtype=torch.long), num_classes=len(CLASS_NAMES))
    active_conn = min(inp.get("active_connections", 0), CONN_MAX) / CONN_MAX
    failed_auth = min(inp.get("failed_auth_count", 0), AUTH_MAX) / AUTH_MAX
    last_sync = min(inp.get("last_sync_age_sec", 0), SYNC_MAX) / SYNC_MAX

    n_count = max(inp.get("neighbor_count", 0), 0)
    n_isolated = inp.get("neighbors_isolated", 0)
    n_avg_load = min(raw_n_avg_load, LOAD_MAX) / LOAD_MAX
    n_max_threat = min(max(float(inp.get("neighbors_max_threat", 0.0)), 0.0), 1.0)
    n_fail_avg = min(inp.get("neighbors_failed_auth_avg", 0.0), AUTH_MAX) / AUTH_MAX
    n_degraded = inp.get("neighbors_degraded", 0)
    n_reconn = inp.get("neighbors_reconnecting", 0)
    n_avg_conn = min(inp.get("neighbors_avg_connections", 0.0), CONN_MAX) / CONN_MAX

    iso_ratio = (n_isolated / n_count) if n_count > 0 else 0.0
    deg_ratio = (n_degraded / n_count) if n_count > 0 else 0.0
    rec_ratio = (n_reconn / n_count) if n_count > 0 else 0.0
    susp_cnt = inp.get("peer_suspicion_count", 0)
    has_susp = 1.0 if susp_cnt > 0 else 0.0
    susp_r = min(susp_cnt, n_count) / max(n_count, 1)
    integrity_ok = max(1.0 - susp_r, 0.0)
    
    load_delta_raw = raw_self_load - raw_n_avg_load
    load_delta_abs = min(abs(load_delta_raw) / LOAD_MAX, 1.0)
    signed_delta = max(min(load_delta_raw / LOAD_MAX, 1.0), -1.0)

    iso_pressure = min(iso_ratio * 0.5 + n_max_threat * 0.5, 1.0)
    auth_anomaly = min(failed_auth + (1.0 - integrity_ok) * 0.5, 1.0)
    sq_load_gap = min((load_delta_raw / LOAD_MAX) ** 2, 1.0)

    threat_sq = n_max_threat ** 2
    load_x_auth = min(self_load * auth_anomaly, 1.0)
    iso_x_threat = min(iso_ratio * n_max_threat, 1.0)
    susp_x_fail = min(susp_r * failed_auth, 1.0)
    integrity_x_threat = min((1.0 - integrity_ok) * n_max_threat, 1.0)

    load_below = 1.0 if raw_self_load < LOW_LOAD_MAX * LOAD_MAX else 0.0
    net_load_up = 1.0 if raw_n_avg_load > raw_self_load else 0.0
    healthy_recovery = (integrity_ok * (1.0 - failed_auth) * (1.0 - n_max_threat) * (1.0 - susp_r))

    features = [
        self_load, self_temp, integrity_ok, active_conn, failed_auth, 
        last_sync, min(n_count, NEIGHBOR_NORM)/NEIGHBOR_NORM, iso_ratio, n_avg_load, n_max_threat, 
        n_fail_avg, deg_ratio, rec_ratio, n_avg_conn, has_susp, 
        susp_r, load_delta_abs, iso_pressure, auth_anomaly, signed_delta, 
        sq_load_gap, threat_sq, load_x_auth, iso_x_threat, susp_x_fail, 
        integrity_x_threat, load_below, net_load_up, healthy_recovery
    ]
    
    base_features = torch.tensor(features, dtype=torch.float32)
    features_tensor = torch.cat([base_features, prev_reason.float()])
    
    return features_tensor

BASE_FEATURES = config.hyperparameters.mlp_network.base_features
INPUT_DIM = BASE_FEATURES + N_CLASSES
HIDDEN1 = config.hyperparameters.mlp_network.hidden1_size
HIDDEN2 = config.hyperparameters.mlp_network.hidden2_size
HIDDEN3 = config.hyperparameters.mlp_network.hidden3_size
THREAT_HIDDEN = config.hyperparameters.mlp_network.threat_hidden_size

EXPERT_WEIGHT_MIN = config.hyperparameters.expert_system.weight_min   
EXPERT_WEIGHT_MAX = config.hyperparameters.expert_system.weight_max   
EXPERT_WEIGHT_ON_ERROR = config.hyperparameters.expert_system.weight_on_error  
ENTROPY_MIDPOINT = config.hyperparameters.entropy.midpoint    
ENTROPY_SHARPNESS = config.hyperparameters.entropy.sharpness   

# 3. СЕМАНТИЧЕСКИЕ ПРИЗНАКИ
def extract_semantic_flags(f: torch.Tensor) -> dict:
    self_load     = f[0].item()
    self_temp     = f[1].item()
    integrity_ok  = f[2].item()
    failed_auth   = f[4].item()
    iso_ratio     = f[7].item()
    n_avg_load    = f[8].item()
    n_max_threat  = f[9].item()
    n_fail_avg    = f[10].item()
    deg_ratio     = f[11].item()
    rec_ratio     = f[12].item()
    has_susp      = f[14].item()
    susp_r        = f[15].item()
    auth_anomaly  = f[18].item()
    
    st = config.semantic_thresholds

    return {
        "self_load": self_load,
        "self_temp": self_temp,
        "integrity_ok": integrity_ok,
        "failed_auth": failed_auth,
        "iso_ratio": iso_ratio,
        "n_avg_load": n_avg_load,
        "n_max_threat": n_max_threat,
        "n_fail_avg": n_fail_avg,
        "deg_ratio": deg_ratio,
        "rec_ratio": rec_ratio,
        "has_susp": has_susp,
        "susp_r": susp_r,
        "auth_anomaly": auth_anomaly,
        "hardware_strain":    (self_load > st['hardware_strain']['load_min'] or self_temp > st['hardware_strain']['temp_min']),
        "critical_strain":    (self_temp > st['critical_strain']['temp_min']),
        "network_overload":   (self_load > st['network_overload']['self_load_min'] and n_avg_load > st['network_overload']['neighbors_avg_load_min']),
        "auth_attack":        (failed_auth > st['auth_attack']['failed_auth_min'] or auth_anomaly > st['auth_attack']['auth_anomaly_min']),
        "integrity_critical": (integrity_ok < st['integrity_critical']['integrity_ok_max'] or auth_anomaly > st['integrity_critical']['auth_anomaly_min']),
        "isolation_risk":     (iso_ratio > st['isolation_risk']['iso_ratio_min']),
        "low_load_anomaly":   (self_load < st['low_load_anomaly']['self_load_max']),
        "healthy_state": (
            integrity_ok > st['healthy_state']['integrity_ok_min'] and 
            failed_auth < st['healthy_state']['failed_auth_max'] and 
            n_max_threat < st['healthy_state']['neighbors_max_threat_max'] and 
            susp_r < st['healthy_state']['suspicion_ratio_max'] and 
            self_load < st['healthy_state']['self_load_max']
        ),
    }


# 4. ДЕТЕРМИНИРОВАННЫЙ ЭКСПЕРТ
def expert_logits(flags: dict) -> torch.Tensor:
    lg = torch.full((N_CLASSES,), -5.0, dtype=torch.float32)

    self_load     = flags["self_load"]
    self_temp     = flags["self_temp"]
    integrity_ok  = flags["integrity_ok"]
    failed_auth   = flags["failed_auth"]
    iso_ratio     = flags["iso_ratio"]
    n_avg_load    = flags["n_avg_load"]
    n_max_threat  = flags["n_max_threat"]
    n_fail_avg    = flags["n_fail_avg"]
    deg_ratio     = flags["deg_ratio"]
    rec_ratio     = flags["rec_ratio"]
    has_susp      = flags["has_susp"]
    susp_r        = flags["susp_r"]
    auth_anomaly  = flags["auth_anomaly"]
    
    st = config.semantic_thresholds

    # 0: normal_operation
    score_normal = (
        (1.0 - self_load)*1.5 + integrity_ok*2.5 + (1.0 - failed_auth)*1.5 +
        (1.0 - iso_ratio)*1.2 + (1.0 - n_max_threat)*0.8 + (1.0 - susp_r)*0.8 + 
        (1.0 - auth_anomaly)*0.8
    )
    score_normal -= max(self_load - st['healthy_state']['self_load_max'], 0) * 20.0
    score_normal -= (1.0 - integrity_ok) * 6.0
    score_normal -= max(failed_auth - 0.2, 0) * 6.0
    score_normal -= susp_r * 6.0
    score_normal -= iso_ratio * 5.0
    score_normal -= n_max_threat * 3.0
    score_normal -= max(st['low_load_anomaly']['self_load_max'] - self_load, 0) * 45.0
    lg[0] = score_normal

    if flags["hardware_strain"]: # 1
        lg[1] = self_load * 5.0 + self_temp * 3.0 - 2.0
    else: lg[1] = -6.0

    if flags["network_overload"]: # 2
        lg[2] = self_load * 3.0 + n_avg_load * 4.0 - 2.0
    else: lg[2] = -6.0

    if self_load > 0.40 and (iso_ratio > 0.20 or deg_ratio > 0.15): # 3
        lg[3] = self_load * 2.5 + iso_ratio * 3.0 + deg_ratio * 2.5 - 1.5
    else: lg[3] = -6.0

    if self_load > 0.40 and auth_anomaly > 0.20: # 4
        lg[4] = self_load * 2.5 + auth_anomaly * 3.0 - 2.0
    else: lg[4] = -6.0

    if flags["low_load_anomaly"] and n_avg_load > self_load: # 5
        lg[5] = (st['low_load_anomaly']['self_load_max'] - self_load) * 15.0 + (n_avg_load - self_load) * 5.0
    else: lg[5] = -6.0

    if n_avg_load > self_load + 0.20 and n_avg_load > 0.55: # 6
        lg[6] = (n_avg_load - self_load) * 8.0 + n_avg_load * 2.0 - 1.5
    else: lg[6] = -6.0

    if self_load < 0.35 and (iso_ratio > 0.25 or deg_ratio > 0.20): # 7
        lg[7] = (0.35 - self_load) * 10.0 + iso_ratio * 4.0 + deg_ratio * 3.0 - 1.0
    else: lg[7] = -6.0

    if not (integrity_ok > 0.5) or flags["auth_attack"] or n_max_threat > 0.45: # 8
        lg[8] = (1.0 - integrity_ok) * 4.0 + failed_auth * 3.0 + n_max_threat * 2.5 - 1.0
    else: lg[8] = -6.0

    if failed_auth > 0.30: # 9
        lg[9] = failed_auth * 6.0 + n_fail_avg * 2.0 - 1.0
    else: lg[9] = -6.0

    if integrity_ok < 0.5: # 10 
        lg[10] = (1.0 - integrity_ok) * 7.0 - 1.0
    else: lg[10] = -6.0

    if susp_r > 0.15: # 11
        lg[11] = susp_r * 6.0 + has_susp * 1.5 - 0.5
    else: lg[11] = -6.0

    if flags["isolation_risk"]: # 12
        lg[12] = iso_ratio * 6.0 + n_max_threat * 2.5 - 0.5
    else: lg[12] = -6.0

    if flags["healthy_state"]: # 13
        lg[13] = integrity_ok * 2.0 + (1.0 - iso_ratio) * 1.0
    else: lg[13] = -6.0

    if rec_ratio > 0.3 and integrity_ok > 0.8: # 14
        lg[14] = rec_ratio * 2.5
    else: lg[14] = -7.0

    return lg


def adaptive_expert_weight(mlp_probs: torch.Tensor) -> float:
    eps = 1e-9
    entropy = -torch.sum(mlp_probs * torch.log(mlp_probs + eps)).item()
    max_entropy = math.log(N_CLASSES)
    normalized_entropy = min(max(entropy / max_entropy, 0.0), 1.0)

    activation = 1.0 / (1.0 + math.exp(-ENTROPY_SHARPNESS * (normalized_entropy - ENTROPY_MIDPOINT)))
    return EXPERT_WEIGHT_MIN + (EXPERT_WEIGHT_MAX - EXPERT_WEIGHT_MIN) * activation


class MLP(nn.Module):
    def __init__(self, seed: int = 42):
        super().__init__()
        
        if seed is not None:
            torch.manual_seed(seed)

        self.fc1 = nn.Linear(INPUT_DIM, HIDDEN1)
        self.ln1 = nn.LayerNorm(HIDDEN1, eps=1e-6)

        self.fc2 = nn.Linear(HIDDEN1, HIDDEN2)
        self.ln2 = nn.LayerNorm(HIDDEN2, eps=1e-6)

        # КЛАССИФИКАЦИЯ
        self.fc3_class = nn.Linear(HIDDEN2, HIDDEN3)
        self.ln3_class = nn.LayerNorm(HIDDEN3, eps=1e-6)
        self.fc4_class = nn.Linear(HIDDEN3, N_CLASSES)

        # ОЦЕНКА УГРОЗЫ
        self.fc3_threat = nn.Linear(HIDDEN2, THREAT_HIDDEN)
        self.ln3_threat = nn.LayerNorm(THREAT_HIDDEN, eps=1e-6)
        self.fc4_threat = nn.Linear(THREAT_HIDDEN, 1)

        self._init_weights()
        self._structural_init()

    def _init_weights(self):
        for m in [self.fc1, self.fc2, self.fc3_class, self.fc3_threat]:
            nn.init.xavier_uniform_(m.weight, gain=1.0)
            nn.init.zeros_(m.bias)
            
        for m in [self.fc4_class, self.fc4_threat]:
            nn.init.xavier_uniform_(m.weight, gain=0.5)
            nn.init.zeros_(m.bias)

    @torch.no_grad()
    def _structural_init(self):
        S = 1.5 
        M = 0.8
        N = -0.9
        
        W1_data = self.fc1.weight.data.T
        
        for i in range(0, 23):
            W1_data[0, i] += S
            W1_data[1, i] += M
            W1_data[8, i] += M
            W1_data[22, i] += S
            W1_data[16, i] += M
            W1_data[26, i] += N
            W1_data[2, i] += M * 0.5

        for i in range(23, 46):
            W1_data[26, i] += S
            W1_data[27, i] += S
            W1_data[0, i] += N
            W1_data[8, i] += M
            W1_data[7, i] += M
            W1_data[11, i] += M
            W1_data[19, i] += M

        for i in range(46, 72):
            W1_data[2, i] += N
            W1_data[4, i] += S
            W1_data[18, i] += S
            W1_data[9, i] += M
            W1_data[21, i] += M
            W1_data[25, i] += S
            W1_data[22, i] += M
            W1_data[10, i] += M

        for i in range(72, 95):
            W1_data[7, i] += S
            W1_data[14, i] += M
            W1_data[15, i] += S
            W1_data[23, i] += S
            W1_data[24, i] += M
            W1_data[17, i] += M

        for i in range(95, 128):
            W1_data[2, i] += S
            W1_data[12, i] += S
            W1_data[9, i] += N
            W1_data[15, i] += N
            W1_data[4, i] += N
            W1_data[7, i] += N
            W1_data[28, i] += N

        for c_idx in [1, 2, 3, 4]: 
            self.fc4_class.bias.data[c_idx] -= 0.5
            
        for c_idx in [5, 6, 7]: 
            self.fc4_class.bias.data[c_idx] -= 0.8
            
        for c_idx in [8, 9, 10, 11, 12, 13]:
            self.fc4_class.bias.data[c_idx] -= 1.5
            
        for c_idx in [14, 15]: 
            self.fc4_class.bias.data[c_idx] -= 1.5
            
        self.fc4_class.bias.data[0] += 0.5
        
    def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        h1 = F.relu(self.ln1(self.fc1(x)))
        h2 = F.relu(self.ln2(self.fc2(h1)))
        
        h3_c = F.relu(self.ln3_class(self.fc3_class(h2))) 
        logits_class = self.fc4_class(h3_c)
        
        h3_t = F.relu(self.ln3_threat(self.fc3_threat(h2))) 
        logits_threat = self.fc4_threat(h3_t)
        
        return logits_class, logits_threat

    def predict(self, f: torch.Tensor, flags: dict, prev_state: str, time_in_state: int) -> tuple[torch.Tensor, float, float]:
        biased_expert_logits = apply_expert_soft_bias(expert_logits(flags), flags)
        expert_probs = F.softmax(biased_expert_logits, dim=-1)

        try:
            with torch.no_grad():
                mlp_logits_c, mlp_logits_t = self.forward(f)
                raw_mlp_probs = F.softmax(mlp_logits_c, dim=-1)
                
                mlp_probs = apply_bayesian_update(raw_mlp_probs, prev_state, time_in_state)
                mlp_threat = torch.sigmoid(torch.clamp(mlp_logits_t, -250, 250))[0].item()

                expert_weight = adaptive_expert_weight(mlp_probs)
                final_probs = expert_weight * expert_probs + (1.0 - expert_weight) * mlp_probs

            return final_probs, mlp_threat, expert_weight

        except Exception as e:
            logger.warning(f"MLP forward failed, falling back to expert-only ({e})")
            return expert_probs, 1.0, EXPERT_WEIGHT_ON_ERROR

    def save(self, path: str):
        torch.save(self.state_dict(), path)

    def load(self, path: str):
        self.load_state_dict(torch.load(path, map_location='cpu', weights_only=True))

# 5. THREAT SCORE
def compute_threat(probs: torch.Tensor, flags: dict) -> float:
    base = torch.dot(probs, CLASS_THREATS).item()
    bonus = 0.0
    if flags["integrity_ok"] < 0.5:   bonus += 0.25
    if flags["failed_auth"] > 0.5:    bonus += 0.15
    if flags["isolation_risk"]:       bonus += 0.10
    if flags["auth_anomaly"] > 0.7:   bonus += 0.10
    if flags["susp_r"] > 0.5:         bonus += 0.08

    return round(min(base + bonus, 1.0), 4)

# 6. ГИСТЕРЕЗИС
def apply_bayesian_update(mlp_probs: torch.Tensor, prev_state: str, time_in_state: int) -> torch.Tensor:
    try:
        curr_idx = CLASS_NAMES.index(prev_state)
    except ValueError:
        return mlp_probs

    prior = torch.full((N_CLASSES,), 0.01, dtype=torch.float32) # базовая вероятность для всех классов
    
    if prev_state in ["malware_detected", "integrity_violation", "peer_consensus_isolation"]:
        confidence = min(0.5 + time_in_state / 20.0, 0.95) # Угрозы сильнее
    elif prev_state in ["high_load_hardware_strain", "high_load_network_overload"]:
        confidence = max(0.2, 0.6 - (time_in_state / 30.0)) # Нагрузка со временем спадает
    else:
        confidence = min(0.4 + time_in_state / 40.0, 0.85) # Нормальные состояния стабильны
        
    prior[curr_idx] = confidence
    prior = prior / prior.sum()

    likelihood = mlp_probs
    unnormalized_posterior = likelihood * prior

    evidence = unnormalized_posterior.sum()
    if evidence > 1e-9:
        posterior = unnormalized_posterior / evidence
    else:
        posterior = likelihood
        
    return posterior

# 7. МЯГКАЯ КОРРЕКТИРОВКА
def apply_expert_soft_bias(logits: torch.Tensor, flags: dict) -> torch.Tensor:
    lg = logits.clone()

    if flags["hardware_strain"] and flags["self_temp"] > 0.65:
        lg[1] += 1.4

    if flags["iso_ratio"] > 0.35 or flags["deg_ratio"] > 0.25:
        lg[3] += 1.1

    if flags["auth_anomaly"] > 0.45:
        lg[4] += 1.3

    return lg

def refine_load_class(class_name: str, flags: dict) -> str:
    high_set = {
        "high_load_hardware_strain", "high_load_network_overload",
        "high_load_neighbor_failure_relay", "high_load_anomalous_activity",
    }
    low_set = {
        "load_below_normal", "load_on_network_has_increased",
        "low_load_neighbor_failure_relay",
    }

    if class_name in high_set:
        if flags["self_temp"] > 0.65: return "high_load_hardware_strain"
        if flags["iso_ratio"] > 0.35 or flags["deg_ratio"] > 0.25: return "high_load_neighbor_failure_relay"
        if flags["auth_anomaly"] > 0.45: return "high_load_anomalous_activity"
        if flags["n_avg_load"] > 0.55: return "high_load_network_overload"
        return "high_load_hardware_strain"

    if class_name in low_set:
        if flags["n_avg_load"] > flags["self_load"] + 0.20 and flags["n_avg_load"] > 0.55:
            return "load_on_network_has_increased"
        if flags["iso_ratio"] > 0.25 or flags["deg_ratio"] > 0.20:
            return "low_load_neighbor_failure_relay"
        return "load_below_normal"

    return class_name

def emergency_override(class_name: str, ai_action: str, flags: dict) -> tuple[str, str, bool]:
    safety_activation = 1.0 / (1.0 + math.exp(-20.0 * (flags["self_temp"] - 0.85)))

    if safety_activation > 0.5 and flags["critical_strain"]:
        return (
            "reduce_load",
            f"Emergency safety circuit engaged ({safety_activation:.2%}). "
            f"Critical hardware temperature detected.",
            True,
        )

    if flags["integrity_critical"]:
        return (
            "enter_isolation",
            "Emergency safety circuit engaged. Node integrity validation failure.",
            True,
        )

    return ai_action, CLASS_REASONS.get(class_name, "Unknown event"), False

# 8. ГЛАВНЫЙ ЦИКЛ
def make_output(inp: dict, mlp: MLP) -> dict:
    f = build_features(inp)
    flags = extract_semantic_flags(f)

    state_reason = inp.get("ai_state_reason", "normal_operation")
    time_in_state = inp.get("time_in_state_sec", 0)

    probs, raw_threat, expert_weight = mlp.predict(f, flags, state_reason, time_in_state)

    top_idx = int(torch.argmax(probs).item())
    class_name = CLASS_NAMES[top_idx]
    confidence = float(probs[top_idx].item())

    class_name = refine_load_class(class_name, flags)
    ai_suggested_action = CLASS_ACTIONS.get(class_name, "do_nothing")

    final_action, reason, overridden = emergency_override(class_name, ai_suggested_action, flags)
    if overridden:
        reason = f"{reason} AI class: {class_name}. Forced action: {final_action}"

    prev_threat = float(inp.get("previous_threat_score", raw_threat))
    heuristic_threat = compute_threat(probs, flags)
    blended_threat = expert_weight * heuristic_threat + (1.0 - expert_weight) * raw_threat

    alpha = 0.3  
    if blended_threat > prev_threat:
        alpha = 0.8
    final_threat = (alpha * blended_threat) + ((1.0 - alpha) * prev_threat)

    return {
        "threat_score": round(float(final_threat), 4),
        "predicted_state": class_name,
        "recommended_action": final_action,
        "event_reason": reason,
        "confidence": round(confidence, 4),
    }

def main():
    mlp = MLP(seed=42)
    mlp.eval()

    weights_path = os.path.join(os.path.dirname(__file__), "weights.pth")
    if os.path.exists(weights_path):
        try:
            mlp.load(weights_path)
            logger.info(f"Loaded trained PyTorch weights from {weights_path}")
        except Exception as e:
            logger.warning(f"Could not load weights ({e}), using init")

    logger.info(f"[AI] Node Classifier v7 — Expert weight ∈ [{EXPERT_WEIGHT_MIN}; {EXPERT_WEIGHT_MAX}] | {INPUT_DIM}→{HIDDEN1}→{HIDDEN2}→{HIDDEN3}→{N_CLASSES} | {N_CLASSES} classes")

    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            data = json.loads(raw)
            out = make_output(data, mlp)
            print(json.dumps(out), flush=True)
        except Exception as e:
            fallback = {
                "threat_score": 0.0,
                "predicted_state": f"error:{e}",
                "recommended_action": "do_nothing",
                "event_reason": f"Model error: {e}",
                "confidence": 0.0,
            }
            print(json.dumps(fallback), flush=True)
            logger.info(f"[AI ERROR] {e} | {raw[:200]}")

if __name__ == "__main__":
    main()