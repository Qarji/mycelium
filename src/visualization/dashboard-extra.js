const DashboardExtra = (() => {
    const MAX_TICK_HISTORY = 240;
    const MAX_LOAD_HEATMAP_TICKS = 80;
    const MODE_COLOR = {
        Normal: "#1dc943", Throttled: "#1976d2", Boosted: "#fbc02d",
        Degraded: "#f57c00", Isolated: "#d32f2f", Reconnecting: "#8e63d4",
    };

    // --- состояние ---
    let consensusHistory = [];
    let loadHeatmap = []; 
    let utilizationHistory = [];
    let aiHistory = [];
    let bridgeHistory = [];
    let knownNodeIds = [];
    let seenTicks = new Set();

    const STORAGE_KEY = 'simDashboardExtraState';
    const SAVE_DEBOUNCE_MS = 800;
    let saveTimer = null;

    function scheduleSave() {
        if (saveTimer) clearTimeout(saveTimer);
        saveTimer = setTimeout(persistState, SAVE_DEBOUNCE_MS);
    }

    function persistState() {
        try {
            sessionStorage.setItem(STORAGE_KEY, JSON.stringify({
                consensusHistory, loadHeatmap, utilizationHistory, aiHistory, bridgeHistory,
                knownNodeIds, seenTicks: Array.from(seenTicks),
            }));
        } catch (e) {
            console.warn('DashboardExtra.persistState failed:', e);
        }
    }

    function restoreState() {
        try {
            const raw = sessionStorage.getItem(STORAGE_KEY);
            if (!raw) return false;
            const s = JSON.parse(raw);
            consensusHistory = Array.isArray(s.consensusHistory) ? s.consensusHistory : [];
            loadHeatmap = Array.isArray(s.loadHeatmap) ? s.loadHeatmap : [];
            utilizationHistory = Array.isArray(s.utilizationHistory) ? s.utilizationHistory : [];
            aiHistory = Array.isArray(s.aiHistory) ? s.aiHistory : [];
            bridgeHistory = Array.isArray(s.bridgeHistory) ? s.bridgeHistory : [];
            knownNodeIds = Array.isArray(s.knownNodeIds) ? s.knownNodeIds : [];
            seenTicks = new Set(Array.isArray(s.seenTicks) ? s.seenTicks : []);
            renderAll();
            return true;
        } catch (e) {
            console.warn('DashboardExtra.restoreState failed:', e);
            return false;
        }
    }

    function clearPersisted() {
        if (saveTimer) { clearTimeout(saveTimer); saveTimer = null; }
        try { sessionStorage.removeItem(STORAGE_KEY); } catch (e) { /* ignore */ }
    }

    function reset() {
        consensusHistory = [];
        loadHeatmap = [];
        utilizationHistory = [];
        aiHistory = [];
        bridgeHistory = [];
        knownNodeIds = [];
        seenTicks = new Set();
        clearPersisted();
        renderAll();
    }

    // Совпадает по формату со строками из build_visual_state: "[T{tick}] Node {id}: {action} -> {allowed} ({reason})"
    const LOG_RE = /^\[T(\d+)\] Node (\d+): (\w+) -> (true|false) \((.*)\)$/;

    function ingest(data) {
        if (!data || !Array.isArray(data.nodes) || data.nodes.length === 0) return;
        if (seenTicks.has(data.tick)) {
            renderAll();
            return;
        }
        seenTicks.add(data.tick);

        if (knownNodeIds.length !== data.nodes.length) {
            knownNodeIds = data.nodes.map(n => n.id).sort((a, b) => a - b);
        }

        ingestConsensus(data);
        ingestHeatmap(data);
        ingestUtilization(data);
        ingestAiConfidence(data);
        ingestBridges(data);

        renderAll();
        scheduleSave();
    }

    // ---------- 1. Индекс распределённого консенсуса ----------
    function ingestConsensus(data) {
        const suspicionVotes = data.nodes.reduce((s, n) => s + (n.peer_suspicion_votes ?? 0), 0);
        const maxSuspicion = Math.max(0, ...data.nodes.map(n => n.peer_suspicion_votes ?? 0));

        const reduceVotes = data.nodes.filter(n => n.mode === "Throttled").length;
        const boostVotes = data.nodes.filter(n => n.mode === "Boosted").length;
        const neighborCountApprox = Math.max(1, data.nodes.length - 1);
        const majority = Math.floor(neighborCountApprox / 2) + 1;

        consensusHistory.push({
            tick: data.tick,
            reduceVotes, boostVotes,
            suspicionVotes, maxSuspicion,
            majority,
            hasBackendVotes: data.nodes.some(n => typeof n.peer_suspicion_votes === 'number'),
        });
        if (consensusHistory.length > MAX_TICK_HISTORY) consensusHistory.shift();
    }

    // ---------- 2. Тепловая карта миграции нагрузки ----------
    function ingestHeatmap(data) {
        loadHeatmap.push({
            tick: data.tick,
            nodes: data.nodes.map(n => ({ id: n.id, load: n.load, mode: n.mode })),
        });
        if (loadHeatmap.length > MAX_LOAD_HEATMAP_TICKS) loadHeatmap.shift();
    }

    // ---------- 3. Давление на сеть (gauge) ----------
    function ingestUtilization(data) {
        const hasBackendField = typeof data.network_utilization === 'number';
        const utilization = hasBackendField ? data.network_utilization : approxUtilization(data.nodes);
        const starving = typeof data.network_starving === 'boolean'
            ? data.network_starving
            : data.nodes.filter(n => n.mode === "Boosted").length > data.nodes.length / 2;

        utilizationHistory.push({ tick: data.tick, utilization, starving, isApprox: !hasBackendField });
        if (utilizationHistory.length > MAX_TICK_HISTORY) utilizationHistory.shift();
    }
    function approxUtilization(nodes) {
        const BOOST_CEILING_FALLBACK = 100;
        const total = nodes.reduce((s, n) => s + n.load, 0);
        const capacity = nodes.length * BOOST_CEILING_FALLBACK;
        return capacity > 0 ? total / capacity : 0;
    }

    // ---------- 4. Уверенность ИИ vs Фактическая угроза ----------
    function ingestAiConfidence(data) {
        const hasConfidence = data.nodes.some(n => typeof n.confidence === 'number');
        const threats = data.nodes.map(n => n.threat || 0);
        const avgThreat = threats.reduce((a, b) => a + b, 0) / threats.length;

        let avgConfidence = null;
        let fallbackCount = 0;
        if (hasConfidence) {
            const confidences = data.nodes.map(n => n.confidence ?? 0);
            avgConfidence = confidences.reduce((a, b) => a + b, 0) / confidences.length;
            fallbackCount = data.nodes.filter(n => isFallbackReason(n.ai_state_reason)).length;
        }

        aiHistory.push({ tick: data.tick, avgThreat, avgConfidence, fallbackCount, hasConfidence });
        if (aiHistory.length > MAX_TICK_HISTORY) aiHistory.shift();
    }
    const FALLBACK_REASONS = new Set([
        "malware_detected", "auth_bruteforce_detected", "integrity_violation",
        "peer_consensus_isolation", "neighbor_cascade_failure", "reconnect_timeout_failure",
    ]);
    function isFallbackReason(reason) {
        return !!reason && FALLBACK_REASONS.has(reason);
    }

    // ---------- 5. Восстановление топологии: виртуальные мосты ----------
    function ingestBridges(data) {
        const edges = data.edges || [];
        const physicalActive = edges.filter(e => !e.virtual_link).length;
        const virtualActive = edges.filter(e => e.virtual_link).length;
        const isolatedCount = data.nodes.filter(n => n.mode === "Isolated" || n.mode === "Reconnecting").length;

        bridgeHistory.push({ tick: data.tick, physicalActive, virtualActive, isolatedCount });
        if (bridgeHistory.length > MAX_TICK_HISTORY) bridgeHistory.shift();
    }

    // ---------- утилиты canvas (тот же паттерн, что в dashboard.js) ----------
    function prepCanvas(id) {
        const canvas = document.getElementById(id);
        if (!canvas) return null;
        const parent = canvas.parentElement;
        const cssWidth = parent.clientWidth;
        const cssHeight = canvas.classList.contains('tall') ? 260 : 200;
        const dpr = window.devicePixelRatio || 1;
        canvas.style.height = cssHeight + 'px';
        canvas.width = Math.max(1, Math.floor(cssWidth * dpr));
        canvas.height = Math.max(1, Math.floor(cssHeight * dpr));
        const ctx = canvas.getContext('2d');
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        return { ctx, w: cssWidth, h: cssHeight };
    }

    function emptyState(ctx, w, h, text) {
        ctx.fillStyle = "#4a4a4a";
        ctx.font = "12px Consolas, monospace";
        ctx.textAlign = "center";
        ctx.fillText(text, w / 2, h / 2);
    }

    function drawGrid(ctx, w, h, rows = 4, padLeft = 38) {
        ctx.strokeStyle = "#262626";
        ctx.lineWidth = 1;
        for (let i = 0; i <= rows; i++) {
            const y = 10 + (h - 30) * (i / rows);
            ctx.beginPath();
            ctx.moveTo(padLeft, y);
            ctx.lineTo(w - 8, y);
            ctx.stroke();
        }
    }

    function axisTicks(ctx, w, h, padLeft, plotW, firstTick, lastTick) {
        ctx.fillStyle = "#6e7681";
        ctx.font = "10px Consolas, monospace";
        ctx.textAlign = "left";
        ctx.fillText("t" + firstTick, padLeft, h - 4);
        ctx.textAlign = "right";
        ctx.fillText("t" + lastTick, w - 8, h - 4);
    }

    // ---------- 1. Индекс распределённого консенсуса — multi-line ----------
    function renderConsensus() {
        const p = prepCanvas('chart-consensus');
        if (!p) return;
        const { ctx, w, h } = p;
        ctx.clearRect(0, 0, w, h);
        if (consensusHistory.length < 2) return emptyState(ctx, w, h, "Ожидание данных симуляции…");

        const padTop = 10, padBottom = 20, padLeft = 32, padRight = 8;
        const plotH = h - padTop - padBottom;
        const plotW = w - padLeft - padRight;
        const n = consensusHistory.length;
        const slot = plotW / (n - 1);

        const maxVotes = Math.max(
            4,
            ...consensusHistory.map(c => Math.max(c.reduceVotes, c.boostVotes, c.maxSuspicion, c.majority))
        );
        const yOf = (v) => padTop + plotH * (1 - v / maxVotes);

        drawGrid(ctx, w, h, 4, padLeft);
        ctx.fillStyle = "#565656";
        ctx.font = "10px Consolas, monospace";
        ctx.textAlign = "right";
        for (let i = 0; i <= 4; i++) {
            const v = maxVotes * (1 - i / 4);
            ctx.fillText(Math.round(v), padLeft - 6, padTop + plotH * (i / 4) + 3);
        }

        const series = [
            { key: 'reduceVotes', color: '#1976d2' },
            { key: 'boostVotes', color: '#fbc02d' },
            { key: 'suspicionVotes', color: '#d32f2f' },
        ];
        series.forEach(({ key, color }) => {
            ctx.strokeStyle = color;
            ctx.lineWidth = 1.8;
            ctx.beginPath();
            consensusHistory.forEach((c, i) => {
                const x = padLeft + slot * i;
                const y = yOf(c[key]);
                if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
            });
            ctx.stroke();
        });

        axisTicks(ctx, w, h, padLeft, plotW, consensusHistory[0].tick, consensusHistory[n - 1].tick);

        if (!consensusHistory[n - 1].hasBackendVotes) {
            ctx.fillStyle = "#6e7681";
            ctx.font = "9px Consolas, monospace";
            ctx.textAlign = "left";
            ctx.fillText("⚠ peer_suspicion_votes не получен от сервера — линия голосов подозрения приближена нулём", padLeft, padTop + 10);
        }

        renderConsensusLegend();
    }
    function renderConsensusLegend() {
        const el = document.getElementById('consensus-legend');
        if (!el) return;
        el.innerHTML = `
            <span><i class="dot" style="background:#1976d2"></i>ReduceLoad (узлов в Throttled)</span>
            <span><i class="dot" style="background:#fbc02d"></i>BoostLoad (узлов в Boosted)</span>
            <span><i class="dot" style="background:#d32f2f"></i>PeerSuspicion (голосов получено)</span>
        `;
    }

    // ---------- 2. Тепловая карта миграции нагрузки ----------
    function renderHeatmap() {
        const p = prepCanvas('chart-heatmap');
        if (!p) return;
        const { ctx, w, h } = p;
        ctx.clearRect(0, 0, w, h);
        if (loadHeatmap.length < 2 || knownNodeIds.length === 0) return emptyState(ctx, w, h, "Ожидание данных симуляции…");

        const padTop = 10, padBottom = 20, padLeft = 34, padRight = 8;
        const plotH = h - padTop - padBottom;
        const plotW = w - padLeft - padRight;
        const rows = knownNodeIds.length;
        const cols = loadHeatmap.length;
        const cellW = plotW / cols;
        const cellH = plotH / rows;

        ctx.fillStyle = "#565656";
        ctx.font = "9px Consolas, monospace";
        ctx.textAlign = "right";
        knownNodeIds.forEach((id, r) => {
            ctx.fillText("#" + id, padLeft - 5, padTop + cellH * r + cellH * 0.65);
        });

        loadHeatmap.forEach((snap, c) => {
            const byId = new Map(snap.nodes.map(n => [n.id, n]));
            knownNodeIds.forEach((id, r) => {
                const node = byId.get(id);
                const x = padLeft + cellW * c;
                const y = padTop + cellH * r;
                if (!node) {
                    ctx.fillStyle = "#141414";
                    ctx.fillRect(x, y, Math.ceil(cellW), Math.ceil(cellH));
                    return;
                }
                ctx.fillStyle = loadToColor(node.load, node.mode);
                ctx.fillRect(x, y, Math.ceil(cellW), Math.ceil(cellH));
            });
        });

        // Разделительные линии между строками узлов — помогает глазу вести по ID
        ctx.strokeStyle = "#101010";
        ctx.lineWidth = 1;
        for (let r = 0; r <= rows; r++) {
            const y = padTop + cellH * r;
            ctx.beginPath();
            ctx.moveTo(padLeft, y);
            ctx.lineTo(padLeft + plotW, y);
            ctx.stroke();
        }

        axisTicks(ctx, w, h, padLeft, plotW, loadHeatmap[0].tick, loadHeatmap[cols - 1].tick);
        renderHeatmapLegend();
    }
    // как "волна" тёплого цвета, расходящаяся от узла, ушедшего в изоляцию.
    function loadToColor(load, mode) {
        if (mode === "Isolated") return "#3a1a4a";
        if (mode === "Reconnecting") return "#5a3a8a";
        const t = Math.max(0, Math.min(1, load / 255));
        // 0 -> #1976d2 (синий), 0.5 -> #fbc02d (жёлтый), 1 -> #d32f2f (красный)
        if (t < 0.3) {
            return lerpColor("#1976d2", "#fbc02d", t / 0.3);
        }
        return lerpColor("#fbc02d", "#d32f2f", (t - 0.3) / 0.3);
    }
    function lerpColor(a, b, t) {
        const ca = hexToRgb(a), cb = hexToRgb(b);
        const r = Math.round(ca.r + (cb.r - ca.r) * t);
        const g = Math.round(ca.g + (cb.g - ca.g) * t);
        const bch = Math.round(ca.b + (cb.b - ca.b) * t);
        return `rgb(${r},${g},${bch})`;
    }
    function hexToRgb(hex) {
        const v = parseInt(hex.slice(1), 16);
        return { r: (v >> 16) & 255, g: (v >> 8) & 255, b: v & 255 };
    }
    function renderHeatmapLegend() {
        const el = document.getElementById('heatmap-legend');
        if (!el) return;
        el.innerHTML = `
            <span><i class="dot" style="background:#1976d2"></i>низкая нагрузка</span>
            <span><i class="dot" style="background:#fbc02d"></i>средняя нагрузка</span>
            <span><i class="dot" style="background:#d32f2f"></i>высокая нагрузка</span>
            <span><i class="dot" style="background:#3a1a4a"></i>Изоляция</span>
        `;
    }

    // ---------- 3. Давление на сеть — gauge ----------
    function renderGauge() {
        const p = prepCanvas('chart-gauge');
        if (!p) return;
        const { ctx, w, h } = p;
        ctx.clearRect(0, 0, w, h);
        if (utilizationHistory.length === 0) return emptyState(ctx, w, h, "Ожидание данных симуляции…");

        const latest = utilizationHistory[utilizationHistory.length - 1];
        const rawLoad = latest.utilization * 100; 
        
        function getSigmoidProgress(x) {
            return 1 / (1 + Math.exp(-(x - 70) / 45));
        }

        const util = getSigmoidProgress(rawLoad);
        const utilVisual = util;
        const scale = 0.95; 
        const cx = w / 2;
        const cyc = h * 0.58; 
        const radius = Math.min(w * 0.34, h * 0.5) * scale;
        const a0 = degToRad(135), a1 = degToRad(405);

        const zones = [
            { from: 0.0, to: 0.3, color: "#29b6f6" }, // Недостаток (<30%)
            { from: 0.3, to: 0.7, color: "#1dc943" }, // Норма (30%-70%)
            { from: 0.7, to: 0.85, color: "#fbc02d" }, // Перегруз (70%-85%)
            { from: 0.85, to: 1.0, color: "#d32f2f" }, // Крит (85%-100%)
        ];
        const trackW = Math.max(10, radius * 0.22);

        zones.forEach(z => {
            ctx.beginPath();
            ctx.strokeStyle = z.color;
            ctx.globalAlpha = 0.35;
            ctx.lineWidth = trackW;
            ctx.arc(cx, cyc, radius, a0 + (a1 - a0) * z.from, a0 + (a1 - a0) * z.to);
            ctx.stroke();
            ctx.globalAlpha = 1;
        });

        // Логика статусов на основе новых линейных порогов
        let activeColor = "#1dc943";
        let statusText = "ШТАТНЫЙ РЕЖИМ";
        
        if (util < 0.3) {
            activeColor = "#29b6f6";
            statusText = "НЕДОСТАТОК НАГРУЗКИ";
        } else if (util > 0.7 && util <= 0.85) {
            activeColor = "#fbc02d";
            statusText = "ПЕРЕГРУЗКА";
        } else if (util > 0.85) {
            activeColor = "#d32f2f";
            statusText = "КРИТИЧЕСКАЯ ПЕРЕГРУЗКА";
        }

        if (latest.starving && util >= 0.3 && util <= 0.7) {
            statusText = "ПАДЕНИЕ НАГРУЗКИ";
        }

        // Активная дуга
        ctx.beginPath();
        ctx.strokeStyle = activeColor;
        ctx.lineWidth = trackW;
        ctx.lineCap = "round";
        ctx.arc(cx, cyc, radius, a0, a0 + (a1 - a0) * utilVisual);
        ctx.stroke();
        ctx.lineCap = "butt";

        // Стрелка
        const needleAngle = a0 + (a1 - a0) * utilVisual;
        const nx = cx + Math.cos(needleAngle) * (radius - trackW * 0.7);
        const ny = cyc + Math.sin(needleAngle) * (radius - trackW * 0.7);
        ctx.beginPath();
        ctx.strokeStyle = "#e4e4e4";
        ctx.lineWidth = 2;
        ctx.moveTo(cx, cyc);
        ctx.lineTo(nx, ny);
        ctx.stroke();
        ctx.beginPath();
        ctx.fillStyle = "#e4e4e4";
        ctx.arc(cx, cyc, 4, 0, Math.PI * 2);
        ctx.fill();

        ctx.fillStyle = "#e4e4e4";
        ctx.font = "bold 26px Consolas, monospace";
        ctx.textAlign = "center";
        ctx.fillText(Math.round(util * 100) + "%", cx, cyc + radius * 0.45);

        // Статус под спидометром
        ctx.font = "14px Consolas, monospace";
        ctx.fillStyle = activeColor === "#d32f2f" ? "#ffffff"
            : (activeColor === "#fbc02d" ? "#ffe082" 
            : (activeColor === "#29b6f6" ? "#b3e5fc" : "#a5d6a7"));
            
        ctx.fillText(statusText, cx, cyc + radius * 0.55 + 18);

        if (latest.isApprox) {
            ctx.font = "14px Consolas, monospace";
            ctx.fillStyle = "#6e7681";
            ctx.fillText("⚠ приближено на клиенте — сервер ещё не шлёт network_utilization", cx, h - 6);
        }
    }
    function degToRad(d) { return d * Math.PI / 180; }

    // ---------- 4. Уверенность ИИ vs фактическая угроза ----------
    function renderAiConfidence() {
        const p = prepCanvas('chart-ai-confidence');
        if (!p) return;
        const { ctx, w, h } = p;
        ctx.clearRect(0, 0, w, h);
        if (aiHistory.length < 2) return emptyState(ctx, w, h, "Ожидание данных симуляции…");

        const padTop = 10, padBottom = 20, padLeft = 32, padRight = 8;
        const plotH = h - padTop - padBottom;
        const plotW = w - padLeft - padRight;
        const n = aiHistory.length;
        const slot = plotW / (n - 1);
        const yOf = (v) => padTop + plotH * (1 - Math.max(0, Math.min(1, v)));

        drawGrid(ctx, w, h, 4, padLeft);
        ctx.fillStyle = "#565656";
        ctx.font = "10px Consolas, monospace";
        ctx.textAlign = "right";
        ["1.0", "0.75", "0.5", "0.25", "0.0"].forEach((lbl, i) => {
            ctx.fillText(lbl, padLeft - 6, padTop + plotH * (i / 4) + 3);
        });

        ctx.strokeStyle = "#d32f2f";
        ctx.lineWidth = 1.8;
        ctx.beginPath();
        aiHistory.forEach((a, i) => {
            const x = padLeft + slot * i;
            const y = yOf(a.avgThreat);
            if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
        });
        ctx.stroke();

        const hasConfidence = aiHistory.some(a => a.hasConfidence);
        if (hasConfidence) {
            ctx.strokeStyle = "#4fc1ff";
            ctx.lineWidth = 1.8;
            ctx.beginPath();
            let started = false;
            aiHistory.forEach((a, i) => {
                if (a.avgConfidence === null) return;
                const x = padLeft + slot * i;
                const y = yOf(a.avgConfidence);
                if (!started) { ctx.moveTo(x, y); started = true; } else { ctx.lineTo(x, y); }
            });
            ctx.stroke();

            ctx.fillStyle = "#ff9800";
            aiHistory.forEach((a, i) => {
                if (!a.fallbackCount) return;
                const x = padLeft + slot * i;
                const y = yOf(a.avgThreat);
                ctx.beginPath();
                ctx.arc(x, y, 3 + Math.min(4, a.fallbackCount), 0, Math.PI * 2);
                ctx.globalAlpha = 0.7;
                ctx.fill();
                ctx.globalAlpha = 1;
            });
        }

        axisTicks(ctx, w, h, padLeft, plotW, aiHistory[0].tick, aiHistory[n - 1].tick);

        if (!hasConfidence) {
            ctx.fillStyle = "#6e7681";
            ctx.font = "9px Consolas, monospace";
            ctx.textAlign = "left";
            ctx.fillText("⚠ confidence не получен от сервера — показана только угроза", padLeft, padTop + 10);
        }

        renderAiConfidenceLegend();
    }
    function renderAiConfidenceLegend() {
        const el = document.getElementById('ai-confidence-legend');
        if (!el) return;
        el.innerHTML = `
            <span><i class="dot" style="background:#d32f2f"></i>средняя угроза</span>
            <span><i class="dot" style="background:#4fc1ff"></i>средняя уверенность ИИ</span>
            <span><i class="dot" style="background:#ff9800"></i>сработал фолбек оценки угрозы соседа</span>
        `;
    }

    // ---------- 5. Восстановление топологии: виртуальные мосты — stacked area ----------
    function renderBridges() {
        const p = prepCanvas('chart-bridges');
        if (!p) return;
        const { ctx, w, h } = p;
        ctx.clearRect(0, 0, w, h);
        if (bridgeHistory.length < 2) return emptyState(ctx, w, h, "Ожидание данных симуляции…");

        const padTop = 10, padBottom = 20, padLeft = 34, padRight = 8;
        const plotH = h - padTop - padBottom;
        const plotW = w - padLeft - padRight;
        const n = bridgeHistory.length;
        const slot = plotW / (n - 1);

        const maxTotal = Math.max(1, ...bridgeHistory.map(b => b.physicalActive + b.virtualActive));
        const yOf = (v) => padTop + plotH * (1 - v / maxTotal);

        drawGrid(ctx, w, h, 4, padLeft);
        ctx.fillStyle = "#565656";
        ctx.font = "10px Consolas, monospace";
        ctx.textAlign = "right";
        for (let i = 0; i <= 4; i++) {
            const v = maxTotal * (1 - i / 4);
            ctx.fillText(Math.round(v), padLeft - 6, padTop + plotH * (i / 4) + 3);
        }

        // Площадь физических связей (низ стека)
        ctx.fillStyle = "#9e9e9e";
        ctx.globalAlpha = 0.55;
        ctx.beginPath();
        bridgeHistory.forEach((b, i) => {
            const x = padLeft + slot * i;
            const y = yOf(b.physicalActive);
            if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
        });
        ctx.lineTo(padLeft + slot * (n - 1), yOf(0));
        ctx.lineTo(padLeft, yOf(0));
        ctx.closePath();
        ctx.fill();
        ctx.globalAlpha = 1;

        ctx.fillStyle = "#4fc1ff";
        ctx.globalAlpha = 0.55;
        ctx.beginPath();
        bridgeHistory.forEach((b, i) => {
            const x = padLeft + slot * i;
            const y = yOf(b.physicalActive + b.virtualActive);
            if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
        });
        for (let i = n - 1; i >= 0; i--) {
            const x = padLeft + slot * i;
            const y = yOf(bridgeHistory[i].physicalActive);
            ctx.lineTo(x, y);
        }
        ctx.closePath();
        ctx.fill();
        ctx.globalAlpha = 1;

        // Контурные линии поверх площадей для читаемости
        ctx.strokeStyle = "#cfcfcf";
        ctx.lineWidth = 1.2;
        ctx.beginPath();
        bridgeHistory.forEach((b, i) => {
            const x = padLeft + slot * i;
            const y = yOf(b.physicalActive);
            if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
        });
        ctx.stroke();

        ctx.strokeStyle = "#4fc1ff";
        ctx.lineWidth = 1.6;
        ctx.beginPath();
        bridgeHistory.forEach((b, i) => {
            const x = padLeft + slot * i;
            const y = yOf(b.physicalActive + b.virtualActive);
            if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
        });
        ctx.stroke();

        bridgeHistory.forEach((b, i) => {
            if (!b.isolatedCount) return;
            const x = padLeft + slot * i;
            ctx.fillStyle = "#d32f2f";
            ctx.beginPath();
            ctx.arc(x, padTop + plotH + 12, 2.5, 0, Math.PI * 2);
            ctx.fill();
        });

        axisTicks(ctx, w, h, padLeft, plotW, bridgeHistory[0].tick, bridgeHistory[n - 1].tick);
        renderBridgesLegend();
    }
    function renderBridgesLegend() {
        const el = document.getElementById('bridges-legend');
        if (!el) return;
        const latest = bridgeHistory[bridgeHistory.length - 1];
        el.innerHTML = `
            <span><i class="dot" style="background:#9e9e9e"></i>физические связи (${latest.physicalActive})</span>
            <span><i class="dot" style="background:#4fc1ff"></i>виртуальные мосты (${latest.virtualActive})</span>
            <span><i class="dot" style="background:#d32f2f"></i>тик с изолированным узлом</span>
        `;
    }

    function renderAll() {
        renderConsensus();
        renderHeatmap();
        renderGauge();
        renderAiConfidence();
        renderBridges();
    }

    let resizeTimer = null;
    window.addEventListener('resize', () => {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(renderAll, 150);
    });

    return { ingest, reset, renderAll, restoreState };
})();

DashboardExtra.restoreState();