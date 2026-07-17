// РАЗДЕЛ ИНФОГРАФИКИ (Dashboard)
const Dashboard = (() => {

    const MAX_TICK_HISTORY = 240;      // окно для свечей/площадей/скаттера
    const MODE_ORDER = ["Normal", "Throttled", "Boosted", "Degraded", "Isolated", "Reconnecting"];
    const MODE_COLOR = {
        Normal: "#1dc943", Throttled: "#1976d2", Boosted: "#fbc02d",
        Degraded: "#f57c00", Isolated: "#d32f2f", Reconnecting: "#8e63d4",
    };
    const ACTION_COLOR_OK = "#4caf50";
    const ACTION_COLOR_REJECT = "#f44336";
    const SOURCE_COLOR = {
        "ИИ-предсказание": "#4fc1ff",
        "Эвристика/соседи": "#fbc02d",
        "Детерминированный": "#8e8e8e",
        "Консенсус соседей": "#d32f2f",
    };

    // --- состояние, копится по мере поступления тиков ---
    let tickHistory = [];              // [{tick, avgLoad, minLoad, maxLoad, avgThreat, modeCounts:{}}]
    let decisionsByAction = {};        // { "ReduceLoad": {allowed, rejected}, ... }
    let decisionsBySource = {};        // { "ИИ-предсказание": n, ... }
    let totalDecisions = 0;
    let totalRejected = 0;
    let cascadesAllowed = 0;           // успешные санкционированные EnterIsolation (сработавший circuit breaker)
    let lastNodeMode = {};             // node_id -> текущий известный режим (для отслеживания переходов)
    let isolationStart = {};           // node_id -> tick входа в Isolated
    let recoveryEpisodes = [];         // [{nodeId, duration}]
    let lastNodesSnapshot = [];        // последний data.nodes как есть — для scatter
    let seenTicks = new Set();

    // --- персистентность состояния через sessionStorage (переживает F5,
    // чистится по Restart или при закрытии вкладки) ---
    const STORAGE_KEY = 'simDashboardState';
    const SAVE_DEBOUNCE_MS = 800;
    let saveTimer = null;

    function scheduleSave() {
        if (saveTimer) clearTimeout(saveTimer);
        saveTimer = setTimeout(persistState, SAVE_DEBOUNCE_MS);
    }

    function persistState() {
        try {
            sessionStorage.setItem(STORAGE_KEY, JSON.stringify({
                tickHistory, decisionsByAction, decisionsBySource,
                totalDecisions, totalRejected, cascadesAllowed,
                lastNodeMode, isolationStart, recoveryEpisodes,
                lastNodesSnapshot,
                seenTicks: Array.from(seenTicks),
            }));
        } catch (e) {
            console.warn('Dashboard.persistState failed:', e);
        }
    }

    function restoreState() {
        try {
            const raw = sessionStorage.getItem(STORAGE_KEY);
            if (!raw) return false;
            const s = JSON.parse(raw);
            tickHistory = Array.isArray(s.tickHistory) ? s.tickHistory : [];
            decisionsByAction = s.decisionsByAction || {};
            decisionsBySource = s.decisionsBySource || {};
            totalDecisions = s.totalDecisions || 0;
            totalRejected = s.totalRejected || 0;
            cascadesAllowed = s.cascadesAllowed || 0;
            lastNodeMode = s.lastNodeMode || {};
            isolationStart = s.isolationStart || {};
            recoveryEpisodes = Array.isArray(s.recoveryEpisodes) ? s.recoveryEpisodes : [];
            lastNodesSnapshot = Array.isArray(s.lastNodesSnapshot) ? s.lastNodesSnapshot : [];
            seenTicks = new Set(Array.isArray(s.seenTicks) ? s.seenTicks : []);
            renderAll();
            updateMetaBar();
            return true;
        } catch (e) {
            console.warn('Dashboard.restoreState failed:', e);
            return false;
        }
    }

    function clearPersisted() {
        if (saveTimer) { clearTimeout(saveTimer); saveTimer = null; }
        try { sessionStorage.removeItem(STORAGE_KEY); } catch (e) { /* ignore */ }
    }

    const LOG_RE = /^\[T(\d+)\] Node (\d+): (\w+) -> (true|false) \((.*)\)$/;

    function classifySource(reasonText) {
        const r = reasonText.toLowerCase();
        if (r.includes("reconnect") || r.includes("calibration hold") || r.includes("waiting for neighbor acks") || r.includes("recovery process") || r.includes("handshake")) {
            return "Детерминированный";
        }
        if (r.includes("neighbor") && (r.includes("voted") || r.includes("flagged") || r.includes("consensus"))) {
            return "Консенсус соседей";
        }
        if (r.includes("neighbor") || r.includes("redistribut") || r.includes("advisory") || r.includes("absorbing") || r.includes("headroom") || r.includes("network overloaded") || r.includes("network starving")) {
            return "Эвристика/соседи";
        }
        return "ИИ-предсказание";
    }

    function reset() {
        tickHistory = [];
        decisionsByAction = {};
        decisionsBySource = {};
        totalDecisions = 0;
        totalRejected = 0;
        cascadesAllowed = 0;
        lastNodeMode = {};
        isolationStart = {};
        recoveryEpisodes = [];
        lastNodesSnapshot = [];
        seenTicks = new Set();
        clearPersisted();
        renderAll();
        updateMetaBar();
    }

    function ingest(data) {
        if (!data || !Array.isArray(data.nodes) || data.nodes.length === 0) return;
        if (seenTicks.has(data.tick)) {
            lastNodesSnapshot = data.nodes;
            renderAll();
            return;
        }
        seenTicks.add(data.tick);

        // --- 1. агрегаты по узлам этого тика ---
        const loads = data.nodes.map(n => n.load);
        const threats = data.nodes.map(n => n.threat || 0);
        const modeCounts = {};
        MODE_ORDER.forEach(m => modeCounts[m] = 0);
        data.nodes.forEach(n => { modeCounts[n.mode] = (modeCounts[n.mode] || 0) + 1; });

        tickHistory.push({
            tick: data.tick,
            avgLoad: loads.reduce((a, b) => a + b, 0) / loads.length,
            minLoad: Math.min(...loads),
            maxLoad: Math.max(...loads),
            avgThreat: threats.reduce((a, b) => a + b, 0) / threats.length,
            modeCounts,
            total: data.nodes.length,
        });
        if (tickHistory.length > MAX_TICK_HISTORY) tickHistory.shift();

        lastNodesSnapshot = data.nodes;

        // --- 2. отслеживание переходов режима для эпизодов изоляции ---
        data.nodes.forEach(n => {
            const prev = lastNodeMode[n.id];
            if (prev !== n.mode) {
                if (n.mode === "Isolated") {
                    isolationStart[n.id] = data.tick;
                } else if (isolationStart[n.id] !== undefined) {
                    const duration = data.tick - isolationStart[n.id];
                    if (duration > 0) {
                        recoveryEpisodes.push({ nodeId: n.id, duration });
                        if (recoveryEpisodes.length > 40) recoveryEpisodes.shift();
                    }
                    delete isolationStart[n.id];
                }
                lastNodeMode[n.id] = n.mode;
            }
        });

        // --- 3. разбор логов решений этого тика ---
        (data.logs || []).forEach(line => {
            const m = LOG_RE.exec(line);
            if (!m) return;
            const [, , , action, allowedStr, reason] = m;
            const allowed = allowedStr === "true";

            if (!decisionsByAction[action]) decisionsByAction[action] = { allowed: 0, rejected: 0 };
            if (allowed) decisionsByAction[action].allowed++; else decisionsByAction[action].rejected++;

            totalDecisions++;
            if (!allowed) totalRejected++;
            if (allowed && action === "EnterIsolation") cascadesAllowed++;

            const src = classifySource(reason);
            decisionsBySource[src] = (decisionsBySource[src] || 0) + 1;
        });

        renderAll();
        updateMetaBar();
        scheduleSave();
    }

    function updateMetaBar() {
        setText("dm-ticks", tickHistory.length);
        setText("dm-decisions", totalDecisions);
        setText("dm-rejected", totalRejected);
        setText("dm-cascades", cascadesAllowed);
    }
    function setText(id, val) {
        const el = document.getElementById(id);
        if (el) el.textContent = val;
    }

    // ---------- утилиты canvas ----------
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

    function drawGrid(ctx, w, h, rows = 4) {
        ctx.strokeStyle = "#262626";
        ctx.lineWidth = 1;
        for (let i = 0; i <= rows; i++) {
            const y = 10 + (h - 30) * (i / rows);
            ctx.beginPath();
            ctx.moveTo(38, y);
            ctx.lineTo(w - 8, y);
            ctx.stroke();
        }
    }

    // ---------- A. Свечной график load + линия угрозы ----------
    function renderCandles() {
        const p = prepCanvas('chart-candles');
        if (!p) return;
        const { ctx, w, h } = p;
        ctx.clearRect(0, 0, w, h);
        if (tickHistory.length < 2) return emptyState(ctx, w, h, "Ожидание данных симуляции…");

        const padTop = 10, padBottom = 20, padLeft = 38, padRight = 8;
        const plotH = h - padTop - padBottom;
        const plotW = w - padLeft - padRight;

        const maxLoad = Math.max(100, ...tickHistory.map(t => t.maxLoad));
        const minLoad = 0;
        const yOf = (v) => padTop + plotH * (1 - (v - minLoad) / (maxLoad - minLoad));

        drawGrid(ctx, w, h);
        ctx.fillStyle = "#565656";
        ctx.font = "10px Consolas, monospace";
        ctx.textAlign = "right";
        for (let i = 0; i <= 4; i++) {
            const v = maxLoad * (1 - i / 4);
            ctx.fillText(Math.round(v), padLeft - 6, yOf(v) + 3);
        }

        const n = tickHistory.length;
        const slot = plotW / n;
        const bodyW = Math.max(2, slot * 0.55);

        tickHistory.forEach((t, i) => {
            const cx = padLeft + slot * i + slot / 2;
            const openLoad = i > 0 ? tickHistory[i - 1].avgLoad : t.avgLoad;
            const closeLoad = t.avgLoad;
            const up = closeLoad >= openLoad;
            const color = up ? "#1dc943" : "#d32f2f";

            // фитиль — реальный разброс load между узлами в этот тик
            ctx.strokeStyle = color;
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(cx, yOf(t.maxLoad));
            ctx.lineTo(cx, yOf(t.minLoad));
            ctx.stroke();

            // тело — open→close среднего load
            const yA = yOf(openLoad), yB = yOf(closeLoad);
            ctx.fillStyle = color;
            const top = Math.min(yA, yB), bh = Math.max(1.5, Math.abs(yA - yB));
            ctx.fillRect(cx - bodyW / 2, top, bodyW, bh);
        });

        // линия средней угрозы (шкала 0..1 -> высота плота)
        ctx.strokeStyle = "#4fc1ff";
        ctx.lineWidth = 1.6;
        ctx.beginPath();
        tickHistory.forEach((t, i) => {
            const cx = padLeft + slot * i + slot / 2;
            const cy = padTop + plotH * (1 - Math.min(1, t.avgThreat));
            if (i === 0) ctx.moveTo(cx, cy); else ctx.lineTo(cx, cy);
        });
        ctx.stroke();

        ctx.fillStyle = "#6e7681";
        ctx.textAlign = "left";
        ctx.fillText("t" + tickHistory[0].tick, padLeft, h - 4);
        ctx.textAlign = "right";
        ctx.fillText("t" + tickHistory[n - 1].tick, w - padRight, h - 4);
    }

    // ---------- B. Stacked area — состав режимов во времени ----------
    function renderModes() {
        const p = prepCanvas('chart-modes');
        if (!p) return;
        const { ctx, w, h } = p;
        ctx.clearRect(0, 0, w, h);
        if (tickHistory.length < 2) return emptyState(ctx, w, h, "Ожидание данных симуляции…");

        const padTop = 10, padBottom = 20, padLeft = 38, padRight = 8;
        const plotH = h - padTop - padBottom;
        const plotW = w - padLeft - padRight;
        const n = tickHistory.length;
        const slot = plotW / (n - 1);

        drawGrid(ctx, w, h);
        ctx.fillStyle = "#565656";
        ctx.font = "10px Consolas, monospace";
        ctx.textAlign = "right";
        ["100%", "75%", "50%", "25%", "0%"].forEach((lbl, i) => {
            ctx.fillText(lbl, padLeft - 6, padTop + plotH * (i / 4) + 3);
        });

        let cumulative = new Array(n).fill(0);
        MODE_ORDER.forEach(mode => {
            const color = MODE_COLOR[mode];
            ctx.fillStyle = color;
            ctx.globalAlpha = 0.85;
            ctx.beginPath();
            tickHistory.forEach((t, i) => {
                const frac = (t.modeCounts[mode] || 0) / t.total;
                cumulative[i] += frac;
                const x = padLeft + slot * i;
                const y = padTop + plotH * (1 - cumulative[i]);
                if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
            });
            for (let i = n - 1; i >= 0; i--) {
                const prevCum = cumulative[i] - ((tickHistory[i].modeCounts[mode] || 0) / tickHistory[i].total);
                const x = padLeft + slot * i;
                const y = padTop + plotH * (1 - prevCum);
                ctx.lineTo(x, y);
            }
            ctx.closePath();
            ctx.fill();
            ctx.globalAlpha = 1;
        });

        ctx.fillStyle = "#6e7681";
        ctx.font = "10px Consolas, monospace";
        ctx.textAlign = "left";
        ctx.fillText("t" + tickHistory[0].tick, padLeft, h - 4);
        ctx.textAlign = "right";
        ctx.fillText("t" + tickHistory[n - 1].tick, w - padRight, h - 4);

        renderModesLegend();
    }
    function renderModesLegend() {
        const el = document.getElementById('modes-legend');
        if (!el) return;
        el.innerHTML = MODE_ORDER.map(m =>
            `<span><i class="dot" style="background:${MODE_COLOR[m]}"></i>${m}</span>`
        ).join('');
    }

    // ---------- C. Decisions — allowed vs rejected по типу действия ----------
    function renderDecisions() {
        const p = prepCanvas('chart-decisions');
        if (!p) return;
        const { ctx, w, h } = p;
        ctx.clearRect(0, 0, w, h);
        const actions = Object.keys(decisionsByAction);
        if (actions.length === 0) return emptyState(ctx, w, h, "Решений пока не поступало");

        actions.sort((a, b) => (decisionsByAction[b].allowed + decisionsByAction[b].rejected) - (decisionsByAction[a].allowed + decisionsByAction[a].rejected));

        // --- ИЗМЕНЕНИЯ ТУТ: Увеличили отступы слева и справа ---
        const padLeft = 145;   // Было 118 (теперь влезут даже самые длинные экшены)
        const padRight = 75;   // Было 44 (теперь влезут большие числа вроде "999/999")
        const padTop = 8;
        const padBottom = 8;
        
        const rowH = Math.min(29, (h - padTop - padBottom) / actions.length);
        const plotW = w - padLeft - padRight;
        const maxTotal = Math.max(1, ...actions.map(a => decisionsByAction[a].allowed + decisionsByAction[a].rejected));

        // --- ИЗМЕНЕНИЯ ТУТ: Сделали шрифт чуть компактнее (13px вместо 15px) ---
        ctx.font = "15px Consolas, monospace"; 
        
        actions.forEach((action, i) => {
            const y = padTop + i * rowH;
            const { allowed, rejected } = decisionsByAction[action];
            const total = allowed + rejected;
            const barW = plotW * (total / maxTotal);
            const allowedW = barW * (allowed / total);
            const rejectedW = barW - allowedW;

            ctx.fillStyle = "#c2c2c2";
            ctx.textAlign = "right";
            ctx.fillText(action, padLeft - 8, y + rowH * 0.65);

            ctx.fillStyle = ACTION_COLOR_OK;
            ctx.fillRect(padLeft, y + rowH * 0.18, allowedW, rowH * 0.5);
            ctx.fillStyle = ACTION_COLOR_REJECT;
            ctx.fillRect(padLeft + allowedW, y + rowH * 0.18, rejectedW, rowH * 0.5);

            ctx.fillStyle = "#c1c1c1";
            ctx.textAlign = "left";
            ctx.fillText(`${allowed}/${total}`, padLeft + barW + 6, y + rowH * 0.65);
        });
    }

    // ---------- D. Источник решения — donut ----------
    function renderSources() {
        const p = prepCanvas('chart-sources');
        if (!p) return;
        const { ctx, w, h } = p;
        ctx.clearRect(0, 0, w, h);
        const keys = Object.keys(decisionsBySource);
        const total = keys.reduce((s, k) => s + decisionsBySource[k], 0);
        if (total === 0) return emptyState(ctx, w, h, "Решений пока не поступало");

        const cx = w * 0.32, cy = h / 2, rOuter = Math.min(w * 0.28, h * 0.42), rInner = rOuter * 0.58;
        let angle = -Math.PI / 2;

        keys.forEach(k => {
            const frac = decisionsBySource[k] / total;
            const sweep = frac * Math.PI * 2;
            ctx.beginPath();
            ctx.moveTo(cx, cy);
            ctx.arc(cx, cy, rOuter, angle, angle + sweep);
            ctx.closePath();
            ctx.fillStyle = SOURCE_COLOR[k] || "#888";
            ctx.fill();
            angle += sweep;
        });
        ctx.fillStyle = "#171717";
        ctx.beginPath();
        ctx.arc(cx, cy, rInner, 0, Math.PI * 2);
        ctx.fill();

        ctx.fillStyle = "#e4e4e4";
        ctx.font = "bold 20px Consolas, monospace";
        ctx.textAlign = "center";
        const autonomousFrac = 1 - ((decisionsBySource["ИИ-предсказание"] || 0) / total);
        ctx.fillText(Math.round(autonomousFrac * 100) + "%", cx, cy + 5);
        ctx.font = "16px Consolas, monospace";
        ctx.fillStyle = "#bdc1c7";
        ctx.fillText("не ИИ", cx, cy + 18);

        const legendX = w * 0.58;
        let ly = h * 0.22;
        ctx.font = "18px Consolas, monospace";
        ctx.textAlign = "left";
        keys.forEach(k => {
            const pct = Math.round((decisionsBySource[k] / total) * 100);
            ctx.fillStyle = SOURCE_COLOR[k] || "#888";
            ctx.fillRect(legendX, ly - 8, 8, 8);
            ctx.fillStyle = "#dbdbdb";
            ctx.fillText(`${k} — ${pct}%`, legendX + 14, ly);
            ly += 28;
        });
    }

    function renderScatterLegend() {
        const el = document.getElementById('scatter-legend');
        if (!el) return;
        const present = [...new Set(lastNodesSnapshot.map(n => n.mode))];
        el.innerHTML = present.map(m =>
            `<span><i class="dot" style="background:${MODE_COLOR[m] || '#888'}"></i>${m}</span>`
        ).join('');
    }

    function renderAll() {
        renderCandles();
        renderModes();
        renderDecisions();
        renderSources();
    }

    let resizeTimer = null;
    window.addEventListener('resize', () => {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(renderAll, 150);
    });

    return { ingest, reset, renderAll, restoreState };
})();

Dashboard.restoreState();