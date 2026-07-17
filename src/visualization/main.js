// ПЕРСИСТЕНТНОСТЬ ЖУРНАЛА ЛОГОВ
const LogsPersistence = (() => {
    const KEY = 'simLogsState';
    const SAVE_DEBOUNCE_MS = 800;
    let saveTimer = null;
    let getLastLogTick = () => -1;
    let setLastLogTick = () => {};

    function init(getter, setter) {
        getLastLogTick = getter;
        setLastLogTick = setter;
    }

    function scheduleSave() {
        if (saveTimer) clearTimeout(saveTimer);
        saveTimer = setTimeout(save, SAVE_DEBOUNCE_MS);
    }

    function save() {
        try {
            const logDiv = document.getElementById('logs');
            if (!logDiv) return;
            sessionStorage.setItem(KEY, JSON.stringify({
                html: logDiv.innerHTML,
                lastLogTick: getLastLogTick(),
            }));
        } catch (e) {
            console.warn('LogsPersistence.save failed:', e);
        }
    }

    function restore() {
        try {
            const raw = sessionStorage.getItem(KEY);
            if (!raw) return false;
            const parsed = JSON.parse(raw);
            const logDiv = document.getElementById('logs');
            if (!logDiv || typeof parsed.html !== 'string') return false;
            logDiv.innerHTML = parsed.html;
            logDiv.scrollTop = logDiv.scrollHeight;
            if (typeof parsed.lastLogTick === 'number') {
                setLastLogTick(parsed.lastLogTick);
            }
            return true;
        } catch (e) {
            console.warn('LogsPersistence.restore failed:', e);
            return false;
        }
    }

    function clear() {
        if (saveTimer) { clearTimeout(saveTimer); saveTimer = null; }
        try { sessionStorage.removeItem(KEY); } catch (e) { /* ignore */ }
    }

    return { init, scheduleSave, restore, clear };
})();

let cy = cytoscape({
    container: document.getElementById('cy'),
    elements: [],
    autoungrabify: false,
    wheelSensitivity: 0.1,
    style: [
        {
            selector: 'node',
            style: {
                'label': 'data(label)',
                'text-wrap': 'wrap',
                'text-max-width': '130px',
                'text-valign': 'bottom',
                'text-halign': 'center',
                'text-margin-y': '8px',
                'font-size': '15px',
                'font-weight': '600',
                'font-family': 'Consolas, monospace',
                'color': '#e0e0e0',
                'text-background-color': '#1e1e1e',
                'text-background-opacity': 0.7,
                'text-background-padding': '4px',
                'text-background-shape': 'roundrectangle',
                'width': 55,
                'height': 55,
                'border-width': 2,
                'border-color': '#fff',
                'background-color': '#666',
                'transition-property': 'background-color, width, height',
                'transition-duration': '0.3s',
                'active-bg-opacity': 0,
                'overlay-opacity': 0
            }
        },
        {
            selector: 'edge',
            style: {
                'width': 4,
                'line-color': '#9e9e9e',
                'curve-style': 'haystack',
                'opacity': 0.8
            }
        },
        {
            selector: 'node:selected',
            style: {
                'border-color': '#4fc1ff',
                'border-width': 4
            }
        },
        {
            selector: 'node.being-dragged',
            style: {
                'overlay-opacity': 0.15,
                'overlay-color': '#4fc1ff'
            }
        },
        {
            selector: 'edge.virtual-link',
            style: {
                'line-color': '#4fc1ff',
                'line-style': 'dashed',
                'width': 3,
                'opacity': 0.9
            }
        },
    ],
    layout: { name: 'preset' }
});

let grabbedNode = null;

cy.on('grab', 'node', (evt) => {
    grabbedNode = evt.target;
    grabbedNode.addClass('being-dragged');
});

cy.on('free', 'node', (evt) => {
    evt.target.removeClass('being-dragged');
    if (grabbedNode && grabbedNode.id() === evt.target.id()) {
        grabbedNode = null;
    }
});

let savedPositions = {
    "1": {x: 500, y: 350}, 
    "2": {x: 300, y: 250}, 
    "3": {x: 150, y: 400},
    "4": {x: 150, y: 120}, 
    "5": {x: 500, y: 120}, 
    "6": {x: 700, y: 350},
    "7": {x: 300, y: 500}, 
    "8": {x: 280, y: 120},
    "9": {x: 500, y: 500},
    "10": {x: 0, y: 400},
};

const ws = new WebSocket("ws://localhost:3030/ws");
let knownNodes = []; // Храним известные узлы для селектора

let currentTick = 0;
let currentMaxTicks = 0;

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (justRestarted && data.tick <= 1) {
        justRestarted = false;
    }
    currentTick = data.tick;
    if (typeof data.max_ticks === 'number') {
        currentMaxTicks = data.max_ticks;
    }
    updateTick(data.tick);
    updateNAL(data.network_avg_load);
    updateGraphSmooth(data);
    updateLogsAccumulative(data.logs, data.tick);
    Dashboard.ingest(data);
    DashboardExtra.ingest(data);
    updateDurationHint();

    if (knownNodes.length !== data.nodes.length) {
        knownNodes = data.nodes;
        updateTargetDropdown();
    }
};

function getColor(mode) {
    switch(mode) {
        case "Normal":     return "#1dc943"; 
        case "Throttled":  return "#1976d2"; 
        case "Boosted":    return "#fbc02d"; 
        case "Degraded":   return "#f57c00"; 
        case "Isolated":   return "#d32f2f"; 
        case "Recovery":   return "#0288d1"; 
        default:           return "#888888";
    }
}

function updateTick(tick) { document.getElementById("tick").textContent = tick; }
function updateNAL(avg_load) { document.getElementById("net_avg_load").textContent = avg_load; }

function updateGraphSmooth(data) {
    cy.batch(() => {
        data.nodes.forEach((n, i) => {
            const id = n.id.toString();
            const existingNode = cy.getElementById(id);
            const label = `#${n.id} ${n.mode}\nL:${n.load}  T:${n.threat.toFixed(2)}`;
            const bgColor = getColor(n.mode);

            if (existingNode.length > 0) {
                existingNode.data('label', label);
                existingNode.data('raw_data', n);
                existingNode.style('background-color', bgColor);
                existingNode.style('border-color', n.mode === "Isolated" ? '#ff5252' : '#fff');
            } else {
                let pos = savedPositions[id];
                if (!pos) {
                    const angle = (2 * Math.PI * i) / data.nodes.length;
                    pos = { x: 400 + 200 * Math.cos(angle), y: 300 + 200 * Math.sin(angle) };
                }
                cy.add({
                    group: 'nodes',
                    data: { id: id, label: label, raw_data: n },
                    position: pos,
                    style: { 'background-color': bgColor }
                });
            }
        });

        const currentEdgeIds = new Set();
        data.edges.forEach(e => {
            const id = `${e.source}-${e.target}`;
            currentEdgeIds.add(id);
            const existingEdge = cy.getElementById(id);

            if (existingEdge.length === 0) {
                cy.add({
                    group: 'edges',
                    data: { id: id, source: e.source.toString(), target: e.target.toString() },
                    classes: e.virtual_link ? 'virtual-link' : ''
                });
            } else {
                existingEdge.toggleClass('virtual-link', !!e.virtual_link);
            }
        });

        cy.edges().forEach(edge => {
            if (!currentEdgeIds.has(edge.id())) {
                cy.remove(edge);
            }
        });
    });
    updatePopupIfOpen();
}

let lastLogTick = -1;
LogsPersistence.init(() => lastLogTick, (v) => { lastLogTick = v; });
LogsPersistence.restore();
const LOG_LINE_RE = /^\[T(\d+)\]\s(.*)$/;

function updateLogsAccumulative(logs, fallbackTick) {
    if (!logs || logs.length === 0) return;
    const logDiv = document.getElementById("logs");

    logs.forEach(l => {
        const m = LOG_LINE_RE.exec(l);
        const lineTick = m ? parseInt(m[1], 10) : fallbackTick;
        const text = m ? m[2] : l;

        if (lineTick !== lastLogTick) {
            const header = document.createElement("div");
            header.className = "log-tick-header";
            header.textContent = `[ Тик ${lineTick} ]`;
            logDiv.appendChild(header);
            lastLogTick = lineTick;
        }

        const entry = document.createElement("div");
        entry.className = "log-entry";
        if (text.includes("true")) entry.innerHTML = text.replace("true", "<span style='color:#4caf50'>true</span>");
        else if (text.includes("false")) entry.innerHTML = text.replace("false", "<span style='color:#f44336'>false</span>");
        else entry.textContent = text;
        logDiv.appendChild(entry);
    });
    logDiv.scrollTop = logDiv.scrollHeight;
    LogsPersistence.scheduleSave();
}

const popup = document.getElementById('node-popup');
let selectedNodeId = null;

cy.on('tap', 'node', function(evt){
    const node = evt.target;
    selectedNodeId = node.id();
    const pos = node.renderedPosition();
    popup.style.display = 'block';
    popup.style.left = (pos.x + 30) + 'px';
    popup.style.top = (pos.y - 30) + 'px';
    renderPopupData(node);
});

cy.on('tap', function(evt){
    if(evt.target === cy) { popup.style.display = 'none'; selectedNodeId = null; }
});
cy.on('pan', function() { popup.style.display = 'none'; selectedNodeId = null; });

function renderPopupData(node) {
    const raw = node.data('raw_data');
    if (!raw) return;
    document.getElementById('popup-title').innerText = `Узел #${raw.id}`;
    document.getElementById('popup-mode').innerText = raw.mode;
    document.getElementById('popup-mode').style.color = getColor(raw.mode);
    document.getElementById('popup-load').innerText = raw.load;
    document.getElementById('popup-threat').innerText = raw.threat.toFixed(3);
    document.getElementById('popup-connections').innerText = raw.active_connections;
    document.getElementById('popup-failed_auth').innerText = raw.failed_auth_count;
    document.getElementById('popup-edges').innerText = node.connectedEdges().length;
}

function updatePopupIfOpen() {
    if (selectedNodeId && popup.style.display === 'block') {
        const node = cy.getElementById(selectedNodeId);
        if (node.length > 0) {
            renderPopupData(node);
            const pos = node.renderedPosition();
            popup.style.left = (pos.x + 30) + 'px';
            popup.style.top = (pos.y - 30) + 'px';
        }
    }
}

// --- ЛОГИКА МЕНЮ СЦЕНАРИЕВ ---
const scriptsBtn = document.getElementById('btn-scripts');
const scriptsMenu = document.getElementById('scripts-menu');
const historyBtn = document.getElementById('btn-history');
const historyMenu = document.getElementById('history-menu');
const durationInput = document.getElementById('duration-input');
const durationRemainingEl = document.getElementById('duration-remaining');
const durationErrorEl = document.getElementById('duration-error');
const applyScriptBtn = document.getElementById('btn-apply-script');

scriptsBtn.addEventListener('click', () => {
    const opening = scriptsMenu.style.display === 'none' || !scriptsMenu.style.display;
    scriptsMenu.style.display = opening ? 'block' : 'none';
    if (opening) {
        historyMenu.style.display = 'none';
        updateDurationHint();
        validateDurationInput();
    }
});

historyBtn.addEventListener('click', () => {
    const opening = historyMenu.style.display === 'none' || !historyMenu.style.display;
    historyMenu.style.display = opening ? 'block' : 'none';
    if (opening) {
        scriptsMenu.style.display = 'none';
    }
});

function updateTargetDropdown() {
    const select = document.getElementById('target-select');
    const currentVal = select.value;
    select.innerHTML = '<option value="All">Все узлы</option><option value="Random">Случайный узел</option>';
    
    // Сортировка узлов по id
    const sortedNodes = [...knownNodes].sort((a,b) => a.id - b.id);
    sortedNodes.forEach(n => {
        const opt = document.createElement('option');
        opt.value = `ById:${n.id}`;
        opt.text = `Узел #${n.id}`;
        select.appendChild(opt);
    });

    // Восстановление выбранного пункта
    if (Array.from(select.options).some(o => o.value === currentVal)) {
        select.value = currentVal;
    }
}

function remainingTicks() {
    if (!currentMaxTicks) return null; // бэкенд ещё не прислал max_ticks
    const r = currentMaxTicks - currentTick;
    return r > 0 ? r : 0;
}

function updateDurationHint() {
    const remaining = remainingTicks();
    durationRemainingEl.textContent = remaining === null ? '—' : remaining;
    if (remaining !== null) {
        durationInput.max = String(remaining);
    }
}

// Возвращает { valid: bool, value: number|null, message: string }
function validateDurationInput() {
    const raw = durationInput.value.trim();
    const remaining = remainingTicks();

    if (raw === '') {
        durationErrorEl.textContent = 'Введите длительность';
        durationInput.classList.add('invalid');
        return { valid: false, value: null };
    }
    // Разрешаем только цифры — исключает "1.5", "1e3", "-1" в обход браузерного number-инпута.
    if (!/^\d+$/.test(raw)) {
        durationErrorEl.textContent = 'Только целое число тиков';
        durationInput.classList.add('invalid');
        return { valid: false, value: null };
    }
    const value = parseInt(raw, 10);
    if (value <= 0) {
        durationErrorEl.textContent = 'Длительность должна быть больше 0';
        durationInput.classList.add('invalid');
        return { valid: false, value: null };
    }
    if (remaining !== null && value > remaining) {
        durationErrorEl.textContent = `Не может превышать оставшиеся тики (${remaining})`;
        durationInput.classList.add('invalid');
        return { valid: false, value: null };
    }
    if (remaining === 0) {
        durationErrorEl.textContent = 'Симуляция завершена — тиков не осталось';
        durationInput.classList.add('invalid');
        return { valid: false, value: null };
    }

    durationErrorEl.textContent = '';
    durationInput.classList.remove('invalid');
    return { valid: true, value };
}

durationInput.addEventListener('input', validateDurationInput);

// --- История применённых сценариев (сбрасывается по Restart) ---
let scenarioHistory = [];

function renderHistoryTable() {
    const tbody = document.getElementById('history-tbody');
    tbody.innerHTML = '';

    if (scenarioHistory.length === 0) {
        const row = document.createElement('tr');
        row.id = 'history-empty-row';
        row.innerHTML = '<td colspan="4">Сценарии ещё не применялись</td>';
        tbody.appendChild(row);
        return;
    }

    // Новые сверху — удобнее следить за последними действиями.
    [...scenarioHistory].reverse().forEach(entry => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td class="history-tick">${entry.tick}</td>
            <td class="history-scenario">${entry.scenarioText}</td>
            <td class="history-target">${entry.targetText}</td>
            <td class="history-duration">${entry.duration}</td>
        `;
        tbody.appendChild(row);
    });
}

applyScriptBtn.addEventListener('click', () => {
    const scenSelect = document.getElementById('scenario-select');
    const targetSelect = document.getElementById('target-select');

    const { valid, value: duration } = validateDurationInput();
    if (!valid) {
        // Не отправляем команду и не закрываем меню — даём пользователю
        // увидеть сообщение об ошибке и исправить значение на месте.
        durationInput.focus();
        return;
    }

    const scenId = scenSelect.value;
    const scenText = scenSelect.options[scenSelect.selectedIndex].text.split('(')[0].trim();
    const targetVal = targetSelect.value;
    const targetText = targetSelect.options[targetSelect.selectedIndex].text;

    let tType = "All";
    let tId = 0;

    if (targetVal.startsWith("ById:")) {
        tType = "ById";
        tId = targetVal.split(":")[1];
    } else if (targetVal === "Random") {
        tType = "Random";
    }

    ws.send(`scenario:${scenId}:${tType}:${tId}:${duration}`);

    const alertBox = document.getElementById('scenario-alert');
    const displayTargetText = (tType === "All" || tType === "Random") ? targetText : `#${tId}`;

    alertBox.innerText = `⚠️ ${scenText} | Цель: ${displayTargetText} | ${duration} тик.`;
    alertBox.style.display = 'block';

    // Сброс таймера анимации (чтобы не пропало раньше времени, если кликнуть дважды)
    if(window.alertTimeout) clearTimeout(window.alertTimeout);
    window.alertTimeout = setTimeout(() => { alertBox.style.display = 'none'; }, 5000);

    scenarioHistory.push({
        tick: currentTick,
        scenarioText: scenText,
        targetText: displayTargetText,
        duration: duration,
    });
    renderHistoryTable();

    scriptsMenu.style.display = 'none';
});

// Базовые элементы управления
document.getElementById('btn-run').addEventListener('click', () => ws.send('run'));
document.getElementById('btn-stop').addEventListener('click', () => ws.send('stop'));
let justRestarted = false;
document.getElementById('btn-restart').addEventListener('click', () => {
    ws.send('restart');
    justRestarted = true;
    cy.elements().remove();
    document.getElementById('logs').innerHTML = '';
    lastLogTick = -1;
    LogsPersistence.clear();
    updateTick(0);
    updateNAL(0);
    Dashboard.reset();
    DashboardExtra.reset();
    // История сценариев относится к текущему запуску симуляции — сбрасываем вместе с ним.
    scenarioHistory = [];
    renderHistoryTable();
    historyMenu.style.display = 'none';
    scriptsMenu.style.display = 'none';
});