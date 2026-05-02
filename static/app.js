// ---------------------------------------------------------------------------
// GA4 bootstrap — must run before DOMContentLoaded so the dataLayer is
// available when the async gtag.js library initialises.
// ---------------------------------------------------------------------------
window.dataLayer = window.dataLayer || [];
function gtag() { dataLayer.push(arguments); }

const CONSENT_KEY = 'analytics_consent';
const GA_ID = 'G-99NT7YXMY8';

const consent = localStorage.getItem(CONSENT_KEY);

if (consent === 'accepted') {
    // User previously accepted — initialise GA4 fully.
    gtag('js', new Date());
    gtag('config', GA_ID);
} else {
    // 'declined' or not yet set — keep GA4 in denied mode.
    gtag('consent', 'default', {
        analytics_storage: 'denied',
        ad_storage: 'denied',
    });
}

// ---------------------------------------------------------------------------
// Consent banner wiring
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', function () {
    const banner     = document.getElementById('consent-banner');
    const btnAccept  = document.getElementById('consent-accept');
    const btnDecline = document.getElementById('consent-decline');

    if (!localStorage.getItem(CONSENT_KEY)) {
        banner.classList.remove('hidden');
    }

    btnAccept.addEventListener('click', function () {
        localStorage.setItem(CONSENT_KEY, 'accepted');
        banner.classList.add('hidden');
        gtag('consent', 'update', { analytics_storage: 'granted' });
        gtag('js', new Date());
        gtag('config', GA_ID);
    });

    btnDecline.addEventListener('click', function () {
        localStorage.setItem(CONSENT_KEY, 'declined');
        banner.classList.add('hidden');
    });
});

// ---------------------------------------------------------------------------
// WebSocket
// ---------------------------------------------------------------------------
const WS_URL = 'ws://localhost:7777/ws';
const MAX_FLOWS      = 200;
const MAX_ALERTS     = 50;
const MAX_DNS        = 100;
const MAX_ENRICHMENT = 50;

const OT_PORTS = new Set([502, 102, 44818, 4840, 20000, 47808, 9600, 1962,
                           18245, 4000, 2222, 1089, 1090, 1091]);

const OT_PROTOCOLS = new Set(['Modbus', 'S7comm', 'EtherNet/IP', 'OPC-UA',
    'DNP3', 'BACnet', 'OMRON FINS', 'PCWorx', 'GE SRTP', 'Emerson DeltaV',
    'FF Annunciation', 'Foundation Fieldbus', 'FF System Management']);

let ws             = null;
let reconnectTimer = null;
let threatIPs      = new Set();
let statsData      = { packets: 0, bytes: 0, flows: 0, alerts: 0 };

// ---------------------------------------------------------------------------
// Connection management
// ---------------------------------------------------------------------------
function connect() {
    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
        return;
    }

    setStatus('connecting');

    ws = new WebSocket(WS_URL);

    ws.addEventListener('open', function () {
        clearTimeout(reconnectTimer);
        setStatus('connected');
    });

    ws.addEventListener('message', function (event) {
        try {
            const msg = JSON.parse(event.data);
            handleMessage(msg);
        } catch (e) {
            // Ignore malformed frames.
        }
    });

    ws.addEventListener('close', function () {
        setStatus('disconnected');
        scheduleReconnect();
    });

    ws.addEventListener('error', function () {
        ws.close();
    });
}

function scheduleReconnect() {
    clearTimeout(reconnectTimer);
    reconnectTimer = setTimeout(connect, 3000);
}

function handleMessage(msg) {
    switch (msg.type) {
        case 'flow':        addFlow(msg);        break;
        case 'alert':       addAlert(msg);       break;
        case 'dns':         addDNS(msg);         break;
        case 'stats':       updateStats(msg);    break;
        case 'enrichment':  addEnrichment(msg);  break;
        case 'status':      /* no-op for now */  break;
    }
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------
function setStatus(state) {
    const dot    = document.getElementById('statusDot');
    const text   = document.getElementById('statusText');
    const banner = document.getElementById('downloadBanner');

    if (state === 'connected') {
        dot.className   = 'status-dot online';
        text.className  = 'status-text status-connected';
        text.textContent = '● CONNECTED';
        banner.classList.add('hidden');
    } else if (state === 'connecting') {
        dot.className   = 'status-dot';
        text.className  = 'status-text status-connecting';
        text.textContent = '● CONNECTING...';
        banner.classList.remove('hidden');
    } else {
        dot.className   = 'status-dot offline';
        text.className  = 'status-text status-disconnected';
        text.textContent = '● DISCONNECTED';
        banner.classList.remove('hidden');
    }
}

// ---------------------------------------------------------------------------
// Flow table
// ---------------------------------------------------------------------------
function addFlow(msg) {
    const tbody = document.getElementById('flow-body');

    const tr = document.createElement('tr');
    tr.classList.add('row-new');
    setTimeout(function () { tr.classList.remove('row-new'); }, 500);

    const isOT     = isOTPort(msg.dst_port);
    const isThreat = threatIPs.has(msg.src) || threatIPs.has(msg.dst);

    const tdTime  = document.createElement('td');
    const tdSrc   = document.createElement('td');
    const tdDst   = document.createElement('td');
    const tdPort  = document.createElement('td');
    const tdProto = document.createElement('td');
    const tdBytes = document.createElement('td');

    tdTime.className  = 'col-dim';
    tdSrc.className   = isThreat ? 'col-threat' : '';
    tdDst.className   = isThreat ? 'col-threat' : '';
    tdPort.className  = isOT     ? 'col-ot'     : 'col-dim';
    tdProto.className = isOT     ? 'col-ot'     : '';
    tdBytes.className = 'col-dim';

    tdTime.textContent  = formatTime(msg.timestamp);
    tdSrc.textContent   = msg.src;
    tdDst.textContent   = msg.dst;
    tdPort.textContent  = isOT ? msg.dst_port + ' ⚠ OT' : msg.dst_port;
    tdProto.textContent = msg.protocol;
    tdBytes.textContent = formatBytes(msg.bytes);

    tr.appendChild(tdTime);
    tr.appendChild(tdSrc);
    tr.appendChild(tdDst);
    tr.appendChild(tdPort);
    tr.appendChild(tdProto);
    tr.appendChild(tdBytes);

    tbody.insertBefore(tr, tbody.firstChild);

    while (tbody.children.length > MAX_FLOWS) {
        tbody.removeChild(tbody.lastChild);
    }
}

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------
function addAlert(msg) {
    const list = document.getElementById('alerts-list');

    // Remove empty placeholder.
    const empty = list.querySelector('.panel-empty');
    if (empty) list.removeChild(empty);

    const entry = document.createElement('div');
    entry.className = 'alert-entry';

    const textSpan = document.createElement('span');
    const timeSpan = document.createElement('span');
    timeSpan.className = 'alert-time';
    timeSpan.textContent = formatTime(null);

    if (msg.alert_type === 'beaconing') {
        const interval = msg.interval_ms != null ? msg.interval_ms.toFixed(0) : '?';
        textSpan.textContent = '⚠ BEACONING — ' + msg.src + ' → ' + msg.dst +
            ' — interval: ' + interval + 'ms × ' + msg.count + ' connections';
    } else if (msg.alert_type === 'port_scan') {
        const ports = Array.isArray(msg.ports_hit) ? msg.ports_hit.length : '?';
        const win   = msg.window_seconds != null ? msg.window_seconds : '?';
        textSpan.textContent = '⚠ PORT SCAN — ' + msg.src +
            ' — ' + ports + ' unique ports in ' + win + 's';
    } else {
        textSpan.textContent = '⚠ ' + (msg.alert_type || 'ALERT').toUpperCase() +
            ' — ' + msg.src + ' → ' + msg.dst;
    }

    entry.appendChild(textSpan);
    entry.appendChild(timeSpan);
    list.insertBefore(entry, list.firstChild);

    while (list.children.length > MAX_ALERTS) {
        list.removeChild(list.lastChild);
    }

    statsData.alerts++;
    updateStatsDisplay();
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------
function addDNS(msg) {
    const tbody = document.getElementById('dns-body');

    const tr = document.createElement('tr');

    const tdTime  = document.createElement('td');
    const tdSrc   = document.createElement('td');
    const tdQuery = document.createElement('td');
    const tdType  = document.createElement('td');
    const tdResp  = document.createElement('td');

    tdTime.className = 'col-dim';
    tdType.className = 'col-dim';
    tdResp.className = 'col-dim';

    tdTime.textContent  = formatTime(msg.timestamp);
    tdSrc.textContent   = msg.src || '';
    tdQuery.textContent = msg.query || '';
    tdType.textContent  = msg.record_type || '';
    tdResp.textContent  = msg.response || '—';

    if (msg.is_suspicious) {
        tr.classList.add('col-threat');
        const reason = msg.suspicion_reason ? ' ⚠ ' + msg.suspicion_reason : ' ⚠';
        tdQuery.textContent += reason;
    }

    tr.appendChild(tdTime);
    tr.appendChild(tdSrc);
    tr.appendChild(tdQuery);
    tr.appendChild(tdType);
    tr.appendChild(tdResp);

    tbody.insertBefore(tr, tbody.firstChild);

    while (tbody.children.length > MAX_DNS) {
        tbody.removeChild(tbody.lastChild);
    }
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------
function updateStats(msg) {
    statsData.packets = msg.total_packets;
    statsData.bytes   = msg.total_bytes;
    statsData.flows   = msg.active_flows;
    updateStatsDisplay();
    if (msg.protocol_breakdown) updateProtoBars(msg.protocol_breakdown);
    if (msg.top_talkers)        updateTopTalkers(msg.top_talkers);
}

function updateStatsDisplay() {
    document.getElementById('stat-packets').textContent = statsData.packets.toLocaleString();
    document.getElementById('stat-bytes').textContent   = formatBytes(statsData.bytes);
    document.getElementById('stat-flows').textContent   = statsData.flows.toLocaleString();
    document.getElementById('stat-alerts').textContent  = statsData.alerts.toLocaleString();
}

function updateProtoBars(breakdown) {
    const container = document.getElementById('proto-bars');

    // Sort descending by count.
    const entries = Object.entries(breakdown).sort(function (a, b) { return b[1] - a[1]; });
    const total   = entries.reduce(function (sum, e) { return sum + e[1]; }, 0);

    if (total === 0) return;

    const top  = entries.slice(0, 8);
    const rest = entries.slice(8).reduce(function (sum, e) { return sum + e[1]; }, 0);
    if (rest > 0) top.push(['Other', rest]);

    container.textContent = '';

    top.forEach(function (entry) {
        const name  = entry[0];
        const count = entry[1];
        const pct   = ((count / total) * 100).toFixed(1);
        const isOT  = OT_PROTOCOLS.has(name);

        const row   = document.createElement('div');
        row.className = 'proto-row';

        const nameEl = document.createElement('span');
        nameEl.className  = 'proto-name';
        nameEl.textContent = name;

        const wrap = document.createElement('div');
        wrap.className = 'proto-bar-wrap';

        const bar  = document.createElement('div');
        bar.className = 'proto-bar' + (isOT ? ' ot' : '');
        bar.style.width = pct + '%';

        wrap.appendChild(bar);

        const pctEl = document.createElement('span');
        pctEl.className  = 'proto-pct';
        pctEl.textContent = pct + '%';

        row.appendChild(nameEl);
        row.appendChild(wrap);
        row.appendChild(pctEl);
        container.appendChild(row);
    });
}

function updateTopTalkers(talkers) {
    const list = document.getElementById('talkers-list');
    list.textContent = '';

    if (!talkers || talkers.length === 0) {
        const empty = document.createElement('div');
        empty.className  = 'panel-empty';
        empty.textContent = '// waiting for traffic';
        list.appendChild(empty);
        return;
    }

    talkers.forEach(function (t) {
        const row    = document.createElement('div');
        row.className = 'talker-row';

        const ipEl   = document.createElement('span');
        ipEl.className  = 'talker-ip' + (threatIPs.has(t.ip) ? ' threat' : '');
        ipEl.textContent = t.ip;

        const bytesEl = document.createElement('span');
        bytesEl.className  = 'talker-bytes';
        bytesEl.textContent = '↑ ' + formatBytes(t.bytes);

        row.appendChild(ipEl);
        row.appendChild(bytesEl);
        list.appendChild(row);
    });
}

// ---------------------------------------------------------------------------
// Enrichment
// ---------------------------------------------------------------------------
function addEnrichment(msg) {
    const list = document.getElementById('enrichment-list');

    // Remove empty placeholder.
    const empty = list.querySelector('.panel-empty');
    if (empty) list.removeChild(empty);

    const isThreat = msg.verdict === 'threat' || msg.verdict === 'malicious';

    if (isThreat) {
        threatIPs.add(msg.ip);
        // Retroactively colour any existing flow rows for this IP.
        document.querySelectorAll('#flow-body tr').forEach(function (tr) {
            const cells = tr.querySelectorAll('td');
            if (cells.length < 3) return;
            if (cells[1].textContent === msg.ip || cells[2].textContent === msg.ip) {
                cells[1].classList.add('col-threat');
                cells[2].classList.add('col-threat');
            }
        });
    }

    const entry = document.createElement('div');
    entry.className = 'enrich-entry ' + (isThreat ? 'threat' : 'clean');

    const ipEl = document.createElement('span');
    ipEl.className  = 'enrich-ip';
    ipEl.textContent = msg.ip;

    const badgeEl = document.createElement('span');
    badgeEl.className  = 'enrich-badge';
    badgeEl.textContent = (msg.verdict || 'unknown').toUpperCase();

    const metaEl = document.createElement('span');
    metaEl.className = 'enrich-badge';
    const scorePart = msg.abuse_score != null ? 'abuse: ' + msg.abuse_score + '/100' : '';
    const torPart   = 'TOR: ' + (msg.is_tor ? 'true' : 'false');
    metaEl.textContent = [scorePart, torPart].filter(Boolean).join(' | ');

    entry.appendChild(ipEl);
    entry.appendChild(badgeEl);
    entry.appendChild(metaEl);

    list.insertBefore(entry, list.firstChild);

    while (list.children.length > MAX_ENRICHMENT) {
        list.removeChild(list.lastChild);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function formatBytes(bytes) {
    if (bytes == null || bytes === 0) return '0 B';
    if (bytes < 1024)       return bytes + ' B';
    if (bytes < 1048576)    return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
    return (bytes / 1073741824).toFixed(2) + ' GB';
}

function formatTime(timestamp) {
    if (!timestamp) {
        return new Date().toTimeString().slice(0, 8);
    }
    try {
        return new Date(timestamp).toTimeString().slice(0, 8);
    } catch (e) {
        return new Date().toTimeString().slice(0, 8);
    }
}

function isOTPort(port) {
    return OT_PORTS.has(parseInt(port, 10));
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
connect();
