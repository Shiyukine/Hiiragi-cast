// Cast bridge WebSocket client + video player controller

const params = new URLSearchParams(window.location.search);
const BRIDGE_PORT = params.get('bridgePort') || 9000;
const WS_URL = `ws://localhost:${BRIDGE_PORT}`;

// ── DOM refs ──────────────────────────────────────────────────────────────────
const idle = document.getElementById('idle');
const statusDot = document.getElementById('status-dot');
const statusText = document.getElementById('status-text');

// ── State ──────────────────────────────────────────────────────────────────────
const castWebview = document.getElementById('cast-webview');
/*castWebview.addEventListener('console-message', (e) => {
    let level = ["debug", "info", "warn", "error"][e.level] || "log";
    console[level](`[WebView] ${e.message} (line ${e.line}, source: ${e.sourceId})`);
});*/
/*castWebview.addEventListener('dom-ready', () => {
    castWebview.openDevTools()
})*/

function showIdle() {
    castWebview.src = 'about:blank';
    castWebview.style.opacity = '0';
    idle.classList.remove('hidden');
    window.castBridge.setTitle('');
}

function showReceiver(url) {
    idle.classList.add('hidden');
    castWebview.src = url;
    castWebview.style.opacity = '1';
}

function setConnected(yes) {
    statusDot.className = yes ? 'connected' : '';
    statusText.textContent = yes ? 'Waiting for cast…' : 'Connecting to receiver…';
}

// ── Cast event handlers ───────────────────────────────────────────────────────
const handlers = {
    // IPC receiver apps (CC1AD845, etc.) — content rendered inside the <webview>
    'load-url'({ url }) {
        /*if (url.includes('www.gstatic.com/cast/sdk/default_receiver/')) {
            console.warn('[Bridge] Ignoring load-url for', url);
            url = "https://www.gstatic.com/eureka/player/player.html?skin=https://www.gstatic.com/eureka/player/0000/skins/cast/skin.css"
        }*/
        showReceiver(url);
    },

    'stop-url'() {
        showIdle();
    },
};

// ── WebSocket connection with auto-reconnect ──────────────────────────────────
let ws = null;
let reconnectTimer = null;

function connect() {
    if (ws) return;
    ws = new WebSocket(WS_URL);

    ws.onopen = () => {
        console.log('[Bridge] Connected to', WS_URL);
        setConnected(true);
        clearTimeout(reconnectTimer);
    };

    ws.onmessage = ({ data }) => {
        let event;
        try { event = JSON.parse(data); } catch { return; }
        const handler = handlers[event.event];
        if (handler) {
            handler(event);
        } else {
            console.warn('[Bridge] Unknown event:', event.event, event);
        }
    };

    ws.onerror = (e) => console.warn('[Bridge] WS error', e);

    ws.onclose = () => {
        console.log('[Bridge] Disconnected — retrying in 2s');
        setConnected(false);
        ws = null;
        reconnectTimer = setTimeout(connect, 2000);
    };
}

connect();
