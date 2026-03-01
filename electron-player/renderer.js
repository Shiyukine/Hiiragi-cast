// Cast bridge WebSocket client + video player controller

const params = new URLSearchParams(window.location.search);
const BRIDGE_PORT = params.get('bridgePort') || 9000;
const WS_URL = `ws://localhost:${BRIDGE_PORT}`;

// ── DOM refs ──────────────────────────────────────────────────────────────────
const idle = document.getElementById('idle');
const statusDot = document.getElementById('status-dot');
const statusText = document.getElementById('status-text');
const mirrorCanvas = document.getElementById('mirror-canvas');
const mirrorCtx = mirrorCanvas.getContext('2d');

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
    mirrorCanvas.style.display = 'none';
    idle.classList.remove('hidden');
    window.castBridge.setTitle('');
}

function showReceiver(url) {
    idle.classList.add('hidden');
    mirrorCanvas.style.display = 'none';
    castWebview.src = url;
    castWebview.style.opacity = '1';
}

// Set canvas drawing buffer to the video's native resolution, then
// compute and apply a letterbox-fit CSS display size so the canvas
// always fills the window while preserving aspect ratio.
// The GPU compositor scales drawing-buffer → CSS pixels (Lanczos),
// which is sharper than any software upscale inside drawImage().
function setMirrorCanvasToVideoSize(fw, fh) {
    if (mirrorCanvas.width !== fw || mirrorCanvas.height !== fh) {
        mirrorCanvas.width = fw;
        mirrorCanvas.height = fh;
        mirrorCtx.imageSmoothingEnabled = true;
        mirrorCtx.imageSmoothingQuality = 'high';
    }
    fitMirrorCanvas();
}

// Recompute the CSS display size to letterbox-fit the current window.
function fitMirrorCanvas() {
    const fw = mirrorCanvas.width;
    const fh = mirrorCanvas.height;
    if (!fw || !fh) return;
    const scale = Math.min(window.innerWidth / fw, window.innerHeight / fh);
    mirrorCanvas.style.width = Math.round(fw * scale) + 'px';
    mirrorCanvas.style.height = Math.round(fh * scale) + 'px';
}

window.addEventListener('resize', () => {
    if (mirrorCanvas.style.display === 'block') fitMirrorCanvas();
});

function showMirror() {
    idle.classList.add('hidden');
    castWebview.src = 'about:blank';
    castWebview.style.opacity = '0';
    mirrorCanvas.style.display = 'block';
    // Canvas size is set when the first frame arrives (video native resolution).
}

function hideMirror() {
    mirrorCanvas.style.display = 'none';
    idle.classList.remove('hidden');
}

function setConnected(yes) {
    statusDot.className = yes ? 'connected' : '';
    statusText.textContent = yes ? 'Waiting for cast…' : 'Connecting to receiver…';
}

// ── Cast event handlers ───────────────────────────────────────────────────────
const handlers = {
    // Chrome Tab Mirroring — display WebRTC frames on canvas
    'start-mirror'() {
        showMirror();
    },

    'stop-mirror'() {
        hideMirror();
    },

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

    ws.binaryType = 'arraybuffer';

    ws.onmessage = ({ data }) => {
        // Binary message = JPEG-encoded video frame (raw JPEG file bytes).
        // createImageBitmap decodes via Chromium's GPU JPEG pipeline.
        if (data instanceof ArrayBuffer) {
            if (mirrorCanvas.style.display !== 'block') return;
            if (!mirrorCanvas._frameCount) mirrorCanvas._frameCount = 0;
            mirrorCanvas._frameCount++;
            createImageBitmap(new Blob([data], { type: 'image/jpeg' })).then(bitmap => {
                const bw = bitmap.width, bh = bitmap.height;
                setMirrorCanvasToVideoSize(bw, bh);
                mirrorCtx.drawImage(bitmap, 0, 0);
                bitmap.close();
                if (mirrorCanvas._frameCount === 1) {
                    console.log('[Mirror] First JPEG frame:', bw + 'x' + bh);
                }
            }).catch(e => {
                if (mirrorCanvas._frameCount <= 3) console.error('[Mirror] JPEG decode error:', e);
            });
            return;
        }

        // Text message = JSON event
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
