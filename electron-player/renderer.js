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

function showOverlay() {
    const overlay = document.getElementById('overlay');
    overlay.classList.add('visible');

    document.body.style.cursor = 'default';

    setTimeout(() => {
        if (overlay.classList.contains('visible')) {
            for (const btn of overlay.children) {
                btn.style.opacity = '1';
            }
        }
    }, 10);
}

function hideOverlay() {
    const overlay = document.getElementById('overlay');
    for (const btn of overlay.children) {
        btn.style.opacity = '0';
    }
    setTimeout(() => {
        overlay.classList.remove('visible');
    }, 300);

    if (fullscreen) {
        document.body.style.cursor = 'none';
    }
}

let overlayTimeout = null;
window.addEventListener('mousemove', () => {
    showOverlay();
    clearTimeout(overlayTimeout);
    overlayTimeout = setTimeout(() => {
        hideOverlay();
    }, 3000);
});

let fullscreen = false;
const fullscreenSvgs = {
    expand: [
        "M19,24H17a1,1,0,0,1,0-2h2a3,3,0,0,0,3-3V17a1,1,0,0,1,2,0v2A5.006,5.006,0,0,1,19,24Z",
        "M1,8A1,1,0,0,1,0,7V5A5.006,5.006,0,0,1,5,0H7A1,1,0,0,1,7,2H5A3,3,0,0,0,2,5V7A1,1,0,0,1,1,8Z",
        "M7,24H5a5.006,5.006,0,0,1-5-5V17a1,1,0,0,1,2,0v2a3,3,0,0,0,3,3H7a1,1,0,0,1,0,2Z",
        "M23,8a1,1,0,0,1-1-1V5a3,3,0,0,0-3-3H17a1,1,0,0,1,0-2h2a5.006,5.006,0,0,1,5,5V7A1,1,0,0,1,23,8Z",
    ],
    compress: [
        "M7,0A1,1,0,0,0,6,1V3A3,3,0,0,1,3,6H1A1,1,0,0,0,1,8H3A5.006,5.006,0,0,0,8,3V1A1,1,0,0,0,7,0Z",
        "M23,16H21a5.006,5.006,0,0,0-5,5v2a1,1,0,0,0,2,0V21a3,3,0,0,1,3-3h2a1,1,0,0,0,0-2Z",
        "M21,8h2a1,1,0,0,0,0-2H21a3,3,0,0,1-3-3V1a1,1,0,0,0-2,0V3A5.006,5.006,0,0,0,21,8Z",
        "M3,16H1a1,1,0,0,0,0,2H3a3,3,0,0,1,3,3v2a1,1,0,0,0,2,0V21A5.006,5.006,0,0,0,3,16Z",
    ],
}

function setFullscreenIcon(isFullscreen) {
    const paths = isFullscreen ? fullscreenSvgs.compress : fullscreenSvgs.expand;
    const svg = document.getElementById('fullscreen-svg');
    while (svg.firstChild) {
        svg.removeChild(svg.firstChild);
    }
    for (const d of paths) {
        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path.setAttribute('d', d);
        svg.appendChild(path);
    }
}

document.getElementById("fullscreen").addEventListener('click', () => {
    if (fullscreen) {
        document.exitFullscreen();
        document.getElementById('fullscreen-text').innerText = 'Use fullscreen';
    } else {
        document.documentElement.requestFullscreen();
        document.getElementById('fullscreen-text').innerText = 'Exit fullscreen';
    }
    setFullscreenIcon(!fullscreen);
    fullscreen = !fullscreen;
});

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
