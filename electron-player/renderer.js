// Cast bridge WebSocket client + video player controller

const params = new URLSearchParams(window.location.search);
const BRIDGE_PORT = params.get('bridgePort') || 9000;
const WS_URL = `ws://localhost:${BRIDGE_PORT}`;

// ── DOM refs ──────────────────────────────────────────────────────────────────
const video = document.getElementById('video');
const idle = document.getElementById('idle');
const playerWrap = document.getElementById('player-wrap');
const overlay = document.getElementById('overlay');
const mediaTitle = document.getElementById('media-title');
const mediaSub = document.getElementById('media-sub');
const progressBar = document.getElementById('progress-bar');
const timeDisplay = document.getElementById('time-display');
const statusDot = document.getElementById('status-dot');
const statusText = document.getElementById('status-text');
const spinner = document.getElementById('spinner');

// ── State ─────────────────────────────────────────────────────────────────────
let duration = 0;
let overlayTimer = null;
let hlsInstance = null;   // active hls.js instance
let dashInstance = null;   // active dash.js player

// ── Format detection ──────────────────────────────────────────────────────────
function isHLS(src, contentType) {
    if (contentType && /(mpegurl|x-mpegurl)/i.test(contentType)) return true;
    return /\.m3u8(\?|$)/i.test(src);
}

function isDASH(src, contentType) {
    if (contentType && /dash\+xml/i.test(contentType)) return true;
    return /\.mpd(\?|$)/i.test(src);
}

// ── Teardown helpers ──────────────────────────────────────────────────────────
function destroyHls() {
    if (hlsInstance) { hlsInstance.destroy(); hlsInstance = null; }
}

function destroyDash() {
    if (dashInstance) { dashInstance.reset(); dashInstance = null; }
}

function destroyAll() {
    destroyHls();
    destroyDash();
}

// ── Load helper ───────────────────────────────────────────────────────────────
function loadMedia(src, startTime) {
    destroyAll();

    if (isHLS(src, '')) {
        // ── HLS (hls.js) ────────────────────────────────────────────────────
        if (typeof Hls === 'undefined') {
            console.error('[HLS] hls.js not loaded');
            showIdle();
            return;
        }
        if (Hls.isSupported()) {
            hlsInstance = new Hls({ enableWorker: true });
            hlsInstance.loadSource(src);
            hlsInstance.attachMedia(video);
            hlsInstance.on(Hls.Events.MANIFEST_PARSED, () => {
                if (startTime) video.currentTime = startTime;
                video.play().catch(() => { });
            });
            hlsInstance.on(Hls.Events.ERROR, (_, data) => {
                if (data.fatal) {
                    console.error('[HLS] Fatal error:', data.type, data.details);
                    destroyHls();
                    showIdle();
                }
            });
        } else if (video.canPlayType('application/vnd.apple.mpegurl')) {
            video.src = src;
            if (startTime) video.currentTime = startTime;
            video.play().catch(() => { });
        }

    } else if (isDASH(src, '')) {
        // ── MPEG-DASH (dash.js) ──────────────────────────────────────────────
        if (typeof dashjs === 'undefined') {
            console.error('[DASH] dash.js not loaded');
            showIdle();
            return;
        }
        dashInstance = dashjs.MediaPlayer().create();
        dashInstance.initialize(video, src, true);
        if (startTime) dashInstance.seek(startTime);
        dashInstance.on(dashjs.MediaPlayer.events.ERROR, (e) => {
            console.error('[DASH] Fatal error:', e);
            destroyDash();
            showIdle();
        });

    } else {
        // ── MP4 / WebM / plain audio — native element ────────────────────────
        video.src = src;
        if (startTime) video.currentTime = startTime;
        video.play().catch(() => { });
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function fmtTime(s) {
    s = Math.floor(s || 0);
    const m = Math.floor(s / 60);
    const ss = String(s % 60).padStart(2, '0');
    return `${m}:${ss}`;
}

function showPlayer() {
    idle.classList.add('hidden');
    playerWrap.classList.add('visible');
}

function showIdle() {
    idle.classList.remove('hidden');
    playerWrap.classList.remove('visible');
    window.castBridge.setTitle('');
}

function showOverlay() {
    overlay.classList.remove('hidden');
    clearTimeout(overlayTimer);
    overlayTimer = setTimeout(() => overlay.classList.add('hidden'), 4000);
}

function setConnected(yes) {
    statusDot.className = yes ? 'connected' : '';
    statusText.textContent = yes ? 'Waiting for cast…' : 'Connecting to receiver…';
}

// ── Video event wiring ────────────────────────────────────────────────────────
video.addEventListener('waiting', () => spinner.classList.add('visible'));
video.addEventListener('playing', () => spinner.classList.remove('visible'));
video.addEventListener('canplay', () => spinner.classList.remove('visible'));

video.addEventListener('timeupdate', () => {
    const cur = video.currentTime;
    const dur = video.duration || duration;
    if (dur > 0) {
        progressBar.style.width = `${(cur / dur) * 100}%`;
        timeDisplay.textContent = `${fmtTime(cur)} / ${fmtTime(dur)}`;
    }
});

video.addEventListener('ended', () => {
    showIdle();
});

video.addEventListener('error', (e) => {
    console.error('Video error:', e);
    showIdle();
});

// Double-click to toggle fullscreen
playerWrap.addEventListener('dblclick', () => {
    window.castBridge.setFullscreen(!document.fullscreenElement);
});

// Show overlay on mouse move over player
playerWrap.addEventListener('mousemove', showOverlay);

// ── Cast event handlers ───────────────────────────────────────────────────────
const handlers = {
    load({ contentId, contentType, title, subtitle, poster, duration: dur, currentTime }) {
        console.log('[Cast] LOAD', contentType || '?', contentId);
        video.poster = poster || '';
        duration = dur || 0;

        mediaTitle.textContent = title || 'Now Playing';
        mediaSub.textContent = subtitle || '';

        window.castBridge.setTitle(title || 'Now Playing');
        showPlayer();
        showOverlay();
        spinner.classList.add('visible');

        loadMedia(contentId, currentTime || 0);
    },

    play() {
        video.play().catch(() => { });
        showOverlay();
    },

    pause() {
        video.pause();
        showOverlay();
    },

    seek({ currentTime }) {
        video.currentTime = currentTime;
        showOverlay();
    },

    stop() {
        video.pause();
        destroyAll();
        video.src = '';
        showIdle();
    },

    volume({ level, muted }) {
        video.volume = Math.max(0, Math.min(1, level));
        video.muted = muted;
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
