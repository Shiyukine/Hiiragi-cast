const { app, BrowserWindow, ipcMain, webFrameMain } = require('electron');
app.commandLine.appendSwitch('disable-site-isolation-trials')
const path = require('path');
app.userAgentFallback = "Mozilla/5.0 (X11; Linux armv7l) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.7977.65 Safari/537.36 CrKey/1.56.469779";

// Default bridge WebSocket port (must match --bridge-port in run.py)
const BRIDGE_PORT = process.env.BRIDGE_PORT || 9000;

let mainWindow = null;

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1280,
        height: 720,
        titleBarStyle: process.platform == "darwin" ? "hiddenInset" : (process.platform == "linux" ? "default" : "hidden"),
        trafficLightPosition: { x: 10, y: 12 },
        //frame: process.platform != "win32",
        ...(process.platform === 'win32' ? {
            titleBarOverlay: {
                color: '#00000000',
                symbolColor: '#ffffff',
                height: 35
            }
        } : {}),
        backgroundColor: '#000',
        title: 'Hiiragi Cast Player',
        icon: path.join(__dirname, 'src', 'assets', 'icon.png'),
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            // Allow playback of any content URL (CORS bypass for cast streams)
            webSecurity: false,
        },
    });

    // remove X-Frame-Options to allow embedding the player in an iframe (for the web-based UI)
    mainWindow.webContents.session.webRequest.onHeadersReceived((details, callback) => {
        const responseHeaders = details.responseHeaders;
        delete responseHeaders['x-frame-options'];
        delete responseHeaders['content-security-policy-report-only'];
        delete responseHeaders['content-security-policy'];
        callback({ cancel: false, responseHeaders });
    });

    mainWindow.setMenuBarVisibility(false);

    mainWindow.webContents.on('did-finish-load', () => {
        if (process.platform === 'linux') {
            mainWindow.webContents.insertCSS(`#window-top-bar {
                display: none;
            }`
            );
        }
    });

    mainWindow.webContents.on('did-frame-navigate', (event, url, httpResponseCode, httpStatusText, isMainFrame, frameProcessId, frameRoutingId) => {
        if (url.includes('https://www.gstatic.com/cast/sdk/')) {
            try {
                const script = `(() => {
                    navigator.__defineGetter__('userAgent', function() {
                        return "${app.userAgentFallback.split('CrKey/1.56.469779').join("")}";
                    });
                })();`;
                webFrameMain.fromId(frameProcessId, frameRoutingId).executeJavaScript(script);
            } catch (e) {
                console.warn('[Youtube inject] YouTube quality injection failed:', e);
            }
        }
    });

    /**
     * soon :)
     *
    mainWindow.webContents.on('did-frame-navigate', (event, url, httpResponseCode, httpStatusText, isMainFrame, frameProcessId, frameRoutingId) => {
        if (!url.includes('youtube.com') && !url.includes('youtu.be')) return;
        try {
            const _YT_QUALITY_SCRIPT = `(function forceMaxQuality() {
                var p = document.querySelector('.html5-video-player');
                if (!p || typeof p.getAvailableQualityLevels !== 'function') {
                    return setTimeout(forceMaxQuality, 800);
                }
                var levels = p.getAvailableQualityLevels();
                if (!levels || levels.length === 0) {
                    return setTimeout(forceMaxQuality, 800);
                }
                var current = p.getPlaybackQuality();
                var best = "hd2160";
                if (current != best) {
                    try { p.setPlaybackQualityRange(best, best); } catch(e) {}
                    try { p.setPlaybackQuality(best); } catch(e) {}
                }
                // Re-apply every 5 s in case auto-quality kicks back in
                setTimeout(forceMaxQuality, 5000);
            })();`;
            webFrameMain.fromId(frameProcessId, frameRoutingId).executeJavaScript(_YT_QUALITY_SCRIPT);
        } catch (e) {
            console.warn('[Youtube inject] YouTube quality injection failed:', e);
        }
    });*/

    // Pass the bridge port to the renderer via query param
    mainWindow.loadURL(
        `file://${path.join(__dirname, 'src', 'index.html')}?bridgePort=${BRIDGE_PORT}`
    );
}

app.whenReady().then(() => {
    createWindow();
    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
});

// Renderer can ask to go fullscreen via IPC
ipcMain.on('set-fullscreen', (_, flag) => {
    mainWindow?.setFullScreen(flag);
});

ipcMain.on('set-title', (_, title) => {
    mainWindow?.setTitle(title ? `${title} – Hiiragi Cast` : 'Hiiragi Cast Player');
});

