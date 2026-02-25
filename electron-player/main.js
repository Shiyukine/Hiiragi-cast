const { app, BrowserWindow, ipcMain } = require('electron');
app.commandLine.appendSwitch('disable-site-isolation-trials')
const path = require('path');
app.userAgentFallback = "Mozilla/5.0 (X11; Linux armv7l) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 CrKey/1.56.467165";

// Default bridge WebSocket port (must match --bridge-port in run.py)
const BRIDGE_PORT = process.env.BRIDGE_PORT || 9000;

let mainWindow = null;

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1280,
        height: 720,
        backgroundColor: '#000',
        title: 'Hiiragi Cast Player',
        icon: path.join(__dirname, 'assets', 'icon.png'),
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false,
            // Allow playback of any content URL (CORS bypass for cast streams)
            webSecurity: false,
            // Required for <webview> tag to work in the renderer
            webviewTag: true,
        },
    });

    // remove X-Frame-Options to allow embedding the player in an iframe (for the web-based UI)
    mainWindow.webContents.session.webRequest.onHeadersReceived((details, callback) => {
        const responseHeaders = details.responseHeaders;
        delete responseHeaders['x-frame-options'];
        delete responseHeaders['content-security-policy-report-only'];
        delete responseHeaders['content-security-policy'];
        delete responseHeaders[''];
        callback({ cancel: false, responseHeaders });
    });

    mainWindow.loadFile('index.html');
    mainWindow.setMenuBarVisibility(false);

    // Pass the bridge port to the renderer via query param
    mainWindow.loadURL(
        `file://${path.join(__dirname, 'index.html')}?bridgePort=${BRIDGE_PORT}`
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

