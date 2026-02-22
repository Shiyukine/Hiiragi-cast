const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('castBridge', {
    setFullscreen: (flag) => ipcRenderer.send('set-fullscreen', flag),
    setTitle: (title) => ipcRenderer.send('set-title', title),
});
