'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('checkerAPI', {
  getPlatformInfo: () => ipcRenderer.invoke('checker:get-platform-info'),
  startScan: () => ipcRenderer.invoke('checker:start-scan'),
  openPrivacy: () => ipcRenderer.invoke('checker:open-privacy'),
  syncRemote: () => ipcRenderer.invoke('checker:sync-remote'),
  showContextMenu: (payload) => ipcRenderer.send('checker:show-context-menu', payload),
  onScanLog: (callback) => {
    const listener = (_event, payload) => callback(payload);
    ipcRenderer.on('checker:scan-log', listener);
    return () => ipcRenderer.removeListener('checker:scan-log', listener);
  },
});
