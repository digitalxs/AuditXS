// AuditXS — preload for the embedded terminal window.
//
// Runs in the sandboxed, context-isolated renderer and exposes a tiny, typed
// bridge (window.term) to the main process over IPC — nothing else. The
// renderer never gets Node or arbitrary IPC; only these named channels.

'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('term', {
  // Ask the main process to spawn the PTY broker for this window.
  start: (cols, rows) => ipcRenderer.send('term:start', { cols, rows }),
  // Renderer → PTY.
  input: (data) => ipcRenderer.send('term:input', data),
  resize: (cols, rows) => ipcRenderer.send('term:resize', { cols, rows }),
  // PTY → renderer.
  onData: (cb) => ipcRenderer.on('term:data', (_e, bytes) => cb(bytes)),
  onExit: (cb) => ipcRenderer.on('term:exit', (_e, code) => cb(code)),
  onError: (cb) => ipcRenderer.on('term:error', (_e, message) => cb(message)),
});
