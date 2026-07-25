// AuditXS — Electron desktop shell.
//
// This is a thin, secure native window around the AuditXS localhost web UI
// (gui/auditxs-web.py). It does NOT reimplement the UI: it starts the same
// audited web server the `auditxs web` command runs, then loads its
// loopback URL in a locked-down BrowserWindow. All of the web UI's security
// properties (loopback-only bind, per-launch bearer token, CSRF header,
// argv-only subprocess calls, strict CSP) therefore apply unchanged.
//
// The Electron process itself runs UNPRIVILEGED. The web server needs root
// (it drives audits/hardening), so it is elevated once at startup with
// pkexec — matching the polkit "auth_admin_keep" policy, so the whole
// session is authorized with a single prompt. When the window closes we ask
// the server to stop cleanly (POST /api/quit with the token) and also send
// SIGTERM as a fallback.

'use strict';

const { app, BrowserWindow, Menu, ipcMain, shell, dialog } = require('electron');
const { spawn } = require('child_process');
const http = require('http');
const net = require('net');
const path = require('path');

const AUDITXS = process.env.AUDITXS_BIN || 'auditxs';
const PYTHON = process.env.AUDITXS_PYTHON || 'python3';

let serverProc = null;
let serverURL = null;
let serverPort = null;
let serverToken = null;

// Ask the OS for a free loopback port so two instances never collide.
function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
  });
}

// Start `auditxs web` (via pkexec when we are not already root) and resolve
// once it prints its loopback URL + token.
function startServer(port) {
  return new Promise((resolve, reject) => {
    const asRoot = typeof process.getuid === 'function' && process.getuid() === 0;
    const cmd = asRoot ? AUDITXS : 'pkexec';
    const args = asRoot
      ? ['web', '--no-open', '--port', String(port)]
      : [AUDITXS, 'web', '--no-open', '--port', String(port)];

    const proc = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let buf = '';
    let settled = false;

    const scan = (chunk) => {
      buf += chunk.toString();
      const m = buf.match(/http:\/\/127\.0\.0\.1:(\d+)\/\?t=([A-Za-z0-9_-]+)/);
      if (m && !settled) {
        settled = true;
        serverURL = m[0];
        serverPort = m[1];
        serverToken = m[2];
        resolve(proc);
      }
    };
    proc.stdout.on('data', scan);
    proc.stderr.on('data', scan);
    proc.on('error', (e) => { if (!settled) { settled = true; reject(e); } });
    proc.on('exit', (code) => {
      if (!settled) {
        settled = true;
        reject(new Error('the web server exited before it was ready (code ' + code +
          '). Was the authentication prompt cancelled?'));
      }
    });
    setTimeout(() => {
      if (!settled) { settled = true; reject(new Error('timed out waiting for the AuditXS web server')); }
    }, 30000);
  });
}

// Clean shutdown: the server runs as root, so we cannot always kill it from an
// unprivileged process — ask it to stop over its own authenticated API.
function quitServer() {
  return new Promise((resolve) => {
    if (!serverPort || !serverToken) return resolve();
    const req = http.request({
      host: '127.0.0.1',
      port: Number(serverPort),
      path: '/api/quit',
      method: 'POST',
      headers: {
        'X-Auth-Token': serverToken,
        'Content-Type': 'application/json',
        'Content-Length': 2,
      },
    }, () => resolve());
    req.on('error', () => resolve());
    req.write('{}');
    req.end();
    setTimeout(resolve, 1500);
  });
}

// ---- embedded terminal -----------------------------------------------------
// A real, fully-interactive terminal (like Konsole) inside the app: xterm.js in
// the renderer, a dependency-free Python PTY broker (pty-bridge.py) here. It
// runs with the app's own UNPRIVILEGED rights — a shell the user could open
// themselves, so no privilege is added. One broker process per terminal window.
const terms = new Map();   // webContents.id -> child process

function writeResize(child, cols, rows) {
  try {
    const ctrl = child.stdio && child.stdio[3];
    if (ctrl && ctrl.writable) {
      ctrl.write(JSON.stringify({ resize: [Number(cols) || 80, Number(rows) || 24] }) + '\n');
    }
  } catch (e) { /* child may have exited */ }
}

function killTerm(id) {
  const child = terms.get(id);
  if (!child) return;
  terms.delete(id);
  try { child.stdin.end(); } catch (e) { /* ignore */ }
  try { child.kill('SIGTERM'); } catch (e) { /* ignore */ }
}

function openTerminalWindow() {
  const win = new BrowserWindow({
    width: 900,
    height: 560,
    minWidth: 480,
    minHeight: 280,
    title: 'AuditXS — Terminal',
    backgroundColor: '#121318',
    autoHideMenuBar: true,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      preload: path.join(__dirname, 'terminal-preload.js'),
    },
  });
  win.on('closed', () => killTerm(win.webContents.id));
  win.loadFile(path.join(__dirname, 'terminal.html'));
  return win;
}

// The renderer asks us to start its shell once xterm is laid out.
ipcMain.on('term:start', (e, size) => {
  const id = e.sender.id;
  if (terms.has(id)) return;               // already running for this window
  const send = (channel, payload) => {
    if (!e.sender.isDestroyed()) e.sender.send(channel, payload);
  };
  let child;
  try {
    child = spawn(PYTHON, [path.join(__dirname, 'pty-bridge.py')], {
      stdio: ['pipe', 'pipe', 'pipe', 'pipe'],
      env: Object.assign({}, process.env, { TERM: 'xterm-256color' }),
    });
  } catch (err) {
    send('term:error', 'Could not start the terminal: ' + err.message +
      ' (is python3 installed?)');
    return;
  }
  terms.set(id, child);
  child.stdout.on('data', (d) => send('term:data', new Uint8Array(d)));
  child.stderr.on('data', () => { /* the shell's stderr is on the PTY already */ });
  child.on('error', (err) => send('term:error',
    'Could not start the terminal: ' + err.message + ' (is python3 installed?)'));
  child.on('exit', (code) => { terms.delete(id); send('term:exit', code); });
  if (size) writeResize(child, size.cols, size.rows);
});

ipcMain.on('term:input', (e, data) => {
  const child = terms.get(e.sender.id);
  if (child) { try { child.stdin.write(data); } catch (err) { /* exited */ } }
});

ipcMain.on('term:resize', (e, size) => {
  const child = terms.get(e.sender.id);
  if (child && size) writeResize(child, size.cols, size.rows);
});

function buildMenu() {
  const template = [
    { label: 'AuditXS', submenu: [{ role: 'reload' }, { role: 'toggleDevTools' },
      { type: 'separator' }, { role: 'quit' }] },
    { label: 'Terminal', submenu: [
      { label: 'New Terminal', accelerator: 'CmdOrCtrl+Shift+T', click: openTerminalWindow },
    ] },
    { role: 'editMenu' },
    { role: 'viewMenu' },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1200,
    height: 860,
    minWidth: 820,
    minHeight: 560,
    title: 'AuditXS',
    backgroundColor: '#121318',
    autoHideMenuBar: true,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  // Lock navigation to the local server; hand external links to the browser.
  const isLocal = (u) => u.startsWith('http://127.0.0.1:');
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (isLocal(url)) return { action: 'allow' };
    shell.openExternal(url);
    return { action: 'deny' };
  });
  win.webContents.on('will-navigate', (e, url) => {
    if (!isLocal(url)) { e.preventDefault(); shell.openExternal(url); }
  });

  return win.loadURL(serverURL).then(() => win);
}

app.whenReady().then(async () => {
  try {
    buildMenu();
    const port = await freePort();
    serverProc = await startServer(port);
    await createWindow();
  } catch (e) {
    dialog.showErrorBox('AuditXS',
      'Could not start the AuditXS desktop app:\n\n' + e.message +
      '\n\nMake sure AuditXS is installed and you approve the authentication prompt.');
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0 && serverURL) createWindow();
});

let shuttingDown = false;
async function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  for (const id of Array.from(terms.keys())) killTerm(id);
  await quitServer();
  if (serverProc) { try { serverProc.kill('SIGTERM'); } catch (e) { /* ignore */ } }
}

app.on('window-all-closed', async () => {
  await shutdown();
  app.quit();
});
app.on('before-quit', () => { if (serverProc) { try { serverProc.kill('SIGTERM'); } catch (e) { /* ignore */ } } });

// Abrupt termination (logout, `kill`, Ctrl-C) does not run before-quit, and
// the server may be running as root (via pkexec) where we cannot kill it
// directly — so stop it over its authenticated /api/quit, then exit. Without
// this the server (and its bound port) would leak.
function handleSignal() {
  shutdown().then(() => app.exit(0)).catch(() => app.exit(0));
}
process.on('SIGTERM', handleSignal);
process.on('SIGINT', handleSignal);
process.on('SIGHUP', handleSignal);
