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

const { app, BrowserWindow, shell, dialog } = require('electron');
const { spawn } = require('child_process');
const http = require('http');
const net = require('net');

const AUDITXS = process.env.AUDITXS_BIN || 'auditxs';

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
