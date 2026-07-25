# AuditXS — Electron desktop app

A native desktop window for AuditXS, built on Electron. It is a **thin,
secure shell** around the AuditXS localhost web UI (`gui/auditxs-web.py`):
it starts the same audited web server that `auditxs web` runs, then loads its
loopback URL in a locked-down `BrowserWindow`. Nothing about the UI or its
security model is reimplemented — the web UI's loopback-only bind, per-launch
bearer token, CSRF header, argv-only subprocess calls and strict CSP all apply
unchanged.

The Electron process runs **unprivileged**. The web server needs root (it
drives audits and hardening), so it is elevated once at startup with `pkexec`
— matching the installed polkit `auth_admin_keep` policy, so a whole session
is authorized with a single password prompt. On window close — and on
`SIGTERM`/`SIGINT`/`SIGHUP` — the app asks the server to stop cleanly
(`POST /api/quit` with the token) and sends `SIGTERM` as a fallback.

> If the Electron process is **hard-killed** (`SIGKILL`, a crash), the server
> can't be signalled and keeps running: it is idle, loopback-only, and its
> bearer token died with the app so nothing can drive it — it is reclaimed at
> the next reboot, and a fresh launch simply binds a new free port. A normal
> quit or logout stops it cleanly.

## Run it

The easy way (once AuditXS is installed) is the launcher, which installs the
Node dependency on first use and starts the app:

```bash
auditxs electron
```

Manually, from a checkout:

```bash
cd gui/electron
npm install          # one-time: downloads Electron
AUDITXS_BIN=/opt/auditxs/auditxs npm start
```

`AUDITXS_BIN` points at the `auditxs` executable (the launcher sets it for
you). **Workstation profile only** — like the web/Qt/zenity interfaces, it
refuses to start on a server (use `auditxs tui` there).

## Embedded terminal

The app hosts a **real, fully-interactive terminal inside its own window** —
open it from **Terminal → New Terminal** or with **Ctrl+Shift+T**. It's a
genuine PTY (runs vim, htop, less, and anything else), built with
[xterm.js](https://xtermjs.org/) in the renderer and a dependency-free Python
PTY broker (`pty-bridge.py`) in the main process — **no native `node-pty`
build**, so it installs and runs anywhere Python does (already an AuditXS
dependency). Each terminal window gets its own broker process; keystrokes and
window-size changes are forwarded over Electron IPC, and the shell runs with the
app's own **unprivileged** rights (a shell you could open yourself). If the
front-end can't load, it points you at `auditxs terminal` on the CLI.

## Why three GUIs?

- **zenity** — zero extra dependencies; always available on a desktop.
- **Qt** (`auditxs qt`) — a fully native window (PySide6), no browser engine.
- **web** (`auditxs web`) — a browser tab; also reachable over an SSH tunnel.
- **Electron** (`auditxs electron`) — the web UI as a standalone desktop app
  for people who want an app window without opening a browser.

They all drive the exact same `auditxs` CLI and the same transparent,
reversible engine.

## Files

- `main.js` — the Electron main process (server lifecycle, secure window,
  menu, and the embedded-terminal IPC + PTY broker lifecycle).
- `terminal.html` — the embedded terminal renderer (xterm.js UI).
- `terminal-preload.js` — the small sandboxed IPC bridge (`window.term`).
- `pty-bridge.py` — dependency-free Python PTY broker for the terminal.
- `package.json` — metadata, the Electron dev-dependency, and the xterm.js
  runtime dependencies.

There is intentionally no bundled `node_modules` in the repository; the
launcher (or `npm install`) fetches Electron and xterm.js on first use.
