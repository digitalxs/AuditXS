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

## Why three GUIs?

- **zenity** — zero extra dependencies; always available on a desktop.
- **Qt** (`auditxs qt`) — a fully native window (PySide6), no browser engine.
- **web** (`auditxs web`) — a browser tab; also reachable over an SSH tunnel.
- **Electron** (`auditxs electron`) — the web UI as a standalone desktop app
  for people who want an app window without opening a browser.

They all drive the exact same `auditxs` CLI and the same transparent,
reversible engine.

## Files

- `main.js` — the Electron main process (server lifecycle + secure window).
- `package.json` — metadata and the Electron dev-dependency.

There is intentionally no bundled `node_modules` in the repository; the
launcher (or `npm install`) fetches Electron on first use.
