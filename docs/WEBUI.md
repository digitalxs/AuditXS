# AuditXS web UI

A local, **Material Design 3** web interface for AuditXS. It is a thin
front-end over the `auditxs` command — everything it does is a command you
could type — so the transparency and reversibility guarantees are unchanged.

## Why a web UI

A hardening tool's most important targets are **servers**, which usually have
no graphical desktop. A native desktop app (zenity/GTK/Qt) cannot run there.
The web UI serves both audiences from one codebase:

- **Workstation:** run it and it opens in your browser.
- **Headless server:** run it over SSH and reach it through a tunnel.

## Launching

```bash
sudo auditxs web                 # starts on http://127.0.0.1:8787 and opens a browser
sudo auditxs web --port 9000     # choose the port
sudo auditxs web --no-open       # don't auto-open a browser (print the URL only)
```

It requires `python3` (standard library only — no framework, no pip installs)
and root, because auditing reads privileged files such as `/etc/shadow`.

On launch it prints a URL that contains a one-time token:

```
╭─ AuditXS web UI ───────────────────────────────╮
│  Open: http://127.0.0.1:8787/?t=<token>
│  Bound to 127.0.0.1 only. Remote server? Tunnel first:
│    ssh -L 8787:127.0.0.1:8787 user@host
│  Stop with Ctrl-C.
╰────────────────────────────────────────────────╯
```

## Using it on a remote (headless) server

The server binds `127.0.0.1` **only** — it is never exposed to the network.
Reach it through an SSH tunnel from your workstation:

```bash
# on the server
sudo auditxs web --no-open

# on your laptop (new terminal) — forward the local port
ssh -L 8787:127.0.0.1:8787 user@server

# then open the printed http://127.0.0.1:8787/?t=<token> URL in your browser
```

## What you can do

- **Dashboard** — the hardening score ring, PASS/FAIL/WARN/SKIP chips, and
  every check grouped by category and domain, with severity, CIS id, level
  and NIST mapping. A red banner appears if a package has a known CVE.
- **Features** — real Material toggle switches, one per fixable control.
  Flipping an *off* control *on* shows the exact `explain` text first (what
  will change / how it reverts), then applies it; the change is recorded in
  a snapshot. Controls already on are locked here — turn them off from
  Snapshots (a rollback), preserving the reversibility model.
- **Snapshots** — every hardening run, with a one-click **Roll back**.
- **Tools** — which defensive tools are installed. Install/scan is done from
  the CLI (`sudo auditxs tools install lynis`, `sudo auditxs tools scan`).
- **Open report** — the full Material HTML report in a new tab.

## Security model

Because the UI drives root operations, it is built defensively:

| Control | Behaviour |
|---|---|
| **Network exposure** | Binds `127.0.0.1` only, always. It cannot be made to listen on a routable address. |
| **Authentication** | A fresh random bearer token every launch; required on every request. The launch URL carries it once, then the page sends it as `X-Auth-Token`. |
| **CSRF** | State-changing actions are POST-only and require the token in a header (not a cookie/query), and the `Host` must be loopback. |
| **Command injection** | Every `auditxs` call uses an argv list — never a shell. Check IDs and snapshot IDs are validated against `[A-Za-z0-9-]`. |
| **Consent** | `harden` is only ever run after you review the change text and confirm. |
| **Content policy** | A strict `Content-Security-Policy` (`default-src 'self'`) and `X-Content-Type-Options: nosniff` are sent on every response. |
| **Least authority** | The server is a front-end; it holds no state and runs the same commands you could run by hand. |

Do **not** port-forward this UI to `0.0.0.0` or expose it publicly. If you
need multi-user or remote access, put it behind your own authenticated
reverse proxy with TLS — but the intended model is localhost + SSH tunnel.

## When to use which interface

| | CLI | Web UI | zenity GUI |
|---|---|---|---|
| Headless server | ✔ | ✔ (SSH tunnel) | ✗ |
| Workstation | ✔ | ✔ | ✔ |
| Material look, live toggles | – | ✔ | – |
| Zero extra dependencies | ✔ | needs python3 | needs zenity |
| Automation / scripting | ✔ | – | – |

All three are front-ends over the same engine; use whichever fits.
