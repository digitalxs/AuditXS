# AuditXS web UI

A local, **Material Design 3** web interface for AuditXS. It is a thin
front-end over the `auditxs` command — everything it does is a command you
could type — so the transparency and reversibility guarantees are unchanged.

## Why a web UI (and who it is for)

The web UI is the graphical interface for **workstations** — run it and it
opens in your browser, with the full audit/harden/rollback workflow behind a
Material Design 3 surface.

It is **disabled on the `server` profile** by design. Servers are kept to
text interfaces only, so a headless box never runs a root web server: use the
ncurses terminal UI over a plain SSH session instead —

```bash
sudo auditxs tui                 # menu-driven, works over SSH, no browser/tunnel
```

— or the CLI directly. If a machine really is a desktop that was installed
with the server profile, override for a one-off with `--profile workstation`
(then the tunnel workflow below applies).

## Launching

```bash
sudo auditxs web                 # starts on http://127.0.0.1:9000 and opens a browser
sudo auditxs web --port 8080     # choose a different port
sudo auditxs web --no-open       # don't auto-open a browser (print the URL only)
```

The default port is **9000**; override it any time with `--port`.

It requires the **workstation** profile, `python3` (standard library only —
no framework, no pip installs) and root, because auditing reads privileged
files such as `/etc/shadow`.

On launch it prints a URL that contains a one-time token:

```
╭─ AuditXS web UI ───────────────────────────────╮
│  Open: http://127.0.0.1:9000/?t=<token>
│  Bound to 127.0.0.1 only. Remote server? Tunnel first:
│    ssh -L 9000:127.0.0.1:9000 user@host
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
ssh -L 9000:127.0.0.1:9000 user@server

# then open the printed http://127.0.0.1:9000/?t=<token> URL in your browser
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
- **Fix it buttons** *(v0.14)* — every FAIL row with an automatic fix carries
  **Fix it** (review → consent → reversible fix → re-audit); WARN and
  manual-fix rows carry **How to fix** with the full remediation guidance.
- **Fleet** *(v0.14)* — manage the host inventory (`user@host` per line),
  SSH key and remote sudo, run a read-only fleet audit with live percentage
  progress, and open the aggregated overview dashboard.
- **Console** *(v0.14)* — a collapsible panel (status bar → *Console*)
  accepting **auditxs subcommands only**: `cve`, `waivers`, `errors AX6002`,
  `schedule status`, … Commands are executed argv-only (never a shell) and
  the subcommand and every argument are validated server-side, keeping the
  injection posture identical to every other route.
- **Status bar** *(v0.14)* — version, profile and live operation progress,
  always visible at the bottom.
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

| | CLI | Web UI | Qt app | zenity GUI |
|---|---|---|---|---|
| Headless server | ✔ | ✔ (SSH tunnel) | ✗ | ✗ |
| Workstation | ✔ | ✔ | ✔ | ✔ |
| Material look, live toggles | – | ✔ | ✔ | – |
| Cross-desktop consistent | n/a | ✔ | ✔ | follows GTK theme |
| Extra dependencies | none | python3 | PySide6/Qt (large) | zenity |
| Automation / scripting | ✔ | – | – | – |

All are front-ends over the same engine; use whichever fits.

### The native Qt app (optional)

For a workstation-first **native desktop** app there's an optional Qt/QML
front-end (PySide6 + Qt Quick Controls, Material style) with real toggle
switches, a dashboard, snapshots and rollback:

```bash
# install the optional add-on package (pulls in the Qt runtime)
sudo apt install ./dist/auditxs-gui-qt_*_all.deb   # build with packaging/build-deb-gui-qt.sh
sudo auditxs qt        # or launch "AuditXS (Qt)" from your desktop menu
```

It's kept a **separate package** so the base `auditxs` and servers never pull
in the large Qt runtime. On headless servers, use the web UI instead.
