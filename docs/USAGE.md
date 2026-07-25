# AuditXS user manual

AuditXS audits Linux systems against fundamental security baselines and —
only with your explicit consent — hardens them with fully reversible
changes. This manual covers the CLI, the GUI, and the operational
workflows. See [COMPLIANCE.md](COMPLIANCE.md) for framework alignment and
[CHECKS.md](CHECKS.md) for every check's documentation.

## Contents

1. [Concepts](#concepts)
2. [Installation](#installation)
3. [Auditing](#auditing)
4. [Hardening](#hardening)
5. [Rollback](#rollback)
6. [Baselines & drift detection](#baselines--drift-detection)
7. [Scheduled audits](#scheduled-audits)
8. [Maintenance (doctor)](#maintenance-doctor)
9. [The GUI](#the-gui-workstation-profile)
10. [Privileges & credential caching](#privileges--credential-caching)
11. [Debugging](#debugging)
12. [Files & directories](#files--directories)
13. [Exit codes](#exit-codes)

## Concepts

- **Check** — one auditable statement about the system (e.g. `SSH-001 —
  SSH root login is disabled`). Every check documents what it inspects,
  why it matters, what its fix changes and how that is reverted:
  `auditxs explain SSH-001`.
- **Status** — `PASS`, `FAIL` (finding; a fix is offered when the check
  provides one), `WARN` (needs human judgement — never auto-fixed), `SKIP`
  (not applicable: software absent or wrong profile).
- **Profile** — `server` or `workstation`, chosen at install time
  (`/etc/auditxs/auditxs.conf`), overridable per run with `--profile`.
- **Category / Domain** — checks are grouped in categories (SSH, Kernel,
  …) which roll up into five assessment domains: Server Hardening,
  OS Hardening, Network Security, Application Hardening, Database
  Hardening.
- **Snapshot** — the recorded pre-change state (file copies + action
  manifest) created automatically by the first change of a `harden` run.
- **Baseline** — an approved audit report used to detect drift.

## Installation

```bash
git clone https://github.com/digitalxs/AuditXS.git
cd AuditXS
sudo ./setup.sh                    # interactive: mode + Server/Workstation
sudo ./setup.sh --server -y        # non-interactive server install
sudo ./setup.sh --workstation -y --no-gui
sudo ./setup.sh --refresh          # repair/update files, keep configuration
sudo update-auditxs                # update an existing installation
sudo /opt/auditxs/uninstall.sh    # remove (asks before deleting snapshots)
```

## Auditing

Audits are **strictly read-only** — nothing on the system changes.

```bash
sudo auditxs audit                          # everything applicable to the profile
sudo auditxs audit --category SSH           # one category
sudo auditxs audit --domain "Database"      # one assessment domain
sudo auditxs audit --check SSH-001 --check FW-002
sudo auditxs audit --profile server         # override the configured profile
sudo auditxs audit --format json            # machine-readable to stdout (also: tsv, html)
```

Every console audit saves timestamped HTML and JSON reports under
`/var/lib/auditxs/reports/` (plus `latest.json` / `latest.html`) and ends
with a severity-weighted hardening score (0–100).

**Progress.** Every interface shows live progress with a percentage while an
operation runs. On the CLI a progress bar (`████░░ 45% (55/122) SSH-003`)
is drawn on stderr below the scrolling results whenever the terminal is
interactive — it disappears automatically when output is piped or captured
(force it off with `AUDITXS_NO_PROGRESS=1`). The terminal UI shows a dialog
gauge, the zenity and Qt apps a percentage dialog/bar, and the web UI a
Material progress bar — all fed by the same engine. During `harden`, each fix
is announced as `fix N of M (P%)`; fleet mode prints `(host i/N · P%)` per
host. Integrators can read the machine progress with
`--progress-file <path>`: the engine rewrites one line, `PCT DONE TOTAL
CHECK-ID`, after every check.

The **HTML report is interactive** (while staying a single, self-contained
file you can archive or email):

- **Show only findings** — a toggle in the score card hides every passed,
  skipped and waived check, so the report shows just the FAILs and WARNs;
  categories with nothing left to show disappear too. Flip it back to see
  the full evidence trail.
- **Fix it / How to fix buttons** — every FAIL and WARN row carries a button.
  For a failing check with an automatic, reversible fix it reveals (and copies
  to the clipboard) the exact command — `sudo auditxs harden --check <ID>` —
  which audits just that check and offers its fix with the usual consent and
  snapshot. For warnings and manual-fix items it gives
  `auditxs explain <ID>`, the documented remediation guidance. A static
  report never executes anything itself — the buttons hand you the command,
  and AuditXS still asks before changing the system.

To read the catalogue without running anything:

```bash
auditxs list                # table of all checks
auditxs list --markdown     # full documentation (source of docs/CHECKS.md)
auditxs explain FW-002      # one check in depth, including NIST CSF mapping
```

## Hardening

```bash
sudo auditxs harden --dry-run     # preview: every intended command/file, zero changes
sudo auditxs harden               # interactive: each fix explained, then confirmed
sudo auditxs harden --category SSH
sudo auditxs harden --check NET-002 --yes   # non-interactive (automation)
```

For each failing check with an automatic fix, AuditXS shows what is
checked and why, exactly what the fix changes, and how it is reverted —
then asks. After applying, the check is re-audited and the honest result
reported. All changes of one run land in a single snapshot.

Checks whose remediation is irreversible or judgement-heavy (package
upgrades, sudoers NOPASSWD entries, database settings, MFA enrolment…)
are **report-only**: they explain the manual path and never touch the
system.

## Rollback

```bash
sudo auditxs snapshots            # list snapshots (id, date, actions, state)
sudo auditxs rollback latest      # undo the most recent hardening run
sudo auditxs rollback 20260712-211102
```

Rollback shows the full plan (every recorded action, reverted in reverse
order), asks for confirmation, restores files byte-for-byte, re-applies
recorded permissions/sysctl/service states, offers to remove packages
AuditXS installed, then validates and reloads affected daemons (sshd is
re-validated with `sshd -t` before reload). The global ledger
`/var/lib/auditxs/changes.log` records everything ever changed, including
rollbacks.

## Baselines & drift detection

Capture a known-good state and detect any regression from it:

```bash
sudo auditxs audit                     # produce a report
sudo auditxs baseline set              # approve the latest report as baseline
auditxs baseline show                  # inspect the approved baseline
sudo auditxs audit --baseline /etc/auditxs/baseline.json   # compare inline
sudo auditxs diff /etc/auditxs/baseline.json               # compare latest report
```

`auditxs diff` exits **1 when any check regressed**, so it can gate CI
pipelines or fire monitoring alerts. Improvements, regressions and scope
changes are listed separately with the score delta.

Port-level drift: approve the expected listening ports once and `NET-004`
fails whenever anything new starts listening — see
`auditxs explain NET-004`.

## Scheduled audits

```bash
sudo auditxs schedule enable    # daily read-only audit via systemd timer
auditxs schedule status
sudo auditxs schedule disable
```

The timer runs `auditxs schedule run`: a quiet audit (reports saved as
usual) followed by a comparison against the approved baseline. A
regression makes the service run **fail**, which any systemd-based
monitoring picks up (`systemctl status auditxs-audit.service`, journal,
OnFailure hooks). Without systemd, add a cron entry:
`0 3 * * * /usr/local/bin/auditxs schedule run`.

## Vulnerability (CVE) warnings

```bash
sudo auditxs cve                  # warn about installed packages with a known CVE
```

Uses the distribution's own security data (Debian: `debsecan` or the
security apt suite; Fedora: `dnf updateinfo`; openSUSE: `zypper patches`).
Exits non-zero when vulnerable packages are found. The same signal appears
automatically at the end of every `audit` (console banner + check
`VULN-001` + HTML report banner + log) and in the GUI after an audit. For a
precise per-CVE list on Debian, `sudo auditxs tools install debsecan`.

## Applying package updates

Keeping packages patched is the single most effective control, so AuditXS can
apply updates for you — three ways, all consented:

```bash
sudo auditxs update --dry-run       # preview exactly what would be updated
sudo auditxs update                 # apply pending SECURITY updates (asks first)
sudo auditxs update --all           # a full upgrade (asks first)
sudo auditxs update --security --yes # non-interactive (automation)
```

`update` previews the change list first, then applies on consent (or `--yes`).
It defaults to **security** updates; `--all` does a full upgrade. On Arch only
a full `pacman -Syu` is supported (partial upgrades are unsupported there).

> **Important:** a package upgrade is **not reversible** by `auditxs rollback`
> — the snapshot engine cannot undo a software upgrade. `update` says so and is
> deliberately kept out of the harden/rollback flow. It records start/finish in
> the change ledger (`/var/lib/auditxs/changes.log`).

**To patch automatically**, choose either:

- **Let the OS do it** — the `UPD-002` control ("automatic security updates")
  is a *reversible* hardening fix: applying it installs and enables the
  distribution's own mechanism (`unattended-upgrades` on Debian/Ubuntu/Pop!_OS,
  `dnf-automatic` on Fedora). The system then patches itself, and
  `auditxs rollback` can undo the configuration.
- **Let the scheduled audit do it** — set `AUTO_UPDATE=1` in
  `/etc/auditxs/auditxs.conf`. The daily `auditxs schedule` run then applies
  pending security updates whenever it finds them (and, if `ALERT_WEBHOOK` /
  `ALERT_EMAIL` are configured, notifies you). Off by default.

## Security tooling

```bash
sudo auditxs tools status         # which defensive tools are installed
sudo auditxs tools install lynis  # guided, reversible install (also: rkhunter,
                                  # aide, debsecan, suricata, crowdsec, fail2ban…)
sudo auditxs tools scan           # run installed scanners, collect their reports
auditxs tools vpn                 # review WireGuard / OpenVPN configuration
```

Scanner reports are saved under `/var/lib/auditxs/reports/tools/<timestamp>/`.
CrowdSec and OSSEC/Wazuh require third-party installers — AuditXS prints the
official steps rather than piping a remote script into your shell.

## Fleet mode — auditing many hosts over SSH

```bash
auditxs fleet web01 db01 app03            # audit three hosts (uses your SSH agent/keys)
auditxs fleet web01 --user admin --key ~/.ssh/id_ed25519 --sudo
auditxs fleet --inventory hosts.txt --ask-pass   # SSH login password for all hosts (needs sshpass)

# Log in over SSH, then use sudo with a password on the host (no passwordless
# sudo needed) — prompts once for the SSH password and once for the sudo password:
auditxs fleet --inventory hosts.txt --user admin --ask-pass --ask-sudo-pass

# SSH key login + sudo password (the most common setup):
auditxs fleet --inventory hosts.txt --key ~/.ssh/id_ed25519 --ask-sudo-pass
```

**Authenticating to the host and to root.** `--ask-pass` prompts once for the
SSH *login* password (needs `sshpass`); `--ask-sudo-pass` prompts once for the
remote *sudo* password and feeds it to `sudo -S` over the SSH channel's stdin —
so it never appears in the process list on either machine, and you do **not**
need passwordless sudo on the hosts. `--sudo` alone still works when the login
user has passwordless sudo (`NOPASSWD`). All three GUIs expose the same
credentials on their Fleet screen (SSH key **or** password, plus an optional
sudo password); passwords entered there are used only for that run and never
saved.

Fleet mode runs a **read-only** `auditxs audit` on each host and prints an
aggregated score table, saving each host's JSON — plus an **aggregated HTML
overview dashboard** (`index.html`) — under
`/var/lib/auditxs/reports/fleet/<timestamp>/`. It **never** hardens over SSH —
review each report and harden that host locally. Each remote host must have
AuditXS installed; fleet never pushes code.

| Option | Meaning |
|---|---|
| `--hosts a,b,c` / positional | hosts to audit (`user@host` or `host`) |
| `--inventory <file>` | read hosts from a file (one `user@host` per line, `#` comments) |
| `--user <name>` | default SSH user for hosts written without `user@` |
| `--key <file>` | SSH private key (key auth is preferred) |
| `--ask-pass` | prompt once for the **SSH login** password, used for all hosts (via `sshpass`) |
| `--sudo` | run the remote audit via **passwordless** sudo (`sudo -n`) |
| `--ask-sudo-pass` | prompt once for the remote **sudo** password; fed to `sudo -S` over SSH (never on the command line) |
| `--port <n>` | SSH port (default 22) |
| `--timeout <sec>` | per-host timeout (default 120) · `--output <dir>` where reports go |
| `--remote-report` | also generate a full HTML report **on each audited host** (`/var/lib/auditxs/reports/`) and fetch a copy back |
| `--strict-host-key` / `--insecure-host-key` | tighten or disable host-key checking |

**Authentication** prefers keys; password auth passes the password to `sshpass`
through the environment, never the command line. **Host keys** are verified
(trust-on-first-use, refusing changed keys). **Exit codes**: `2` if any host
could not be audited, `1` if some host has failing checks, `0` if all clean.
Any failure prints a stable error number (see below).

### A complete walkthrough

This sets up a small fleet (three servers) for recurring audits from one
controller machine.

**1. Install AuditXS on every target.** Fleet never pushes code — each host
runs its own installed copy:

```bash
ssh admin@web01 'git clone https://github.com/digitalxs/AuditXS && sudo AuditXS/setup.sh'
# or install the .deb on Debian/Ubuntu targets
```

**2. Create an audit user and key.** A dedicated user keeps the access
auditable and the key non-interactive:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/auditxs_fleet -C "auditxs fleet"
for h in web01 db01 mail01; do ssh-copy-id -i ~/.ssh/auditxs_fleet admin@$h; done
```

**3. Allow the remote audit to run as root** (full results need root — without
it, privileged checks come back SKIP/WARN and scores read lower than reality).
On each target add a narrow sudoers rule:

```
# /etc/sudoers.d/auditxs-fleet  (visudo -f)
admin ALL=(root) NOPASSWD: /usr/local/bin/auditxs
```

**4. Write an inventory** — one `user@host` per line, `#` comments allowed:

```
# fleet.txt — production
admin@web01
admin@db01
admin@mail01     # mail relay
```

**5. Run the fleet audit:**

```bash
auditxs fleet --inventory fleet.txt --key ~/.ssh/auditxs_fleet --sudo --remote-report
```

Each host is audited read-only in turn; you get a per-host result line, then
the aggregated summary table, and the reports listed below. Re-run any time —
each run gets its own timestamped directory, so history is preserved.

**6. Review and act.** Open the overview dashboard (next section), drill into
a host's report, then fix findings *on that host* with `sudo auditxs harden`.
For drift detection between runs, compare a host's JSON from two runs:

```bash
auditxs diff /var/lib/auditxs/reports/fleet/<old>/web01.json \
             /var/lib/auditxs/reports/fleet/<new>/web01.json
```

### The fleet overview dashboard

Every run writes an aggregated **HTML overview** to
`/var/lib/auditxs/reports/fleet/<timestamp>/index.html` (also printed at the
end of the run). It is a single self-contained page — no external assets, safe
to archive or email — showing:

- the **fleet-average hardening score** as a dial, and chips counting hosts
  that are clean / have findings / could not be audited;
- a **per-host table**: state, pass/fail/warn counts, a score bar, and links
  to that host's saved `JSON` (and `HTML` with `--remote-report`) reports —
  the links are relative, so the directory can be copied elsewhere intact;
- the standing reminder that fleet mode changed nothing, and that hardening
  happens per-host after review.

### Troubleshooting a fleet run

Every per-host failure is classified to a stable error number shown in the
summary; `auditxs errors <code>` explains any of them.

| State in table | Code | Typical cause |
|---|---|---|
| `UNREACHABLE` | AX6001 | host down, wrong name/port, firewall |
| `AUTHFAIL` | AX6002 | wrong user, key not installed, password wrong |
| `HOSTKEY` | AX6003 | host key changed (reinstall — or MITM; verify!) |
| `NO-AUDITXS` | AX6005 | AuditXS not installed on the target |
| `NO-RESULT` | AX6006 | remote audit produced no JSON (try `--sudo`) |
| `TIMEOUT` | AX6007 | slow host/link — raise `--timeout` |

## Error numbers

Every recoverable failure reports a unique `AXnnnn` code with a plain
explanation and fix, on the console and in `/var/lib/auditxs/errors.log`.

```bash
auditxs errors            # the whole catalogue (the "database")
auditxs errors AX6002     # explain one code
auditxs errors ssh        # search titles/descriptions
auditxs errors log        # recent occurrences on this host
```

The full catalogue is also in [ERRORS.md](ERRORS.md) (regenerate with
`auditxs errors --markdown`).

## Maintenance (doctor)

```bash
auditxs doctor        # as root, also verifies snapshot integrity
```

Doctor verifies the installation (commands, registered checks), required
and feature tooling, configuration (profile, baseline, port allowlist),
snapshot integrity (manifest structure and saved file copies), state size,
the change ledger, and the scheduled-audit timer. Exit code 1 means at
least one real problem was found.

## Interfaces by profile

AuditXS deliberately limits its interfaces by profile. Servers get **text
interfaces only** — the CLI and an ncurses terminal UI — so a headless box
never runs a browser, an X client, or a root web server. Workstations may
use any interface.

| Interface | Command | Server | Workstation |
|---|---|:---:|:---:|
| Command line | `auditxs audit` / `harden` / … | ✔ | ✔ |
| Terminal UI (ncurses) | `sudo auditxs tui` | ✔ | ✔ |
| Localhost web UI | `sudo auditxs web` | – | ✔ |
| Native desktop app (Qt) | `sudo auditxs qt` | – | ✔ |
| Graphical launcher (zenity) | `auditxs-gui` | – | ✔ |

`web`, `qt` and `auditxs-gui` refuse to start on the server profile and
point you at `sudo auditxs tui`. Check the active profile with `auditxs
profile`; override per-run with `--profile workstation` (or edit
`/etc/auditxs/auditxs.conf`).

## The terminal UI (ncurses)

```bash
sudo auditxs tui                 # menu-driven interface in the terminal
```

The recommended interface for servers: it runs entirely in the terminal
over a plain SSH session — no browser, no tunnel, no X, no root web server.
It is a thin front-end over the CLI (whiptail, or `dialog` as a fallback)
and offers the full workflow — audit, turn controls on/off, roll back,
CVE check, install/run security tools, generate a report, doctor — with the
same mandatory *review before every change* screen as the CLI. Available on
workstations too.

## The web UI (workstation profile)

```bash
sudo auditxs web                 # Material Design web UI on http://127.0.0.1:9000
sudo auditxs web --port 9000 --no-open
```

A localhost-only, token-authenticated Material Design 3 interface (Python
standard library — no framework). Disabled on the server profile (use the
terminal UI over SSH instead). Full details and the security model:
[WEBUI.md](WEBUI.md).

## The GUI (workstation profile)

`auditxs-gui` is a thin wrapper over the CLI — everything it does is a visible
`auditxs` command, elevated per-operation via pkexec so you see an
authentication prompt exactly when privileges are used. Like the web and Qt
interfaces it is disabled on the server profile.

**Which window you get.** When the Qt app (`auditxs-gui-qt`, PySide6) is
installed, `auditxs-gui` opens the **windowed Qt interface** — a single
application window with its own title bar and full window controls (minimize,
maximize/restore, move, resize). Without PySide6 it falls back to the classic
**zenity** dialogs. zenity dialogs are drawn by your window manager and cannot
carry their own min/max buttons (on GNOME's default layout the WM shows only a
close button), which is why the windowed Qt app is preferred when available.
Force one or the other:

```bash
AUDITXS_GUI=qt      auditxs-gui      # require the windowed Qt app
AUDITXS_GUI=zenity  auditxs-gui      # use the classic zenity dialogs
```

The Qt window runs unprivileged and elevates each action with pkexec, so it
displays normally on both X11 and Wayland. The zenity flow (below) behaves the
same way.

- **Audit** — read-only audit with a sortable results table; a CVE warning
  pops up afterwards if vulnerable packages are found.
- **Features** — the on/off toggle view: every security control with its
  live ON/OFF state. Tick an off control and apply to turn it on (with the
  mandatory review screen); turn controls off again via Rollback.
- **Harden** — pick fixes from a checklist, review *exactly what will
  change* (mandatory review screen), apply, see the full change log.
- **Tools** — install security tools, run scanners, review VPN config.
- **Report** — generate and open the Material-style HTML report.
- **Rollback** — pick a snapshot, see it reverted.
- **Baseline** — approve the latest audit for drift alerts.
- **Doctor / Catalogue / About**.

The console output uses a clean **nala-style** boxed layout; the HTML report
uses **Material Design 3** (theme-aware light/dark, score ring, status
chips). The zenity GUI itself follows your desktop's GTK theme.

### Four graphical interfaces (v0.16)

All four drive the same `auditxs` CLI and the same reversible engine; pick
whichever fits:

- **zenity** (`auditxs-gui`) — zero extra dependencies, always available on a
  desktop.
- **Qt** (`auditxs qt`) — a fully native window (PySide6), no browser engine.
- **web** (`auditxs web`) — a browser tab; also reachable over an SSH tunnel.
- **Electron** (`auditxs electron`) — the web UI as a standalone desktop app.
  It runs unprivileged and elevates the web server once with `pkexec` (one
  prompt per session with the polkit *keep* policy). Needs Node.js; the
  Electron runtime is fetched per-user on first launch, so the first
  `auditxs electron` may take a moment while it downloads.

Every button and control is wired to a real action: **Fix it** applies a
reversible fix after review; the **Feature** on/off switches turn the
corresponding control on when toggled (after the mandatory review step); the
**Fleet** controls run remote audits; the **console** runs commands. These
flows are exercised end-to-end in the test suite (browser-driven for the web
UI, offscreen-QML plus a data-layer selftest for Qt).

### The GUIs do everything the CLI does (v0.14)

- **Fix it on every finding.** Each FAIL/WARN row (Qt dashboard, web
  dashboard, and the zenity results list via *Fix / Details*) carries a
  button: **Fix it** runs the review → consent → reversible-fix → verify flow
  for that one check; **How to fix** shows detailed manual guidance (the
  exact change to make, and how it would be reverted) when no automatic fix
  exists.
- **Fleet from the GUI.** The Fleet tab (Qt, web) / submenu (zenity) manages
  hosts (`user@host`), the SSH key and remote sudo, and runs the fleet audit
  with live percentage progress, ending at the aggregated overview
  dashboard. Qt and zenity share `~/.config/auditxs/fleet-hosts`; the web UI
  (running as root) manages `/var/lib/auditxs/fleet-hosts`.
- **Embedded console.** A collapsible panel at the bottom (status bar →
  *Console*): in the Qt app it runs any command with your user's own
  privileges (line-based — interactive TUI programs still need a real
  terminal); in the web UI it accepts **auditxs subcommands only**, executed
  argv-only with no shell, matching the web UI's strict security model.
  The zenity menu's *Terminal* entry opens your system terminal instead.
- **Ops everywhere.** CVE scan, doctor, schedule, baseline, waivers, alerts,
  the error catalogue and the check catalogue are one click away (Qt *Ops*
  tab, zenity menu entries, web console).
- **Status bar.** Qt and the web UI show the version, profile and host plus
  the live operation percentage at the bottom of the window at all times.

## Privileges & credential caching

You should only have to authenticate **once per working session**, not once
per action:

- **CLI** — a single command run (`sudo auditxs harden`) authenticates once
  for the whole run, however many fixes you apply. Between commands, sudo's
  own credential cache applies (15 minutes by default per terminal), so
  consecutive `sudo auditxs …` commands do not re-prompt. Adjust with
  `timestamp_timeout` in sudoers if your policy allows a longer window.
- **GUIs (Qt, zenity)** — the graphical front-ends run unprivileged and
  elevate each individual operation with **pkexec**. AuditXS installs a
  polkit policy (`com.digitalxs.auditxs.policy`, action
  `com.digitalxs.auditxs.run`) whose default is **`auth_admin_keep`**: the
  first elevated action prompts, and polkit then remembers the authorization
  for the active desktop session (about five minutes, the polkit default), so
  a burst of consecutive GUI actions asks for your password once. The policy
  is installed by `setup.sh` and by the `.deb`, and removed on uninstall.
  It applies only to the exact installed AuditXS binary paths
  (`/opt/auditxs/auditxs`, `/usr/share/auditxs/auditxs`) — running from a
  development checkout keeps the stricter prompt-every-time default.
- **Web UI and terminal UI** — `sudo auditxs web` / `sudo auditxs tui`
  authenticate once at launch and keep running with that privilege; there are
  no further prompts for the life of the session.

This design keeps the security property that matters — privileges are only
ever exercised through the consented AuditXS entry points — while removing
repeated password prompts inside one burst of work.

## Debugging

```bash
sudo auditxs audit --debug        # per-check timings, return codes, decisions
AUDITXS_DEBUG=1 sudo auditxs harden --dry-run
```

Debug output goes to stderr and to the daily log
(`/var/log/auditxs/auditxs-YYYYMMDD.log`). Every executed command, file
write and snapshot action is logged even without debug mode.

## Files & directories

| Path | Purpose |
|---|---|
| `/opt/auditxs` | the program |
| `/usr/local/bin/auditxs`, `auditxs-gui`, `update-auditxs` | commands |
| `/etc/auditxs/auditxs.conf` | profile configuration |
| `/etc/auditxs/baseline.json` | approved baseline (optional) |
| `/etc/auditxs/allowed-ports.conf` | approved listening ports (optional, NET-004) |
| `/var/lib/auditxs/snapshots/` | rollback snapshots |
| `/var/lib/auditxs/reports/` | HTML/JSON audit reports |
| `/var/lib/auditxs/changes.log` | append-only ledger of every change |
| `/var/log/auditxs/` | daily logs, installer logs |
| files written by fixes | always labelled: `sysctl.d/99-auditxs-*`, `sshd_config.d/99-auditxs.conf`, `sudoers.d/99-auditxs`, `modprobe.d/99-auditxs-*`, … |

## Exit codes

| Command | 0 | 1 |
|---|---|---|
| `audit` | audit completed (findings do not affect the exit code) | usage/runtime error |
| `harden` | run completed | usage/runtime error |
| `diff` | no regressions | regressions found (or error) |
| `schedule run` | audit ok, no drift | regression vs baseline (alerts monitoring) |
| `doctor` | no problems | problems found |
| `rollback` | rolled back | cancelled or error |
