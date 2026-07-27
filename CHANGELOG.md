# Changelog

All notable changes to **AuditXS** are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[Semantic Versioning](https://semver.org/). The repository-root `VERSION` file
is the single source of truth for the current version.

---

## [0.27.0]

### Web UI — usability overhaul (`auditxs web`)
- **Learn tab.** The tiered tutorial (simple → intermediate → advanced → pro)
  is now in the web UI, served from the same `auditxs tutorial` content via a
  new token-gated `/api/tutorial` endpoint.
- **Search & filter.** A search box filters the full check list by id, title,
  category, status or finding text as you type (the input keeps focus), with a
  live "N of M checks" count and a "failures & warnings only" toggle.
- **Light/dark toggle.** A theme button switches light/dark and persists the
  choice (`localStorage`), overriding the OS preference; both themes fully
  styled via CSS variables.
- **External scanners in the report.** A "scanners" toggle runs the audit with
  `--with-tools`; Lynis/rkhunter/chkrootkit/debsecan findings appear in an
  advisory *External tool findings* section (from the JSON `external` array).
- **Accessibility.** Tabs are a proper ARIA `tablist` with roles, `aria-selected`,
  roving `tabindex` and arrow-key navigation; visible keyboard focus rings; and
  `prefers-reduced-motion` is honoured.
- **Responsive.** The appbar, tab strip, hero and rows reflow cleanly on small
  screens (the tab strip scrolls horizontally).
- **Privilege indicator.** The header shows when the UI is running unprivileged
  and points to `sudo` for the full audit.

Web tests extended (+12) to cover the new endpoints, page wiring and markers.

## [0.26.0]

### Added
- **Tiered in-terminal tutorial — `auditxs tutorial`.** Four progressive
  levels teach the tool at the depth you want:
  - **simple** — the whole workflow in one command (`auditxs start`), your
    score, and how to undo everything;
  - **intermediate** — audit vs harden, targeting a category/check/domain,
    `explain`, snapshots/rollback, unprivileged audit, scheduling;
  - **advanced** — profiles, baselines/drift, the external-scanner join
    (`--with-tools`), waivers, CVE/updates, the alternate interfaces;
  - **pro** — unattended runs and exit codes, SARIF/CSV for CI, fleet over
    SSH, alerts, NIST/CIS/STIG compliance mapping, the reversibility model,
    and writing your own checks.
  `auditxs tutorial` with no argument shows the menu; `all` prints every
  level. Read-only guidance — it never changes the system. Typo-suggestions
  and `learn`/`guide-me` aliases included. The GUIs will surface the same four
  levels next.

## [0.25.0]

### Added
- **Joined external-tool findings in the audit report — `auditxs audit
  --with-tools`.** One audit now folds the findings of four independent
  scanners into the same report: **Lynis** (hardening warnings + suggestions),
  **rkhunter** and **chkrootkit** (rootkit/anomaly warnings) and **debsecan**
  (CVEs in installed packages, Debian). They appear in a dedicated *External
  tool findings* section in the console, the HTML report and the JSON (`external`
  array) — clearly labelled **advisory (not scored)**, so they never move the
  AuditXS hardening score, which stays a measure of AuditXS's own
  reversible-fixable checks.
- **`--tools-cached`** — same join but reads each tool's last report instead of
  re-scanning, for a fast refresh. Lynis and rkhunter use their canonical files
  (`/var/log/lynis-report.dat`, `/var/log/rkhunter.log`); chkrootkit and
  debsecan output is cached under `/var/lib/auditxs/toolcache/`.
- **debsecan** added to `auditxs tools scan` (chkrootkit, Lynis and rkhunter
  were already there).

### Notes
- The join is opt-in: a plain `auditxs audit` stays fast and self-contained.
  With `--with-tools`, missing scanners are simply skipped, and each tool is run
  only when root; otherwise its last report is read.

## [0.24.0]

### Added
- **SMB hardening checks (new `SMB` category).** `SMB-001` verifies the Samba
  server refuses SMBv1/NT1 (requires `server min protocol = SMB2` or higher);
  `SMB-002` verifies SMB signing — or encryption — is enforced (`server signing
  = mandatory` / `smb encrypt = required`) to block SMB relay and tampering.
  Both carry reversible, testparm-validated fixes and skip cleanly when Samba
  is not installed.
- **Inactive-account auditing (`ACC-010`).** Flags interactive accounts (real
  login shell, UID ≥ UID_MIN) that have not authenticated within
  `AUDITXS_INACTIVE_DAYS` days (default 90; set as low as 30). Advisory —
  it lists the accounts and the exact lock/expire command rather than
  auto-locking, since a dormant admin or automation identity can be legitimate.
- **Lynis integration — `auditxs lynis`.** Runs Lynis (the independent host
  auditor) and folds its findings — hardening index, warnings, suggestions —
  into an AuditXS-style summary. `auditxs lynis --report` re-reads the last run
  without re-running. Read-only: Lynis never changes anything.
- **Unprivileged audit mode.** `auditxs audit` and `auditxs report` now run
  without root — root-only checks report as *skipped* and a banner points to
  `sudo` for the complete picture. State-changing commands (`harden`,
  `rollback`, `start`) still require root.

### Changed
- **Deliberate de-duplication with Lynis.** AuditXS owns the reversible,
  consented fixes; Lynis owns breadth. AuditXS does not reimplement Lynis's
  tests — it surfaces them. Port/service/protocol hardening remains covered by
  the existing `NET-001/002/004` and `SVC-001..004` checks (no parallel checks
  were added).

## [0.23.0]

### Added
- **`auditxs start` — a guided run for newcomers.** One command walks the whole
  workflow: a read-only audit, a plain-language summary of what failed, then it
  offers each automatic fix in turn — every change shown first, applied only
  with consent, and fully reversible. It reuses the exact audit and harden
  machinery (the fix loop is now a shared `harden_apply_loop`), so the system
  is audited only once and there is no separate code path to drift.
- **Friendlier help.** Bare `auditxs` and `auditxs help` now show a short
  everyday-commands view; `auditxs help --full` prints the complete reference.
- **"Did you mean …?" suggestions.** A mistyped command (e.g. `audti`, `wbe`)
  now suggests the closest real command (Levenshtein ≤ 2, first-letter
  tie-break) instead of a bare error.
- **First-run nudge.** On a fresh install with no saved reports, bare `auditxs`
  greets you and points at `sudo auditxs start`.
- **One-line installer** (`scripts/install.sh`): `curl -fsSL …/install.sh |
  sudo bash` clones AuditXS and runs `setup.sh`, feeding it a real terminal for
  the Server/Workstation prompt even over a pipe. The README/USAGE now also
  surface the prebuilt `.deb` from the Releases page.

### Changed
- **The "Features" (turn-controls-on/off) section is gone from every GUI.** It
  duplicated hardening behind a confusing on/off metaphor. Hardening is
  unchanged and still one click away: the **Fix it** buttons on the Dashboard
  (Qt + web), the **Harden** menu (zenity), and the TUI's menu entry — renamed
  from *Features* to **Harden** — all apply the same reviewed, reversible fixes.

## [0.22.0]

### Changed
- **The web UI now runs on the server profile too.** It's no longer
  workstation-only: on a headless server it's a network-reachable control
  panel. Only the *desktop* GUIs (Qt, Electron, zenity) stay workstation-only
  (they need a display).

### Added
- **Network / LAN-IP access for the web UI.** `auditxs web` gained `--remote`
  (bind all interfaces, `0.0.0.0`) alongside the existing `--bind ADDR`. When
  bound to the network the printed URL uses the **server's own IP** (best-effort
  primary address), and any other reachable addresses are listed. Remote access
  stays a deliberate, warned opt-in — the access token is the only credential,
  so AuditXS prints TLS / reverse-proxy / firewall guidance. For a persistent
  server control panel, `auditxs webservice enable --remote` remains the
  recommended path.

### Fixed
- An **empty** `--token-file` is now (re)populated with the token instead of
  being left empty, so reconnecting to a running service always works.

## [0.21.0]

### Added
- **A real, Konsole-like terminal.** AuditXS can now open a fully-interactive
  terminal (a shell that runs TUI programs like vim, htop, less), not just the
  line-based console:
  - New command `auditxs terminal` opens your terminal emulator, **preferring
    KDE Konsole** and falling back through the common emulators (kgx,
    gnome-terminal, tilix, xfce4-terminal, alacritty, kitty, foot, xterm, …).
    If none is installed it offers to install Konsole (elevating via pkexec/sudo).
    It runs unprivileged — a shell you could open yourself.
  - **Embedded terminal in the desktop app.** The Electron app now hosts a real
    terminal *inside its own window* (menu **Terminal → New Terminal**, or
    **Ctrl+Shift+T**), built with xterm.js and a dependency-free Python PTY
    broker (`gui/electron/pty-bridge.py`) — no native `node-pty` build required.
    Full interactivity and window-resize (SIGWINCH) support.
  - **In every GUI.** A new **Terminal** tab in the Qt app and a rewired
    **Terminal** entry in the zenity menu open the real terminal; the web UI's
    console points to it (and to SSH) for a full shell.
  - New error `AX1006` (*No terminal emulator available*).
  - The web console remains deliberately restricted to `auditxs` subcommands —
    a full remote shell is never exposed over the (optionally network-reachable)
    web UI; use SSH for that.

## [0.20.0]

### Added
- **Web UI on/off switch — local or remote.** The web UI can now run as a
  managed background service instead of only a foreground command:
  - `auditxs webservice enable` turns it on as a systemd service
    (`auditxs-web.service`) that starts at boot. It binds to `127.0.0.1` by
    default — reach it over an SSH tunnel.
  - `auditxs webservice enable --remote` (or `--bind ADDR`) exposes it to the
    network (`0.0.0.0`). This is a deliberate, loudly warned opt-in: the web UI
    drives privileged operations, so a stable bearer **access token** is
    required on every request and AuditXS tells you to put TLS / a reverse
    proxy in front and firewall the port.
  - `auditxs webservice status` shows whether it is on, the bind address/port
    and the access-token URL; `auditxs webservice disable` turns it off and
    removes the unit; `auditxs webservice token [--reset]` shows or rotates the
    token (rotating restarts the service).
  - The token lives in a root-only file (`/etc/auditxs/web-token`, `0600`) so a
    running service keeps a stable credential you can reconnect with.
  - **On/off switch in every GUI.** A new **Web** tab in the Qt and web apps and
    a **WebService** entry in the zenity menu turn the service on/off, choose
    local vs. remote, and show/rotate the token — with the remote-exposure
    warning gated behind an explicit confirmation.
  - `auditxs web` gained `--bind ADDR`, `--token-file PATH` and `--service`;
    in `--service` mode it runs headless (no desktop-session requirement) and
    reads/creates the persistent token.
  - New error **AX8003** (*Web service management failed*) and token-gated web
    routes `GET`/`POST /api/webservice`.

## [0.19.0]

### Added
- **Per-tool Install / Uninstall / Repair.** Every security tool now has its
  own three buttons in the GUIs (Tools tab in the web and Qt apps; a *Manage*
  flow in the zenity Tools menu) and matching CLI verbs:
  - `auditxs tools install <tool>` — lay the tool down with its defaults.
  - `auditxs tools uninstall <tool>` — remove it, **stopping and disabling its
    service first**.
  - `auditxs tools repair <tool>` — purge its configuration and reinstall so
    package defaults are restored (fresh config).
  - `auditxs tools list` / `state` — machine-readable tool list / install
    state (drives the GUIs).
  - `timeshift` is now a managed tool; `pkg_purge` added for clean repairs.
  - New token-gated web route `POST /api/tools/action` (argv-validated).

## [0.18.0]

### Added
- **Timeshift-backed updates — package upgrades you can roll back.** AuditXS
  now integrates with Timeshift (filesystem snapshots), which *can* undo a
  software upgrade that `auditxs rollback` cannot:
  - `auditxs update` takes a Timeshift system snapshot **before** applying
    anything whenever Timeshift is installed and configured (labelled
    `AuditXS pre-update …`), and prints the `timeshift --restore` command to
    undo it. `--snapshot` forces it (aborting if Timeshift is missing);
    `--no-snapshot` skips it.
  - **UPD-001 ("no pending updates") is now a fixable finding** — the Fix it
    button / `harden --check UPD-001` takes a Timeshift snapshot, then applies
    the pending updates. It **requires** Timeshift so the otherwise-reversible
    harden flow never makes an unrecoverable change, and declines with guidance
    when Timeshift isn't available.
  - `timeshift` added to `auditxs tools install`. New error `AX5006` (Timeshift
    snapshot failed).

### Fixed
- **Fleet password auth now installs `sshpass` automatically** instead of
  failing with `AX6004`: directly when root (CLI / web UI), or elevated with
  `pkexec`/`sudo` when launched unprivileged from the Qt/zenity GUIs.
- **No more `errors.log: Permission denied` leak.** When AuditXS runs
  unprivileged (e.g. a fleet audit from a GUI), the error-ledger write is now
  writability-checked first, so a failed append no longer prints a stray
  "Permission denied" line (`>> file 2>/dev/null` can't suppress an open
  failure).

## [0.17.0]

### Added
- **Package updating** — AuditXS can now apply updates, three consented ways:
  - **`auditxs update`** — a new command that previews the exact change list
    (read-only), then applies **security** updates on consent (`--all` for a
    full upgrade, `--dry-run` to preview, `--yes` for automation). Per distro:
    `unattended-upgrade`/`apt-get` (Debian), `dnf upgrade --security` (Fedora),
    `pacman -Syu` (Arch — only full upgrades are supported), `zypper patch
    --category security` (openSUSE). It is **honest that a package upgrade is
    not reversible** by `rollback`, is kept out of the harden/rollback flow,
    and records start/finish in the change ledger. New error `AX5005`.
  - **`AUTO_UPDATE=1`** in `/etc/auditxs/auditxs.conf` — the scheduled audit
    then applies pending security updates automatically when it finds them
    (and alerts via the configured webhook/email). Off by default.
  - The existing **`UPD-002` reversible fix** (enable the distro's own
    automatic-security-update mechanism) remains the "let the OS patch itself"
    option.
  - Exposed in the GUIs: a "Preview updates" + confirm-gated "Apply security
    updates" pair on the Qt Ops tab, an **Update** entry in the zenity menu
    (preview → consent → apply), and `update` whitelisted in the web/Qt
    consoles.

## [0.16.0]

### Added
- **Electron desktop app** (`auditxs electron`) — a fourth graphical
  interface: the audited localhost web UI in a standalone, locked-down
  desktop window. It reuses the web UI wholesale (loopback-only bind,
  per-launch token, CSRF, argv-only calls, strict CSP), runs **unprivileged**,
  and elevates the web server once with `pkexec` (a single prompt per session
  under the polkit keep policy). Node.js required; the Electron runtime is
  fetched per-user on first launch (never shipped in the package). New
  `POST /api/quit` (token-gated) lets the app stop its server cleanly on
  window close, and `SIGTERM`/`SIGINT`/`SIGHUP` handlers cover logout/kill.

### Verified / fixed
- **GUI interaction verification** — the web UI's buttons and controls were
  driven end-to-end in a headless browser: **Fix it** (review + Apply),
  **How to fix** (manual guidance, no Apply), the **Feature** on/off switches
  (toggle → review modal → correct `POST /api/harden`), and tab rendering,
  all with zero JS errors. The served page's interactive wiring is now a
  web-test regression guard, and the Qt data-layer selftest gained checks for
  the op whitelist and fleet config round-trip (18 checks).

## [0.15.0]

### Added
- **SSH login + interactive sudo for fleet audits.** You can now scan remote
  hosts by logging in over SSH and using `sudo` **with a password** — no
  passwordless sudo required.
  - `auditxs fleet --ask-pass` prompts once for the SSH login password;
    `--ask-sudo-pass` prompts once for the remote sudo password and feeds it to
    `sudo -S` over the SSH channel's stdin, so it never appears in the process
    list on either machine. `--sudo` alone still means passwordless sudo.
  - The credentials are exposed on the **Fleet screen of all three GUIs** (Qt,
    web, zenity): SSH key **or** login password, plus an optional sudo
    password. Passwords are used only for that run and never saved; the GUIs
    pass them to the engine through the environment (`AUDITXS_SSH_PASS` /
    `AUDITXS_SUDO_PASS`), never on the command line.
  - New error `AX6009` (remote sudo authentication failed) distinguishes a
    rejected sudo password / missing sudoers rule from an SSH auth failure.

## [0.14.1]

### Fixed
- **Qt GUI: no concurrent privileged operations.** The "Run audit" button and
  the Fix it / Feature-toggle / Roll back initiators were disabled only while
  an audit was running, not while a background Ops/Tools/Fleet operation was —
  so a second elevated `auditxs` process could be launched over a running one
  (both writing the shared progress file and potentially both touching
  snapshots). A single `busy` guard now gates every action initiator, so only
  one operation runs at a time.

## [0.14.0]

A major GUI release — the graphical interfaces reach feature parity with the
CLI.

### Added
- **"Fix it" everywhere** — every FAIL/WARN row in the Qt app, the web UI and
  the zenity results list now carries a button: *Fix it* (review → consent →
  reversible fix → verify) when an automatic fix exists, *How to fix* with
  detailed, explicit manual guidance when it does not.
- **Fleet management from the GUI** — a Fleet tab (Qt, web) / submenu
  (zenity): add and remove `user@host` entries, choose the SSH key, toggle
  remote sudo, and one **Audit fleet** button with live percentage progress,
  finishing with the aggregated overview dashboard. Qt and zenity share the
  same user-level inventory (`~/.config/auditxs/fleet-hosts`); the web UI
  (root) manages `/var/lib/auditxs/fleet-hosts`.
- **Embedded console** — a collapsible terminal panel at the bottom of the
  Qt app (full shell, the user's own privileges, line-based) and the web UI
  (auditxs subcommands only — argv, never a shell — enforced server-side);
  zenity gains a *Terminal* menu entry that opens the system terminal.
- **Full CLI parity** — new Ops tab (Qt) and menu entries (zenity) for every
  remaining operation: CVE scan, doctor, schedule (status/enable/disable/run),
  baseline, waivers (list/add/remove), alerts (status/test), the error
  catalogue and the check catalogue; the web console covers the same surface.
- **Status bar** — Qt and the web UI show a permanent bottom bar with the
  AuditXS version, profile and host, the live operation progress (percentage)
  and the console toggle; the zenity menu header shows version and host.

### Changed
- The Qt app's long operations all run in a worker thread with progress in
  the status bar (the window never freezes). New `/api/cli`,
  `/api/fleet/*` web routes are token-authenticated and argv-whitelisted like
  every other route. Web tests grown to 14 (console auth + whitelist).

## [0.13.0]

### Added
- **Live progress with percentage in every interface.** The audit engine now
  counts its work and reports it as it goes:
  - **CLI** — an in-terminal progress bar
    (`████░░ 45% (55/122) SSH-003`) drawn on stderr under the scrolling
    results; auto-disabled when output is piped/captured, or with
    `AUDITXS_NO_PROGRESS=1`. `harden` announces `fix N of M (P%)` per fix
    and fleet mode prints `(host i/N · P%)` per host.
  - **Terminal UI** — a real dialog gauge showing percentage and the current
    check (replacing the fake pulsing gauge; the audit also no longer runs
    twice).
  - **zenity GUI** — audit, harden and the features view show true
    percentages with the current check id in the progress dialog.
  - **Qt app** — the audit runs in a worker thread (the window stays live)
    with a Material progress bar, percentage and current check; the Run
    audit button shows the live percentage.
  - **Web UI** — a Material linear progress bar with percentage and check
    count above the dashboard, fed by a new authenticated `/api/progress`
    endpoint.
  - Front-ends read progress via the new `--progress-file <path>` option
    (one rewritten line: `PCT DONE TOTAL CHECK-ID`) — a CLI flag rather than
    an environment variable so it survives pkexec's environment
    sanitization.

## [0.12.0]

### Added
- **Authenticate once, not per click** — a polkit policy
  (`com.digitalxs.auditxs.policy`, default `auth_admin_keep`) ships with both
  install methods: the first pkexec-elevated GUI action prompts, and polkit
  then remembers the authorization for the active session (~5 minutes), so a
  burst of consecutive Qt/zenity actions asks for the password once. The
  policy is installed by `setup.sh` and the `.deb`, removed on uninstall, and
  applies only to the canonical installed binary paths. A new
  *Privileges & credential caching* section in the manual explains the model
  for every interface (CLI sudo cache, GUI polkit keep, web/tui root-once).
- **Documentation website** — `scripts/build-site.py` (Python stdlib only)
  renders every guide to a branded, theme-aware, self-contained HTML page in
  `docs/` (sidebar navigation, on-page contents, cross-links rewritten),
  plus a `docs/index.html` hub — ready to publish at
  <https://auditxs.digitalxs.ca/docs>.
- **Project landing page** — a polished `index.html` at the repository root
  (hero, feature grid, install snippet, links to the documentation and
  GitHub), generated by the same script with the current version stamped in.
- CI now builds the site and validates the polkit policy XML on every push.

## [0.11.1]

### Added
- **Interactive HTML report** (still a single self-contained file):
  - a **"Show only findings" toggle** in the score card hides every passed,
    skipped and waived check — and any now-empty category — so the report
    shows just the FAILs and WARNs;
  - a **"Fix it" button** on every failing check with an automatic fix,
    revealing and copying the exact command
    (`sudo auditxs harden --check <ID>`), and a **"How to fix"** button
    (`auditxs explain <ID>`) on warnings and manual-fix items. The static
    report never executes anything — the buttons hand over the command and
    AuditXS still asks for consent before changing the system.
  - Both behaviours are covered by unit tests and were exercised end-to-end
    in headless Chromium.

## [0.11.0]

### Added
- **Fleet overview dashboard** — every `auditxs fleet` run now writes an
  aggregated, self-contained HTML dashboard (`index.html`) next to the
  per-host reports: fleet-average score dial, clean/findings/errored host
  chips, and a per-host table with score bars and relative links to each
  host's saved JSON/HTML reports. Unreachable and errored hosts are shown,
  not hidden. Covered by unit tests.
- **Fleet walkthrough** in `docs/USAGE.md` — end-to-end setup (install on
  targets, dedicated audit user + key, narrow sudoers rule, inventory file,
  run, review, drift-diff) plus a troubleshooting table mapping fleet states
  to their `AX6xxx` error numbers.

### Changed
- `docs/ARCHITECTURE.md` gained a fleet-mode section (data flow, invariants,
  dashboard design); `digitalxs-dev-doc.MD` §9 documents the `ov[]` record
  format and the coding workflow for extending the dashboard.

## [0.10.1]

### Added
- **Qt runtime preflight** — `auditxs qt` now detects when PySide6 and its
  QtQuick QML modules (Controls, Layouts, Window) are missing and offers to
  install the correct packages for the current distribution instead of failing
  with a raw `ImportError`. The prompt is shown in the terminal when attached
  to a tty, or as a zenity dialog when launched from the desktop; privileges
  are elevated with `pkexec` (graphical) or `sudo` as appropriate, and a
  declined prompt prints fall-back guidance for the web and terminal UIs.
  Package-install failures report error `AX5001`.

## [0.10.0]

Governance, integrations and a big coverage expansion — **122 checks across 26
categories**.

### Added
- **Accepted-risk waivers** — `auditxs waive <ID> "reason" [--until DATE]`,
  `auditxs waivers`, `auditxs unwaive <ID>`. A waived finding renders as
  **WAIVED** (not FAIL/WARN) in audits, reports and drift alerts, keeps the
  original result in its detail, is excluded from the hardening score, and is
  emitted as a proper **SARIF suppression**. Expired waivers stop applying.
- **SARIF 2.1.0 and CSV export** — `report --format sarif|csv`. SARIF carries
  `security-severity`, CIS/NIST properties and waiver suppressions, ready for
  **GitHub code scanning**, Azure DevOps and security dashboards.
- **Containers category** (Docker / Podman): unencrypted-TCP daemon exposure,
  user-namespace remapping, no `--privileged` containers, `docker`-group
  sprawl, and `live-restore`.
- **Boot-chain integrity**: GRUB bootloader password, UEFI Secure Boot, kernel
  lockdown mode.
- **TLS certificate expiry** monitoring (Let's Encrypt + common service paths).
- **PAM hardening**: account lockout after failed logins (`pam_faillock`) and
  password-history reuse prevention (`pam_pwhistory`).
- More checks: kernel core-dump restriction, USBGuard presence, scheduled-scan
  presence, mail DKIM/DMARC milters, PostgreSQL and MySQL/MariaDB TLS
  enforcement.
- **Drift & CVE alerting** — `auditxs alert status|test`; webhook
  (Slack-compatible) and/or email sinks fired from scheduled audits on baseline
  drift or newly-vulnerable packages.
- **Graphical installer** — `install-gui.sh`, a branded zenity wizard
  (welcome → profile → options → install → done).
- New error codes `AX2005/2006/7001/8001/8002`, wired into the new subsystems.

### Changed
- Fixture tests for the container/boot/database checks and waiver unit tests
  (72 unit / 45 fixture tests). Docs, man page and generated catalogues
  refreshed.

## [0.9.1]
### Added
- GUI branding across the web UI, Qt app, HTML report and zenity About:
  gradient brand logo, "by DigitalXS", and a footer —
  *🛡️ AuditXS · Made with ❤ from Canada 🍁 · © 2026 DigitalXS — Programming & Development*.

## [0.9.0]
### Added
- Web-stack & CMS coverage: **nginx** (obsolete TLS, HSTS), **Varnish** (admin
  binding, secret permissions), a **WebApps** category (WordPress, Drupal,
  Laravel, Roundcube), **BIND** (AXFR restriction, DNSSEC), and **Network**
  (promiscuous-mode interfaces, NTP time-sync).
- `auditxs fleet --remote-report` leaves a full HTML report on each audited
  host.

## [0.8.2]
### Added
- Dedicated **Fail2ban** category: service enabled at boot, ban-policy sanity,
  recidive jail, `ignoreip` breadth.

## [0.8.1]
### Changed
- Web UI default port is now **9000** (override with `--port`).

## [0.8.0]
### Added
- **Fleet mode** (`auditxs fleet`): read-only audits across many hosts over SSH
  (key or password auth), aggregated scores and per-host reports.
- **Error-code system** (`auditxs errors`): stable `AXnnnn` codes with a plain
  why/fix, an occurrence ledger, and a generated `docs/ERRORS.md`.
- **Trust & distribution**: `.deb` SHA256 checksums, a tag-triggered signed
  GitHub release workflow, `scripts/release.sh`, and the root `VERSION` file as
  the single source of truth.
- Developer & maintainer guide (`digitalxs-dev-doc.MD`).

## [0.7.0] – [0.7.2]
### Added
- **Profile-gated interfaces**: servers are text-only (CLI + a new ncurses
  **terminal UI**, `auditxs tui`); the web UI, Qt app and zenity GUI are
  workstation-only.
- Expanded, capability-grouped security-tool integration (ClamAV, OpenSCAP,
  auditd, USBGuard, Firejail, arpwatch, Logwatch, osquery, Trivy, …).
- Native window chrome for the Qt app (frameless window with in-app
  minimize/maximize/move/resize); the graphical launcher prefers the Qt app.

## [0.6.0]
### Added
- Localhost **Material Design web UI** (`auditxs web`) and an optional
  **Qt/QML** desktop app (`auditxs-gui-qt`); cybersecurity best-practices guide.

## [0.5.0]
### Added
- CIS Benchmark IDs + Level 1/2 metadata and filters; fixture-testable checks
  via an `AX_ROOT` path prefix; Debian **.deb** packaging with a man page.

## [0.4.0]
### Added
- Debian 13 awareness; service hardening (PHP, MySQL/MariaDB, Apache, Postfix,
  Dovecot, BIND, Unbound, ufw); CVE/known-vulnerability warnings; security-tool
  integration (`auditxs tools`); nala-style console + Material HTML report.

## [0.3.0]
### Added
- Five assessment domains and NIST CSF 2.0 mappings; `doctor`, `baseline`,
  `schedule`; debug mode; unit tests; the documentation set.

## [0.2.0]
### Added
- fail2ban/sshguard, SELinux/AppArmor status and `pam_pwquality` checks;
  baseline diff mode; the CI workflow and containerised smoke tests.

## [0.1.0]
### Added
- Initial release: the read-only audit engine, snapshot/rollback, ~40 checks,
  the CLI and zenity GUI, and the dxsbash-style installer.

[0.10.0]: https://github.com/digitalxs/AuditXS/releases
