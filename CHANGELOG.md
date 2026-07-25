# Changelog

All notable changes to **AuditXS** are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[Semantic Versioning](https://semver.org/). The repository-root `VERSION` file
is the single source of truth for the current version.

---

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
