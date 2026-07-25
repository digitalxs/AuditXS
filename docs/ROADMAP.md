# AuditXS roadmap — must-have features and professional practice

This is the considered feature advice behind AuditXS's direction: what a
professional baseline-hardening tool must have (and why), what it should
gain next, and what it should deliberately *never* do. Ordered by value.

## Already implemented (the non-negotiables)

These are the table stakes for trustworthy hardening tooling — the reason
they shipped first:

1. **Read-only audit by default** — assessment must never mutate state.
2. **Full reversibility** — snapshots + manifest + rollback. A hardening
   tool without undo is an outage generator.
3. **Per-change transparency and consent** — explain → confirm → verify,
   dry-run previews, labelled drop-in files, append-only change ledger.
4. **Validate-or-restore for critical daemons** — sshd/sudoers/nginx/
   apache changes are syntax-checked and auto-reverted on failure;
   SSH/firewall lockout guards.
5. **Profiles** (server/workstation) — context decides what is a finding.
6. **Drift detection** — approved baseline + `diff` with CI-friendly exit
   codes, port allowlist (NET-004), scheduled audits alerting via systemd.
7. **Framework mapping** (NIST CSF 2.0, CIS/STIG alignment), **unit +
   end-to-end tests in CI**, **debug mode**, **doctor** self-diagnostics.

## Shipped in v0.18

- **Timeshift-backed updates**: `auditxs update` takes a Timeshift system
  snapshot before applying (when Timeshift is configured), so an upgrade can be
  rolled back with `timeshift --restore` — closing the "package upgrades aren't
  reversible" gap. **UPD-001 is now fixable** on this basis (Timeshift-gated),
  and `timeshift` is installable via `auditxs tools`. New error `AX5006`.

## Shipped in v0.17

- **Package updating** (`auditxs update`): preview + consented apply of
  security (or `--all`) updates, honestly flagged as not snapshot-reversible;
  `AUTO_UPDATE=1` makes the scheduled audit patch automatically; the
  reversible `UPD-002` fix still enables the OS's own auto-updates. Wired into
  the Qt/zenity/web GUIs. New error `AX5005`.

## Shipped in v0.16

- **Electron desktop app** (`auditxs electron`): a fourth GUI — the audited
  localhost web UI in a standalone, locked-down window (unprivileged app +
  one-time pkexec for the server, clean `/api/quit` shutdown). Node fetched
  per-user on first launch.
- **GUI interaction verification**: web UI buttons/toggles/fix-flows driven
  end-to-end in a headless browser; the page wiring is now a web-test
  regression guard, and the Qt selftest covers the op whitelist and fleet
  config round-trip.

## Shipped in v0.15

- **SSH login + interactive sudo for fleet audits** (`--ask-pass` /
  `--ask-sudo-pass`): scan remote hosts by logging in over SSH and using sudo
  with a password (fed to `sudo -S` over the channel, never on argv) — no
  passwordless sudo required. Exposed on every GUI's Fleet screen; new error
  `AX6009` for remote sudo failure.

## Shipped in v0.14

- **GUI feature parity**: Fix it / How to fix buttons on every finding in
  the Qt, web and zenity interfaces (with detailed manual guidance where no
  automatic fix exists); a Fleet tab/submenu (hosts + credentials + one-click
  fleet audit with progress and the overview dashboard); an embedded
  collapsible console (full shell in Qt, argv-whitelisted auditxs commands in
  the web UI, system terminal launcher in zenity); an Ops tab / menu entries
  covering every remaining CLI operation; and a status bar with version,
  profile, host and live progress.

## Shipped in v0.13

- **Progress bars with percentage everywhere**: in-terminal bar for the CLI
  (auto-off when piped), a real gauge in the TUI, true percentages in the
  zenity dialogs, an async worker + Material bar in the Qt app, and an
  authenticated `/api/progress` endpoint driving a linear bar in the web UI —
  all fed by the engine via the new `--progress-file` option.

## Shipped in v0.12

- **Single-prompt GUI authentication**: an installed polkit policy
  (`auth_admin_keep`) keeps the pkexec authorization for the active session,
  so consecutive Qt/zenity actions ask for the password once; documented for
  every interface in the manual's *Privileges & credential caching* section.
- **Documentation website + landing page**: `scripts/build-site.py` renders
  all guides into branded, self-contained HTML under `docs/` with a hub page,
  and generates the project landing `index.html` — publishable as-is at
  auditxs.digitalxs.ca. Built and validated in CI.

## Shipped in v0.11

- **Interactive HTML report** *(v0.11.1)*: a "show only findings" toggle
  (hides PASS/SKIP/WAIVE rows and empty categories) and per-finding
  **Fix it / How to fix** buttons that reveal and copy the exact remediation
  command (`harden --check <ID>` / `explain <ID>`) — the report stays a
  static, self-contained file and never executes anything itself.
- **Fleet overview dashboard**: every fleet run writes an aggregated,
  self-contained `index.html` next to the per-host reports — fleet-average
  score dial, clean/findings/errored chips, per-host score bars, relative
  links to each host's JSON/HTML. This completes the "aggregating JSON
  reports into one HTML overview" half of the multi-host roadmap item.
- **Fleet walkthrough & docs**: end-to-end setup guide in USAGE.md
  (audit user, sudoers, inventory, drift-diff, troubleshooting table),
  fleet section in ARCHITECTURE.md, and the dashboard coding workflow in
  the developer guide.

## Shipped in v0.10

- **Qt runtime preflight** *(v0.10.1)*: `auditxs qt` detects a missing PySide6 /
  QtQuick module set and offers to install the right packages for the running
  distribution (terminal prompt or zenity dialog, elevating with pkexec/sudo),
  falling back to web/tui guidance if declined — no more raw `ImportError` on a
  fresh workstation.
- **Accepted-risk waivers** (`auditxs waive/unwaive/waivers`): findings render
  as WAIVED with a justification + optional expiry; represented as SARIF
  suppressions and excluded from the score.
- **SARIF 2.1.0 + CSV export** (`report --format sarif|csv`) for GitHub code
  scanning and dashboards.
- **New coverage** (17 checks → 122 total across 26 categories): **Containers**
  (Docker/Podman: TCP/TLS exposure, userns-remap, no `--privileged`, docker-group,
  live-restore), **Boot** (GRUB password, Secure Boot, kernel lockdown),
  **TLS** certificate expiry, **PAM** account lockout (faillock) + password
  history, coredump restriction, USBGuard presence, scheduled-scan presence,
  mail DKIM/DMARC, PostgreSQL/MySQL TLS enforcement.
- **Drift & CVE alerting** (`auditxs alert`): webhook (Slack-compatible) and/or
  email sinks fired from scheduled audits.
- **Graphical installer** (`install-gui.sh`): a branded zenity install wizard.
- New error codes AX2005/2006/7001/8001/8002, wired into the new subsystems.

## Shipped in v0.9

- **GUI branding & polish** *(v0.9.1)*: gradient brand logo and "by DigitalXS"
  in the web UI top bar; a consistent footer across the web UI, Qt app, HTML
  report and zenity About — 🛡️ AuditXS · Made with ❤ from Canada 🍁 · © 2026
  DigitalXS — Programming & Development.
- **Web-stack & CMS coverage** (14 new checks, now 105 total across 23
  categories):
  - **nginx** — obsolete TLS (SSLv3/TLS 1.0/1.1) and HSTS (NGX-001/002).
  - **Varnish** — admin-interface binding and secret-file permissions
    (VRN-001/002).
  - New **WebApps** category — **WordPress** (wp-config perms, WP_DEBUG),
    **Drupal** (settings.php perms), **Laravel** (`.env` perms,
    `APP_DEBUG`/`APP_ENV`), **Roundcube** (config perms, installer).
  - **BIND** — zone-transfer (AXFR) restriction and DNSSEC validation
    (BND-003/004).
  - **Network** — promiscuous-mode interfaces and NTP time-sync
    (NET-005/006).
- **Fleet `--remote-report`**: leave a full HTML report on each audited host
  (and fetch a copy to the controller).

## Shipped in v0.8

- **Dedicated Fail2ban category** *(v0.8.2)*: four checks beyond the SSH-008
  brute-force check — service enabled at boot (F2B-001), ban-policy sanity
  (F2B-002), a recidive jail for repeat offenders (F2B-003, with a reversible
  fix), and `ignoreip` breadth (F2B-004). Fixture-tested.
- **Web UI default port is now 9000** *(v0.8.1)* (was 8787); override any time
  with `auditxs web --port N`.
- **Fleet mode** (`auditxs fleet`): read-only audits across many hosts over SSH
  (key or password auth via sshpass), aggregated score table + per-host JSON,
  CI-friendly exit codes. Never hardens over SSH by design.
- **Error-code system**: every recoverable failure reports a stable `AXnnnn`
  number with a plain why/fix, logged to `/var/lib/auditxs/errors.log`;
  browsable with `auditxs errors` and generated into `docs/ERRORS.md`.
- **Trust & distribution**: `.deb` builds now emit a SHA256 checksum; a
  tag-triggered `release.yml` publishes a signed GitHub Release (GPG when a key
  secret is configured), and `scripts/release.sh` prepares releases locally.
  The root `VERSION` file is now the single source of truth (fixes a
  version/​package drift).
- **Developer guide** `digitalxs-dev-doc.MD`: architecture, code map, check
  API, debugging, testing, release process and GitHub workflow.

## Shipped in v0.7

- **Native window chrome for the Qt app** *(v0.7.1)*. The desktop app is now a
  frameless window with its own Material title bar: in-app minimize /
  maximize-restore / close buttons (drawn as shapes, no glyph-font
  dependency), drag-to-move (`startSystemMove`), double-click-to-maximize and
  edge/corner resize (`startSystemResize`). An offscreen `tests/qml_test.py`
  loads the QML and exercises the window controls in CI.
- **`auditxs-gui` prefers the windowed app** *(v0.7.2)*. On a workstation the
  graphical launcher opens the Qt window (with the controls above) whenever
  PySide6 is present, falling back to the zenity dialogs otherwise
  (`AUDITXS_GUI=qt|zenity` overrides). The Qt app now runs unprivileged and
  elevates each action with pkexec — matching the zenity model — so it
  displays on both X11 and Wayland.
- **Profile-gated interfaces.** Servers are restricted to text interfaces —
  the CLI and a new **ncurses terminal UI** (`auditxs tui`, whiptail/dialog)
  that runs over a plain SSH session; the web UI, Qt app and zenity GUI are
  workstation-only and refuse to start on a server. No browser or root web
  server ever runs on a headless box.
- **Expanded security-tool integration.** `auditxs tools` now inventories,
  installs and runs a broader, capability-grouped set: **ClamAV** (malware),
  **OpenSCAP** (SCAP/SSG CIS/STIG evaluation), **auditd**, **osquery**,
  **Trivy**, **USBGuard**, **Firejail**, **arpwatch**, **Logwatch** and
  process accounting — alongside the existing Lynis/rkhunter/AIDE/CrowdSec/
  Suricata, all through one reversible interface with per-tool post-install
  setup guidance.

## Shipped in v0.6

- **Localhost web UI** (`auditxs web`): a Material Design 3 single-page app
  served by the Python standard library — loopback-only bind, ephemeral
  token auth, CSRF header, strict CSP, argv-only subprocess calls.
- **Native Qt/QML desktop app** as the optional `auditxs-gui-qt` package,
  with a headless data-layer selftest in CI.

## Shipped in v0.5

- **CIS Benchmark ids + Level 1/2** on every mappable check, with
  `--level` and `--framework cis` filters (surfaced in explain/list/reports).
- **Fixture-testable checks** via an `AX_ROOT` path prefix; `tests/check_test.sh`
  exercises real `audit_*` logic (Accounts, Filesystem, Debian) in CI.
- **Debian `.deb` package** (`packaging/build-deb.sh`) with man page, desktop
  launcher and conffile; built + install-tested in CI.

## Shipped in v0.4

- Debian 13 "trixie" awareness and Debian-family checks (APT signature
  enforcement, release EOL, needrestart).
- Service hardening: PHP, MySQL/MariaDB (config + accounts), Apache security
  headers & directory listing, ufw logging/gufw, Postfix + Dovecot, BIND +
  Unbound.
- **CVE / known-vulnerability warnings** from distribution security data,
  surfaced on console, log, HTML report and GUI (`auditxs cve`, `VULN-001`).
- **Security-tool integration** (`auditxs tools`): install/scan Lynis,
  rkhunter, Tiger, chkrootkit, checksecurity, lsat, AIDE; set up CrowdSec /
  Suricata; VPN (WireGuard/OpenVPN) config review. File-integrity (AIDE) and
  IDS/IPS presence checks (`SEC-001..004`).
- **nala-style console** output and a **Material Design 3** HTML report.

## Next (high value, in order)

1. **Scheduled AIDE verification** — a timer that runs `aide --check` and
   feeds tampering findings back into the audit (install/presence already
   covered by SEC-003).
2. **PDF/signed reports** — assessors want tamper-evident evidence;
   render the HTML report to PDF and sign report archives (minisign).
3. **MFA enrolment helper** — guided, opt-in `auditxs mfa enrol` wizard
   (google-authenticator/pam_u2f) that configures PAM+sshd only after a
   verified second-factor login in a parallel session.
4. **Package-manager hook** — post-transaction hook re-running the port
   allowlist and services checks, catching drift the moment software is
   installed rather than at the next scheduled audit.
5. **Shell completion** — bash/zsh/fish completions for operator ergonomics
   (the `auditxs(8)` man page ships with the .deb as of v0.5).
6. **Broaden `AX_ROOT` coverage** — convert the remaining file-reading
   checks (SSH drop-ins, sysctl readers, service configs) to `axpath` so
   the fixture test suite can cover every module.
7. **Localization** of check explanations (the metadata layer already
   separates text from logic).

## Deliberate non-goals

- **No irreversible change inside the reversible flow.** Partitioning, MAC
  enablement and database schema/config changes stay report-only, and nothing
  that a snapshot can't undo is ever part of `harden`/`rollback`. Package
  updating is the one explicitly-consented exception, and it is kept *outside*
  that flow: `auditxs update` states plainly that an upgrade can't be rolled
  back, previews first, and requires consent (or an opt-in `AUTO_UPDATE=1`).
- **No agent, no daemon, no cloud.** AuditXS stays a transparent local
  tool; scheduling uses the system's own timer infrastructure.
- **No exploit/scan functionality.** AuditXS hardens configurations; it
  is not a vulnerability scanner. Pair it with dedicated scanners
  (OpenVAS/Greenbone, Trivy) and complementary auditors (Lynis).
- **No opaque scoring.** The score stays a simple severity-weighted
  PASS/FAIL ratio that anyone can recompute from the report.

## Complementary tooling (defence in depth)

AuditXS covers configuration hardening. A complete posture adds:
vulnerability scanning (Greenbone/Trivy), EDR/antimalware where mandated,
central log shipping (journald → Loki/ELK/rsyslog relay), backup with
tested restores, and for fleets a configuration-management source of truth
(Ansible) — AuditXS then acts as the independent verifier of what is
actually running.
