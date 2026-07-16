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

## Shipped in v0.8

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

1. **Notification channels for drift** — `schedule run` currently fails
   the systemd unit on regression; add native mail/webhook (Slack/Matrix)
   notifiers so small setups get alerts without a monitoring stack.
2. **Multi-host operation** — `auditxs fleet` running audits over SSH
   against an inventory file, aggregating JSON reports into one HTML
   overview. The JSON format is already stable for this.
3. **Scheduled AIDE verification** — a timer that runs `aide --check` and
   feeds tampering findings back into the audit (install/presence already
   covered by SEC-003).
4. **PDF/signed reports** — assessors want tamper-evident evidence;
   render the HTML report to PDF and sign report archives (minisign).
5. **MFA enrolment helper** — guided, opt-in `auditxs mfa enrol` wizard
   (google-authenticator/pam_u2f) that configures PAM+sshd only after a
   verified second-factor login in a parallel session.
6. **Package-manager hook** — post-transaction hook re-running the port
   allowlist and services checks, catching drift the moment software is
   installed rather than at the next scheduled audit.
7. **Shell completion** — bash/zsh/fish completions for operator ergonomics
   (the `auditxs(8)` man page ships with the .deb as of v0.5).
8. **Broaden `AX_ROOT` coverage** — convert the remaining file-reading
   checks (SSH drop-ins, sysctl readers, service configs) to `axpath` so
   the fixture test suite can cover every module.
9. **Localization** of check explanations (the metadata layer already
   separates text from logic).

## Deliberate non-goals

- **No irreversible automation.** Package upgrades, partitioning, MAC
  enablement, database schema/config changes stay report-only forever.
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
