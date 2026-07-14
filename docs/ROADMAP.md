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
