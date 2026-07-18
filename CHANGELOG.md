# Changelog

All notable changes to **AuditXS** are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[Semantic Versioning](https://semver.org/). The repository-root `VERSION` file
is the single source of truth for the current version.

---

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
