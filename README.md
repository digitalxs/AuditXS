# AuditXS

[![CI](https://github.com/digitalxs/AuditXS/actions/workflows/ci.yml/badge.svg)](https://github.com/digitalxs/AuditXS/actions/workflows/ci.yml)

**Transparent, reversible Linux security auditing & hardening** — by [DigitalXS](https://digitalxs.ca)

AuditXS audits Linux systems against fundamental, professional security
baselines (inspired by CIS-style controls) and — only if you ask it to —
hardens them, **one explained, consented, reversible change at a time**.

Supported distributions: **Debian (incl. Debian 13 "trixie") · Ubuntu · Pop!\_OS · Arch · Fedora · openSUSE** (and their derivatives).

---

## The three rules AuditXS lives by

1. **Transparent.** `auditxs audit` is strictly read-only. Every check can
   tell you *what* it inspects, *why* it matters, *exactly what* its fix
   changes and *how* that change is reverted (`auditxs explain SSH-001`).
   Every file AuditXS writes carries an `AuditXS` comment header saying
   which check wrote it and how to revert it.
2. **Reversible.** Before anything is modified, the previous state is
   recorded in a timestamped **snapshot**: modified files are copied,
   service states, sysctl values and permissions are logged in a manifest.
   `sudo auditxs rollback <snapshot>` (or `rollback latest`) restores
   everything, in reverse order. A global append-only ledger
   (`/var/lib/auditxs/changes.log`) records every action ever taken.
3. **Consented.** `auditxs harden` walks through failed checks one by one,
   shows the full explanation, and asks before each fix. `--dry-run` prints
   every intended command and file write without touching anything;
   `--yes` enables unattended use once you trust it.

## Installation

**Debian / Ubuntu (.deb):**

```bash
git clone https://github.com/digitalxs/AuditXS.git && cd AuditXS
./packaging/build-deb.sh          # builds dist/auditxs_<version>_all.deb
sudo apt install ./dist/auditxs_*_all.deb
```

The package installs to `/usr/share/auditxs`, provides `auditxs`,
`auditxs-gui` and `update-auditxs`, a man page (`man auditxs`) and a desktop
launcher, and updates cleanly with `apt`.

**Any distribution (source installer, dxsbash-style):**

```bash
git clone https://github.com/digitalxs/AuditXS.git
cd AuditXS
sudo ./setup.sh
```

The installer (in the spirit of [dxsbash](https://github.com/digitalxs/dxsbash)) will:

- detect your distribution,
- ask whether this machine is a **Server** or a **Workstation**
  (the profile decides which checks apply — see below),
- install to `/opt/auditxs` and link `auditxs`, `auditxs-gui` and
  `update-auditxs` into `/usr/local/bin`,
- optionally install `zenity` and a desktop launcher for the GUI.

Non-interactive: `sudo ./setup.sh --server -y` · `sudo ./setup.sh --workstation -y` ·
`--no-gui` · `--refresh` (repair/update in place) · `--uninstall`.

Update later with `sudo update-auditxs`. Remove with `sudo /opt/auditxs/uninstall.sh`.

## Usage

```text
sudo auditxs audit                     read-only audit + HTML/JSON report
sudo auditxs harden --dry-run          preview every fix, change nothing
sudo auditxs harden                    apply fixes one by one, with consent
sudo auditxs harden --category SSH     harden one category only
sudo auditxs rollback latest           undo the last hardening run completely
sudo auditxs snapshots                 list change snapshots
auditxs list                           the full check catalogue
auditxs explain FW-002 SSH-005         what a check inspects/changes/reverts
sudo auditxs report --format html      fresh report to stdout (also: json, tsv)
sudo auditxs audit --baseline old.json compare a fresh audit against a saved report
auditxs diff old.json new.json         compare two saved reports (exits 1 on regressions)
sudo auditxs audit --domain "Database" audit one assessment domain
sudo auditxs cve                       warn about installed packages with a known CVE
sudo auditxs tools status              which security tools are installed
sudo auditxs tools install lynis       install a security tool (reversible)
sudo auditxs tools scan                run installed scanners (Lynis, rkhunter…)
auditxs tools vpn                      review WireGuard / OpenVPN configuration
sudo auditxs web                       launch the Material Design web UI (localhost-only)
sudo auditxs qt                        launch the native Qt desktop app (optional auditxs-gui-qt)
sudo auditxs baseline set              approve the latest report for drift alerts
sudo auditxs schedule enable           daily audit + drift alert (systemd timer)
auditxs doctor                         diagnose installation, tooling, snapshots
sudo auditxs audit --debug             verbose diagnostics (timings, decisions)
auditxs-gui                            graphical interface (zenity + pkexec)
```

The console uses a clean **nala-style** boxed layout; the HTML report is
**Material Design 3** (theme-aware, score ring, status chips, per-domain
cards). Both the console and the report show a **CVE warning banner** when an
installed package has a known vulnerability with a fix available, and the
warning is written to the log and surfaced in the GUI.

A severity-weighted **hardening score (0–100)** summarizes each audit, and
every audit saves timestamped HTML + JSON reports under
`/var/lib/auditxs/reports/`.

**Baseline tracking:** keep a report from a known-good state and compare any
later audit against it — `auditxs diff` exits non-zero when a check
regressed, so it slots straight into monitoring or CI.

## Server vs. Workstation profiles

Chosen during installation (stored in `/etc/auditxs/auditxs.conf`,
overridable per-run with `--profile`):

| | Server | Workstation |
|---|---|---|
| Updates, firewall, accounts, filesystem, kernel basics, MAC status | ✔ | ✔ |
| SSH key-only login, idle-session timeouts, fail2ban brute-force protection | ✔ | – |
| auditd + baseline audit rules | ✔ | – |
| Disable Avahi / CUPS / Bluetooth | ✔ | – (desktop needs them) |
| Restrictive umask (027), Ctrl-Alt-Del guard, martian logging, wireless detection | ✔ | – |

## Assessment domains & frameworks

Checks roll up into the five domains professional assessments are
organised around — audit any one of them with `--domain`:

**Server Hardening** (SSH, accounts, sudo accountability, MFA posture,
admin-account inventory) · **OS Hardening** (CIS/STIG-aligned: updates,
kernel, filesystem, MAC, logging, banners, /tmp) · **Network Security**
(firewall, protocol surface, listening-port allowlist drift detection) ·
**Application Hardening** (service surface, nginx/Apache secure config
with validate-or-restore) · **Database Hardening** (MySQL/PostgreSQL
exposure, 'trust' auth detection, TLS/encryption guidance — report-only
by design).

Every check carries an indicative **NIST CSF 2.0** mapping, shown in
`auditxs explain`, the reports and [docs/CHECKS.md](docs/CHECKS.md).
Details: [docs/COMPLIANCE.md](docs/COMPLIANCE.md).

## What is covered (87 checks, 20 categories)

**Updates** (pending updates, automatic security updates, pending reboot) ·
**Debian** (APT signature enforcement, release EOL awareness, needrestart) ·
**OS** (login banners, /tmp mount options) · **Privileged** (sudo
pty+logging, SSH MFA posture, admin inventory) · **Applications**
(nginx/Apache version disclosure, Apache security headers, directory
listing) · **PHP** (expose_php, display_errors, session cookies, dangerous
functions) · **Mail** (Postfix open-relay/TLS/banner, Dovecot plaintext-auth
and TLS) · **DNS** (BIND recursion/version, Unbound access control) ·
**SecurityTools** (Lynis, rootkit detector, AIDE, IDS/IPS present) ·
**Vulnerabilities** (known-CVE packages, precise CVE data source) ·
**Database** (MySQL/MariaDB exposure, local_infile, anonymous accounts;
PostgreSQL exposure and authentication) ·
**SSH** (root login, auth limits, empty passwords, X11, key-only auth with
lockout guard, idle timeout, grace time, fail2ban/sshguard brute-force
protection) · **Firewall** (installed, active, default-deny — with an SSH
**lockout guard** before enabling) · **Accounts** (UID-0 uniqueness, empty
passwords, password aging, NOPASSWD sudo, system-account shells, umask,
pam_pwquality password rules) · **Filesystem** (sticky bits, world-writable
files, unowned files, sensitive-file permissions, home permissions, SUID
inventory) · **Kernel** (ASLR, kptr/dmesg restrictions, SYN cookies, ICMP
redirects, source routing, rp_filter, martian logging, IP forwarding with
container/VM detection, suid_dumpable, Ctrl-Alt-Del) · **MAC**
(SELinux/AppArmor status with per-distro guidance) · **Services** (legacy
plaintext services, Avahi, CUPS, Bluetooth, systemd sandboxing overview) ·
**Network** (listening inventory, uncommon protocols dccp/sctp/rds/tipc,
wireless on servers) · **Logging** (persistent journal, auditd, baseline
rules, log permissions).

The full catalogue with per-check documentation is generated from the code
itself: [docs/CHECKS.md](docs/CHECKS.md) (or run `auditxs list --markdown`).

Checks marked **manual** (e.g. pending updates, NOPASSWD sudo entries,
SUID inventory) *never* change the system — irreversible or judgment-heavy
actions are deliberately left to the administrator.

## Safety engineering worth knowing about

- **SSH**: fixes go into `/etc/ssh/sshd_config.d/99-auditxs.conf`, are
  validated with `sshd -t`, and the previous config is restored
  automatically if validation fails. Key-only authentication is **refused**
  unless at least one regular user already has `authorized_keys`.
- **Firewall**: before enabling, the SSH port is explicitly allowed whenever
  the machine is managed over SSH (lockout guard).
- **Kernel**: one labelled drop-in per check under `/etc/sysctl.d/`;
  previous runtime values recorded and restored on rollback. IP forwarding
  is left alone when Docker/Podman/libvirt is detected.
- **Permissions**: AuditXS only ever *tightens* modes, and records each
  file's exact previous mode.
- **Packages**: never removed automatically; packages *installed* by a fix
  are recorded and offered for removal during rollback.

## Maintenance & operations

- `auditxs doctor` — self-diagnostics: tooling, configuration, snapshot
  integrity, scheduled-audit state.
- `sudo auditxs baseline set` + `sudo auditxs schedule enable` — daily
  read-only audit whose systemd unit **fails on drift** from the approved
  baseline, so existing monitoring alerts on configuration regressions.
- `sudo update-auditxs` — in-place updates; the uninstaller protects your
  snapshots and removes the scheduler units.

## Security tooling, external scanners & CVE warnings

AuditXS covers configuration hardening itself, and *integrates* the wider
ecosystem rather than reinventing it:

- **`auditxs tools install`** — guided, reversible install of Lynis,
  rkhunter, chkrootkit, Tiger, checksecurity, lsat, AIDE, debsecan,
  Suricata, fail2ban and CrowdSec. Third-party installers (CrowdSec,
  OSSEC/Wazuh) are shown as official steps, never piped blindly to a shell.
- **`auditxs tools scan`** — runs the installed scanners and collects their
  reports under `/var/lib/auditxs/reports/tools/` so you can cross-verify.
- **`auditxs tools vpn`** — reviews WireGuard and OpenVPN configuration
  (private-key file permissions, weak ciphers, HMAC).
- **`auditxs cve`** — warns when an installed package has a **known
  vulnerability with a fix available**, using the distribution's own
  security data (Debian debsecan / security suite, Fedora `dnf updateinfo`,
  openSUSE `zypper patches`). The warning appears on the console, in the log,
  in the HTML report banner, as check `VULN-001`, and in the GUI. AuditXS
  never upgrades packages for you — upgrades are not reversible.
- Checks `SEC-001..004` report whether the host is equipped with a host
  auditor, rootkit detector, file-integrity monitor and an IDS/IPS engine —
  i.e. whether the installed software is in a good, defended state.

## Documentation

| | |
|---|---|
| [docs/USAGE.md](docs/USAGE.md) | full user manual (CLI, GUI, workflows, files, exit codes) |
| [docs/SECURITY-GUIDE.md](docs/SECURITY-GUIDE.md) | **cybersecurity best-practices guide** — the reasoning behind every control, as a hardening playbook |
| [docs/WEBUI.md](docs/WEBUI.md) | the localhost Material Design web UI (`auditxs web`) and its security model |
| [docs/CHECKS.md](docs/CHECKS.md) | every check: what/why, what the fix changes, how it reverts (generated from the code) |
| [docs/COMPLIANCE.md](docs/COMPLIANCE.md) | domains, NIST CSF 2.0, CIS/STIG alignment, assessor evidence |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | engine, snapshot format, check API, testing |
| [docs/ROADMAP.md](docs/ROADMAP.md) | must-have feature rationale and deliberate non-goals |

## Repository layout

```
auditxs            CLI entry point
lib/               engine: core, distro, snapshot/rollback, registry, reports, fix helpers, maintenance
checks/            the 14 check modules (self-registering, self-documenting)
gui/               zenity GUI + desktop launcher
setup.sh           installer (Server/Workstation selection)
uninstall.sh       uninstaller (protects your snapshots)
scripts/updater.sh update-auditxs command
tests/             unit tests (safe anywhere) + end-to-end smoke test for disposable containers
.github/workflows  CI: shellcheck + bash -n, smoke test in Debian/Ubuntu/Fedora/Arch/openSUSE containers
docs/              architecture + generated check catalogue
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how the engine,
snapshot format and check API work — adding a new check is ~30 lines.

## License

GPL-3.0 — same spirit as the rest of the DigitalXS tooling.

**Disclaimer:** AuditXS applies conservative, widely-accepted baseline
hardening, but every environment is different. Review each fix (that is
what the explanations are for), test on non-production systems first, and
keep console access available when hardening remote machines.
