<div align="center">

# 🛡️ AuditXS

### Transparent, reversible Linux security auditing &amp; hardening

*Audit your system against professional security baselines — then harden it,
one explained, consented, reversible change at a time.*

[![CI](https://github.com/digitalxs/AuditXS/actions/workflows/ci.yml/badge.svg)](https://github.com/digitalxs/AuditXS/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-0.7.1-2ea44f)](https://github.com/digitalxs/AuditXS/releases)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)
[![Bash](https://img.shields.io/badge/bash-4%2B-121011?logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Checks](https://img.shields.io/badge/checks-87-8957e5)](docs/CHECKS.md)
[![Frameworks](https://img.shields.io/badge/NIST%20CSF%202.0%20·%20CIS%20·%20STIG-informational)](docs/COMPLIANCE.md)

**Debian** · **Ubuntu** · **Pop!\_OS** · **Arch** · **Fedora** · **openSUSE** *(and derivatives)*

[Quick start](#-quick-start) · [Usage](#-usage) · [Profiles &amp; interfaces](#-profiles--interfaces) · [Coverage](#-what-is-covered) · [Documentation](#-documentation)

</div>

---

AuditXS assesses a Linux system against fundamental, professional security
baselines (aligned with **CIS Benchmark** / **DISA STIG** controls and mapped
to the **NIST Cybersecurity Framework 2.0**) and — only if you ask it to —
hardens it. Every change is explained before it happens, applied only with
your consent, and can be undone completely. It is written in portable Bash,
ships as a `.deb` or a source installer, and offers a CLI, an ncurses
terminal UI, a localhost web UI and a native desktop app.

<div align="center">

### The three rules AuditXS lives by

</div>

| | | |
|:--:|---|---|
| 🔍 | **Transparent** | `auditxs audit` is strictly read-only. Every check explains *what* it inspects, *why* it matters, *exactly what* its fix changes and *how* it reverts (`auditxs explain SSH-001`). Every file AuditXS writes carries a header naming the check that wrote it and how to undo it. |
| ↩️ | **Reversible** | Before anything changes, the previous state is captured in a timestamped **snapshot** — files copied, service/sysctl/permission state logged in a manifest. `sudo auditxs rollback latest` restores everything in reverse order. A global append-only ledger (`/var/lib/auditxs/changes.log`) records every action ever taken. |
| ✅ | **Consented** | `auditxs harden` walks failed checks one by one, shows the full explanation, and asks before each fix. `--dry-run` prints every intended command and file write without touching anything; `--yes` enables unattended use once you trust it. |

---

## 🚀 Quick start

**Debian / Ubuntu — build and install the `.deb`:**

```bash
git clone https://github.com/digitalxs/AuditXS.git && cd AuditXS
./packaging/build-deb.sh                 # builds dist/auditxs_<version>_all.deb
sudo apt install ./dist/auditxs_*_all.deb
```

Installs to `/usr/share/auditxs`, provides the `auditxs`, `auditxs-gui` and
`update-auditxs` commands, a man page (`man auditxs`) and a desktop launcher,
and updates cleanly with `apt`.

**Any distribution — source installer *(dxsbash-style)*:**

```bash
git clone https://github.com/digitalxs/AuditXS.git && cd AuditXS
sudo ./setup.sh
```

The installer detects your distribution, asks whether the machine is a
**Server** or **Workstation** (this profile decides which checks apply), links
the commands into `/usr/local/bin`, and installs the terminal-UI dependency —
plus `zenity` and a desktop launcher on workstations.

```bash
# non-interactive variants
sudo ./setup.sh --server -y          # or --workstation -y
sudo ./setup.sh --no-gui             # skip the graphical launcher
sudo ./setup.sh --refresh            # repair / update in place
sudo ./setup.sh --uninstall
```

Update later with `sudo update-auditxs`; remove with `sudo /opt/auditxs/uninstall.sh`
(your snapshots are preserved).

**First run:**

```bash
sudo auditxs audit                   # read-only — nothing is changed
sudo auditxs harden --dry-run        # preview every fix without applying it
```

---

## 🧭 Usage

```text
sudo auditxs audit                     read-only audit + HTML/JSON report
sudo auditxs harden --dry-run          preview every fix, change nothing
sudo auditxs harden                    apply fixes one by one, with consent
sudo auditxs harden --category SSH     harden one category only
sudo auditxs rollback latest           undo the last hardening run completely
sudo auditxs snapshots                 list change snapshots

auditxs list                           the full check catalogue
auditxs list --level 1                 only CIS Level 1 checks
auditxs explain FW-002 SSH-005         what a check inspects / changes / reverts
sudo auditxs audit --domain Database   audit one assessment domain
sudo auditxs report --format html      fresh report to stdout (also: json, tsv)
sudo auditxs audit --baseline old.json compare a fresh audit against a saved report
auditxs diff old.json new.json         compare two reports (exits 1 on regressions)

sudo auditxs cve                       warn about installed packages with a known CVE
sudo auditxs tools status              inventory of installed security tooling
sudo auditxs tools install lynis       install a security tool (reversible)
sudo auditxs tools scan                run installed scanners (Lynis, rkhunter, …)
auditxs tools vpn                      review WireGuard / OpenVPN configuration

sudo auditxs tui                       terminal (ncurses) UI — works over SSH, any profile
sudo auditxs web                       Material Design web UI, localhost-only (workstation)
sudo auditxs qt                        native Qt desktop app (workstation; auditxs-gui-qt)
auditxs profile                        print the active profile (server | workstation)

sudo auditxs baseline set              approve the latest report for drift alerts
sudo auditxs schedule enable           daily audit + drift alert (systemd timer)
auditxs doctor                         diagnose installation, tooling, snapshots
sudo auditxs audit --debug             verbose diagnostics (timings, decisions)
```

Every audit prints a severity-weighted **hardening score (0–100)** and saves
timestamped HTML + JSON reports under `/var/lib/auditxs/reports/`. The console
uses a clean **nala-style** boxed layout; the HTML report is **Material Design
3** (theme-aware, score ring, status chips, per-domain cards). A **CVE warning
banner** appears on the console, in the log, in the report and in the GUI when
an installed package has a known vulnerability with a fix available.

<details>
<summary><b>See it in action</b> — every check documents itself</summary>

```text
$ auditxs explain SSH-001

SSH-001 — SSH root login is disabled
  Category: SSH · Domain: Server Hardening · Severity: critical · Profiles: server,workstation
  NIST CSF 2.0: PR.AA-01, PR.AA-03  ·  CIS: 5.1.20  ·  Level: 1
  What is checked and why:
    Checks the effective 'PermitRootLogin' value (via sshd -T). Direct root
    login is the primary target of SSH brute-force campaigns and removes the
    audit trail of who logged in. Administrators should log in as a normal
    user and elevate with sudo.
  What the automatic fix changes:
    Sets 'PermitRootLogin no' in /etc/ssh/sshd_config.d/99-auditxs.conf,
    validates the configuration with 'sshd -t' and reloads the SSH service.
  How it is reverted:
    The previous SSH configuration is saved in the snapshot; 'sudo auditxs
    rollback' restores it, re-validates with 'sshd -t' and reloads sshd.
```

</details>

---

## 👤 Profiles &amp; interfaces

The **profile** — chosen at install time, stored in `/etc/auditxs/auditxs.conf`,
overridable per-run with `--profile` — decides both *which checks apply* and
*which interfaces are available*.

**Checks by profile:**

| Applies to | Server | Workstation |
|---|:--:|:--:|
| Updates, firewall, accounts, filesystem, kernel basics, MAC status | ✔ | ✔ |
| SSH key-only login, idle-session timeouts, fail2ban brute-force protection | ✔ | – |
| auditd + baseline audit rules | ✔ | – |
| Disable Avahi / CUPS / Bluetooth | ✔ | – *(desktop needs them)* |
| Restrictive umask (027), Ctrl-Alt-Del guard, martian logging, wireless detection | ✔ | – |

**Interfaces by profile** — servers are kept to text interfaces only, so
nothing runs a browser or a root web server on a headless box:

| Interface | Command | Server | Workstation |
|---|---|:--:|:--:|
| Command line | `auditxs audit` / `harden` / … | ✔ | ✔ |
| Terminal UI (ncurses, works over SSH) | `sudo auditxs tui` | ✔ | ✔ |
| Localhost web UI (Material Design) | `sudo auditxs web` | – | ✔ |
| Native desktop app (Qt) | `sudo auditxs qt` | – | ✔ |
| Graphical launcher (zenity) | `auditxs-gui` | – | ✔ |

> On a server, `web` / `qt` / `auditxs-gui` refuse to start and point you at
> `sudo auditxs tui`. If a machine is really a desktop installed with the
> server profile, add `--profile workstation` for a one-off, or edit the config.

---

## 🧩 Assessment domains &amp; frameworks

Checks roll up into the five domains professional assessments are organised
around — audit any one with `--domain`:

- **Server Hardening** — SSH, accounts, sudo accountability, MFA posture, admin-account inventory
- **OS Hardening** — CIS/STIG-aligned updates, kernel, filesystem, MAC, logging, banners, `/tmp`
- **Network Security** — firewall, protocol surface, listening-port allowlist drift detection
- **Application Hardening** — service surface, nginx/Apache secure config with validate-or-restore
- **Database Hardening** — MySQL/PostgreSQL exposure, `trust`-auth detection, TLS guidance *(report-only by design)*

Every mappable check carries an indicative **NIST CSF 2.0** function and a
**CIS Benchmark** id + level, surfaced in `auditxs explain`, the reports and
[docs/CHECKS.md](docs/CHECKS.md). Filter with `--framework cis` or `--level 1|2`.
Full detail: [docs/COMPLIANCE.md](docs/COMPLIANCE.md).

---

## 📋 What is covered

**87 checks across 20 categories.** The full catalogue — with per-check
documentation generated from the code itself — lives in
[docs/CHECKS.md](docs/CHECKS.md) (or run `auditxs list --markdown`).

| Category | Highlights |
|---|---|
| **Updates** | pending updates, automatic security updates, pending reboot |
| **Debian** | APT signature enforcement, release EOL awareness, needrestart |
| **SSH** | root login, auth limits, empty passwords, X11, key-only auth *(with lockout guard)*, idle timeout, grace time, fail2ban/sshguard |
| **Firewall** | installed, active, default-deny — with an SSH **lockout guard** before enabling |
| **Accounts** | UID-0 uniqueness, empty passwords, password aging, NOPASSWD sudo, system-account shells, umask, `pam_pwquality` |
| **Privileged** | sudo pty + logging, SSH MFA posture, admin inventory |
| **Filesystem** | sticky bits, world-writable &amp; unowned files, sensitive-file &amp; home permissions, SUID inventory |
| **Kernel** | ASLR, kptr/dmesg restrictions, SYN cookies, ICMP redirects, source routing, rp_filter, martian logging, IP forwarding *(container/VM aware)*, suid_dumpable, Ctrl-Alt-Del |
| **MAC** | SELinux / AppArmor status with per-distro guidance |
| **Services** | legacy plaintext services, Avahi, CUPS, Bluetooth, systemd sandboxing overview |
| **Network** | listening inventory, uncommon protocols (dccp/sctp/rds/tipc), wireless on servers |
| **Logging** | persistent journal, auditd, baseline rules, log permissions |
| **Applications / PHP** | nginx/Apache version disclosure, security headers, directory listing; `expose_php`, `display_errors`, session cookies, dangerous functions |
| **Mail / DNS** | Postfix open-relay/TLS/banner, Dovecot plaintext-auth &amp; TLS; BIND recursion/version, Unbound access control |
| **Database** | MySQL/MariaDB exposure, `local_infile`, anonymous accounts; PostgreSQL exposure &amp; authentication |
| **SecurityTools / Vulnerabilities** | host auditor, rootkit detector, file-integrity monitor, IDS/IPS present; known-CVE packages from distribution security data |

> Checks marked **manual** (e.g. pending updates, NOPASSWD sudo entries, SUID
> inventory) *never* change the system — irreversible or judgment-heavy actions
> are deliberately left to the administrator.

---

## 🔒 Safety engineering worth knowing about

- **SSH** — fixes go into `/etc/ssh/sshd_config.d/99-auditxs.conf`, are validated with `sshd -t`, and the previous config is restored automatically on failure. Key-only auth is **refused** unless a regular user already has `authorized_keys`.
- **Firewall** — before enabling, the SSH port is explicitly allowed whenever the machine is managed over SSH (lockout guard).
- **Kernel** — one labelled drop-in per check under `/etc/sysctl.d/`; previous runtime values recorded and restored on rollback. IP forwarding is left alone when Docker / Podman / libvirt is detected.
- **Permissions** — AuditXS only ever *tightens* modes, and records each file's exact previous mode.
- **Packages** — never removed automatically; packages *installed* by a fix are recorded and offered for removal during rollback.

---

## 🛠️ Security tooling, external scanners &amp; CVE warnings

AuditXS hardens configuration itself, and *integrates* the wider ecosystem
rather than reinventing it — all through the same reversible interface:

- **`auditxs tools status`** — a capability-grouped inventory (host auditing/compliance, rootkit/malware, file integrity, vulnerability data, audit/accounting, active defence, isolation/device control, endpoint visibility) so you can see coverage gaps at a glance.
- **`auditxs tools install`** — guided, reversible install of **Lynis, rkhunter, chkrootkit, Tiger, checksecurity, lsat, AIDE, debsecan, ClamAV, OpenSCAP, auditd, Fail2ban, CrowdSec, Suricata, arpwatch, USBGuard, Firejail, Logwatch** and more, each with post-install setup guidance. Third-party installers (CrowdSec, OSSEC/Wazuh, osquery, Trivy) are shown as official signed-repo steps, never piped blindly to a shell.
- **`auditxs tools scan`** — runs the installed scanners (including ClamAV and an auto-selected OpenSCAP CIS/STIG profile) and collects their reports under `/var/lib/auditxs/reports/tools/` for cross-verification.
- **`auditxs tools vpn`** — reviews WireGuard / OpenVPN configuration (private-key permissions, weak ciphers, HMAC).
- **`auditxs cve`** — warns when an installed package has a **known vulnerability with a fix available**, using the distribution's own security data (Debian debsecan, Fedora `dnf updateinfo`, openSUSE `zypper patches`). AuditXS never upgrades packages for you — upgrades are not reversible.

---

## 📚 Documentation

| Guide | What's inside |
|---|---|
| [docs/USAGE.md](docs/USAGE.md) | Full user manual — CLI, all interfaces, workflows, files, exit codes |
| [docs/SECURITY-GUIDE.md](docs/SECURITY-GUIDE.md) | **Cybersecurity best-practices playbook** — the reasoning behind every control |
| [docs/WEBUI.md](docs/WEBUI.md) | The localhost web UI (`auditxs web`) and its security model |
| [docs/CHECKS.md](docs/CHECKS.md) | Every check: what/why, what the fix changes, how it reverts *(generated from code)* |
| [docs/COMPLIANCE.md](docs/COMPLIANCE.md) | Domains, NIST CSF 2.0, CIS/STIG alignment, assessor evidence |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Engine, snapshot format, check API, testing |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Must-have feature rationale and deliberate non-goals |

---

## 🗂️ Repository layout

```text
auditxs             CLI entry point
lib/                engine — core, distro, snapshot/rollback, registry, reports, fix helpers, maintenance
checks/             20 self-registering, self-documenting check modules (87 checks)
gui/                terminal UI (ncurses), zenity GUI, web UI, Qt/QML app + desktop launcher
setup.sh            installer (Server / Workstation selection)
uninstall.sh        uninstaller (protects your snapshots)
scripts/updater.sh  the update-auditxs command
packaging/          .deb build scripts + man page
tests/              unit + fixture check tests (safe anywhere) + containerised smoke test
.github/workflows/  CI — shellcheck + bash -n, unit/check/web/Qt tests, .deb build, 5-distro smoke matrix
docs/               architecture, compliance, security guide + generated check catalogue
```

Adding a new check is ~30 lines — see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
for the engine, snapshot format and check API.

---

## 📄 License

**GPL-3.0** — in the same spirit as the rest of the [DigitalXS](https://digitalxs.ca) tooling.

> **Disclaimer** — AuditXS applies conservative, widely-accepted baseline
> hardening, but every environment is different. Review each fix (that is what
> the explanations are for), test on non-production systems first, and keep
> console access available when hardening remote machines.

<div align="center">

Made with care by [**DigitalXS**](https://digitalxs.ca) · [Report an issue](https://github.com/digitalxs/AuditXS/issues) · [Contribute](docs/ARCHITECTURE.md)

</div>
