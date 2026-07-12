# AuditXS

**Transparent, reversible Linux security auditing & hardening** — by [DigitalXS](https://digitalxs.ca)

AuditXS audits Linux systems against fundamental, professional security
baselines (inspired by CIS-style controls) and — only if you ask it to —
hardens them, **one explained, consented, reversible change at a time**.

Supported distributions: **Debian · Ubuntu · Pop!\_OS · Arch · Fedora · openSUSE** (and their derivatives).

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
auditxs-gui                            graphical interface (zenity + pkexec)
```

A severity-weighted **hardening score (0–100)** summarizes each audit, and
every audit saves timestamped HTML + JSON reports under
`/var/lib/auditxs/reports/`.

## Server vs. Workstation profiles

Chosen during installation (stored in `/etc/auditxs/auditxs.conf`,
overridable per-run with `--profile`):

| | Server | Workstation |
|---|---|---|
| Updates, firewall, accounts, filesystem, kernel basics | ✔ | ✔ |
| SSH key-only login, idle-session timeouts | ✔ | – |
| auditd + baseline audit rules | ✔ | – |
| Disable Avahi / CUPS / Bluetooth | ✔ | – (desktop needs them) |
| Restrictive umask (027), Ctrl-Alt-Del guard, martian logging, wireless detection | ✔ | – |

## What is covered (47 checks, 9 categories)

**Updates** (pending updates, automatic security updates, pending reboot) ·
**SSH** (root login, auth limits, empty passwords, X11, key-only auth with
lockout guard, idle timeout, grace time) · **Firewall** (installed, active,
default-deny — with an SSH **lockout guard** before enabling) ·
**Accounts** (UID-0 uniqueness, empty passwords, password aging, NOPASSWD
sudo, system-account shells, umask) · **Filesystem** (sticky bits,
world-writable files, unowned files, sensitive-file permissions, home
permissions, SUID inventory) · **Kernel** (ASLR, kptr/dmesg restrictions,
SYN cookies, ICMP redirects, source routing, rp_filter, martian logging,
IP forwarding with container/VM detection, suid_dumpable, Ctrl-Alt-Del) ·
**Services** (legacy plaintext services, Avahi, CUPS, Bluetooth, systemd
sandboxing overview) · **Network** (listening inventory, uncommon protocols
dccp/sctp/rds/tipc, wireless on servers) · **Logging** (persistent journal,
auditd, baseline rules, log permissions).

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

## Repository layout

```
auditxs            CLI entry point
lib/               engine: core, distro, snapshot/rollback, registry, reports, fix helpers
checks/            the 9 check modules (self-registering, self-documenting)
gui/               zenity GUI + desktop launcher
setup.sh           installer (Server/Workstation selection)
uninstall.sh       uninstaller (protects your snapshots)
scripts/updater.sh update-auditxs command
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
