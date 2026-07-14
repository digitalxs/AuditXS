# AuditXS — frameworks, domains and compliance alignment

AuditXS implements *fundamental, widely-accepted baseline controls*. It is
aligned with — but is not a certified implementation of — the CIS
Benchmarks, DISA STIG principles and the NIST Cybersecurity Framework 2.0.
Use it as the automated foundation of an assessment, not as a compliance
certificate.

## Assessment domains

Every check belongs to a category, and categories roll up into the five
domains security assessments are usually organised around. Audit a single
domain with `--domain`:

```bash
sudo auditxs audit --domain "Server Hardening"
sudo auditxs audit --domain "Database"        # prefix match works
```

| Domain | Categories | What it evaluates |
|---|---|---|
| **Server Hardening** | SSH, Accounts, Privileged | privileged access (sudo accountability, admin inventory), MFA posture, remote-access configuration |
| **OS Hardening** | Updates, OS, Kernel, Filesystem, MAC, Logging | CIS/STIG-aligned OS configuration: patching, kernel hardening, permissions, MAC, audit trail |
| **Network Security** | Firewall, Network | exposure control, default-deny, protocol surface, listening-port drift detection (NET-004) |
| **Application Hardening** | Services, Applications | least service surface, web-server secure configuration (validated drop-ins) |
| **Database Hardening** | Database | exposure, authentication strength ('trust' detection), TLS/at-rest encryption guidance |

## NIST Cybersecurity Framework 2.0

Each check carries an indicative NIST CSF 2.0 subcategory mapping, visible
in `auditxs explain <ID>`, in [CHECKS.md](CHECKS.md), and in the JSON/HTML
reports. Mappings are category-level defaults with per-check overrides —
indicative, not a formal crosswalk.

Where AuditXS sits in the CSF functions:

- **IDENTIFY** — pending-update awareness (UPD-001), administrative
  account inventory (PRV-003), SUID and listening-service inventories.
- **PROTECT** — the majority of checks: access control (PR.AA), data
  security (PR.DS), platform security (PR.PS), resilience (PR.IR).
- **DETECT** — auditd + rules (LOG-002/003), persistent journal
  (LOG-001), port-allowlist drift (NET-004), scheduled audits with
  baseline comparison (`auditxs schedule`).
- **RESPOND / RECOVER** — out of scope for a configuration tool, with one
  deliberate exception: complete rollback (`auditxs rollback`) restores a
  known configuration state, and the change ledger provides the
  configuration-change record an investigation needs.

## CIS Benchmark IDs and profile levels

Every mappable check carries a structured, indicative CIS Benchmark
section reference and a **profile level**:

- **Level 1** — baseline hardening that applies broadly with little
  operational impact (the default).
- **Level 2** — stricter, defence-in-depth controls that may affect
  functionality (e.g. SSH key-only auth, auditd + rules, `/tmp` noexec,
  umask 027, blocking uncommon network protocols).

Filter by them, mirroring how a CIS assessment is scoped:

```bash
sudo auditxs audit --level 1                 # Level-1 controls only
sudo auditxs audit --level 2                 # Level 1 + Level 2
sudo auditxs audit --framework cis           # only checks with a CIS reference
auditxs list --framework cis                 # the CIS-mapped catalogue
auditxs explain SSH-001                       # shows CIS id + level + NIST
```

The CIS id and level appear in `explain`, `list`, `docs/CHECKS.md`, and the
JSON/HTML reports. The numbers track CIS section *areas* (Distribution
Independent / Debian Linux Benchmark), not a specific revision — treat them
as indicative cross-references, not certification.

## CIS Benchmark / DISA STIG alignment

AuditXS checks correspond to Level-1-style CIS items that are safe to
automate and meaningful on every distribution: sysctl network/kernel
hardening (KRN-*), filesystem permissions and sticky bits (FS-*), sudo
use_pty/logfile (PRV-001, CIS 5.2.x), SSH server hardening (SSH-*, CIS
4.2.x style), login banners (OSH-001, STIG SRG-OS-000023), /tmp mount
options (OSH-002, CIS 1.1.2), legacy service removal (SVC-001), uncommon
protocol blacklisting (NET-002), password quality and aging (ACC-003/007).

Deviations are deliberate and documented per check:

- items that differ per organisation (banner wording, port lists,
  password maximums) ship conservative defaults you can edit;
- items whose automation is risky (bootloader/MAC enablement, PAM stack
  edits on Fedora/Arch, database configuration, mount changes) are
  **report-only** with the exact manual path in the finding;
- every automated change is reversible, which some benchmark items
  (package removal, partitioning) cannot be — those are reported instead.

## Evidence for assessors

- `auditxs report --format html` — human-readable evidence with status,
  severity, domain and NIST mapping per check.
- `auditxs report --format json` — machine-readable for GRC tooling.
- `/var/lib/auditxs/changes.log` — append-only record of every change
  AuditXS ever made (including rollbacks), with timestamps and check IDs.
- Snapshots — before/after proof for every applied fix.
- `auditxs diff` — dated comparison against the approved baseline,
  demonstrating configuration-drift monitoring (CSF DE.CM).
