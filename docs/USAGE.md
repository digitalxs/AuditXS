# AuditXS user manual

AuditXS audits Linux systems against fundamental security baselines and —
only with your explicit consent — hardens them with fully reversible
changes. This manual covers the CLI, the GUI, and the operational
workflows. See [COMPLIANCE.md](COMPLIANCE.md) for framework alignment and
[CHECKS.md](CHECKS.md) for every check's documentation.

## Contents

1. [Concepts](#concepts)
2. [Installation](#installation)
3. [Auditing](#auditing)
4. [Hardening](#hardening)
5. [Rollback](#rollback)
6. [Baselines & drift detection](#baselines--drift-detection)
7. [Scheduled audits](#scheduled-audits)
8. [Maintenance (doctor)](#maintenance-doctor)
9. [The GUI](#the-gui)
10. [Debugging](#debugging)
11. [Files & directories](#files--directories)
12. [Exit codes](#exit-codes)

## Concepts

- **Check** — one auditable statement about the system (e.g. `SSH-001 —
  SSH root login is disabled`). Every check documents what it inspects,
  why it matters, what its fix changes and how that is reverted:
  `auditxs explain SSH-001`.
- **Status** — `PASS`, `FAIL` (finding; a fix is offered when the check
  provides one), `WARN` (needs human judgement — never auto-fixed), `SKIP`
  (not applicable: software absent or wrong profile).
- **Profile** — `server` or `workstation`, chosen at install time
  (`/etc/auditxs/auditxs.conf`), overridable per run with `--profile`.
- **Category / Domain** — checks are grouped in categories (SSH, Kernel,
  …) which roll up into five assessment domains: Server Hardening,
  OS Hardening, Network Security, Application Hardening, Database
  Hardening.
- **Snapshot** — the recorded pre-change state (file copies + action
  manifest) created automatically by the first change of a `harden` run.
- **Baseline** — an approved audit report used to detect drift.

## Installation

```bash
git clone https://github.com/digitalxs/AuditXS.git
cd AuditXS
sudo ./setup.sh                    # interactive: mode + Server/Workstation
sudo ./setup.sh --server -y        # non-interactive server install
sudo ./setup.sh --workstation -y --no-gui
sudo ./setup.sh --refresh          # repair/update files, keep configuration
sudo update-auditxs                # update an existing installation
sudo /opt/auditxs/uninstall.sh    # remove (asks before deleting snapshots)
```

## Auditing

Audits are **strictly read-only** — nothing on the system changes.

```bash
sudo auditxs audit                          # everything applicable to the profile
sudo auditxs audit --category SSH           # one category
sudo auditxs audit --domain "Database"      # one assessment domain
sudo auditxs audit --check SSH-001 --check FW-002
sudo auditxs audit --profile server         # override the configured profile
sudo auditxs audit --format json            # machine-readable to stdout (also: tsv, html)
```

Every console audit saves timestamped HTML and JSON reports under
`/var/lib/auditxs/reports/` (plus `latest.json` / `latest.html`) and ends
with a severity-weighted hardening score (0–100).

To read the catalogue without running anything:

```bash
auditxs list                # table of all checks
auditxs list --markdown     # full documentation (source of docs/CHECKS.md)
auditxs explain FW-002      # one check in depth, including NIST CSF mapping
```

## Hardening

```bash
sudo auditxs harden --dry-run     # preview: every intended command/file, zero changes
sudo auditxs harden               # interactive: each fix explained, then confirmed
sudo auditxs harden --category SSH
sudo auditxs harden --check NET-002 --yes   # non-interactive (automation)
```

For each failing check with an automatic fix, AuditXS shows what is
checked and why, exactly what the fix changes, and how it is reverted —
then asks. After applying, the check is re-audited and the honest result
reported. All changes of one run land in a single snapshot.

Checks whose remediation is irreversible or judgement-heavy (package
upgrades, sudoers NOPASSWD entries, database settings, MFA enrolment…)
are **report-only**: they explain the manual path and never touch the
system.

## Rollback

```bash
sudo auditxs snapshots            # list snapshots (id, date, actions, state)
sudo auditxs rollback latest      # undo the most recent hardening run
sudo auditxs rollback 20260712-211102
```

Rollback shows the full plan (every recorded action, reverted in reverse
order), asks for confirmation, restores files byte-for-byte, re-applies
recorded permissions/sysctl/service states, offers to remove packages
AuditXS installed, then validates and reloads affected daemons (sshd is
re-validated with `sshd -t` before reload). The global ledger
`/var/lib/auditxs/changes.log` records everything ever changed, including
rollbacks.

## Baselines & drift detection

Capture a known-good state and detect any regression from it:

```bash
sudo auditxs audit                     # produce a report
sudo auditxs baseline set              # approve the latest report as baseline
auditxs baseline show                  # inspect the approved baseline
sudo auditxs audit --baseline /etc/auditxs/baseline.json   # compare inline
sudo auditxs diff /etc/auditxs/baseline.json               # compare latest report
```

`auditxs diff` exits **1 when any check regressed**, so it can gate CI
pipelines or fire monitoring alerts. Improvements, regressions and scope
changes are listed separately with the score delta.

Port-level drift: approve the expected listening ports once and `NET-004`
fails whenever anything new starts listening — see
`auditxs explain NET-004`.

## Scheduled audits

```bash
sudo auditxs schedule enable    # daily read-only audit via systemd timer
auditxs schedule status
sudo auditxs schedule disable
```

The timer runs `auditxs schedule run`: a quiet audit (reports saved as
usual) followed by a comparison against the approved baseline. A
regression makes the service run **fail**, which any systemd-based
monitoring picks up (`systemctl status auditxs-audit.service`, journal,
OnFailure hooks). Without systemd, add a cron entry:
`0 3 * * * /usr/local/bin/auditxs schedule run`.

## Maintenance (doctor)

```bash
auditxs doctor        # as root, also verifies snapshot integrity
```

Doctor verifies the installation (commands, registered checks), required
and feature tooling, configuration (profile, baseline, port allowlist),
snapshot integrity (manifest structure and saved file copies), state size,
the change ledger, and the scheduled-audit timer. Exit code 1 means at
least one real problem was found.

## The GUI

`auditxs-gui` (zenity) is a thin wrapper over the CLI — everything it does
is a visible `auditxs` command, elevated per-operation via pkexec so you
see an authentication prompt exactly when privileges are used.

- **Audit** — read-only audit with a sortable results table.
- **Harden** — pick fixes from a checklist, review *exactly what will
  change* (mandatory review screen), apply, see the full change log.
- **Report** — generate and open the HTML report.
- **Rollback** — pick a snapshot, see it reverted.
- **Baseline** — approve the latest audit for drift alerts.
- **Doctor / Catalogue / About**.

## Debugging

```bash
sudo auditxs audit --debug        # per-check timings, return codes, decisions
AUDITXS_DEBUG=1 sudo auditxs harden --dry-run
```

Debug output goes to stderr and to the daily log
(`/var/log/auditxs/auditxs-YYYYMMDD.log`). Every executed command, file
write and snapshot action is logged even without debug mode.

## Files & directories

| Path | Purpose |
|---|---|
| `/opt/auditxs` | the program |
| `/usr/local/bin/auditxs`, `auditxs-gui`, `update-auditxs` | commands |
| `/etc/auditxs/auditxs.conf` | profile configuration |
| `/etc/auditxs/baseline.json` | approved baseline (optional) |
| `/etc/auditxs/allowed-ports.conf` | approved listening ports (optional, NET-004) |
| `/var/lib/auditxs/snapshots/` | rollback snapshots |
| `/var/lib/auditxs/reports/` | HTML/JSON audit reports |
| `/var/lib/auditxs/changes.log` | append-only ledger of every change |
| `/var/log/auditxs/` | daily logs, installer logs |
| files written by fixes | always labelled: `sysctl.d/99-auditxs-*`, `sshd_config.d/99-auditxs.conf`, `sudoers.d/99-auditxs`, `modprobe.d/99-auditxs-*`, … |

## Exit codes

| Command | 0 | 1 |
|---|---|---|
| `audit` | audit completed (findings do not affect the exit code) | usage/runtime error |
| `harden` | run completed | usage/runtime error |
| `diff` | no regressions | regressions found (or error) |
| `schedule run` | audit ok, no drift | regression vs baseline (alerts monitoring) |
| `doctor` | no problems | problems found |
| `rollback` | rolled back | cancelled or error |
