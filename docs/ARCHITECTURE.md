# AuditXS architecture

AuditXS is plain Bash (4+) with no runtime dependencies beyond coreutils
and the tools it audits. It is organised as a small engine plus
self-registering, self-documenting check modules.

```
auditxs                 CLI dispatcher: sources lib/*, then checks/*, parses args
lib/core.sh             colours, logging, prompts, xrun/write_file (dry-run aware)
lib/distro.sh           /etc/os-release detection, apt/pacman/dnf/zypper abstraction
lib/backup.sh           snapshot + manifest + ledger + rollback engine
lib/registry.sh         check registration, audit/harden runners, list/explain
lib/report.sh           TSV / JSON / self-contained HTML reports
lib/fixlib.sh           shared fix helpers (sysctl drop-ins, sshd, units, login.defs)
checks/NN-<category>.sh check modules, loaded in numeric order
gui/auditxs-gui         zenity front-end; elevates individual CLI calls via pkexec
```

## Check API

A check is registered with one call plus metadata, and implements
`audit_<ID>` (required) and `fix_<ID>` (optional):

```bash
register_check "SSH-001" "SSH" "critical" "server,workstation" \
    "SSH root login is disabled"
set_meta SSH-001 desc   "What is checked and why it matters…"
set_meta SSH-001 fix    "Exactly what the automatic fix changes…"
set_meta SSH-001 revert "How rollback restores the previous state…"

audit_SSH_001() {   # 0=PASS 1=FAIL(fixable) 2=WARN(manual) 3=SKIP
    DETAIL="human-readable evidence"
    return 1
}
fix_SSH_001() { sshd_set PermitRootLogin no && sshd_apply; }
```

Rules for fixes:

- **Record before you touch.** Call `track_file`, `record_mode`,
  `record_sysctl`, `record_service_state` or `record_action` *before*
  modifying anything. `track_file` copies an existing file into the
  snapshot, or records that the file did not exist (so rollback deletes it).
- **Run through `xrun`/`xrun_q`/`write_file`** so `--dry-run` shows the
  exact command or file content instead of executing.
- **Never remove data, never loosen permissions, never upgrade packages.**
  Checks whose remediation is irreversible or judgment-heavy return
  WARN (2) and have no fix function.
- After a fix, the engine re-runs the audit function to verify, and reports
  honestly if it still fails.

## Snapshot format

Created lazily on the first recorded action of a `harden` run:

```
/var/lib/auditxs/snapshots/<YYYYMMDD-HHMMSS>/
├── meta            id/date/host/profile/version
├── manifest.tsv    seq  check-id  type  target  prev  new
├── checks          IDs of checks that applied fixes
├── files/…         verbatim copies of files before modification
└── ROLLED_BACK     (timestamp; present once reverted)
```

Manifest action types and their rollback behaviour:

| type | rollback |
|---|---|
| `file` | copy saved file back |
| `file_created` | delete the file |
| `mode` | chmod back to recorded octal mode |
| `sysctl` | `sysctl -w key=previous` (drop-in file itself is a `file_created`) |
| `service` | restore recorded enabled/active state |
| `pkg` | offer to remove package AuditXS installed |
| `ufw_state` / `ufw_rule` / `ufw_default` | disable ufw / delete rule / restore policy |
| `fw_service` / `fw_target` | remove firewalld service / restore zone target |
| `note` | informational only |

Rollback replays the manifest **in reverse order**, then reloads affected
daemons (systemd units, journald, auditd rules) and validates + reloads
sshd if SSH files were restored.

Every recorded action is also appended to the global ledger
`/var/lib/auditxs/changes.log` — an append-only, human-readable history of
everything AuditXS ever changed on the machine, including rollbacks.

## Profiles

`PROFILE` (`server` | `workstation`) comes from `/etc/auditxs/auditxs.conf`
(written by the installer) or `--profile`. Each check declares the profiles
it applies to; non-applicable checks are reported as SKIP, so the report
always shows the full picture.

## Adding a distribution

`lib/distro.sh` maps `ID`/`ID_LIKE` to a family (`debian`, `arch`,
`redhat`, `suse`) which selects the package manager and firewall
convention. Derivatives usually work out of the box via `ID_LIKE`.
