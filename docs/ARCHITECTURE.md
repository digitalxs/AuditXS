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

## Domains and NIST CSF mapping (v0.3)

`DOMAIN_OF_CATEGORY` in `lib/registry.sh` rolls categories up into the
five assessment domains (`--domain` filter, report grouping).
`NIST_OF_CATEGORY` provides indicative NIST CSF 2.0 mappings per category;
individual checks override with `set_meta <ID> nist "PR.AA-03"`. Both
surfaces appear in `explain`, `list --markdown`, JSON and HTML reports.

## Maintenance commands (v0.3)

`lib/maintenance.sh` implements:

- `doctor` — installation/tooling/config diagnostics plus snapshot
  integrity verification (manifest structure, saved file copies).
- `baseline set|show|clear` — manages `/etc/auditxs/baseline.json`, the
  approved report used for drift comparison.
- `schedule enable|disable|status|run` — a systemd service+timer pair
  running `auditxs schedule run` daily: quiet audit, then
  `diff_current_against` the baseline; a regression fails the unit so
  monitoring can alert. The units are plain labelled files removed by
  `schedule disable` (and by the uninstaller).

## Debugging and testing

- `--debug` (or `AUDITXS_DEBUG=1`) prints per-check timings, return codes
  and engine decisions to stderr and the daily log.
- `tests/unit.sh` — pure-function unit tests (escaping, permission math,
  registry filtering, report parsing, diff classification). Safe anywhere.
- `tests/smoke.sh` — end-to-end in a disposable container: audit
  (asserting read-only), dry-run (asserting zero changes), real harden,
  baseline diff both directions, rollback with byte-exact restoration.
- CI runs shellcheck + `bash -n`, the unit tests, and the smoke test in
  Debian/Ubuntu/Fedora/Arch/openSUSE containers.

## v0.4 additions

New engine libraries:

- `lib/cve.sh` — known-vulnerability awareness from the distribution's own
  security data (Debian debsecan / apt-security suite, dnf updateinfo,
  zypper patches). Populates `CVE_COUNT`/`CVE_SOURCE`/`CVE_LIST`, surfaced by
  check `VULN-001`, the console/HTML banners and `auditxs cve`.
- `lib/tools.sh` — the `auditxs tools` subcommand: `status`, `install`,
  `scan`, `vpn`. Installs go through the snapshot machinery; scanners
  (Lynis, rkhunter, tiger, chkrootkit, checksecurity, lsat) are run and
  their reports collected under `/var/lib/auditxs/reports/tools/`. CrowdSec
  and OSSEC/Wazuh, which need third-party installers, are handled with
  guidance rather than piping remote scripts to a shell.

Console & report styling:

- `lib/core.sh` gains `nala_box`/`nala_row`/`nala_end`/`nala_rule` — clean
  rounded box-drawing output inspired by the `nala` apt front-end, used by
  the audit header, per-category section rules and the summary. Falls back
  to plain output when not on a colour terminal.
- `lib/report.sh` `results_html` is a self-contained **Material Design 3**
  report: theme-aware (light/dark), score ring, status chips, per-domain
  cards, NIST column, and a CVE warning banner when applicable.

New check categories (all mapped into the five domains): Debian, PHP, Mail
(Postfix/Dovecot), DNS (BIND/Unbound), Fail2ban, WebApps (WordPress/Drupal/
Laravel/Roundcube), SecurityTools, Vulnerabilities — plus firewall (ufw
logging/gufw), web-server (nginx TLS/HSTS, Varnish), and MySQL
(local_infile/accounts) additions. 122 checks total across 26 categories.

Debian 13 "trixie": `lib/distro.sh` records `DISTRO_VERSION`/`DISTRO_CODENAME`;
`DEB-002` treats Debian 12/13 as supported and flags EOL releases.

## v0.5 additions

**Fixture-testable checks (`AX_ROOT`).** `lib/core.sh` defines `AX_ROOT`
(from `AUDITXS_ROOT_PREFIX`) and `axpath()`. Checks that read config files
resolve paths through `axpath` so their `audit_<ID>` logic can be exercised
against a fake `/etc` tree with no privileges. `tests/check_test.sh` builds
fixtures and asserts PASS/FAIL/WARN outcomes for the Accounts and Filesystem
checks and the Debian-release check. New file-reading checks should use
`axpath` to remain testable. Converted so far: Accounts (ACC-*), Filesystem
FS-004.

**CIS Benchmark ids + profile levels.** `lib/registry.sh` holds a central,
indicative CIS section map (`CIS_OF_CHECK`) and a Level-2 set
(`LEVEL2_CHECK`); `cis_of`/`level_of` resolve per-check overrides
(`set_meta <ID> cis|level`) first. Surfaced in `explain`, `list`,
`docs/CHECKS.md`, and JSON/HTML reports. Filters: `--level 1|2` (2 includes
1) and `--framework cis`, applied by `selected()` so they narrow audit,
list and markdown output alike.

**Debian packaging.** `packaging/build-deb.sh` produces an `all`-arch `.deb`
with `dpkg-deb`: the program under `/usr/share/auditxs`, command symlinks in
`/usr/bin`, `man auditxs(8)`, a desktop launcher, a conffile
`/etc/auditxs/auditxs.conf`, and postinst/postrm maintainer scripts that
create state dirs and preserve snapshots on removal. `update-auditxs`
detects a dpkg-managed install and defers to apt. CI builds the package and
installs/runs/purges it in a clean `debian:stable` container.

## v0.6 — the web UI

`gui/auditxs-web.py` is a Python **standard-library** HTTP server (no
framework) that renders a Material Design 3 single-page app and drives the
`auditxs` CLI. It is launched by `auditxs web` (which sets `AUDITXS_BIN` to
the resolved CLI path and execs python3). It stays a thin front-end: every
operation is the same `auditxs` command run with an argv list.

Security-critical properties, tested by `tests/web_test.sh` (in CI):

- binds `127.0.0.1` only — never a routable address;
- a fresh bearer token per launch, required on every request (`X-Auth-Token`);
- state-changing routes are POST-only with the token in a header (CSRF) and a
  loopback `Host` check;
- CLI invocations use argv lists (never a shell); check/snapshot IDs are
  validated `[A-Za-z0-9-]`;
- strict `Content-Security-Policy` and `X-Content-Type-Options` on every
  response.

Reach a headless server over an SSH tunnel; see docs/WEBUI.md. The zenity GUI
remains the zero-dependency desktop fallback.
