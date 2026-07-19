# AuditXS — Developer & Maintainer Guide

`digitalxs-dev-doc.MD` — the engineering companion to the user-facing
[README](README.md). It documents how AuditXS is built, why it is built that
way, and everything you need to develop, debug, test, package, release and
maintain it.

Audience: contributors and maintainers. If you only want to *use* AuditXS, read
the [README](README.md) and [docs/USAGE.md](docs/USAGE.md) instead.

---

## Table of contents

1. [Design philosophy](#1-design-philosophy)
2. [Repository map](#2-repository-map)
3. [Runtime architecture](#3-runtime-architecture)
4. [The check API — how a check works](#4-the-check-api--how-a-check-works)
5. [Core library reference](#5-core-library-reference)
6. [The snapshot / rollback engine](#6-the-snapshot--rollback-engine)
7. [Interfaces and profile gating](#7-interfaces-and-profile-gating)
8. [The error-code system](#8-the-error-code-system)
9. [Fleet mode internals](#9-fleet-mode-internals)
10. [Debugging](#10-debugging)
11. [Testing](#11-testing)
12. [Coding standards](#12-coding-standards)
13. [Versioning & the release process](#13-versioning--the-release-process)
14. [Working with GitHub on this project](#14-working-with-github-on-this-project)
15. [Maintenance runbook](#15-maintenance-runbook)
16. [Security model & threat considerations](#16-security-model--threat-considerations)

---

## 1. Design philosophy

Everything in AuditXS follows three inviolable rules. When in doubt, they win
over convenience:

1. **Transparent** — `auditxs audit` is strictly read-only. Every check
   documents *what* it inspects, *why*, *exactly what* its fix changes and
   *how* to revert it. Every file AuditXS writes carries a header naming the
   check that wrote it.
2. **Reversible** — nothing is changed before the previous state is captured in
   a snapshot. If a change cannot be recorded, it is not made. `auditxs
   rollback` restores everything.
3. **Consented** — fixes are applied one at a time, each after explicit
   confirmation (or `--yes`), with `--dry-run` to preview.

Practical consequences you must preserve when contributing:

- **Audit code must never mutate the system.** `audit_*` functions only read.
- **Fix code must record before it changes.** Use the snapshot helpers; never
  edit a file without first backing it up through them.
- **Irreversible actions are refused or left manual** (package upgrades,
  removing accounts, anything with data-loss potential).
- **Fail safe.** Validate daemon configs (`sshd -t`, `nginx -t`) and restore on
  failure; guard against SSH/firewall lockout.

---

## 2. Repository map

```
auditxs                 CLI entry point / dispatcher (sources libs + checks, routes commands)
VERSION                 single source of truth for the version string
lib/                    the engine (pure Bash, one concern per file)
  core.sh               colours, logging, prompts, privilege/env checks, xrun, write_file
  errors.sh             the AXnnnn error catalogue + ax_error() reporter
  distro.sh             distribution detection + package-manager abstraction
  registry.sh           check registration, metadata, run_audit, scoring, framework maps
  backup.sh             snapshot/rollback engine (manifest.tsv + changes.log)
  fixlib.sh             shared fix helpers (sysctl groups, sshd, services, logindefs)
  report.sh             text / TSV / JSON / HTML (Material Design) report renderers
  cve.sh                CVE / known-vulnerability scan (distribution security data)
  tools.sh              'auditxs tools' — install/scan external security tooling
  fleet.sh              'auditxs fleet' — read-only audit across hosts over SSH
  maintenance.sh        doctor, baseline, schedule, diff
checks/                 26 self-registering check modules (122 checks); numbered by category
gui/
  auditxs-gui           zenity front-end (per-op pkexec; prefers the Qt app when present)
  auditxs-tui.sh        ncurses (whiptail/dialog) terminal UI — the server interface
  auditxs-web.py        localhost Material Design web UI (Python stdlib only)
  auditxs-qt.py         PySide6 host for the Qt/QML app (Qt-free data layer + selftest)
  auditxs.qml           Qt Quick Controls (Material) view with custom window chrome
setup.sh                installer (Server/Workstation selection, dxsbash-style)
uninstall.sh            uninstaller (protects snapshots)
scripts/
  updater.sh            'update-auditxs' command
  release.sh            local release prep (build + checksum + optional sign + tag)
  build-site.py         static docs website generator (docs/*.html + index.html)
packaging/
  build-deb.sh          builds the .deb + SHA256 checksum
  auditxs.8             man page
  com.digitalxs.auditxs.policy   polkit policy (GUI auth kept between actions)
tests/                  unit.sh, check_test.sh, web_test.sh, qml_test.py, smoke.sh
.github/workflows/
  ci.yml                lint + tests + .deb build + 5-distro smoke matrix
  release.yml           tag-triggered signed release
docs/                   USAGE, SECURITY-GUIDE, WEBUI, CHECKS (generated), COMPLIANCE,
                        ERRORS (generated), ARCHITECTURE, ROADMAP
```

**Load order** (`auditxs` lines near the top): `core → errors → distro → backup
→ registry → report → fixlib → maintenance → cve → tools → fleet`, then every
`checks/*.sh` in filename order. Because sourcing is ordered, a library may use
anything defined earlier — `errors.sh` is loaded right after `core.sh` so every
later module can call `ax_error`.

---

## 3. Runtime architecture

A single Bash process; no daemon, no state machine beyond global variables.

```
 user → auditxs <cmd> [opts]
          │
          ├─ source lib/*.sh  (defines helpers + the check registry arrays)
          ├─ source checks/*.sh  (each calls register_check + set_meta at load time,
          │                       and defines audit_<ID> / fix_<ID> functions)
          ├─ parse global options into FORMAT/FILTER_*/ARGS
          ├─ detect_distro ; load /etc/auditxs/auditxs.conf (PROFILE)
          └─ dispatch on <cmd>:
                audit   → run_audit → print_summary → save_reports  (read-only)
                harden  → cmd_harden → per-check: explain → confirm → snapshot → fix → verify
                rollback→ replay a snapshot manifest in reverse
                report/diff/baseline/schedule/doctor/cve/tools/fleet/errors/…
```

Key global state (defined in `lib/registry.sh`) is a set of associative arrays
keyed by check ID: `CHECK_CATEGORY`, `CHECK_SEVERITY`, `CHECK_PROFILES`,
`CHECK_TITLE`, `CHECK_META_DESC/FIX/REVERT/CIS/LEVEL`, and the per-run
`RESULT_STATUS` / `RESULT_DETAIL`. `CHECK_IDS` preserves registration order.

**Filesystem prefix for testability.** `AX_ROOT` (`lib/core.sh`) is a path
prefix, empty in production. Checks that read system files resolve them through
`axpath()` (e.g. `axpath /etc/login.defs`). Setting
`AUDITXS_ROOT_PREFIX=/some/fixture` makes a check read from a fixture tree
instead of the real system — this is how `tests/check_test.sh` exercises real
`audit_*` logic without touching the host.

---

## 4. The check API — how a check works

A check is ~15–30 lines in a `checks/*.sh` file. Files are numbered by category
(`20-ssh.sh`, `40-accounts.sh`, …) and load in that order.

### 4.1 Anatomy

```bash
# 1) Register: <id> <category> <severity> <profiles> <title>
register_check "SSH-001" "SSH" "critical" "server,workstation" \
    "SSH root login is disabled"

# 2) Metadata: the transparency contract (desc/fix/revert) + framework tags
set_meta SSH-001 desc   "What is checked and why…"
set_meta SSH-001 fix    "What the automatic fix changes…"
set_meta SSH-001 revert "How it is reverted…"
set_meta SSH-001 cis    "5.1.20"      # optional CIS Benchmark reference
set_meta SSH-001 level  "1"           # optional CIS level (1 or 2)
set_meta SSH-001 nist   "PR.AA-01"    # optional NIST CSF 2.0 mapping

# 3) Audit function — READ ONLY. Name: audit_<ID with '-' → '_'>
audit_SSH_001() {
    ssh_installed || { DETAIL="OpenSSH server is not installed"; return 3; }  # SKIP
    local v; v=$(sshd_effective permitrootlogin)
    [ "$v" = no ] && { DETAIL="PermitRootLogin no"; return 0; }               # PASS
    DETAIL="PermitRootLogin is '$v'"; return 1                                # FAIL
}

# 4) Fix function (optional) — name: fix_<ID>. Only runs after consent.
fix_SSH_001() { sshd_set PermitRootLogin no && sshd_apply; }
```

### 4.2 Return-code convention (`status_str` in `registry.sh`)

| return | status | meaning |
|:------:|:------:|---------|
| `0` | **PASS** | control is in place |
| `1` | **FAIL** | control is missing; if a `fix_*` exists it is offered |
| `2` | **WARN** | needs human judgement; never auto-fixed |
| `3` | **SKIP** | not applicable (software absent, wrong profile) |

Set the module-global `DETAIL` string to explain the result; it appears in the
console, reports and GUIs. A check with no `fix_*` is a **manual** check and is
never applied automatically.

### 4.3 Rules for check authors

- **Audit reads only.** No writes, no service restarts, no package changes.
- **Resolve system paths with `axpath`** so the check is fixture-testable.
- **Skip cleanly** when the relevant software is absent (`return 3`).
- **Fixes go through the snapshot helpers** (§6) and validate-or-restore for
  daemons. Use the shared helpers in `fixlib.sh` where possible.
- **Add fixture tests** in `tests/check_test.sh` for non-trivial logic.
- Regenerate the catalogue afterwards: `./auditxs list --markdown > docs/CHECKS.md`.

---

## 5. Core library reference

| File | Provides |
|------|----------|
| `core.sh` | `AUDITXS_VERSION` (read from `VERSION`), colour vars, `say/info/ok/warn/err/die/debug`, `log`, `confirm`, `require_root`, `have`, `has_systemd`, `svc_active/enabled/enable`, `unit_exists`, `xrun`/`xrun_q` (dry-run-aware command runner), `write_file`, `AX_ROOT`/`axpath` |
| `errors.sh` | The `AXnnnn` catalogue, `ax_error`/`ax_die`, `cmd_errors` (§8) |
| `distro.sh` | `detect_distro` (sets `DISTRO_ID/NAME/FAMILY/VERSION`, `PKG`), `pkg_installed`, `pkg_install` |
| `registry.sh` | `register_check`, `set_meta`, `run_audit`, `cmd_harden`, `has_fix`, `compute_score`, `status_str`, `sev_weight`, `domain_of`, `nist_of`, `cis_of`, framework/domain maps, filters (`selected`, `check_applies`) |
| `backup.sh` | `snapshot_begin_lazy`/`snapshot_finish`, `track_file`, `record_mode`/`record_sysctl`/`record_service_state`, `manifest_add`, `record_action`, `rollback_snapshot`, `latest_snapshot`, `cmd_snapshots`, `emergency_restore_file` |
| `fixlib.sh` | `audit_sysctl_group`/`fix_sysctl_group`, `sshd_effective/set/apply`, `ssh_installed`, `ssh_in_use`, `disable_unit`/`enable_unit`, `set_logindefs`, `local_filesystems` |
| `report.sh` | `results_text/tsv/json/html`, `save_reports`, `cmd_diff`, `diff_current_against`, `json_escape`, `html_escape` |
| `cve.sh` | `cve_scan`, `cve_banner`, `cmd_cve` (Debian debsecan, Fedora `dnf updateinfo`, openSUSE `zypper patches`) |
| `tools.sh` | `cmd_tools` (status/install/scan/vpn), tool metadata, per-tool post-install |
| `fleet.sh` | `cmd_fleet` and its per-host SSH runner (§9) |
| `maintenance.sh` | `cmd_doctor`, `cmd_baseline`, `cmd_schedule` |

The distribution abstraction is the reason one codebase spans Debian/Ubuntu/Pop,
Arch, Fedora/RHEL and openSUSE: `DISTRO_FAMILY` is one of `debian`/`arch`/
`redhat`/`suse`, and `PKG` is `apt`/`pacman`/`dnf`/`zypper`. Branch on
`DISTRO_FAMILY`, never on a specific distro name.

---

## 6. The snapshot / rollback engine

`lib/backup.sh` is the safety net that makes hardening reversible.

- **`snapshot_begin_lazy`** creates `/var/lib/auditxs/snapshots/<timestamp>/`
  and begins a manifest. Called lazily on the first change of a `harden` run,
  so a run that changes nothing leaves no empty snapshot.
- **`track_file <path>`** copies the current file into the snapshot and records
  a `file` (or `file_created`) action.
- **`record_mode` / `record_sysctl` / `record_service_state`** capture the
  previous permission / sysctl value / service state before a change.
- **`manifest_add <type> <target> <prev> <new>`** appends a tab-separated row to
  `<snapshot>/manifest.tsv`. Every recorded change also lands in the global
  append-only ledger `/var/lib/auditxs/changes.log`.
- **`snapshot_finish`** closes the run and tells the user where the manifest is.
- **`rollback_snapshot <id|latest>`** (the `rollback` command) replays the
  manifest **in reverse order** (`tac`), restoring files, modes, sysctls and
  services, re-validating daemons, and optionally removing packages the run
  installed.

**Invariant:** if `manifest_add` cannot write, the change must not proceed
(reversibility comes first — see error `AX4002`). When you add a new kind of
mutation, add a matching `record_*` and a rollback case for its manifest type.

Manifest row format: `seq  check  type  target  prev  new`.

---

## 7. Interfaces and profile gating

All five interfaces are thin front-ends over the same CLI — every action is an
`auditxs` command you could type.

| Interface | File | Notes |
|-----------|------|-------|
| CLI | `auditxs` | the canonical surface; everything else calls it |
| Terminal UI | `gui/auditxs-tui.sh` | whiptail/dialog; the interactive interface for servers (works over SSH) |
| Web UI | `gui/auditxs-web.py` | Python stdlib only; localhost bind, ephemeral token, CSRF header, strict CSP |
| Qt app | `gui/auditxs-qt.py` + `auditxs.qml` | PySide6; frameless window with custom min/max/move/resize chrome |
| zenity | `gui/auditxs-gui` | GTK dialogs; prefers the Qt app when PySide6 is present |

**Profile gating.** The `PROFILE` (server|workstation, from
`/etc/auditxs/auditxs.conf` or `--profile`) decides both which checks apply and
which interfaces are allowed. Servers are text-only: `web`/`qt`/`auditxs-gui`
call `require_workstation_interface` and refuse on the server profile, steering
the user to `auditxs tui`. When adding a graphical feature, gate it the same way.

**Elevation model.** The zenity and Qt GUIs run **unprivileged** and elevate
each privileged action with `pkexec` (see `_elevate` in `auditxs-qt.py` and
`elevate` in `auditxs-gui`), so the window displays on X11 and Wayland. The web
server runs as root (localhost only). The CLI uses `require_root` per command.

---

## 8. The error-code system

`lib/errors.sh` is the single source of truth for operational errors.

- Every recoverable failure reports a stable **`AXnnnn`** number, grouped by
  area: `AX1xxx` environment, `AX2xxx` audit, `AX3xxx` harden, `AX4xxx`
  snapshot/rollback, `AX5xxx` tools, `AX6xxx` fleet/SSH, `AX7xxx` reporting,
  `AX9xxx` internal.
- **`ax_error <CODE> [context…]`** prints the number, a one-line *why* and
  *fix*, plus the context, to stderr; logs it; appends to the ledger
  `/var/lib/auditxs/errors.log`; and returns 1. **`ax_die`** does that then
  exits 1.
- **`auditxs errors`** browses the catalogue; `auditxs errors AX6002` explains
  one; `auditxs errors ssh` searches; `auditxs errors log` shows recent
  occurrences on this host.
- **`docs/ERRORS.md` is generated**: `./auditxs errors --markdown > docs/ERRORS.md`.

### Adding an error code

1. Add one `_ax_def AXNNNN "title" "why" "fix"` line in the right numeric group
   in `lib/errors.sh` (this also appends to `AX_ERR_CODES` for ordering).
2. Call `ax_error AXNNNN "key=value context"` at the failure site.
3. Regenerate `docs/ERRORS.md`.

Codes are an API — never renumber or repurpose an existing code; add a new one.

---

## 9. Fleet mode internals

`lib/fleet.sh` audits many hosts over SSH. It is **read-only by design** — it
only ever runs `auditxs audit --format json` remotely and never hardens over
SSH. Apply fixes on each host after reviewing its report.

- **Auth:** key auth is preferred (`--key`, or the SSH agent). Password auth
  (`--ask-pass`) reads the password once and passes it to `sshpass -e` via the
  environment, never on the command line (so it never appears in `ps`); the
  variable is unset immediately after the run. sshpass-missing ⇒ `AX6004`.
- **Host keys:** `StrictHostKeyChecking=accept-new` by default (trust-on-first-
  use, refuses *changed* keys — MITM protection). `--strict-host-key` requires a
  pre-known key; `--insecure-host-key` disables checking (warned).
- **Per host:** wrap `ssh` in `timeout`; classify the outcome into a specific
  error code by inspecting the exit status and stderr — `255`+"permission
  denied" ⇒ `AX6002`, "host key verification failed" ⇒ `AX6003`, "command not
  found" ⇒ `AX6005`, timeout ⇒ `AX6007`, no JSON ⇒ `AX6006`, otherwise
  unreachable ⇒ `AX6001`. Each host's JSON is saved under
  `/var/lib/auditxs/reports/fleet/<ts>/`.
- **Exit code:** `2` if any host could not be audited, `1` if all reachable but
  some have failing checks, `0` if all clean — CI/monitoring friendly.

Remote hosts must have AuditXS installed; fleet never pushes code. The summary
JSON is parsed with `grep` (no hard Python dependency in the core path).

### The aggregated overview dashboard (v0.11)

Every fleet run also writes `<outdir>/index.html`, an aggregated Material
dashboard for the whole run. The moving parts:

- **`ov[]` records.** `_fleet_row` has a dual role: it appends the aligned
  console table row *and* a TAB-separated structured record to `ov[]` —
  `host \t state \t pass \t fail \t warn \t score \t filename-stem` (the stem
  is the host sanitized `[^A-Za-z0-9._-] → _`, same as the saved report
  files). Both `rows[]` and `ov[]` are `local` to `cmd_fleet` and mutated from
  `_fleet_one`/`_fleet_row` via bash dynamic scoping. Error outcomes
  (UNREACHABLE, AUTHFAIL, …) are records too — the dashboard shows them, it
  does not hide them.
- **`_fleet_overview_html`** is a *pure* generator: it reads `ov[]` and
  `$outdir` from the caller's scope and writes HTML to stdout. It computes the
  clean/findings/errored host counts and the fleet-average score (numeric
  scores only), then renders one table row per record. Links to
  `<stem>.json`/`<stem>.html` are **relative** and only emitted when the file
  actually exists, so the run directory is self-contained and can be archived
  or copied whole. All host-derived text goes through `html_escape`.

**Coding workflow when you touch the dashboard:**

1. Change the record format only in `_fleet_row`, and update every consumer
   (`_fleet_overview_html` is currently the only one). Keep the record
   TAB-separated — host names can contain almost anything else.
2. The generator must stay pure (no SSH, no globals written) — that is what
   lets `tests/unit.sh` cover it by fabricating `ov[]` + a temp `$outdir` and
   grepping the output ("fleet HTML overview" test block). Extend those tests
   with every new column or aggregate you add.
3. Keep the page self-contained (inline CSS, no external assets, relative
   links) and theme-aware (the `prefers-color-scheme: dark` block), matching
   `results_html` in `lib/report.sh` — the two share the visual language and
   the branded footer.
4. Run the gate: `bash -n lib/fleet.sh && shellcheck -S warning lib/fleet.sh
   && bash tests/unit.sh`.

---

## 10. Debugging

- **`--debug`** (or `AUDITXS_DEBUG=1`) turns on `debug()` output: per-check
  status, return code, timing and the first chars of `DETAIL`, to stderr and the
  log.
- **`--dry-run`** with `harden` prints every intended command (`xrun` shows
  `[dry-run] would run: …`) and file write without changing anything.
- **Logs:** `/var/log/auditxs/auditxs-<date>.log` (root) or
  `~/.local/state/auditxs/…` (non-root). Errors also go to
  `/var/lib/auditxs/errors.log`.
- **Fixture debugging:** run a single check against a fixture tree —
  `AUDITXS_ROOT_PREFIX=/path/to/fixture` plus the check's `audit_*` function (see
  `tests/check_test.sh` for the harness).
- **Syntax first:** `bash -n <file>` catches most Bash mistakes before running.
- **Doctor:** `auditxs doctor` diagnoses tooling, config, snapshot integrity,
  the scheduler and now the available interfaces.

---

## 11. Testing

| Suite | Command | What it covers | Safe on your machine? |
|-------|---------|----------------|:---------------------:|
| Unit | `bash tests/unit.sh` | pure functions (escaping, scoring, parsing, helpers) | yes |
| Check fixtures | `bash tests/check_test.sh` | real `audit_*` logic against fixture trees via `AX_ROOT` | yes |
| Web UI | `bash tests/web_test.sh` | token auth, CSRF, loopback binding, JSON routes | yes |
| Qt/QML | `python3 tests/qml_test.py` | loads `auditxs.qml` offscreen, drives window controls (skips without PySide6) | yes |
| Qt data layer | `python3 gui/auditxs-qt.py --selftest` | Qt-free backend + the pkexec `_elevate` decision | yes |
| Smoke (e2e) | `bash tests/smoke.sh` | install + `audit`/`harden --dry-run` in a container | **containers only** |

`tests/smoke.sh` actually changes a system, so run it only in disposable
containers (that is what CI does across five distros). Everything else is safe
to run locally and in CI.

**When you add code, add a test.** New pure helper ⇒ `unit.sh`. New/*changed*
check logic ⇒ a fixture case in `check_test.sh`. New error code ⇒ it appears in
the generated `docs/ERRORS.md` (diff it). Keep it green before you push.

---

## 12. Coding standards

- **Bash 4+**, portable across the four package families. Prefer POSIX-ish
  constructs; use Bash arrays/associative arrays (they are why the registry is
  clean).
- **ShellCheck clean at `-S warning`.** The repo's intentional suppressions are
  in `.shellcheckrc` (dynamic sourcing, deliberate word-splitting, compact
  status expressions). Do not add blanket `# shellcheck disable` lines — justify
  each one.
- **Quote expansions**; branch on `DISTRO_FAMILY`, not distro names; resolve
  system paths through `axpath` in checks.
- **User-facing text** goes through `say/info/ok/warn/err`; never `echo` raw
  colour codes. Errors go through `ax_error`.
- **Match the surrounding style** — comment density, naming (`audit_<ID>` /
  `fix_<ID>`, `cmd_<subcommand>`, `_private_helper`), and the nala-style box UI.
- CI enforces `bash -n` + ShellCheck on `auditxs`, `setup.sh`, `uninstall.sh`,
  the GUIs, `scripts/*.sh`, `lib/*.sh`, `checks/*.sh`.

---

## 13. Versioning & the release process

**Single source of truth: the root `VERSION` file.** `lib/core.sh` reads it,
`packaging/build-deb.sh` reads it, git tags mirror it. Never hard-code a version
elsewhere. Semantic versioning: `MAJOR.MINOR.PATCH`.

To cut a release:

```bash
# 1. Bump the version and note what changed
echo "0.8.1" > VERSION
$EDITOR docs/ROADMAP.md          # add a "Shipped in vX.Y.Z" line
$EDITOR CHANGELOG.md             # add the release notes
./auditxs list --markdown > docs/CHECKS.md   # if checks changed
./auditxs errors --markdown > docs/ERRORS.md # if error codes changed
python3 scripts/build-site.py    # regenerate the HTML docs site + landing page
                                 # (docs/*.html, docs/index.html, index.html —
                                 #  published at https://auditxs.digitalxs.ca)

# 2. Verify + build + checksum locally (also runs the test gate)
./scripts/release.sh             # add --sign to GPG-sign, --tag to tag locally

# 3. Commit, tag, push the tag → triggers the Release workflow
git add -A && git commit -m "Release v0.8.1"
git tag -a v0.8.1 -m "AuditXS v0.8.1"
git push origin HEAD
git push origin v0.8.1
```

Pushing a `v*` tag runs `.github/workflows/release.yml`, which on a clean
runner: verifies the tag equals `VERSION`, runs the lint/test gate, builds the
`.deb`, writes `SHA256SUMS`, **GPG-signs the checksums when the
`GPG_PRIVATE_KEY`/`GPG_PASSPHRASE` repo secrets are set** (otherwise ships
unsigned), and publishes a GitHub Release with the `.deb`, `SHA256SUMS`,
signature and man page attached.

**Users verify a download with** `sha256sum -c SHA256SUMS` and, when signed,
`gpg --verify SHA256SUMS.asc SHA256SUMS`.

To enable signing, add repo secrets (Settings → Secrets and variables →
Actions): `GPG_PRIVATE_KEY` (`gpg --armor --export-secret-keys KEYID`) and
`GPG_PASSPHRASE`.

---

## 14. Working with GitHub on this project

**Branches.** `main` is the release line and is protected by CI. Do feature work
on a topic branch and open a pull request.

```bash
git checkout -b feature/short-description
# … commit …
git push -u origin feature/short-description
```

**Commits.** Imperative subject, a body that says *why*, wrap ~72 cols. Keep a
change and its tests/docs in the same commit where practical.

**Pull requests.** CI (`ci.yml`) must be green: lint, unit/check/web/qt tests,
`.deb` build, and the five-distro smoke matrix. In the PR body describe the
change, how you verified it, and any user-facing/behaviour notes. If a PR
template exists, fill its sections.

**CI overview (`.github/workflows/ci.yml`), runs on push to `main` and every PR:**

- **lint** — `bash -n` + `shellcheck -S warning` over the whole shell surface.
- **unit** — `unit.sh`, `check_test.sh`, `web_test.sh`, the Qt selftest, and the
  offscreen `qml_test.py` (installs PySide6 + minimal GL libs).
- **package** — builds the `.deb` and installs/smoke-tests it in a `debian:stable`
  container.
- **smoke matrix** — `smoke.sh` in `debian:stable`, `ubuntu:24.04`,
  `fedora:latest`, `archlinux:latest`, `opensuse/leap:15.6`.

**Releases** are tag-driven (§13). Never edit a published release's artifacts by
hand — bump `VERSION` and cut a new tag.

**Issues / error reports.** Ask reporters for the `AXnnnn` code and a `--debug`
trace; the code points straight at the failure class in `docs/ERRORS.md`.

---

## 15. Maintenance runbook

- **A check misfires on a distro.** Reproduce with a fixture
  (`AUDITXS_ROOT_PREFIX`), fix the `audit_*`/`fix_*`, add the fixture case to
  `check_test.sh`, regenerate `docs/CHECKS.md`.
- **A new distro release changes defaults.** Update the relevant check and, if
  needed, `detect_distro`. Add it to the smoke matrix if it is a new family.
- **Add a security tool.** Extend `_tool_pkg`/`_tool_present`/`_install_post` and
  the status/scan lists in `lib/tools.sh`; mirror the choice in the TUI and
  zenity tool menus.
- **CVE source changes.** `lib/cve.sh` is per-family; keep the parser tolerant
  and never let a CVE lookup mutate the system.
- **State growth.** Snapshots and reports accumulate under `/var/lib/auditxs`.
  `auditxs doctor` reports the size; document rotation for operators.
- **Dependency drift.** ShellCheck, PySide6 and container base images move; keep
  CI pinned where it matters and green everywhere.
- **Keep docs generated.** `docs/CHECKS.md` and `docs/ERRORS.md` are generated —
  regenerate them in the same commit that changes their sources.

---

## 16. Security model & threat considerations

AuditXS runs with root and edits security-sensitive configuration, so its own
safety matters as much as its findings.

- **Least privilege at the edges.** GUIs run unprivileged and elevate per action
  via `pkexec`; the web UI binds loopback only, requires an ephemeral token and a
  CSRF header, sets a strict CSP, and calls subprocesses argv-only (never a
  shell string).
- **No remote code execution by AuditXS.** Third-party installers
  (CrowdSec/OSSEC/osquery/Trivy) are shown as official signed-repo steps, never
  piped to a shell. Fleet mode pushes no code and only runs a read-only audit.
- **Secrets.** Never log passwords or keys. Fleet password auth uses `sshpass
  -e` (environment, not argv) and clears `SSHPASS` after use.
- **Supply chain.** Releases ship `SHA256SUMS` and (when configured) a detached
  GPG signature; the `VERSION`↔tag check prevents mislabelled artifacts.
- **Fail safe.** Daemon changes are validated (`sshd -t`, `nginx -t`) and
  auto-restored on failure; the firewall step has an SSH lockout guard; every
  change is reversible via the snapshot engine.
- **Input from the system is untrusted.** Treat file contents, command output
  and remote responses defensively; quote and validate.

When in doubt, choose the option that is more transparent, more reversible, and
less privileged — in that order.

---

*Part of [AuditXS](README.md) by [DigitalXS](https://digitalxs.ca). See also
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/CHECKS.md](docs/CHECKS.md),
[docs/ERRORS.md](docs/ERRORS.md) and [docs/SECURITY-GUIDE.md](docs/SECURITY-GUIDE.md).*
