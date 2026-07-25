#!/usr/bin/env bash
#
# AuditXS unit tests — exercise the pure engine functions without touching
# the system. Safe to run anywhere, as any user. Exits non-zero on failure.
#
set -u

cd "$(dirname "$0")/.." || exit 1

PASS=0
FAILED=0

t() { # t <description> <expected> <actual>
    if [ "$2" = "$3" ]; then
        PASS=$((PASS + 1))
    else
        FAILED=$((FAILED + 1))
        echo "FAIL: $1" >&2
        echo "      expected: '$2'" >&2
        echo "      actual:   '$3'" >&2
    fi
}

tt() { # tt <description> <expected yes|no> <command...> — test exit status
    local desc=$1 want=$2 got
    shift 2
    if "$@"; then got=yes; else got=no; fi
    t "$desc" "$want" "$got"
}

# Load the engine quietly (function definitions + registration only).
QUIET=1
. lib/core.sh
. lib/errors.sh
. lib/waivers.sh
. lib/distro.sh
. lib/backup.sh
. lib/registry.sh
. lib/report.sh
. lib/fixlib.sh
. lib/maintenance.sh
. lib/cve.sh
. lib/tools.sh
. lib/update.sh
. lib/fleet.sh
for c in checks/*.sh; do . "$c"; done

TMPD=$(mktemp -d)
trap 'rm -rf "$TMPD"' EXIT

# ------------------------------------------------------------- core/escape
t "json_escape quotes"      '\"hi\"'      "$(json_escape '"hi"')"
t "json_escape backslash"   'a\\b'        "$(json_escape 'a\b')"
t "json_escape newline"     'a\nb'        "$(json_escape "$(printf 'a\nb')")"
t "json_escape tab"         'a\tb'        "$(json_escape "$(printf 'a\tb')")"
t "html_escape"             '&amp;&lt;&gt;' "$(html_escape '&<>')"
t "html_escape plain"       'abc'         "$(html_escape 'abc')"

# --------------------------------------------------------------- registry
t "fn_name audit"           'audit_SSH_001' "$(fn_name SSH-001 audit)"
t "fn_name fix"             'fix_FW_002'    "$(fn_name FW-002 fix)"
t "sev_weight critical"     '4' "$(sev_weight critical)"
t "sev_weight low"          '1' "$(sev_weight low)"
t "status_str 0"            'PASS' "$(status_str 0)"
t "status_str 2"            'WARN' "$(status_str 2)"
t "status_str 3"            'SKIP' "$(status_str 3)"
tt "has_fix SSH-001 yes"    yes has_fix SSH-001
tt "has_fix ACC-001 no"     no  has_fix ACC-001
tt "registry has 80+ checks" yes test "${#CHECK_IDS[@]}" -ge 80

PROFILE=server
tt "SSH-004 applies to server"          yes check_applies SSH-004
PROFILE=workstation
tt "SSH-004 not for workstation"        no  check_applies SSH-004
tt "SSH-001 applies to workstation"     yes check_applies SSH-001

FILTER_CHECKS=" SSH-001"; FILTER_CATEGORY=""; FILTER_DOMAIN=""
tt "selected honours --check (match)"    yes selected SSH-001
tt "selected honours --check (no match)" no  selected SSH-002
FILTER_CHECKS=""; FILTER_CATEGORY="ssh"
tt "selected honours --category"         yes selected SSH-001
tt "selected rejects other category"     no  selected FW-001
FILTER_CATEGORY=""; FILTER_DOMAIN="database"
tt "selected honours --domain (prefix, case-insensitive)" yes selected DB-001
tt "selected --domain rejects others"    no  selected SSH-001
FILTER_DOMAIN=""

# --------------------------------------------------------- domains & NIST
t "domain of Database"      'Database Hardening'    "$(domain_of Database)"
t "domain of SSH"           'Server Hardening'      "$(domain_of SSH)"
t "domain of Kernel"        'OS Hardening'          "$(domain_of Kernel)"
t "domain of Mail"          'Application Hardening' "$(domain_of Mail)"
t "domain of DNS"           'Network Security'      "$(domain_of DNS)"
t "domain of PHP"           'Application Hardening' "$(domain_of PHP)"
t "domain fallback"         'Other'                 "$(domain_of Nonsense)"
# nala-style helpers strip ANSI/glyphs correctly
t "_vlen strips ansi"       '5' "$(NALA_W=68; _vlen "$(printf '\033[31mhello\033[0m')")"
t "_repeat n"               '---' "$(_repeat 3 '-')"
# CVE / tools entry points are defined
defined() { declare -F "$1" >/dev/null; }
tt "cve_scan is defined"    yes defined cve_scan
tt "cmd_tools is defined"   yes defined cmd_tools
tt "nist_of SSH-001 non-empty"  yes test -n "$(nist_of SSH-001)"
t "nist_of override (PRV-002)"  'PR.AA-03' "$(nist_of PRV-002)"

# CIS Benchmark id + Level
t "cis_of SSH-001"          '5.1.20' "$(cis_of SSH-001)"
t "cis_of unmapped empty"   ''       "$(cis_of PRV-003)"
t "level_of default 1"      '1'      "$(level_of SSH-001)"
t "level_of L2 override"    '2'      "$(level_of SSH-005)"
t "level_of auditd is L2"   '2'      "$(level_of LOG-002)"

# -------------------------------------------------------------- perm math
tt "perm_exceeds 644>640"   yes perm_exceeds 644 640
tt "perm_exceeds 600<640"   no  perm_exceeds 600 640
tt "perm_exceeds 640=640"   no  perm_exceeds 640 640
tt "perm_exceeds ignores special bits" no perm_exceeds 1777 777

# ------------------------------------------------------------ report parse
cat > "$TMPD/old.json" <<'EOF'
{
  "date": "2026-01-01T00:00:00+00:00",
  "summary": { "pass": 1, "fail": 1, "warn": 0, "skip": 0, "score": "40" },
  "results": [
    { "id": "AAA-001", "category": "X", "severity": "high", "status": "PASS", "fixable": true, "title": "a", "detail": "" },
    { "id": "BBB-001", "category": "X", "severity": "high", "status": "FAIL", "fixable": true, "title": "b", "detail": "" }
  ]
}
EOF
cat > "$TMPD/new.json" <<'EOF'
{
  "date": "2026-02-01T00:00:00+00:00",
  "summary": { "pass": 1, "fail": 1, "warn": 0, "skip": 0, "score": "60" },
  "results": [
    { "id": "AAA-001", "category": "X", "severity": "high", "status": "FAIL", "fixable": true, "title": "a", "detail": "" },
    { "id": "BBB-001", "category": "X", "severity": "high", "status": "PASS", "fixable": true, "title": "b", "detail": "" }
  ]
}
EOF
t "parse_report_results count" '2' "$(parse_report_results "$TMPD/old.json" | grep -c .)"
t "parse_report_results value" 'AAA-001 PASS' "$(parse_report_results "$TMPD/old.json" | head -n1)"
t "parse_report_field score"   '40' "$(parse_report_field "$TMPD/old.json" score)"
t "parse_report_field date"    '2026-01-01T00:00:00+00:00' "$(parse_report_field "$TMPD/old.json" date)"
t "_status_rank FAIL"          '2' "$(_status_rank FAIL)"
t "_status_rank PASS"          '0' "$(_status_rank PASS)"

# ----------------------------------------------------------------- diff
out=$(cmd_diff "$TMPD/old.json" "$TMPD/new.json"); rc=$?
t "diff detects regression (exit)"   '1' "$rc"
tt "diff lists AAA-001 regression"   yes grep -q 'AAA-001: PASS → FAIL' <<< "$out"
tt "diff lists BBB-001 improvement"  yes grep -q 'BBB-001: FAIL → PASS' <<< "$out"
out=$(cmd_diff "$TMPD/old.json" "$TMPD/old.json"); rc=$?
t "diff identical reports (exit 0)"  '0' "$rc"
tt "diff identical says none"        yes grep -q 'No regressions' <<< "$out"

# ---- error catalogue (lib/errors.sh) -------------------------------------
AX_ERROR_LEDGER="$TMPD/errors.log"     # keep the test side-effect-free
t "error catalogue AX6002 title"     "SSH authentication failed" "${AX_ERR_TITLE[AX6002]:-}"
t "error catalogue is populated"     yes "$([ ${#AX_ERR_CODES[@]} -ge 20 ] && echo yes || echo no)"
errout=$(ax_error AXZZZZ 2>&1)
tt "unknown code maps to AX9001"     yes grep -q 'AX9001' <<< "$errout"
tt "ax_error returns non-zero"       no  ax_error AX9000 2>/dev/null
mdrows=$(cmd_errors --markdown | grep -c '| `AX')
t "errors --markdown emits rows"     yes "$([ "$mdrows" -ge 20 ] && echo yes || echo no)"
tt "ax_error wrote to the ledger"    yes test -s "$TMPD/errors.log"

# ---- waivers (lib/waivers.sh) --------------------------------------------
AX_WAIVERS_FILE="$TMPD/waivers.conf"
printf 'SSH-001 | - | accepted, compensating control\nFW-002 | 2000-01-01 | expired waiver\n' > "$AX_WAIVERS_FILE"
WAIVERS_LOADED=0; unset WAIVER_REASON WAIVER_EXPIRY; declare -A WAIVER_REASON WAIVER_EXPIRY
tt "is_waived active (no expiry)"    yes is_waived SSH-001
tt "is_waived expired waiver"        no  is_waived FW-002
tt "is_waived unwaived check"        no  is_waived ACC-001
t  "waiver_reason text"              "accepted, compensating control" "$(waiver_reason SSH-001)"

# ---- fleet JSON summary parsing (lib/fleet.sh) ---------------------------
fjson='{"summary": { "pass": 12, "fail": 3, "warn": 2, "skip": 5, "score": "82" }, "results": []}'
t "_fleet_field pass"                "12" "$(_fleet_field "$fjson" pass)"
t "_fleet_field fail"                "3"  "$(_fleet_field "$fjson" fail)"
t "_fleet_field warn"                "2"  "$(_fleet_field "$fjson" warn)"
t "_fleet_score"                     "82" "$(_fleet_score "$fjson")"

# ---- fleet HTML overview (lib/fleet.sh) ----------------------------------
outdir="$TMPD/fleet"; mkdir -p "$outdir"
printf '{}' > "$outdir/web01.json"; printf '<html></html>' > "$outdir/web01.html"
ov=(
    "$(printf 'web01\tOK\t41\t0\t3\t96\tweb01')"
    "$(printf 'db01\tFINDINGS\t35\t6\t4\t78\tdb01')"
    "$(printf 'bad<host>\tUNREACHABLE\t-\t-\t-\t-\tbad_host_')"
)
fov=$(_fleet_overview_html)
tt "overview counts hosts"      yes grep -q '3 host(s) audited'      <<<"$fov"
tt "overview avg score"         yes grep -q '<b>87</b>'              <<<"$fov"
tt "overview errored chip"      yes grep -q '1 unreachable/errored'  <<<"$fov"
tt "overview links saved html"  yes grep -q 'href="web01.html"'      <<<"$fov"
tt "overview no link when absent" no grep -q 'href="db01.html"'      <<<"$fov"
tt "overview escapes hostnames" yes grep -q 'bad&lt;host&gt;'        <<<"$fov"
unset outdir ov fov

# ---- progress engine (lib/core.sh) ---------------------------------------
AUDITXS_PROGRESS_FILE="$TMPD/prog"
progress_begin 4
progress_step AAA-001 2>/dev/null
read -r _pct _d _t _id < "$TMPD/prog"
t "progress 1/4 writes 25%"       "25 1 4 AAA-001" "$_pct $_d $_t $_id"
progress_step BBB 2>/dev/null; progress_step CCC 2>/dev/null; progress_step DDD 2>/dev/null
read -r _pct _d _t _id < "$TMPD/prog"
t "progress 4/4 writes 100%"      "100 4 4 DDD" "$_pct $_d $_t $_id"
progress_end
read -r _pct _d _t _id < "$TMPD/prog"
t "progress_end marks done"       "100 4 4 done" "$_pct $_d $_t $_id"
progress_begin 0 2>/dev/null
tt "progress_begin 0 is a no-op"  yes progress_end
unset AUDITXS_PROGRESS_FILE

# ---- version consistency --------------------------------------------------
# The README must always show the current version (badge + visible text line).
_ver=$(tr -d '[:space:]' < VERSION)
tt "README shows current version text"  yes grep -q "Current version: v${_ver}" README.md
tt "README version badge is current"    yes grep -q "badge/version-${_ver}-" README.md
t  "engine reads the VERSION file"      "$_ver" "$AUDITXS_VERSION"

# ---- HTML report interactivity (lib/report.sh) ---------------------------
# Fabricate a tiny result set: SSH-001 has an auto fix (FAIL → "Fix it"),
# SSH-003 WARN → "How to fix", SSH-002 PASS → no button at all.
RESULT_STATUS=(); RESULT_DETAIL=()
RESULT_STATUS[SSH-001]=FAIL; RESULT_DETAIL[SSH-001]="root login permitted"
RESULT_STATUS[SSH-002]=PASS; RESULT_DETAIL[SSH-002]=""
RESULT_STATUS[SSH-003]=WARN; RESULT_DETAIL[SSH-003]="check manually"
SCORE=50 N_PASS=1 N_FAIL=1 N_WARN=1 N_SKIP=0 PROFILE=server
rhtml=$(results_html)
tt "report findings toggle present"   yes grep -q 'id="onlyfind"' <<<"$rhtml"
tt "report rows carry data-st"        yes grep -q '<tr data-st="PASS">' <<<"$rhtml"
tt "report Fix-it on fixable FAIL"    yes grep -q 'data-cmd="sudo auditxs harden --check SSH-001">Fix it' <<<"$rhtml"
tt "report How-to-fix on WARN"        yes grep -q 'data-cmd="auditxs explain SSH-003">How to fix' <<<"$rhtml"
tt "report no button on PASS"         no  grep -q 'check SSH-002' <<<"$rhtml"
tt "report filter script present"     yes grep -q 'applyFilter' <<<"$rhtml"
unset rhtml

# ---- package update command (lib/update.sh) ------------------------------
# _update_apply must build the right, scoped upgrade command per package
# manager. Run in dry-run so nothing executes (xrun prints "would run: …").
# Use scope=all where possible to avoid the apt-security path's pkg_install
# (which would touch the snapshot engine).
t "apt all → apt-get upgrade"    "yes" "$(DRYRUN=1 PKG=apt;    _update_apply all 2>&1 | grep -q 'apt-get -y upgrade' && echo yes || echo no)"
t "dnf security uses --security" "yes" "$(DRYRUN=1 PKG=dnf;    _update_apply security 2>&1 | grep -q -- '--security' && echo yes || echo no)"
t "dnf all omits --security"     "no"  "$(DRYRUN=1 PKG=dnf;    _update_apply all 2>&1 | grep -q -- '--security' && echo yes || echo no)"
t "pacman is always full -Syu"   "yes" "$(DRYRUN=1 PKG=pacman; _update_apply security 2>&1 | grep -q 'pacman -Syu' && echo yes || echo no)"
t "zypper security patches"      "yes" "$(DRYRUN=1 PKG=zypper; _update_apply security 2>&1 | grep -q 'patch --category security' && echo yes || echo no)"
t "unknown pkg mgr → error rc"   "1"   "$(DRYRUN=1 PKG=none;   _update_apply all >/dev/null 2>&1; echo $?)"

# ---- Qt runtime preflight (dispatcher helpers) ---------------------------
# The helpers live in the `auditxs` dispatcher, not a lib; pull just that block.
eval "$(awk '/^# -+ Qt runtime deps/{f=1} f; /^ensure_qt_runtime\(\)/{g=1} g&&/^}/{f=0}' auditxs)"
t "_qt_packages debian"  "python3-pyside6.qtquick qml6-module-qtquick-controls qml6-module-qtquick-layouts qml6-module-qtquick-window" "$(DISTRO_FAMILY=debian _qt_packages)"
t "_qt_packages redhat"  "python3-pyside6" "$(DISTRO_FAMILY=redhat _qt_packages)"
t "_qt_packages arch"    "pyside6"         "$(DISTRO_FAMILY=arch _qt_packages)"
t "_qt_packages suse"    "python3-pyside6" "$(DISTRO_FAMILY=suse _qt_packages)"
t "_qt_packages unknown" ""               "$(DISTRO_FAMILY=unknown _qt_packages)"
# _qt_has_runtime must reflect whether a PySide6 import actually succeeds.
if python3 -c 'import PySide6.QtCore, PySide6.QtGui, PySide6.QtQml' >/dev/null 2>&1; then
    tt "_qt_has_runtime (PySide6 present)" yes _qt_has_runtime
else
    tt "_qt_has_runtime (PySide6 absent)"  no  _qt_has_runtime
fi

echo
echo "unit tests: $PASS passed, $FAILED failed"
[ "$FAILED" -eq 0 ]
