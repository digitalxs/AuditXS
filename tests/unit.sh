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

echo
echo "unit tests: $PASS passed, $FAILED failed"
[ "$FAILED" -eq 0 ]
