#!/usr/bin/env bash
#
# AuditXS — lib/registry.sh
# Check registry and execution engine.
#
# Every check registers itself with an ID, category, severity, applicable
# profiles and title, plus three pieces of metadata that make AuditXS
# transparent:
#   desc   — what is checked and why it matters
#   fix    — exactly what the automatic fix changes on the system
#   revert — how that change is undone
#
# A check provides audit_<ID> (required) and fix_<ID> (optional; checks
# without a fix never change the system). Audit return codes:
#   0 = PASS   1 = FAIL (finding; a fix is offered when the check has one)
#   2 = WARN (manual review)   3 = SKIP
#
# Part of AuditXS — transparent, reversible Linux security auditing.
#

declare -a CHECK_IDS=()
declare -A CHECK_TITLE=() CHECK_CATEGORY=() CHECK_SEVERITY=() CHECK_PROFILES=()
declare -A CHECK_META_DESC=() CHECK_META_FIX=() CHECK_META_REVERT=() CHECK_META_NIST=()
declare -A CHECK_META_CIS=() CHECK_META_LEVEL=()
declare -A RESULT_STATUS=() RESULT_DETAIL=()

# ------------------------------------------------- CIS Benchmark & levels
# Indicative, section-level mapping to the CIS Distribution Independent /
# Debian Linux Benchmark, plus a CIS profile Level (1 = baseline that
# applies broadly with little operational impact; 2 = stricter, defence-in-
# depth, may affect functionality). Checks not listed default to Level 1 and
# no CIS reference. A check may override centrally here or inline with
# 'set_meta <ID> cis "5.1.20"' / 'set_meta <ID> level 2'. These numbers track
# CIS section areas, not a specific benchmark revision — treat as indicative.
declare -A CIS_OF_CHECK=(
    [UPD-001]="1.9" [UPD-002]="1.9"
    [OSH-001]="1.7.1" [OSH-002]="1.1.2"
    [MAC-001]="1.6.1"
    [KRN-001]="1.5.3" [KRN-002]="1.5.1" [KRN-003]="3.3.9" [KRN-004]="3.3.2"
    [KRN-005]="3.3.1" [KRN-006]="3.3.7" [KRN-007]="3.3.4" [KRN-008]="3.2.1"
    [KRN-009]="1.5.1" [KRN-010]="1.4.3"
    [SSH-001]="5.1.20" [SSH-002]="5.1.5" [SSH-003]="5.1.21" [SSH-004]="5.1.9"
    [SSH-005]="5.1.22" [SSH-006]="5.1.10" [SSH-007]="5.1.4"
    [ACC-001]="6.2.9" [ACC-002]="6.2.8" [ACC-003]="5.5.1.1" [ACC-005]="5.5.2"
    [ACC-006]="5.5.5" [ACC-007]="5.4.1"
    [PRV-001]="5.3.4" [PRV-002]="5.3.7"
    [FS-001]="1.1.9" [FS-002]="6.1.10" [FS-003]="6.1.11" [FS-004]="6.1.2"
    [FS-005]="6.2.7" [FS-006]="6.1.13"
    [FW-001]="3.5.1" [FW-002]="3.5.1.1" [FW-003]="3.5.1.2" [FW-004]="3.5.1.3"
    [NET-002]="3.4"
    [SVC-001]="2.3" [SVC-002]="2.1.3" [SVC-003]="2.1.4" [SVC-004]="2.1.2"
    [LOG-001]="6.2.1.1" [LOG-002]="6.3.1" [LOG-003]="6.3.3" [LOG-004]="6.2.3"
    [VULN-001]="1.9"
)
# Level-2 (stricter) checks; everything else defaults to Level 1.
declare -A LEVEL2_CHECK=(
    [SSH-005]=1 [OSH-002]=1 [ACC-006]=1 [KRN-007]=1 [NET-002]=1
    [LOG-002]=1 [LOG-003]=1 [SVC-002]=1 [SVC-003]=1 [SVC-004]=1
    [SEC-003]=1
)
cis_of()   { echo "${CHECK_META_CIS[$1]:-${CIS_OF_CHECK[$1]:-}}"; }
level_of() {
    local id=$1
    if [ -n "${CHECK_META_LEVEL[$id]:-}" ]; then echo "${CHECK_META_LEVEL[$id]}"
    elif [ -n "${LEVEL2_CHECK[$id]:-}" ]; then echo 2
    else echo 1
    fi
}

# ------------------------------------------------- domains & NIST CSF 2.0
# Each category belongs to one assessment domain, so audits and reports can
# be sliced the way security assessments are organised (--domain).
declare -A DOMAIN_OF_CATEGORY=(
    [Updates]="OS Hardening"
    [OS]="OS Hardening"
    [Debian]="OS Hardening"
    [Kernel]="OS Hardening"
    [Filesystem]="OS Hardening"
    [MAC]="OS Hardening"
    [Logging]="OS Hardening"
    [SecurityTools]="OS Hardening"
    [Vulnerabilities]="OS Hardening"
    [SSH]="Server Hardening"
    [Accounts]="Server Hardening"
    [Privileged]="Server Hardening"
    [Firewall]="Network Security"
    [Network]="Network Security"
    [DNS]="Network Security"
    [Services]="Application Hardening"
    [Applications]="Application Hardening"
    [PHP]="Application Hardening"
    [Mail]="Application Hardening"
    [Database]="Database Hardening"
)
domain_of() { echo "${DOMAIN_OF_CATEGORY[$1]:-Other}"; }

# Indicative NIST CSF 2.0 subcategory mapping per category; individual
# checks may override with: set_meta <ID> nist "PR.AA-03"
declare -A NIST_OF_CATEGORY=(
    [Updates]="ID.RA-01, PR.PS-02"
    [OS]="PR.PS-01"
    [Debian]="PR.PS-01, PR.PS-02"
    [Kernel]="PR.PS-01, PR.IR-01"
    [Filesystem]="PR.DS-01, PR.AA-05"
    [MAC]="PR.PS-01, PR.AA-05"
    [Logging]="PR.PS-04, DE.CM-01"
    [SecurityTools]="DE.CM-08, ID.RA-01"
    [Vulnerabilities]="ID.RA-01, DE.CM-08"
    [SSH]="PR.AA-01, PR.AA-03"
    [Accounts]="PR.AA-01, PR.AA-05"
    [Privileged]="PR.AA-05"
    [Firewall]="PR.IR-01"
    [Network]="PR.IR-01, DE.CM-01"
    [DNS]="PR.IR-01, PR.PS-01"
    [Services]="PR.PS-01"
    [Applications]="PR.PS-01"
    [PHP]="PR.PS-01"
    [Mail]="PR.DS-02, PR.AA-05"
    [Database]="PR.DS-01, PR.AA-05"
)
nist_of() {
    local id=$1
    echo "${CHECK_META_NIST[$id]:-${NIST_OF_CATEGORY[${CHECK_CATEGORY[$id]}]:-}}"
}

N_PASS=0 N_FAIL=0 N_WARN=0 N_SKIP=0
SCORE="-"
DETAIL=""

register_check() { # <id> <category> <severity> <profiles> <title>
    local id=$1
    CHECK_IDS+=("$id")
    CHECK_CATEGORY[$id]=$2
    CHECK_SEVERITY[$id]=$3
    CHECK_PROFILES[$id]=$4
    CHECK_TITLE[$id]=$5
}

set_meta() { # <id> desc|fix|revert <text>
    local id=$1 key=$2 val=$3
    case $key in
        desc)   CHECK_META_DESC[$id]=$val ;;
        fix)    CHECK_META_FIX[$id]=$val ;;
        revert) CHECK_META_REVERT[$id]=$val ;;
        nist)   CHECK_META_NIST[$id]=$val ;;
        cis)    CHECK_META_CIS[$id]=$val ;;
        level)  CHECK_META_LEVEL[$id]=$val ;;
    esac
}

fn_name() { local id=${1//-/_}; echo "${2}_${id}"; }
has_fix() { declare -F "$(fn_name "$1" fix)" >/dev/null; }

check_applies() { # <id> — 0 if the check applies to $PROFILE
    case ",${CHECK_PROFILES[$1]}," in
        *",$PROFILE,"*) return 0 ;;
        *)              return 1 ;;
    esac
}

selected() { # <id> — honours --check and --category filters
    local id=$1
    if [ -n "${FILTER_CHECKS:-}" ]; then
        case " $FILTER_CHECKS " in *" $id "*) : ;; *) return 1 ;; esac
    fi
    if [ -n "${FILTER_CATEGORY:-}" ]; then
        [ "${CHECK_CATEGORY[$id],,}" = "${FILTER_CATEGORY,,}" ] || return 1
    fi
    if [ -n "${FILTER_DOMAIN:-}" ]; then
        local d
        d=$(domain_of "${CHECK_CATEGORY[$id]}")
        [[ "${d,,}" == "${FILTER_DOMAIN,,}"* ]] || return 1
    fi
    # --level N: include checks at Level ≤ N (CIS L2 profile includes L1).
    if [ -n "${FILTER_LEVEL:-}" ]; then
        [ "$(level_of "$id")" -le "$FILTER_LEVEL" ] 2>/dev/null || return 1
    fi
    # --framework cis: only checks that carry a CIS reference.
    if [ "${FILTER_FRAMEWORK:-}" = cis ]; then
        [ -n "$(cis_of "$id")" ] || return 1
    fi
    return 0
}

status_str() {
    case $1 in
        0) echo PASS ;; 1) echo FAIL ;; 2) echo WARN ;; 3) echo SKIP ;;
        *) echo WARN ;;
    esac
}

sev_weight() {
    case $1 in critical) echo 4 ;; high) echo 3 ;; medium) echo 2 ;; *) echo 1 ;; esac
}

print_result() { # <id>
    [ "$QUIET" = 1 ] && return 0
    local id=$1 col=""
    local st=${RESULT_STATUS[$id]}
    case $st in
        PASS) col=$GREEN ;;
        FAIL) col=$RED ;;
        WARN) col=$YELLOW ;;
        SKIP) col=$DIM ;;
    esac
    printf '%b\n' "[${col}${st}${RC}] ${BOLD}$id${RC} ${DIM}(${CHECK_SEVERITY[$id]}, ${CHECK_CATEGORY[$id]})${RC} ${CHECK_TITLE[$id]}"
    if [ -n "${RESULT_DETAIL[$id]}" ] && [ "$st" != "PASS" ]; then
        printf '%s\n' "${RESULT_DETAIL[$id]}" | sed "s/^/       /" | head -n 12
    fi
}

print_audit_header() {
    [ "$QUIET" = 1 ] && return 0
    nala_box "AuditXS v$AUDITXS_VERSION  ·  security configuration audit"
    nala_row "Host:    $(hostname 2>/dev/null)"
    nala_row "System:  ${DISTRO_NAME}"
    nala_row "Profile: ${BOLD}${PROFILE}${RC}  ·  $(date '+%F %T')"
    nala_row "${DIM}Audit mode is read-only — nothing on this system is changed.${RC}"
    nala_end
}

run_audit() {
    local id fn rc st _prev_cat=""
    N_PASS=0 N_FAIL=0 N_WARN=0 N_SKIP=0
    AUDIT_DATE=$(date -Is)
    for id in "${CHECK_IDS[@]}"; do
        selected "$id" || continue
        # nala-style section rule when the category changes
        if [ "${CHECK_CATEGORY[$id]}" != "$_prev_cat" ]; then
            _prev_cat=${CHECK_CATEGORY[$id]}
            nala_rule "${_prev_cat} — $(domain_of "$_prev_cat")"
        fi
        if ! check_applies "$id"; then
            RESULT_STATUS[$id]=SKIP
            RESULT_DETAIL[$id]="Not applicable to the '$PROFILE' profile"
            N_SKIP=$((N_SKIP + 1))
            print_result "$id"
            continue
        fi
        DETAIL=""
        fn=$(fn_name "$id" audit)
        local t0 t1
        t0=$(date +%s%3N 2>/dev/null || date +%s)
        if declare -F "$fn" >/dev/null; then
            "$fn"; rc=$?
        else
            rc=3; DETAIL="No audit implementation"
        fi
        t1=$(date +%s%3N 2>/dev/null || date +%s)
        st=$(status_str "$rc")
        debug "$id → $st (rc=$rc, $((t1 - t0))ms) ${DETAIL:0:120}"
        RESULT_STATUS[$id]=$st
        RESULT_DETAIL[$id]=$DETAIL
        case $st in
            PASS) N_PASS=$((N_PASS + 1)) ;;
            FAIL) N_FAIL=$((N_FAIL + 1)) ;;
            WARN) N_WARN=$((N_WARN + 1)) ;;
            SKIP) N_SKIP=$((N_SKIP + 1)) ;;
        esac
        print_result "$id"
    done
    compute_score
}

compute_score() {
    local id got=0 max=0 w
    for id in "${CHECK_IDS[@]}"; do
        case "${RESULT_STATUS[$id]:-}" in
            PASS) w=$(sev_weight "${CHECK_SEVERITY[$id]}"); got=$((got + w)); max=$((max + w)) ;;
            FAIL) w=$(sev_weight "${CHECK_SEVERITY[$id]}"); max=$((max + w)) ;;
        esac
    done
    if [ "$max" -gt 0 ]; then
        SCORE=$(( got * 100 / max ))
    else
        SCORE="-"
    fi
}

print_summary() {
    [ "$QUIET" = 1 ] && return 0
    nala_box "Summary"
    nala_row "Results: ${GREEN}$N_PASS passed${RC} · ${RED}$N_FAIL failed${RC} · ${YELLOW}$N_WARN warnings${RC} · ${DIM}$N_SKIP skipped${RC}"
    nala_row "Hardening score: ${BOLD}$SCORE/100${RC} ${DIM}(severity-weighted, PASS vs FAIL)${RC}"
    if [ "$N_FAIL" -gt 0 ]; then
        nala_row "Next step: ${BOLD}sudo auditxs harden${RC} reviews each failed check with you before changing anything."
    fi
    nala_end
}

# ------------------------------------------------------------ transparency
fold_indent() {
    printf '%s\n' "$1" | fold -s -w 74 | sed 's/^/    /'
}

show_check_details() { # <id>
    local id=$1
    hr
    printf '%b\n' "${BOLD}$id — ${CHECK_TITLE[$id]}${RC}"
    local _cis; _cis=$(cis_of "$id")
    printf '%b\n' "  Category: ${CHECK_CATEGORY[$id]} · Domain: $(domain_of "${CHECK_CATEGORY[$id]}") · Severity: ${CHECK_SEVERITY[$id]} · Profiles: ${CHECK_PROFILES[$id]}"
    printf '%b\n' "  NIST CSF 2.0: $(nist_of "$id")  ·  CIS: ${_cis:-—}  ·  Level: $(level_of "$id")"
    if [ -n "${CHECK_META_DESC[$id]:-}" ]; then
        printf '%b\n' "  ${CYAN}What is checked and why:${RC}"
        fold_indent "${CHECK_META_DESC[$id]}"
    fi
    if has_fix "$id"; then
        printf '%b\n' "  ${CYAN}What the automatic fix changes:${RC}"
        fold_indent "${CHECK_META_FIX[$id]:-—}"
        printf '%b\n' "  ${CYAN}How it is reverted:${RC}"
        fold_indent "${CHECK_META_REVERT[$id]:-All changes are recorded in a snapshot; run 'sudo auditxs rollback <snapshot>' to restore the previous state.}"
    else
        printf '%b\n' "  ${CYAN}Fix:${RC} manual — this check only reports; it never changes your system."
    fi
}

# ----------------------------------------------------------------- harden
cmd_harden() {
    print_audit_header
    run_audit
    print_summary

    local targets=() id
    for id in "${CHECK_IDS[@]}"; do
        [ "${RESULT_STATUS[$id]:-}" = "FAIL" ] || continue
        has_fix "$id" && targets+=("$id")
    done

    say ""
    if [ ${#targets[@]} -eq 0 ]; then
        ok "No automatically fixable findings for profile '$PROFILE'. Review any WARN items manually."
        return 0
    fi

    info "${#targets[@]} failing check(s) have an automatic, reversible fix."
    [ "$DRYRUN" = 1 ] && info "${BOLD}DRY-RUN:${RC} every intended change is shown below, but nothing will be modified."
    say ""

    local applied=0 skipped=0 notdone=0
    for id in "${targets[@]}"; do
        show_check_details "$id"
        printf '%b\n' "  ${CYAN}Current state:${RC}"
        fold_indent "${RESULT_DETAIL[$id]:-—}"
        say ""
        if ! confirm "Apply the fix for $id now?"; then
            info "Skipped $id — nothing changed."
            skipped=$((skipped + 1))
            continue
        fi
        CURRENT_CHECK=$id
        DETAIL=""
        if "$(fn_name "$id" fix)"; then
            if [ "$DRYRUN" = 1 ]; then
                applied=$((applied + 1))
            else
                APPLIED_CHECKS+=("$id")
                DETAIL=""
                if "$(fn_name "$id" audit)"; then
                    ok "$id — fix applied and verified."
                    applied=$((applied + 1))
                else
                    warn "$id — fix applied but verification still fails${DETAIL:+: $DETAIL}"
                    notdone=$((notdone + 1))
                fi
            fi
        else
            warn "$id — fix was not applied${DETAIL:+: $DETAIL}"
            notdone=$((notdone + 1))
        fi
        CURRENT_CHECK=""
    done

    hr
    say "Hardening summary: ${GREEN}$applied applied${RC} · ${DIM}$skipped skipped${RC} · ${YELLOW}$notdone not applied/verified${RC}"
    snapshot_finish
}

# ------------------------------------------------------------- list/explain
cmd_list() { # [--markdown]
    local id fixable
    if [ "${1:-}" = "--markdown" ]; then
        markdown_docs
        return 0
    fi
    printf '%b\n' "${BOLD}AuditXS check catalogue${RC} (${#CHECK_IDS[@]} checks) — details: auditxs explain <ID>"
    hr
    printf '%b\n' "${BOLD}ID        SEVERITY  L  FIX    PROFILES              TITLE${RC}"
    for id in "${CHECK_IDS[@]}"; do
        selected "$id" || continue
        if has_fix "$id"; then fixable="auto"; else fixable="manual"; fi
        printf '%-9s %-9s %-2s %-6s %-21s %s\n' \
            "$id" "${CHECK_SEVERITY[$id]}" "$(level_of "$id")" "$fixable" "${CHECK_PROFILES[$id]}" "${CHECK_TITLE[$id]}"
    done
    hr
    printf '%b\n' "${DIM}Checks marked 'manual' only report — they never change the system.${RC}"
}

cmd_explain() { # <id...>
    local id found=0
    [ $# -eq 0 ] && die "Usage: auditxs explain <CHECK-ID>... (see 'auditxs list')"
    for id in "$@"; do
        id=${id^^}
        if [ -n "${CHECK_TITLE[$id]:-}" ]; then
            show_check_details "$id"
            found=1
        else
            warn "Unknown check ID: $id"
        fi
    done
    [ "$found" = 1 ] && hr
}

markdown_docs() {
    local id cat="" fixable
    echo "# AuditXS check catalogue"
    echo
    echo "Generated from the check registry by \`auditxs list --markdown\` (v$AUDITXS_VERSION)."
    echo
    echo "Legend: checks with an **automatic fix** are only ever applied by"
    echo "\`auditxs harden\` after showing you exactly what will change, and every"
    echo "change is recorded in a snapshot that \`auditxs rollback\` can restore."
    echo "**Manual** checks only report — they never change the system."
    echo
    for id in "${CHECK_IDS[@]}"; do
        selected "$id" || continue
        if [ "${CHECK_CATEGORY[$id]}" != "$cat" ]; then
            cat=${CHECK_CATEGORY[$id]}
            echo "## $cat — $(domain_of "$cat") domain"
            echo
        fi
        echo "### $id — ${CHECK_TITLE[$id]}"
        echo
        local mcis; mcis=$(cis_of "$id")
        echo "- **Severity:** ${CHECK_SEVERITY[$id]}"
        echo "- **Profiles:** ${CHECK_PROFILES[$id]}"
        echo "- **CIS Benchmark:** ${mcis:-—} · **Level:** $(level_of "$id")"
        echo "- **NIST CSF 2.0:** $(nist_of "$id")"
        if has_fix "$id"; then fixable="automatic (reversible)"; else fixable="manual (report-only)"; fi
        echo "- **Fix:** $fixable"
        echo
        [ -n "${CHECK_META_DESC[$id]:-}" ] && { echo "${CHECK_META_DESC[$id]}"; echo; }
        if has_fix "$id"; then
            echo "**What the fix changes:** ${CHECK_META_FIX[$id]:-—}"
            echo
            echo "**How it is reverted:** ${CHECK_META_REVERT[$id]:-All changes are recorded in a snapshot; run \`sudo auditxs rollback <snapshot>\` to restore the previous state.}"
            echo
        fi
    done
}
