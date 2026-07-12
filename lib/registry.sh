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
#   0 = PASS   1 = FAIL (fixable finding)   2 = WARN (manual review)   3 = SKIP
#
# Part of AuditXS — transparent, reversible Linux security auditing.
#

declare -a CHECK_IDS=()
declare -A CHECK_TITLE=() CHECK_CATEGORY=() CHECK_SEVERITY=() CHECK_PROFILES=()
declare -A CHECK_META_DESC=() CHECK_META_FIX=() CHECK_META_REVERT=()
declare -A RESULT_STATUS=() RESULT_DETAIL=()

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
    local id=$1 st=${RESULT_STATUS[$id]} col=""
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
    hr
    printf '%b\n' "${BOLD}AuditXS v$AUDITXS_VERSION${RC} — security configuration audit"
    printf '%b\n' "Host: $(hostname 2>/dev/null)  ·  ${DISTRO_NAME}  ·  Profile: ${BOLD}${PROFILE}${RC}  ·  $(date '+%F %T')"
    printf '%b\n' "${DIM}Audit mode is read-only: nothing on this system is changed.${RC}"
    hr
}

run_audit() {
    local id fn rc st
    N_PASS=0 N_FAIL=0 N_WARN=0 N_SKIP=0
    AUDIT_DATE=$(date -Is)
    for id in "${CHECK_IDS[@]}"; do
        selected "$id" || continue
        if ! check_applies "$id"; then
            RESULT_STATUS[$id]=SKIP
            RESULT_DETAIL[$id]="Not applicable to the '$PROFILE' profile"
            N_SKIP=$((N_SKIP + 1))
            print_result "$id"
            continue
        fi
        DETAIL=""
        fn=$(fn_name "$id" audit)
        if declare -F "$fn" >/dev/null; then
            "$fn"; rc=$?
        else
            rc=3; DETAIL="No audit implementation"
        fi
        st=$(status_str "$rc")
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
    hr
    printf '%b\n' "Results: ${GREEN}$N_PASS passed${RC} · ${RED}$N_FAIL failed${RC} · ${YELLOW}$N_WARN warnings${RC} · ${DIM}$N_SKIP skipped${RC}"
    printf '%b\n' "Hardening score: ${BOLD}$SCORE/100${RC} ${DIM}(severity-weighted, PASS vs FAIL)${RC}"
    if [ "$N_FAIL" -gt 0 ]; then
        printf '%b\n' "Next step: ${BOLD}sudo auditxs harden${RC} reviews each failed check with you before changing anything."
    fi
    hr
}

# ------------------------------------------------------------ transparency
fold_indent() {
    printf '%s\n' "$1" | fold -s -w 74 | sed 's/^/    /'
}

show_check_details() { # <id>
    local id=$1
    hr
    printf '%b\n' "${BOLD}$id — ${CHECK_TITLE[$id]}${RC}"
    printf '%b\n' "  Category: ${CHECK_CATEGORY[$id]} · Severity: ${CHECK_SEVERITY[$id]} · Profiles: ${CHECK_PROFILES[$id]}"
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
    printf '%b\n' "${BOLD}ID        SEVERITY  FIX    PROFILES              TITLE${RC}"
    for id in "${CHECK_IDS[@]}"; do
        if has_fix "$id"; then fixable="auto"; else fixable="manual"; fi
        printf '%-9s %-9s %-6s %-21s %s\n' \
            "$id" "${CHECK_SEVERITY[$id]}" "$fixable" "${CHECK_PROFILES[$id]}" "${CHECK_TITLE[$id]}"
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
        if [ "${CHECK_CATEGORY[$id]}" != "$cat" ]; then
            cat=${CHECK_CATEGORY[$id]}
            echo "## $cat"
            echo
        fi
        echo "### $id — ${CHECK_TITLE[$id]}"
        echo
        echo "- **Severity:** ${CHECK_SEVERITY[$id]}"
        echo "- **Profiles:** ${CHECK_PROFILES[$id]}"
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
