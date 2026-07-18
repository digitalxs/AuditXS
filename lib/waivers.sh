#!/usr/bin/env bash
#
# AuditXS — lib/waivers.sh
# Accepted-risk exceptions ("waivers"). A professional assessment routinely
# has findings that are knowingly accepted (a compensating control exists, a
# fix is scheduled, the risk is tolerated). A waiver records that decision —
# with a justification and optional expiry — so the finding renders as WAIVED
# instead of FAIL/WARN in every audit, report and drift alert.
#
#   auditxs waive SSH-005 "keys rolling out, tracked in OPS-42" --until 2026-12-31
#   auditxs waivers            # list active + expired waivers
#   auditxs unwaive SSH-005    # remove a waiver
#
# Waivers never change the system or hide the real result — the original
# status is preserved in the detail text, and expired waivers stop applying.
#
# File format (/etc/auditxs/waivers.conf), one per line:
#   CHECK-ID | YYYY-MM-DD-or-dash | justification text
#

AX_WAIVERS_FILE="${AX_WAIVERS_FILE:-/etc/auditxs/waivers.conf}"

declare -A WAIVER_REASON WAIVER_EXPIRY
WAIVERS_LOADED=0

load_waivers() {
    WAIVERS_LOADED=1
    local f; f=$(axpath "$AX_WAIVERS_FILE")
    [ -r "$f" ] || return 0
    local id exp reason
    while IFS='|' read -r id exp reason; do
        id=${id//[[:space:]]/}
        case $id in ''|\#*) continue ;; esac
        id=${id^^}
        WAIVER_EXPIRY[$id]=${exp//[[:space:]]/}
        reason=${reason#"${reason%%[![:space:]]*}"}   # ltrim
        WAIVER_REASON[$id]=${reason%"${reason##*[![:space:]]}"}   # rtrim
    done < "$f"
}

# is_waived <id> — 0 if an active (non-expired) waiver exists for the check.
is_waived() {
    [ "$WAIVERS_LOADED" = 1 ] || load_waivers
    local id=${1^^}
    [ -n "${WAIVER_REASON[$id]+x}" ] || return 1
    local exp=${WAIVER_EXPIRY[$id]:-}
    if [ -n "$exp" ] && [ "$exp" != "-" ]; then
        [[ "$exp" < "$(date +%Y-%m-%d)" ]] && return 1   # expired → no longer waived
    fi
    return 0
}
waiver_reason() { echo "${WAIVER_REASON[${1^^}]:-}"; }
waiver_expiry() { local e=${WAIVER_EXPIRY[${1^^}]:-}; [ "$e" = - ] && e=""; echo "$e"; }

# ---- commands ------------------------------------------------------------
cmd_waive() {
    require_root "waive"
    local id="" until="" reason=()
    while [ $# -gt 0 ]; do
        case $1 in
            --until) until=${2:?--until needs a date}; shift ;;
            -*)      die "waive: unknown option $1" ;;
            *)       if [ -z "$id" ]; then id=${1^^}; else reason+=("$1"); fi ;;
        esac
        shift
    done
    [ -n "$id" ] || die "Usage: sudo auditxs waive <CHECK-ID> \"reason\" [--until YYYY-MM-DD]"
    [ -n "${CHECK_TITLE[$id]:-}" ] || ax_die AX2005 "id=$id"
    [ ${#reason[@]} -gt 0 ] || die "A justification is required: sudo auditxs waive $id \"why this risk is accepted\""
    if [ -n "$until" ] && ! printf '%s' "$until" | grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'; then
        ax_die AX2006 "value=$until"
    fi

    mkdir -p "$(dirname "$AX_WAIVERS_FILE")" 2>/dev/null || ax_die AX1005 "dir=$(dirname "$AX_WAIVERS_FILE")"
    local tmp; tmp=$(mktemp)
    [ -f "$AX_WAIVERS_FILE" ] && grep -viE "^[[:space:]]*${id}[[:space:]]*\|" "$AX_WAIVERS_FILE" > "$tmp" 2>/dev/null
    printf '%s | %s | %s\n' "$id" "${until:--}" "${reason[*]}" >> "$tmp"
    if [ ! -f "$AX_WAIVERS_FILE" ]; then
        { echo "# AuditXS accepted-risk waivers — CHECK-ID | expiry(YYYY-MM-DD or -) | justification"; cat "$tmp"; } > "$AX_WAIVERS_FILE"
    else
        cat "$tmp" > "$AX_WAIVERS_FILE"
    fi
    rm -f "$tmp"; chmod 640 "$AX_WAIVERS_FILE" 2>/dev/null
    ok "Waived ${BOLD}$id${RC}${until:+ until $until}: ${reason[*]}"
    log "[waiver] added $id until=${until:--} reason=${reason[*]}"
}

cmd_unwaive() {
    require_root "unwaive"
    local id=${1:?Usage: sudo auditxs unwaive <CHECK-ID>}; id=${id^^}
    [ -f "$AX_WAIVERS_FILE" ] || { warn "No waivers file."; return 1; }
    if ! grep -qiE "^[[:space:]]*${id}[[:space:]]*\|" "$AX_WAIVERS_FILE"; then
        warn "No waiver for $id."; return 1
    fi
    local tmp; tmp=$(mktemp)
    grep -viE "^[[:space:]]*${id}[[:space:]]*\|" "$AX_WAIVERS_FILE" > "$tmp"
    cat "$tmp" > "$AX_WAIVERS_FILE"; rm -f "$tmp"
    ok "Removed the waiver for ${BOLD}$id${RC}."
    log "[waiver] removed $id"
}

cmd_waivers() {
    load_waivers
    if [ ${#WAIVER_REASON[@]} -eq 0 ]; then
        say "No waivers configured. Accept a known finding with:"
        say "  ${BOLD}sudo auditxs waive <CHECK-ID> \"justification\" [--until YYYY-MM-DD]${RC}"
        return 0
    fi
    nala_box "Accepted-risk waivers (${#WAIVER_REASON[@]})"
    local id exp state today; today=$(date +%Y-%m-%d)
    while IFS= read -r id; do
        exp=${WAIVER_EXPIRY[$id]}
        if [ -n "$exp" ] && [ "$exp" != "-" ] && [[ "$exp" < "$today" ]]; then
            state="${RED}EXPIRED $exp${RC}"
        elif [ -n "$exp" ] && [ "$exp" != "-" ]; then
            state="${GREEN}until $exp${RC}"
        else
            state="${DIM}no expiry${RC}"
        fi
        nala_row "$(printf '%b%-9s%b %b' "$BOLD" "$id" "$RC" "$state")"
        nala_row "  ${DIM}${WAIVER_REASON[$id]}${RC}"
    done < <(printf '%s\n' "${!WAIVER_REASON[@]}" | sort)
    nala_end
    say ""
    say "Remove one with: ${BOLD}sudo auditxs unwaive <CHECK-ID>${RC}   ·   Expired waivers no longer apply."
}
