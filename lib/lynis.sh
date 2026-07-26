#!/usr/bin/env bash
#
# AuditXS — lib/lynis.sh
# Lynis integration (orchestrate-and-absorb). AuditXS does not reimplement
# Lynis's hundreds of tests; instead it runs Lynis (the de-facto open-source
# host auditor, https://github.com/CISOfy/lynis) and folds Lynis's own findings
# — its hardening index, warnings and suggestions — into AuditXS's output as
# read-only, advisory results.
#
# The division of labour (this is the dedup boundary):
#   * AuditXS owns the REVERSIBLE, consented fixes (snapshot + rollback). Lynis
#     never changes the system, so nothing here applies a fix.
#   * Lynis owns breadth — deep detective checks AuditXS deliberately does not
#     duplicate. Where an AuditXS check and a Lynis test cover the same control,
#     AuditXS keeps its check (because it can also *fix* it) and simply surfaces
#     Lynis's opinion alongside for cross-verification.
#

LYNIS_REPORT="${LYNIS_REPORT:-/var/log/lynis-report.dat}"

# _lynis_report_get <file> <key>  — print every value recorded for <key> in a
# lynis-report.dat (one per line). Keys look like 'hardening_index' or the
# repeated 'warning[]' / 'suggestion[]' arrays; values are pipe-delimited.
# Pure text parsing, so it is unit-testable against a fixture report.
_lynis_report_get() {
    local f=$1 key=$2
    [ -f "$f" ] || return 1
    awk -v k="$key" '
        { p = index($0, "=");
          if (p > 0 && substr($0, 1, p - 1) == k) print substr($0, p + 1) }' "$f"
}

# _lynis_finding_id <pipe-delimited value>  — Lynis warning/suggestion values
# are "TESTID|message|details|solution"; return "TESTID: message".
_lynis_finding_id() {
    printf '%s' "$1" | awk -F'|' '{ msg=$2; if (msg=="") msg="(no description)";
        printf "%s: %s", $1, msg }'
}

# _lynis_summary <report.dat>  — render an AuditXS-style summary of a Lynis run.
# Reads only the report file, so it works both right after a run and with
# '--report' against the last saved report.
_lynis_summary() {
    local f=$1 hi tests
    hi=$(_lynis_report_get "$f" hardening_index | tail -n1)
    tests=$(_lynis_report_get "$f" lynis_version | tail -n1)

    local -a warns suggs
    mapfile -t warns < <(_lynis_report_get "$f" 'warning[]')
    mapfile -t suggs < <(_lynis_report_get "$f" 'suggestion[]')

    nala_box "Lynis — independent host audit"
    nala_row "Hardening index: ${BOLD}${hi:-?}/100${RC} ${DIM}(Lynis's own score; complements the AuditXS score)${RC}"
    nala_row "Findings: ${RED}${#warns[@]} warning(s)${RC} · ${YELLOW}${#suggs[@]} suggestion(s)${RC}${tests:+ ${DIM}· Lynis $tests${RC}}"
    nala_end

    local v
    if [ "${#warns[@]}" -gt 0 ]; then
        say "${BOLD}Warnings${RC} (Lynis flags these as important):"
        for v in "${warns[@]}"; do say "  ${RED}•${RC} $(_lynis_finding_id "$v")"; done
        say ""
    fi
    if [ "${#suggs[@]}" -gt 0 ]; then
        local shown=0
        say "${BOLD}Suggestions${RC} (top ${LYNIS_MAX_SUGGEST:-15}):"
        for v in "${suggs[@]}"; do
            say "  ${YELLOW}•${RC} $(_lynis_finding_id "$v")"
            shown=$((shown + 1)); [ "$shown" -ge "${LYNIS_MAX_SUGGEST:-15}" ] && break
        done
        [ "${#suggs[@]}" -gt "${LYNIS_MAX_SUGGEST:-15}" ] && \
            say "  ${DIM}… and $(( ${#suggs[@]} - ${LYNIS_MAX_SUGGEST:-15} )) more (full detail: less ${f})${RC}"
        say ""
    fi
    say "${DIM}Lynis reports; it never changes the system. Where a finding overlaps an"
    say "AuditXS check, fix it reversibly with ${RC}${BOLD}sudo auditxs harden${RC}${DIM} (then re-run to verify).${RC}"
}

# cmd_lynis [--report] — run Lynis and summarise, or (--report) summarise the
# last saved report without re-running.
cmd_lynis() {
    local report_only=0
    case ${1:-} in
        --report|report) report_only=1 ;;
        --run|run|"")    report_only=0 ;;
        *) die "Usage: auditxs lynis [--run | --report]" ;;
    esac

    if [ "$report_only" = 0 ]; then
        require_root lynis
        if ! have lynis; then
            err "Lynis is not installed."
            info "Install it (recorded for rollback): ${BOLD}sudo auditxs tools install lynis${RC}"
            info "Or view an existing report without running: ${BOLD}auditxs lynis --report${RC}"
            return 1
        fi
        info "Running Lynis (this can take a minute)…"
        # Lynis writes the machine-readable report to LYNIS_REPORT regardless of
        # console verbosity. Its own exit status is non-zero when warnings exist,
        # which is expected here — we read the report, not the exit code.
        lynis audit system --quiet --no-colors >/dev/null 2>&1 || true
    fi

    if [ ! -f "$LYNIS_REPORT" ]; then
        err "No Lynis report at ${LYNIS_REPORT}."
        [ "$report_only" = 1 ] && info "Run one first: ${BOLD}sudo auditxs lynis${RC}"
        return 1
    fi
    _lynis_summary "$LYNIS_REPORT"
}
