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

# =====================================================================
# Joined external-tool findings — fold Lynis + rkhunter results into the
# AuditXS audit report (console, HTML and JSON). Advisory ONLY: these never
# affect the AuditXS hardening score, which reflects AuditXS's own
# reversible-fixable checks. Enabled per run with `auditxs audit --with-tools`.
# =====================================================================

RKHUNTER_LOG="${RKHUNTER_LOG:-/var/log/rkhunter.log}"
WITH_TOOLS="${WITH_TOOLS:-0}"          # set to 1 by --with-tools
# Tools that print findings to stdout (no canonical report file) get their
# output cached here so `--tools-cached` can re-read it without a re-scan.
AUDITXS_TOOLCACHE="${AUDITXS_TOOLCACHE:-/var/lib/auditxs/toolcache}"

declare -gA EXT_TOOL EXT_STATUS EXT_DETAIL
EXT_IDS=()
N_EXT_WARN=0
N_EXT_INFO=0

_ext_add() { # <id> <tool> <status:WARN|INFO> <detail>
    EXT_IDS+=("$1"); EXT_TOOL[$1]=$2; EXT_STATUS[$1]=$3; EXT_DETAIL[$1]=$4
    case $3 in WARN) N_EXT_WARN=$((N_EXT_WARN + 1)) ;; *) N_EXT_INFO=$((N_EXT_INFO + 1)) ;; esac
}

# rkhunter logs "[time] Warning: <message>" lines; collect the unique messages.
_rkhunter_warnings() {
    [ -f "$RKHUNTER_LOG" ] || return 1
    awk -F'Warning: ' '/Warning: /{ w=$2; sub(/[ \t]+$/,"",w); if (w!="") print w }' \
        "$RKHUNTER_LOG" | sort -u
}

# _fold_file_lines <file> <id-prefix> <tool> <status> [keep-regex] — add each
# non-empty line of <file> as an external finding (optionally only lines that
# match keep-regex). Used for tools that print plain-text findings to stdout
# (chkrootkit, debsecan). Testable against a fixture file.
_fold_file_lines() {
    local file=$1 prefix=$2 tool=$3 status=$4 keep=${5:-} v i=0
    [ -f "$file" ] || return 0
    while IFS= read -r v; do
        v=${v%$'\r'}
        [ -n "$v" ] || continue
        [ -n "$keep" ] && { printf '%s' "$v" | grep -qiE "$keep" || continue; }
        i=$((i + 1))
        _ext_add "$(printf '%s-%03d' "$prefix" "$i")" "$tool" "$status" "$v"
    done < "$file"
}

# collect_external_findings — populate the EXT_* arrays from Lynis and rkhunter.
# When WITH_TOOLS_RUN=1 (default, and only if root) the tools are run fresh
# first; otherwise the last saved reports are read as-is. Safe when neither tool
# is installed (it simply collects nothing).
collect_external_findings() {
    EXT_IDS=(); N_EXT_WARN=0; N_EXT_INFO=0
    local run=${WITH_TOOLS_RUN:-1} v i

    if have lynis; then
        if [ "$run" = 1 ] && [ "$(id -u)" -eq 0 ]; then
            info "  running Lynis (folding its findings into this report)…"
            lynis audit system --quiet --no-colors >/dev/null 2>&1 || true
        fi
        if [ -f "$LYNIS_REPORT" ]; then
            i=0
            while IFS= read -r v; do [ -n "$v" ] || continue; i=$((i + 1))
                _ext_add "$(printf 'LYNIS-W%03d' "$i")" Lynis WARN "$(_lynis_finding_id "$v")"
            done < <(_lynis_report_get "$LYNIS_REPORT" 'warning[]')
            i=0
            while IFS= read -r v; do [ -n "$v" ] || continue; i=$((i + 1))
                _ext_add "$(printf 'LYNIS-S%03d' "$i")" Lynis INFO "$(_lynis_finding_id "$v")"
            done < <(_lynis_report_get "$LYNIS_REPORT" 'suggestion[]')
        fi
    fi

    if have rkhunter; then
        if [ "$run" = 1 ] && [ "$(id -u)" -eq 0 ]; then
            info "  running rkhunter (folding its findings into this report)…"
            rkhunter --check --sk --nocolors >/dev/null 2>&1 || true
        fi
        i=0
        while IFS= read -r v; do [ -n "$v" ] || continue; i=$((i + 1))
            _ext_add "$(printf 'RKH-%03d' "$i")" rkhunter WARN "$v"
        done < <(_rkhunter_warnings)
    fi

    # ---- chkrootkit (rootkit/anomaly scanner; prints findings to stdout) ----
    if have chkrootkit; then
        local ckfile="$AUDITXS_TOOLCACHE/chkrootkit.out"
        if [ "$run" = 1 ] && [ "$(id -u)" -eq 0 ]; then
            info "  running chkrootkit (folding its findings into this report)…"
            mkdir -p "$AUDITXS_TOOLCACHE" 2>/dev/null
            chkrootkit -q > "$ckfile" 2>/dev/null || true
        fi
        # -q already suppresses "nothing found" noise; keep only lines that name
        # a real concern so occasional benign chatter does not become a finding.
        _fold_file_lines "$ckfile" CHKR chkrootkit WARN \
            'INFECTED|Vulnerable|Warning|suspicious|PACKET SNIFFER|Possible'
    fi

    # ---- debsecan (Debian Security Analyzer; CVEs in installed packages) ----
    if have debsecan; then
        local dsfile="$AUDITXS_TOOLCACHE/debsecan.out"
        if [ "$run" = 1 ] && [ "$(id -u)" -eq 0 ]; then
            info "  running debsecan (folding its findings into this report)…"
            mkdir -p "$AUDITXS_TOOLCACHE" 2>/dev/null
            # --only-fixed: vulnerabilities with a fix available (actionable).
            debsecan --only-fixed 2>/dev/null | sort -u > "$dsfile" || true
        fi
        _fold_file_lines "$dsfile" DSEC debsecan WARN
    fi
    return 0
}

# print_external_findings — console rendering of the joined findings (advisory).
# Shows every warning; caps suggestions with a pointer to the full report.
print_external_findings() {
    [ "$QUIET" = 1 ] && return 0
    [ "${#EXT_IDS[@]}" -gt 0 ] || return 0
    local id shown=0 cap=${EXT_MAX_INFO:-15} wcap=${EXT_MAX_WARN:-25} wshown=0
    nala_box "External tool findings  ·  advisory (not scored)"
    nala_row "Folded in from independent scanners: ${RED}${N_EXT_WARN} warning(s)${RC} · ${YELLOW}${N_EXT_INFO} suggestion(s)${RC}"
    nala_end
    for id in "${EXT_IDS[@]}"; do
        [ "${EXT_STATUS[$id]}" = WARN ] || continue
        [ "$wshown" -lt "$wcap" ] || continue
        say "  ${RED}!${RC} ${DIM}[${EXT_TOOL[$id]}]${RC} ${EXT_DETAIL[$id]}"
        wshown=$((wshown + 1))
    done
    [ "$N_EXT_WARN" -gt "$wcap" ] && \
        say "  ${DIM}… and $((N_EXT_WARN - wcap)) more warning(s) — see the saved HTML/JSON report.${RC}"
    for id in "${EXT_IDS[@]}"; do
        [ "${EXT_STATUS[$id]}" = INFO ] || continue
        [ "$shown" -lt "$cap" ] || continue
        say "  ${YELLOW}•${RC} ${DIM}[${EXT_TOOL[$id]}]${RC} ${EXT_DETAIL[$id]}"
        shown=$((shown + 1))
    done
    [ "$N_EXT_INFO" -gt "$cap" ] && \
        say "  ${DIM}… and $((N_EXT_INFO - cap)) more suggestion(s) — see the saved HTML/JSON report.${RC}"
    say ""
    say "${DIM}Advisory: from Lynis/rkhunter, shown for cross-verification. AuditXS does not"
    say "auto-fix these; where they overlap an AuditXS check, use ${RC}${BOLD}sudo auditxs harden${RC}${DIM}.${RC}"
}

# _html_external_section — an HTML card listing the joined findings (empty
# output when there are none). Reuses the report's badge/filter classes so it
# participates in the "show only findings" toggle.
_html_external_section() {
    [ "${#EXT_IDS[@]}" -gt 0 ] || return 0
    local id badge
    printf '<h2 class="cat">External tool findings <small>— advisory, not scored</small></h2>\n'
    printf '<div class="card catcard" style="padding:.5rem .5rem"><div class="tablewrap"><table>\n'
    printf '<tr><th>Level</th><th>Tool</th><th>Finding</th></tr>\n'
    for id in "${EXT_IDS[@]}"; do
        if [ "${EXT_STATUS[$id]}" = WARN ]; then
            badge='<span class="badge WARN">Warning</span>'
        else
            badge='<span class="badge SKIP">Suggestion</span>'
        fi
        printf '<tr data-st="%s"><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
            "${EXT_STATUS[$id]}" "$badge" "$(html_escape "${EXT_TOOL[$id]}")" \
            "$(html_escape "${EXT_DETAIL[$id]}")"
    done
    printf '</table></div></div>\n'
}
