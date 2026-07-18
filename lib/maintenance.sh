#!/usr/bin/env bash
#
# AuditXS — lib/maintenance.sh
# Maintenance & operations: self-diagnostics (doctor), approved-baseline
# management (baseline), and scheduled audits with drift alerts (schedule).
#
# Part of AuditXS — transparent, reversible Linux security auditing.
#

BASELINE_PATH=/etc/auditxs/baseline.json
SCHED_SERVICE=/etc/systemd/system/auditxs-audit.service
SCHED_TIMER=/etc/systemd/system/auditxs-audit.timer

# --------------------------------------------------------------- doctor ---
_doc_issues=0
_doc_ok()   { printf '%b\n' "  ${GREEN}✓${RC} $*"; }
_doc_warn() { printf '%b\n' "  ${YELLOW}!${RC} $*"; }
_doc_bad()  { printf '%b\n' "  ${RED}✗${RC} $*"; _doc_issues=$((_doc_issues + 1)); }

cmd_doctor() {
    _doc_issues=0
    printf '%b\n' "${BOLD}AuditXS doctor${RC} — installation and environment diagnostics"
    hr

    printf '%b\n' "${BOLD}Installation${RC}"
    _doc_ok "version $AUDITXS_VERSION, installed at $AUDITXS_ROOT"
    local n_checks=${#CHECK_IDS[@]}
    if [ "$n_checks" -gt 0 ]; then
        _doc_ok "$n_checks checks registered"
    else
        _doc_bad "no checks registered — checks/ directory missing or unreadable"
    fi
    local cmd tgt
    for cmd in auditxs auditxs-gui update-auditxs; do
        if [ -e "/usr/local/bin/$cmd" ]; then
            tgt=$(readlink -f "/usr/local/bin/$cmd" 2>/dev/null)
            _doc_ok "command $cmd → ${tgt:-copy}"
        else
            _doc_warn "command $cmd not in /usr/local/bin (run: sudo $AUDITXS_ROOT/setup.sh --refresh)"
        fi
    done

    printf '%b\n' "${BOLD}Required tools${RC}"
    local t
    for t in awk sed grep find stat tac fold sort; do
        if have "$t"; then _doc_ok "$t"; else _doc_bad "$t missing — core engine cannot work without it"; fi
    done

    printf '%b\n' "${BOLD}Feature tools${RC} (missing ones only reduce coverage)"
    local feat="findmnt:filesystem_checks ss:network_checks sysctl:kernel_checks \
systemctl:service_checks sshd:SSH_checks visudo:sudo_fix auditctl:audit_rules \
zenity:GUI pkexec:GUI_elevation"
    local pair
    for pair in $feat; do
        t=${pair%%:*}
        if have "$t" || [ -x "/usr/sbin/${t}" ]; then
            _doc_ok "$t"
        else
            _doc_warn "$t not found (${pair#*:} unavailable/skipped)"
        fi
    done

    printf '%b\n' "${BOLD}Interfaces${RC}"
    if have whiptail || have dialog; then
        _doc_ok "terminal UI (whiptail/dialog) — 'sudo auditxs tui' available"
    else
        _doc_warn "no whiptail/dialog — 'sudo auditxs tui' unavailable (CLI still works)"
    fi
    if [ "${PROFILE:-}" = server ]; then
        _doc_ok "profile 'server': web/Qt/zenity interfaces intentionally disabled (use tui/CLI)"
    else
        if have python3; then _doc_ok "python3 — 'auditxs web' available"; else _doc_warn "no python3 — 'auditxs web' unavailable"; fi
    fi

    printf '%b\n' "${BOLD}Configuration${RC}"
    if [ -r "$AUDITXS_CONF" ]; then
        case "${PROFILE:-}" in
            server|workstation) _doc_ok "profile: $PROFILE ($AUDITXS_CONF)" ;;
            *) _doc_bad "invalid or missing PROFILE in $AUDITXS_CONF" ;;
        esac
    else
        _doc_warn "no $AUDITXS_CONF — run the installer, or pass --profile on each run"
    fi
    if [ -f "$BASELINE_PATH" ]; then
        _doc_ok "approved baseline: $BASELINE_PATH ($(parse_report_field "$BASELINE_PATH" date), score $(parse_report_field "$BASELINE_PATH" score))"
    else
        _doc_warn "no approved baseline — 'sudo auditxs baseline set' enables drift alerts"
    fi
    if [ -f /etc/auditxs/allowed-ports.conf ]; then
        _doc_ok "port allowlist: /etc/auditxs/allowed-ports.conf ($(grep -csv '^#' /etc/auditxs/allowed-ports.conf 2>/dev/null || echo '?') entries)"
    else
        _doc_warn "no port allowlist — see 'auditxs explain NET-004' for drift detection"
    fi

    if [ "$(id -u)" -eq 0 ]; then
        printf '%b\n' "${BOLD}State & snapshot integrity${RC}"
        local d id bad_snap=0 n_snap=0
        if [ -d "$SNAP_ROOT" ]; then
            for d in "$SNAP_ROOT"/*/; do
                [ -f "$d/manifest.tsv" ] || continue
                n_snap=$((n_snap + 1))
                id=$(basename "$d")
                # every manifest row must have 6 fields; every 'file' action a saved copy
                if awk -F'\t' 'NF != 6 {exit 1}' "$d/manifest.tsv" 2>/dev/null; then
                    while IFS=$'\t' read -r _ _ type target _ _; do
                        if [ "$type" = "file" ] && [ ! -e "$d/files$target" ]; then
                            _doc_bad "snapshot $id: missing saved copy for $target"
                            bad_snap=1
                        fi
                    done < "$d/manifest.tsv"
                else
                    _doc_bad "snapshot $id: corrupt manifest"
                    bad_snap=1
                fi
            done
        fi
        [ "$bad_snap" = 0 ] && _doc_ok "$n_snap snapshot(s), manifests and file copies intact"
        if [ -d /var/lib/auditxs ]; then
            _doc_ok "state size: $(du -sh /var/lib/auditxs 2>/dev/null | awk '{print $1}') in /var/lib/auditxs"
        fi
        [ -f "$CHANGES_LOG" ] && _doc_ok "change ledger: $(wc -l < "$CHANGES_LOG") entries"
    else
        printf '%b\n' "${BOLD}State & snapshot integrity${RC}"
        _doc_warn "run as root to verify snapshots and state directories"
    fi

    printf '%b\n' "${BOLD}Scheduled audits${RC}"
    if has_systemd && [ -f "$SCHED_TIMER" ]; then
        _doc_ok "auditxs-audit.timer: enabled=$(systemctl is-enabled auditxs-audit.timer 2>/dev/null) active=$(systemctl is-active auditxs-audit.timer 2>/dev/null)"
    else
        _doc_warn "no scheduled audit — 'sudo auditxs schedule enable' runs a daily audit with drift alerts"
    fi

    hr
    if [ "$_doc_issues" -eq 0 ]; then
        ok "No problems found."
        return 0
    fi
    err "$_doc_issues problem(s) found — see above."
    return 1
}

# -------------------------------------------------------------- baseline ---
cmd_baseline() { # set [file] | show | clear
    local action=${1:-show} src
    case $action in
        set)
            require_root "baseline set"
            src=${2:-/var/lib/auditxs/reports/latest.json}
            [ -r "$src" ] || die "No report at $src — run 'sudo auditxs audit' first (or pass a report file)"
            grep -q '"results"' "$src" || die "$src does not look like an AuditXS JSON report"
            mkdir -p "$(dirname "$BASELINE_PATH")"
            cp -f "$src" "$BASELINE_PATH" && chmod 640 "$BASELINE_PATH"
            ok "Approved baseline set from $src"
            say "  date:  $(parse_report_field "$BASELINE_PATH" date)"
            say "  score: $(parse_report_field "$BASELINE_PATH" score)/100"
            say "  Compare any time with: ${BOLD}sudo auditxs diff $BASELINE_PATH${RC}"
            ;;
        show)
            [ -f "$BASELINE_PATH" ] || { say "No approved baseline. Create one with: sudo auditxs baseline set"; return 0; }
            say "Approved baseline: $BASELINE_PATH"
            say "  host:    $(parse_report_field "$BASELINE_PATH" host)"
            say "  profile: $(parse_report_field "$BASELINE_PATH" profile)"
            say "  date:    $(parse_report_field "$BASELINE_PATH" date)"
            say "  score:   $(parse_report_field "$BASELINE_PATH" score)/100"
            ;;
        clear)
            require_root "baseline clear"
            [ -f "$BASELINE_PATH" ] || { say "No baseline to clear."; return 0; }
            confirm "Remove the approved baseline ($BASELINE_PATH)?" || return 1
            rm -f "$BASELINE_PATH" && ok "Baseline removed."
            ;;
        *) die "Usage: auditxs baseline set [report.json] | show | clear" ;;
    esac
}

# -------------------------------------------------------------- schedule ---
cmd_schedule() { # enable | disable | status | run
    local action=${1:-status} bin
    case $action in
        enable)
            require_root "schedule enable"
            has_systemd || die "Scheduled audits need systemd. Cron alternative: '0 3 * * * /usr/local/bin/auditxs schedule run'"
            bin=$(command -v auditxs || echo "$AUDITXS_ROOT/auditxs")
            write_file "$SCHED_SERVICE" 0644 "# AuditXS scheduled audit — created by 'auditxs schedule enable'.
# Remove with: sudo auditxs schedule disable
[Unit]
Description=AuditXS daily security audit (read-only) with baseline drift alert

[Service]
Type=oneshot
Nice=10
ExecStart=$bin schedule run"
            write_file "$SCHED_TIMER" 0644 "# AuditXS scheduled audit — created by 'auditxs schedule enable'.
# Remove with: sudo auditxs schedule disable
[Unit]
Description=Run the AuditXS daily security audit

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target"
            xrun_q systemctl daemon-reload
            xrun_q systemctl enable --now auditxs-audit.timer || die "Could not enable auditxs-audit.timer"
            ok "Daily audit scheduled (auditxs-audit.timer)."
            say "  The audit is read-only. If an approved baseline exists ($BASELINE_PATH),"
            say "  regressions mark the service run as failed — visible in 'systemctl status"
            say "  auditxs-audit.service' and the journal, so monitoring can alert on it."
            [ -f "$BASELINE_PATH" ] || say "  ${YELLOW}Tip:${RC} set a baseline now: ${BOLD}sudo auditxs baseline set${RC}"
            ;;
        disable)
            require_root "schedule disable"
            has_systemd || die "systemd not detected"
            systemctl disable --now auditxs-audit.timer >/dev/null 2>&1
            rm -f "$SCHED_TIMER" "$SCHED_SERVICE"
            systemctl daemon-reload
            ok "Scheduled audit removed."
            ;;
        status)
            if has_systemd && [ -f "$SCHED_TIMER" ]; then
                say "auditxs-audit.timer: enabled=$(systemctl is-enabled auditxs-audit.timer 2>/dev/null) active=$(systemctl is-active auditxs-audit.timer 2>/dev/null)"
                systemctl list-timers auditxs-audit.timer --no-pager 2>/dev/null | head -n 2 | tail -n 1
            else
                say "No scheduled audit. Enable with: sudo auditxs schedule enable"
            fi
            ;;
        run)
            # What the timer executes: quiet audit (saves reports), then a
            # drift check against the approved baseline. A regression makes
            # this command — and therefore the systemd service run — fail.
            require_root "schedule run"
            QUIET=1
            run_audit
            save_reports
            cve_scan
            log "scheduled audit complete: score=$SCORE pass=$N_PASS fail=$N_FAIL"
            local _drift=0
            if [ -f "$BASELINE_PATH" ]; then
                QUIET=0
                if ! diff_current_against "$BASELINE_PATH"; then
                    err "Security configuration regressed against the approved baseline."
                    _drift=1
                fi
            fi
            # Active alerting (best-effort) when a sink is configured.
            if alerts_configured; then
                if [ "$_drift" = 1 ]; then
                    send_alert "Configuration drift detected" \
                        "The scheduled audit regressed against the approved baseline (score $SCORE/100, $N_FAIL failing). Review with: sudo auditxs diff $BASELINE_PATH" || true
                elif [ -n "${CVE_COUNT:-}" ] && [ "${CVE_COUNT:-0}" != 0 ] && [ "${CVE_COUNT:-0}" != "?" ]; then
                    send_alert "Vulnerable packages need updates" \
                        "$CVE_COUNT installed package(s) have a known vulnerability with a fix available (source: ${CVE_SOURCE:-distro}). Run: sudo auditxs cve" || true
                fi
            fi
            [ "$_drift" = 1 ] && return 1
            return 0
            ;;
        *) die "Usage: auditxs schedule enable | disable | status | run" ;;
    esac
}
