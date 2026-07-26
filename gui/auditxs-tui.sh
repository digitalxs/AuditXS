#!/usr/bin/env bash
#
# AuditXS — gui/auditxs-tui.sh
# ncurses (whiptail/dialog) terminal interface. This is the interactive UI for
# SERVERS: it runs entirely in the terminal, works over a plain SSH session
# (no browser, no X, no tunnel, no root web server), and is also available on
# workstations. It is a thin front-end over the `auditxs` CLI.
#
# Launched by:  sudo auditxs tui
#

AUDITXS_BIN=${AUDITXS_BIN:-auditxs}
BT="AuditXS — terminal interface"
WORK="${XDG_CACHE_HOME:-${TMPDIR:-/tmp}}/auditxs-tui.$$"
mkdir -p "$WORK"
trap 'rm -rf "$WORK"' EXIT

# Pick an ncurses dialog tool (whiptail is Debian default; dialog is the fallback).
if command -v whiptail >/dev/null 2>&1; then
    DIALOG=whiptail
elif command -v dialog >/dev/null 2>&1; then
    DIALOG=dialog
else
    echo "The terminal UI needs 'whiptail' (package: whiptail) or 'dialog'." >&2
    echo "  Debian/Ubuntu: sudo apt install whiptail" >&2
    echo "  Fedora:        sudo dnf install newt   (or dialog)" >&2
    echo "Meanwhile, the full CLI works: sudo auditxs audit" >&2
    exit 1
fi

# ------------------------------------------------------------- helpers ---
# menu <title> <text> <tag desc tag desc...>  → echoes chosen tag
menu() {
    local title=$1 text=$2; shift 2
    "$DIALOG" --title "$title" --backtitle "$BT" \
        --menu "$text" 22 78 12 "$@" 3>&1 1>&2 2>&3
}
msgbox()  { "$DIALOG" --title "$1" --backtitle "$BT" --msgbox "$2" 20 78; }
yesno()   { "$DIALOG" --title "$1" --backtitle "$BT" --yesno "$2" 14 78; }
textbox() { "$DIALOG" --title "$1" --backtitle "$BT" --scrolltext --textbox "$2" 24 88; }
gauge_run() { # <text> <command...> — run a command behind a pulsing message
    local text=$1; shift
    { "$@" >/dev/null 2>&1; } &
    local pid=$! p=0
    { while kill -0 "$pid" 2>/dev/null; do echo $((p%100)); p=$((p+7)); sleep 0.3; done; echo 100; } \
        | "$DIALOG" --title "$BT" --gauge "$text" 8 70 0
    wait "$pid"
}

gauge_progress() { # <text> <stdout-file> <command...> — real percentage gauge
    # Runs the command once with --progress-file and feeds the true
    # percentage (and current check id) to the dialog gauge.
    local text=$1 outfile=$2; shift 2
    local prog="$WORK/progress" donef="$WORK/gauge.done"
    : > "$prog"; rm -f "$donef"
    # stdout is the machine-readable payload; stderr lands in a sidecar so
    # callers that want it (harden log) can append it afterwards.
    ( "$@" --progress-file "$prog" > "$outfile" 2>"$outfile.stderr"; : > "$donef" ) &
    local pid=$!
    (
        local pct d t cid
        while [ ! -f "$donef" ]; do
            if IFS=' ' read -r pct d t cid < "$prog" 2>/dev/null && [ -n "${pct:-}" ]; then
                printf 'XXX\n%s\n%s\n%s  (%s/%s)\nXXX\n' \
                    "$pct" "$text" "${cid:-starting…}" "${d:-0}" "${t:-?}"
            fi
            sleep 0.3
        done
        echo 100
    ) | "$DIALOG" --title "$BT" --gauge "$text" 10 70 0
    wait "$pid"
}

RESULTS="$WORK/audit.tsv"

do_audit() {
    gauge_progress "Auditing (read-only — nothing is changed)…" "$RESULTS" \
        "$AUDITXS_BIN" audit --format tsv --quiet
    local pass fail warn skip
    pass=$(grep -c '^PASS' "$RESULTS"); fail=$(grep -c '^FAIL' "$RESULTS")
    warn=$(grep -c '^WARN' "$RESULTS"); skip=$(grep -c '^SKIP' "$RESULTS")
    {
        echo "AuditXS audit results"
        echo "====================="
        echo "PASS: $pass   FAIL: $fail   WARN: $warn   SKIP: $skip"
        echo
        awk -F'\t' '{printf "[%-4s] %-9s %-9s %s\n", $1, $2, $3, $6;
                     if ($7 != "" && $1 != "PASS") printf "         %s\n", $7}' "$RESULTS"
    } > "$WORK/audit.txt"
    textbox "Audit results ($pass pass / $fail fail / $warn warn)" "$WORK/audit.txt"
}

do_harden() {
    [ -s "$RESULTS" ] || { msgbox "Harden" "Run an Audit first so AuditXS knows the current state."; return; }
    local args=() status id sev cat fixable title detail
    while IFS=$'\t' read -r status id sev cat fixable title detail; do
        [ "$status" = FAIL ] && [ "$fixable" = yes ] || continue
        args+=("$id" "$title" OFF)
    done < "$RESULTS"
    [ ${#args[@]} -gt 0 ] || { msgbox "Harden" "No automatically fixable findings in the last audit.\nWARN items need manual review (see the report)."; return; }
    local chosen
    chosen=$("$DIALOG" --title "Apply fixes" --backtitle "$BT" \
        --checklist "Space to select the fixes to apply. You will review each change before it is applied; every change is reversible." \
        22 82 12 "${args[@]}" 3>&1 1>&2 2>&3) || return
    chosen=$(echo "$chosen" | tr -d '"')
    [ -n "$chosen" ] || return
    # Show what will change, then confirm.
    # shellcheck disable=SC2086
    "$AUDITXS_BIN" explain $chosen 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' > "$WORK/explain.txt"
    textbox "What will change (review carefully)" "$WORK/explain.txt"
    yesno "Apply changes" "Apply the selected fix(es) now?\nEach change is recorded in a snapshot and reversible." || return
    local cmd=("$AUDITXS_BIN" harden --yes --quiet) c
    for c in $chosen; do cmd+=(--check "$c"); done
    gauge_progress "Applying selected fixes (snapshotted & reversible)…" \
        "$WORK/harden.log" "${cmd[@]}"
    cat "$WORK/harden.log.stderr" >> "$WORK/harden.log" 2>/dev/null
    sed -i 's/\x1b\[[0-9;]*m//g' "$WORK/harden.log"
    textbox "Result (every change is listed & reversible)" "$WORK/harden.log"
    do_audit
}

do_snapshots() {
    "$AUDITXS_BIN" snapshots --format tsv > "$WORK/snaps.tsv" 2>/dev/null
    [ -s "$WORK/snaps.tsv" ] || { msgbox "Snapshots" "No snapshots yet.\nThey are created when hardening changes something."; return; }
    local args=() id date profile n status
    while IFS=$'\t' read -r id date profile n status; do
        args+=("$id" "$date · $n action(s) · $status")
    done < "$WORK/snaps.tsv"
    local sel
    sel=$(menu "Rollback" "Choose a snapshot to revert (undoes every recorded change):" "${args[@]}") || return
    [ -n "$sel" ] || return
    yesno "Rollback" "Revert every change recorded in snapshot $sel?" || return
    "$AUDITXS_BIN" rollback "$sel" --yes > "$WORK/rb.log" 2>&1
    sed -i 's/\x1b\[[0-9;]*m//g' "$WORK/rb.log"
    textbox "Rollback result" "$WORK/rb.log"
}

do_cve() {
    gauge_run "Checking installed packages for known CVEs…" "$AUDITXS_BIN" cve
    "$AUDITXS_BIN" cve > "$WORK/cve.txt" 2>&1
    sed -i 's/\x1b\[[0-9;]*m//g' "$WORK/cve.txt"
    textbox "Vulnerability / CVE report" "$WORK/cve.txt"
}

do_tools() {
    local action
    action=$(menu "Security tools" "Install and run security tooling:" \
        status  "Show which tools are installed" \
        install "Install a security tool" \
        scan    "Run installed scanners" \
        vpn     "Review VPN configuration") || return
    case $action in
        status) "$AUDITXS_BIN" tools status 2>&1 | sed 's/\x1b\[[0-9;]*m//g' > "$WORK/t.txt"; textbox "Security tooling" "$WORK/t.txt" ;;
        vpn)    "$AUDITXS_BIN" tools vpn 2>&1 | sed 's/\x1b\[[0-9;]*m//g' > "$WORK/t.txt"; textbox "VPN review" "$WORK/t.txt" ;;
        scan)   yesno "Scan" "Run all installed external scanners now?\n(This can take several minutes.)" || return
                gauge_run "Running scanners…" "$AUDITXS_BIN" tools scan
                "$AUDITXS_BIN" tools scan 2>&1 | sed 's/\x1b\[[0-9;]*m//g' > "$WORK/t.txt"; textbox "Scanner results" "$WORK/t.txt" ;;
        install)
            local tool
            tool=$(menu "Install a tool" "Choose a tool to install (recorded and reversible):" \
                lynis "Host security auditor" \
                aide "File integrity monitoring" \
                rkhunter "Rootkit detector" \
                clamav "Antivirus / malware scanner" \
                openscap "SCAP compliance scanner" \
                auditd "Linux audit daemon" \
                fail2ban "Log-based ban engine" \
                suricata "Network IDS/IPS") || return
            [ -n "$tool" ] || return
            gauge_run "Installing $tool…" "$AUDITXS_BIN" tools install "$tool"
            "$AUDITXS_BIN" tools install "$tool" > "$WORK/ti.log" 2>&1
            sed -i 's/\x1b\[[0-9;]*m//g' "$WORK/ti.log"
            textbox "Install $tool" "$WORK/ti.log" ;;
    esac
}

do_report() {
    "$AUDITXS_BIN" report --format html --quiet > "$WORK/report.html" 2>/dev/null
    local dest="/var/lib/auditxs/reports/tui-report.html"
    cp -f "$WORK/report.html" "$dest" 2>/dev/null || dest="$WORK/report.html"
    msgbox "Report" "HTML report written to:\n  $dest\n\nCopy it to a workstation to view, or use the JSON report for tooling:\n  sudo auditxs report --format json"
}

do_doctor() {
    "$AUDITXS_BIN" doctor 2>&1 | sed 's/\x1b\[[0-9;]*m//g' > "$WORK/doc.txt"
    textbox "Doctor — installation diagnostics" "$WORK/doc.txt"
}

# --------------------------------------------------------------- main ---
while true; do
    action=$(menu "Main menu" "Transparent, reversible security auditing.\nAudit never changes anything; Harden asks before every change." \
        audit     "Run a read-only security audit" \
        harden    "Review and apply fixes for failed checks (reversible)" \
        snapshots "Roll back a previous hardening run" \
        cve       "Check for known vulnerabilities (CVEs)" \
        tools     "Install and run security tools" \
        report    "Generate an HTML/JSON report" \
        doctor    "Diagnose the installation" \
        quit      "Exit") || break
    case $action in
        audit)     do_audit ;;
        harden)    do_harden ;;
        snapshots) do_snapshots ;;
        cve)       do_cve ;;
        tools)     do_tools ;;
        report)    do_report ;;
        doctor)    do_doctor ;;
        quit|"")   break ;;
    esac
done
clear 2>/dev/null || true
