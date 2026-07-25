#!/usr/bin/env bash
#
# AuditXS — lib/errors.sh
# The AuditXS error catalogue ("error database") and the ax_error() reporter.
#
# Every recoverable failure in AuditXS is reported with a stable, unique error
# number (AXnnnn) so that operators can look up *exactly* what went wrong and
# how to fix it — on the console, in the log, and in docs/ERRORS.md. The
# catalogue below is the single source of truth; `auditxs errors` browses it
# and `auditxs errors --markdown` regenerates the docs table.
#
#   Numbering:  AX1xxx environment · AX2xxx audit · AX3xxx harden
#               AX4xxx snapshot/rollback · AX5xxx tools/packaging
#               AX6xxx fleet/SSH · AX7xxx reporting · AX9xxx internal
#
# Part of AuditXS — https://github.com/digitalxs/AuditXS
#

# Persistent ledger of error occurrences (best-effort; falls back silently).
AX_ERROR_LEDGER="${AX_ERROR_LEDGER:-/var/lib/auditxs/errors.log}"

declare -A AX_ERR_TITLE AX_ERR_WHY AX_ERR_FIX
AX_ERR_CODES=()

# _ax_def <CODE> <title> <why> <fix>
_ax_def() {
    AX_ERR_CODES+=("$1")
    AX_ERR_TITLE[$1]=$2
    AX_ERR_WHY[$1]=$3
    AX_ERR_FIX[$1]=$4
}

# ---- AX1xxx — environment / configuration --------------------------------
_ax_def AX1001 "Unsupported or undetected distribution" \
    "AuditXS could not map this system to a supported package family (Debian, Arch, RedHat/Fedora, SUSE)." \
    "Confirm /etc/os-release exists and names a supported distribution or ID_LIKE; run 'auditxs doctor'."
_ax_def AX1002 "Missing required core tool" \
    "A tool the engine depends on (awk, sed, grep, find, stat…) is not installed." \
    "Install coreutils/gawk/grep/findutils for your distribution; 'auditxs doctor' lists what is missing."
_ax_def AX1003 "Operation requires root privileges" \
    "The requested operation reads or writes privileged state and must run as root." \
    "Re-run with sudo, e.g. 'sudo auditxs audit'."
_ax_def AX1004 "Invalid or missing profile" \
    "PROFILE is not 'server' or 'workstation', so AuditXS cannot decide which checks apply." \
    "Set PROFILE in /etc/auditxs/auditxs.conf (run the installer) or pass --profile server|workstation."
_ax_def AX1005 "State directory not writable" \
    "AuditXS could not create or write under its state directory (snapshots, reports, ledgers)." \
    "Ensure /var/lib/auditxs exists and is writable by root, and that the disk is not full."

# ---- AX2xxx — audit / checks ---------------------------------------------
_ax_def AX2001 "Check module failed to load" \
    "A file under checks/ could not be sourced (syntax error or missing dependency)." \
    "Run 'bash -n checks/<file>.sh' to find the error; see digitalxs-dev-doc.MD for the check API."
_ax_def AX2002 "Check raised an internal error" \
    "An audit_<ID> function returned an unexpected status or crashed while inspecting the system." \
    "Re-run with --debug to see the failing check and its output; file an issue with that trace."
_ax_def AX2003 "Report could not be written" \
    "The HTML/JSON/TSV report file could not be created under the reports directory." \
    "Check that /var/lib/auditxs/reports is writable and the disk has free space."
_ax_def AX2004 "Baseline report unreadable or malformed" \
    "The baseline file passed to --baseline / diff is missing or is not a valid AuditXS JSON report." \
    "Point at a report produced by 'auditxs report --format json'; re-approve with 'auditxs baseline set'."
_ax_def AX2005 "Unknown check ID" \
    "A check ID that does not exist was referenced (e.g. for a waiver or --check filter)." \
    "List valid IDs with 'auditxs list'; IDs look like SSH-001, FW-002, CON-001."
_ax_def AX2006 "Invalid date" \
    "A date was not in the required YYYY-MM-DD format." \
    "Use an ISO date, e.g. --until 2026-12-31."

# ---- AX3xxx — harden / fixes ---------------------------------------------
_ax_def AX3001 "Fix failed to apply" \
    "A fix_<ID> function could not complete; the change was not applied." \
    "Re-run with --debug; review the specific check with 'auditxs explain <ID>'. Nothing was left half-applied."
_ax_def AX3002 "sshd configuration validation failed" \
    "The proposed SSH change did not pass 'sshd -t', so AuditXS restored the previous configuration." \
    "Inspect /etc/ssh/sshd_config.d/99-auditxs.conf and existing config for conflicts; fix and retry."
_ax_def AX3003 "Firewall change blocked by lockout guard" \
    "Enabling the firewall would have dropped the SSH session because the SSH port was not allowed first." \
    "Allow the SSH port (the guard normally does this automatically) or run from local console, then retry."
_ax_def AX3004 "Service reload failed after change" \
    "A daemon (sshd, nginx, apache…) did not reload/restart cleanly after a configuration change." \
    "Check the service status/journal; the change is recorded in the snapshot and can be rolled back."

# ---- AX4xxx — snapshot / rollback ----------------------------------------
_ax_def AX4001 "Snapshot could not be created" \
    "AuditXS could not create the snapshot directory or manifest before making a change, so it refused to proceed." \
    "Ensure /var/lib/auditxs/snapshots is writable and the disk is not full; nothing was changed."
_ax_def AX4002 "Snapshot manifest write failed" \
    "A change could not be recorded in the snapshot manifest, so the change was not carried out (reversibility first)." \
    "Check disk space and permissions on /var/lib/auditxs/snapshots."
_ax_def AX4003 "Rollback target not found" \
    "The snapshot id requested for rollback does not exist." \
    "List snapshots with 'auditxs snapshots' and pass a valid id (or 'latest')."
_ax_def AX4004 "Rollback could not restore an item" \
    "One recorded action could not be reverted (a file was removed, permissions changed externally, etc.)." \
    "Review the rollback log; restore the item manually from the snapshot directory if needed."

# ---- AX5xxx — tools / packaging ------------------------------------------
_ax_def AX5001 "Package installation failed" \
    "The distribution package manager could not install a requested package." \
    "Update your package indexes, check network/repository access, and retry 'auditxs tools install <name>'."
_ax_def AX5002 "Unknown security tool requested" \
    "The tool name passed to 'tools install' is not one AuditXS knows how to install." \
    "Run 'auditxs tools install' with no name to see the known list."
_ax_def AX5003 "External scanner reported errors" \
    "An installed scanner (Lynis, rkhunter, ClamAV, OpenSCAP…) exited non-zero; its findings are still saved." \
    "Read the saved report under /var/lib/auditxs/reports/tools/ — a non-zero exit is often findings, not a crash."
_ax_def AX5004 "SCAP content not found" \
    "OpenSCAP was asked to scan but no SCAP Security Guide (SSG) content is installed." \
    "Install the 'scap-security-guide'/'ssg-*' content package, then re-run 'auditxs tools scan openscap'."

# ---- AX6xxx — fleet / SSH -------------------------------------------------
_ax_def AX6001 "Cannot reach host" \
    "The remote host did not accept a TCP/SSH connection (down, wrong address/port, or firewalled)." \
    "Verify the hostname/IP and port, that sshd is running, and that a firewall is not blocking you."
_ax_def AX6002 "SSH authentication failed" \
    "The remote host rejected the credentials (wrong user, key not authorised, or bad password)." \
    "Check the username; authorise your key with 'ssh-copy-id', or re-check the password. Prefer key auth."
_ax_def AX6003 "Host key verification failed" \
    "The remote host key is unknown or has changed, so AuditXS refused to connect (possible MITM)." \
    "Verify the host key out-of-band and add it to known_hosts. Only use --insecure-host-key on trusted networks."
_ax_def AX6004 "Password auth needs sshpass" \
    "Password authentication was requested but 'sshpass' (used to feed the password to ssh) is not installed." \
    "Install sshpass, or better, switch to key authentication (--key) which needs no extra tooling."
_ax_def AX6005 "Remote auditxs not available" \
    "'auditxs' was not found on the remote host, so it cannot run an audit there." \
    "Install AuditXS on the remote host (or use --sudo if it is installed but needs root), then retry."
_ax_def AX6006 "Remote audit returned no result" \
    "The remote command produced no parseable JSON audit result." \
    "Re-run with --debug to see the raw remote output; confirm the remote 'auditxs audit' works when run directly."
_ax_def AX6007 "Remote command timed out" \
    "The remote host did not finish the audit within the timeout." \
    "Raise --timeout, or check load/connectivity on that host."
_ax_def AX6008 "Inventory unreadable or empty" \
    "The --inventory file could not be read or contained no hosts." \
    "Provide a readable file with one host (user@host) per line, or pass hosts with --hosts."
_ax_def AX6009 "Remote sudo authentication failed" \
    "The remote 'sudo' rejected the password, or the login user is not allowed to run auditxs via sudo." \
    "Check the sudo password (--ask-sudo-pass), and that the SSH user may run 'auditxs' with sudo on that host (a sudoers rule)."

# ---- AX7xxx — reporting ---------------------------------------------------
_ax_def AX7001 "Unknown output format" \
    "An unsupported value was passed to --format." \
    "Use one of: text, json, tsv, html, sarif, csv."

# ---- AX8xxx — alerting ----------------------------------------------------
_ax_def AX8001 "Alert delivery failed" \
    "AuditXS could not deliver a drift/CVE alert to the configured sink (webhook or email)." \
    "Check the sink URL/address and connectivity; test with 'auditxs alert test'."
_ax_def AX8002 "No alert sink configured" \
    "An alert was requested but no webhook or email destination is configured." \
    "Set ALERT_WEBHOOK and/or ALERT_EMAIL in /etc/auditxs/auditxs.conf (see 'auditxs alert')."

# ---- AX9xxx — internal ----------------------------------------------------
_ax_def AX9000 "Unspecified error" \
    "An error occurred that does not yet have a dedicated code." \
    "Re-run with --debug and include the trace when reporting the issue."
_ax_def AX9001 "Unknown error code referenced" \
    "Code path reported an error number that is not defined in the catalogue (this is a bug)." \
    "Please report it at https://github.com/digitalxs/AuditXS/issues."

# --------------------------------------------------------------------------
# ax_error <CODE> [context…] — report a catalogued error: print the number,
# title, why and fix to stderr, and log it (plus a ledger line). Returns 1 so
# callers can write:  ax_error AX6002 "host=$h" ; return 1
ax_error() {
    local code=$1; shift
    local ctx="$*"
    if [ -z "${AX_ERR_TITLE[$code]:-}" ]; then
        ctx="referenced=$code${ctx:+ $ctx}"
        code=AX9001
    fi
    printf '%b\n' "${RED}✗ [${code}]${RC} ${BOLD}${AX_ERR_TITLE[$code]}${RC}" >&2
    printf '%b\n' "    ${DIM}why:${RC} ${AX_ERR_WHY[$code]}" >&2
    printf '%b\n' "    ${DIM}fix:${RC} ${AX_ERR_FIX[$code]}" >&2
    [ -n "$ctx" ] && printf '%b\n' "    ${DIM}context:${RC} $ctx" >&2
    printf '%b\n' "    ${DIM}details:${RC} auditxs errors $code" >&2
    log "[error $code] ${AX_ERR_TITLE[$code]}${ctx:+ | $ctx}"
    _ax_ledger "$code" "$ctx"
    return 1
}

# ax_die <CODE> [context…] — ax_error then exit 1.
ax_die() { ax_error "$@"; exit 1; }

# Append an occurrence to the persistent error ledger (best-effort, never fatal).
_ax_ledger() {
    local dir; dir=$(dirname "$AX_ERROR_LEDGER")
    [ -d "$dir" ] || mkdir -p "$dir" 2>/dev/null || return 0
    printf '%s\t%s\t%s\t%s\n' "$(date -Is 2>/dev/null)" "$1" "${HOSTNAME:-$(hostname 2>/dev/null)}" "$2" \
        >> "$AX_ERROR_LEDGER" 2>/dev/null
    return 0
}

# --------------------------------------------------------------------------
# cmd_errors [CODE|term|--markdown|--log] — browse the error database.
cmd_errors() {
    case "${1:-}" in
        --markdown|--md|markdown) _errors_markdown; return 0 ;;
        --log|log)                _errors_log; return 0 ;;
    esac

    local query=${1:-} code hit=0
    if [ -z "$query" ]; then
        nala_box "AuditXS error catalogue (${#AX_ERR_CODES[@]} codes)"
        for code in "${AX_ERR_CODES[@]}"; do
            nala_row "$(printf '%b%-7s%b %s' "$BOLD" "$code" "$RC" "${AX_ERR_TITLE[$code]}")"
        done
        nala_end
        say ""
        say "Explain one:  ${BOLD}auditxs errors AX6002${RC}   ·   Search:  ${BOLD}auditxs errors ssh${RC}"
        say "Recent occurrences on this host:  ${BOLD}auditxs errors --log${RC}"
        return 0
    fi

    # Exact code, or case-insensitive search across code/title/why.
    local uq=${query^^}
    for code in "${AX_ERR_CODES[@]}"; do
        if [ "$code" = "$uq" ] \
           || printf '%s\n' "$code ${AX_ERR_TITLE[$code]} ${AX_ERR_WHY[$code]}" \
              | grep -qiF -- "$query"; then
            _errors_print_one "$code"; hit=1
        fi
    done
    [ "$hit" = 1 ] || { warn "No error code or catalogue entry matches: $query"; return 1; }
}

_errors_print_one() {
    local c=$1
    hr
    printf '%b\n' "${BOLD}${c}${RC} — ${AX_ERR_TITLE[$c]}"
    printf '%b\n' "  ${DIM}why:${RC} ${AX_ERR_WHY[$c]}"
    printf '%b\n' "  ${DIM}fix:${RC} ${AX_ERR_FIX[$c]}"
}

_errors_log() {
    if [ ! -s "$AX_ERROR_LEDGER" ]; then
        say "No errors recorded yet (${AX_ERROR_LEDGER})."
        return 0
    fi
    nala_box "Recent error occurrences (${AX_ERROR_LEDGER})"
    local ts code host ctx
    while IFS=$'\t' read -r ts code host ctx; do
        nala_row "$(printf '%b%-7s%b %s  %s%s%s  %s' "$BOLD" "$code" "$RC" "$ts" "$DIM" "$host" "$RC" "$ctx")"
    done < <(tail -n 40 "$AX_ERROR_LEDGER")
    nala_end
}

# Regenerate docs/ERRORS.md from the catalogue (single source of truth).
_errors_markdown() {
    local code prefix last_prefix=""
    printf '# AuditXS error catalogue\n\n'
    printf 'Every recoverable failure in AuditXS reports a stable error number '
    printf '(`AXnnnn`). Look one up on the command line with `auditxs errors '
    printf '<code>`, or search titles with `auditxs errors <term>`. Occurrences '
    printf 'are recorded in `/var/lib/auditxs/errors.log` (`auditxs errors --log`).\n\n'
    printf 'Generated from the catalogue in `lib/errors.sh` by `auditxs errors --markdown`.\n\n'
    printf '| Code | Meaning | Why it happens | How to resolve |\n'
    printf '|------|---------|----------------|----------------|\n'
    for code in "${AX_ERR_CODES[@]}"; do
        printf '| `%s` | %s | %s | %s |\n' \
            "$code" "${AX_ERR_TITLE[$code]}" "${AX_ERR_WHY[$code]}" "${AX_ERR_FIX[$code]}"
    done
}
