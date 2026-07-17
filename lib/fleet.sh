#!/usr/bin/env bash
#
# AuditXS — lib/fleet.sh
# Fleet mode: run read-only audits across many hosts over SSH and aggregate
# the results. This is the 'auditxs fleet' subcommand.
#
#   auditxs fleet host1 user@host2 --user admin --key ~/.ssh/id_ed25519
#   auditxs fleet --inventory hosts.txt --ask-pass --sudo
#
# By design fleet mode is READ-ONLY: it only ever runs 'auditxs audit' on the
# remote host and collects the JSON result. Hardening is deliberately never
# performed over SSH — apply fixes on each host after reviewing its report.
#
# Security posture:
#   * Key authentication is preferred; password auth uses sshpass with the
#     password passed via the environment (never on the command line, so it
#     does not appear in 'ps').
#   * Host keys are verified (StrictHostKeyChecking=accept-new by default,
#     which pins on first use and refuses changed keys). --strict-host-key
#     requires a pre-known key; --insecure-host-key disables the check (warned).
#   * Each remote host must have AuditXS installed; fleet never pushes code.
#
# Part of AuditXS — https://github.com/digitalxs/AuditXS
#

FLEET_REPORT_DIR_ROOT="/var/lib/auditxs/reports/fleet"

cmd_fleet() {
    local -a hosts=() _h=()
    local inventory="" user="" key="" port=22 timeout=120
    local use_sudo=0 ask_pass=0 shk="accept-new" outdir="" remote_report=0

    while [ $# -gt 0 ]; do
        case $1 in
            --hosts)      IFS=',' read -ra _h <<<"${2:-}"; hosts+=("${_h[@]}"); shift ;;
            --inventory)  inventory=${2:-}; shift ;;
            --user)       user=${2:-}; shift ;;
            --key)        key=${2:-}; shift ;;
            --port)       port=${2:-22}; shift ;;
            --timeout)    timeout=${2:-120}; shift ;;
            --output)     outdir=${2:-}; shift ;;
            --sudo)       use_sudo=1 ;;
            --remote-report) remote_report=1 ;;
            --ask-pass)   ask_pass=1 ;;
            --strict-host-key)   shk=yes ;;
            --insecure-host-key) shk=no ;;
            -*)           die "fleet: unknown option '$1' (see 'auditxs help')" ;;
            *)            hosts+=("$1") ;;
        esac
        shift
    done

    # Gather hosts from an inventory file (one 'user@host' per line, # comments).
    if [ -n "$inventory" ]; then
        [ -r "$inventory" ] || { ax_error AX6008 "file=$inventory"; return 2; }
        local line
        while IFS= read -r line; do
            line=${line%%#*}; line=${line// /}
            [ -n "$line" ] && hosts+=("$line")
        done < "$inventory"
    fi

    if [ ${#hosts[@]} -eq 0 ]; then
        die "fleet: no hosts. Pass them as arguments, --hosts a,b,c, or --inventory FILE.
Example: ${BOLD}auditxs fleet web01 db01 --user admin --key ~/.ssh/id_ed25519 --sudo${RC}"
    fi

    # Validate tooling for the chosen auth mode.
    have ssh || die "fleet requires the 'ssh' client (openssh-client)."
    local sshpass_pre=()
    if [ "$ask_pass" = 1 ]; then
        have sshpass || { ax_error AX6004; return 2; }
        local _pw
        printf '%s' "SSH password (used for all hosts): " >&2
        read -rs _pw; printf '\n' >&2
        export SSHPASS="$_pw"; _pw=""
        sshpass_pre=(sshpass -e)
    fi
    [ "$shk" = no ] && warn "Host-key checking is DISABLED (--insecure-host-key). Only do this on a trusted network."

    # Where to save the per-host JSON reports.
    local ts; ts=$(date +%Y%m%d-%H%M%S)
    outdir=${outdir:-"$FLEET_REPORT_DIR_ROOT/$ts"}
    mkdir -p "$outdir" 2>/dev/null || { ax_error AX1005 "dir=$outdir"; return 2; }
    chmod 750 "$FLEET_REPORT_DIR_ROOT" "$outdir" 2>/dev/null

    nala_box "Fleet audit — ${#hosts[@]} host(s), read-only"
    nala_row "Reports: ${DIM}$outdir${RC}   ·   timeout ${timeout}s/host   ·   host-key: $shk"
    nala_end
    say ""

    # Per-host loop.
    local -a rows=()
    local errored=0 with_fails=0 target
    for target in "${hosts[@]}"; do
        _fleet_one "$target"
    done

    # Clear the password from the environment as soon as we are done with it.
    [ "$ask_pass" = 1 ] && unset SSHPASS

    # Summary table.
    hr
    printf '%b\n' "${BOLD}Fleet summary${RC}"
    printf '  %-28s %-11s %8s %8s %8s %7s\n' "HOST" "STATE" "PASS" "FAIL" "WARN" "SCORE"
    local r
    for r in "${rows[@]}"; do printf '  %s\n' "$r"; done
    hr
    printf '%b\n' "Per-host JSON reports saved under: ${BOLD}$outdir${RC}"
    if [ "$errored" -gt 0 ]; then
        printf '%b\n' "${RED}$errored host(s) could not be audited${RC} — see the error numbers above (${BOLD}auditxs errors <code>${RC})."
    fi
    if [ "$with_fails" -gt 0 ]; then
        printf '%b\n' "${YELLOW}$with_fails host(s) have failing checks${RC} — review each report and harden that host."
    fi
    [ "$errored" -gt 0 ] && return 2
    [ "$with_fails" -gt 0 ] && return 1
    printf '%b\n' "${GREEN}All hosts audited cleanly.${RC}"
    return 0
}

# Run one host (updates rows/errored/with_fails in the caller's scope).
_fleet_one() {
    local target=$1
    # Prepend the default --user if the target has no explicit user@.
    case $target in *@*) : ;; *) [ -n "$user" ] && target="$user@$target" ;; esac

    local host=${target#*@}
    local -a ssh_opts=(-o "ConnectTimeout=10" -o "StrictHostKeyChecking=$shk" -p "$port")
    [ -n "$key" ] && ssh_opts+=(-i "$key")
    if [ "$ask_pass" = 1 ]; then
        ssh_opts+=(-o "BatchMode=no")           # sshpass supplies the password
    else
        ssh_opts+=(-o "BatchMode=yes")          # key/agent only — never prompt
    fi
    [ "$shk" = no ] && ssh_opts+=(-o "UserKnownHostsFile=/dev/null" -o "GlobalKnownHostsFile=/dev/null")

    local remote="auditxs audit --format json --quiet"
    [ "$use_sudo" = 1 ] && remote="sudo -n $remote"

    info "Auditing ${BOLD}$target${RC} …"
    local out err rc
    out=$(timeout "$timeout" "${sshpass_pre[@]}" ssh "${ssh_opts[@]}" "$target" "$remote" 2>"$outdir/.stderr")
    rc=$?
    err=$(cat "$outdir/.stderr" 2>/dev/null); rm -f "$outdir/.stderr"

    # Interpret failures with a specific error number.
    if [ "$rc" -eq 124 ]; then
        ax_error AX6007 "host=$host timeout=${timeout}s"; _fleet_row "$host" "TIMEOUT" - - - -; errored=$((errored+1)); return
    fi
    if [ "$rc" -eq 255 ] || { [ -z "$out" ] && [ "$rc" -ne 0 ]; }; then
        local code=AX6001 state=UNREACHABLE
        if printf '%s' "$err" | grep -qiE 'permission denied|authentication failed|no supported authentication'; then
            code=AX6002; state=AUTHFAIL
        elif printf '%s' "$err" | grep -qiE 'host key verification failed|remote host identification has changed'; then
            code=AX6003; state=HOSTKEY
        elif printf '%s' "$err" | grep -qiE 'command not found|auditxs: not found|no such file'; then
            code=AX6005; state="NO-AUDITXS"
        fi
        ax_error "$code" "host=$host${err:+ | ${err%%$'\n'*}}"
        _fleet_row "$host" "$state" - - - -; errored=$((errored+1)); return
    fi
    if printf '%s' "$err" | grep -qiE 'command not found|auditxs: not found'; then
        ax_error AX6005 "host=$host"; _fleet_row "$host" "NO-AUDITXS" - - - -; errored=$((errored+1)); return
    fi

    # Parse the JSON summary.
    if ! printf '%s' "$out" | grep -q '"summary"'; then
        ax_error AX6006 "host=$host${err:+ | ${err%%$'\n'*}}"
        _fleet_row "$host" "NO-RESULT" - - - -; errored=$((errored+1)); return
    fi
    local safe=${host//[^A-Za-z0-9._-]/_}   # never let a host string traverse paths
    printf '%s\n' "$out" > "$outdir/$safe.json"
    local p f w s sc
    p=$(_fleet_field "$out" pass);  f=$(_fleet_field "$out" fail)
    w=$(_fleet_field "$out" warn);  sc=$(_fleet_score "$out")
    : "${p:=0}" "${f:=0}" "${w:=0}" "${sc:=?}"
    ok "$target audited — ${GREEN}$p pass${RC} · ${RED}$f fail${RC} · ${YELLOW}$w warn${RC} · score $sc/100"
    local state="OK"
    if [ "$f" -gt 0 ] 2>/dev/null; then state="FINDINGS"; with_fails=$((with_fails+1)); fi
    _fleet_row "$host" "$state" "$p" "$f" "$w" "$sc"
    [ "$remote_report" = 1 ] && _fleet_remote_report "$target" "$host" "$safe"
}

# Generate a full HTML report ON the audited host (kept in its own
# /var/lib/auditxs/reports/) and fetch a copy to the controller's output dir.
_fleet_remote_report() {
    local target=$1 host=$2 safe=$3
    local gen="auditxs report --format html --quiet"
    local tee_cmd="tee /var/lib/auditxs/reports/auditxs-report.html"
    if [ "$use_sudo" = 1 ]; then gen="sudo -n $gen"; tee_cmd="sudo -n $tee_cmd"; fi
    local html
    html=$(timeout "$timeout" "${sshpass_pre[@]}" ssh "${ssh_opts[@]}" "$target" \
              "$gen | $tee_cmd" 2>/dev/null)
    if printf '%s' "$html" | grep -q '<html'; then
        printf '%s\n' "$html" > "$outdir/$safe.html"
        say "    ${DIM}full report saved on $host at /var/lib/auditxs/reports/auditxs-report.html (copy: $outdir/$safe.html)${RC}"
    else
        warn "Could not generate the remote report on $host (needs root; try --sudo)."
    fi
}

# Append a plain, aligned summary row (no colour, so column widths stay exact).
_fleet_row() {
    rows+=("$(printf '%-28s %-11s %8s %8s %8s %7s' "$1" "$2" "$3" "$4" "$5" "$6")")
}

# Extract a numeric summary field ("pass"/"fail"/"warn"/"skip") from JSON.
_fleet_field() {
    printf '%s' "$1" | grep -oE "\"$2\": *[0-9]+" | head -1 | grep -oE '[0-9]+' | head -1
}
# Score is a quoted string in the JSON ("score": "82").
_fleet_score() {
    printf '%s' "$1" | grep -oE '"score": *"[0-9]+"' | head -1 | grep -oE '[0-9]+' | head -1
}
