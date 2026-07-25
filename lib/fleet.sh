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

# SSH password authentication needs 'sshpass'. Rather than fail, try to install
# it: directly when root (CLI / web UI), or elevated (pkexec on a desktop, else
# sudo) when unprivileged (Qt / zenity fleet). Installs directly — no snapshot
# side effects, since fleet is read-only. Returns 0 once sshpass is present.
_fleet_ensure_sshpass() {
    have sshpass && return 0
    local cmd=""
    case $PKG in
        apt)    cmd="env DEBIAN_FRONTEND=noninteractive apt-get install -y -q sshpass" ;;
        pacman) cmd="pacman -S --noconfirm --needed sshpass" ;;
        dnf)    cmd="dnf install -y -q sshpass" ;;
        zypper) cmd="zypper --non-interactive --quiet install sshpass" ;;
        *)      return 1 ;;
    esac
    info "Installing 'sshpass' (needed for SSH password authentication)…"
    if [ "$(id -u)" -eq 0 ]; then
        sh -c "$cmd" >/dev/null 2>&1
    elif { [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ]; } && have pkexec; then
        pkexec sh -c "$cmd" >/dev/null 2>&1
    elif have sudo; then
        sudo sh -c "$cmd" >/dev/null 2>&1
    fi
    have sshpass
}

cmd_fleet() {
    local -a hosts=() _h=()
    local inventory="" user="" key="" port=22 timeout=120
    local use_sudo=0 ask_pass=0 ask_sudo_pass=0 shk="accept-new" outdir="" remote_report=0
    local sudo_mode=none

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
            --ask-sudo-pass|--sudo-pass) ask_sudo_pass=1 ;;
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
    # Passwords can be supplied non-interactively via the environment (how the
    # GUIs pass them, since they have no tty): AUDITXS_SSH_PASS for the SSH
    # login, AUDITXS_SUDO_PASS for the remote sudo. Otherwise we prompt. Either
    # way the value is consumed here and the env vars are cleared immediately so
    # they never leak to the ssh/sshpass child processes.
    local sshpass_pre=()
    if [ "$ask_pass" = 1 ]; then
        _fleet_ensure_sshpass || { ax_error AX6004; return 2; }
        if [ -n "${AUDITXS_SSH_PASS+x}" ]; then
            export SSHPASS="$AUDITXS_SSH_PASS"
        else
            local _pw
            printf '%s' "SSH login password (used for all hosts): " >&2
            read -rs _pw; printf '\n' >&2
            export SSHPASS="$_pw"; _pw=""
        fi
        sshpass_pre=(sshpass -e)
    fi
    unset AUDITXS_SSH_PASS

    # Remote privilege escalation. --ask-sudo-pass feeds the remote sudo
    # password to `sudo -S` over the SSH channel's stdin (never on the command
    # line, so it never appears in 'ps'). --sudo without a password assumes
    # passwordless sudo (sudo -n). FLEET_SUDO_PW is cleared right after the run.
    FLEET_SUDO_PW=""
    if [ "$ask_sudo_pass" = 1 ]; then
        sudo_mode=pass
        if [ -n "${AUDITXS_SUDO_PASS+x}" ]; then
            FLEET_SUDO_PW="$AUDITXS_SUDO_PASS"
        else
            printf '%s' "Remote sudo password (used for all hosts): " >&2
            read -rs FLEET_SUDO_PW; printf '\n' >&2
        fi
    elif [ "$use_sudo" = 1 ]; then
        sudo_mode=nopass
    fi
    unset AUDITXS_SUDO_PASS
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

    # Per-host loop (with x/y · % progress on the console and progress file).
    local -a rows=() ov=()
    local errored=0 with_fails=0 target _hi=0
    for target in "${hosts[@]}"; do
        _hi=$((_hi + 1))
        FLEET_PROGRESS="($_hi/${#hosts[@]} · $((_hi * 100 / ${#hosts[@]}))%)"
        progress_file_note "$((_hi * 100 / ${#hosts[@]}))" "$_hi" "${#hosts[@]}" "${target#*@}"
        _fleet_one "$target"
    done
    FLEET_PROGRESS=""

    # Clear the passwords as soon as we are done with them.
    [ "$ask_pass" = 1 ] && unset SSHPASS
    FLEET_SUDO_PW=""; unset FLEET_SUDO_PW

    # Summary table.
    hr
    printf '%b\n' "${BOLD}Fleet summary${RC}"
    printf '  %-28s %-11s %8s %8s %8s %7s\n' "HOST" "STATE" "PASS" "FAIL" "WARN" "SCORE"
    local r
    for r in "${rows[@]}"; do printf '  %s\n' "$r"; done
    hr
    # Aggregated HTML overview — one dashboard for the whole run, linking each
    # host's saved reports. Always generated, even when some hosts errored.
    _fleet_overview_html > "$outdir/index.html"
    printf '%b\n' "Per-host JSON reports saved under: ${BOLD}$outdir${RC}"
    printf '%b\n' "Fleet overview dashboard:          ${BOLD}$outdir/index.html${RC}"
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

# _fleet_run <target> <remote-cmd> — run the remote command over SSH. In
# password-sudo mode it feeds the sudo password to the remote `sudo -S` on the
# SSH channel's stdin using a shell builtin (printf), so the password never
# appears in the process list on either side. Reads ssh_opts/sshpass_pre/
# timeout/sudo_mode/FLEET_SUDO_PW from the enclosing fleet call (dynamic scope).
_fleet_run() {
    local target=$1 cmd=$2
    if [ "$sudo_mode" = pass ]; then
        printf '%s\n' "$FLEET_SUDO_PW" \
            | timeout "$timeout" "${sshpass_pre[@]}" ssh "${ssh_opts[@]}" "$target" "$cmd"
    else
        timeout "$timeout" "${sshpass_pre[@]}" ssh "${ssh_opts[@]}" "$target" "$cmd" </dev/null
    fi
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

    # Build the remote command for the chosen sudo mode. In password mode the
    # audit runs under `sudo -S` reading the password from stdin (see _fleet_run).
    local remote="auditxs audit --format json --quiet"
    case $sudo_mode in
        nopass) remote="sudo -n $remote" ;;
        pass)   remote="sudo -S -p '' $remote" ;;
    esac

    info "Auditing ${BOLD}$target${RC} ${DIM}${FLEET_PROGRESS:-}${RC} …"
    local out err rc
    out=$(_fleet_run "$target" "$remote" 2>"$outdir/.stderr")
    rc=$?
    err=$(cat "$outdir/.stderr" 2>/dev/null); rm -f "$outdir/.stderr"

    # Interpret failures with a specific error number.
    if [ "$rc" -eq 124 ]; then
        ax_error AX6007 "host=$host timeout=${timeout}s"; _fleet_row "$host" "TIMEOUT" - - - -; errored=$((errored+1)); return
    fi
    # Remote sudo rejected the password / user not permitted (distinct from SSH
    # auth). Checked before the generic SSH-auth match so the message is right.
    if printf '%s' "$err" | grep -qiE 'incorrect password|sorry, try again|sudo:.*(password|not allowed|no tty|a terminal is required)|is not in the sudoers'; then
        ax_error AX6009 "host=$host${err:+ | ${err%%$'\n'*}}"
        _fleet_row "$host" "SUDO-FAIL" - - - -; errored=$((errored+1)); return
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
    # A single sudo wraps the whole report|tee pipeline, so password-mode sudo
    # authenticates once (the piped password) and the pipeline runs as root.
    local pipeline="auditxs report --format html --quiet | tee /var/lib/auditxs/reports/auditxs-report.html"
    local rcmd="$pipeline"
    case $sudo_mode in
        pass)   rcmd="sudo -S -p '' sh -c '$pipeline'" ;;
        nopass) rcmd="sudo -n sh -c '$pipeline'" ;;
    esac
    local html
    html=$(_fleet_run "$target" "$rcmd" 2>/dev/null)
    if printf '%s' "$html" | grep -q '<html'; then
        printf '%s\n' "$html" > "$outdir/$safe.html"
        say "    ${DIM}full report saved on $host at /var/lib/auditxs/reports/auditxs-report.html (copy: $outdir/$safe.html)${RC}"
    else
        warn "Could not generate the remote report on $host (needs root; try --sudo or --ask-sudo-pass)."
    fi
}

# Append a plain, aligned summary row (no colour, so column widths stay exact)
# and a structured record for the HTML overview (TAB-separated:
# host, state, pass, fail, warn, score, sanitized-filename-stem).
_fleet_row() {
    rows+=("$(printf '%-28s %-11s %8s %8s %8s %7s' "$1" "$2" "$3" "$4" "$5" "$6")")
    ov+=("$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s' "$1" "$2" "$3" "$4" "$5" "$6" "${1//[^A-Za-z0-9._-]/_}")")
}

# _fleet_overview_html — self-contained Material dashboard aggregating every
# host in this run. Reads the ov[] records and $outdir from the caller's scope
# and prints HTML; relative links point at the sibling per-host report files.
_fleet_overview_html() {
    local rec host state p f w sc safe
    local total=${#ov[@]} okc=0 findc=0 errc=0 sum=0 scored=0
    for rec in "${ov[@]}"; do
        IFS=$'\t' read -r host state p f w sc safe <<<"$rec"
        case $state in
            OK)       okc=$((okc+1)) ;;
            FINDINGS) findc=$((findc+1)) ;;
            *)        errc=$((errc+1)) ;;
        esac
        case $sc in ''|*[!0-9]*) : ;; *) sum=$((sum+sc)); scored=$((scored+1)) ;; esac
    done
    local avg="?" avg_pct=0 avg_color="var(--skip)"
    if [ "$scored" -gt 0 ]; then
        avg=$((sum / scored)); avg_pct=$avg
        if   [ "$avg" -lt 50 ]; then avg_color="var(--err)"
        elif [ "$avg" -lt 75 ]; then avg_color="var(--warn)"
        else                         avg_color="var(--ok)"; fi
    fi
    local err_chip=""
    [ "$errc" -gt 0 ] && err_chip="<span class=\"chip fail\">● $errc unreachable/errored</span>"

    cat <<OVHEAD
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AuditXS fleet overview — $(html_escape "$(hostname 2>/dev/null)")</title>
<style>
  :root {
    --bg:#f6f6fa; --surface:#ffffff; --surface-2:#eef0f6; --on-surface:#1b1b21;
    --on-surface-var:#5a5c66; --outline:#e2e3ec; --primary:#4b56d2; --primary-c:#fff;
    --ok:#1e7d46; --err:#ba1a1a; --warn:#a25b00; --skip:#6b7280;
    --ok-c:#e6f4ea; --err-c:#ffe9e7; --warn-c:#fff3e0; --skip-c:#eceef2;
    --shadow:0 1px 2px rgba(0,0,0,.08),0 2px 8px rgba(0,0,0,.05);
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#121318; --surface:#1c1d24; --surface-2:#23252e; --on-surface:#e4e2e9;
      --on-surface-var:#c6c6d0; --outline:#33343d; --primary:#bcc2ff; --primary-c:#1a2277;
      --ok:#7fd99b; --err:#ffb4ab; --warn:#f5bd6e; --skip:#a8abb4;
      --ok-c:#12331f; --err-c:#3d1512; --warn-c:#3a2a12; --skip-c:#282a32; }
  }
  * { box-sizing:border-box; }
  body { font-family:"Segoe UI",system-ui,-apple-system,Roboto,sans-serif; margin:0;
    background:var(--bg); color:var(--on-surface); line-height:1.5; }
  .wrap { max-width:64rem; margin:0 auto; padding:1.5rem 1.25rem 4rem; }
  header.top { display:flex; align-items:center; gap:.75rem; padding:.5rem 0 1.25rem; }
  .logo { width:2.5rem; height:2.5rem; border-radius:.9rem; background:var(--primary);
    color:var(--primary-c); display:grid; place-items:center; font-weight:700; font-size:1.1rem; }
  h1 { font-size:1.4rem; font-weight:600; margin:0; }
  .sub { color:var(--on-surface-var); font-size:.85rem; }
  .card { background:var(--surface); border:1px solid var(--outline); border-radius:1.25rem;
    box-shadow:var(--shadow); padding:1.25rem 1.4rem; margin:1rem 0; }
  .hero { display:flex; flex-wrap:wrap; gap:1.5rem; align-items:center; }
  .score { --v:$avg_pct; width:8rem; height:8rem; border-radius:50%; flex:0 0 auto;
    background:conic-gradient($avg_color calc(var(--v)*1%), var(--surface-2) 0);
    display:grid; place-items:center; }
  .score > div { width:6.2rem; height:6.2rem; border-radius:50%; background:var(--surface);
    display:grid; place-items:center; text-align:center; }
  .score b { font-size:1.8rem; } .score span { font-size:.7rem; color:var(--on-surface-var); }
  .chips { display:flex; flex-wrap:wrap; gap:.5rem; margin-top:.25rem; }
  .chip { display:inline-flex; align-items:center; gap:.35rem; padding:.35rem .75rem;
    border-radius:2rem; font-size:.82rem; font-weight:600; }
  .chip.pass { background:var(--ok-c); color:var(--ok); }
  .chip.fail { background:var(--err-c); color:var(--err); }
  .chip.warn { background:var(--warn-c); color:var(--warn); }
  .note { background:var(--warn-c); color:var(--warn); border-radius:1rem; padding:.9rem 1.2rem;
    margin:1rem 0; font-size:.85rem; }
  .tablewrap { overflow-x:auto; }
  table { border-collapse:collapse; width:100%; min-width:44rem; }
  th,td { text-align:left; padding:.6rem .75rem; border-bottom:1px solid var(--outline);
    vertical-align:middle; font-size:.88rem; }
  th { color:var(--on-surface-var); font-weight:600; font-size:.72rem; text-transform:uppercase;
    letter-spacing:.04em; }
  tr:last-child td { border-bottom:none; }
  .state { display:inline-block; min-width:3.2rem; text-align:center; padding:.2rem .55rem;
    border-radius:.6rem; font-weight:700; font-size:.72rem; }
  .state.ok   { background:var(--ok-c);   color:var(--ok); }
  .state.warn { background:var(--warn-c); color:var(--warn); }
  .state.err  { background:var(--err-c);  color:var(--err); }
  .hostname { font-family:ui-monospace,"Cascadia Code",monospace; font-size:.85rem; }
  .scorebar { display:inline-block; width:7rem; height:.5rem; border-radius:.3rem;
    background:var(--surface-2); vertical-align:middle; margin-right:.5rem; overflow:hidden; }
  .scorebar > span { display:block; height:100%; border-radius:.3rem; }
  .scnum { font-weight:700; font-size:.85rem; }
  .links a { color:var(--primary); text-decoration:none; font-weight:600; font-size:.82rem;
    margin-right:.5rem; }
  code { background:var(--surface-2); padding:.1rem .35rem; border-radius:.35rem; font-size:.82em; }
  footer { color:var(--on-surface-var); font-size:.78rem; margin-top:2.5rem;
    border-top:1px solid var(--outline); padding-top:1rem; text-align:center; line-height:1.7; }
  footer .brand { font-weight:700; font-size:.92rem; color:var(--on-surface); letter-spacing:.02em; }
  footer .heart { color:#e0245e; }
  footer .copy strong { color:var(--on-surface); }
  footer a { color:var(--primary); text-decoration:none; font-weight:600; }
  @media (max-width:640px){ .hero{gap:1rem} .score{width:6.5rem;height:6.5rem}
    .score>div{width:5rem;height:5rem} }
</style>
</head>
<body>
<div class="wrap">
<header class="top">
  <div class="logo">A</div>
  <div>
    <h1>AuditXS fleet overview</h1>
    <div class="sub">controller $(html_escape "$(hostname 2>/dev/null)") · $(date -Is 2>/dev/null) · v$AUDITXS_VERSION</div>
  </div>
</header>

<div class="card hero">
  <div class="score"><div><div><b>$avg</b><br><span>avg / 100</span></div></div></div>
  <div style="flex:1 1 15rem">
    <div style="font-weight:600;margin-bottom:.4rem">$total host(s) audited <span class="sub">(read-only, over SSH)</span></div>
    <div class="chips">
      <span class="chip pass">● $okc clean</span>
      <span class="chip warn">● $findc with findings</span>
      $err_chip
    </div>
  </div>
</div>

<div class="note">Fleet mode is <strong>read-only</strong>: nothing on any host was changed.
To fix findings, review a host's report below, then run <code>sudo auditxs harden</code>
<em>on that host</em> — hardening is deliberately never performed over SSH.</div>

<div class="card" style="padding:.5rem .5rem"><div class="tablewrap"><table>
<tr><th>Host</th><th>State</th><th>Pass</th><th>Fail</th><th>Warn</th><th>Score</th><th>Reports</th></tr>
OVHEAD

    local cls links bar barc
    for rec in "${ov[@]}"; do
        IFS=$'\t' read -r host state p f w sc safe <<<"$rec"
        case $state in
            OK)       cls=ok ;;
            FINDINGS) cls=warn ;;
            *)        cls=err ;;
        esac
        links=""
        [ -f "$outdir/$safe.json" ] && links="<a href=\"$safe.json\">JSON</a>"
        [ -f "$outdir/$safe.html" ] && links="$links<a href=\"$safe.html\">HTML</a>"
        [ -z "$links" ] && links="—"
        case $sc in ''|*[!0-9]*) bar=0; sc="—" ;; *) bar=$sc ;; esac
        if   [ "$bar" -lt 50 ]; then barc="var(--err)"
        elif [ "$bar" -lt 75 ]; then barc="var(--warn)"
        else                         barc="var(--ok)"; fi
        printf '<tr><td class="hostname">%s</td><td><span class="state %s">%s</span></td><td>%s</td><td>%s</td><td>%s</td><td><span class="scorebar"><span style="width:%s%%;background:%s"></span></span><span class="scnum">%s</span></td><td class="links">%s</td></tr>\n' \
            "$(html_escape "$host")" "$cls" "$(html_escape "$state")" "$p" "$f" "$w" \
            "$bar" "$barc" "$sc" "$links"
    done

    cat <<'OVFOOT'
</table></div></div>
<footer>
<div>Generated by <strong>AuditXS</strong> fleet mode — transparent, reversible Linux security auditing.</div>
<div>Error numbers: <code>auditxs errors &lt;code&gt;</code> · Compare runs: <code>auditxs diff &lt;old.json&gt; &lt;new.json&gt;</code></div>
<div class="brand" style="margin-top:1rem">🛡️ AuditXS</div>
<div class="made">Made with <span class="heart">&#10084;</span> from Canada &#127809;</div>
<div class="copy">&copy; 2026 <strong>DigitalXS</strong> — Programming &amp; Development · <a href="https://digitalxs.ca">digitalxs.ca</a></div>
</footer>
</div>
</body>
</html>
OVFOOT
}

# Extract a numeric summary field ("pass"/"fail"/"warn"/"skip") from JSON.
_fleet_field() {
    printf '%s' "$1" | grep -oE "\"$2\": *[0-9]+" | head -1 | grep -oE '[0-9]+' | head -1
}
# Score is a quoted string in the JSON ("score": "82").
_fleet_score() {
    printf '%s' "$1" | grep -oE '"score": *"[0-9]+"' | head -1 | grep -oE '[0-9]+' | head -1
}
