#!/usr/bin/env bash
#
# AuditXS — lib/webservice.sh
# The web UI as a toggleable background service: `auditxs webservice`.
#
# By default the web UI is a foreground, loopback-only command you start when
# you need it. This makes it a persistent systemd service you can switch on and
# off, reachable locally and — as an explicit, warned opt-in — remotely.
#
#   auditxs webservice enable            # on, localhost only (reach via SSH tunnel)
#   auditxs webservice enable --remote   # on, reachable from the network (0.0.0.0)
#   auditxs webservice status            # is it on? URL + access token
#   auditxs webservice disable           # off
#   auditxs webservice token --reset     # rotate the access token
#
# SECURITY: the web UI drives privileged operations. Remote mode is guarded —
# a stable bearer token is required on every request, and AuditXS prints loud
# guidance to put TLS / a reverse proxy in front and firewall the port. The
# token lives in a root-only file so a running service has a stable credential.
#
# Part of AuditXS — https://github.com/digitalxs/AuditXS
#

WEB_UNIT_NAME="auditxs-web.service"
WEB_UNIT_PATH="/etc/systemd/system/${WEB_UNIT_NAME}"
WEB_TOKEN_FILE="/etc/auditxs/web-token"
WEB_DEFAULT_PORT=9000

# _web_token — read the persistent token, creating it (root-only) if absent.
_web_token() {
    if [ ! -s "$WEB_TOKEN_FILE" ]; then
        mkdir -p "$(dirname "$WEB_TOKEN_FILE")" 2>/dev/null
        # urlsafe-ish 32-byte token
        (LC_ALL=C tr -dc 'A-Za-z0-9_-' </dev/urandom | head -c 43; echo) > "$WEB_TOKEN_FILE" 2>/dev/null
        chmod 600 "$WEB_TOKEN_FILE" 2>/dev/null
    fi
    cat "$WEB_TOKEN_FILE" 2>/dev/null
}

# _web_primary_ip — a routable address to build the remote URL from.
_web_primary_ip() {
    hostname -I 2>/dev/null | awk '{print $1}' | grep -E '^[0-9]' || echo "<this-host>"
}

# _web_unit_field <key> — read a stored key from the unit's ExecStart (port/bind).
_web_unit_field() {
    [ -f "$WEB_UNIT_PATH" ] || return 1
    grep -oE -- "--$1 [^ ]+" "$WEB_UNIT_PATH" 2>/dev/null | head -1 | awk '{print $2}'
}

cmd_webservice() {
    local sub=${1:-status}; [ $# -gt 0 ] && shift
    case $sub in
        status)      _webservice_status ;;
        enable|on)   _webservice_enable "$@" ;;
        disable|off) _webservice_disable ;;
        token)       _webservice_token "$@" ;;
        *) die "Usage: auditxs webservice status | enable [--port N] [--remote | --bind ADDR] | disable | token [--reset]" ;;
    esac
}

_webservice_status() {
    if ! has_systemd; then warn "No systemd — the web service toggle needs systemd."; return 1; fi
    local active enabled port bind token host
    active=$(systemctl is-active "$WEB_UNIT_NAME" 2>/dev/null)
    enabled=$(systemctl is-enabled "$WEB_UNIT_NAME" 2>/dev/null)
    port=$(_web_unit_field port); bind=$(_web_unit_field bind)
    : "${port:=$WEB_DEFAULT_PORT}" "${bind:=127.0.0.1}"
    nala_box "AuditXS web service"
    nala_row "State:   ${BOLD}${active:-inactive}${RC} (boot: ${enabled:-disabled})"
    nala_row "Bind:    ${bind}:${port}   ·   $([ "$bind" = 127.0.0.1 ] && echo 'local only (SSH-tunnel for remote)' || echo 'REMOTE — reachable from the network')"
    if [ "$active" = active ]; then
        token=$(cat "$WEB_TOKEN_FILE" 2>/dev/null)
        host=$([ "$bind" = 127.0.0.1 ] && echo 127.0.0.1 || { [ "$bind" = 0.0.0.0 ] && _web_primary_ip || echo "$bind"; })
        nala_row "URL:     ${BOLD}http://${host}:${port}/?t=${token}${RC}"
    fi
    nala_end
    [ "$active" = active ]
}

_webservice_enable() {
    require_root "webservice enable"
    if ! has_systemd; then ax_error AX8003 "no systemd on this host"; return 1; fi
    local port=$WEB_DEFAULT_PORT bind=127.0.0.1
    while [ $# -gt 0 ]; do
        case $1 in
            --port)   port=${2:?--port needs a value}; shift ;;
            --bind)   bind=${2:?--bind needs a value}; shift ;;
            --remote) bind=0.0.0.0 ;;
            -*)       die "webservice enable: unknown option '$1'" ;;
        esac
        shift
    done
    case $port in ''|*[!0-9]*) die "webservice: invalid port '$port'" ;; esac

    _web_token >/dev/null   # ensure the token file exists

    if [ "$bind" != 127.0.0.1 ] && [ "$bind" != localhost ]; then
        warn "Enabling REMOTE access (bind ${bind}). The web UI runs privileged operations."
        warn "Anyone who can reach ${bind}:${port} and has the token controls this host."
        warn "Put TLS / a reverse proxy in front and restrict the port with your firewall."
    fi

    umask 022
    cat > "$WEB_UNIT_PATH" <<EOF
# AuditXS web UI service — managed by 'auditxs webservice'. Do not edit by hand.
[Unit]
Description=AuditXS web UI
Documentation=man:auditxs(8)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${AUDITXS_SELF} web --service --no-open --port ${port} --bind ${bind} --token-file ${WEB_TOKEN_FILE}
Restart=on-failure
RestartSec=3
User=root
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "$WEB_UNIT_PATH"
    xrun_q systemctl daemon-reload
    if xrun_q systemctl enable --now "$WEB_UNIT_NAME"; then
        ok "AuditXS web service is ${BOLD}ON${RC} (bind ${bind}:${port}, starts at boot)."
        ledger "webservice enabled (bind=$bind port=$port)"
        _webservice_status
    else
        ax_error AX8003 "systemctl enable --now $WEB_UNIT_NAME failed"
        return 1
    fi
}

_webservice_disable() {
    require_root "webservice disable"
    if ! has_systemd; then ax_error AX8003 "no systemd on this host"; return 1; fi
    xrun_q systemctl disable --now "$WEB_UNIT_NAME" 2>/dev/null
    if [ -f "$WEB_UNIT_PATH" ]; then xrun_q rm -f "$WEB_UNIT_PATH"; xrun_q systemctl daemon-reload; fi
    ok "AuditXS web service is ${BOLD}OFF${RC}."
    ledger "webservice disabled"
}

_webservice_token() {
    require_root "webservice token"
    if [ "${1:-}" = "--reset" ]; then
        rm -f "$WEB_TOKEN_FILE"
        _web_token >/dev/null
        ok "Access token rotated."
        if has_systemd && [ "$(systemctl is-active "$WEB_UNIT_NAME" 2>/dev/null)" = active ]; then
            xrun_q systemctl restart "$WEB_UNIT_NAME"
            ok "Web service restarted with the new token."
        fi
        ledger "webservice token rotated"
    fi
    say "Access token: ${BOLD}$(_web_token)${RC}"
    say "  File: ${DIM}${WEB_TOKEN_FILE}${RC} (root-only)"
}
