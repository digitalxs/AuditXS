#!/usr/bin/env bash
#
# AuditXS — checks/76-webserver.sh
# Category: Applications — deeper nginx TLS/header checks and the Varnish
# cache/reverse-proxy. Complements the version-disclosure checks in 75-apps.sh.
#
# nginx checks read the effective config with 'nginx -T' (like APP-001) and
# SKIP cleanly when nginx is absent. Varnish checks inspect the running
# command line and secret file. Deep TLS/VCL tuning is report-only — it is too
# environment-specific to change automatically.
#

_nginx_dump() { nginx -T 2>/dev/null; }

# ---------------------------------------------------------------- NGX-001 ---
register_check "NGX-001" "Applications" "high" "server" \
    "nginx does not offer obsolete TLS (SSLv3/TLS 1.0/1.1)"
set_meta NGX-001 desc "Checks the effective 'ssl_protocols' in the nginx configuration. SSLv3, TLS 1.0 and TLS 1.1 are deprecated and vulnerable (POODLE, BEAST) — a hardened server offers only TLS 1.2 and 1.3. Report-only: the correct TLS policy depends on the clients you must support."
set_meta NGX-001 revert "No change is made (report-only)."

audit_NGX_001() {
    have nginx || { DETAIL="nginx is not installed"; return 3; }
    local cfg; cfg=$(_nginx_dump)
    [ -n "$cfg" ] || { DETAIL="Could not read nginx configuration (nginx -T failed — fix config errors first)"; return 2; }
    local proto
    proto=$(printf '%s\n' "$cfg" | grep -iE '^[[:space:]]*ssl_protocols' | head -1)
    [ -n "$proto" ] || { DETAIL="No ssl_protocols directive found (TLS not configured, or defaults in use)"; return 3; }
    if printf '%s' "$proto" | grep -qiE 'SSLv3|TLSv1(\.1)?([^.0-9]|$)'; then
        DETAIL="nginx offers obsolete TLS: ${proto# } — set 'ssl_protocols TLSv1.2 TLSv1.3;'"
        return 1
    fi
    DETAIL="nginx offers only modern TLS (${proto# })"
    return 0
}

# ---------------------------------------------------------------- NGX-002 ---
register_check "NGX-002" "Applications" "low" "server" \
    "nginx sends HSTS on TLS sites"
set_meta NGX-002 desc "Checks that an HTTPS-serving nginx sends a 'Strict-Transport-Security' (HSTS) header, which tells browsers to only ever connect over TLS and blunts SSL-stripping attacks. Report-only — enabling HSTS is a commitment (browsers will refuse plain HTTP for the max-age), so it must be a deliberate choice."
set_meta NGX-002 revert "No change is made (report-only)."

audit_NGX_002() {
    have nginx || { DETAIL="nginx is not installed"; return 3; }
    local cfg; cfg=$(_nginx_dump)
    [ -n "$cfg" ] || { DETAIL="Could not read nginx configuration"; return 2; }
    printf '%s' "$cfg" | grep -qiE 'listen[^;]*ssl|listen[^;]*443' \
        || { DETAIL="nginx does not serve TLS (no HSTS needed)"; return 3; }
    if printf '%s' "$cfg" | grep -qiE 'add_header[[:space:]]+Strict-Transport-Security'; then
        DETAIL="nginx sends the Strict-Transport-Security (HSTS) header"; return 0
    fi
    DETAIL="TLS is served but no HSTS header — consider: add_header Strict-Transport-Security \"max-age=31536000\" always;"
    return 2
}

# ---- Varnish ---------------------------------------------------------------
_varnish_installed() { have varnishd || have varnishadm || [ -d "$(axpath /etc/varnish)" ]; }
# The running varnishd command line (management -T / secret -S live here).
_varnishd_cmdline() {
    if have pgrep; then pgrep -a varnishd 2>/dev/null | head -1; fi
}

# ---------------------------------------------------------------- VRN-001 ---
register_check "VRN-001" "Applications" "high" "server" \
    "Varnish admin interface is bound to localhost"
set_meta VRN-001 desc "Checks the Varnish management interface (varnishd -T). It must listen on the loopback address only (127.0.0.1:6082); if it is bound to a public address, anyone who can reach it — combined with the secret — can reconfigure the cache. Report-only."
set_meta VRN-001 revert "No change is made (report-only)."

audit_VRN_001() {
    _varnish_installed || { DETAIL="Varnish is not installed"; return 3; }
    local cmd; cmd=$(_varnishd_cmdline)
    [ -n "$cmd" ] || { DETAIL="varnishd is not running — cannot inspect the -T management binding"; return 2; }
    local t; t=$(printf '%s\n' "$cmd" | grep -oE '\-T[[:space:]]*[^ ]+' | head -1 | sed 's/^-T[[:space:]]*//')
    [ -n "$t" ] || { DETAIL="No explicit -T management address (Varnish default is 127.0.0.1 — verify)"; return 0; }
    case $t in
        127.0.0.1:*|localhost:*|\[::1\]:*|127.0.0.1|::1) DETAIL="Varnish management interface bound to loopback ($t)"; return 0 ;;
        0.0.0.0:*|\*:*|:::*|*) DETAIL="Varnish management interface is bound to $t — restrict it to 127.0.0.1:6082"; return 1 ;;
    esac
}

# ---------------------------------------------------------------- VRN-002 ---
register_check "VRN-002" "Applications" "medium" "server" \
    "Varnish admin secret file is not world-readable"
set_meta VRN-002 desc "Checks the permissions of the Varnish admin secret (default /etc/varnish/secret). This file authenticates connections to the management interface; if it is world-readable, any local user can control the cache. It should be 0600/0640 and owned by root."
set_meta VRN-002 fix "Tightens the secret file to mode 0640 (root:root/varnish). The previous mode is recorded and restored on rollback."
set_meta VRN-002 revert "'sudo auditxs rollback' restores the previous mode of the secret file."

_varnish_secret() {
    local s; s=$(_varnishd_cmdline | grep -oE '\-S[[:space:]]*[^ ]+' | head -1 | sed 's/^-S[[:space:]]*//')
    [ -n "$s" ] && { echo "$s"; return; }
    echo "$(axpath /etc/varnish/secret)"
}

audit_VRN_002() {
    _varnish_installed || { DETAIL="Varnish is not installed"; return 3; }
    local s; s=$(_varnish_secret)
    [ -f "$s" ] || { DETAIL="No Varnish secret file found at $s"; return 3; }
    local mode; mode=$(stat -c %a "$s" 2>/dev/null)
    if [ -n "$mode" ] && [ "$((0$mode & 044))" -ne 0 ]; then
        DETAIL="Varnish secret $s is mode $mode (group/world-readable) — should be 0640 or stricter"
        return 1
    fi
    DETAIL="Varnish secret $s is mode ${mode:-?} (not world-readable)"
    return 0
}
fix_VRN_002() {
    local s; s=$(_varnish_secret)
    [ -f "$s" ] || return 1
    record_mode "$s" 640
    xrun chmod 640 "$s"
}
