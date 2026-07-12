#!/usr/bin/env bash
#
# AuditXS — checks/75-apps.sh
# Category: Applications — secure configuration of commonly exposed
# applications (web servers). Fixes use labelled drop-in files, are
# validated with the application's own config test, and are removed
# immediately if validation fails — the same pattern as SSH hardening.
# Skipped entirely when the application is not installed.
#

register_check "APP-001" "Applications" "medium" "server" \
    "nginx does not disclose its version (server_tokens off)"
set_meta APP-001 desc "Checks that nginx is configured with 'server_tokens off' so error pages and the Server header stop advertising the exact version. Version disclosure gives attackers a shortcut to matching exploits; suppressing it is a baseline web-server hardening step."
set_meta APP-001 fix "Writes /etc/nginx/conf.d/99-auditxs.conf containing 'server_tokens off;'. The configuration is validated with 'nginx -t' — if validation fails the file is removed immediately — then nginx is reloaded (no downtime). Applied only when nginx.conf includes /etc/nginx/conf.d."
set_meta APP-001 revert "'sudo auditxs rollback' deletes the drop-in and reloads nginx."

audit_APP_001() {
    have nginx || { DETAIL="nginx is not installed"; return 3; }
    local cfg
    cfg=$(nginx -T 2>/dev/null)
    [ -n "$cfg" ] || { DETAIL="Could not read the nginx configuration (nginx -T failed — fix config errors first)"; return 2; }
    if printf '%s\n' "$cfg" | grep -qE '^[[:space:]]*server_tokens[[:space:]]+off'; then
        DETAIL="server_tokens off"
        return 0
    fi
    DETAIL="nginx advertises its version (server_tokens is on by default)"
    return 1
}

fix_APP_001() {
    if ! grep -qsE '^[[:space:]]*include[[:space:]]+/etc/nginx/conf\.d/\*\.conf' /etc/nginx/nginx.conf; then
        DETAIL="nginx.conf does not include /etc/nginx/conf.d — add 'server_tokens off;' to the http{} block manually"
        return 1
    fi
    local f=/etc/nginx/conf.d/99-auditxs.conf
    track_file "$f"
    write_file "$f" 0644 "# AuditXS APP-001 — do not disclose the nginx version.
# Written by AuditXS $AUDITXS_VERSION on $(date -Is).
# Revert with: sudo auditxs rollback <snapshot>  (or delete this file and reload nginx)
server_tokens off;" || return 1
    if [ "$DRYRUN" != 1 ] && ! nginx -t >/dev/null 2>&1; then
        err "nginx configuration validation failed — removing the drop-in."
        emergency_restore_file "$f"
        DETAIL="nginx -t rejected the change; nothing was applied"
        return 1
    fi
    [ "$DRYRUN" = 1 ] || { svc_active nginx && xrun_q systemctl reload nginx; }
    return 0
}

# Apache layout differs per family:
#   Debian family: /etc/apache2 with conf-available/ + a2enconf
#   Fedora/RHEL:   /etc/httpd/conf.d (included by default)
#   openSUSE:      /etc/apache2/conf.d (included by default)
_apache_ctl() {
    if have apache2ctl; then echo apache2ctl
    elif have apachectl; then echo apachectl
    elif have httpd; then echo "httpd -t"
    else return 1
    fi
}

_apache_installed() {
    unit_exists apache2.service || unit_exists httpd.service || have apache2ctl || have httpd
}

register_check "APP-002" "Applications" "medium" "server" \
    "Apache does not disclose version details"
set_meta APP-002 desc "Checks that Apache is configured with 'ServerTokens Prod' and 'ServerSignature Off' so responses and error pages stop advertising the exact server version and modules. Same rationale as APP-001: version disclosure is free reconnaissance."
set_meta APP-002 fix "Writes a labelled config drop-in (Debian family: /etc/apache2/conf-available/zz-auditxs.conf enabled via symlink; Fedora: /etc/httpd/conf.d/zz-auditxs.conf; openSUSE: /etc/apache2/conf.d/zz-auditxs.conf) setting ServerTokens Prod and ServerSignature Off. Validated with the Apache config test — removed immediately if validation fails — then Apache is reloaded."
set_meta APP-002 revert "'sudo auditxs rollback' deletes the drop-in (and its enabling symlink on the Debian family) and reloads Apache."

audit_APP_002() {
    _apache_installed || { DETAIL="Apache is not installed"; return 3; }
    local roots="/etc/apache2 /etc/httpd" missing=""
    grep -rqsiE '^[[:space:]]*ServerTokens[[:space:]]+Prod' $roots || missing+="ServerTokens=Prod "
    grep -rqsiE '^[[:space:]]*ServerSignature[[:space:]]+Off' $roots || missing+="ServerSignature=Off "
    if [ -n "$missing" ]; then
        DETAIL="Not configured: $missing"
        return 1
    fi
    DETAIL="ServerTokens Prod and ServerSignature Off are set"
    return 0
}

fix_APP_002() {
    local f link="" ctl unit
    if [ -d /etc/apache2/conf-available ]; then
        f=/etc/apache2/conf-available/zz-auditxs.conf
        link=/etc/apache2/conf-enabled/zz-auditxs.conf
        unit=apache2
    elif [ -d /etc/httpd/conf.d ]; then
        f=/etc/httpd/conf.d/zz-auditxs.conf
        unit=httpd
    elif [ -d /etc/apache2/conf.d ]; then
        f=/etc/apache2/conf.d/zz-auditxs.conf
        unit=apache2
    else
        DETAIL="Unrecognized Apache layout — set ServerTokens Prod and ServerSignature Off manually"
        return 1
    fi
    ctl=$(_apache_ctl) || { DETAIL="No Apache control binary found"; return 1; }

    track_file "$f"
    write_file "$f" 0644 "# AuditXS APP-002 — do not disclose Apache version details.
# Written by AuditXS $AUDITXS_VERSION on $(date -Is).
# Revert with: sudo auditxs rollback <snapshot>  (or delete this file and reload Apache)
ServerTokens Prod
ServerSignature Off" || return 1
    if [ -n "$link" ]; then
        track_file "$link"
        [ "$DRYRUN" = 1 ] || ln -sfn ../conf-available/zz-auditxs.conf "$link"
    fi
    if [ "$DRYRUN" != 1 ] && ! $ctl -t >/dev/null 2>&1 && ! $ctl configtest >/dev/null 2>&1; then
        err "Apache configuration validation failed — removing the drop-in."
        [ -n "$link" ] && emergency_restore_file "$link"
        emergency_restore_file "$f"
        DETAIL="Apache config test rejected the change; nothing was applied"
        return 1
    fi
    [ "$DRYRUN" = 1 ] || { svc_active "$unit" && xrun_q systemctl reload "$unit"; }
    return 0
}
