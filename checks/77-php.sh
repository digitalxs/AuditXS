#!/usr/bin/env bash
#
# AuditXS — checks/77-php.sh
# Category: PHP — hardening of PHP runtime configuration for web-facing SAPIs
# (Apache mod_php and PHP-FPM). Skipped when PHP is not installed. Safe,
# web-relevant directives are fixed through a clearly-labelled conf.d drop-in;
# directives that commonly break applications are report-only.
#

# Web-facing SAPI conf.d directories (Debian/Ubuntu layout: /etc/php/<v>/<sapi>/conf.d).
_php_confd_dirs() {
    local d
    for d in /etc/php/*/apache2/conf.d /etc/php/*/fpm/conf.d; do
        [ -d "$d" ] && echo "$d"
    done
    # RHEL/SUSE single-tree layout
    [ -d /etc/php.d ] && echo /etc/php.d
}

_php_installed() { have php || [ -d /etc/php ] || [ -d /etc/php.d ]; }

# Effective value of a directive: last non-comment assignment wins across
# php.ini and every conf.d file (mirrors PHP's own load order).
_php_effective() {
    local key=$1 f v="" hit
    for f in /etc/php/*/apache2/php.ini /etc/php/*/fpm/php.ini /etc/php.ini \
             /etc/php/*/apache2/conf.d/*.ini /etc/php/*/fpm/conf.d/*.ini /etc/php.d/*.ini; do
        [ -f "$f" ] || continue
        hit=$(grep -iE "^[[:space:]]*${key}[[:space:]]*=" "$f" 2>/dev/null | tail -n1)
        [ -n "$hit" ] && v=$(printf '%s' "$hit" | sed -E 's/^[^=]*=[[:space:]]*//; s/[[:space:]]*$//')
    done
    printf '%s' "$v"
}

_php_truthy() { case "${1,,}" in on|1|true|yes) return 0 ;; *) return 1 ;; esac; }

# Write a directive into a drop-in for every web SAPI conf.d dir.
_php_set() { # <key> <value>
    local key=$1 val=$2 d f wrote=0
    while IFS= read -r d; do
        [ -n "$d" ] || continue
        f="$d/99-auditxs.ini"
        track_file "$f"
        if [ "$DRYRUN" = 1 ]; then
            say "  ${DIM}[dry-run] would set '$key = $val' in $f${RC}"
            wrote=1; continue
        fi
        if [ ! -f "$f" ]; then
            printf '; AuditXS PHP hardening — written by AuditXS %s\n; Revert with: sudo auditxs rollback <snapshot>\n' \
                "$AUDITXS_VERSION" > "$f"
            chmod 644 "$f"
        fi
        if grep -qiE "^[[:space:]]*${key}[[:space:]]*=" "$f"; then
            sed -i -E "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${val}|I" "$f"
        else
            printf '%s = %s\n' "$key" "$val" >> "$f"
        fi
        wrote=1
    done <<< "$(_php_confd_dirs)"
    [ "$wrote" = 1 ] || { DETAIL="No PHP web SAPI conf.d directory found"; return 1; }
    say "  (restart php-fpm / apache2 for the change to take effect)"
    return 0
}

register_check "PHP-001" "PHP" "medium" "server" \
    "PHP does not expose its version (expose_php Off)"
set_meta PHP-001 desc "Checks that 'expose_php' is Off so PHP stops advertising its exact version in the X-Powered-By response header and on error pages. Version disclosure hands attackers a shortcut to matching exploits."
set_meta PHP-001 fix "Sets 'expose_php = Off' in a 99-auditxs.ini drop-in inside each web SAPI's conf.d directory (Apache mod_php and PHP-FPM). Restart the web server / php-fpm to apply."
set_meta PHP-001 revert "'sudo auditxs rollback' removes the drop-in (or restores its previous content)."
set_meta PHP-001 nist "PR.PS-01"

audit_PHP_001() {
    _php_installed || { DETAIL="PHP is not installed"; return 3; }
    local v; v=$(_php_effective expose_php)
    if [ -n "$v" ] && ! _php_truthy "$v"; then DETAIL="expose_php = $v"; return 0; fi
    DETAIL="expose_php is ${v:-On (default)} — PHP advertises its version"
    return 1
}
fix_PHP_001() { _php_set expose_php Off; }

register_check "PHP-002" "PHP" "medium" "server" \
    "PHP does not display errors to visitors (display_errors Off)"
set_meta PHP-002 desc "Checks that 'display_errors' is Off. Rendered PHP errors leak file paths, SQL fragments and stack details to anyone hitting the page — reconnaissance gold. Errors should go to the log, not the browser."
set_meta PHP-002 fix "Sets 'display_errors = Off' (and leaves logging intact) in the 99-auditxs.ini drop-in for each web SAPI. Restart php-fpm / apache2 to apply."
set_meta PHP-002 revert "'sudo auditxs rollback' removes the drop-in (or restores its previous content)."
set_meta PHP-002 nist "PR.PS-01, PR.PS-04"

audit_PHP_002() {
    _php_installed || { DETAIL="PHP is not installed"; return 3; }
    local v; v=$(_php_effective display_errors)
    if [ -n "$v" ] && ! _php_truthy "$v"; then DETAIL="display_errors = $v"; return 0; fi
    DETAIL="display_errors is ${v:-On} — PHP errors are shown to visitors"
    return 1
}
fix_PHP_002() { _php_set display_errors Off; }

register_check "PHP-003" "PHP" "medium" "server" \
    "PHP session cookies are hardened (HttpOnly + Secure + SameSite)"
set_meta PHP-003 desc "Checks session.cookie_httponly (blocks JavaScript from reading the session cookie — mitigates XSS session theft), session.cookie_secure (cookie only sent over HTTPS) and session.cookie_samesite (CSRF mitigation). These are baseline web-session protections."
set_meta PHP-003 fix "Sets session.cookie_httponly = On, session.cookie_secure = On and session.cookie_samesite = Lax in the 99-auditxs.ini drop-in for each web SAPI. NOTE: cookie_secure requires the site to be served over HTTPS; on a plain-HTTP test site, sessions will only work once TLS is in place. Restart php-fpm / apache2 to apply."
set_meta PHP-003 revert "'sudo auditxs rollback' removes the drop-in (or restores its previous content)."
set_meta PHP-003 nist "PR.DS-02, PR.AA-05"

audit_PHP_003() {
    _php_installed || { DETAIL="PHP is not installed"; return 3; }
    local ho sec ss bad=""
    ho=$(_php_effective session.cookie_httponly)
    sec=$(_php_effective session.cookie_secure)
    ss=$(_php_effective session.cookie_samesite)
    _php_truthy "$ho"  || bad+="session.cookie_httponly=${ho:-off} "
    _php_truthy "$sec" || bad+="session.cookie_secure=${sec:-off} "
    case "${ss,,}" in lax|strict) : ;; *) bad+="session.cookie_samesite=${ss:-unset} "; esac
    if [ -n "$bad" ]; then DETAIL="Weak session cookie settings: $bad"; return 1; fi
    DETAIL="session cookies: HttpOnly + Secure + SameSite=$ss"
    return 0
}
fix_PHP_003() {
    _php_set session.cookie_httponly On \
        && _php_set session.cookie_secure On \
        && _php_set session.cookie_samesite Lax
}

register_check "PHP-004" "PHP" "high" "server" \
    "Dangerous PHP functions are reviewed (disable_functions)"
set_meta PHP-004 desc "Checks whether high-risk functions that turn a PHP-code-execution bug into full command execution (exec, system, shell_exec, passthru, popen, proc_open, and the config-reading php_uname) are listed in 'disable_functions'. Report-only: many legitimate applications and control panels rely on some of these, so blindly disabling them can break the site — AuditXS shows you the recommended list to add after confirming your apps do not need them."
set_meta PHP-004 nist "PR.PS-01"

audit_PHP_004() {
    _php_installed || { DETAIL="PHP is not installed"; return 3; }
    local cur missing="" fn
    cur=$(_php_effective disable_functions)
    for fn in exec system shell_exec passthru proc_open popen; do
        case ",${cur// /}," in *",$fn,"*) : ;; *) missing+="$fn " ;; esac
    done
    if [ -z "$missing" ]; then DETAIL="disable_functions covers the common command-execution functions"; return 0; fi
    DETAIL="Not in disable_functions: $missing
If your applications do not need them, add to a PHP conf.d drop-in:
  disable_functions = exec,system,shell_exec,passthru,proc_open,popen"
    return 2
}
