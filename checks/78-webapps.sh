#!/usr/bin/env bash
#
# AuditXS — checks/78-webapps.sh
# Category: WebApps — configuration exposure of common web applications and
# frameworks: WordPress, Drupal, Laravel and Roundcube.
#
# These checks are READ-ONLY (no fix functions): the failures they find —
# world-readable secret files, debug mode left on — must be corrected with
# knowledge of the site's ownership/web user, so auto-changing them could take
# a site offline. AuditXS reports precisely what to fix instead.
#
# All paths resolve through axpath() so the logic is fixture-testable, and each
# check SKIPs cleanly when the application is not present.
#

# Document-root bases to scan (kept shallow and web-specific for speed).
_web_bases() {
    local b out=()
    for b in /var/www/html /var/www /srv/www /srv/http /usr/share/nginx/html; do
        [ -d "$(axpath "$b")" ] && out+=("$(axpath "$b")")
    done
    printf '%s\n' "${out[@]}"
}

# _world_readable <file> — true if others (o) can read the file.
_world_readable() {
    local m; m=$(stat -c %a "$1" 2>/dev/null)
    [ -n "$m" ] && [ "$((0$m & 004))" -ne 0 ]
}

_wp_configs()       { local d; while IFS= read -r d; do [ -n "$d" ] && find "$d" -maxdepth 4 -name wp-config.php 2>/dev/null; done < <(_web_bases); }
_drupal_settings()  { local d; while IFS= read -r d; do [ -n "$d" ] && find "$d" -maxdepth 6 -path '*/sites/*/settings.php' 2>/dev/null; done < <(_web_bases); }
_laravel_envs()     { local d; while IFS= read -r d; do [ -n "$d" ] && find "$d" -maxdepth 4 -name artisan -printf '%h/.env\n' 2>/dev/null; done < <(_web_bases); }
_roundcube_configs() {
    local c; for c in /etc/roundcube/config.inc.php /var/lib/roundcube/config/config.inc.php; do
        [ -f "$(axpath "$c")" ] && echo "$(axpath "$c")"
    done
    local d; while IFS= read -r d; do [ -n "$d" ] && find "$d" -maxdepth 5 -path '*roundcube*/config/config.inc.php' 2>/dev/null; done < <(_web_bases)
}

# ---------------------------------------------------------------- WP-001 ---
register_check "WP-001" "WebApps" "high" "server,workstation" \
    "WordPress wp-config.php is not world-readable"
set_meta WP-001 desc "wp-config.php holds the database credentials and secret keys. If it is readable by other local users (or served as text), those secrets leak. It should be owned by the web user and mode 0640 or stricter. Report-only — correct ownership is site-specific."
set_meta WP-001 revert "No change is made (report-only)."

audit_WP_001() {
    local f found=0 bad=""
    while IFS= read -r f; do
        [ -f "$f" ] || continue; found=1
        _world_readable "$f" && bad+="${f#"$AX_ROOT"} "
    done < <(_wp_configs)
    [ "$found" = 1 ] || { DETAIL="WordPress is not installed"; return 3; }
    if [ -n "$bad" ]; then
        DETAIL="World-readable wp-config.php: ${bad% } — chmod 640 and ensure only the web user can read it"
        return 1
    fi
    DETAIL="wp-config.php is not world-readable"; return 0
}

# ---------------------------------------------------------------- WP-002 ---
register_check "WP-002" "WebApps" "medium" "server,workstation" \
    "WordPress debug mode (WP_DEBUG) is off"
set_meta WP-002 desc "WP_DEBUG shows PHP errors, warnings and file paths to visitors — useful in development, dangerous in production where it leaks internals. This checks that WP_DEBUG is not defined as true. Report-only."
set_meta WP-002 revert "No change is made (report-only)."

audit_WP_002() {
    local f found=0 bad=""
    while IFS= read -r f; do
        [ -f "$f" ] || continue; found=1
        grep -qiE "define\(\s*['\"]WP_DEBUG['\"]\s*,\s*true\s*\)" "$f" 2>/dev/null && bad+="${f#"$AX_ROOT"} "
    done < <(_wp_configs)
    [ "$found" = 1 ] || { DETAIL="WordPress is not installed"; return 3; }
    if [ -n "$bad" ]; then
        DETAIL="WP_DEBUG is enabled in: ${bad% } — set define('WP_DEBUG', false) for production"
        return 1
    fi
    DETAIL="WP_DEBUG is not enabled"; return 0
}

# ---------------------------------------------------------------- DRU-001 ---
register_check "DRU-001" "WebApps" "high" "server,workstation" \
    "Drupal settings.php is not world-readable"
set_meta DRU-001 desc "Drupal's settings.php contains the database credentials and the site's hash salt. It should never be world-readable; Drupal itself warns when it is. This checks the permissions of every settings.php found. Report-only — the correct owner/group depends on your web user."
set_meta DRU-001 revert "No change is made (report-only)."

audit_DRU_001() {
    local f found=0 bad=""
    while IFS= read -r f; do
        [ -f "$f" ] || continue; found=1
        _world_readable "$f" && bad+="${f#"$AX_ROOT"} "
    done < <(_drupal_settings)
    [ "$found" = 1 ] || { DETAIL="Drupal is not installed"; return 3; }
    if [ -n "$bad" ]; then
        DETAIL="World-readable settings.php: ${bad% } — chmod 640 (Drupal recommends 444 only for the web user, not others)"
        return 1
    fi
    DETAIL="Drupal settings.php is not world-readable"; return 0
}

# ---------------------------------------------------------------- LAR-001 ---
register_check "LAR-001" "WebApps" "critical" "server,workstation" \
    "Laravel .env is not world-readable"
set_meta LAR-001 desc "A Laravel .env file holds APP_KEY, database, mail and third-party credentials in plaintext. If it is world-readable (or served over HTTP), the whole application is compromised. It must be readable only by the web user (0640 or stricter) and never inside the public web root. Report-only."
set_meta LAR-001 revert "No change is made (report-only)."

audit_LAR_001() {
    local f found=0 bad=""
    while IFS= read -r f; do
        [ -f "$f" ] || continue; found=1
        _world_readable "$f" && bad+="${f#"$AX_ROOT"} "
    done < <(_laravel_envs)
    [ "$found" = 1 ] || { DETAIL="Laravel (.env) is not installed"; return 3; }
    if [ -n "$bad" ]; then
        DETAIL="World-readable Laravel .env: ${bad% } — chmod 640 and keep it OUTSIDE the public web root"
        return 1
    fi
    DETAIL="Laravel .env is not world-readable"; return 0
}

# ---------------------------------------------------------------- LAR-002 ---
register_check "LAR-002" "WebApps" "high" "server,workstation" \
    "Laravel runs in production mode with debug off"
set_meta LAR-002 desc "Checks that Laravel's .env sets APP_ENV=production and APP_DEBUG=false. With APP_DEBUG=true, the Ignition error page renders full stack traces, environment variables and secrets to any visitor who triggers an error. Report-only."
set_meta LAR-002 revert "No change is made (report-only)."

audit_LAR_002() {
    local f found=0 bad=""
    while IFS= read -r f; do
        [ -f "$f" ] || continue; found=1
        if grep -qiE '^[[:space:]]*APP_DEBUG[[:space:]]*=[[:space:]]*true' "$f" 2>/dev/null; then
            bad+="${f#"$AX_ROOT"}(APP_DEBUG=true) "
        elif grep -qiE '^[[:space:]]*APP_ENV[[:space:]]*=' "$f" 2>/dev/null \
             && ! grep -qiE '^[[:space:]]*APP_ENV[[:space:]]*=[[:space:]]*production' "$f" 2>/dev/null; then
            bad+="${f#"$AX_ROOT"}(APP_ENV!=production) "
        fi
    done < <(_laravel_envs)
    [ "$found" = 1 ] || { DETAIL="Laravel (.env) is not installed"; return 3; }
    if [ -n "$bad" ]; then
        DETAIL="Laravel not in hardened production mode: ${bad% } — set APP_ENV=production and APP_DEBUG=false"
        return 1
    fi
    DETAIL="Laravel is in production mode with debug off"; return 0
}

# ---------------------------------------------------------------- RC-001 ---
register_check "RC-001" "WebApps" "high" "server,workstation" \
    "Roundcube config is protected and the installer is disabled"
set_meta RC-001 desc "Checks Roundcube webmail: its config.inc.php (IMAP/SMTP credentials, des_key) must not be world-readable, and 'enable_installer' must not be left true — the installer can read and rewrite the configuration and must be off in production. Report-only."
set_meta RC-001 revert "No change is made (report-only)."

audit_RC_001() {
    local f found=0 issues=""
    while IFS= read -r f; do
        [ -f "$f" ] || continue; found=1
        _world_readable "$f" && issues+="${f#"$AX_ROOT"}(world-readable) "
        grep -qiE "enable_installer'\]?\s*=\s*true|\['enable_installer'\]\s*=\s*true" "$f" 2>/dev/null \
            && issues+="${f#"$AX_ROOT"}(installer enabled) "
    done < <(_roundcube_configs)
    [ "$found" = 1 ] || { DETAIL="Roundcube is not installed"; return 3; }
    if [ -n "$issues" ]; then
        DETAIL="Roundcube issues: ${issues% } — chmod 640 config.inc.php and set \$config['enable_installer'] = false"
        return 1
    fi
    DETAIL="Roundcube config is protected and the installer is disabled"; return 0
}
