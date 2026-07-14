#!/usr/bin/env bash
#
# AuditXS — checks/85-database.sh
# Category: Database — exposure and authentication posture of installed
# database servers. ALL database checks are report-only by design:
# changing database configuration without knowing the application landscape
# (and without database credentials) is how audit tools cause outages.
# The findings give the exact settings to change and where.
# Skipped entirely when the database server is not installed.
#

# Addresses a TCP port is bound to, one per line (empty = not listening).
_port_bindings() {
    have ss || return 1
    ss -tlnH 2>/dev/null | awk -v p=":$1\$" '$4 ~ p {print $4}'
}

_all_local() { # true if every given bind address is loopback
    local a
    while IFS= read -r a; do
        case $a in
            127.*|\[::1\]*|::1*) : ;;
            *) return 1 ;;
        esac
    done <<< "$1"
    return 0
}

register_check "DB-001" "Database" "high" "server" \
    "MySQL/MariaDB is not needlessly exposed to the network"
set_meta DB-001 desc "When MySQL/MariaDB is installed, checks whether it listens only on localhost. A database reachable from the network is a direct target for credential attacks and must sit behind strict firewall rules with TLS enforced. Report-only: AuditXS never edits database configuration. If exposure is found, the finding lists the hardening steps: set 'bind-address = 127.0.0.1' (if remote access is not required), 'require_secure_transport = ON' for TLS, run 'mysql_secure_installation' (removes anonymous users/test DB), and enable at-rest encryption (innodb_encrypt_tables / keyring) per your engine's documentation."
set_meta DB-001 nist "PR.DS-01, PR.DS-02, PR.AA-05"

_mysql_installed() {
    unit_exists mysql.service || unit_exists mysqld.service || unit_exists mariadb.service \
        || have mysqld || have mariadbd
}

audit_DB_001() {
    _mysql_installed || { DETAIL="MySQL/MariaDB is not installed"; return 3; }
    have ss || { DETAIL="'ss' not available to inspect listeners"; return 2; }
    local binds
    binds=$(_port_bindings 3306)
    if [ -z "$binds" ]; then
        DETAIL="Not listening on TCP 3306 (socket-only or stopped). Still recommended: run mysql_secure_installation and enable at-rest encryption."
        return 0
    fi
    if _all_local "$binds"; then
        DETAIL="Listening on localhost only ($(echo "$binds" | tr '\n' ' ')). Recommended additionally: require_secure_transport=ON, mysql_secure_installation, at-rest encryption."
        return 0
    fi
    DETAIL="MySQL/MariaDB is reachable from the network: $(echo "$binds" | tr '\n' ' ')
If remote access is NOT required: set 'bind-address = 127.0.0.1' in my.cnf and restart.
If it IS required: restrict the port to specific sources in the firewall, set 'require_secure_transport = ON' (TLS only), use per-host accounts with strong auth, run mysql_secure_installation, and enable at-rest encryption."
    return 2
}

register_check "DB-002" "Database" "high" "server" \
    "PostgreSQL uses strong authentication and is not needlessly exposed"
set_meta DB-002 desc "When PostgreSQL is installed, checks (1) whether it listens only on localhost and (2) whether pg_hba.conf contains 'trust' entries, which grant access WITHOUT ANY authentication. Report-only: AuditXS never edits database configuration. Findings include the fix path: replace 'trust' with 'scram-sha-256', set 'password_encryption = scram-sha-256', restrict listen_addresses, enable TLS (ssl=on), and use encrypted storage for the data directory."
set_meta DB-002 nist "PR.DS-01, PR.DS-02, PR.AA-01"

_postgres_installed() {
    unit_exists postgresql.service || have postgres || [ -d /var/lib/pgsql ] || [ -d /etc/postgresql ]
}

audit_DB_002() {
    _postgres_installed || { DETAIL="PostgreSQL is not installed"; return 3; }
    local binds trust="" f found=""
    for f in /etc/postgresql/*/*/pg_hba.conf /var/lib/pgsql/data/pg_hba.conf /var/lib/postgres/data/pg_hba.conf; do
        [ -f "$f" ] || continue
        found=1
        trust+=$(grep -HnsE '^[^#]*\btrust\b' "$f")$'\n'
    done
    trust=$(printf '%s' "$trust" | grep . || true)

    local issues=""
    if have ss; then
        binds=$(_port_bindings 5432)
        if [ -n "$binds" ] && ! _all_local "$binds"; then
            issues+="Listening on the network: $(echo "$binds" | tr '\n' ' ')— restrict listen_addresses/firewall and require TLS (ssl=on)."$'\n'
        fi
    fi
    if [ -n "$trust" ]; then
        issues+="'trust' authentication entries (NO password required):"$'\n'"$trust"$'\n'"Replace with scram-sha-256 and set password_encryption = scram-sha-256, then reload."
    fi
    if [ -n "$issues" ]; then
        DETAIL="$issues"
        return 2
    fi
    if [ -z "$found" ]; then
        DETAIL="PostgreSQL detected but no readable pg_hba.conf found in standard locations — verify authentication settings manually"
        return 2
    fi
    DETAIL="Local-only listener and no 'trust' authentication entries. Recommended additionally: ssl=on, scram-sha-256 password encryption, encrypted storage for the data directory."
    return 0
}

register_check "DB-003" "Database" "medium" "server" \
    "MySQL/MariaDB local_infile is disabled"
set_meta DB-003 desc "When MySQL/MariaDB is installed, checks that 'local_infile' is OFF. LOAD DATA LOCAL INFILE lets a client (or an attacker who gains SQL access, e.g. via SQL injection) read arbitrary files from the database server's filesystem. Almost no application needs it. Report-only: AuditXS never edits database configuration — the finding gives the exact setting."
set_meta DB-003 nist "PR.DS-01, PR.AA-05"

audit_DB_003() {
    _mysql_installed || { DETAIL="MySQL/MariaDB is not installed"; return 3; }
    local v=""
    if have mysql; then
        v=$(mysql -N -B -e "SELECT @@local_infile;" 2>/dev/null | head -n1)
    fi
    if [ -z "$v" ]; then
        DETAIL="Could not query local_infile (no local socket access). Verify with: SELECT @@local_infile; and set 'local_infile=0' in a [mysqld] drop-in under /etc/mysql/mysql.conf.d/ or /etc/my.cnf.d/."
        return 2
    fi
    if [ "$v" = 0 ]; then DETAIL="local_infile = 0 (disabled)"; return 0; fi
    DETAIL="local_infile = $v (enabled) — allows reading server files via LOAD DATA LOCAL INFILE.
Fix: add 'local_infile=0' under [mysqld] in a drop-in (e.g. /etc/mysql/mysql.conf.d/99-hardening.cnf) and restart the server."
    return 1
}

register_check "DB-004" "Database" "high" "server" \
    "MySQL/MariaDB has no anonymous or passwordless accounts"
set_meta DB-004 desc "When MySQL/MariaDB is installed, checks for anonymous accounts (empty User) and accounts with an empty authentication string — both allow login without credentials. These are exactly what 'mysql_secure_installation' removes. Report-only: account changes require DBA judgement; the finding lists what to run."
set_meta DB-004 nist "PR.AA-01, PR.AA-05"

audit_DB_004() {
    _mysql_installed || { DETAIL="MySQL/MariaDB is not installed"; return 3; }
    have mysql || { DETAIL="mysql client not available to query accounts"; return 2; }
    local anon empty
    anon=$(mysql -N -B -e "SELECT COUNT(*) FROM mysql.user WHERE User='';" 2>/dev/null | head -n1)
    empty=$(mysql -N -B -e "SELECT COUNT(*) FROM mysql.user WHERE authentication_string='' AND plugin NOT IN ('auth_socket','unix_socket');" 2>/dev/null | head -n1)
    if [ -z "$anon$empty" ]; then
        DETAIL="Could not query accounts (no local access). Run 'sudo mysql_secure_installation' to review anonymous/passwordless accounts."
        return 2
    fi
    if [ "${anon:-0}" = 0 ] && [ "${empty:-0}" = 0 ]; then
        DETAIL="No anonymous or passwordless accounts"
        return 0
    fi
    DETAIL="Found ${anon:-0} anonymous and ${empty:-0} passwordless account(s). Remove them with 'sudo mysql_secure_installation' or DROP USER."
    return 1
}
