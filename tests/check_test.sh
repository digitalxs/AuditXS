#!/usr/bin/env bash
#
# AuditXS check tests — exercise real audit_<ID> logic against a FAKE root
# tree via AUDITXS_ROOT_PREFIX (AX_ROOT). No privileges, no host changes;
# safe to run anywhere. Covers the checks that read config files and have
# been converted to axpath() (Accounts, Filesystem) plus variable-driven
# checks (Debian release).
#
set -u
cd "$(dirname "$0")/.." || exit 1

PASS=0
FAILED=0
ck() { # ck <desc> <expected-rc> <actual-rc>
    if [ "$2" = "$3" ]; then
        PASS=$((PASS + 1))
    else
        FAILED=$((FAILED + 1))
        echo "FAIL: $1 — expected rc $2, got $3" >&2
        [ -n "${DETAIL:-}" ] && echo "      DETAIL: ${DETAIL:0:100}" >&2
    fi
}

FIX=$(mktemp -d)
trap 'rm -rf "$FIX"' EXIT
export AUDITXS_ROOT_PREFIX="$FIX"
QUIET=1

# shellcheck disable=SC1091
. lib/core.sh
. lib/distro.sh
. lib/backup.sh
. lib/registry.sh
. lib/report.sh
. lib/fixlib.sh
. lib/maintenance.sh
. lib/cve.sh
. lib/tools.sh
. lib/lynis.sh
for c in checks/*.sh; do . "$c"; done
AX_ROOT="$FIX"          # belt-and-suspenders (already set from the env at source time)
mkdir -p "$FIX/etc"

echo "== Accounts (ACC-*) against fixtures =="

# ACC-001 — a second UID-0 account is a backdoor (WARN); clean passwd PASS.
printf 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n' > "$FIX/etc/passwd"
audit_ACC_001; ck "ACC-001 clean passwd → PASS" 0 $?
printf 'root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/root:/bin/bash\n' > "$FIX/etc/passwd"
audit_ACC_001; ck "ACC-001 second UID-0 → WARN" 2 $?

# ACC-002 — empty password field.
printf 'root:$6$x:19000:0:99999:7:::\nalice:$6$y:19000:0:99999:7:::\n' > "$FIX/etc/shadow"
audit_ACC_002; ck "ACC-002 no empty passwords → PASS" 0 $?
printf 'root:$6$x:19000:0:99999:7:::\nbob::19000:0:99999:7:::\n' > "$FIX/etc/shadow"
audit_ACC_002; ck "ACC-002 empty password → FAIL" 1 $?

# ACC-003 — password aging policy in login.defs.
printf 'PASS_MAX_DAYS\t365\nPASS_MIN_DAYS\t1\nPASS_WARN_AGE\t7\nUID_MIN\t1000\n' > "$FIX/etc/login.defs"
audit_ACC_003; ck "ACC-003 sane aging → PASS" 0 $?
printf 'PASS_MAX_DAYS\t99999\nPASS_MIN_DAYS\t0\nPASS_WARN_AGE\t7\nUID_MIN\t1000\n' > "$FIX/etc/login.defs"
audit_ACC_003; ck "ACC-003 weak aging → FAIL" 1 $?

# ACC-006 — restrictive umask (server profile) in login.defs.
printf 'UMASK\t027\nUID_MIN\t1000\n' > "$FIX/etc/login.defs"
audit_ACC_006; ck "ACC-006 umask 027 → PASS" 0 $?
printf 'UMASK\t022\nUID_MIN\t1000\n' > "$FIX/etc/login.defs"
audit_ACC_006; ck "ACC-006 umask 022 → FAIL" 1 $?

# ACC-005 — system accounts must not have a login shell.
printf 'UID_MIN\t1000\n' > "$FIX/etc/login.defs"
printf 'root:x:0:0::/root:/bin/bash\nsvc:x:150:150::/home/svc:/usr/sbin/nologin\n' > "$FIX/etc/passwd"
audit_ACC_005; ck "ACC-005 nologin system acct → PASS" 0 $?
printf 'root:x:0:0::/root:/bin/bash\nsvc:x:150:150::/home/svc:/bin/bash\n' > "$FIX/etc/passwd"
audit_ACC_005; ck "ACC-005 system acct with shell → FAIL" 1 $?

echo "== Filesystem (FS-004) against fixtures =="

# FS-004 — sensitive file permissions (only shadow present in the fixture).
: > "$FIX/etc/shadow"; chmod 640 "$FIX/etc/shadow"
audit_FS_004; ck "FS-004 shadow 640 → PASS" 0 $?
chmod 644 "$FIX/etc/shadow"
audit_FS_004; ck "FS-004 shadow 644 (world-readable) → FAIL" 1 $?
chmod 600 "$FIX/etc/shadow"
audit_FS_004; ck "FS-004 shadow 600 → PASS" 0 $?

echo "== Fail2ban (F2B-*) against fixtures =="
mkdir -p "$FIX/etc/fail2ban/jail.d"

# F2B-002 — lenient maxretry + short bantime → WARN
printf '[DEFAULT]\nmaxretry = 10\nbantime = 60\nignoreip = 127.0.0.1/8 ::1\n' > "$FIX/etc/fail2ban/jail.local"
audit_F2B_002; ck "F2B-002 lenient policy → WARN" 2 $?

# F2B-002 — sane policy → PASS ; F2B-004 loopback+RFC1918 → PASS
printf '[DEFAULT]\nmaxretry = 4\nbantime = 1h\nignoreip = 127.0.0.1/8 ::1 10.0.0.0/8\n' > "$FIX/etc/fail2ban/jail.local"
audit_F2B_002; ck "F2B-002 sane policy → PASS" 0 $?
audit_F2B_004; ck "F2B-004 loopback/RFC1918 ignoreip → PASS" 0 $?

# F2B-004 — a broad public range in ignoreip → WARN
printf '[DEFAULT]\nignoreip = 127.0.0.1/8 8.0.0.0/8 0.0.0.0/0\n' > "$FIX/etc/fail2ban/jail.local"
audit_F2B_004; ck "F2B-004 broad ignoreip → WARN" 2 $?

# F2B-003 — recidive jail enabled in jail.d → PASS ; absent → FAIL
printf '[recidive]\nenabled = true\n' > "$FIX/etc/fail2ban/jail.d/recidive.conf"
audit_F2B_003; ck "F2B-003 recidive enabled → PASS" 0 $?
rm -f "$FIX/etc/fail2ban/jail.d/recidive.conf"
printf '[DEFAULT]\nmaxretry = 4\n' > "$FIX/etc/fail2ban/jail.local"
audit_F2B_003; ck "F2B-003 no recidive → FAIL" 1 $?
rm -rf "${FIX:?}/etc/fail2ban"

echo "== WebApps (WP/LAR) against fixtures =="
mkdir -p "$FIX/var/www/html/site"
# WP-001 — world-readable wp-config.php → FAIL ; 640 → PASS
printf "<?php define('DB_PASSWORD','x');\n" > "$FIX/var/www/html/site/wp-config.php"
chmod 644 "$FIX/var/www/html/site/wp-config.php"
audit_WP_001; ck "WP-001 world-readable wp-config → FAIL" 1 $?
chmod 640 "$FIX/var/www/html/site/wp-config.php"
audit_WP_001; ck "WP-001 wp-config 640 → PASS" 0 $?
# WP-002 — WP_DEBUG true → FAIL
printf "<?php define('WP_DEBUG', true);\n" > "$FIX/var/www/html/site/wp-config.php"
audit_WP_002; ck "WP-002 WP_DEBUG true → FAIL" 1 $?
# Laravel .env
: > "$FIX/var/www/html/site/artisan"
printf 'APP_ENV=production\nAPP_DEBUG=false\n' > "$FIX/var/www/html/site/.env"
chmod 640 "$FIX/var/www/html/site/.env"
audit_LAR_001; ck "LAR-001 .env 640 → PASS" 0 $?
audit_LAR_002; ck "LAR-002 production/debug off → PASS" 0 $?
printf 'APP_ENV=local\nAPP_DEBUG=true\n' > "$FIX/var/www/html/site/.env"
audit_LAR_002; ck "LAR-002 APP_DEBUG=true → FAIL" 1 $?
chmod 644 "$FIX/var/www/html/site/.env"
audit_LAR_001; ck "LAR-001 world-readable .env → FAIL" 1 $?
rm -rf "${FIX:?}/var/www"

echo "== BIND (BND-003/004) against fixtures =="
mkdir -p "$FIX/etc/bind"
printf 'options {\n allow-transfer { any; };\n dnssec-validation no;\n};\n' > "$FIX/etc/bind/named.conf.options"
audit_BND_003; ck "BND-003 allow-transfer any → FAIL" 1 $?
audit_BND_004; ck "BND-004 dnssec-validation no → FAIL" 1 $?
printf 'options {\n allow-transfer { none; };\n dnssec-validation auto;\n};\n' > "$FIX/etc/bind/named.conf.options"
audit_BND_003; ck "BND-003 allow-transfer none → PASS" 0 $?
audit_BND_004; ck "BND-004 dnssec-validation auto → PASS" 0 $?
rm -rf "${FIX:?}/etc/bind"

echo "== Containers (CON-*) against fixtures =="
mkdir -p "$FIX/etc/docker"
printf '{ "hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"] }\n' > "$FIX/etc/docker/daemon.json"
audit_CON_001; ck "CON-001 tcp without tls → FAIL" 1 $?
printf '{ "userns-remap": "default", "live-restore": true }\n' > "$FIX/etc/docker/daemon.json"
audit_CON_001; ck "CON-001 unix socket only → PASS" 0 $?
audit_CON_002; ck "CON-002 userns-remap set → PASS" 0 $?
audit_CON_005; ck "CON-005 live-restore true → PASS" 0 $?
printf '{}\n' > "$FIX/etc/docker/daemon.json"
audit_CON_002; ck "CON-002 no userns-remap → WARN" 2 $?
rm -rf "${FIX:?}/etc/docker"

echo "== Boot (BOOT-001) against fixtures =="
mkdir -p "$FIX/boot/grub"
printf 'set timeout=5\nmenuentry linux { linux /vmlinuz }\n' > "$FIX/boot/grub/grub.cfg"
audit_BOOT_001; ck "BOOT-001 no password → FAIL" 1 $?
printf 'set superusers="admin"\npassword_pbkdf2 admin grub.pbkdf2.sha512.x\n' > "$FIX/boot/grub/grub.cfg"
audit_BOOT_001; ck "BOOT-001 password set → PASS" 0 $?
rm -rf "${FIX:?}/boot"

echo "== Database TLS (DB-005/006) against fixtures =="
mkdir -p "$FIX/etc/postgresql/16/main" "$FIX/etc/mysql"
printf "listen_addresses = 'localhost'\nssl = off\n" > "$FIX/etc/postgresql/16/main/postgresql.conf"
audit_DB_005; ck "DB-005 ssl off → FAIL" 1 $?
printf "ssl = on\n" > "$FIX/etc/postgresql/16/main/postgresql.conf"
audit_DB_005; ck "DB-005 ssl on → PASS" 0 $?
printf '[mysqld]\nrequire_secure_transport = ON\n' > "$FIX/etc/mysql/my.cnf"
audit_DB_006; ck "DB-006 require_secure_transport ON → PASS" 0 $?
printf '[mysqld]\nbind-address = 127.0.0.1\n' > "$FIX/etc/mysql/my.cnf"
audit_DB_006; ck "DB-006 no TLS enforcement → WARN" 2 $?
rm -rf "${FIX:?}/etc/postgresql" "$FIX/etc/mysql"

echo "== Debian release (DEB-002) via variables =="
DISTRO_FAMILY=debian; DISTRO_ID=debian
DISTRO_VERSION=13 DISTRO_CODENAME=trixie;   audit_DEB_002; ck "DEB-002 Debian 13 → PASS" 0 $?
DISTRO_VERSION=12 DISTRO_CODENAME=bookworm; audit_DEB_002; ck "DEB-002 Debian 12 → PASS" 0 $?
DISTRO_VERSION=11 DISTRO_CODENAME=bullseye; audit_DEB_002; ck "DEB-002 Debian 11 → WARN" 2 $?
DISTRO_VERSION=10 DISTRO_CODENAME=buster;   audit_DEB_002; ck "DEB-002 Debian 10 (EOL) → FAIL" 1 $?

echo "== SMB hardening (SMB-001/002) against fixtures =="
mkdir -p "$FIX/etc/samba"
# SMB-001 — SMBv1/NT1 must be refused via 'server min protocol'.
rm -f "$FIX/etc/samba/smb.conf"
audit_SMB_001; ck "SMB-001 no Samba → SKIP" 3 $?
printf '[global]\n   workgroup = WG\n' > "$FIX/etc/samba/smb.conf"
audit_SMB_001; ck "SMB-001 min protocol unset → FAIL" 1 $?
printf '[global]\n   server min protocol = NT1\n' > "$FIX/etc/samba/smb.conf"
audit_SMB_001; ck "SMB-001 NT1 → FAIL" 1 $?
printf '[global]\n   server min protocol = SMB2\n' > "$FIX/etc/samba/smb.conf"
audit_SMB_001; ck "SMB-001 SMB2 → PASS" 0 $?
# SMB-002 — signing (or encryption) must be enforced.
printf '[global]\n   server min protocol = SMB2\n' > "$FIX/etc/samba/smb.conf"
audit_SMB_002; ck "SMB-002 signing unset → FAIL" 1 $?
printf '[global]\n   server signing = mandatory\n' > "$FIX/etc/samba/smb.conf"
audit_SMB_002; ck "SMB-002 signing mandatory → PASS" 0 $?
printf '[global]\n   smb encrypt = required\n' > "$FIX/etc/samba/smb.conf"
audit_SMB_002; ck "SMB-002 smb encrypt required → PASS" 0 $?
rm -rf "${FIX:?}/etc/samba"

echo "== Inactive accounts (ACC-010) human-account helper =="
printf 'UID_MIN\t1000\n' > "$FIX/etc/login.defs"
printf 'root:x:0:0::/root:/bin/bash\ndaemon:x:1:1::/x:/usr/sbin/nologin\nalice:x:1001:1001::/home/alice:/bin/bash\nbob:x:1002:1002::/home/bob:/usr/sbin/nologin\ncarol:x:1003:1003::/home/carol:/bin/zsh\n' > "$FIX/etc/passwd"
ck "ACC-010 human login accounts" "alice carol" "$(_human_login_accounts | tr '\n' ' ' | sed 's/ $//')"

echo "== Lynis report parser =="
cat > "$FIX/lynis-report.dat" <<'LYN'
lynis_version=3.0.9
hardening_index=64
warning[]=SSH-7408|SSH configuration is not hardened|-|-
warning[]=KRNL-5820|Ptrace protection is not enabled|-|-
suggestion[]=AUTH-9328|Default umask could be more strict|-|-
LYN
ck "Lynis hardening_index parsed"   "64" "$(_lynis_report_get "$FIX/lynis-report.dat" hardening_index)"
ck "Lynis warnings parsed"          "2"  "$(_lynis_report_get "$FIX/lynis-report.dat" 'warning[]' | wc -l | tr -d ' ')"
ck "Lynis finding id formatting"    "SSH-7408: SSH configuration is not hardened" \
   "$(_lynis_finding_id 'SSH-7408|SSH configuration is not hardened|-|-')"
ck "Lynis missing report → rc1"     "1" "$(_lynis_report_get "$FIX/none.dat" hardening_index >/dev/null 2>&1; echo $?)"

echo "== External-tool join (rkhunter parser + finding accounting) =="
printf '[10:00:00] Warning: Test warning one\n[10:00:01] Info: not a warning\n[10:00:02] Warning: Test warning two\n[10:00:03] Warning: Test warning one\n' > "$FIX/rkhunter.log"
RKHUNTER_LOG="$FIX/rkhunter.log"
ck "rkhunter warnings parsed (deduped)" "2" "$(_rkhunter_warnings | wc -l | tr -d ' ')"
EXT_IDS=(); N_EXT_WARN=0; N_EXT_INFO=0
_ext_add RKH-001 rkhunter WARN "Test warning one"
_ext_add LYNIS-S001 Lynis INFO "AUTH-1: tidy something"
ck "external warning tally"    "1" "$N_EXT_WARN"
ck "external suggestion tally" "1" "$N_EXT_INFO"
ck "external ids recorded"     "2" "${#EXT_IDS[@]}"
ck "external detail stored"    "Test warning one" "${EXT_DETAIL[RKH-001]}"
# chkrootkit/debsecan folding via _fold_file_lines (plain-text stdout tools).
printf 'Checking bindshell... INFECTED\na benign progress line\nsuspicious file /tmp/x found\n' > "$FIX/ck.out"
EXT_IDS=(); N_EXT_WARN=0; N_EXT_INFO=0
_fold_file_lines "$FIX/ck.out" CHKR chkrootkit WARN 'INFECTED|suspicious|Warning|Vulnerable'
ck "chkrootkit keep-regex drops benign" "2" "${#EXT_IDS[@]}"
printf 'CVE-2023-0001 openssl\n\nCVE-2023-0002 curl\n' > "$FIX/ds.out"
EXT_IDS=(); N_EXT_WARN=0; N_EXT_INFO=0
_fold_file_lines "$FIX/ds.out" DSEC debsecan WARN
ck "debsecan folds non-empty lines"     "2" "${#EXT_IDS[@]}"

echo
echo "check tests: $PASS passed, $FAILED failed"
[ "$FAILED" -eq 0 ]
