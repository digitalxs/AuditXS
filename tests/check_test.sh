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

echo "== Debian release (DEB-002) via variables =="
DISTRO_FAMILY=debian; DISTRO_ID=debian
DISTRO_VERSION=13 DISTRO_CODENAME=trixie;   audit_DEB_002; ck "DEB-002 Debian 13 → PASS" 0 $?
DISTRO_VERSION=12 DISTRO_CODENAME=bookworm; audit_DEB_002; ck "DEB-002 Debian 12 → PASS" 0 $?
DISTRO_VERSION=11 DISTRO_CODENAME=bullseye; audit_DEB_002; ck "DEB-002 Debian 11 → WARN" 2 $?
DISTRO_VERSION=10 DISTRO_CODENAME=buster;   audit_DEB_002; ck "DEB-002 Debian 10 (EOL) → FAIL" 1 $?

echo
echo "check tests: $PASS passed, $FAILED failed"
[ "$FAILED" -eq 0 ]
