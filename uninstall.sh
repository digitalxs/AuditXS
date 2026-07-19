#!/usr/bin/env bash
#
# AuditXS uninstaller.
# Removes the program and commands. Configuration, snapshots (your rollback
# safety net!) and logs are only removed if you explicitly agree.
#

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RC=$'\e[0m'; BOLD=$'\e[1m'; DIM=$'\e[2m'
    RED=$'\e[31m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'
else
    RC=''; BOLD=''; DIM=''; RED=''; GREEN=''; YELLOW=''
fi

ok()   { printf '%b\n' "${GREEN}✓${RC} $*"; }
warn() { printf '%b\n' "${YELLOW}!${RC} $*"; }
fail() { printf '%b\n' "${RED}✗${RC} $*" >&2; exit 1; }
confirm() {
    local reply
    printf '%b' "${BOLD}$1${RC} [y/N] "
    read -r reply || return 1
    case $reply in [yY]|[yY][eE][sS]) return 0 ;; *) return 1 ;; esac
}

[ "$(id -u)" -eq 0 ] || fail "Please run as root: sudo ./uninstall.sh"

INSTALL_DIR=/opt/auditxs
STATE_DIR=/var/lib/auditxs

printf '%b\n' "${BOLD}Uninstalling AuditXS${RC}"
echo

# Safety: point out snapshots that are still applied.
if [ -d "$STATE_DIR/snapshots" ]; then
    applied=0
    for d in "$STATE_DIR/snapshots"/*/; do
        [ -f "$d/manifest.tsv" ] && [ ! -f "$d/ROLLED_BACK" ] && applied=$((applied + 1))
    done
    if [ "$applied" -gt 0 ]; then
        warn "$applied hardening snapshot(s) are still applied on this system."
        warn "If you want to revert those changes, run ${BOLD}sudo auditxs rollback <id>${RC} BEFORE uninstalling."
        confirm "Continue uninstalling anyway (hardening changes stay in place)?" || exit 1
    fi
fi

# Remove the scheduled-audit units if present
if [ -f /etc/systemd/system/auditxs-audit.timer ]; then
    systemctl disable --now auditxs-audit.timer >/dev/null 2>&1
    rm -f /etc/systemd/system/auditxs-audit.timer /etc/systemd/system/auditxs-audit.service
    systemctl daemon-reload 2>/dev/null
    ok "removed scheduled audit (auditxs-audit.timer)"
fi

for cmd in auditxs auditxs-gui update-auditxs; do
    if [ -e "/usr/local/bin/$cmd" ] || [ -L "/usr/local/bin/$cmd" ]; then
        rm -f "/usr/local/bin/$cmd" && ok "removed /usr/local/bin/$cmd"
    fi
done

[ -f /usr/share/applications/auditxs.desktop ] \
    && rm -f /usr/share/applications/auditxs.desktop && ok "removed desktop launcher"

[ -f /usr/share/polkit-1/actions/com.digitalxs.auditxs.policy ] \
    && rm -f /usr/share/polkit-1/actions/com.digitalxs.auditxs.policy && ok "removed polkit policy"

if [ -d "$INSTALL_DIR" ]; then
    rm -rf "$INSTALL_DIR" && ok "removed $INSTALL_DIR"
fi

echo
if [ -d /etc/auditxs ]; then
    if confirm "Remove configuration (/etc/auditxs)?"; then
        rm -rf /etc/auditxs && ok "removed /etc/auditxs"
    else
        ok "kept /etc/auditxs"
    fi
fi

if [ -d "$STATE_DIR" ]; then
    warn "$STATE_DIR contains snapshots (rollback data), reports and the change ledger."
    if confirm "Remove snapshots, reports and change ledger ($STATE_DIR)? This removes the ability to rollback!"; then
        rm -rf "$STATE_DIR" && ok "removed $STATE_DIR"
    else
        ok "kept $STATE_DIR"
    fi
fi

if [ -d /var/log/auditxs ]; then
    if confirm "Remove logs (/var/log/auditxs)?"; then
        rm -rf /var/log/auditxs && ok "removed /var/log/auditxs"
    else
        ok "kept /var/log/auditxs"
    fi
fi

echo
ok "${BOLD}AuditXS has been uninstalled.${RC}"
printf '%b\n' "${DIM}Note: hardening changes previously applied with 'auditxs harden' remain in effect"
printf '%b\n' "unless you rolled them back first. Files written by AuditXS are labelled with"
printf '%b\n' "'AuditXS' comments (sysctl.d, sshd_config.d, modprobe.d, audit rules).${RC}"
