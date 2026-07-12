#!/usr/bin/env bash
#
# AuditXS updater — installed as 'update-auditxs'.
# Pulls the latest version and refreshes the installation in place,
# keeping your configuration (profile), snapshots and logs.
#

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RC=$'\e[0m'; BOLD=$'\e[1m'; GREEN=$'\e[32m'; RED=$'\e[31m'; YELLOW=$'\e[33m'
else
    RC=''; BOLD=''; GREEN=''; RED=''; YELLOW=''
fi

INSTALL_DIR=/opt/auditxs

[ "$(id -u)" -eq 0 ] || { printf '%b\n' "${RED}✗${RC} Please run as root: ${BOLD}sudo update-auditxs${RC}"; exit 1; }
[ -d "$INSTALL_DIR" ]  || { printf '%b\n' "${RED}✗${RC} AuditXS is not installed in $INSTALL_DIR."; exit 1; }

if [ -d "$INSTALL_DIR/.git" ] && command -v git >/dev/null 2>&1; then
    printf '%b\n' "${BOLD}Updating AuditXS from git...${RC}"
    if git -C "$INSTALL_DIR" pull --ff-only; then
        printf '%b\n' "${GREEN}✓${RC} Repository updated — refreshing installation"
        exec "$INSTALL_DIR/setup.sh" --refresh
    else
        printf '%b\n' "${RED}✗${RC} git pull failed. Fix the repository state in $INSTALL_DIR or reinstall:"
        printf '%b\n' "  git clone https://github.com/digitalxs/AuditXS.git && cd AuditXS && sudo ./setup.sh"
        exit 1
    fi
else
    printf '%b\n' "${YELLOW}!${RC} This installation was not made from a git clone."
    printf '%b\n' "Update by reinstalling:"
    printf '%b\n' "  ${BOLD}git clone https://github.com/digitalxs/AuditXS.git && cd AuditXS && sudo ./setup.sh${RC}"
    exit 1
fi
