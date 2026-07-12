#!/usr/bin/env bash
#
# AuditXS — lib/core.sh
# Core utilities: colours, logging, prompts, privilege and environment checks.
#
# Part of AuditXS — transparent, reversible Linux security auditing.
# https://github.com/digitalxs/AuditXS
#

AUDITXS_VERSION="0.2.0"

# ------------------------------------------------------------------ colours
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RC=$'\e[0m'    BOLD=$'\e[1m'     DIM=$'\e[2m'
    RED=$'\e[31m'  GREEN=$'\e[32m'   YELLOW=$'\e[33m'
    BLUE=$'\e[34m' MAGENTA=$'\e[35m' CYAN=$'\e[36m'  WHITE=$'\e[97m'
else
    RC='' BOLD='' DIM='' RED='' GREEN='' YELLOW='' BLUE='' MAGENTA='' CYAN='' WHITE=''
fi

# Global behaviour flags (may be overridden by the CLI)
QUIET=${QUIET:-0}
ASSUME_YES=${ASSUME_YES:-0}
DRYRUN=${DRYRUN:-0}

# ------------------------------------------------------------------ logging
init_logging() {
    if [ "$(id -u)" -eq 0 ]; then
        LOG_DIR=/var/log/auditxs
    else
        LOG_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/auditxs"
    fi
    mkdir -p "$LOG_DIR" 2>/dev/null || LOG_DIR="${TMPDIR:-/tmp}"
    LOG_FILE="$LOG_DIR/auditxs-$(date +%Y%m%d).log"
}

# File-only log line (plain text, timestamped)
log() {
    [ -n "${LOG_FILE:-}" ] || return 0
    printf '%s %s\n' "$(date '+%F %T')" "$*" >> "$LOG_FILE" 2>/dev/null
    return 0
}

say()  { [ "$QUIET" = 1 ] || printf '%b\n' "$*"; log "$*"; }
info() { [ "$QUIET" = 1 ] || printf '%b\n' "${CYAN}::${RC} $*"; log "[info] $*"; }
ok()   { [ "$QUIET" = 1 ] || printf '%b\n' "${GREEN}✓${RC} $*";  log "[ok] $*"; }
warn() { printf '%b\n' "${YELLOW}!${RC} $*" >&2; log "[warn] $*"; }
err()  { printf '%b\n' "${RED}✗${RC} $*" >&2;   log "[error] $*"; }
die()  { err "$*"; exit 1; }
hr()   { [ "$QUIET" = 1 ] || printf '%b\n' "${DIM}──────────────────────────────────────────────────────────────────${RC}"; }

# ------------------------------------------------------------------ prompts
# confirm "Question?"  → 0 = yes.  Honours --yes; reads the terminal directly
# so it works even when stdout is being captured.
confirm() {
    [ "$ASSUME_YES" = 1 ] && return 0
    local reply
    printf '%b' "${BOLD}$1${RC} [y/N] " > /dev/tty 2>/dev/null || printf '%b' "${BOLD}$1${RC} [y/N] "
    read -r reply < /dev/tty 2>/dev/null || return 1
    case $reply in [yY]|[yY][eE][sS]) return 0 ;; *) return 1 ;; esac
}

# ------------------------------------------------------------------ helpers
have() { command -v "$1" >/dev/null 2>&1; }

require_root() {
    [ "$(id -u)" -eq 0 ] || die "This operation requires root. Re-run with: ${BOLD}sudo auditxs $*${RC}"
}

has_systemd() { [ -d /run/systemd/system ]; }

svc_active()  { has_systemd && systemctl is-active --quiet "$1" 2>/dev/null; }
svc_enabled() { has_systemd && [ "$(systemctl is-enabled "$1" 2>/dev/null)" = "enabled" ]; }
unit_exists() { has_systemd && systemctl list-unit-files "$1" 2>/dev/null | grep -q "^$1"; }

# Debian/Ubuntu call the unit "ssh", everyone else "sshd".
ssh_service_name() {
    if unit_exists ssh.service; then echo ssh; else echo sshd; fi
}

# ------------------------------------------------------------------ actions
# xrun — run a command, or just print it in dry-run mode. Every executed
# command is logged, which is part of the transparency contract.
xrun() {
    if [ "$DRYRUN" = 1 ]; then
        printf '%b\n' "  ${DIM}[dry-run] would run: $*${RC}"
        log "[dry-run] $*"
        return 0
    fi
    log "[exec] $*"
    "$@"
}

# xrun_q — like xrun but silences the command's stdout (not the dry-run note).
xrun_q() {
    if [ "$DRYRUN" = 1 ]; then
        xrun "$@"
        return 0
    fi
    log "[exec] $*"
    "$@" > /dev/null
}

# write_file <path> <mode> <content> — create/overwrite a file. In dry-run
# mode the full intended content is shown instead.
write_file() {
    local path=$1 mode=$2 content=$3
    if [ "$DRYRUN" = 1 ]; then
        printf '%b\n' "  ${DIM}[dry-run] would write $path (mode $mode):${RC}"
        printf '%s\n' "$content" | sed 's/^/      /'
        return 0
    fi
    mkdir -p "$(dirname "$path")" || return 1
    printf '%s\n' "$content" > "$path" || return 1
    chmod "$mode" "$path" || return 1
    log "[write] $path (mode $mode)"
}
