#!/usr/bin/env bash
#
# AuditXS — lib/core.sh
# Core utilities: colours, logging, prompts, privilege and environment checks.
#
# Part of AuditXS — transparent, reversible Linux security auditing.
# https://github.com/digitalxs/AuditXS
#

AUDITXS_VERSION="0.5.0"

# ------------------------------------------------------------------ colours
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RC=$'\e[0m'    BOLD=$'\e[1m'     DIM=$'\e[2m'
    RED=$'\e[31m'  GREEN=$'\e[32m'   YELLOW=$'\e[33m'
    BLUE=$'\e[34m' MAGENTA=$'\e[35m' CYAN=$'\e[36m'  WHITE=$'\e[97m'
else
    RC='' BOLD='' DIM='' RED='' GREEN='' YELLOW='' BLUE='' MAGENTA='' CYAN='' WHITE=''
fi

# ------------------------------------------------------------- nala-style UI
# Clean rounded box-drawing output inspired by the 'nala' apt front-end.
# Falls back to plain ASCII when not writing to a colour terminal so logs and
# piped output stay readable. Width is fixed to match hr().
NALA_W=${NALA_W:-68}

_repeat() { local n=$1 c=$2 s=; while [ "$n" -gt 0 ]; do s+=$c; n=$((n-1)); done; printf '%s' "$s"; }

# Visible length of a string with ANSI escapes and multibyte glyphs stripped.
_vlen() {
    local s=$1
    s=$(printf '%s' "$s" | sed $'s/\033\\[[0-9;]*m//g')
    printf '%s' "${#s}"
}

# nala_box <title> — top border with an embedded title (rounded corners).
nala_box() {
    [ "$QUIET" = 1 ] && return 0
    local title=$1 tl=8 fill
    tl=$(_vlen "$title")
    fill=$(( NALA_W - tl - 5 ))
    [ "$fill" -lt 0 ] && fill=0
    printf '%b\n' "${CYAN}╭─${RC} ${BOLD}${title}${RC} ${CYAN}$(_repeat "$fill" '─')╮${RC}"
}

# nala_row <text> — a content line inside a box (left border only, clean look).
nala_row() {
    [ "$QUIET" = 1 ] && return 0
    printf '%b\n' "${CYAN}│${RC} $*"
}

# nala_end — bottom border (matches the width of nala_box's top border).
nala_end() {
    [ "$QUIET" = 1 ] && return 0
    printf '%b\n' "${CYAN}╰$(_repeat "$((NALA_W-2))" '─')╯${RC}"
}

# nala_rule <label> — a labelled section separator, nala style.
nala_rule() {
    [ "$QUIET" = 1 ] && return 0
    local label=$1 ll fill
    ll=$(_vlen "$label")
    fill=$(( NALA_W - ll - 3 ))
    [ "$fill" -lt 0 ] && fill=0
    printf '%b\n' "${DIM}── ${RC}${BOLD}${label}${RC} ${DIM}$(_repeat "$fill" '─')${RC}"
}

# Global behaviour flags (may be overridden by the CLI)
QUIET=${QUIET:-0}
ASSUME_YES=${ASSUME_YES:-0}
DRYRUN=${DRYRUN:-0}
DEBUG=${AUDITXS_DEBUG:-0}

# AX_ROOT — filesystem root prefix. Empty in normal operation (real system);
# set to a fixture directory via AUDITXS_ROOT_PREFIX so check logic can be
# unit-tested against a fake /etc tree without touching the host. Checks that
# read config files should resolve paths through axpath(); see tests/check_test.sh
# and docs/ARCHITECTURE.md ("Fixture-testable checks").
AX_ROOT="${AUDITXS_ROOT_PREFIX:-}"
axpath() { printf '%s%s' "$AX_ROOT" "$1"; }

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

# Debug diagnostics (--debug or AUDITXS_DEBUG=1): timings, return codes and
# internal decisions, printed to stderr and the log file.
debug() {
    [ "$DEBUG" = 1 ] || return 0
    printf '%b\n' "${MAGENTA}[debug]${RC} $*" >&2
    log "[debug] $*"
}
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
