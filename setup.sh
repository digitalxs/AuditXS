#!/usr/bin/env bash
#
# AuditXS installer — in the spirit of dxsbash (https://github.com/digitalxs/dxsbash)
#
# Installs AuditXS to /opt/auditxs, links the 'auditxs', 'auditxs-gui' and
# 'update-auditxs' commands into /usr/local/bin, and configures the machine's
# role profile (Server or Workstation) in /etc/auditxs/auditxs.conf.
#
# Usage:
#   sudo ./setup.sh                  interactive install
#   sudo ./setup.sh --server -y      non-interactive server install
#   sudo ./setup.sh --workstation -y non-interactive workstation install
#   sudo ./setup.sh --refresh        reinstall files, keep configuration
#   sudo ./setup.sh --uninstall      remove AuditXS
#
# One-liner (inspect it first — never pipe blindly):
#   git clone https://github.com/digitalxs/AuditXS.git && cd AuditXS && sudo ./setup.sh
#

set -o pipefail

# ------------------------------------------------------------------ colours
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RC=$'\e[0m'; BOLD=$'\e[1m'; DIM=$'\e[2m'
    RED=$'\e[31m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; CYAN=$'\e[36m'; WHITE=$'\e[97m'
else
    RC=''; BOLD=''; DIM=''; RED=''; GREEN=''; YELLOW=''; CYAN=''; WHITE=''
fi

REPO_URL="https://github.com/digitalxs/AuditXS.git"
INSTALL_DIR=/opt/auditxs
BIN_DIR=/usr/local/bin
CONF_DIR=/etc/auditxs
CONF_FILE=$CONF_DIR/auditxs.conf
STATE_DIR=/var/lib/auditxs
LOG_DIR=/var/log/auditxs
DESKTOP_FILE=/usr/share/applications/auditxs.desktop

MODE=""
PROFILE_CHOICE=""
ASSUME_YES=0
WANT_GUI=ask

LOGFILE=""
ilog() { [ -n "$LOGFILE" ] && printf '%s %s\n' "$(date '+%F %T')" "$*" >> "$LOGFILE"; return 0; }
say()  { printf '%b\n' "$*"; ilog "$*"; }
ok()   { printf '%b\n' "${GREEN}✓${RC} $*"; ilog "[ok] $*"; }
warn() { printf '%b\n' "${YELLOW}!${RC} $*"; ilog "[warn] $*"; }
fail() { printf '%b\n' "${RED}✗${RC} $*" >&2; ilog "[fail] $*"; exit 1; }

confirm() {
    [ "$ASSUME_YES" = 1 ] && return 0
    local reply
    printf '%b' "${BOLD}$1${RC} [y/N] "
    read -r reply || return 1
    case $reply in [yY]|[yY][eE][sS]) return 0 ;; *) return 1 ;; esac
}

banner() {
    printf '%b\n' "${CYAN}"
    cat <<'EOF'
     █████╗ ██╗   ██╗██████╗ ██╗████████╗██╗  ██╗███████╗
    ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝╚██╗██╔╝██╔════╝
    ███████║██║   ██║██║  ██║██║   ██║    ╚███╔╝ ███████╗
    ██╔══██║██║   ██║██║  ██║██║   ██║    ██╔██╗ ╚════██║
    ██║  ██║╚██████╔╝██████╔╝██║   ██║   ██╔╝ ██╗███████║
    ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝
EOF
    printf '%b\n' "${RC}    ${WHITE}Transparent, reversible Linux security auditing${RC}"
    printf '%b\n' "    ${DIM}by DigitalXS — https://github.com/digitalxs/AuditXS${RC}"
    echo
}

# ------------------------------------------------------------ distro check
detect_distro() {
    DISTRO_ID=unknown; DISTRO_NAME="Unknown Linux"; PKG=unknown
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        DISTRO_ID=${ID:-unknown}
        DISTRO_NAME=${PRETTY_NAME:-$DISTRO_ID}
    fi
    local like=" ${ID_LIKE:-} "
    case $DISTRO_ID in
        debian|ubuntu|pop|linuxmint|neon|raspbian) PKG=apt ;;
        arch|manjaro|endeavouros|garuda)           PKG=pacman ;;
        fedora|rhel|centos|rocky|almalinux)        PKG=dnf ;;
        opensuse*|sles|sled)                       PKG=zypper ;;
        *)
            case $like in
                *debian*|*ubuntu*) PKG=apt ;;
                *arch*)            PKG=pacman ;;
                *fedora*|*rhel*)   PKG=dnf ;;
                *suse*)            PKG=zypper ;;
            esac ;;
    esac

    case $DISTRO_ID in
        debian)      ok "Detected ${WHITE}Debian GNU/Linux${RC} ($DISTRO_NAME)" ;;
        ubuntu)      ok "Detected ${WHITE}Ubuntu Linux${RC} ($DISTRO_NAME)" ;;
        pop)         ok "Detected ${WHITE}Pop!_OS${RC} ($DISTRO_NAME)" ;;
        arch)        ok "Detected ${WHITE}Arch Linux${RC}" ;;
        fedora)      ok "Detected ${WHITE}Fedora Linux${RC} ($DISTRO_NAME)" ;;
        opensuse*)   ok "Detected ${WHITE}openSUSE${RC} ($DISTRO_NAME)" ;;
        *)
            if [ "$PKG" != unknown ]; then
                warn "Detected $DISTRO_NAME — not one of the six primary targets, but the '$PKG' family is supported."
            else
                warn "Detected $DISTRO_NAME — unsupported distribution."
                warn "AuditXS targets Debian, Ubuntu, Pop!_OS, Arch, Fedora and openSUSE."
                confirm "Continue anyway at your own risk?" || exit 1
            fi ;;
    esac
}

pkg_install_one() {
    case $PKG in
        apt)    env DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$1" ;;
        pacman) pacman -S --noconfirm --needed "$1" ;;
        dnf)    dnf install -y -q "$1" ;;
        zypper) zypper --non-interactive --quiet install "$1" ;;
        *)      return 1 ;;
    esac
}

# ------------------------------------------------------------------- steps
require_root() {
    [ "$(id -u)" -eq 0 ] || fail "Please run the installer as root: ${BOLD}sudo ./setup.sh${RC}"
}

find_source() {
    # Prefer the directory this script lives in (git clone / tarball).
    SRC_DIR=$(cd "$(dirname "$0")" && pwd)
    if [ -x "$SRC_DIR/auditxs" ] && [ -d "$SRC_DIR/lib" ]; then
        return 0
    fi
    # Otherwise fetch the repository.
    command -v git >/dev/null 2>&1 || fail "git is required to fetch AuditXS (or run setup.sh from a cloned repo)."
    SRC_DIR=$(mktemp -d /tmp/auditxs-src.XXXXXX)
    say "Cloning $REPO_URL ..."
    git clone --depth 1 "$REPO_URL" "$SRC_DIR/AuditXS" >/dev/null 2>&1 || fail "git clone failed."
    SRC_DIR="$SRC_DIR/AuditXS"
}

install_files() {
    say ""
    say "${BOLD}Installing AuditXS to $INSTALL_DIR${RC}"
    mkdir -p "$INSTALL_DIR" || fail "Cannot create $INSTALL_DIR"
    # Copy the repository (including .git when present, so update-auditxs can pull).
    if command -v rsync >/dev/null 2>&1; then
        # Never copy the per-user Electron dependency into the system install.
        rsync -a --delete --exclude 'gui/electron/node_modules' \
              --exclude 'gui/electron/package-lock.json' \
              "$SRC_DIR/" "$INSTALL_DIR/" || fail "Copy to $INSTALL_DIR failed"
    else
        rm -rf "${INSTALL_DIR:?}"/* "$INSTALL_DIR/.git" 2>/dev/null
        cp -a "$SRC_DIR/." "$INSTALL_DIR/" || fail "Copy to $INSTALL_DIR failed"
        rm -rf "$INSTALL_DIR/gui/electron/node_modules" "$INSTALL_DIR/gui/electron/package-lock.json"
    fi
    chmod 755 "$INSTALL_DIR/auditxs" "$INSTALL_DIR/gui/auditxs-gui" \
              "$INSTALL_DIR/gui/auditxs-tui.sh" \
              "$INSTALL_DIR/setup.sh" "$INSTALL_DIR/uninstall.sh" \
              "$INSTALL_DIR/scripts/updater.sh" 2>/dev/null
    ok "Files installed"

    # Command symlinks (fall back to wrapper copies if symlinking fails).
    local name target
    for name in auditxs:auditxs auditxs-gui:gui/auditxs-gui update-auditxs:scripts/updater.sh; do
        target=${name#*:}; name=${name%%:*}
        if ln -sf "$INSTALL_DIR/$target" "$BIN_DIR/$name" 2>/dev/null; then
            ok "Command available: ${BOLD}$name${RC} → $INSTALL_DIR/$target"
        else
            printf '#!/bin/sh\nexec %s "$@"\n' "$INSTALL_DIR/$target" > "$BIN_DIR/$name" \
                && chmod 755 "$BIN_DIR/$name" \
                && ok "Command available (wrapper): $name"
        fi
    done

    mkdir -p "$STATE_DIR/snapshots" "$STATE_DIR/reports" "$LOG_DIR"
    chmod 750 "$STATE_DIR" "$STATE_DIR/snapshots" "$STATE_DIR/reports" "$LOG_DIR"
    ok "State directories ready ($STATE_DIR, $LOG_DIR)"

    # Polkit policy: keep GUI authentication (auth_admin_keep), so consecutive
    # pkexec-elevated AuditXS actions only ask for the password once.
    if [ -d /usr/share/polkit-1/actions ] && [ -f "$INSTALL_DIR/packaging/com.digitalxs.auditxs.policy" ]; then
        cp "$INSTALL_DIR/packaging/com.digitalxs.auditxs.policy" \
           /usr/share/polkit-1/actions/com.digitalxs.auditxs.policy \
            && chmod 644 /usr/share/polkit-1/actions/com.digitalxs.auditxs.policy \
            && ok "Polkit policy installed (GUI authentication is kept between actions)"
    fi
}

choose_profile() {
    # Keep an existing profile on refresh/update unless the user wants to change it.
    local current=""
    [ -r "$CONF_FILE" ] && current=$(sed -n 's/^PROFILE=//p' "$CONF_FILE")

    if [ -n "$PROFILE_CHOICE" ]; then
        PROFILE=$PROFILE_CHOICE
    elif [ "$MODE" = refresh ] && [ -n "$current" ]; then
        PROFILE=$current
        ok "Keeping existing profile: ${BOLD}$PROFILE${RC}"
        return 0
    else
        echo
        printf '%b\n' "${BOLD}How is this machine used?${RC} The profile decides which checks apply."
        echo
        printf '%b\n' "  ${BOLD}1)${RC} ${WHITE}Server${RC}       — headless or service machine."
        printf '%b\n' "     ${DIM}Adds: SSH key-only login & session timeouts, auditd + audit rules,"
        printf '%b\n' "     disabling of desktop services (Avahi/CUPS/Bluetooth), stricter umask,"
        printf '%b\n' "     Ctrl-Alt-Del protection, martian logging, wireless detection.${RC}"
        echo
        printf '%b\n' "  ${BOLD}2)${RC} ${WHITE}Workstation${RC}  — desktop or laptop used interactively."
        printf '%b\n' "     ${DIM}Keeps desktop conveniences (printing, mDNS, Bluetooth) out of scope"
        printf '%b\n' "     and focuses on updates, firewall, accounts, filesystem and kernel basics.${RC}"
        echo
        local choice=""
        if [ "$ASSUME_YES" = 1 ]; then
            choice=2
        else
            printf '%b' "${BOLD}Select profile${RC} [1/2] (default: 2 — Workstation): "
            read -r choice
        fi
        case $choice in
            1) PROFILE=server ;;
            *) PROFILE=workstation ;;
        esac
    fi

    mkdir -p "$CONF_DIR"
    cat > "$CONF_FILE" <<EOF
# AuditXS configuration — written by setup.sh on $(date -Is)
# PROFILE decides which checks apply: server | workstation
# Change it any time by re-running: sudo /opt/auditxs/setup.sh
PROFILE=$PROFILE
EOF
    chmod 644 "$CONF_FILE"
    ok "Profile configured: ${BOLD}$PROFILE${RC} ($CONF_FILE)"
    ilog "profile=$PROFILE"
}

# The ncurses terminal UI ('auditxs tui') is the interactive interface for
# servers and is available on workstations too, so ensure a dialog tool exists
# on every profile. whiptail is the Debian default; dialog is the fallback.
setup_tui() {
    if command -v whiptail >/dev/null 2>&1 || command -v dialog >/dev/null 2>&1; then
        return 0
    fi
    say "Installing 'whiptail' for the terminal UI (auditxs tui) ..."
    if pkg_install_one whiptail >/dev/null 2>&1 || pkg_install_one newt >/dev/null 2>&1 \
       || pkg_install_one dialog >/dev/null 2>&1; then
        ok "terminal UI dependency installed"
    else
        warn "Could not install whiptail/dialog automatically — 'auditxs tui' needs one of them."
        warn "The CLI (sudo auditxs audit) works fully without it."
    fi
}

setup_gui() {
    setup_tui

    # Graphical interfaces are disabled on the server profile — do not pull in
    # zenity or a desktop launcher on a headless machine.
    if [ "$PROFILE" = server ]; then
        say "${DIM}Server profile: graphical interface disabled — use 'sudo auditxs tui' over SSH.${RC}"
        return 0
    fi

    local have_zenity=0
    command -v zenity >/dev/null 2>&1 && have_zenity=1

    if [ "$WANT_GUI" = no ]; then
        say "${DIM}Skipping GUI setup (--no-gui)${RC}"
        return 0
    fi
    if [ "$have_zenity" = 0 ]; then
        if [ "$WANT_GUI" = ask ]; then
            echo
            if ! confirm "Install 'zenity' so the graphical interface (auditxs-gui) works?"; then
                warn "GUI dependency not installed — the CLI works fully without it. Install 'zenity' later to use auditxs-gui."
                return 0
            fi
        fi
        say "Installing zenity ..."
        if pkg_install_one zenity >/dev/null 2>&1; then
            ok "zenity installed"
        else
            warn "Could not install zenity automatically — install it with your package manager to use the GUI."
            return 0
        fi
    fi
    if [ -d /usr/share/applications ]; then
        cp -f "$INSTALL_DIR/gui/auditxs.desktop" "$DESKTOP_FILE" 2>/dev/null \
            && ok "Desktop launcher installed ($DESKTOP_FILE)"
    fi
}

print_summary() {
    echo
    printf '%b\n' "${GREEN}${BOLD}AuditXS is installed.${RC}"
    printf '%b\n' "${DIM}Install log: $LOGFILE${RC}"
    echo
    printf '%b\n' "${BOLD}Quick start${RC}"
    printf '%b\n' "  ${CYAN}sudo auditxs audit${RC}              read-only audit + HTML/JSON report"
    printf '%b\n' "  ${CYAN}sudo auditxs harden --dry-run${RC}   preview every fix without changing anything"
    printf '%b\n' "  ${CYAN}sudo auditxs harden${RC}             apply fixes one by one, with consent"
    printf '%b\n' "  ${CYAN}sudo auditxs rollback latest${RC}    undo the last hardening run completely"
    printf '%b\n' "  ${CYAN}auditxs list${RC}                    browse all checks; ${CYAN}auditxs explain SSH-001${RC} for details"
    printf '%b\n' "  ${CYAN}sudo auditxs tui${RC}                menu-driven terminal UI (works over SSH)"
    if [ "$PROFILE" = server ]; then
        printf '%b\n' "  ${DIM}(graphical interfaces are disabled on the server profile — use 'tui' or the CLI)${RC}"
    else
        printf '%b\n' "  ${CYAN}auditxs-gui${RC}                     graphical interface (also: ${CYAN}sudo auditxs web${RC})"
    fi
    printf '%b\n' "  ${CYAN}update-auditxs${RC}                  update to the latest version"
    echo
    printf '%b\n' "${DIM}Transparency: audits never change anything; every applied fix is recorded in"
    printf '%b\n' "a snapshot under $STATE_DIR/snapshots and in the ledger $STATE_DIR/changes.log.${RC}"
}

do_uninstall() {
    exec "$INSTALL_DIR/uninstall.sh"
}

# -------------------------------------------------------------------- main
for arg in "$@"; do
    case $arg in
        --server)      PROFILE_CHOICE=server ;;
        --workstation) PROFILE_CHOICE=workstation ;;
        --yes|-y)      ASSUME_YES=1 ;;
        --no-gui)      WANT_GUI=no ;;
        --gui)         WANT_GUI=yes ;;
        --refresh)     MODE=refresh; ASSUME_YES=1 ;;
        --uninstall)   MODE=uninstall ;;
        --help|-h)
            sed -n '3,20p' "$0"; exit 0 ;;
        *) fail "Unknown option: $arg" ;;
    esac
done

banner
require_root

mkdir -p "$LOG_DIR" 2>/dev/null
LOGFILE="$LOG_DIR/install-$(date +%Y%m%d-%H%M%S).log"
ilog "setup started: mode=${MODE:-interactive} args=$*"

detect_distro

if [ "$MODE" = uninstall ]; then
    do_uninstall
    exit $?
fi

if [ -z "$MODE" ] && [ "$ASSUME_YES" != 1 ]; then
    echo
    printf '%b\n' "${BOLD}What would you like to do?${RC}"
    printf '%b\n' "  ${BOLD}1)${RC} Install ${DIM}(default — fresh install or update in place)${RC}"
    printf '%b\n' "  ${BOLD}2)${RC} Repair  ${DIM}(reinstall files and commands, keep configuration)${RC}"
    printf '%b\n' "  ${BOLD}3)${RC} Uninstall"
    printf '%b\n' "  ${BOLD}4)${RC} Quit"
    printf '%b' "${BOLD}Select${RC} [1-4] (default: 1): "
    read -r menu
    case $menu in
        2) MODE=refresh ;;
        3) do_uninstall; exit $? ;;
        4) exit 0 ;;
        *) MODE=install ;;
    esac
fi
[ -z "$MODE" ] && MODE=install

find_source
install_files
choose_profile
setup_gui
print_summary
ilog "setup finished successfully"
