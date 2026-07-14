#!/usr/bin/env bash
#
# AuditXS — lib/distro.sh
# Distribution detection and package-manager abstraction for
# Debian, Ubuntu, Pop!_OS, Arch, Fedora and openSUSE (and derivatives).
#
# Part of AuditXS — transparent, reversible Linux security auditing.
#

DISTRO_ID=unknown
DISTRO_NAME="Unknown Linux"
DISTRO_FAMILY=unknown
DISTRO_VERSION=""
DISTRO_CODENAME=""
PKG=unknown

detect_distro() {
    local like=""
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        DISTRO_ID=${ID:-unknown}
        DISTRO_NAME=${PRETTY_NAME:-$DISTRO_ID}
        DISTRO_VERSION=${VERSION_ID:-}
        DISTRO_CODENAME=${VERSION_CODENAME:-}
        like=${ID_LIKE:-}
    fi

    case $DISTRO_ID in
        debian|ubuntu|pop|linuxmint|neon|raspbian)      DISTRO_FAMILY=debian ;;
        arch|archarm|manjaro|endeavouros|garuda)        DISTRO_FAMILY=arch ;;
        fedora|rhel|centos|rocky|almalinux)             DISTRO_FAMILY=redhat ;;
        opensuse*|sles|sled)                            DISTRO_FAMILY=suse ;;
        *)
            case " $like " in
                *debian*|*ubuntu*) DISTRO_FAMILY=debian ;;
                *arch*)            DISTRO_FAMILY=arch ;;
                *fedora*|*rhel*)   DISTRO_FAMILY=redhat ;;
                *suse*)            DISTRO_FAMILY=suse ;;
            esac ;;
    esac

    case $DISTRO_FAMILY in
        debian) PKG=apt ;;
        arch)   PKG=pacman ;;
        redhat) PKG=dnf ;;
        suse)   PKG=zypper ;;
    esac
}

pkg_installed() {
    case $PKG in
        apt)        dpkg-query -W -f '${Status}' "$1" 2>/dev/null | grep -q "install ok installed" ;;
        pacman)     pacman -Qi "$1" >/dev/null 2>&1 ;;
        dnf|zypper) rpm -q "$1" >/dev/null 2>&1 ;;
        *)          return 1 ;;
    esac
}

# pkg_install <pkg...> — installs packages, recording each one in the active
# snapshot so a rollback can offer to remove it again.
pkg_install() {
    local p rc=0
    for p in "$@"; do
        if pkg_installed "$p"; then
            say "  package '$p' is already installed"
            continue
        fi
        record_action pkg "$p" absent installed
        case $PKG in
            apt)    xrun env DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$p" ;;
            pacman) xrun pacman -S --noconfirm --needed "$p" ;;
            dnf)    xrun dnf install -y -q "$p" ;;
            zypper) xrun zypper --non-interactive --quiet install "$p" ;;
            *)      err "No supported package manager found"; return 1 ;;
        esac || rc=1
    done
    return $rc
}

pkg_remove() {
    case $PKG in
        apt)    env DEBIAN_FRONTEND=noninteractive apt-get remove -y -q "$1" ;;
        pacman) pacman -R --noconfirm "$1" ;;
        dnf)    dnf remove -y -q "$1" ;;
        zypper) zypper --non-interactive remove "$1" ;;
        *)      err "No supported package manager found"; return 1 ;;
    esac
}

# pending_updates — echo the number of pending package updates, or "?" if it
# cannot be determined. Read-only: never syncs or mutates package databases.
pending_updates() {
    local n=""
    case $PKG in
        apt)
            n=$(apt-get -s -qq upgrade 2>/dev/null | grep -c '^Inst ') ;;
        pacman)
            if have checkupdates; then
                n=$(checkupdates 2>/dev/null | wc -l)
            else
                n=$(pacman -Qu 2>/dev/null | wc -l)
            fi ;;
        dnf)
            n=$(timeout 120 dnf -q check-update 2>/dev/null | grep -Ec '^[[:alnum:]][^[:space:]]+[[:space:]]') ;;
        zypper)
            n=$(timeout 120 zypper --non-interactive -q list-updates 2>/dev/null | grep -c '^v ') ;;
    esac
    case $n in ''|*[!0-9]*) echo "?" ;; *) echo "$n" ;; esac
}
