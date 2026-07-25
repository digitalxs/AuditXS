#!/usr/bin/env bash
#
# AuditXS — lib/terminal.sh
# Open a real, fully-working terminal (a shell) from AuditXS: `auditxs terminal`.
#
# The GUIs already carry a line-based console for quick one-off commands, but a
# konsole-like terminal — interactive, able to run TUI programs (vim, htop,
# less, nano) — needs a real PTY. On the desktop the simplest, most faithful way
# to give you that is to open your terminal emulator, preferring KDE's Konsole
# (which is exactly what "similar to konsole" asks for) and falling back through
# the common emulators. If none is installed we offer to install Konsole.
#
# The Electron desktop app additionally hosts a terminal *inside its window*
# (xterm.js + gui/electron/pty-bridge.py); this command is the shared engine the
# CLI, the Qt app and the zenity GUI use to pop a real terminal window.
#
# It runs with the caller's own (unprivileged) rights — it opens a shell you
# could have opened yourself, so no privilege is added here.
#
# Part of AuditXS — https://github.com/digitalxs/AuditXS
#

# Preferred emulators, most-wanted first. Konsole leads (the requested one).
TERMINAL_EMULATORS="konsole kgx gnome-terminal x-terminal-emulator tilix \
xfce4-terminal mate-terminal lxterminal terminator deepin-terminal qterminal \
alacritty kitty foot wezterm st urxvt xterm"

# _terminal_find — echo the first installed emulator, or fail (rc 1).
_terminal_find() {
    local t
    for t in $TERMINAL_EMULATORS; do
        have "$t" && { echo "$t"; return 0; }
    done
    return 1
}

# _terminal_pkg — the package to offer when none is installed. Konsole is
# packaged as "konsole" on every supported family, so it is a safe default.
_terminal_pkg() {
    case "${DISTRO_FAMILY:-}" in
        debian|arch|redhat|suse) echo konsole ;;
        *)                       echo konsole ;;
    esac
}

# _terminal_has_display — is there a graphical session to open a window in?
_terminal_has_display() { [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ]; }

# launch_terminal — open a terminal window (a login-ish interactive shell) as
# the invoking user, detached so it outlives AuditXS.
#   rc 0 launched · 2 no graphical display · 3 no emulator installed
launch_terminal() {
    _terminal_has_display || return 2
    local emu; emu=$(_terminal_find) || return 3
    if have setsid; then
        setsid "$emu" >/dev/null 2>&1 </dev/null &
    else
        nohup "$emu" >/dev/null 2>&1 </dev/null &
    fi
    return 0
}

cmd_terminal() {
    # Internal: run as root to install the terminal package, then return.
    if [ "${1:-}" = "--install" ]; then
        require_root "terminal --install"
        local pkg; pkg=$(_terminal_pkg)
        pkg_install "$pkg" || { ax_error AX5001 "installing $pkg"; return 1; }
        return 0
    fi

    launch_terminal; local rc=$?
    if [ "$rc" -eq 0 ]; then
        ok "Opened a terminal window."
        return 0
    fi
    if [ "$rc" -eq 2 ]; then
        warn "No graphical display here — you already have a terminal at this prompt."
        return 0
    fi

    # rc 3: no emulator installed — offer to install Konsole.
    local pkg; pkg=$(_terminal_pkg)
    warn "No terminal emulator is installed."
    if _gui_ask "AuditXS — install a terminal" \
           "No terminal emulator is installed. Install ${pkg} (KDE Konsole) now?"; then
        if [ "$(id -u)" -eq 0 ]; then
            pkg_install "$pkg" || { ax_error AX5001 "installing $pkg"; return 1; }
        elif have pkexec; then
            pkexec "$AUDITXS_SELF" terminal --install || return 1
        elif have sudo; then
            sudo "$AUDITXS_SELF" terminal --install || return 1
        else
            ax_error AX1006 "cannot elevate to install $pkg"; return 1
        fi
        if launch_terminal; then ok "Opened a terminal window (${BOLD}$pkg${RC})."; return 0; fi
    fi
    ax_error AX1006 "no terminal emulator available"
    return 1
}
