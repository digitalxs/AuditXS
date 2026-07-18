#!/usr/bin/env bash
#
# AuditXS — install-gui.sh
# A graphical installation assistant (zenity wizard) for desktops. It collects
# your choices, then runs the standard setup.sh with the matching flags,
# elevated once via pkexec. On a headless server, use the text installer:
#     sudo ./setup.sh
#
# Design: a clear multi-step wizard (welcome → profile → options → install →
# done), branded, with a real progress indicator and a final summary — the
# graphical-installer best practices, within what zenity offers.
#
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
TITLE="AuditXS Installer"
WIDTH=560

# --- preflight ------------------------------------------------------------
if ! command -v zenity >/dev/null 2>&1; then
    echo "install-gui.sh needs 'zenity' (a desktop). On a server use: sudo ./setup.sh" >&2
    exit 1
fi
if [ ! -x "$HERE/setup.sh" ]; then
    zenity --error --title "$TITLE" --width $WIDTH \
        --text "setup.sh was not found next to this installer. Run install-gui.sh from inside the AuditXS folder." 2>/dev/null
    exit 1
fi

VERSION=$(cat "$HERE/VERSION" 2>/dev/null || echo "")

# --- 1. welcome -----------------------------------------------------------
zenity --question --title "$TITLE" --width $WIDTH --ok-label "Get started" --cancel-label "Quit" \
    --text "<big><b>🛡️ AuditXS${VERSION:+ $VERSION}</b></big>

Transparent, reversible Linux security auditing &amp; hardening.

This assistant will install AuditXS on <b>this machine</b>. Auditing is always
read-only; any hardening you later apply is explained first and fully reversible.

You will be asked for your password once, to install system files." 2>/dev/null || exit 0

# --- 2. profile -----------------------------------------------------------
PROFILE=$(zenity --list --radiolist --title "$TITLE" --width $WIDTH --height 320 \
    --text "<b>How is this machine used?</b>  The profile decides which checks apply." \
    --column "" --column "Profile" --column "Description" \
    TRUE  workstation "Desktop / laptop — keeps printing, mDNS, Bluetooth in scope" \
    FALSE server      "Headless or service machine — stricter SSH, auditd, service lock-down" \
    2>/dev/null) || exit 0
[ -n "$PROFILE" ] || PROFILE=workstation

# --- 3. options -----------------------------------------------------------
OPTS=$(zenity --list --checklist --title "$TITLE" --width $WIDTH --height 300 \
    --text "<b>Options</b>" \
    --column "" --column "opt" --column "Description" \
    TRUE  gui   "Install the graphical interface dependencies (desktop only)" \
    FALSE tools "Also install recommended scanners now (Lynis, rkhunter, AIDE)" \
    2>/dev/null) || exit 0

WANT_GUI=1; WANT_TOOLS=0
case "$OPTS" in *gui*) WANT_GUI=1 ;; *) WANT_GUI=0 ;; esac
case "$OPTS" in *tools*) WANT_TOOLS=1 ;; esac

# --- 4. confirm -----------------------------------------------------------
zenity --question --title "$TITLE" --width $WIDTH --ok-label "Install" --cancel-label "Back out" \
    --text "<b>Ready to install AuditXS.</b>

• Profile: <b>$PROFILE</b>
• Graphical interface: <b>$([ "$WANT_GUI" = 1 ] && echo yes || echo no)</b>
• Install to <tt>/opt/auditxs</tt>, commands into <tt>/usr/local/bin</tt>

Continue?" 2>/dev/null || exit 0

# --- 5. install (elevated) with a progress pulse --------------------------
ELEV=""
if command -v pkexec >/dev/null 2>&1; then ELEV="pkexec"; elif command -v sudo >/dev/null 2>&1; then ELEV="sudo"; fi
[ -n "$ELEV" ] || { zenity --error --title "$TITLE" --width $WIDTH --text "Need pkexec or sudo to install." 2>/dev/null; exit 1; }

SETUP_ARGS=(--"$PROFILE" -y)
[ "$WANT_GUI" = 0 ] && SETUP_ARGS+=(--no-gui)

LOG=$(mktemp)
(
    "$ELEV" "$HERE/setup.sh" "${SETUP_ARGS[@]}" >"$LOG" 2>&1
    echo $? > "$LOG.rc"
    if [ "$WANT_TOOLS" = 1 ] && [ "$(cat "$LOG.rc")" = 0 ]; then
        "$ELEV" auditxs tools install lynis rkhunter aide >>"$LOG" 2>&1 || true
    fi
) | zenity --progress --title "$TITLE" --width $WIDTH --pulsate --auto-close --no-cancel \
    --text "Installing AuditXS ($PROFILE profile)…\nYou may be prompted for your password." 2>/dev/null

RC=$(cat "$LOG.rc" 2>/dev/null || echo 1)

# --- 6. result ------------------------------------------------------------
if [ "$RC" = 0 ]; then
    zenity --info --title "$TITLE" --width $WIDTH --text \
"<big><b>✓ AuditXS is installed.</b></big>

Run your first <b>read-only</b> audit:
<tt>sudo auditxs audit</tt>

$([ "$WANT_GUI" = 1 ] && echo "Or open the graphical interface:  <tt>auditxs-gui</tt>")

<small>🛡️ AuditXS · Made with ❤ from Canada 🍁 · © 2026 <b>DigitalXS</b> — Programming &amp; Development</small>" 2>/dev/null
else
    zenity --text-info --title "$TITLE — installation failed" --width 760 --height 480 \
        --filename "$LOG" 2>/dev/null
fi
rm -f "$LOG" "$LOG.rc"
