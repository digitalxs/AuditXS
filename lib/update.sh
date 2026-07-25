#!/usr/bin/env bash
#
# AuditXS — lib/update.sh
# On-demand package updating: `auditxs update`.
#
# This is the ONE place AuditXS applies package upgrades, and it is kept
# deliberately separate from the reversible harden/rollback flow because
# package upgrades are NOT reversible by the snapshot engine — you cannot
# "roll back" an upgrade. So this command:
#   * previews exactly what would change (read-only) first,
#   * warns, in the open, that it is not snapshot-reversible,
#   * requires consent (or --yes) and supports --dry-run,
#   * records start/finish in the append-only change ledger,
#   * defaults to SECURITY updates only (--all for a full upgrade).
#
# For hands-off operation there are two other paths that reuse this engine:
#   * UPD-002's reversible fix, which enables the distro's own automatic
#     security updates (the system then patches itself); and
#   * `AUTO_UPDATE=1` in /etc/auditxs/auditxs.conf, which makes the scheduled
#     audit apply security updates when it finds them pending.
#
# Part of AuditXS — https://github.com/digitalxs/AuditXS
#

# ---------------------------------------------------------------- Timeshift
# Timeshift makes a package update recoverable: a filesystem snapshot taken
# BEFORE the update can be restored afterwards (something the AuditXS snapshot
# engine cannot do for upgrades). When Timeshift is present, `auditxs update`
# snapshots first by default; the update fix (UPD-001) requires it.

timeshift_available() { have timeshift; }

# timeshift_configured — Timeshift has a backup device/config set up. Without
# this, --create fails; we detect it so we can guide the user to configure it.
timeshift_configured() {
    [ -f /etc/timeshift/timeshift.json ] || [ -f /etc/timeshift.json ]
}

# timeshift_snapshot <comment> — create an on-demand system snapshot. Honours
# dry-run. Returns non-zero (AX5006) if it cannot.
timeshift_snapshot() {
    local comment=$1
    timeshift_available || { ax_error AX5006 "timeshift not installed"; return 1; }
    if ! timeshift_configured; then
        ax_error AX5006 "timeshift is not configured (run 'sudo timeshift --create' once to pick a backup device)"
        return 1
    fi
    say ""
    info "Creating a Timeshift snapshot so these updates can be rolled back…"
    # --scripted: non-interactive; tag O = on-demand (kept out of the daily set).
    xrun timeshift --create --comments "$comment" --scripted --tags O || {
        ax_error AX5006 "timeshift --create failed"
        return 1
    }
    ledger "timeshift snapshot created before update ($comment)"
    return 0
}

# timeshift_restore_hint — print how to undo the update with Timeshift.
timeshift_restore_hint() {
    say ""
    info "To roll these updates back, restore the snapshot taken just now:"
    say "    ${BOLD}sudo timeshift --restore${RC}      (pick the 'AuditXS pre-update …' snapshot)"
    say "    ${DIM}list snapshots:  sudo timeshift --list${RC}"
}

# _update_preview — list what would be updated (strictly read-only).
_update_preview() {
    case $PKG in
        apt)
            apt-get -s upgrade 2>/dev/null | awk '/^Inst /{print "  "$2" "$3}' | head -80 ;;
        dnf)
            timeout 120 dnf -q check-update 2>/dev/null \
                | awk 'NF>=3 && $1 !~ /^(Last|Obsoleting|Security)/ {print "  "$1}' | head -80 ;;
        pacman)
            pacman -Qu 2>/dev/null | sed 's/^/  /' | head -80 ;;
        zypper)
            if [ "${1:-security}" = security ]; then
                timeout 120 zypper --non-interactive list-patches 2>/dev/null \
                    | awk -F'|' 'tolower($0) ~ /security/ {gsub(/^ +| +$/,"",$2); if ($2) print "  "$2}' | head -80
            else
                timeout 120 zypper --non-interactive list-updates 2>/dev/null \
                    | awk -F'|' '/^v /{gsub(/^ +| +$/,"",$3); if ($3) print "  "$3}' | head -80
            fi ;;
    esac
}

# _update_apply <scope> — run the real upgrade, honouring dry-run via xrun.
# scope is "security" or "all".
_update_apply() {
    local scope=$1
    case $PKG in
        apt)
            xrun_q env DEBIAN_FRONTEND=noninteractive apt-get update -q || return 1
            if [ "$scope" = security ]; then
                # unattended-upgrade applies exactly the configured security set.
                if ! pkg_installed unattended-upgrades; then
                    pkg_install unattended-upgrades || true
                fi
                if pkg_installed unattended-upgrades && have unattended-upgrade; then
                    xrun unattended-upgrade -v
                else
                    warn "unattended-upgrades not available — applying all available upgrades instead."
                    xrun env DEBIAN_FRONTEND=noninteractive apt-get -y upgrade
                fi
            else
                xrun env DEBIAN_FRONTEND=noninteractive apt-get -y upgrade
            fi ;;
        dnf)
            if [ "$scope" = security ]; then
                xrun dnf -y --refresh upgrade --security
            else
                xrun dnf -y --refresh upgrade
            fi ;;
        pacman)
            # Arch does not support partial/security-only upgrades; the only
            # supported operation is a full system upgrade.
            warn "Arch supports only a full system upgrade (partial upgrades are unsupported) — running 'pacman -Syu'."
            xrun pacman -Syu --noconfirm ;;
        zypper)
            if [ "$scope" = security ]; then
                xrun zypper --non-interactive patch --category security --auto-agree-with-licenses
            else
                xrun zypper --non-interactive update --auto-agree-with-licenses
            fi ;;
        *)
            ax_error AX5005 "no supported package manager for this distribution"
            return 1 ;;
    esac
}

# cmd_update [--all|--security] [--dry-run] [--yes] — apply pending updates.
cmd_update() {
    require_root update
    local scope=security snapshot=auto
    while [ $# -gt 0 ]; do
        case $1 in
            --all|--full)   scope=all ;;
            --security)     scope=security ;;
            --snapshot)     snapshot=force ;;   # require a Timeshift snapshot
            --no-snapshot)  snapshot=off ;;     # skip it (not recommended)
            --dry-run)      DRYRUN=1 ;;
            --yes|-y)       ASSUME_YES=1 ;;
            -*)             die "update: unknown option '$1' (see 'auditxs help')" ;;
            *)              die "update: unexpected argument '$1'" ;;
        esac
        shift
    done
    # Arch only ever does full upgrades.
    [ "$PKG" = pacman ] && scope=all

    local n; n=$(pending_updates)
    nala_box "Apply package updates — scope: ${scope}"
    nala_row "Distribution: ${DIM}${DISTRO_NAME}${RC}   ·   pending in cache: ${BOLD}${n}${RC}"
    nala_end
    say ""

    local preview; preview=$(_update_preview "$scope")
    if [ -z "$preview" ]; then
        ok "No ${scope} updates to apply — the system is up to date."
        return 0
    fi
    info "These packages would be updated (${scope}):"
    printf '%s\n' "$preview"
    say ""

    # Decide whether a Timeshift snapshot will guard this update.
    local will_snapshot=0
    case $snapshot in
        force) will_snapshot=1 ;;
        auto)  timeshift_available && timeshift_configured && will_snapshot=1 ;;
        off)   will_snapshot=0 ;;
    esac
    if [ "$will_snapshot" = 1 ]; then
        ok "A Timeshift snapshot will be taken first — these updates ${BOLD}can be rolled back${RC} (sudo timeshift --restore)."
    else
        warn "Package upgrades are ${BOLD}NOT reversible${RC} by 'auditxs rollback', and no Timeshift snapshot will be taken. Install Timeshift (${BOLD}sudo auditxs tools install timeshift${RC}) for one-command rollback, or make a backup first."
    fi
    [ "$DRYRUN" = 1 ] && info "${BOLD}DRY-RUN:${RC} the commands below are shown but nothing is executed."

    if [ "$DRYRUN" != 1 ]; then
        confirm "Apply these ${scope} updates now?" || { info "Cancelled — nothing was changed."; return 0; }
    fi

    # Snapshot BEFORE touching packages. If it was explicitly required (--snapshot
    # or the auto path found Timeshift) and fails, abort — staying recoverable.
    if [ "$will_snapshot" = 1 ]; then
        timeshift_snapshot "AuditXS pre-update $(date '+%F %H:%M') (scope=$scope)" || return 1
    fi

    ledger "package update started (scope=$scope, pending=$n, snapshot=$will_snapshot)"
    if _update_apply "$scope"; then
        if [ "$DRYRUN" != 1 ]; then
            ok "Updates applied. A reboot may be required to activate them — check ${BOLD}auditxs audit${RC} (UPD-003)."
            [ "$will_snapshot" = 1 ] && timeshift_restore_hint
            ledger "package update completed (scope=$scope)"
        fi
        return 0
    fi
    ax_error AX5005 "scope=$scope distro=$DISTRO_FAMILY"
    [ "$will_snapshot" = 1 ] && { warn "The update failed after a snapshot was taken — restore it if the system is in a bad state:"; timeshift_restore_hint; }
    ledger "package update FAILED (scope=$scope)"
    return 1
}
