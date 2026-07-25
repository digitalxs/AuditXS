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
    local scope=security
    while [ $# -gt 0 ]; do
        case $1 in
            --all|--full)  scope=all ;;
            --security)    scope=security ;;
            --dry-run)     DRYRUN=1 ;;
            --yes|-y)      ASSUME_YES=1 ;;
            -*)            die "update: unknown option '$1' (see 'auditxs help')" ;;
            *)             die "update: unexpected argument '$1'" ;;
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
    warn "Package upgrades are ${BOLD}NOT reversible${RC} by 'auditxs rollback' — the snapshot engine cannot undo a software upgrade. Make sure you have backups before proceeding."
    [ "$DRYRUN" = 1 ] && info "${BOLD}DRY-RUN:${RC} the commands below are shown but nothing is executed."

    if [ "$DRYRUN" != 1 ]; then
        confirm "Apply these ${scope} updates now?" || { info "Cancelled — nothing was changed."; return 0; }
    fi

    ledger "package update started (scope=$scope, pending=$n)"
    if _update_apply "$scope"; then
        if [ "$DRYRUN" != 1 ]; then
            ok "Updates applied. A reboot may be required to activate them — check ${BOLD}auditxs audit${RC} (UPD-003)."
            ledger "package update completed (scope=$scope)"
        fi
        return 0
    fi
    ax_error AX5005 "scope=$scope distro=$DISTRO_FAMILY"
    ledger "package update FAILED (scope=$scope)"
    return 1
}
