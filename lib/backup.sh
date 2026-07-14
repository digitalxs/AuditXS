#!/usr/bin/env bash
#
# AuditXS — lib/backup.sh
# Snapshot & rollback engine.
#
# Every change AuditXS makes is recorded here FIRST: files are copied into a
# timestamped snapshot before they are touched, and every single action is
# appended to a human-readable manifest (TSV) plus a global append-only
# change ledger. `auditxs rollback <snapshot>` replays the manifest in
# reverse to restore the system to its pre-hardening state.
#
# Manifest format (tab-separated):
#   <seq>  <check-id>  <action-type>  <target>  <previous-state>  <new-state>
#
# Part of AuditXS — transparent, reversible Linux security auditing.
#

SNAP_ROOT="${SNAP_ROOT:-/var/lib/auditxs/snapshots}"
CHANGES_LOG="${CHANGES_LOG:-/var/lib/auditxs/changes.log}"

SNAPSHOT_DIR=""
SNAPSHOT_ID=""
SNAP_SEQ=0
CURRENT_CHECK=""
declare -A TRACKED_FILES=()
declare -a APPLIED_CHECKS=()

# --------------------------------------------------------------- recording
snapshot_begin_lazy() {
    [ -n "$SNAPSHOT_DIR" ] && return 0
    SNAPSHOT_ID="$(date +%Y%m%d-%H%M%S)"
    SNAPSHOT_DIR="$SNAP_ROOT/$SNAPSHOT_ID"
    mkdir -p "$SNAPSHOT_DIR/files" || die "Cannot create snapshot directory $SNAPSHOT_DIR"
    chmod 700 "$SNAPSHOT_DIR"
    {
        echo "id=$SNAPSHOT_ID"
        echo "date=$(date -Is)"
        echo "host=$(hostname 2>/dev/null || echo unknown)"
        echo "profile=${PROFILE:-unknown}"
        echo "auditxs_version=$AUDITXS_VERSION"
    } > "$SNAPSHOT_DIR/meta"
    log "snapshot $SNAPSHOT_ID started"
    info "Change snapshot started: $SNAPSHOT_DIR"
}

# One line into the global, append-only change ledger.
ledger() {
    mkdir -p "$(dirname "$CHANGES_LOG")" 2>/dev/null
    printf '%s | snapshot=%s | check=%s | %s\n' \
        "$(date '+%F %T')" "${SNAPSHOT_ID:-none}" "${CURRENT_CHECK:-none}" "$*" \
        >> "$CHANGES_LOG" 2>/dev/null
    return 0
}

manifest_add() { # <type> <target> <prev> <new>
    snapshot_begin_lazy
    SNAP_SEQ=$((SNAP_SEQ + 1))
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$SNAP_SEQ" "${CURRENT_CHECK:--}" "$1" "$2" "$3" "$4" \
        >> "$SNAPSHOT_DIR/manifest.tsv"
    ledger "$1 $2 (was: $3 → now: $4)"
}

# track_file <path> — call BEFORE modifying or creating a file. Existing
# files are copied into the snapshot; files that do not exist yet are
# recorded as "created" so rollback deletes them.
track_file() {
    local path=$1
    if [ "$DRYRUN" = 1 ]; then
        say "  ${DIM}[dry-run] would back up $path before changing it${RC}"
        return 0
    fi
    [ -n "${TRACKED_FILES[$path]:-}" ] && return 0
    snapshot_begin_lazy
    if [ -e "$path" ]; then
        mkdir -p "$SNAPSHOT_DIR/files$(dirname "$path")"
        cp -a "$path" "$SNAPSHOT_DIR/files$path" || die "Backup of $path failed — aborting before making changes"
        TRACKED_FILES[$path]=saved
        manifest_add file "$path" "copy-saved" "modified"
    else
        TRACKED_FILES[$path]=created
        manifest_add file_created "$path" "absent" "created"
    fi
}

record_mode() { # <path> <intended-mode> — call BEFORE chmod
    [ "$DRYRUN" = 1 ] && return 0
    manifest_add mode "$1" "$(stat -c %a "$1" 2>/dev/null || echo '?')" "$2"
}

record_sysctl() { # <key> <new-value> — call BEFORE sysctl -w
    [ "$DRYRUN" = 1 ] && return 0
    local prev
    prev=$(sysctl -n "$1" 2>/dev/null || echo "?")
    manifest_add sysctl "$1" "$prev" "$2"
}

record_service_state() { # <unit> <new-state-desc> — call BEFORE changing it
    [ "$DRYRUN" = 1 ] && return 0
    local en ac
    en=$(systemctl is-enabled "$1" 2>/dev/null || echo unknown)
    ac=$(systemctl is-active "$1" 2>/dev/null || echo unknown)
    manifest_add service "$1" "$en;$ac" "$2"
}

record_action() { # <type> <target> <prev> <new> — generic
    [ "$DRYRUN" = 1 ] && return 0
    manifest_add "$1" "$2" "$3" "$4"
}

# emergency_restore_file <path> — immediately restore a tracked file (used
# when a config validation fails right after writing, e.g. sshd -t).
emergency_restore_file() {
    local path=$1
    case "${TRACKED_FILES[$path]:-}" in
        saved)   cp -a "$SNAPSHOT_DIR/files$path" "$path" && warn "Restored $path from snapshot" ;;
        created) rm -f "$path" && warn "Removed newly created $path" ;;
    esac
}

snapshot_finish() {
    [ -n "$SNAPSHOT_DIR" ] || return 0
    [ "$DRYRUN" = 1 ] && return 0
    printf '%s\n' "${APPLIED_CHECKS[@]}" > "$SNAPSHOT_DIR/checks" 2>/dev/null
    hr
    ok "Change snapshot saved: ${BOLD}$SNAPSHOT_ID${RC}"
    say "  Every change is listed in:  $SNAPSHOT_DIR/manifest.tsv"
    say "  Global change ledger:       $CHANGES_LOG"
    say "  Undo everything with:       ${BOLD}sudo auditxs rollback $SNAPSHOT_ID${RC}"
}

# ---------------------------------------------------------------- listing
cmd_snapshots() { # [--tsv]
    local tsv=${1:-} d id date profile n status found=0
    if [ -d "$SNAP_ROOT" ]; then
        for d in "$SNAP_ROOT"/*/; do
            [ -f "$d/manifest.tsv" ] || continue
            found=1
            id=$(basename "$d")
            date=$(sed -n 's/^date=//p' "$d/meta" 2>/dev/null)
            profile=$(sed -n 's/^profile=//p' "$d/meta" 2>/dev/null)
            n=$(wc -l < "$d/manifest.tsv")
            status=applied
            [ -f "$d/ROLLED_BACK" ] && status=rolled-back
            if [ "$tsv" = "--tsv" ]; then
                printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$date" "$profile" "$n" "$status"
            else
                printf '%b\n' "  ${BOLD}$id${RC}  $date  profile=$profile  actions=$n  status=$status"
            fi
        done
    fi
    if [ "$found" = 0 ] && [ "$tsv" != "--tsv" ]; then
        say "No snapshots yet — snapshots are created the first time 'auditxs harden' changes something."
    fi
}

# latest_snapshot — id of the most recent snapshot that was not rolled back.
latest_snapshot() {
    local d best=""
    for d in "$SNAP_ROOT"/*/; do
        [ -f "$d/manifest.tsv" ] || continue
        [ -f "$d/ROLLED_BACK" ] && continue
        best=$(basename "$d")
    done
    [ -n "$best" ] && echo "$best"
}

# --------------------------------------------------------------- rollback
rollback_snapshot() { # <snapshot-id>
    local id=$1 dir="$SNAP_ROOT/$1"
    [ -f "$dir/manifest.tsv" ] || die "Snapshot '$id' not found. List snapshots with: sudo auditxs snapshots"
    [ -f "$dir/ROLLED_BACK" ] && warn "Snapshot $id was already rolled back on $(cat "$dir/ROLLED_BACK")."

    local n
    n=$(wc -l < "$dir/manifest.tsv")
    say ""
    info "Rollback plan for snapshot ${BOLD}$id${RC} — $n recorded action(s), reverted in reverse order:"
    tac "$dir/manifest.tsv" | while IFS=$'\t' read -r seq chk type target prev new; do
        say "  $seq. [$chk] $type $target  ($new → $prev)"
    done
    say ""
    confirm "Proceed with this rollback?" || { info "Rollback cancelled — nothing was changed."; return 1; }

    local ssh_touched=0 systemd_touched=0 journald_touched=0 audit_touched=0
    local seq chk type target prev new en ac
    while IFS=$'\t' read -r seq chk type target prev new; do
        case $type in
            file)
                if cp -a "$dir/files$target" "$target"; then ok "restored $target"
                else err "failed to restore $target"; fi ;;
            file_created)
                rm -f "$target" && ok "removed $target (did not exist before)" ;;
            mode)
                if [ "$prev" != "?" ]; then
                    chmod "$prev" "$target" 2>/dev/null && ok "permissions of $target → $prev"
                fi ;;
            sysctl)
                if [ "$prev" != "?" ]; then
                    sysctl -w "$target=$prev" >/dev/null 2>&1 && ok "sysctl $target → $prev"
                fi ;;
            service)
                en=${prev%%;*}; ac=${prev##*;}
                case $en in
                    enabled)  systemctl enable "$target" >/dev/null 2>&1 ;;
                    disabled) systemctl disable "$target" >/dev/null 2>&1 ;;
                esac
                case $ac in
                    active)   systemctl start "$target" >/dev/null 2>&1 ;;
                    inactive) systemctl stop "$target" >/dev/null 2>&1 ;;
                esac
                ok "service $target → $prev" ;;
            pkg)
                if [ "$prev" = "absent" ] && pkg_installed "$target"; then
                    if confirm "Package '$target' was installed by AuditXS. Remove it again?"; then
                        pkg_remove "$target" && ok "removed package $target"
                    else
                        info "keeping package $target"
                    fi
                fi ;;
            ufw_state)
                if [ "$prev" = "inactive" ] && have ufw; then
                    ufw --force disable >/dev/null 2>&1 && ok "ufw disabled (was inactive before)"
                fi ;;
            ufw_rule)
                # shellcheck disable=SC2086
                have ufw && ufw --force delete $target >/dev/null 2>&1 && ok "ufw rule removed: $target" ;;
            ufw_logging)
                if have ufw && [ "$prev" != "?" ]; then
                    ufw logging "$prev" >/dev/null 2>&1 && ok "ufw logging → $prev"
                fi ;;
            ufw_default)
                # shellcheck disable=SC2086
                have ufw && [ "$prev" != "?" ] && ufw default $prev incoming >/dev/null 2>&1 \
                    && ok "ufw default incoming policy → $prev" ;;
            fw_service)
                if have firewall-cmd; then
                    firewall-cmd --permanent --remove-service="$target" >/dev/null 2>&1
                    firewall-cmd --reload >/dev/null 2>&1
                    ok "firewalld service removed: $target"
                fi ;;
            fw_target)
                if have firewall-cmd && [ "$prev" != "?" ]; then
                    firewall-cmd --permanent --zone="$target" --set-target="$prev" >/dev/null 2>&1
                    firewall-cmd --reload >/dev/null 2>&1
                    ok "firewalld zone $target target → $prev"
                fi ;;
            pam_config)
                if have pam-config; then
                    pam-config -d "--$target" >/dev/null 2>&1 \
                        && ok "pam-config module removed: $target"
                fi ;;
            note) : ;;
            *) warn "unknown manifest action '$type' for $target — skipped" ;;
        esac
        case $target in
            /etc/ssh/*)                       ssh_touched=1 ;;
            /etc/systemd/journald.conf.d/*)   journald_touched=1; systemd_touched=1 ;;
            /etc/systemd/*)                   systemd_touched=1 ;;
            /etc/audit/*)                     audit_touched=1 ;;
        esac
    done < <(tac "$dir/manifest.tsv")

    # Post-rollback service handling
    if [ "$systemd_touched" = 1 ] && has_systemd; then
        systemctl daemon-reload 2>/dev/null
    fi
    if [ "$journald_touched" = 1 ] && has_systemd; then
        systemctl try-restart systemd-journald 2>/dev/null
    fi
    if [ "$audit_touched" = 1 ] && have augenrules; then
        augenrules --load >/dev/null 2>&1 || warn "auditd rules could not be reloaded (a reboot may be required)"
    fi
    if [ "$ssh_touched" = 1 ]; then
        if sshd -t 2>/dev/null || /usr/sbin/sshd -t 2>/dev/null; then
            has_systemd && systemctl try-restart "$(ssh_service_name)" 2>/dev/null
            ok "SSH configuration restored, validated and reloaded"
        else
            warn "sshd reports an invalid configuration after restore — review /etc/ssh before restarting sshd."
        fi
    fi

    date -Is > "$dir/ROLLED_BACK"
    ledger "rollback of snapshot $id completed"
    hr
    ok "Rollback of ${BOLD}$id${RC} complete."
    say "  A reboot is recommended if kernel (sysctl) or boot settings were reverted."
}
