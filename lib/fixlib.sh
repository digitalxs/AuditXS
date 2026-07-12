#!/usr/bin/env bash
#
# AuditXS — lib/fixlib.sh
# Shared building blocks used by check modules: sysctl drop-ins, safe sshd
# configuration (validate-or-restore), login.defs edits, service state
# changes with recorded previous state, and filesystem enumeration.
#
# Part of AuditXS — transparent, reversible Linux security auditing.
#

# ------------------------------------------------------------------ sysctl
# audit_sysctl_group key=want...   (want may be a regex alternation, e.g. 1|2)
# Uses DETAIL; returns 0 pass / 1 fail / 2 unavailable.
audit_sysctl_group() {
    local kv key want cur bad="" miss=""
    for kv in "$@"; do
        key=${kv%%=*}; want=${kv#*=}
        cur=$(sysctl -n "$key" 2>/dev/null)
        if [ -z "$cur" ]; then
            miss+="$key "
            continue
        fi
        [[ "$cur" =~ ^($want)$ ]] || bad+="$key=$cur (recommended: $want)"$'\n'
    done
    if [ -n "$bad" ]; then
        DETAIL="Current values:"$'\n'"$bad"
        return 1
    fi
    if [ -n "$miss" ]; then
        DETAIL="Not available on this kernel: $miss"
        return 2
    fi
    DETAIL="All values already set as recommended"
    return 0
}

# fix_sysctl_group <check-id> <title> key=value...
# Writes one clearly-labelled drop-in per check under /etc/sysctl.d/ and
# applies the values at runtime. Previous runtime values are recorded so
# rollback restores them and deletes the drop-in.
fix_sysctl_group() {
    local id=$1 title=$2; shift 2
    local f kv key
    f="/etc/sysctl.d/99-auditxs-$(printf '%s' "$id" | tr '[:upper:]' '[:lower:]').conf"
    local content="# AuditXS $id — $title
# Written by AuditXS $AUDITXS_VERSION on $(date -Is).
# Revert with: sudo auditxs rollback <snapshot>
# (or simply delete this file and reboot)"
    track_file "$f"
    for kv in "$@"; do
        key=${kv%%=*}
        record_sysctl "$key" "${kv#*=}"
        content+=$'\n'"$key = ${kv#*=}"
    done
    write_file "$f" 0644 "$content" || return 1
    for kv in "$@"; do
        xrun_q sysctl -w "$kv" || warn "could not apply $kv at runtime (will apply after reboot)"
    done
    return 0
}

# -------------------------------------------------------------------- sshd
SSHD_MAIN=/etc/ssh/sshd_config
SSHD_DROPIN=/etc/ssh/sshd_config.d/99-auditxs.conf
_SSHD_T_CACHE=""

sshd_bin() {
    if have sshd; then command -v sshd
    elif [ -x /usr/sbin/sshd ]; then echo /usr/sbin/sshd
    else return 1
    fi
}

ssh_installed() { [ -f "$SSHD_MAIN" ] && sshd_bin >/dev/null; }

# sshd_effective <lowercase-key> — value from the effective config (sshd -T).
sshd_effective() {
    if [ -z "$_SSHD_T_CACHE" ]; then
        _SSHD_T_CACHE=$("$(sshd_bin)" -T 2>/dev/null)
    fi
    [ -n "$_SSHD_T_CACHE" ] || return 1
    printf '%s\n' "$_SSHD_T_CACHE" | awk -v k="$1" '$1==k { $1=""; sub(/^ /,""); print; exit }'
}

ssh_ports() {
    local p
    p=$("$(sshd_bin)" -T 2>/dev/null | awk '$1=="port"{print $2}')
    [ -n "$p" ] && echo "$p" || echo 22
}

ssh_in_use() { [ -n "${SSH_CONNECTION:-}" ] || svc_active "$(ssh_service_name)"; }

# sshd_set <Directive> <value> — prefer a clearly-labelled drop-in file when
# the distribution config includes sshd_config.d (all six supported distros
# do on current releases); otherwise edit the main config with a backup.
sshd_set() {
    local key=$1 val=$2
    if grep -qiE '^[[:space:]]*Include[[:space:]]+.*sshd_config\.d' "$SSHD_MAIN" 2>/dev/null; then
        track_file "$SSHD_DROPIN"
        if [ "$DRYRUN" = 1 ]; then
            say "  ${DIM}[dry-run] would set '$key $val' in $SSHD_DROPIN${RC}"
            return 0
        fi
        mkdir -p "$(dirname "$SSHD_DROPIN")"
        if [ ! -f "$SSHD_DROPIN" ]; then
            {
                echo "# AuditXS SSH hardening — written by AuditXS $AUDITXS_VERSION"
                echo "# Every directive below was applied by 'auditxs harden' with your approval."
                echo "# Revert with: sudo auditxs rollback <snapshot>  (or delete this file and reload sshd)"
            } > "$SSHD_DROPIN"
            chmod 600 "$SSHD_DROPIN"
        fi
        if grep -qiE "^[[:space:]]*$key([[:space:]]|$)" "$SSHD_DROPIN"; then
            sed -i -E "s|^[[:space:]]*${key}([[:space:]]).*|${key} ${val}|I" "$SSHD_DROPIN"
        else
            printf '%s %s\n' "$key" "$val" >> "$SSHD_DROPIN"
        fi
        log "[sshd] set $key $val in $SSHD_DROPIN"
    else
        track_file "$SSHD_MAIN"
        if [ "$DRYRUN" = 1 ]; then
            say "  ${DIM}[dry-run] would set '$key $val' in $SSHD_MAIN${RC}"
            return 0
        fi
        if grep -qiE "^[[:space:]]*$key([[:space:]]|$)" "$SSHD_MAIN"; then
            sed -i -E "s|^[[:space:]]*${key}([[:space:]]).*|${key} ${val}|I" "$SSHD_MAIN"
        else
            printf '\n# AuditXS hardening (revert: sudo auditxs rollback)\n%s %s\n' "$key" "$val" >> "$SSHD_MAIN"
        fi
        log "[sshd] set $key $val in $SSHD_MAIN"
    fi
}

# sshd_apply — validate the new configuration; restore the previous files
# immediately if validation fails, otherwise reload the SSH service.
sshd_apply() {
    _SSHD_T_CACHE=""
    if [ "$DRYRUN" = 1 ]; then
        say "  ${DIM}[dry-run] would validate with 'sshd -t' and reload the SSH service${RC}"
        return 0
    fi
    if ! "$(sshd_bin)" -t 2>/dev/null; then
        err "New SSH configuration failed validation (sshd -t) — restoring previous configuration."
        emergency_restore_file "$SSHD_DROPIN"
        emergency_restore_file "$SSHD_MAIN"
        _SSHD_T_CACHE=""
        DETAIL="sshd -t rejected the change; previous configuration was restored automatically"
        return 1
    fi
    has_systemd && systemctl try-restart "$(ssh_service_name)" 2>/dev/null
    return 0
}

# -------------------------------------------------------------- login.defs
set_logindefs() { # <KEY> <value>
    local key=$1 val=$2 f=/etc/login.defs
    track_file "$f"
    if [ "$DRYRUN" = 1 ]; then
        say "  ${DIM}[dry-run] would set '$key $val' in $f${RC}"
        return 0
    fi
    if grep -qE "^[[:space:]]*$key([[:space:]]|$)" "$f"; then
        sed -i -E "s|^[[:space:]]*(${key})([[:space:]]).*|\1\t${val}|" "$f"
    else
        printf '%s\t%s\n' "$key" "$val" >> "$f"
    fi
    log "[login.defs] set $key $val"
}

# ---------------------------------------------------------------- services
# disable_unit <unit> — disable and stop a unit, recording its previous
# state so rollback re-enables/restarts it.
disable_unit() {
    local u=$1 en ac
    unit_exists "$u" || return 0
    en=$(systemctl is-enabled "$u" 2>/dev/null)
    ac=$(systemctl is-active "$u" 2>/dev/null)
    if [ "$en" != "enabled" ] && [ "$ac" != "active" ]; then
        return 0
    fi
    record_service_state "$u" "disabled;inactive"
    xrun systemctl disable --now "$u"
}

# enable_unit <unit> — enable and start a unit, recording its previous state.
enable_unit() {
    local u=$1
    if ! unit_exists "$u"; then
        DETAIL="systemd unit $u not found"
        return 1
    fi
    record_service_state "$u" "enabled;active"
    xrun systemctl enable --now "$u"
}

# ------------------------------------------------------------- filesystems
# local_filesystems — mount points of real local filesystems, one per line.
local_filesystems() {
    if have findmnt; then
        findmnt -rn -o TARGET,FSTYPE 2>/dev/null \
            | awk '$2 ~ /^(ext[234]|xfs|btrfs|f2fs|jfs|reiserfs)$/ {print $1}' \
            | sort -u
    else
        echo /
    fi
}
