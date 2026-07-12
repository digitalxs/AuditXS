#!/usr/bin/env bash
#
# AuditXS — checks/50-filesystem.sh
# Category: Filesystem — permissions and ownership fundamentals.
# All scans stay on local filesystems (-xdev) and every permission change
# records the file's previous mode so rollback restores it exactly.
#

# perm_exceeds <current-octal> <max-octal> — true if current grants bits
# beyond max (special bits ignored).
perm_exceeds() {
    local cur=$((8#$1)) max=$((8#$2))
    [ $(( cur & ~max & 0777 )) -ne 0 ]
}

register_check "FS-001" "Filesystem" "medium" "server,workstation" \
    "World-writable directories have the sticky bit"
set_meta FS-001 desc "Finds directories that any user may write to (like /tmp) but that lack the sticky bit. Without it, any user can delete or rename other users' files in that directory — a classic path for tmp-race attacks."
set_meta FS-001 fix "Adds the sticky bit (chmod +t) to each affected directory. The previous mode of every directory is recorded in the snapshot. No files are touched, only directory modes."
set_meta FS-001 revert "'sudo auditxs rollback' restores each directory's exact previous mode."

_ww_dirs_no_sticky() {
    local m
    local_filesystems | while IFS= read -r m; do
        find "$m" -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null
    done | sort -u
}

audit_FS_001() {
    local dirs n
    dirs=$(_ww_dirs_no_sticky)
    if [ -z "$dirs" ]; then
        DETAIL="All world-writable directories have the sticky bit"
        return 0
    fi
    n=$(echo "$dirs" | wc -l)
    DETAIL="$n world-writable director$( [ "$n" = 1 ] && echo y || echo ies) without sticky bit:"$'\n'"$(echo "$dirs" | head -n 10)"
    return 1
}

fix_FS_001() {
    local d
    while IFS= read -r d; do
        [ -n "$d" ] || continue
        record_mode "$d" "+t"
        xrun chmod +t "$d" || return 1
    done <<< "$(_ww_dirs_no_sticky)"
}

register_check "FS-002" "Filesystem" "medium" "server,workstation" \
    "No world-writable files"
set_meta FS-002 desc "Finds regular files that ANY user on the system may modify. World-writable files let an unprivileged user tamper with data or scripts that other users — or root — later read or execute."
set_meta FS-002 fix "Removes the world-write bit (chmod o-w) from each affected file. Every file's previous mode is recorded in the snapshot. Nothing is deleted and no other permission bits change."
set_meta FS-002 revert "'sudo auditxs rollback' restores each file's exact previous mode."

_ww_files() {
    local m
    local_filesystems | while IFS= read -r m; do
        find "$m" -xdev -type f -perm -0002 2>/dev/null
    done | sort -u
}

audit_FS_002() {
    local files n
    files=$(_ww_files)
    if [ -z "$files" ]; then
        DETAIL="No world-writable files found on local filesystems"
        return 0
    fi
    n=$(echo "$files" | wc -l)
    DETAIL="$n world-writable file(s):"$'\n'"$(echo "$files" | head -n 10)"
    return 1
}

fix_FS_002() {
    local f
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        record_mode "$f" "o-w"
        xrun chmod o-w "$f" || return 1
    done <<< "$(_ww_files)"
}

register_check "FS-003" "Filesystem" "low" "server,workstation" \
    "No unowned or ungrouped files"
set_meta FS-003 desc "Finds files whose owner or group no longer exists (usually left behind by removed packages or deleted users). A future account created with the same UID/GID silently inherits access to them. Report-only: correct ownership depends on what the files are, so AuditXS lists them with 'chown' guidance."

audit_FS_003() {
    local files n m
    files=$(local_filesystems | while IFS= read -r m; do
        find "$m" -xdev \( -nouser -o -nogroup \) 2>/dev/null
    done | sort -u)
    if [ -z "$files" ]; then
        DETAIL="No unowned or ungrouped files"
        return 0
    fi
    n=$(echo "$files" | wc -l)
    DETAIL="$n unowned/ungrouped file(s) — reassign with 'chown user:group <file>' or remove:"$'\n'"$(echo "$files" | head -n 10)"
    return 2
}

register_check "FS-004" "Filesystem" "high" "server,workstation" \
    "Sensitive system files have strict permissions"
set_meta FS-004 desc "Verifies that credential and boot files are not readable/writable more broadly than needed: /etc/shadow and /etc/gshadow (and their '-' backups) at most 640, /etc/passwd and /etc/group at most 644, /etc/crontab and GRUB configuration at most 600, SSH host private keys at most 600. AuditXS only ever TIGHTENS modes — files already stricter than the baseline (e.g. Fedora's shadow at 000) are left untouched."
set_meta FS-004 fix "For each file more permissive than its baseline, chmods it down to the baseline mode. Previous modes are recorded per file in the snapshot."
set_meta FS-004 revert "'sudo auditxs rollback' restores each file's exact previous mode."

_sensitive_files_over_permissive() {
    # Emits "path<TAB>max" for every existing file that exceeds its baseline.
    local spec path max cur
    local specs="/etc/shadow 640
/etc/shadow- 640
/etc/gshadow 640
/etc/gshadow- 640
/etc/passwd 644
/etc/passwd- 644
/etc/group 644
/etc/group- 644
/etc/crontab 600
/boot/grub/grub.cfg 600
/boot/grub2/grub.cfg 600
/etc/ssh/sshd_config 600"
    while read -r path max; do
        [ -f "$path" ] || continue
        cur=$(stat -c %a "$path" 2>/dev/null) || continue
        perm_exceeds "$cur" "$max" && printf '%s\t%s\t%s\n' "$path" "$max" "$cur"
    done <<< "$specs"
    for path in /etc/ssh/ssh_host_*_key; do
        [ -f "$path" ] || continue
        cur=$(stat -c %a "$path" 2>/dev/null) || continue
        perm_exceeds "$cur" "600" && printf '%s\t%s\t%s\n' "$path" 600 "$cur"
    done
}

audit_FS_004() {
    local bad
    bad=$(_sensitive_files_over_permissive)
    if [ -z "$bad" ]; then
        DETAIL="All sensitive files are at or below their baseline permissions"
        return 0
    fi
    DETAIL="Over-permissive sensitive file(s) (current → baseline):"$'\n'"$(echo "$bad" | awk -F'\t' '{printf "%s (%s → %s)\n", $1, $3, $2}')"
    return 1
}

fix_FS_004() {
    local path max cur
    while IFS=$'\t' read -r path max cur; do
        [ -n "$path" ] || continue
        record_mode "$path" "$max"
        xrun chmod "$max" "$path" || return 1
    done <<< "$(_sensitive_files_over_permissive)"
}

register_check "FS-005" "Filesystem" "medium" "server,workstation" \
    "Home directories are not accessible to other users"
set_meta FS-005 desc "Checks that each regular user's home directory is mode 750 or stricter, so other local users cannot read personal files, SSH keys, browser profiles or shell history."
set_meta FS-005 fix "Chmods each over-permissive home directory to 750. Previous modes are recorded per directory. Only the home directory itself is changed — never its contents."
set_meta FS-005 revert "'sudo auditxs rollback' restores each home directory's exact previous mode."

_open_home_dirs() {
    local user pass uid gid gecos home shell cur
    while IFS=: read -r user pass uid gid gecos home shell; do
        [ "$uid" -ge 1000 ] 2>/dev/null || continue
        [ "$uid" -ge 65534 ] && continue
        [ -d "$home" ] || continue
        cur=$(stat -c %a "$home" 2>/dev/null) || continue
        perm_exceeds "$cur" "750" && printf '%s\t%s\n' "$home" "$cur"
    done < /etc/passwd
}

audit_FS_005() {
    local bad
    bad=$(_open_home_dirs)
    if [ -z "$bad" ]; then
        DETAIL="All regular users' home directories are 750 or stricter"
        return 0
    fi
    DETAIL="Over-permissive home directories:"$'\n'"$(echo "$bad" | awk -F'\t' '{printf "%s (mode %s)\n", $1, $2}')"
    return 1
}

fix_FS_005() {
    local home cur
    while IFS=$'\t' read -r home cur; do
        [ -n "$home" ] || continue
        record_mode "$home" 750
        xrun chmod 750 "$home" || return 1
    done <<< "$(_open_home_dirs)"
}

register_check "FS-006" "Filesystem" "low" "server,workstation" \
    "SUID/SGID binary inventory"
set_meta FS-006 desc "Inventories setuid/setgid binaries — programs that run with elevated privileges no matter who starts them — and flags any outside the well-known baseline (sudo, passwd, mount, ...). Unexpected SUID binaries are a common persistence technique. Report-only: removing the bit can break legitimate software, so review each finding."

audit_FS_006() {
    local files unusual n m
    files=$(local_filesystems | while IFS= read -r m; do
        find "$m" -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null
    done | sort -u)
    [ -z "$files" ] && { DETAIL="No SUID/SGID binaries found"; return 0; }
    unusual=$(echo "$files" | grep -vE '/(sudo|sudoedit|su|passwd|chpasswd|gpasswd|chsh|chfn|chage|newgrp|sg|mount|umount|fusermount3?|ping|ping6|pkexec|polkit-agent-helper-1|ssh-keysign|ssh-agent|crontab|at|expiry|unix_chkpwd|unix2_chkpwd|pam_timestamp_check|Xorg\.wrap|dbus-daemon-launch-helper|utempter|wall|write(\.ul)?|locate|plocate|mlocate|screen|sperl.*|exim4?|postdrop|postqueue|mail-lock|mail-unlock|mail-touchlock|dotlockfile|newuidmap|newgidmap|chrome-sandbox|kismet_cap_.*|snap-confine|lxc-user-nic|vmware-user-suid-wrapper|grub2?-set-bootflag)$')
    n=$(echo "$files" | wc -l)
    if [ -z "$unusual" ]; then
        DETAIL="$n SUID/SGID binaries found; all match the common baseline"
        return 0
    fi
    DETAIL="$n SUID/SGID binaries; outside the common baseline (verify each is expected):"$'\n'"$(echo "$unusual" | head -n 15)"
    return 2
}
