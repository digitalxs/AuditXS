#!/usr/bin/env bash
#
# AuditXS — checks/15-os.sh
# Category: OS — operating-system configuration items aligned with CIS
# Benchmark / DISA STIG principles that don't fit a more specific category.
#

register_check "OSH-001" "OS" "low" "server" \
    "Remote logins display an authorized-use banner"
set_meta OSH-001 desc "Checks that SSH presents a login banner (/etc/issue.net via the sshd 'Banner' directive). DISA STIG and many compliance regimes require a notice that use is monitored and restricted to authorized users — it has legal weight in prosecutions and removes any expectation of privacy. Aligned with STIG SRG-OS-000023."
set_meta OSH-001 fix "Writes a generic authorized-use notice to /etc/issue.net (the previous file is saved) and sets 'Banner /etc/issue.net' in /etc/ssh/sshd_config.d/99-auditxs.conf, validated with 'sshd -t'. Organizations with approved legal wording should replace the text in /etc/issue.net afterwards."
set_meta OSH-001 revert "'sudo auditxs rollback' restores the previous /etc/issue.net and SSH configuration."
set_meta OSH-001 nist "PR.AA-06"

audit_OSH_001() {
    ssh_installed || { DETAIL="OpenSSH server is not installed (banner check targets remote logins)"; return 3; }
    local b
    b=$(sshd_effective banner)
    if [ -z "$b" ] || [ "$b" = "none" ]; then
        DETAIL="sshd presents no login banner (Banner ${b:-unset})"
        return 1
    fi
    if [ ! -s "$b" ]; then
        DETAIL="Banner is set to $b but that file is empty or missing"
        return 1
    fi
    DETAIL="Banner $b is presented at login"
    return 0
}

fix_OSH_001() {
    track_file /etc/issue.net
    write_file /etc/issue.net 0644 "*******************************************************************
*  AUTHORIZED USE ONLY                                            *
*  This system is for authorized users only. All activity may be *
*  monitored, recorded and reported. By continuing you consent    *
*  to such monitoring. Disconnect now if you are not authorized.  *
*******************************************************************" || return 1
    sshd_set Banner /etc/issue.net && sshd_apply
}

register_check "OSH-002" "OS" "medium" "server" \
    "/tmp is a separate filesystem with restrictive mount options"
set_meta OSH-002 desc "Checks that /tmp is its own filesystem mounted with nodev, nosuid and noexec (CIS 1.1.2). A separate, restricted /tmp prevents device-file tricks, setuid abuse and direct execution of attacker-staged files in the world-writable directory. Report-only: changing mounts on a running system risks breaking software mid-flight — the finding shows the systemd tmp.mount / fstab path instead. Note noexec on /tmp can affect some installers; test before enforcing."

audit_OSH_002() {
    have findmnt || { DETAIL="findmnt not available"; return 3; }
    local opts o missing=""
    opts=$(findmnt -rn -o OPTIONS /tmp 2>/dev/null)
    if [ -z "$opts" ]; then
        DETAIL="/tmp is not a separate filesystem. Recommended: 'systemctl enable /usr/share/systemd/tmp.mount' (or an fstab tmpfs entry) with nodev,nosuid,noexec."
        return 2
    fi
    for o in nodev nosuid noexec; do
        case ",$opts," in *",$o,"*) : ;; *) missing+="$o " ;; esac
    done
    if [ -z "$missing" ]; then
        DETAIL="/tmp is a separate filesystem with nodev,nosuid,noexec"
        return 0
    fi
    DETAIL="/tmp is a separate filesystem but lacks: $missing— add the option(s) via a tmp.mount drop-in or fstab and remount."
    return 2
}
