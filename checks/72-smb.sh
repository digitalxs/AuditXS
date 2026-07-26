#!/usr/bin/env bash
#
# AuditXS — checks/72-smb.sh
# Category: SMB — Samba / SMB file-sharing hardening. SMBv1 (the NT1 dialect)
# is obsolete and enables relay and downgrade attacks; SMB signing (or
# encryption) prevents on-path tampering and relay. These checks verify the
# Samba *server* configuration. Fixes edit smb.conf's [global] section with a
# backup and a testparm validate-or-restore step, so a bad edit is reverted
# immediately and 'auditxs rollback' restores the original file.
#

# Samba server present? (binary, package, or a config file — the last covers
# the fixture tree, where nothing is installed but smb.conf exists).
_smb_server_present() {
    have smbd || pkg_installed samba || [ -f "$(axpath /etc/samba/smb.conf)" ]
}

# Effective value of an smb.conf parameter (lower-cased, spaces stripped from
# the key — Samba ignores case and internal spacing in parameter names).
# Prefers 'testparm -s' on a real system (authoritative, includes defaults and
# included files); falls back to parsing smb.conf directly for the fixture tree
# or when testparm is unavailable. Prints the last value seen, lower-cased.
_smb_param() { # <key-without-spaces, lowercase>
    local want=$1 conf; conf=$(axpath /etc/samba/smb.conf)
    if [ -z "${AX_ROOT:-}" ] && have testparm; then
        testparm -s 2>/dev/null | awk -F= -v k="$want" '
            { key=$1; gsub(/[ \t]/,"",key); key=tolower(key);
              if (key==k){ v=$2; gsub(/^[ \t]+|[ \t]+$/,"",v); print tolower(v) } }' | tail -n1
        return 0
    fi
    [ -f "$conf" ] || return 0
    awk -F= -v k="$want" '
        /^[ \t]*[;#]/ { next }
        index($0,"=")==0 { next }
        { key=$1; gsub(/[ \t]/,"",key); key=tolower(key);
          if (key==k){ v=$2; sub(/[;#].*/,"",v); gsub(/^[ \t]+|[ \t]+$/,"",v); print tolower(v) } }' \
        "$conf" | tail -n1
}

# Set (or replace) a [global] parameter in smb.conf — reversible + validated.
# Backs the file up (rollback restores it), replaces an existing setting or
# inserts one under [global], validates with testparm, and restores on failure.
_smb_set_global() { # <param> <value>
    local param=$1 value=$2 conf=/etc/samba/smb.conf
    [ -f "$conf" ] || { DETAIL="smb.conf not found"; return 1; }
    track_file "$conf"
    if [ "${DRYRUN:-0}" = 1 ]; then
        say "  would set '${param} = ${value}' in [global] of ${conf}"
        return 0
    fi
    local key_re; key_re=$(printf '%s' "$param" | sed 's/ \+/[ \\t]*/g')
    if grep -qiE "^[ \t]*${key_re}[ \t]*=" "$conf"; then
        sed -i -E "s|^[ \t]*(${key_re})[ \t]*=.*|   ${param} = ${value}|I" "$conf"
    else
        awk -v line="   ${param} = ${value}" '
            BEGIN{ done=0 } { print }
            (!done && tolower($0) ~ /^[ \t]*\[global\]/){ print line; done=1 }
            END{ if(!done){ print "[global]"; print line } }' "$conf" > "$conf.axtmp" \
            && mv "$conf.axtmp" "$conf"
    fi
    if have testparm && ! testparm -s "$conf" >/dev/null 2>&1; then
        warn "  smb.conf failed validation — restoring the previous file"
        return 1
    fi
    say "  set '${param} = ${value}' in [global]"
    svc_active smbd 2>/dev/null && xrun_q systemctl reload smbd 2>/dev/null
    return 0
}

# ---------------------------------------------------------------- SMB-001
register_check "SMB-001" "SMB" "high" "server,workstation" \
    "SMBv1 (NT1) is disabled on the Samba server"
set_meta SMB-001 desc "Checks that the Samba server does not accept the obsolete SMBv1 (NT1) dialect. SMBv1 has no meaningful integrity protection and is the vector for relay and downgrade attacks (and worms like WannaCry). Modern Samba defaults to SMB2, but the protection must be explicit: this check requires 'server min protocol' to be set to SMB2 or higher."
set_meta SMB-001 fix "Sets 'server min protocol = SMB2' in the [global] section of /etc/samba/smb.conf (backed up first, validated with testparm, and smbd reloaded). SMBv1 clients can no longer negotiate."
set_meta SMB-001 revert "'sudo auditxs rollback' restores the saved smb.conf exactly as it was."

audit_SMB_001() {
    _smb_server_present || { DETAIL="Samba (SMB server) is not installed"; return 3; }
    local minp; minp=$(_smb_param serverminprotocol)
    [ -n "$minp" ] || minp=$(_smb_param minprotocol)   # legacy synonym
    case $minp in
        smb2*|smb3*)
            DETAIL="server min protocol = ${minp} — SMBv1/NT1 is refused"; return 0 ;;
        "")
            DETAIL="'server min protocol' is not set explicitly. Modern Samba defaults to SMB2, but the hardening requirement is to set it explicitly to SMB2 (or higher) so SMBv1 can never be negotiated."; return 1 ;;
        *)
            DETAIL="server min protocol = ${minp} — SMBv1/NT1 may be accepted (relay/downgrade risk). Require SMB2 or higher."; return 1 ;;
    esac
}
fix_SMB_001() { _smb_set_global "server min protocol" "SMB2"; }

# ---------------------------------------------------------------- SMB-002
register_check "SMB-002" "SMB" "high" "server,workstation" \
    "SMB signing (or encryption) is required on the Samba server"
set_meta SMB-002 desc "Checks that the Samba server mandates SMB signing (or the stronger SMB encryption). Without enforced signing, an on-path attacker can tamper with or relay SMB sessions. 'server signing = mandatory' rejects unsigned sessions; 'smb encrypt = required' additionally encrypts them (and implies signing)."
set_meta SMB-002 fix "Sets 'server signing = mandatory' in the [global] section of /etc/samba/smb.conf (backed up first, validated with testparm, and smbd reloaded). Existing shares keep working; clients that refuse signing are rejected."
set_meta SMB-002 revert "'sudo auditxs rollback' restores the saved smb.conf exactly as it was."

audit_SMB_002() {
    _smb_server_present || { DETAIL="Samba (SMB server) is not installed"; return 3; }
    local sign enc
    sign=$(_smb_param serversigning)
    enc=$(_smb_param smbencrypt); [ -n "$enc" ] || enc=$(_smb_param serversmbencrypt)
    case $sign in
        mandatory|required)
            DETAIL="server signing = ${sign} — SMB signing is enforced"; return 0 ;;
    esac
    case $enc in
        required|mandatory)
            DETAIL="smb encrypt = ${enc} — SMB encryption is enforced (implies signing)"; return 0 ;;
    esac
    DETAIL="SMB signing is not enforced (server signing = ${sign:-<unset>}). Set 'server signing = mandatory' (or 'smb encrypt = required') to block SMB relay/tampering."
    return 1
}
fix_SMB_002() { _smb_set_global "server signing" "mandatory"; }
