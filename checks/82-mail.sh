#!/usr/bin/env bash
#
# AuditXS — checks/82-mail.sh
# Category: Mail — Postfix (SMTP) and Dovecot (IMAP/POP) security posture.
#
# Mail services are report-only by design: a wrong change to a mail server
# causes silent delivery failures or, worse, an open relay used for spam.
# Each finding gives the exact supported command to apply (postconf -e for
# Postfix, a doveconf-checked include for Dovecot).
#

_postfix_installed() { have postconf || unit_exists postfix.service || [ -f /etc/postfix/main.cf ]; }
_pc() { postconf -h "$1" 2>/dev/null; }   # effective Postfix parameter value

register_check "PFX-001" "Mail" "critical" "server" \
    "Postfix is not an open relay"
set_meta PFX-001 desc "Checks Postfix relay controls: smtpd_relay_restrictions / smtpd_recipient_restrictions must reject mail for domains you do not host (reject_unauth_destination), and mynetworks must not be dangerously broad. An open relay is abused within hours to send spam and gets your IP blacklisted. Report-only — relay policy depends on your network."
set_meta PFX-001 nist "PR.AA-05, PR.IR-01"

audit_PFX_001() {
    _postfix_installed || { DETAIL="Postfix is not installed"; return 3; }
    have postconf || { DETAIL="postconf not available"; return 3; }
    local relay recip mynets
    relay=$(_pc smtpd_relay_restrictions)
    recip=$(_pc smtpd_recipient_restrictions)
    mynets=$(_pc mynetworks)
    if printf '%s %s' "$relay" "$recip" | grep -q 'reject_unauth_destination'; then
        DETAIL="Relay control present (reject_unauth_destination). mynetworks=$mynets — confirm it lists only trusted hosts."
        [ "$mynets" = "0.0.0.0/0" ] && { DETAIL="OPEN RELAY RISK: mynetworks=0.0.0.0/0 relays for the whole internet. Restrict it immediately."; return 1; }
        return 0
    fi
    DETAIL="No 'reject_unauth_destination' found in relay/recipient restrictions — Postfix may relay for anyone.
Fix (supported): sudo postconf -e 'smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated reject_unauth_destination'"
    return 1
}

register_check "PFX-002" "Mail" "high" "server" \
    "Postfix requires TLS for SMTP"
set_meta PFX-002 desc "Checks that Postfix offers/uses TLS: smtpd_tls_security_level should be 'may' (opportunistic) or 'encrypt', and for submission (port 587) 'encrypt'. Without TLS, credentials and mail cross the network in cleartext. Report-only."
set_meta PFX-002 nist "PR.DS-02"

audit_PFX_002() {
    _postfix_installed || { DETAIL="Postfix is not installed"; return 3; }
    have postconf || { DETAIL="postconf not available"; return 3; }
    local lvl; lvl=$(_pc smtpd_tls_security_level)
    case "${lvl,,}" in
        encrypt) DETAIL="smtpd_tls_security_level = encrypt (TLS required)"; return 0 ;;
        may)     DETAIL="smtpd_tls_security_level = may (opportunistic TLS). For submission (587) require it: smtpd_tls_security_level=encrypt in master.cf."; return 0 ;;
        ""|none) DETAIL="TLS is not enabled (smtpd_tls_security_level=${lvl:-unset}).
Fix (supported): sudo postconf -e 'smtpd_tls_security_level = may' and configure smtpd_tls_cert_file/key_file."; return 1 ;;
        *) DETAIL="smtpd_tls_security_level = $lvl"; return 2 ;;
    esac
}

register_check "PFX-003" "Mail" "low" "server" \
    "Postfix SMTP banner does not leak software details"
set_meta PFX-003 desc "Checks that smtpd_banner does not advertise the Postfix/OS version and that the VRFY command is disabled (disable_vrfy_command=yes — VRFY lets attackers enumerate valid usernames). Report-only."
set_meta PFX-003 nist "PR.PS-01"

audit_PFX_003() {
    _postfix_installed || { DETAIL="Postfix is not installed"; return 3; }
    have postconf || { DETAIL="postconf not available"; return 3; }
    local banner vrfy bad=""
    banner=$(_pc smtpd_banner)
    vrfy=$(_pc disable_vrfy_command)
    printf '%s' "$banner" | grep -qiE 'mail_version|\$mail_version' && bad+="banner exposes version; "
    [ "${vrfy,,}" != "yes" ] && bad+="VRFY enabled (username enumeration); "
    if [ -n "$bad" ]; then
        DETAIL="$bad
Fix (supported): sudo postconf -e 'smtpd_banner = \$myhostname ESMTP' 'disable_vrfy_command = yes'"
        return 2
    fi
    DETAIL="Banner clean and VRFY disabled"
    return 0
}

# ------------------------------------------------------------------- Dovecot
_dovecot_installed() { have doveconf || unit_exists dovecot.service || [ -d /etc/dovecot ]; }
_dc() { doveconf -h "$1" 2>/dev/null; }

register_check "DOV-001" "Mail" "high" "server" \
    "Dovecot disables cleartext authentication without TLS"
set_meta DOV-001 desc "Checks that Dovecot's 'disable_plaintext_auth' is yes, so IMAP/POP passwords are never accepted over an unencrypted connection. Otherwise a passive network observer captures every mailbox password. Report-only — Dovecot config is include-based and easy to break."
set_meta DOV-001 nist "PR.DS-02, PR.AA-01"

audit_DOV_001() {
    _dovecot_installed || { DETAIL="Dovecot is not installed"; return 3; }
    have doveconf || { DETAIL="doveconf not available"; return 3; }
    local v; v=$(_dc disable_plaintext_auth)
    if [ "${v,,}" = yes ]; then DETAIL="disable_plaintext_auth = yes"; return 0; fi
    DETAIL="disable_plaintext_auth = ${v:-no} — cleartext logins are accepted.
Fix: set 'disable_plaintext_auth = yes' in /etc/dovecot/conf.d/10-auth.conf, then 'doveconf -n' to validate and restart dovecot."
    return 1
}

register_check "DOV-002" "Mail" "high" "server" \
    "Dovecot enforces modern TLS"
set_meta DOV-002 desc "Checks that Dovecot requires SSL/TLS (ssl = required) and disables obsolete protocols (ssl_min_protocol = TLSv1.2 or higher). Old TLS/SSL versions have exploitable weaknesses. Report-only."
set_meta DOV-002 nist "PR.DS-02"

audit_DOV_002() {
    _dovecot_installed || { DETAIL="Dovecot is not installed"; return 3; }
    have doveconf || { DETAIL="doveconf not available"; return 3; }
    local ssl minp bad=""
    ssl=$(_dc ssl)
    minp=$(_dc ssl_min_protocol)
    [ "${ssl,,}" = required ] || bad+="ssl=${ssl:-unset} (want required); "
    case "$minp" in TLSv1.2|TLSv1.3) : ;; *) bad+="ssl_min_protocol=${minp:-unset} (want TLSv1.2+); "; esac
    if [ -n "$bad" ]; then
        DETAIL="$bad
Fix in /etc/dovecot/conf.d/10-ssl.conf: 'ssl = required' and 'ssl_min_protocol = TLSv1.2', validate with 'doveconf -n', restart dovecot."
        return 1
    fi
    DETAIL="ssl = required, ssl_min_protocol = $minp"
    return 0
}

# ---------------------------------------------------------------- MTA-001 ---
_mta_present() { have postfix || [ -d "$(axpath /etc/postfix)" ] || svc_active postfix; }
register_check "MTA-001" "Mail" "low" "server" \
    "Outbound mail is authenticated (DKIM / DMARC)"
set_meta MTA-001 desc "Checks that a mail server signs and validates mail with DKIM/DMARC milters (OpenDKIM / OpenDMARC). Unsigned mail is trivial to spoof and is widely rejected or junked by recipients. (SPF and DMARC policy records live in DNS and are verified from the receiving side.) Report-only."
set_meta MTA-001 revert "No change is made (report-only)."
audit_MTA_001() {
    _mta_present || { DETAIL="No SMTP server (Postfix) detected"; return 3; }
    local have_dkim=0 have_dmarc=0
    { svc_active opendkim || svc_active opendkim.service || pkg_installed opendkim 2>/dev/null || have opendkim; } && have_dkim=1
    { svc_active opendmarc || svc_active opendmarc.service || pkg_installed opendmarc 2>/dev/null || have opendmarc; } && have_dmarc=1
    if [ "$have_dkim" = 1 ] && [ "$have_dmarc" = 1 ]; then
        DETAIL="DKIM and DMARC milters are present (OpenDKIM + OpenDMARC)"; return 0
    fi
    DETAIL="Missing mail authentication: $([ "$have_dkim" = 0 ] && echo -n 'DKIM ')$([ "$have_dmarc" = 0 ] && echo -n 'DMARC ')— install/enable OpenDKIM and OpenDMARC, and publish SPF/DKIM/DMARC DNS records."
    return 2
}
