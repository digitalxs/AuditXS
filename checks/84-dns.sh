#!/usr/bin/env bash
#
# AuditXS — checks/84-dns.sh
# Category: DNS — BIND9 and Unbound resolver security.
#
# Report-only by design: an incorrect DNS change can black-hole a network or
# turn a resolver into an amplification weapon. Each finding gives the exact
# option and file to change, validated with the server's own config checker.
#

_bind_installed() { have named || unit_exists named.service || unit_exists bind9.service || [ -d /etc/bind ]; }
_bind_conf() { for f in /etc/bind/named.conf.options /etc/named.conf /etc/bind/named.conf; do [ -f "$f" ] && echo "$f"; done; }

register_check "BND-001" "DNS" "high" "server" \
    "BIND does not allow open recursion"
set_meta BND-001 desc "Checks that BIND restricts recursion (allow-recursion / allow-query) to trusted clients rather than the whole internet. An open recursive resolver is abused for DNS amplification DDoS and cache poisoning. Report-only — recursion policy depends on who your resolver serves."
set_meta BND-001 nist "PR.IR-01, PR.AA-05"

audit_BND_001() {
    _bind_installed || { DETAIL="BIND (named) is not installed"; return 3; }
    local cfg; cfg=$(_bind_conf | head -n1)
    [ -n "$cfg" ] || { DETAIL="No BIND options file found to inspect"; return 2; }
    if grep -qE 'allow-recursion|allow-query-cache' "$cfg" 2>/dev/null; then
        if grep -qE 'allow-recursion[[:space:]]*\{[[:space:]]*any' "$cfg" 2>/dev/null; then
            DETAIL="allow-recursion includes 'any' — this is an OPEN resolver (amplification risk). Restrict to your client networks."
            return 1
        fi
        DETAIL="recursion is restricted (allow-recursion/allow-query-cache present in $cfg)"
        return 0
    fi
    DETAIL="No explicit recursion restriction in $cfg — if this is a recursive resolver, add:
  allow-recursion { localhost; 192.0.2.0/24; };   // your trusted clients
and validate with 'named-checkconf'."
    return 2
}

register_check "BND-002" "DNS" "low" "server" \
    "BIND hides its version"
set_meta BND-002 desc "Checks that BIND overrides the 'version' option (version \"not disclosed\";) so a 'dig chaos txt version.bind' query does not reveal the exact BIND version and its known CVEs. Report-only."
set_meta BND-002 nist "PR.PS-01"

audit_BND_002() {
    _bind_installed || { DETAIL="BIND (named) is not installed"; return 3; }
    local cfg; cfg=$(_bind_conf | head -n1)
    [ -n "$cfg" ] || { DETAIL="No BIND options file found"; return 2; }
    if grep -qiE 'version[[:space:]]+"' "$cfg" 2>/dev/null; then
        DETAIL="version string is overridden in $cfg"
        return 0
    fi
    DETAIL="BIND advertises its real version. Add 'version \"not disclosed\";' to the options{} block in $cfg, then 'named-checkconf' and reload."
    return 2
}

# ------------------------------------------------------------------- Unbound
_unbound_installed() { have unbound || unit_exists unbound.service || [ -d /etc/unbound ]; }

register_check "UNB-001" "DNS" "high" "server" \
    "Unbound restricts access and hides identity"
set_meta UNB-001 desc "Checks Unbound's access-control and information-leak settings: 'access-control' should not allow the whole internet (open resolver / amplification), and hide-identity / hide-version should be yes. Report-only."
set_meta UNB-001 nist "PR.IR-01, PR.PS-01"

audit_UNB_001() {
    _unbound_installed || { DETAIL="Unbound is not installed"; return 3; }
    local conf hits hide=""
    conf=$(grep -rhsE '^[[:space:]]*(access-control|hide-identity|hide-version):' \
        /etc/unbound/unbound.conf /etc/unbound/unbound.conf.d/ 2>/dev/null)
    hits=$(printf '%s' "$conf" | grep -c 'access-control')
    printf '%s' "$conf" | grep -qE 'access-control:[[:space:]]*0\.0\.0\.0/0[[:space:]]+allow' \
        && { DETAIL="access-control allows 0.0.0.0/0 — open resolver. Restrict to your client subnets."; return 1; }
    printf '%s' "$conf" | grep -qE 'hide-identity:[[:space:]]*yes' || hide+="hide-identity "
    printf '%s' "$conf" | grep -qE 'hide-version:[[:space:]]*yes'  || hide+="hide-version "
    if [ "$hits" -eq 0 ] || [ -n "$hide" ]; then
        DETAIL="Review Unbound server{} block: set restrictive access-control and ${hide:-identity/version hiding}.
Example: access-control: 192.0.2.0/24 allow / hide-identity: yes / hide-version: yes; validate with 'unbound-checkconf'."
        return 2
    fi
    DETAIL="Unbound restricts access-control and hides identity/version"
    return 0
}
