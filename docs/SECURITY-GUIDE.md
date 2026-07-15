# Linux Security Hardening — a practical best-practices guide

This guide is the *reasoning* behind AuditXS: the professional cybersecurity
practices it checks for, why they matter, and how to apply them safely. It is
organised so you can read it top-to-bottom as a hardening playbook, or jump to
a domain. Every recommendation links to the AuditXS check(s) that verify it, so
you can move from "I should do this" to "AuditXS confirms it's done" in one step.

> AuditXS applies conservative, widely-accepted baselines. This guide is
> educational and general; always test on non-production systems first and
> keep console access when hardening remote machines.

## Contents

1. [Core principles](#1-core-principles)
2. [The hardening workflow](#2-the-hardening-workflow)
3. [Server hardening — privileged access, MFA, SSH](#3-server-hardening)
4. [OS hardening — patching, kernel, filesystem, MAC, logging](#4-os-hardening)
5. [Network security — firewall, exposure, DNS](#5-network-security)
6. [Application hardening — web, PHP, services](#6-application-hardening)
7. [Database hardening](#7-database-hardening)
8. [Vulnerability & patch management](#8-vulnerability--patch-management)
9. [Detection & monitoring](#9-detection--monitoring)
10. [Backups, recovery & incident response](#10-backups-recovery--incident-response)
11. [Compliance frameworks](#11-compliance-frameworks)
12. [Quick checklists](#12-quick-checklists)
13. [References](#13-references)

---

## 1. Core principles

Every specific control below is an instance of one of these ideas. Understand
the principles and the specifics follow.

- **Least privilege.** Every user, process and service should have the minimum
  access it needs and no more. Root is a last resort; services run as
  dedicated non-login accounts; sudo is accountable and password-protected.
  *(AuditXS: ACC-001, ACC-005, PRV-001, PRV-003, ACC-004.)*
- **Defence in depth.** No single control is trusted alone. A firewall *and*
  key-only SSH *and* fail2ban *and* auditd. If one layer fails, others hold.
- **Reduce the attack surface.** Software that isn't installed can't be
  exploited; a port that isn't listening can't be attacked. Remove or disable
  what you don't use. *(SVC-001..004, NET-002, KRN-008, FW-003.)*
- **Patch quickly.** The most-exploited vulnerabilities are known ones with
  patches available. Automate security updates and track CVEs.
  *(UPD-001/002, VULN-001/002, DEB-002/003.)*
- **Assume breach.** Design so that a compromise is *detected* and *contained*.
  Log security events tamper-resistantly; alert on drift.
  *(LOG-001..004, NET-004, `auditxs schedule`.)*
- **Encrypt in transit and at rest.** Credentials and data must not cross the
  network or sit on disk in cleartext. *(SSH, PFX-002, DOV-002, DB-001/002.)*
- **Change control & reversibility.** Every change is intentional, documented,
  and reversible. AuditXS embodies this: snapshots, a change ledger, and
  rollback. Never make a hardening change you cannot undo.
- **Verify, don't trust.** After any change, confirm the system behaves as
  intended. AuditXS re-audits every fix it applies; you should test the
  service too.

---

## 2. The hardening workflow

A repeatable loop, not a one-time event:

```
   audit ──► review ──► harden ──► verify ──► baseline ──► monitor
     ▲                                                        │
     └────────────────────── re-audit ◄──────────────────────┘
```

1. **Audit (read-only).** `sudo auditxs audit` — understand the current state
   and the score. Nothing changes.
2. **Review.** Read the findings. `auditxs explain <ID>` tells you what each
   fix changes and how it reverts. Decide what applies to *your* environment.
3. **Harden — with a safety net.** `sudo auditxs harden --dry-run` first to
   preview, then `sudo auditxs harden` to apply per-control with consent.
   **Keep a second session / console open** when hardening SSH or the firewall.
4. **Verify.** AuditXS re-checks each fix; you verify the service still works
   (log in over SSH in a *new* session before closing the old one).
5. **Baseline.** `sudo auditxs baseline set` records the approved good state.
6. **Monitor for drift.** `sudo auditxs schedule enable` runs a daily audit;
   any regression from the baseline fails the systemd unit so monitoring alerts.

The golden rule for remote machines: **never lock yourself out.** AuditXS has
lockout guards (it allows the SSH port before enabling a firewall, and refuses
to disable password auth unless keys already exist) — but you should still test
in a parallel session.

---

## 3. Server hardening

*Privileged access, authentication, and the most-attacked entry point: SSH.*

### Privileged access management
- **One human, one account.** No shared logins. Administrators log in as
  themselves and elevate with sudo, so the audit trail shows *who* did *what*.
- **sudo must require a password and be accountable.** No `NOPASSWD` for
  interactive users; enable `use_pty` (a rogue program can't detach with root)
  and a dedicated sudo logfile. *(PRV-001, ACC-004.)*
- **Inventory your admins regularly.** Know exactly who is in `sudo`/`wheel`
  and remove anyone who no longer needs it. *(PRV-003.)*
- **root has no second.** Only UID 0 is root; no account should have empty or
  no password. *(ACC-001, ACC-002.)*

### Multi-factor authentication (MFA)
MFA is one of the highest-impact controls against credential theft. For SSH,
chain factors with `AuthenticationMethods publickey,keyboard-interactive` and a
TOTP/hardware-key PAM module (google-authenticator, pam_u2f). **Enrol every
admin first** and test in a parallel session — misconfigured MFA locks everyone
out. *(PRV-002 reports posture; enrolment is manual by design.)*

### SSH hardening (the essentials)
| Practice | Why | Check |
|---|---|---|
| Disable root login | removes the #1 brute-force target and preserves accountability | SSH-001 |
| Key-based auth, disable passwords | immune to guessing/credential-stuffing (set up keys first!) | SSH-005 |
| Limit auth attempts (`MaxAuthTries ≤ 4`) | slows guessing, creates log noise attackers can't avoid | SSH-002 |
| Reject empty passwords | blocks login to accounts with no password | SSH-003 |
| Idle-session timeout | closes abandoned terminals | SSH-006 |
| Short login grace time | blunts pre-auth DoS | SSH-007 |
| Disable X11 forwarding on servers | a compromised server can't attack clients | SSH-004 |
| Brute-force protection (fail2ban/CrowdSec) | bans attacking IPs automatically | SSH-008, SEC-004 |
| Login banner | legal notice; required by many standards | OSH-001 |

Beyond the baseline: restrict `AllowUsers`/`AllowGroups`, move off port 22 only
as obscurity (not security), and consider a bastion host for fleets.

---

## 4. OS hardening

*CIS Benchmark / DISA STIG aligned operating-system configuration.*

### Patch management
Keep the system patched — it is the single most effective control. Enable
unattended **security** updates (`unattended-upgrades` on Debian/Ubuntu,
`dnf-automatic` on Fedora), reboot when the kernel updates, and run a supported
release. *(UPD-001/002/003, DEB-002/003.)*

### Kernel hardening (sysctl)
Sensible network/kernel defaults that cost nothing and close real attack
classes: full ASLR, hidden kernel pointers, TCP SYN cookies, ignore ICMP
redirects and source routing, reverse-path filtering, disable IP forwarding
unless routing, and no setuid core dumps. *(KRN-001..010.)* AuditXS writes one
labelled `/etc/sysctl.d/` drop-in per control and can revert each.

### Filesystem & permissions
- Sensitive files locked down: `/etc/shadow` ≤ 640, SSH host keys 600, GRUB
  config 600. AuditXS only ever *tightens*. *(FS-004.)*
- No world-writable files; sticky bit on world-writable dirs; no unowned files;
  home directories not world-readable. *(FS-001/002/003/005.)*
- Know your setuid/setgid binaries — each is a privilege boundary. *(FS-006.)*
- Separate, restricted `/tmp` (`nodev,nosuid,noexec`). *(OSH-002.)*

### Mandatory Access Control (MAC)
Run SELinux (enforcing) or AppArmor (with profiles) so a compromised service is
confined and can't roam the system. Every supported distro ships one. *(MAC-001.)*

### Logging & audit trail
You cannot respond to what you cannot see:
- Persistent journal so logs survive reboots. *(LOG-001.)*
- The Linux audit daemon (`auditd`) with baseline rules watching identity
  files, sudoers and SSH config — a tamper-resistant record. *(LOG-002/003.)*
- No world-writable log files. *(LOG-004.)*
- Ship logs off-box (rsyslog relay, Loki, ELK) so an attacker can't erase them.

### Accounts & passwords
Password aging, minimum quality (pam_pwquality, `minlen ≥ 12`), a restrictive
default umask, and non-login shells for service accounts. *(ACC-003/005/006/007.)*
Prefer passphrases and a password manager over rotation theatre.

---

## 5. Network security

- **Default-deny host firewall.** Every server runs one (ufw or firewalld),
  active, denying unsolicited inbound by default, allowing only what you serve.
  Log firewall decisions. *(FW-001/002/003/004.)*
- **Know what listens.** Inventory listening ports and *approve* them; anything
  new is drift to investigate — a forgotten debug port, a dropped implant, a
  bad install. *(NET-001, NET-004.)*
- **Shrink protocol surface.** Prevent auto-loading of exotic network protocols
  (DCCP, SCTP, RDS, TIPC) that have a long CVE history and no legitimate use on
  most hosts. *(NET-002.)*
- **DNS.** If you run a resolver (BIND/Unbound), restrict recursion to your
  clients (open resolvers are abused for amplification DDoS), hide the version,
  and enable DNSSEC validation. *(BND-001/002, UNB-001.)*
- **Segment.** Put databases and management interfaces on private networks;
  never expose them to the internet. Use a VPN (WireGuard/OpenVPN) for remote
  admin, with private keys at mode 600 and modern ciphers. *(`auditxs tools vpn`.)*

---

## 6. Application hardening

*Least privilege, secure configuration, and no information leaks for exposed apps.*

- **Don't disclose versions.** Web servers and PHP should not advertise exact
  versions (free reconnaissance for attackers). *(APP-001/002, PHP-001.)*
- **Send security headers.** `X-Content-Type-Options: nosniff`,
  `X-Frame-Options`, `Referrer-Policy`, and — once HTTPS is confirmed — HSTS
  and a Content-Security-Policy. *(APP-003.)*
- **No directory listing.** Disable autoindex/`Options Indexes`. *(APP-004.)*
- **PHP:** `display_errors Off` (errors leak paths/SQL), hardened session
  cookies (HttpOnly, Secure, SameSite), and review dangerous functions
  (`exec`, `system`, …) in `disable_functions`. *(PHP-002/003/004.)*
- **Remove unneeded services.** Legacy plaintext services (telnet, rsh, FTP),
  and desktop services on servers (Avahi, CUPS, Bluetooth) should be gone.
  *(SVC-001/002/003/004.)*
- **Confine services.** Use systemd sandboxing directives
  (`ProtectSystem`, `NoNewPrivileges`, `PrivateTmp`, syscall filters). *(SVC-005.)*
- **TLS everywhere.** Terminate with modern TLS (1.2+), strong ciphers, and
  automated certificates (Let's Encrypt). Redirect HTTP→HTTPS.

### Mail servers
- **Postfix:** never an open relay (`reject_unauth_destination`, tight
  `mynetworks`), require TLS, don't leak the version, disable VRFY. *(PFX-001/002/003.)*
- **Dovecot:** disable plaintext auth without TLS, require TLS 1.2+. *(DOV-001/002.)*

---

## 7. Database hardening

Databases hold the crown jewels; treat them accordingly. AuditXS is
**report-only** here by design (auto-editing a database causes outages), but the
practices are essential:

- **Never expose to the internet.** Bind to localhost or a private network;
  gate with the firewall. *(DB-001, DB-002.)*
- **Strong authentication.** No anonymous or passwordless accounts (run
  `mysql_secure_installation`); PostgreSQL must not use `trust` auth — use
  `scram-sha-256`. *(DB-004, DB-002.)*
- **Least privilege.** Per-application accounts scoped to their own database;
  no application using the admin/root DB user.
- **Encryption.** TLS for connections (`require_secure_transport`, `ssl=on`);
  at-rest encryption for the data directory.
- **Disable risky features.** e.g. MySQL `local_infile` (arbitrary file read
  via SQL injection). *(DB-003.)*
- **Backups you have *tested* restoring.** Encrypted, off-box.

---

## 8. Vulnerability & patch management

- **Track known vulnerabilities.** `sudo auditxs cve` warns when an installed
  package has a reported CVE with a fix available (Debian `debsecan`/security
  suite, Fedora `dnf updateinfo`, openSUSE patches). This appears in the audit,
  the report and the web UI. *(VULN-001/002.)*
- **Prioritise by exploitability**, not just CVSS — a network-reachable,
  actively-exploited bug beats a theoretical local one. Watch CISA KEV.
- **Scan deeper periodically** with dedicated tools: Greenbone/OpenVAS
  (network), Trivy (containers/images), Lynis (host). AuditXS integrates the
  host auditors: `sudo auditxs tools install lynis && sudo auditxs tools scan`.
- **Patch the whole stack** — OS, language runtimes, application dependencies,
  container base images, and firmware.

---

## 9. Detection & monitoring

Assume prevention will sometimes fail; make sure you'll *know*:

- **Host audit trail:** auditd + rules (LOG-002/003), persistent journal.
- **Intrusion prevention:** fail2ban or CrowdSec (log-based banning), Suricata
  (network IDS/IPS). *(SEC-004; `auditxs tools install crowdsec|suricata`.)*
- **File integrity monitoring:** AIDE records hashes of system files so
  tampering is detected. Initialise the baseline on a known-good system.
  *(SEC-003.)*
- **Rootkit / malware detection:** rkhunter and chkrootkit for rootkits;
  ClamAV for known malware (`auditxs tools install clamav`, then
  `auditxs tools scan clamav`). *(SEC-002.)*
- **Endpoint visibility:** osquery exposes live system state as SQL tables
  (processes, sockets, packages, users) — invaluable for hunting and
  inventory. Trivy scans the filesystem and container images for known
  vulnerabilities and misconfigurations.
- **Device & application containment:** USBGuard allow-lists USB devices to
  blunt BadUSB / rogue-device attacks; Firejail sandboxes risky applications;
  arpwatch flags ARP/MAC changes that can signal spoofing on the LAN.
- **Configuration drift:** an approved baseline + scheduled audit
  (`auditxs baseline set`, `auditxs schedule enable`) turns "did something
  change?" into an automatic alert. *(NET-004 for listening-port drift.)*
- **Centralise and alert.** Ship logs off-box and alert on the signals that
  matter (auth failures, sudo use, new listeners, audit regressions).
  Logwatch summarises daily log activity into a digest.

### Security tooling AuditXS integrates

AuditXS does not reimplement scanners — it installs, runs and collects the
output of the established ones through one reversible interface. Inventory
your coverage with `auditxs tools status` (grouped by capability), install
with `auditxs tools install <name>`, and run with `auditxs tools scan`:

| Capability | Tools |
|---|---|
| Host auditing / compliance | Lynis, Tiger, lsat, checksecurity, **OpenSCAP** (SCAP/SSG, CIS/STIG profiles) |
| Rootkit / malware | rkhunter, chkrootkit, **ClamAV** |
| File integrity | AIDE |
| Vulnerability data | debsecan, **Trivy** |
| Audit / accounting | auditd, process accounting (acct) |
| Active defence / IDS | Fail2ban, CrowdSec, Suricata, arpwatch |
| Isolation / device control | Firejail, USBGuard |
| Endpoint visibility / logs | osquery, Logwatch |
| Host IDS | OSSEC / Wazuh (guided setup) |

OpenSCAP is the tool of choice for **formal compliance evidence**: point it
at the SCAP Security Guide content for your distro and evaluate a CIS or STIG
profile (`auditxs tools scan openscap` picks a sensible profile automatically).

---

## 10. Backups, recovery & incident response

Hardening reduces the chance of compromise; backups and a plan determine
whether one is a nuisance or a catastrophe.

- **3-2-1 backups:** three copies, two media, one off-site. Encrypted.
- **Test restores** — an untested backup is a hope, not a backup.
- **Have a written incident-response plan:** how to isolate a host, who to
  notify, how to preserve evidence (AuditXS's change ledger and auditd logs
  help reconstruct *what changed and when*), and how to rebuild from known-good.
- **After an incident**, rebuild rather than clean where feasible; rotate all
  credentials and keys.

AuditXS supports the RECOVER function narrowly but usefully: `auditxs rollback`
restores a known configuration state, and `/var/lib/auditxs/changes.log` is an
append-only record of every change it ever made.

---

## 11. Compliance frameworks

AuditXS maps each check to widely-used frameworks so an audit doubles as
evidence. See [COMPLIANCE.md](COMPLIANCE.md) for the full detail.

- **CIS Benchmarks** — every mappable check carries an indicative CIS section
  and a **profile level** (1 = broad baseline; 2 = stricter defence-in-depth).
  Scope with `--level 1|2` and `--framework cis`.
- **NIST CSF 2.0** — checks are tagged by function/category (IDENTIFY, PROTECT,
  DETECT; plus RECOVER via rollback).
- **DISA STIG** — the OS-hardening controls align with STIG principles
  (banners, permissions, auditing).
- **OWASP** — the web/application controls follow the Secure Headers and
  secure-configuration guidance.

Compliance is a *floor*, not a ceiling. Passing a benchmark is the start of
security, not the end of it.

---

## 12. Quick checklists

### New server (first hour)
- [ ] Create a non-root admin user with sudo; test SSH login as that user.
- [ ] SSH: disable root login, set up keys, disable password auth (SSH-001/005).
- [ ] Enable a default-deny firewall, allowing only SSH + your services (FW-*).
- [ ] Enable automatic security updates (UPD-002).
- [ ] `sudo auditxs audit --profile server` → `harden` the failures.
- [ ] Install brute-force protection (fail2ban/CrowdSec) and auditd.
- [ ] `sudo auditxs baseline set` and `sudo auditxs schedule enable`.
- [ ] Configure off-box logging and tested backups.

### Workstation
- [ ] `sudo auditxs audit --profile workstation` → review and `harden`.
- [ ] Enable the firewall and automatic updates.
- [ ] Full-disk encryption (set at install time).
- [ ] A password manager; MFA on important accounts.
- [ ] Keep the browser and its extensions minimal and updated.

---

## 13. References

- CIS Benchmarks — <https://www.cisecurity.org/cis-benchmarks>
- NIST Cybersecurity Framework 2.0 — <https://www.nist.gov/cyberframework>
- DISA STIGs — <https://public.cyber.mil/stigs/>
- OWASP Secure Headers Project — <https://owasp.org/www-project-secure-headers/>
- CISA Known Exploited Vulnerabilities — <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- Lynis — <https://cisofy.com/lynis/>
- OpenSCAP & SCAP Security Guide — <https://www.open-scap.org/> · <https://github.com/ComplianceAsCode/content>
- ClamAV — <https://www.clamav.net/> · osquery — <https://osquery.io/> · Trivy — <https://trivy.dev/>
- USBGuard — <https://usbguard.github.io/> · Firejail — <https://firejail.wordpress.com/>
- AuditXS check catalogue — [CHECKS.md](CHECKS.md) · usage — [USAGE.md](USAGE.md)

---

*This guide ships with AuditXS. Run `sudo auditxs audit` to see which of these
practices your system already follows, and `auditxs explain <ID>` for the
detail behind any check.*
