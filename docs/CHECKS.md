# AuditXS check catalogue

Generated from the check registry by `auditxs list --markdown` (v0.7.1).

Legend: checks with an **automatic fix** are only ever applied by
`auditxs harden` after showing you exactly what will change, and every
change is recorded in a snapshot that `auditxs rollback` can restore.
**Manual** checks only report — they never change the system.

## Updates — OS Hardening domain

### UPD-001 — No pending package updates

- **Severity:** medium
- **Profiles:** server,workstation
- **CIS Benchmark:** 1.9 · **Level:** 1
- **NIST CSF 2.0:** ID.RA-01, PR.PS-02
- **Fix:** manual (report-only)

Counts package updates pending in the package manager's cache. Unpatched software is the most common initial access vector; known vulnerabilities in outdated packages are actively exploited. AuditXS never upgrades packages itself because upgrades are not reversible — this check only reports.

### UPD-002 — Automatic security updates are enabled

- **Severity:** high
- **Profiles:** server,workstation
- **CIS Benchmark:** 1.9 · **Level:** 1
- **NIST CSF 2.0:** ID.RA-01, PR.PS-02
- **Fix:** automatic (reversible)

Verifies that the distribution's automatic (security) update mechanism is installed and enabled: unattended-upgrades on Debian/Ubuntu/Pop!_OS, dnf-automatic on Fedora. Automatic security updates close the window between a patch being released and it being applied. On Arch and openSUSE there is no official unattended mechanism, so this check only advises.

**What the fix changes:** Debian family: installs the 'unattended-upgrades' package and writes /etc/apt/apt.conf.d/20auto-upgrades enabling daily list updates and unattended security upgrades. Fedora: installs 'dnf-automatic' and enables the dnf-automatic.timer systemd unit. No other update behaviour is changed.

**How it is reverted:** The snapshot records the previous content of 20auto-upgrades (or that it did not exist) and the previous state of dnf-automatic.timer. 'sudo auditxs rollback' restores both; packages installed by AuditXS are offered for removal during rollback.

### UPD-003 — No reboot pending to activate updates

- **Severity:** medium
- **Profiles:** server,workstation
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** ID.RA-01, PR.PS-02
- **Fix:** manual (report-only)

Detects when installed updates (typically a new kernel or core libraries) require a reboot to actually take effect. Until the reboot, the system keeps running the old, vulnerable code. Report-only: AuditXS never reboots a system.

## Debian — OS Hardening domain

### DEB-001 — APT does not accept unauthenticated packages

- **Severity:** high
- **Profiles:** server,workstation
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** PR.DS-06, PR.PS-01
- **Fix:** automatic (reversible)

Checks that APT is not configured to install packages that fail signature verification (APT::Get::AllowUnauthenticated and Acquire::AllowInsecureRepositories must not be enabled). Package signatures are what stop a tampered mirror or man-in-the-middle from installing malicious code — turning verification off removes the whole chain of trust behind apt.

**What the fix changes:** Writes /etc/apt/apt.conf.d/99-auditxs-secure with 'APT::Get::AllowUnauthenticated "false";' and 'Acquire::AllowInsecureRepositories "false";', re-asserting the secure defaults. Existing apt configuration is not edited.

**How it is reverted:** 'sudo auditxs rollback' deletes the drop-in (or restores its previous content).

### DEB-002 — The Debian/Ubuntu release still receives security support

- **Severity:** high
- **Profiles:** server,workstation
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** ID.RA-01, PR.PS-02
- **Fix:** manual (report-only)

Compares the running release against the known end-of-life horizon. Debian 13 'trixie' (2025) and Debian 12 'bookworm' are current; releases past end-of-life (Debian ≤ 10, Ubuntu non-LTS past date) stop receiving security patches, so every later vulnerability stays unfixed. Report-only: a distribution upgrade is a major operation AuditXS will not perform for you.

### DEB-003 — needrestart reports services needing a restart after upgrades

- **Severity:** low
- **Profiles:** server
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** PR.PS-02, ID.RA-01
- **Fix:** automatic (reversible)

Checks that 'needrestart' is installed. After a library security update, long-running services keep the OLD vulnerable library mapped in memory until restarted; needrestart detects exactly which services need restarting so the patch actually takes effect. Complements the reboot check (UPD-003).

**What the fix changes:** Installs the 'needrestart' package. It then runs automatically after apt operations to list (and, interactively, restart) affected services.

**How it is reverted:** 'sudo auditxs rollback' offers to remove the package it installed.

## OS — OS Hardening domain

### OSH-001 — Remote logins display an authorized-use banner

- **Severity:** low
- **Profiles:** server
- **CIS Benchmark:** 1.7.1 · **Level:** 1
- **NIST CSF 2.0:** PR.AA-06
- **Fix:** automatic (reversible)

Checks that SSH presents a login banner (/etc/issue.net via the sshd 'Banner' directive). DISA STIG and many compliance regimes require a notice that use is monitored and restricted to authorized users — it has legal weight in prosecutions and removes any expectation of privacy. Aligned with STIG SRG-OS-000023.

**What the fix changes:** Writes a generic authorized-use notice to /etc/issue.net (the previous file is saved) and sets 'Banner /etc/issue.net' in /etc/ssh/sshd_config.d/99-auditxs.conf, validated with 'sshd -t'. Organizations with approved legal wording should replace the text in /etc/issue.net afterwards.

**How it is reverted:** 'sudo auditxs rollback' restores the previous /etc/issue.net and SSH configuration.

### OSH-002 — /tmp is a separate filesystem with restrictive mount options

- **Severity:** medium
- **Profiles:** server
- **CIS Benchmark:** 1.1.2 · **Level:** 2
- **NIST CSF 2.0:** PR.PS-01
- **Fix:** manual (report-only)

Checks that /tmp is its own filesystem mounted with nodev, nosuid and noexec (CIS 1.1.2). A separate, restricted /tmp prevents device-file tricks, setuid abuse and direct execution of attacker-staged files in the world-writable directory. Report-only: changing mounts on a running system risks breaking software mid-flight — the finding shows the systemd tmp.mount / fstab path instead. Note noexec on /tmp can affect some installers; test before enforcing.

## SSH — Server Hardening domain

### SSH-001 — SSH root login is disabled

- **Severity:** critical
- **Profiles:** server,workstation
- **CIS Benchmark:** 5.1.20 · **Level:** 1
- **NIST CSF 2.0:** PR.AA-01, PR.AA-03
- **Fix:** automatic (reversible)

Checks the effective 'PermitRootLogin' value (via sshd -T). Direct root login is the primary target of SSH brute-force campaigns and removes the audit trail of who logged in. Administrators should log in as a normal user and elevate with sudo.

**What the fix changes:** Sets 'PermitRootLogin no' in /etc/ssh/sshd_config.d/99-auditxs.conf, validates the configuration with 'sshd -t' and reloads the SSH service. If you currently log in as root over SSH, make sure a normal user with sudo works FIRST — auditxs asks before applying and this warning is shown here on purpose.

**How it is reverted:** The previous SSH configuration is saved in the snapshot; 'sudo auditxs rollback' restores it, re-validates with 'sshd -t' and reloads sshd.

### SSH-002 — SSH authentication attempts are limited

- **Severity:** medium
- **Profiles:** server,workstation
- **CIS Benchmark:** 5.1.5 · **Level:** 1
- **NIST CSF 2.0:** PR.AA-01, PR.AA-03
- **Fix:** automatic (reversible)

Checks that 'MaxAuthTries' is 4 or lower. A low limit slows down password-guessing over a single connection and creates log noise attackers cannot avoid.

**What the fix changes:** Sets 'MaxAuthTries 3' in /etc/ssh/sshd_config.d/99-auditxs.conf, validates with 'sshd -t' and reloads sshd.

**How it is reverted:** 'sudo auditxs rollback' restores the previous SSH configuration files from the snapshot.

### SSH-003 — SSH rejects empty passwords

- **Severity:** critical
- **Profiles:** server,workstation
- **CIS Benchmark:** 5.1.21 · **Level:** 1
- **NIST CSF 2.0:** PR.AA-01, PR.AA-03
- **Fix:** automatic (reversible)

Checks that 'PermitEmptyPasswords' is disabled. Allowing empty passwords over SSH lets anyone log into accounts that have no password set.

**What the fix changes:** Sets 'PermitEmptyPasswords no' in /etc/ssh/sshd_config.d/99-auditxs.conf, validates with 'sshd -t' and reloads sshd.

**How it is reverted:** 'sudo auditxs rollback' restores the previous SSH configuration files from the snapshot.

### SSH-004 — SSH X11 forwarding is disabled on servers

- **Severity:** low
- **Profiles:** server
- **CIS Benchmark:** 5.1.9 · **Level:** 1
- **NIST CSF 2.0:** PR.AA-01, PR.AA-03
- **Fix:** automatic (reversible)

Checks that 'X11Forwarding' is disabled. Servers rarely need to forward graphical applications; when enabled, a compromised server can attack connecting clients through the X11 channel.

**What the fix changes:** Sets 'X11Forwarding no' in /etc/ssh/sshd_config.d/99-auditxs.conf, validates with 'sshd -t' and reloads sshd.

**How it is reverted:** 'sudo auditxs rollback' restores the previous SSH configuration files from the snapshot.

### SSH-005 — SSH uses key-based authentication (passwords disabled)

- **Severity:** high
- **Profiles:** server
- **CIS Benchmark:** 5.1.22 · **Level:** 2
- **NIST CSF 2.0:** PR.AA-01, PR.AA-03
- **Fix:** automatic (reversible)

Checks whether 'PasswordAuthentication' is disabled. Key-based authentication is immune to password guessing and credential stuffing. SAFETY GUARD: AuditXS will only offer this fix when at least one regular user already has ~/.ssh/authorized_keys — otherwise disabling passwords would lock you out, so it only warns.

**What the fix changes:** Sets 'PasswordAuthentication no' in /etc/ssh/sshd_config.d/99-auditxs.conf — but ONLY after re-verifying that at least one regular user has an authorized_keys file; the fix refuses to apply otherwise. Validates with 'sshd -t' and reloads sshd. Test key login in a SECOND terminal before closing your current session.

**How it is reverted:** 'sudo auditxs rollback' restores the previous SSH configuration files from the snapshot and reloads sshd, re-enabling password login.

### SSH-006 — Idle SSH sessions are disconnected

- **Severity:** medium
- **Profiles:** server
- **CIS Benchmark:** 5.1.10 · **Level:** 1
- **NIST CSF 2.0:** PR.AA-01, PR.AA-03
- **Fix:** automatic (reversible)

Checks that 'ClientAliveInterval' (1–900 s) and 'ClientAliveCountMax' (3 or less) are configured so that dead or abandoned SSH sessions are closed instead of staying open indefinitely on unattended terminals.

**What the fix changes:** Sets 'ClientAliveInterval 300' and 'ClientAliveCountMax 2' (idle sessions are dropped after ~10 minutes) in /etc/ssh/sshd_config.d/99-auditxs.conf, validates with 'sshd -t' and reloads sshd.

**How it is reverted:** 'sudo auditxs rollback' restores the previous SSH configuration files from the snapshot.

### SSH-007 — SSH login grace time is limited

- **Severity:** low
- **Profiles:** server,workstation
- **CIS Benchmark:** 5.1.4 · **Level:** 1
- **NIST CSF 2.0:** PR.AA-01, PR.AA-03
- **Fix:** automatic (reversible)

Checks that 'LoginGraceTime' is 60 seconds or less. The grace period holds a connection slot open for unauthenticated clients; long values make denial-of-service against sshd easier.

**What the fix changes:** Sets 'LoginGraceTime 45' in /etc/ssh/sshd_config.d/99-auditxs.conf, validates with 'sshd -t' and reloads sshd.

**How it is reverted:** 'sudo auditxs rollback' restores the previous SSH configuration files from the snapshot.

### SSH-008 — SSH brute-force protection is active (fail2ban/sshguard)

- **Severity:** high
- **Profiles:** server
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** PR.AA-01, PR.AA-03
- **Fix:** automatic (reversible)

Checks that an intrusion-prevention service (fail2ban with an sshd jail, or sshguard) is running to ban IPs that repeatedly fail SSH authentication. Rate-limiting brute-force attempts drastically reduces credential-guessing risk and log noise on exposed servers.

**What the fix changes:** Installs fail2ban (plus the python systemd bindings it needs to read the journal), writes /etc/fail2ban/jail.d/99-auditxs.conf enabling the sshd jail with 'backend = systemd', and enables + restarts the fail2ban service. Existing fail2ban configuration is not modified — the drop-in only enables the sshd jail. Defaults apply (5 failures → 10 minute ban).

**How it is reverted:** 'sudo auditxs rollback' removes the jail drop-in, restores the previous service state and offers to remove packages AuditXS installed.

## Firewall — Network Security domain

### FW-001 — A host firewall is installed

- **Severity:** critical
- **Profiles:** server,workstation
- **CIS Benchmark:** 3.5.1 · **Level:** 1
- **NIST CSF 2.0:** PR.IR-01
- **Fix:** automatic (reversible)

Checks that a host firewall front-end is available: ufw, firewalld, or an active nftables input ruleset. Without a host firewall every listening service — including ones started accidentally — is reachable from the network.

**What the fix changes:** Installs the distribution's conventional firewall front-end: 'ufw' on Debian/Ubuntu/Pop!_OS/Arch, 'firewalld' on Fedora/openSUSE. Installing the package does NOT enable the firewall yet — that is check FW-002, which asks separately.

**How it is reverted:** The installed package is recorded in the snapshot; 'sudo auditxs rollback' offers to remove it again.

### FW-002 — The host firewall is enabled and active

- **Severity:** critical
- **Profiles:** server,workstation
- **CIS Benchmark:** 3.5.1.1 · **Level:** 1
- **NIST CSF 2.0:** PR.IR-01
- **Fix:** automatic (reversible)

Checks that the detected firewall is actually running: 'ufw status' reports active, or the firewalld service is active, or an nftables input ruleset is loaded. An installed-but-disabled firewall provides no protection.

**What the fix changes:** ufw: allows the SSH port(s) first when the system is managed over SSH (lockout guard), then runs 'ufw --force enable'. firewalld: enables and starts the firewalld service and ensures the 'ssh' service is allowed in the active zone when SSH is in use. Nothing else is opened or closed.

**How it is reverted:** The previous firewall state and any SSH allow-rule added by AuditXS are recorded; 'sudo auditxs rollback' disables the firewall again (if it was inactive before) and removes the added rules.

### FW-003 — Firewall default-denies inbound traffic

- **Severity:** high
- **Profiles:** server,workstation
- **CIS Benchmark:** 3.5.1.2 · **Level:** 1
- **NIST CSF 2.0:** PR.IR-01
- **Fix:** automatic (reversible)

Checks that unsolicited inbound traffic is denied by default so only explicitly allowed services are reachable. ufw: 'deny (incoming)' default policy; firewalld: the default zone must not have target ACCEPT.

**What the fix changes:** ufw: runs 'ufw default deny incoming' (existing allow rules keep working). firewalld: sets the default zone's target back to 'default' (reject unmatched traffic) and reloads. Outbound traffic is not touched.

**How it is reverted:** The previous default policy / zone target is recorded; 'sudo auditxs rollback' restores it.

### FW-004 — ufw logging is enabled

- **Severity:** low
- **Profiles:** server,workstation
- **CIS Benchmark:** 3.5.1.3 · **Level:** 1
- **NIST CSF 2.0:** DE.CM-01, PR.PS-04
- **Fix:** automatic (reversible)

Checks that ufw logging is on (at least 'low'), so blocked/allowed connection decisions are recorded. Firewall logs are essential evidence when investigating scans, intrusions or misconfigured services. Only applies where ufw is the active firewall.

**What the fix changes:** Runs 'ufw logging low', recording the previous logging state so rollback restores it. No rules are changed.

**How it is reverted:** 'sudo auditxs rollback' restores the previous ufw logging level.

### FW-005 — A firewall management GUI is available on desktops (gufw)

- **Severity:** low
- **Profiles:** workstation
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** PR.IR-01
- **Fix:** manual (report-only)

On workstations with a graphical desktop, checks for 'gufw' — the graphical front-end for ufw — so non-CLI users can review and manage firewall rules. Purely a usability/visibility control; the firewall itself is covered by FW-001..004. Report-only.

## Accounts — Server Hardening domain

### ACC-001 — Only root has UID 0

- **Severity:** critical
- **Profiles:** server,workstation
- **CIS Benchmark:** 6.2.9 · **Level:** 1
- **NIST CSF 2.0:** PR.AA-01, PR.AA-05
- **Fix:** manual (report-only)

Scans /etc/passwd for accounts other than 'root' with UID 0. A second UID-0 account is a classic backdoor: it has full root power under an innocent name. Report-only: removing accounts is a decision AuditXS will not automate.

### ACC-002 — No accounts have empty passwords

- **Severity:** critical
- **Profiles:** server,workstation
- **CIS Benchmark:** 6.2.8 · **Level:** 1
- **NIST CSF 2.0:** PR.AA-01, PR.AA-05
- **Fix:** automatic (reversible)

Scans /etc/shadow for accounts whose password field is empty. Such accounts can be logged into without any password at all (locally, and over any service that permits it).

**What the fix changes:** Locks each affected account with 'passwd -l <user>' (places a '!' in the password field, blocking password login while leaving the account and its files intact). /etc/shadow is backed up to the snapshot first.

**How it is reverted:** 'sudo auditxs rollback' restores the saved /etc/shadow, returning the accounts to their previous state.

### ACC-003 — Password aging policy is configured

- **Severity:** medium
- **Profiles:** server,workstation
- **CIS Benchmark:** 5.5.1.1 · **Level:** 1
- **NIST CSF 2.0:** PR.AA-01, PR.AA-05
- **Fix:** automatic (reversible)

Checks /etc/login.defs for a sane password aging baseline: PASS_MAX_DAYS ≤ 365, PASS_MIN_DAYS ≥ 1 and PASS_WARN_AGE ≥ 7. This bounds how long a leaked password stays valid and prevents instant password re-use. Applies to newly created accounts; existing accounts keep their current aging until changed with 'chage'.

**What the fix changes:** Edits /etc/login.defs (backed up first) setting PASS_MAX_DAYS 365, PASS_MIN_DAYS 1, PASS_WARN_AGE 7. Existing accounts are NOT modified — the report lists the 'chage' command to update them if you wish.

**How it is reverted:** 'sudo auditxs rollback' restores the saved /etc/login.defs.

### ACC-004 — sudo always requires a password

- **Severity:** high
- **Profiles:** server,workstation
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** PR.AA-01, PR.AA-05
- **Fix:** manual (report-only)

Scans /etc/sudoers and /etc/sudoers.d/ for NOPASSWD entries. Passwordless sudo turns any compromise of that user account (or an unlocked terminal) into an instant full-root compromise. Report-only: sudoers changes are risky to automate, so AuditXS shows you exactly which lines to review with 'visudo'.

### ACC-005 — System accounts cannot log in

- **Severity:** medium
- **Profiles:** server,workstation
- **CIS Benchmark:** 5.5.2 · **Level:** 1
- **NIST CSF 2.0:** PR.AA-01, PR.AA-05
- **Fix:** automatic (reversible)

Checks that system (service) accounts — UID below the regular-user threshold — have a non-login shell such as /usr/sbin/nologin. Service accounts with real shells are convenient footholds after a service compromise.

**What the fix changes:** Backs up /etc/passwd, then sets the shell of each affected system account to 'nologin' with 'usermod -s'. Regular user accounts and root are never touched.

**How it is reverted:** 'sudo auditxs rollback' restores the saved /etc/passwd, returning the original shells.

### ACC-006 — Default umask is restrictive (027)

- **Severity:** low
- **Profiles:** server
- **CIS Benchmark:** 5.5.5 · **Level:** 2
- **NIST CSF 2.0:** PR.AA-01, PR.AA-05
- **Fix:** automatic (reversible)

Checks that the default UMASK in /etc/login.defs is 027 or stricter, so files created by users are not readable by every other account on the system. Applied to the server profile only — on single-user workstations the default 022 is a common and acceptable trade-off.

**What the fix changes:** Edits /etc/login.defs (backed up first) setting 'UMASK 027'. Only affects newly created login sessions; existing files are not changed.

**How it is reverted:** 'sudo auditxs rollback' restores the saved /etc/login.defs.

### ACC-007 — Password quality requirements are enforced

- **Severity:** medium
- **Profiles:** server,workstation
- **CIS Benchmark:** 5.4.1 · **Level:** 1
- **NIST CSF 2.0:** PR.AA-01, PR.AA-05
- **Fix:** automatic (reversible)

Checks that pam_pwquality is part of the PAM password stack and that the effective minimum password length (minlen, including /etc/security/pwquality.conf.d drop-ins) is at least 12. Without quality rules users can set trivially guessable passwords. The policy applies when passwords are set or changed — existing passwords are not affected.

**What the fix changes:** Debian family: installs 'libpam-pwquality' (Debian wires it into the PAM stack automatically via pam-auth-update). openSUSE: enables the module with 'pam-config -a --pwquality' (the distribution's supported tool). Then writes /etc/security/pwquality.conf.d/99-auditxs.conf with 'minlen = 12' and 'minclass = 3'. PAM files are never edited directly. On Fedora/Arch with the module missing, AuditXS only reports (PAM stacks there should be changed via authselect / by hand).

**How it is reverted:** 'sudo auditxs rollback' removes the pwquality drop-in, reverts the pam-config change on openSUSE, and offers to remove the package if AuditXS installed it.

## Privileged — Server Hardening domain

### PRV-001 — sudo sessions use a pty and are logged

- **Severity:** medium
- **Profiles:** server,workstation
- **CIS Benchmark:** 5.3.4 · **Level:** 1
- **NIST CSF 2.0:** PR.AA-05, PR.PS-04
- **Fix:** automatic (reversible)

Checks that sudo is configured with 'Defaults use_pty' (prevents a malicious program run under sudo from detaching into the background with root privileges — CIS 5.2.2) and 'Defaults logfile' (a dedicated, append-friendly record of every sudo command — CIS 5.2.3). Privileged-command accountability is a core audit-trail requirement.

**What the fix changes:** Creates /etc/sudoers.d/99-auditxs (mode 0440) containing only 'Defaults use_pty' and 'Defaults logfile="/var/log/sudo.log"'. The file is validated with 'visudo -cf' and the whole sudo configuration re-validated with 'visudo -c'; if either fails the file is removed immediately. No existing sudoers file is edited.

**How it is reverted:** 'sudo auditxs rollback' deletes the drop-in (or restores its previous content).

### PRV-002 — SSH logins use multi-factor authentication

- **Severity:** high
- **Profiles:** server
- **CIS Benchmark:** 5.3.7 · **Level:** 1
- **NIST CSF 2.0:** PR.AA-03
- **Fix:** manual (report-only)

Checks whether SSH requires more than one authentication factor: either 'AuthenticationMethods' chains factors (e.g. 'publickey,keyboard-interactive'), or an MFA PAM module (pam_google_authenticator, pam_u2f, pam_oath, pam_duo) is wired into the sshd stack. MFA is one of the highest-impact controls against credential theft. Report-only: enabling MFA requires enrolling every administrator first — automating it would lock people out, so AuditXS explains the path instead (aligned with NIST CSF PR.AA-03).

### PRV-003 — Administrative account inventory

- **Severity:** low
- **Profiles:** server,workstation
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** PR.AA-05, ID.AM-05
- **Fix:** manual (report-only)

Lists every account with administrative rights: members of the sudo/wheel/admin groups plus explicit user entries in sudoers. Least privilege starts with knowing who holds privilege — review this list regularly and remove anyone who no longer needs it. Informational.

## Filesystem — OS Hardening domain

### FS-001 — World-writable directories have the sticky bit

- **Severity:** medium
- **Profiles:** server,workstation
- **CIS Benchmark:** 1.1.9 · **Level:** 1
- **NIST CSF 2.0:** PR.DS-01, PR.AA-05
- **Fix:** automatic (reversible)

Finds directories that any user may write to (like /tmp) but that lack the sticky bit. Without it, any user can delete or rename other users' files in that directory — a classic path for tmp-race attacks.

**What the fix changes:** Adds the sticky bit (chmod +t) to each affected directory. The previous mode of every directory is recorded in the snapshot. No files are touched, only directory modes.

**How it is reverted:** 'sudo auditxs rollback' restores each directory's exact previous mode.

### FS-002 — No world-writable files

- **Severity:** medium
- **Profiles:** server,workstation
- **CIS Benchmark:** 6.1.10 · **Level:** 1
- **NIST CSF 2.0:** PR.DS-01, PR.AA-05
- **Fix:** automatic (reversible)

Finds regular files that ANY user on the system may modify. World-writable files let an unprivileged user tamper with data or scripts that other users — or root — later read or execute.

**What the fix changes:** Removes the world-write bit (chmod o-w) from each affected file. Every file's previous mode is recorded in the snapshot. Nothing is deleted and no other permission bits change.

**How it is reverted:** 'sudo auditxs rollback' restores each file's exact previous mode.

### FS-003 — No unowned or ungrouped files

- **Severity:** low
- **Profiles:** server,workstation
- **CIS Benchmark:** 6.1.11 · **Level:** 1
- **NIST CSF 2.0:** PR.DS-01, PR.AA-05
- **Fix:** manual (report-only)

Finds files whose owner or group no longer exists (usually left behind by removed packages or deleted users). A future account created with the same UID/GID silently inherits access to them. Report-only: correct ownership depends on what the files are, so AuditXS lists them with 'chown' guidance.

### FS-004 — Sensitive system files have strict permissions

- **Severity:** high
- **Profiles:** server,workstation
- **CIS Benchmark:** 6.1.2 · **Level:** 1
- **NIST CSF 2.0:** PR.DS-01, PR.AA-05
- **Fix:** automatic (reversible)

Verifies that credential and boot files are not readable/writable more broadly than needed: /etc/shadow and /etc/gshadow (and their '-' backups) at most 640, /etc/passwd and /etc/group at most 644, /etc/crontab and GRUB configuration at most 600, SSH host private keys at most 600. AuditXS only ever TIGHTENS modes — files already stricter than the baseline (e.g. Fedora's shadow at 000) are left untouched.

**What the fix changes:** For each file more permissive than its baseline, chmods it down to the baseline mode. Previous modes are recorded per file in the snapshot.

**How it is reverted:** 'sudo auditxs rollback' restores each file's exact previous mode.

### FS-005 — Home directories are not accessible to other users

- **Severity:** medium
- **Profiles:** server,workstation
- **CIS Benchmark:** 6.2.7 · **Level:** 1
- **NIST CSF 2.0:** PR.DS-01, PR.AA-05
- **Fix:** automatic (reversible)

Checks that each regular user's home directory is mode 750 or stricter, so other local users cannot read personal files, SSH keys, browser profiles or shell history.

**What the fix changes:** Chmods each over-permissive home directory to 750. Previous modes are recorded per directory. Only the home directory itself is changed — never its contents.

**How it is reverted:** 'sudo auditxs rollback' restores each home directory's exact previous mode.

### FS-006 — SUID/SGID binary inventory

- **Severity:** low
- **Profiles:** server,workstation
- **CIS Benchmark:** 6.1.13 · **Level:** 1
- **NIST CSF 2.0:** PR.DS-01, PR.AA-05
- **Fix:** manual (report-only)

Inventories setuid/setgid binaries — programs that run with elevated privileges no matter who starts them — and flags any outside the well-known baseline (sudo, passwd, mount, ...). Unexpected SUID binaries are a common persistence technique. Report-only: removing the bit can break legitimate software, so review each finding.

## Kernel — OS Hardening domain

### KRN-001 — Address space layout randomization (ASLR) is fully enabled

- **Severity:** high
- **Profiles:** server,workstation
- **CIS Benchmark:** 1.5.3 · **Level:** 1
- **NIST CSF 2.0:** PR.PS-01, PR.IR-01
- **Fix:** automatic (reversible)

Checks kernel.randomize_va_space=2. ASLR randomizes process memory layout, making memory-corruption exploits substantially harder. 2 (full, including heap) is the kernel default; anything lower means it was weakened.

**What the fix changes:** Writes /etc/sysctl.d/99-auditxs-krn-001.conf with 'kernel.randomize_va_space = 2' and applies it at runtime. Previous value is recorded.

**How it is reverted:** 'sudo auditxs rollback' deletes the drop-in and restores the previous runtime value.

### KRN-002 — Kernel address and log exposure is restricted

- **Severity:** medium
- **Profiles:** server,workstation
- **CIS Benchmark:** 1.5.1 · **Level:** 1
- **NIST CSF 2.0:** PR.PS-01, PR.IR-01
- **Fix:** automatic (reversible)

Checks kernel.kptr_restrict ≥ 1 (hide kernel pointers from unprivileged users) and kernel.dmesg_restrict = 1 (require privilege to read the kernel log). Kernel addresses and dmesg output are building blocks for kernel exploits and information leaks.

**What the fix changes:** Writes /etc/sysctl.d/99-auditxs-krn-002.conf setting only the values that are currently weaker than recommended (kptr_restrict=1, dmesg_restrict=1) and applies them at runtime. Values already stricter are left untouched.

**How it is reverted:** 'sudo auditxs rollback' deletes the drop-in and restores the previous runtime values.

### KRN-003 — TCP SYN cookies are enabled

- **Severity:** high
- **Profiles:** server,workstation
- **CIS Benchmark:** 3.3.9 · **Level:** 1
- **NIST CSF 2.0:** PR.PS-01, PR.IR-01
- **Fix:** automatic (reversible)

Checks net.ipv4.tcp_syncookies=1. SYN cookies keep the system reachable during SYN-flood denial-of-service attacks instead of exhausting the connection backlog.

**What the fix changes:** Writes /etc/sysctl.d/99-auditxs-krn-003.conf with 'net.ipv4.tcp_syncookies = 1' and applies it at runtime.

**How it is reverted:** 'sudo auditxs rollback' deletes the drop-in and restores the previous runtime value.

### KRN-004 — ICMP redirects are ignored and not sent

- **Severity:** medium
- **Profiles:** server,workstation
- **CIS Benchmark:** 3.3.2 · **Level:** 1
- **NIST CSF 2.0:** PR.PS-01, PR.IR-01
- **Fix:** automatic (reversible)

Checks that the system neither accepts nor sends ICMP redirect messages (IPv4 and IPv6). Accepted redirects let an on-path attacker rewrite the routing table and intercept traffic; hosts that are not routers have no reason to send them.

**What the fix changes:** Writes /etc/sysctl.d/99-auditxs-krn-004.conf disabling accept_redirects (v4+v6, all/default), secure_redirects and send_redirects, and applies the values at runtime.

**How it is reverted:** 'sudo auditxs rollback' deletes the drop-in and restores the previous runtime values.

### KRN-005 — Source-routed packets are rejected

- **Severity:** medium
- **Profiles:** server,workstation
- **CIS Benchmark:** 3.3.1 · **Level:** 1
- **NIST CSF 2.0:** PR.PS-01, PR.IR-01
- **Fix:** automatic (reversible)

Checks that accept_source_route is 0 for IPv4 and IPv6. Source routing lets the sender dictate a packet's path — a technique for bypassing firewall policy and spoofing; end hosts should never accept it.

**What the fix changes:** Writes /etc/sysctl.d/99-auditxs-krn-005.conf disabling accept_source_route (v4+v6, all/default) and applies the values at runtime.

**How it is reverted:** 'sudo auditxs rollback' deletes the drop-in and restores the previous runtime values.

### KRN-006 — Reverse-path filtering is enabled

- **Severity:** medium
- **Profiles:** server,workstation
- **CIS Benchmark:** 3.3.7 · **Level:** 1
- **NIST CSF 2.0:** PR.PS-01, PR.IR-01
- **Fix:** automatic (reversible)

Checks net.ipv4.conf.{all,default}.rp_filter is 1 (strict) or 2 (loose). Reverse-path filtering drops packets whose source address could not be routed back the way they came, blunting IP spoofing.

**What the fix changes:** Writes /etc/sysctl.d/99-auditxs-krn-006.conf with rp_filter=1 for all/default and applies it at runtime. If your host does asymmetric routing (rare, multi-homed setups), skip this fix.

**How it is reverted:** 'sudo auditxs rollback' deletes the drop-in and restores the previous runtime values.

### KRN-007 — Suspicious (martian) packets are logged

- **Severity:** low
- **Profiles:** server
- **CIS Benchmark:** 3.3.4 · **Level:** 2
- **NIST CSF 2.0:** PR.PS-01, PR.IR-01
- **Fix:** automatic (reversible)

Checks net.ipv4.conf.{all,default}.log_martians=1 so packets with impossible source addresses are logged. On servers this gives early warning of spoofing or misrouted traffic; on busy networks it adds log volume, which is why it is server-profile only.

**What the fix changes:** Writes /etc/sysctl.d/99-auditxs-krn-007.conf with log_martians=1 for all/default and applies it at runtime.

**How it is reverted:** 'sudo auditxs rollback' deletes the drop-in and restores the previous runtime values.

### KRN-008 — IP forwarding is disabled (unless this host routes traffic)

- **Severity:** high
- **Profiles:** server,workstation
- **CIS Benchmark:** 3.2.1 · **Level:** 1
- **NIST CSF 2.0:** PR.PS-01, PR.IR-01
- **Fix:** automatic (reversible)

Checks that IPv4/IPv6 forwarding is off. A host that silently forwards packets can be abused to pivot between networks. DETECTION: if Docker, Podman or libvirt is present, forwarding is required and this check passes with a note instead.

**What the fix changes:** Writes /etc/sysctl.d/99-auditxs-krn-008.conf disabling net.ipv4.ip_forward and net.ipv6.conf.all.forwarding and applies it at runtime. The fix is only offered when no container/VM runtime was detected — do not apply it on routers or VPN gateways.

**How it is reverted:** 'sudo auditxs rollback' deletes the drop-in and restores the previous runtime values.

### KRN-009 — Core dumps of privileged programs are disabled

- **Severity:** medium
- **Profiles:** server,workstation
- **CIS Benchmark:** 1.5.1 · **Level:** 1
- **NIST CSF 2.0:** PR.PS-01, PR.IR-01
- **Fix:** automatic (reversible)

Checks fs.suid_dumpable=0. Core dumps of setuid programs can spill password hashes and other secrets those programs held in memory into files an attacker may read.

**What the fix changes:** Writes /etc/sysctl.d/99-auditxs-krn-009.conf with 'fs.suid_dumpable = 0' and applies it at runtime.

**How it is reverted:** 'sudo auditxs rollback' deletes the drop-in and restores the previous runtime value.

### KRN-010 — Ctrl-Alt-Del does not reboot the system

- **Severity:** low
- **Profiles:** server
- **CIS Benchmark:** 1.4.3 · **Level:** 1
- **NIST CSF 2.0:** PR.PS-01, PR.IR-01
- **Fix:** automatic (reversible)

Checks that the ctrl-alt-del systemd target is masked. On servers, anyone with (physical or remote-console) keyboard access could otherwise trigger an unclean reboot without authentication.

**What the fix changes:** Masks the target by linking /etc/systemd/system/ctrl-alt-del.target to /dev/null and runs 'systemctl daemon-reload'. No other keyboard behaviour changes.

**How it is reverted:** 'sudo auditxs rollback' removes the mask link (restoring the saved file if one existed) and reloads systemd.

## MAC — OS Hardening domain

### MAC-001 — A mandatory access control system is active (SELinux/AppArmor)

- **Severity:** high
- **Profiles:** server,workstation
- **CIS Benchmark:** 1.6.1 · **Level:** 1
- **NIST CSF 2.0:** PR.PS-01, PR.AA-05
- **Fix:** manual (report-only)

Checks whether SELinux is enforcing or AppArmor is active with loaded profiles. MAC systems confine what a compromised service can do, containing exploits that would otherwise have the full run of the system. Every supported distribution ships one: SELinux on Fedora; AppArmor on Ubuntu, Pop!_OS, Debian and openSUSE (Arch supports AppArmor but does not enable it by default). Report-only: enabling a MAC system needs kernel-parameter/bootloader changes and a reboot, which cannot be made safely reversible — the finding explains the right path for your distribution instead.

## Services — Application Hardening domain

### SVC-001 — Legacy plaintext network services are not running

- **Severity:** high
- **Profiles:** server,workstation
- **CIS Benchmark:** 2.3 · **Level:** 1
- **NIST CSF 2.0:** PR.PS-01
- **Fix:** automatic (reversible)

Checks for enabled/active legacy services that transmit credentials in cleartext or are historically unsafe: telnet, rsh/rlogin/rexec, tftp, xinetd/inetd, NIS (ypserv). These have modern encrypted replacements (SSH, SFTP) and should not run anywhere.

**What the fix changes:** Disables and stops each detected unit with 'systemctl disable --now', recording its previous enabled/active state. Packages are left installed (remove them manually if unneeded).

**How it is reverted:** 'sudo auditxs rollback' re-enables and restarts each service exactly as it was before.

### SVC-002 — Avahi (mDNS) daemon is disabled on servers

- **Severity:** medium
- **Profiles:** server
- **CIS Benchmark:** 2.1.3 · **Level:** 2
- **NIST CSF 2.0:** PR.PS-01
- **Fix:** automatic (reversible)

Checks that avahi-daemon is not running. Avahi advertises the machine and its services on the local network (mDNS/zeroconf) — useful on desktops, but on servers it is unneeded broadcast surface and information disclosure.

**What the fix changes:** Disables and stops avahi-daemon.service and avahi-daemon.socket, recording their previous state. The package stays installed.

**How it is reverted:** 'sudo auditxs rollback' re-enables and restarts the units exactly as they were.

### SVC-003 — Printing services (CUPS) are disabled on servers

- **Severity:** medium
- **Profiles:** server
- **CIS Benchmark:** 2.1.4 · **Level:** 2
- **NIST CSF 2.0:** PR.PS-01
- **Fix:** automatic (reversible)

Checks that CUPS is not running. Print services listen on the network and have a long CVE history; servers that never print should not run them.

**What the fix changes:** Disables and stops cups.service, cups.socket and cups-browsed.service (where present), recording their previous state. The packages stay installed.

**How it is reverted:** 'sudo auditxs rollback' re-enables and restarts the units exactly as they were.

### SVC-004 — Bluetooth is disabled on servers

- **Severity:** medium
- **Profiles:** server
- **CIS Benchmark:** 2.1.2 · **Level:** 2
- **NIST CSF 2.0:** PR.PS-01
- **Fix:** automatic (reversible)

Checks that the bluetooth service is not running. Servers rarely use Bluetooth; the stack adds kernel attack surface reachable from physical proximity.

**What the fix changes:** Disables and stops bluetooth.service, recording its previous state. The package stays installed.

**How it is reverted:** 'sudo auditxs rollback' re-enables and restarts the unit exactly as it was.

### SVC-005 — systemd service sandboxing overview

- **Severity:** low
- **Profiles:** server,workstation
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** PR.PS-01
- **Fix:** manual (report-only)

Summarizes 'systemd-analyze security', which scores every running service by how much sandboxing (namespaces, capability limits, syscall filters) it uses. Informational: use it to pick services worth confining with systemd hardening directives.

## Applications — Application Hardening domain

### APP-001 — nginx does not disclose its version (server_tokens off)

- **Severity:** medium
- **Profiles:** server
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** PR.PS-01
- **Fix:** automatic (reversible)

Checks that nginx is configured with 'server_tokens off' so error pages and the Server header stop advertising the exact version. Version disclosure gives attackers a shortcut to matching exploits; suppressing it is a baseline web-server hardening step.

**What the fix changes:** Writes /etc/nginx/conf.d/99-auditxs.conf containing 'server_tokens off;'. The configuration is validated with 'nginx -t' — if validation fails the file is removed immediately — then nginx is reloaded (no downtime). Applied only when nginx.conf includes /etc/nginx/conf.d.

**How it is reverted:** 'sudo auditxs rollback' deletes the drop-in and reloads nginx.

### APP-002 — Apache does not disclose version details

- **Severity:** medium
- **Profiles:** server
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** PR.PS-01
- **Fix:** automatic (reversible)

Checks that Apache is configured with 'ServerTokens Prod' and 'ServerSignature Off' so responses and error pages stop advertising the exact server version and modules. Same rationale as APP-001: version disclosure is free reconnaissance.

**What the fix changes:** Writes a labelled config drop-in (Debian family: /etc/apache2/conf-available/zz-auditxs.conf enabled via symlink; Fedora: /etc/httpd/conf.d/zz-auditxs.conf; openSUSE: /etc/apache2/conf.d/zz-auditxs.conf) setting ServerTokens Prod and ServerSignature Off. Validated with the Apache config test — removed immediately if validation fails — then Apache is reloaded.

**How it is reverted:** 'sudo auditxs rollback' deletes the drop-in (and its enabling symlink on the Debian family) and reloads Apache.

### APP-003 — Apache sends security response headers

- **Severity:** medium
- **Profiles:** server
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** PR.PS-01, PR.DS-02
- **Fix:** automatic (reversible)

Checks that Apache emits baseline browser-security headers: X-Content-Type-Options (nosniff), X-Frame-Options (clickjacking protection) and Referrer-Policy. These instruct browsers to behave defensively and are a standard part of web-server hardening (OWASP Secure Headers). HSTS is intentionally left out of the automatic fix because it must only be enabled once HTTPS is confirmed working.

**What the fix changes:** Enables mod_headers and writes a labelled conf drop-in (Debian: /etc/apache2/conf-available/zz-auditxs-headers.conf enabled via symlink; Fedora: /etc/httpd/conf.d/; openSUSE: /etc/apache2/conf.d/) adding X-Content-Type-Options, X-Frame-Options and Referrer-Policy. Validated with the Apache config test — removed on failure — then Apache is reloaded.

**How it is reverted:** 'sudo auditxs rollback' deletes the drop-in (and its enabling symlink) and reloads Apache.

### APP-004 — Web server does not list directory contents

- **Severity:** medium
- **Profiles:** server
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** PR.PS-01, PR.DS-01
- **Fix:** manual (report-only)

Checks that automatic directory listing is disabled. When a directory has no index file and listing is on, the web server exposes the full file tree — source, backups, configs — to anyone. Apache: the 'Indexes' option should not be enabled; nginx: 'autoindex' should be off (its default). Report-only: the correct place to disable it depends on your vhost/.htaccess layout, so AuditXS shows where it is enabled rather than guessing.

## PHP — Application Hardening domain

### PHP-001 — PHP does not expose its version (expose_php Off)

- **Severity:** medium
- **Profiles:** server
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** PR.PS-01
- **Fix:** automatic (reversible)

Checks that 'expose_php' is Off so PHP stops advertising its exact version in the X-Powered-By response header and on error pages. Version disclosure hands attackers a shortcut to matching exploits.

**What the fix changes:** Sets 'expose_php = Off' in a 99-auditxs.ini drop-in inside each web SAPI's conf.d directory (Apache mod_php and PHP-FPM). Restart the web server / php-fpm to apply.

**How it is reverted:** 'sudo auditxs rollback' removes the drop-in (or restores its previous content).

### PHP-002 — PHP does not display errors to visitors (display_errors Off)

- **Severity:** medium
- **Profiles:** server
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** PR.PS-01, PR.PS-04
- **Fix:** automatic (reversible)

Checks that 'display_errors' is Off. Rendered PHP errors leak file paths, SQL fragments and stack details to anyone hitting the page — reconnaissance gold. Errors should go to the log, not the browser.

**What the fix changes:** Sets 'display_errors = Off' (and leaves logging intact) in the 99-auditxs.ini drop-in for each web SAPI. Restart php-fpm / apache2 to apply.

**How it is reverted:** 'sudo auditxs rollback' removes the drop-in (or restores its previous content).

### PHP-003 — PHP session cookies are hardened (HttpOnly + Secure + SameSite)

- **Severity:** medium
- **Profiles:** server
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** PR.DS-02, PR.AA-05
- **Fix:** automatic (reversible)

Checks session.cookie_httponly (blocks JavaScript from reading the session cookie — mitigates XSS session theft), session.cookie_secure (cookie only sent over HTTPS) and session.cookie_samesite (CSRF mitigation). These are baseline web-session protections.

**What the fix changes:** Sets session.cookie_httponly = On, session.cookie_secure = On and session.cookie_samesite = Lax in the 99-auditxs.ini drop-in for each web SAPI. NOTE: cookie_secure requires the site to be served over HTTPS; on a plain-HTTP test site, sessions will only work once TLS is in place. Restart php-fpm / apache2 to apply.

**How it is reverted:** 'sudo auditxs rollback' removes the drop-in (or restores its previous content).

### PHP-004 — Dangerous PHP functions are reviewed (disable_functions)

- **Severity:** high
- **Profiles:** server
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** PR.PS-01
- **Fix:** manual (report-only)

Checks whether high-risk functions that turn a PHP-code-execution bug into full command execution (exec, system, shell_exec, passthru, popen, proc_open, and the config-reading php_uname) are listed in 'disable_functions'. Report-only: many legitimate applications and control panels rely on some of these, so blindly disabling them can break the site — AuditXS shows you the recommended list to add after confirming your apps do not need them.

## Network — Network Security domain

### NET-001 — Listening network services inventory

- **Severity:** low
- **Profiles:** server,workstation
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** PR.IR-01, DE.CM-01
- **Fix:** manual (report-only)

Lists every TCP/UDP port the system is listening on. Informational — the point is that YOU can verify each entry is expected. Anything you do not recognize deserves investigation ('ss -tulpn' shows the owning process).

### NET-002 — Uncommon network protocols are disabled

- **Severity:** medium
- **Profiles:** server,workstation
- **CIS Benchmark:** 3.4 · **Level:** 2
- **NIST CSF 2.0:** PR.IR-01, DE.CM-01
- **Fix:** automatic (reversible)

Checks that rarely-used kernel network protocols (DCCP, SCTP, RDS, TIPC) cannot be auto-loaded. These modules have repeatedly been the vehicle for kernel privilege-escalation bugs, and almost no system needs them. If you knowingly use one (e.g. SCTP for telecom software), skip this fix.

**What the fix changes:** Writes /etc/modprobe.d/99-auditxs-netproto.conf with 'install <module> /bin/false' for dccp, sctp, rds and tipc, preventing them from being loaded in the future. Modules already loaded are reported but NOT unloaded (no disruption).

**How it is reverted:** 'sudo auditxs rollback' deletes the modprobe drop-in (or restores its previous content).

### NET-003 — No wireless interfaces on servers

- **Severity:** low
- **Profiles:** server
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** PR.IR-01, DE.CM-01
- **Fix:** manual (report-only)

Detects Wi-Fi interfaces on machines using the server profile. Wireless links on servers bypass wired network controls and extend the attack surface into radio range. Report-only: disabling networking automatically could sever your own connection, so AuditXS shows the 'rfkill block wifi' command instead.

### NET-004 — Listening ports match the approved allowlist

- **Severity:** high
- **Profiles:** server
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** DE.CM-01, PR.IR-01
- **Fix:** manual (report-only)

Compares every listening TCP/UDP port against the administrator-approved allowlist in /etc/auditxs/allowed-ports.conf. This turns 'what is listening?' (NET-001) into drift detection: a service that appears without being approved — a forgotten debug port, a dropped implant, a misconfigured install — is flagged immediately. Report-only: YOU decide what belongs on the list; AuditXS never opens or closes ports. Pair with 'auditxs schedule' for continuous drift monitoring.

## Mail — Application Hardening domain

### PFX-001 — Postfix is not an open relay

- **Severity:** critical
- **Profiles:** server
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** PR.AA-05, PR.IR-01
- **Fix:** manual (report-only)

Checks Postfix relay controls: smtpd_relay_restrictions / smtpd_recipient_restrictions must reject mail for domains you do not host (reject_unauth_destination), and mynetworks must not be dangerously broad. An open relay is abused within hours to send spam and gets your IP blacklisted. Report-only — relay policy depends on your network.

### PFX-002 — Postfix requires TLS for SMTP

- **Severity:** high
- **Profiles:** server
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** PR.DS-02
- **Fix:** manual (report-only)

Checks that Postfix offers/uses TLS: smtpd_tls_security_level should be 'may' (opportunistic) or 'encrypt', and for submission (port 587) 'encrypt'. Without TLS, credentials and mail cross the network in cleartext. Report-only.

### PFX-003 — Postfix SMTP banner does not leak software details

- **Severity:** low
- **Profiles:** server
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** PR.PS-01
- **Fix:** manual (report-only)

Checks that smtpd_banner does not advertise the Postfix/OS version and that the VRFY command is disabled (disable_vrfy_command=yes — VRFY lets attackers enumerate valid usernames). Report-only.

### DOV-001 — Dovecot disables cleartext authentication without TLS

- **Severity:** high
- **Profiles:** server
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** PR.DS-02, PR.AA-01
- **Fix:** manual (report-only)

Checks that Dovecot's 'disable_plaintext_auth' is yes, so IMAP/POP passwords are never accepted over an unencrypted connection. Otherwise a passive network observer captures every mailbox password. Report-only — Dovecot config is include-based and easy to break.

### DOV-002 — Dovecot enforces modern TLS

- **Severity:** high
- **Profiles:** server
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** PR.DS-02
- **Fix:** manual (report-only)

Checks that Dovecot requires SSL/TLS (ssl = required) and disables obsolete protocols (ssl_min_protocol = TLSv1.2 or higher). Old TLS/SSL versions have exploitable weaknesses. Report-only.

## DNS — Network Security domain

### BND-001 — BIND does not allow open recursion

- **Severity:** high
- **Profiles:** server
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** PR.IR-01, PR.AA-05
- **Fix:** manual (report-only)

Checks that BIND restricts recursion (allow-recursion / allow-query) to trusted clients rather than the whole internet. An open recursive resolver is abused for DNS amplification DDoS and cache poisoning. Report-only — recursion policy depends on who your resolver serves.

### BND-002 — BIND hides its version

- **Severity:** low
- **Profiles:** server
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** PR.PS-01
- **Fix:** manual (report-only)

Checks that BIND overrides the 'version' option (version "not disclosed";) so a 'dig chaos txt version.bind' query does not reveal the exact BIND version and its known CVEs. Report-only.

### UNB-001 — Unbound restricts access and hides identity

- **Severity:** high
- **Profiles:** server
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** PR.IR-01, PR.PS-01
- **Fix:** manual (report-only)

Checks Unbound's access-control and information-leak settings: 'access-control' should not allow the whole internet (open resolver / amplification), and hide-identity / hide-version should be yes. Report-only.

## Database — Database Hardening domain

### DB-001 — MySQL/MariaDB is not needlessly exposed to the network

- **Severity:** high
- **Profiles:** server
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** PR.DS-01, PR.DS-02, PR.AA-05
- **Fix:** manual (report-only)

When MySQL/MariaDB is installed, checks whether it listens only on localhost. A database reachable from the network is a direct target for credential attacks and must sit behind strict firewall rules with TLS enforced. Report-only: AuditXS never edits database configuration. If exposure is found, the finding lists the hardening steps: set 'bind-address = 127.0.0.1' (if remote access is not required), 'require_secure_transport = ON' for TLS, run 'mysql_secure_installation' (removes anonymous users/test DB), and enable at-rest encryption (innodb_encrypt_tables / keyring) per your engine's documentation.

### DB-002 — PostgreSQL uses strong authentication and is not needlessly exposed

- **Severity:** high
- **Profiles:** server
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** PR.DS-01, PR.DS-02, PR.AA-01
- **Fix:** manual (report-only)

When PostgreSQL is installed, checks (1) whether it listens only on localhost and (2) whether pg_hba.conf contains 'trust' entries, which grant access WITHOUT ANY authentication. Report-only: AuditXS never edits database configuration. Findings include the fix path: replace 'trust' with 'scram-sha-256', set 'password_encryption = scram-sha-256', restrict listen_addresses, enable TLS (ssl=on), and use encrypted storage for the data directory.

### DB-003 — MySQL/MariaDB local_infile is disabled

- **Severity:** medium
- **Profiles:** server
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** PR.DS-01, PR.AA-05
- **Fix:** manual (report-only)

When MySQL/MariaDB is installed, checks that 'local_infile' is OFF. LOAD DATA LOCAL INFILE lets a client (or an attacker who gains SQL access, e.g. via SQL injection) read arbitrary files from the database server's filesystem. Almost no application needs it. Report-only: AuditXS never edits database configuration — the finding gives the exact setting.

### DB-004 — MySQL/MariaDB has no anonymous or passwordless accounts

- **Severity:** high
- **Profiles:** server
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** PR.AA-01, PR.AA-05
- **Fix:** manual (report-only)

When MySQL/MariaDB is installed, checks for anonymous accounts (empty User) and accounts with an empty authentication string — both allow login without credentials. These are exactly what 'mysql_secure_installation' removes. Report-only: account changes require DBA judgement; the finding lists what to run.

## Logging — OS Hardening domain

### LOG-001 — System journal is persistent across reboots

- **Severity:** medium
- **Profiles:** server,workstation
- **CIS Benchmark:** 6.2.1.1 · **Level:** 1
- **NIST CSF 2.0:** PR.PS-04, DE.CM-01
- **Fix:** automatic (reversible)

Checks that systemd-journald stores logs on disk (/var/log/journal) instead of only in memory. With a volatile journal, every reboot — including one forced by an attacker — erases the evidence.

**What the fix changes:** Creates /var/log/journal and writes /etc/systemd/journald.conf.d/99-auditxs.conf with 'Storage=persistent', then restarts systemd-journald. Existing journald settings in other files are not modified.

**How it is reverted:** 'sudo auditxs rollback' removes the drop-in and restarts journald. The /var/log/journal directory (and logs accumulated in it) is deliberately left in place — deleting logs on rollback would itself be a security problem; remove it manually if desired.

### LOG-002 — The Linux audit daemon (auditd) is installed and running

- **Severity:** high
- **Profiles:** server
- **CIS Benchmark:** 6.3.1 · **Level:** 2
- **NIST CSF 2.0:** PR.PS-04, DE.CM-01
- **Fix:** automatic (reversible)

Checks that auditd — the kernel's audit trail collector — is installed, enabled and active. auditd records security-relevant events (authentication, privilege use, file access rules) in a tamper-resistant log that forensic investigation depends on.

**What the fix changes:** Installs the audit package (auditd/audit depending on distribution) if missing and enables + starts auditd.service. Previous service state and the installed package are recorded.

**How it is reverted:** 'sudo auditxs rollback' restores the previous service state and offers to remove the package if AuditXS installed it.

### LOG-003 — Baseline audit rules are loaded

- **Severity:** medium
- **Profiles:** server
- **CIS Benchmark:** 6.3.3 · **Level:** 2
- **NIST CSF 2.0:** PR.PS-04, DE.CM-01
- **Fix:** automatic (reversible)

Checks that auditd has at least a baseline rule set loaded. An audit daemon with zero rules records almost nothing. The AuditXS baseline watches identity files (/etc/passwd, shadow, group), sudoers, SSH server configuration, and (on x86_64) time changes and kernel module loading.

**What the fix changes:** Writes /etc/audit/rules.d/99-auditxs.rules with the baseline watches described above and loads it with 'augenrules --load'. Existing rules are not modified. Note: if auditd runs in immutable mode (-e 2) a reboot is needed before new rules take effect.

**How it is reverted:** 'sudo auditxs rollback' deletes the rules file and reloads the audit rules.

### LOG-004 — No world-writable log files

- **Severity:** medium
- **Profiles:** server,workstation
- **CIS Benchmark:** 6.2.3 · **Level:** 1
- **NIST CSF 2.0:** PR.PS-04, DE.CM-01
- **Fix:** automatic (reversible)

Checks /var/log for files that any user can modify. World-writable logs let an attacker falsify or destroy the record of their own activity.

**What the fix changes:** Removes the world-write bit (chmod o-w) from each affected file under /var/log, recording every file's previous mode. Nothing is deleted; read permissions are not changed.

**How it is reverted:** 'sudo auditxs rollback' restores each file's exact previous mode.

## SecurityTools — OS Hardening domain

### SEC-001 — A host audit scanner is installed (Lynis)

- **Severity:** medium
- **Profiles:** server,workstation
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** ID.RA-01, DE.CM-08
- **Fix:** automatic (reversible)

Checks for Lynis, the de-facto open-source host security auditor. Lynis performs hundreds of deep checks that complement AuditXS. Having it available means you can cross-verify hardening and produce an independent report ('auditxs tools scan lynis').

**What the fix changes:** Installs 'lynis' from the distribution repositories (recorded for rollback). AuditXS does not run it automatically — use 'auditxs tools scan lynis'.

**How it is reverted:** 'sudo auditxs rollback' offers to remove the package it installed.

### SEC-002 — A rootkit / malware detector is installed

- **Severity:** medium
- **Profiles:** server
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** DE.CM-08, DE.CM-01
- **Fix:** automatic (reversible)

Checks for a rootkit detector (rkhunter or chkrootkit). These scan for known rootkits, suspicious SUID files, and altered system binaries — a basic detective control on any server. Run via 'auditxs tools scan rkhunter'.

**What the fix changes:** Installs 'rkhunter' (recorded for rollback) and performs its initial file-property baseline ('rkhunter --propupd') so future scans can detect changes.

**How it is reverted:** 'sudo auditxs rollback' offers to remove the package it installed.

### SEC-003 — A file integrity monitor is installed (AIDE)

- **Severity:** medium
- **Profiles:** server
- **CIS Benchmark:** — · **Level:** 2
- **NIST CSF 2.0:** PR.DS-06, DE.CM-01
- **Fix:** automatic (reversible)

Checks for AIDE (Advanced Intrusion Detection Environment). AIDE records cryptographic hashes of system files so tampering by an intruder is detected at the next check. It is the standard CIS/STIG file-integrity control. Report/installs only — AuditXS does not initialise the database automatically because that can take time and must happen on a known-good system.

**What the fix changes:** Installs 'aide'. IMPORTANT: after install, initialise the baseline on a trusted system with 'aideinit' (Debian) or 'aide --init', then move the new database into place. AuditXS does not do this for you so the baseline reflects a state you have verified.

**How it is reverted:** 'sudo auditxs rollback' offers to remove the package it installed.

### SEC-004 — An intrusion prevention / IDS engine is present (CrowdSec/Suricata/fail2ban)

- **Severity:** low
- **Profiles:** server
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** DE.CM-01, PR.IR-01
- **Fix:** manual (report-only)

Checks whether at least one active-defence engine is present: CrowdSec (collaborative IPS), Suricata (network IDS/IPS) or fail2ban (log-based banning). At least one is expected on an internet-facing server to detect and block attacks in progress. Use 'auditxs tools install crowdsec|suricata' for a guided setup.

## Vulnerabilities — OS Hardening domain

### VULN-001 — No installed package has a known vulnerability with an available fix

- **Severity:** critical
- **Profiles:** server,workstation
- **CIS Benchmark:** 1.9 · **Level:** 1
- **NIST CSF 2.0:** ID.RA-01, DE.CM-08, PR.PS-02
- **Fix:** manual (report-only)

Cross-references installed package versions against the distribution's own security data (Debian: debsecan or the security apt suite; Ubuntu: security suite; Fedora: dnf updateinfo; openSUSE: zypper patches). A finding means a package you have installed is known-vulnerable and a fixed version is already available in your repositories — the highest-value, lowest-noise vulnerability signal a host can produce offline. Report-only: AuditXS never upgrades packages, because upgrades are not reversible; apply security updates with your package manager.

### VULN-002 — A precise CVE data source is available

- **Severity:** medium
- **Profiles:** server,workstation
- **CIS Benchmark:** — · **Level:** 1
- **NIST CSF 2.0:** ID.RA-01, DE.CM-08
- **Fix:** automatic (reversible)

Checks that the host can produce a precise per-CVE report, not just a security-update count. On Debian this is the 'debsecan' package (queries the Debian Security Tracker); on Ubuntu it is Ubuntu Pro / ubuntu-security-status. Having it installed means VULN-001 can name exact CVEs rather than approximating from the security suite.

**What the fix changes:** Debian: installs 'debsecan'. Other families already ship their advisory tooling (dnf updateinfo, zypper patches) and this check passes there.

**How it is reverted:** 'sudo auditxs rollback' offers to remove the package it installed.

