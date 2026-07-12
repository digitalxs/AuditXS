# AuditXS check catalogue

Generated from the check registry by `auditxs list --markdown` (v0.1.0).

Legend: checks with an **automatic fix** are only ever applied by
`auditxs harden` after showing you exactly what will change, and every
change is recorded in a snapshot that `auditxs rollback` can restore.
**Manual** checks only report — they never change the system.

## Updates

### UPD-001 — No pending package updates

- **Severity:** medium
- **Profiles:** server,workstation
- **Fix:** manual (report-only)

Counts package updates pending in the package manager's cache. Unpatched software is the most common initial access vector; known vulnerabilities in outdated packages are actively exploited. AuditXS never upgrades packages itself because upgrades are not reversible — this check only reports.

### UPD-002 — Automatic security updates are enabled

- **Severity:** high
- **Profiles:** server,workstation
- **Fix:** automatic (reversible)

Verifies that the distribution's automatic (security) update mechanism is installed and enabled: unattended-upgrades on Debian/Ubuntu/Pop!_OS, dnf-automatic on Fedora. Automatic security updates close the window between a patch being released and it being applied. On Arch and openSUSE there is no official unattended mechanism, so this check only advises.

**What the fix changes:** Debian family: installs the 'unattended-upgrades' package and writes /etc/apt/apt.conf.d/20auto-upgrades enabling daily list updates and unattended security upgrades. Fedora: installs 'dnf-automatic' and enables the dnf-automatic.timer systemd unit. No other update behaviour is changed.

**How it is reverted:** The snapshot records the previous content of 20auto-upgrades (or that it did not exist) and the previous state of dnf-automatic.timer. 'sudo auditxs rollback' restores both; packages installed by AuditXS are offered for removal during rollback.

### UPD-003 — No reboot pending to activate updates

- **Severity:** medium
- **Profiles:** server,workstation
- **Fix:** manual (report-only)

Detects when installed updates (typically a new kernel or core libraries) require a reboot to actually take effect. Until the reboot, the system keeps running the old, vulnerable code. Report-only: AuditXS never reboots a system.

## SSH

### SSH-001 — SSH root login is disabled

- **Severity:** critical
- **Profiles:** server,workstation
- **Fix:** automatic (reversible)

Checks the effective 'PermitRootLogin' value (via sshd -T). Direct root login is the primary target of SSH brute-force campaigns and removes the audit trail of who logged in. Administrators should log in as a normal user and elevate with sudo.

**What the fix changes:** Sets 'PermitRootLogin no' in /etc/ssh/sshd_config.d/99-auditxs.conf, validates the configuration with 'sshd -t' and reloads the SSH service. If you currently log in as root over SSH, make sure a normal user with sudo works FIRST — auditxs asks before applying and this warning is shown here on purpose.

**How it is reverted:** The previous SSH configuration is saved in the snapshot; 'sudo auditxs rollback' restores it, re-validates with 'sshd -t' and reloads sshd.

### SSH-002 — SSH authentication attempts are limited

- **Severity:** medium
- **Profiles:** server,workstation
- **Fix:** automatic (reversible)

Checks that 'MaxAuthTries' is 4 or lower. A low limit slows down password-guessing over a single connection and creates log noise attackers cannot avoid.

**What the fix changes:** Sets 'MaxAuthTries 3' in /etc/ssh/sshd_config.d/99-auditxs.conf, validates with 'sshd -t' and reloads sshd.

**How it is reverted:** 'sudo auditxs rollback' restores the previous SSH configuration files from the snapshot.

### SSH-003 — SSH rejects empty passwords

- **Severity:** critical
- **Profiles:** server,workstation
- **Fix:** automatic (reversible)

Checks that 'PermitEmptyPasswords' is disabled. Allowing empty passwords over SSH lets anyone log into accounts that have no password set.

**What the fix changes:** Sets 'PermitEmptyPasswords no' in /etc/ssh/sshd_config.d/99-auditxs.conf, validates with 'sshd -t' and reloads sshd.

**How it is reverted:** 'sudo auditxs rollback' restores the previous SSH configuration files from the snapshot.

### SSH-004 — SSH X11 forwarding is disabled on servers

- **Severity:** low
- **Profiles:** server
- **Fix:** automatic (reversible)

Checks that 'X11Forwarding' is disabled. Servers rarely need to forward graphical applications; when enabled, a compromised server can attack connecting clients through the X11 channel.

**What the fix changes:** Sets 'X11Forwarding no' in /etc/ssh/sshd_config.d/99-auditxs.conf, validates with 'sshd -t' and reloads sshd.

**How it is reverted:** 'sudo auditxs rollback' restores the previous SSH configuration files from the snapshot.

### SSH-005 — SSH uses key-based authentication (passwords disabled)

- **Severity:** high
- **Profiles:** server
- **Fix:** automatic (reversible)

Checks whether 'PasswordAuthentication' is disabled. Key-based authentication is immune to password guessing and credential stuffing. SAFETY GUARD: AuditXS will only offer this fix when at least one regular user already has ~/.ssh/authorized_keys — otherwise disabling passwords would lock you out, so it only warns.

**What the fix changes:** Sets 'PasswordAuthentication no' in /etc/ssh/sshd_config.d/99-auditxs.conf — but ONLY after re-verifying that at least one regular user has an authorized_keys file; the fix refuses to apply otherwise. Validates with 'sshd -t' and reloads sshd. Test key login in a SECOND terminal before closing your current session.

**How it is reverted:** 'sudo auditxs rollback' restores the previous SSH configuration files from the snapshot and reloads sshd, re-enabling password login.

### SSH-006 — Idle SSH sessions are disconnected

- **Severity:** medium
- **Profiles:** server
- **Fix:** automatic (reversible)

Checks that 'ClientAliveInterval' (1–900 s) and 'ClientAliveCountMax' (3 or less) are configured so that dead or abandoned SSH sessions are closed instead of staying open indefinitely on unattended terminals.

**What the fix changes:** Sets 'ClientAliveInterval 300' and 'ClientAliveCountMax 2' (idle sessions are dropped after ~10 minutes) in /etc/ssh/sshd_config.d/99-auditxs.conf, validates with 'sshd -t' and reloads sshd.

**How it is reverted:** 'sudo auditxs rollback' restores the previous SSH configuration files from the snapshot.

### SSH-007 — SSH login grace time is limited

- **Severity:** low
- **Profiles:** server,workstation
- **Fix:** automatic (reversible)

Checks that 'LoginGraceTime' is 60 seconds or less. The grace period holds a connection slot open for unauthenticated clients; long values make denial-of-service against sshd easier.

**What the fix changes:** Sets 'LoginGraceTime 45' in /etc/ssh/sshd_config.d/99-auditxs.conf, validates with 'sshd -t' and reloads sshd.

**How it is reverted:** 'sudo auditxs rollback' restores the previous SSH configuration files from the snapshot.

## Firewall

### FW-001 — A host firewall is installed

- **Severity:** critical
- **Profiles:** server,workstation
- **Fix:** automatic (reversible)

Checks that a host firewall front-end is available: ufw, firewalld, or an active nftables input ruleset. Without a host firewall every listening service — including ones started accidentally — is reachable from the network.

**What the fix changes:** Installs the distribution's conventional firewall front-end: 'ufw' on Debian/Ubuntu/Pop!_OS/Arch, 'firewalld' on Fedora/openSUSE. Installing the package does NOT enable the firewall yet — that is check FW-002, which asks separately.

**How it is reverted:** The installed package is recorded in the snapshot; 'sudo auditxs rollback' offers to remove it again.

### FW-002 — The host firewall is enabled and active

- **Severity:** critical
- **Profiles:** server,workstation
- **Fix:** automatic (reversible)

Checks that the detected firewall is actually running: 'ufw status' reports active, or the firewalld service is active, or an nftables input ruleset is loaded. An installed-but-disabled firewall provides no protection.

**What the fix changes:** ufw: allows the SSH port(s) first when the system is managed over SSH (lockout guard), then runs 'ufw --force enable'. firewalld: enables and starts the firewalld service and ensures the 'ssh' service is allowed in the active zone when SSH is in use. Nothing else is opened or closed.

**How it is reverted:** The previous firewall state and any SSH allow-rule added by AuditXS are recorded; 'sudo auditxs rollback' disables the firewall again (if it was inactive before) and removes the added rules.

### FW-003 — Firewall default-denies inbound traffic

- **Severity:** high
- **Profiles:** server,workstation
- **Fix:** automatic (reversible)

Checks that unsolicited inbound traffic is denied by default so only explicitly allowed services are reachable. ufw: 'deny (incoming)' default policy; firewalld: the default zone must not have target ACCEPT.

**What the fix changes:** ufw: runs 'ufw default deny incoming' (existing allow rules keep working). firewalld: sets the default zone's target back to 'default' (reject unmatched traffic) and reloads. Outbound traffic is not touched.

**How it is reverted:** The previous default policy / zone target is recorded; 'sudo auditxs rollback' restores it.

## Accounts

### ACC-001 — Only root has UID 0

- **Severity:** critical
- **Profiles:** server,workstation
- **Fix:** manual (report-only)

Scans /etc/passwd for accounts other than 'root' with UID 0. A second UID-0 account is a classic backdoor: it has full root power under an innocent name. Report-only: removing accounts is a decision AuditXS will not automate.

### ACC-002 — No accounts have empty passwords

- **Severity:** critical
- **Profiles:** server,workstation
- **Fix:** automatic (reversible)

Scans /etc/shadow for accounts whose password field is empty. Such accounts can be logged into without any password at all (locally, and over any service that permits it).

**What the fix changes:** Locks each affected account with 'passwd -l <user>' (places a '!' in the password field, blocking password login while leaving the account and its files intact). /etc/shadow is backed up to the snapshot first.

**How it is reverted:** 'sudo auditxs rollback' restores the saved /etc/shadow, returning the accounts to their previous state.

### ACC-003 — Password aging policy is configured

- **Severity:** medium
- **Profiles:** server,workstation
- **Fix:** automatic (reversible)

Checks /etc/login.defs for a sane password aging baseline: PASS_MAX_DAYS ≤ 365, PASS_MIN_DAYS ≥ 1 and PASS_WARN_AGE ≥ 7. This bounds how long a leaked password stays valid and prevents instant password re-use. Applies to newly created accounts; existing accounts keep their current aging until changed with 'chage'.

**What the fix changes:** Edits /etc/login.defs (backed up first) setting PASS_MAX_DAYS 365, PASS_MIN_DAYS 1, PASS_WARN_AGE 7. Existing accounts are NOT modified — the report lists the 'chage' command to update them if you wish.

**How it is reverted:** 'sudo auditxs rollback' restores the saved /etc/login.defs.

### ACC-004 — sudo always requires a password

- **Severity:** high
- **Profiles:** server,workstation
- **Fix:** manual (report-only)

Scans /etc/sudoers and /etc/sudoers.d/ for NOPASSWD entries. Passwordless sudo turns any compromise of that user account (or an unlocked terminal) into an instant full-root compromise. Report-only: sudoers changes are risky to automate, so AuditXS shows you exactly which lines to review with 'visudo'.

### ACC-005 — System accounts cannot log in

- **Severity:** medium
- **Profiles:** server,workstation
- **Fix:** automatic (reversible)

Checks that system (service) accounts — UID below the regular-user threshold — have a non-login shell such as /usr/sbin/nologin. Service accounts with real shells are convenient footholds after a service compromise.

**What the fix changes:** Backs up /etc/passwd, then sets the shell of each affected system account to 'nologin' with 'usermod -s'. Regular user accounts and root are never touched.

**How it is reverted:** 'sudo auditxs rollback' restores the saved /etc/passwd, returning the original shells.

### ACC-006 — Default umask is restrictive (027)

- **Severity:** low
- **Profiles:** server
- **Fix:** automatic (reversible)

Checks that the default UMASK in /etc/login.defs is 027 or stricter, so files created by users are not readable by every other account on the system. Applied to the server profile only — on single-user workstations the default 022 is a common and acceptable trade-off.

**What the fix changes:** Edits /etc/login.defs (backed up first) setting 'UMASK 027'. Only affects newly created login sessions; existing files are not changed.

**How it is reverted:** 'sudo auditxs rollback' restores the saved /etc/login.defs.

## Filesystem

### FS-001 — World-writable directories have the sticky bit

- **Severity:** medium
- **Profiles:** server,workstation
- **Fix:** automatic (reversible)

Finds directories that any user may write to (like /tmp) but that lack the sticky bit. Without it, any user can delete or rename other users' files in that directory — a classic path for tmp-race attacks.

**What the fix changes:** Adds the sticky bit (chmod +t) to each affected directory. The previous mode of every directory is recorded in the snapshot. No files are touched, only directory modes.

**How it is reverted:** 'sudo auditxs rollback' restores each directory's exact previous mode.

### FS-002 — No world-writable files

- **Severity:** medium
- **Profiles:** server,workstation
- **Fix:** automatic (reversible)

Finds regular files that ANY user on the system may modify. World-writable files let an unprivileged user tamper with data or scripts that other users — or root — later read or execute.

**What the fix changes:** Removes the world-write bit (chmod o-w) from each affected file. Every file's previous mode is recorded in the snapshot. Nothing is deleted and no other permission bits change.

**How it is reverted:** 'sudo auditxs rollback' restores each file's exact previous mode.

### FS-003 — No unowned or ungrouped files

- **Severity:** low
- **Profiles:** server,workstation
- **Fix:** manual (report-only)

Finds files whose owner or group no longer exists (usually left behind by removed packages or deleted users). A future account created with the same UID/GID silently inherits access to them. Report-only: correct ownership depends on what the files are, so AuditXS lists them with 'chown' guidance.

### FS-004 — Sensitive system files have strict permissions

- **Severity:** high
- **Profiles:** server,workstation
- **Fix:** automatic (reversible)

Verifies that credential and boot files are not readable/writable more broadly than needed: /etc/shadow and /etc/gshadow (and their '-' backups) at most 640, /etc/passwd and /etc/group at most 644, /etc/crontab and GRUB configuration at most 600, SSH host private keys at most 600. AuditXS only ever TIGHTENS modes — files already stricter than the baseline (e.g. Fedora's shadow at 000) are left untouched.

**What the fix changes:** For each file more permissive than its baseline, chmods it down to the baseline mode. Previous modes are recorded per file in the snapshot.

**How it is reverted:** 'sudo auditxs rollback' restores each file's exact previous mode.

### FS-005 — Home directories are not accessible to other users

- **Severity:** medium
- **Profiles:** server,workstation
- **Fix:** automatic (reversible)

Checks that each regular user's home directory is mode 750 or stricter, so other local users cannot read personal files, SSH keys, browser profiles or shell history.

**What the fix changes:** Chmods each over-permissive home directory to 750. Previous modes are recorded per directory. Only the home directory itself is changed — never its contents.

**How it is reverted:** 'sudo auditxs rollback' restores each home directory's exact previous mode.

### FS-006 — SUID/SGID binary inventory

- **Severity:** low
- **Profiles:** server,workstation
- **Fix:** manual (report-only)

Inventories setuid/setgid binaries — programs that run with elevated privileges no matter who starts them — and flags any outside the well-known baseline (sudo, passwd, mount, ...). Unexpected SUID binaries are a common persistence technique. Report-only: removing the bit can break legitimate software, so review each finding.

## Kernel

### KRN-001 — Address space layout randomization (ASLR) is fully enabled

- **Severity:** high
- **Profiles:** server,workstation
- **Fix:** automatic (reversible)

Checks kernel.randomize_va_space=2. ASLR randomizes process memory layout, making memory-corruption exploits substantially harder. 2 (full, including heap) is the kernel default; anything lower means it was weakened.

**What the fix changes:** Writes /etc/sysctl.d/99-auditxs-krn-001.conf with 'kernel.randomize_va_space = 2' and applies it at runtime. Previous value is recorded.

**How it is reverted:** 'sudo auditxs rollback' deletes the drop-in and restores the previous runtime value.

### KRN-002 — Kernel address and log exposure is restricted

- **Severity:** medium
- **Profiles:** server,workstation
- **Fix:** automatic (reversible)

Checks kernel.kptr_restrict ≥ 1 (hide kernel pointers from unprivileged users) and kernel.dmesg_restrict = 1 (require privilege to read the kernel log). Kernel addresses and dmesg output are building blocks for kernel exploits and information leaks.

**What the fix changes:** Writes /etc/sysctl.d/99-auditxs-krn-002.conf setting only the values that are currently weaker than recommended (kptr_restrict=1, dmesg_restrict=1) and applies them at runtime. Values already stricter are left untouched.

**How it is reverted:** 'sudo auditxs rollback' deletes the drop-in and restores the previous runtime values.

### KRN-003 — TCP SYN cookies are enabled

- **Severity:** high
- **Profiles:** server,workstation
- **Fix:** automatic (reversible)

Checks net.ipv4.tcp_syncookies=1. SYN cookies keep the system reachable during SYN-flood denial-of-service attacks instead of exhausting the connection backlog.

**What the fix changes:** Writes /etc/sysctl.d/99-auditxs-krn-003.conf with 'net.ipv4.tcp_syncookies = 1' and applies it at runtime.

**How it is reverted:** 'sudo auditxs rollback' deletes the drop-in and restores the previous runtime value.

### KRN-004 — ICMP redirects are ignored and not sent

- **Severity:** medium
- **Profiles:** server,workstation
- **Fix:** automatic (reversible)

Checks that the system neither accepts nor sends ICMP redirect messages (IPv4 and IPv6). Accepted redirects let an on-path attacker rewrite the routing table and intercept traffic; hosts that are not routers have no reason to send them.

**What the fix changes:** Writes /etc/sysctl.d/99-auditxs-krn-004.conf disabling accept_redirects (v4+v6, all/default), secure_redirects and send_redirects, and applies the values at runtime.

**How it is reverted:** 'sudo auditxs rollback' deletes the drop-in and restores the previous runtime values.

### KRN-005 — Source-routed packets are rejected

- **Severity:** medium
- **Profiles:** server,workstation
- **Fix:** automatic (reversible)

Checks that accept_source_route is 0 for IPv4 and IPv6. Source routing lets the sender dictate a packet's path — a technique for bypassing firewall policy and spoofing; end hosts should never accept it.

**What the fix changes:** Writes /etc/sysctl.d/99-auditxs-krn-005.conf disabling accept_source_route (v4+v6, all/default) and applies the values at runtime.

**How it is reverted:** 'sudo auditxs rollback' deletes the drop-in and restores the previous runtime values.

### KRN-006 — Reverse-path filtering is enabled

- **Severity:** medium
- **Profiles:** server,workstation
- **Fix:** automatic (reversible)

Checks net.ipv4.conf.{all,default}.rp_filter is 1 (strict) or 2 (loose). Reverse-path filtering drops packets whose source address could not be routed back the way they came, blunting IP spoofing.

**What the fix changes:** Writes /etc/sysctl.d/99-auditxs-krn-006.conf with rp_filter=1 for all/default and applies it at runtime. If your host does asymmetric routing (rare, multi-homed setups), skip this fix.

**How it is reverted:** 'sudo auditxs rollback' deletes the drop-in and restores the previous runtime values.

### KRN-007 — Suspicious (martian) packets are logged

- **Severity:** low
- **Profiles:** server
- **Fix:** automatic (reversible)

Checks net.ipv4.conf.{all,default}.log_martians=1 so packets with impossible source addresses are logged. On servers this gives early warning of spoofing or misrouted traffic; on busy networks it adds log volume, which is why it is server-profile only.

**What the fix changes:** Writes /etc/sysctl.d/99-auditxs-krn-007.conf with log_martians=1 for all/default and applies it at runtime.

**How it is reverted:** 'sudo auditxs rollback' deletes the drop-in and restores the previous runtime values.

### KRN-008 — IP forwarding is disabled (unless this host routes traffic)

- **Severity:** high
- **Profiles:** server,workstation
- **Fix:** automatic (reversible)

Checks that IPv4/IPv6 forwarding is off. A host that silently forwards packets can be abused to pivot between networks. DETECTION: if Docker, Podman or libvirt is present, forwarding is required and this check passes with a note instead.

**What the fix changes:** Writes /etc/sysctl.d/99-auditxs-krn-008.conf disabling net.ipv4.ip_forward and net.ipv6.conf.all.forwarding and applies it at runtime. The fix is only offered when no container/VM runtime was detected — do not apply it on routers or VPN gateways.

**How it is reverted:** 'sudo auditxs rollback' deletes the drop-in and restores the previous runtime values.

### KRN-009 — Core dumps of privileged programs are disabled

- **Severity:** medium
- **Profiles:** server,workstation
- **Fix:** automatic (reversible)

Checks fs.suid_dumpable=0. Core dumps of setuid programs can spill password hashes and other secrets those programs held in memory into files an attacker may read.

**What the fix changes:** Writes /etc/sysctl.d/99-auditxs-krn-009.conf with 'fs.suid_dumpable = 0' and applies it at runtime.

**How it is reverted:** 'sudo auditxs rollback' deletes the drop-in and restores the previous runtime value.

### KRN-010 — Ctrl-Alt-Del does not reboot the system

- **Severity:** low
- **Profiles:** server
- **Fix:** automatic (reversible)

Checks that the ctrl-alt-del systemd target is masked. On servers, anyone with (physical or remote-console) keyboard access could otherwise trigger an unclean reboot without authentication.

**What the fix changes:** Masks the target by linking /etc/systemd/system/ctrl-alt-del.target to /dev/null and runs 'systemctl daemon-reload'. No other keyboard behaviour changes.

**How it is reverted:** 'sudo auditxs rollback' removes the mask link (restoring the saved file if one existed) and reloads systemd.

## Services

### SVC-001 — Legacy plaintext network services are not running

- **Severity:** high
- **Profiles:** server,workstation
- **Fix:** automatic (reversible)

Checks for enabled/active legacy services that transmit credentials in cleartext or are historically unsafe: telnet, rsh/rlogin/rexec, tftp, xinetd/inetd, NIS (ypserv). These have modern encrypted replacements (SSH, SFTP) and should not run anywhere.

**What the fix changes:** Disables and stops each detected unit with 'systemctl disable --now', recording its previous enabled/active state. Packages are left installed (remove them manually if unneeded).

**How it is reverted:** 'sudo auditxs rollback' re-enables and restarts each service exactly as it was before.

### SVC-002 — Avahi (mDNS) daemon is disabled on servers

- **Severity:** medium
- **Profiles:** server
- **Fix:** automatic (reversible)

Checks that avahi-daemon is not running. Avahi advertises the machine and its services on the local network (mDNS/zeroconf) — useful on desktops, but on servers it is unneeded broadcast surface and information disclosure.

**What the fix changes:** Disables and stops avahi-daemon.service and avahi-daemon.socket, recording their previous state. The package stays installed.

**How it is reverted:** 'sudo auditxs rollback' re-enables and restarts the units exactly as they were.

### SVC-003 — Printing services (CUPS) are disabled on servers

- **Severity:** medium
- **Profiles:** server
- **Fix:** automatic (reversible)

Checks that CUPS is not running. Print services listen on the network and have a long CVE history; servers that never print should not run them.

**What the fix changes:** Disables and stops cups.service, cups.socket and cups-browsed.service (where present), recording their previous state. The packages stay installed.

**How it is reverted:** 'sudo auditxs rollback' re-enables and restarts the units exactly as they were.

### SVC-004 — Bluetooth is disabled on servers

- **Severity:** medium
- **Profiles:** server
- **Fix:** automatic (reversible)

Checks that the bluetooth service is not running. Servers rarely use Bluetooth; the stack adds kernel attack surface reachable from physical proximity.

**What the fix changes:** Disables and stops bluetooth.service, recording its previous state. The package stays installed.

**How it is reverted:** 'sudo auditxs rollback' re-enables and restarts the unit exactly as it was.

### SVC-005 — systemd service sandboxing overview

- **Severity:** low
- **Profiles:** server,workstation
- **Fix:** manual (report-only)

Summarizes 'systemd-analyze security', which scores every running service by how much sandboxing (namespaces, capability limits, syscall filters) it uses. Informational: use it to pick services worth confining with systemd hardening directives.

## Network

### NET-001 — Listening network services inventory

- **Severity:** low
- **Profiles:** server,workstation
- **Fix:** manual (report-only)

Lists every TCP/UDP port the system is listening on. Informational — the point is that YOU can verify each entry is expected. Anything you do not recognize deserves investigation ('ss -tulpn' shows the owning process).

### NET-002 — Uncommon network protocols are disabled

- **Severity:** medium
- **Profiles:** server,workstation
- **Fix:** automatic (reversible)

Checks that rarely-used kernel network protocols (DCCP, SCTP, RDS, TIPC) cannot be auto-loaded. These modules have repeatedly been the vehicle for kernel privilege-escalation bugs, and almost no system needs them. If you knowingly use one (e.g. SCTP for telecom software), skip this fix.

**What the fix changes:** Writes /etc/modprobe.d/99-auditxs-netproto.conf with 'install <module> /bin/false' for dccp, sctp, rds and tipc, preventing them from being loaded in the future. Modules already loaded are reported but NOT unloaded (no disruption).

**How it is reverted:** 'sudo auditxs rollback' deletes the modprobe drop-in (or restores its previous content).

### NET-003 — No wireless interfaces on servers

- **Severity:** low
- **Profiles:** server
- **Fix:** manual (report-only)

Detects Wi-Fi interfaces on machines using the server profile. Wireless links on servers bypass wired network controls and extend the attack surface into radio range. Report-only: disabling networking automatically could sever your own connection, so AuditXS shows the 'rfkill block wifi' command instead.

## Logging

### LOG-001 — System journal is persistent across reboots

- **Severity:** medium
- **Profiles:** server,workstation
- **Fix:** automatic (reversible)

Checks that systemd-journald stores logs on disk (/var/log/journal) instead of only in memory. With a volatile journal, every reboot — including one forced by an attacker — erases the evidence.

**What the fix changes:** Creates /var/log/journal and writes /etc/systemd/journald.conf.d/99-auditxs.conf with 'Storage=persistent', then restarts systemd-journald. Existing journald settings in other files are not modified.

**How it is reverted:** 'sudo auditxs rollback' removes the drop-in and restarts journald. The /var/log/journal directory (and logs accumulated in it) is deliberately left in place — deleting logs on rollback would itself be a security problem; remove it manually if desired.

### LOG-002 — The Linux audit daemon (auditd) is installed and running

- **Severity:** high
- **Profiles:** server
- **Fix:** automatic (reversible)

Checks that auditd — the kernel's audit trail collector — is installed, enabled and active. auditd records security-relevant events (authentication, privilege use, file access rules) in a tamper-resistant log that forensic investigation depends on.

**What the fix changes:** Installs the audit package (auditd/audit depending on distribution) if missing and enables + starts auditd.service. Previous service state and the installed package are recorded.

**How it is reverted:** 'sudo auditxs rollback' restores the previous service state and offers to remove the package if AuditXS installed it.

### LOG-003 — Baseline audit rules are loaded

- **Severity:** medium
- **Profiles:** server
- **Fix:** automatic (reversible)

Checks that auditd has at least a baseline rule set loaded. An audit daemon with zero rules records almost nothing. The AuditXS baseline watches identity files (/etc/passwd, shadow, group), sudoers, SSH server configuration, and (on x86_64) time changes and kernel module loading.

**What the fix changes:** Writes /etc/audit/rules.d/99-auditxs.rules with the baseline watches described above and loads it with 'augenrules --load'. Existing rules are not modified. Note: if auditd runs in immutable mode (-e 2) a reboot is needed before new rules take effect.

**How it is reverted:** 'sudo auditxs rollback' deletes the rules file and reloads the audit rules.

### LOG-004 — No world-writable log files

- **Severity:** medium
- **Profiles:** server,workstation
- **Fix:** automatic (reversible)

Checks /var/log for files that any user can modify. World-writable logs let an attacker falsify or destroy the record of their own activity.

**What the fix changes:** Removes the world-write bit (chmod o-w) from each affected file under /var/log, recording every file's previous mode. Nothing is deleted; read permissions are not changed.

**How it is reverted:** 'sudo auditxs rollback' restores each file's exact previous mode.

