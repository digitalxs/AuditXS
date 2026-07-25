# AuditXS error catalogue

Every recoverable failure in AuditXS reports a stable error number (`AXnnnn`). Look one up on the command line with `auditxs errors <code>`, or search titles with `auditxs errors <term>`. Occurrences are recorded in `/var/lib/auditxs/errors.log` (`auditxs errors --log`).

Generated from the catalogue in `lib/errors.sh` by `auditxs errors --markdown`.

| Code | Meaning | Why it happens | How to resolve |
|------|---------|----------------|----------------|
| `AX1001` | Unsupported or undetected distribution | AuditXS could not map this system to a supported package family (Debian, Arch, RedHat/Fedora, SUSE). | Confirm /etc/os-release exists and names a supported distribution or ID_LIKE; run 'auditxs doctor'. |
| `AX1002` | Missing required core tool | A tool the engine depends on (awk, sed, grep, find, stat…) is not installed. | Install coreutils/gawk/grep/findutils for your distribution; 'auditxs doctor' lists what is missing. |
| `AX1003` | Operation requires root privileges | The requested operation reads or writes privileged state and must run as root. | Re-run with sudo, e.g. 'sudo auditxs audit'. |
| `AX1004` | Invalid or missing profile | PROFILE is not 'server' or 'workstation', so AuditXS cannot decide which checks apply. | Set PROFILE in /etc/auditxs/auditxs.conf (run the installer) or pass --profile server|workstation. |
| `AX1005` | State directory not writable | AuditXS could not create or write under its state directory (snapshots, reports, ledgers). | Ensure /var/lib/auditxs exists and is writable by root, and that the disk is not full. |
| `AX2001` | Check module failed to load | A file under checks/ could not be sourced (syntax error or missing dependency). | Run 'bash -n checks/<file>.sh' to find the error; see digitalxs-dev-doc.MD for the check API. |
| `AX2002` | Check raised an internal error | An audit_<ID> function returned an unexpected status or crashed while inspecting the system. | Re-run with --debug to see the failing check and its output; file an issue with that trace. |
| `AX2003` | Report could not be written | The HTML/JSON/TSV report file could not be created under the reports directory. | Check that /var/lib/auditxs/reports is writable and the disk has free space. |
| `AX2004` | Baseline report unreadable or malformed | The baseline file passed to --baseline / diff is missing or is not a valid AuditXS JSON report. | Point at a report produced by 'auditxs report --format json'; re-approve with 'auditxs baseline set'. |
| `AX2005` | Unknown check ID | A check ID that does not exist was referenced (e.g. for a waiver or --check filter). | List valid IDs with 'auditxs list'; IDs look like SSH-001, FW-002, CON-001. |
| `AX2006` | Invalid date | A date was not in the required YYYY-MM-DD format. | Use an ISO date, e.g. --until 2026-12-31. |
| `AX3001` | Fix failed to apply | A fix_<ID> function could not complete; the change was not applied. | Re-run with --debug; review the specific check with 'auditxs explain <ID>'. Nothing was left half-applied. |
| `AX3002` | sshd configuration validation failed | The proposed SSH change did not pass 'sshd -t', so AuditXS restored the previous configuration. | Inspect /etc/ssh/sshd_config.d/99-auditxs.conf and existing config for conflicts; fix and retry. |
| `AX3003` | Firewall change blocked by lockout guard | Enabling the firewall would have dropped the SSH session because the SSH port was not allowed first. | Allow the SSH port (the guard normally does this automatically) or run from local console, then retry. |
| `AX3004` | Service reload failed after change | A daemon (sshd, nginx, apache…) did not reload/restart cleanly after a configuration change. | Check the service status/journal; the change is recorded in the snapshot and can be rolled back. |
| `AX4001` | Snapshot could not be created | AuditXS could not create the snapshot directory or manifest before making a change, so it refused to proceed. | Ensure /var/lib/auditxs/snapshots is writable and the disk is not full; nothing was changed. |
| `AX4002` | Snapshot manifest write failed | A change could not be recorded in the snapshot manifest, so the change was not carried out (reversibility first). | Check disk space and permissions on /var/lib/auditxs/snapshots. |
| `AX4003` | Rollback target not found | The snapshot id requested for rollback does not exist. | List snapshots with 'auditxs snapshots' and pass a valid id (or 'latest'). |
| `AX4004` | Rollback could not restore an item | One recorded action could not be reverted (a file was removed, permissions changed externally, etc.). | Review the rollback log; restore the item manually from the snapshot directory if needed. |
| `AX5001` | Package installation failed | The distribution package manager could not install a requested package. | Update your package indexes, check network/repository access, and retry 'auditxs tools install <name>'. |
| `AX5002` | Unknown security tool requested | The tool name passed to 'tools install' is not one AuditXS knows how to install. | Run 'auditxs tools install' with no name to see the known list. |
| `AX5003` | External scanner reported errors | An installed scanner (Lynis, rkhunter, ClamAV, OpenSCAP…) exited non-zero; its findings are still saved. | Read the saved report under /var/lib/auditxs/reports/tools/ — a non-zero exit is often findings, not a crash. |
| `AX5004` | SCAP content not found | OpenSCAP was asked to scan but no SCAP Security Guide (SSG) content is installed. | Install the 'scap-security-guide'/'ssg-*' content package, then re-run 'auditxs tools scan openscap'. |
| `AX6001` | Cannot reach host | The remote host did not accept a TCP/SSH connection (down, wrong address/port, or firewalled). | Verify the hostname/IP and port, that sshd is running, and that a firewall is not blocking you. |
| `AX6002` | SSH authentication failed | The remote host rejected the credentials (wrong user, key not authorised, or bad password). | Check the username; authorise your key with 'ssh-copy-id', or re-check the password. Prefer key auth. |
| `AX6003` | Host key verification failed | The remote host key is unknown or has changed, so AuditXS refused to connect (possible MITM). | Verify the host key out-of-band and add it to known_hosts. Only use --insecure-host-key on trusted networks. |
| `AX6004` | Password auth needs sshpass | Password authentication was requested but 'sshpass' (used to feed the password to ssh) is not installed. | Install sshpass, or better, switch to key authentication (--key) which needs no extra tooling. |
| `AX6005` | Remote auditxs not available | 'auditxs' was not found on the remote host, so it cannot run an audit there. | Install AuditXS on the remote host (or use --sudo if it is installed but needs root), then retry. |
| `AX6006` | Remote audit returned no result | The remote command produced no parseable JSON audit result. | Re-run with --debug to see the raw remote output; confirm the remote 'auditxs audit' works when run directly. |
| `AX6007` | Remote command timed out | The remote host did not finish the audit within the timeout. | Raise --timeout, or check load/connectivity on that host. |
| `AX6008` | Inventory unreadable or empty | The --inventory file could not be read or contained no hosts. | Provide a readable file with one host (user@host) per line, or pass hosts with --hosts. |
| `AX6009` | Remote sudo authentication failed | The remote 'sudo' rejected the password, or the login user is not allowed to run auditxs via sudo. | Check the sudo password (--ask-sudo-pass), and that the SSH user may run 'auditxs' with sudo on that host (a sudoers rule). |
| `AX7001` | Unknown output format | An unsupported value was passed to --format. | Use one of: text, json, tsv, html, sarif, csv. |
| `AX8001` | Alert delivery failed | AuditXS could not deliver a drift/CVE alert to the configured sink (webhook or email). | Check the sink URL/address and connectivity; test with 'auditxs alert test'. |
| `AX8002` | No alert sink configured | An alert was requested but no webhook or email destination is configured. | Set ALERT_WEBHOOK and/or ALERT_EMAIL in /etc/auditxs/auditxs.conf (see 'auditxs alert'). |
| `AX9000` | Unspecified error | An error occurred that does not yet have a dedicated code. | Re-run with --debug and include the trace when reporting the issue. |
| `AX9001` | Unknown error code referenced | Code path reported an error number that is not defined in the catalogue (this is a bug). | Please report it at https://github.com/digitalxs/AuditXS/issues. |
