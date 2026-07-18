#!/usr/bin/env bash
#
# AuditXS — checks/62-boot.sh
# Category: Boot — boot-chain integrity: a GRUB password (stops single-user /
# kernel-parameter tampering from the console), UEFI Secure Boot, and kernel
# lockdown mode. All report-only: changing the bootloader or firmware state
# automatically risks an unbootable system.
#

# ---------------------------------------------------------------- BOOT-001 --
register_check "BOOT-001" "Boot" "medium" "server" \
    "GRUB bootloader is password-protected"
set_meta BOOT-001 desc "Checks whether GRUB requires a password to edit boot entries or use the command line. Without it, anyone with console access can add 'init=/bin/bash' to get a root shell, bypassing every OS control. Set a GRUB superuser + password_pbkdf2. Report-only — a wrong GRUB password change can lock you out of booting."
set_meta BOOT-001 revert "No change is made (report-only)."

audit_BOOT_001() {
    local found=0 f cfg=""
    for f in /boot/grub/grub.cfg /boot/grub2/grub.cfg /etc/grub.d/40_custom /etc/grub.d/00_header; do
        [ -f "$(axpath "$f")" ] && { found=1; cfg+=" $(cat "$(axpath "$f")" 2>/dev/null)"; }
    done
    [ "$found" = 1 ] || { DETAIL="GRUB is not installed (or not the bootloader)"; return 3; }
    if printf '%s' "$cfg" | grep -qiE 'password_pbkdf2|set[[:space:]]+superusers'; then
        DETAIL="GRUB has a superuser/password configured"; return 0
    fi
    DETAIL="No GRUB password — console users can edit boot entries for a root shell. Add a superuser + password_pbkdf2 (grub-mkpasswd-pbkdf2), then update-grub."
    return 1
}

# ---------------------------------------------------------------- BOOT-002 --
register_check "BOOT-002" "Boot" "low" "server,workstation" \
    "UEFI Secure Boot is enabled"
set_meta BOOT-002 desc "Checks whether UEFI Secure Boot is active, so only signed bootloaders/kernels run — blocking bootkits and unsigned kernel modules. Not applicable to legacy BIOS/VMs. Report-only (it is a firmware setting)."
set_meta BOOT-002 revert "No change is made (report-only)."

audit_BOOT_002() {
    [ -d /sys/firmware/efi ] || { DETAIL="System booted in legacy BIOS mode (Secure Boot not applicable)"; return 3; }
    if have mokutil; then
        case "$(mokutil --sb-state 2>/dev/null)" in
            *enabled*) DETAIL="Secure Boot is enabled"; return 0 ;;
            *disabled*) DETAIL="Secure Boot is supported but disabled — enable it in firmware to block unsigned boot code"; return 1 ;;
        esac
    fi
    local ev
    ev=$(ls /sys/firmware/efi/efivars/SecureBoot-* 2>/dev/null | head -1)
    if [ -n "$ev" ] && [ "$(od -An -t u1 "$ev" 2>/dev/null | awk '{print $NF}')" = 1 ]; then
        DETAIL="Secure Boot is enabled"; return 0
    fi
    DETAIL="Secure Boot appears disabled (or state unreadable) — enable it in UEFI firmware if supported"
    return 2
}

# ---------------------------------------------------------------- BOOT-003 --
register_check "BOOT-003" "Boot" "low" "server,workstation" \
    "Kernel lockdown mode is active"
set_meta BOOT-003 desc "Checks the kernel lockdown state. Lockdown ('integrity' or 'confidentiality') stops even root from modifying the running kernel (e.g. loading unsigned modules, /dev/mem), which hardens against kernel-level persistence. Report-only — enabling it can break some legitimate tools."
set_meta BOOT-003 revert "No change is made (report-only)."

audit_BOOT_003() {
    local f=/sys/kernel/security/lockdown
    [ -r "$f" ] || { DETAIL="Kernel lockdown is not available on this kernel"; return 3; }
    local state; state=$(cat "$f" 2>/dev/null)
    case $state in
        *'[none]'*) DETAIL="Kernel lockdown is off ([none]). Enable via 'lockdown=integrity' on the kernel command line or Secure Boot."; return 2 ;;
        *'[integrity]'*|*'[confidentiality]'*) DETAIL="Kernel lockdown is active ($state)"; return 0 ;;
        *) DETAIL="Kernel lockdown state: $state"; return 0 ;;
    esac
}
