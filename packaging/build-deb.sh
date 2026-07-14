#!/usr/bin/env bash
#
# AuditXS — packaging/build-deb.sh
# Build a Debian package (.deb) for AuditXS using dpkg-deb. Produces an
# architecture-independent package that installs the program under
# /usr/share/auditxs with commands symlinked into /usr/bin, a man page, a
# desktop launcher and documentation.
#
# Usage:  ./packaging/build-deb.sh [output-dir]
# Output: <output-dir>/auditxs_<version>_all.deb   (default output-dir: dist/)
#
set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
OUT_DIR=${1:-"$REPO/dist"}
VERSION=$(tr -d '[:space:]' < "$REPO/VERSION")
PKG="auditxs"
ARCH=all
MAINT="DigitalXS <luis@digitalxs.ca>"

command -v dpkg-deb >/dev/null 2>&1 || { echo "dpkg-deb is required (install 'dpkg-dev')" >&2; exit 1; }

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

SHARE="$STAGE/usr/share/auditxs"
DOC="$STAGE/usr/share/doc/auditxs"
mkdir -p "$SHARE" "$STAGE/usr/bin" "$STAGE/usr/share/man/man8" \
         "$STAGE/usr/share/applications" "$DOC" "$STAGE/DEBIAN" \
         "$STAGE/etc/auditxs"

# ---- program tree (no dev artifacts) -------------------------------------
cp -a "$REPO/auditxs" "$SHARE/"
cp -a "$REPO/lib" "$REPO/checks" "$REPO/gui" "$REPO/scripts" "$SHARE/"
cp -a "$REPO/VERSION" "$SHARE/"
chmod 0755 "$SHARE/auditxs" "$SHARE/gui/auditxs-gui" "$SHARE/scripts/updater.sh"

# ---- commands (symlinks resolve back to the shipped tree) ----------------
ln -s /usr/share/auditxs/auditxs          "$STAGE/usr/bin/auditxs"
ln -s /usr/share/auditxs/gui/auditxs-gui  "$STAGE/usr/bin/auditxs-gui"
ln -s /usr/share/auditxs/scripts/updater.sh "$STAGE/usr/bin/update-auditxs"

# ---- desktop launcher + man page -----------------------------------------
cp -a "$REPO/gui/auditxs.desktop" "$STAGE/usr/share/applications/auditxs.desktop"
gzip -9nc "$REPO/packaging/auditxs.8" > "$STAGE/usr/share/man/man8/auditxs.8.gz"

# ---- documentation --------------------------------------------------------
cp -a "$REPO/README.md" "$REPO/docs/"*.md "$DOC/" 2>/dev/null || true
cat > "$DOC/copyright" <<EOF
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: AuditXS
Source: https://github.com/digitalxs/AuditXS

Files: *
Copyright: 2026 DigitalXS <luis@digitalxs.ca>
License: GPL-3.0+
 This program is free software: you can redistribute it and/or modify it
 under the terms of the GNU General Public License version 3 or later.
 On Debian systems the full text is at /usr/share/common-licenses/GPL-3.
EOF
{
    echo "auditxs ($VERSION) unstable; urgency=medium"
    echo
    echo "  * AuditXS $VERSION."
    echo
    echo " -- $MAINT  $(date -R)"
} | gzip -9nc > "$DOC/changelog.Debian.gz"

# ---- control + maintainer scripts ----------------------------------------
INSTALLED_KB=$(du -sk "$STAGE/usr" | cut -f1)
cat > "$STAGE/DEBIAN/control" <<EOF
Package: $PKG
Version: $VERSION
Section: admin
Priority: optional
Architecture: $ARCH
Depends: bash (>= 4.0), coreutils, sed, gawk | mawk, grep, findutils
Recommends: zenity, policykit-1
Suggests: debsecan, lynis, aide, unattended-upgrades
Installed-Size: $INSTALLED_KB
Maintainer: $MAINT
Homepage: https://github.com/digitalxs/AuditXS
Description: transparent, reversible Linux security auditing and hardening
 AuditXS audits a Linux system against fundamental security baselines
 (CIS Benchmark / DISA STIG aligned, mapped to NIST CSF 2.0) and, only with
 explicit consent, hardens it with fully reversible changes.
 .
 Audits are strictly read-only; every fix documents exactly what it changes
 and is recorded in a snapshot that can be rolled back. Includes CVE
 warnings, security-tool integration, a Material-style HTML report and a
 graphical front-end.
EOF

cat > "$STAGE/DEBIAN/conffiles" <<'EOF'
/etc/auditxs/auditxs.conf
EOF

# Ship a default profile config as a conffile (user-editable, preserved on upgrade).
cat > "$STAGE/etc/auditxs/auditxs.conf" <<'EOF'
# AuditXS configuration.
# PROFILE decides which checks apply: server | workstation
# Change it and re-run 'sudo auditxs audit'. Reconfigure the packaged default
# at any time with: sudo dpkg-reconfigure auditxs  (or edit this file).
PROFILE=workstation
EOF

cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
# State directories (not shipped in the package so they are not owned/removed).
for d in /var/lib/auditxs/snapshots /var/lib/auditxs/reports /var/log/auditxs; do
    mkdir -p "$d"
done
chmod 750 /var/lib/auditxs /var/lib/auditxs/snapshots /var/lib/auditxs/reports /var/log/auditxs 2>/dev/null || true
if command -v mandb >/dev/null 2>&1; then mandb -q 2>/dev/null || true; fi
echo "AuditXS installed. Try: sudo auditxs audit    (GUI: auditxs-gui)"
exit 0
EOF

cat > "$STAGE/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
# On purge, offer to keep snapshots/logs? Leave state in place; 'postrm purge'
# removes configuration only. Snapshots are the rollback safety net.
exit 0
EOF

cat > "$STAGE/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = purge ]; then
    rm -f /etc/auditxs/auditxs.conf
    rmdir /etc/auditxs 2>/dev/null || true
    echo "AuditXS purged. Note: /var/lib/auditxs (snapshots/reports) was kept."
    echo "Remove it manually with: sudo rm -rf /var/lib/auditxs /var/log/auditxs"
fi
exit 0
EOF

chmod 0755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm" "$STAGE/DEBIAN/postrm"

# ---- build ----------------------------------------------------------------
mkdir -p "$OUT_DIR"
DEB="$OUT_DIR/${PKG}_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$DEB" >/dev/null
echo "Built: $DEB"
dpkg-deb --info "$DEB" | sed -n '1,20p'
