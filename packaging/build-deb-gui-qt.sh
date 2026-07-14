#!/usr/bin/env bash
#
# AuditXS — packaging/build-deb-gui-qt.sh
# Build the OPTIONAL `auditxs-gui-qt` Debian package: the native Qt/QML
# desktop front-end. It is a small add-on that depends on the base `auditxs`
# package (which already ships gui/auditxs-qt.py and gui/auditxs.qml) plus the
# PySide6 / Qt Quick runtime, and installs a desktop launcher.
#
# Kept separate so the base package stays lightweight and servers never pull in
# the ~hundreds-of-MB Qt runtime.
#
# Usage:  ./packaging/build-deb-gui-qt.sh [output-dir]     (default: dist/)
#
set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
OUT_DIR=${1:-"$REPO/dist"}
VERSION=$(tr -d '[:space:]' < "$REPO/VERSION")
PKG="auditxs-gui-qt"
ARCH=all
MAINT="DigitalXS <luis@digitalxs.ca>"

command -v dpkg-deb >/dev/null 2>&1 || { echo "dpkg-deb is required (install 'dpkg-dev')" >&2; exit 1; }

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$STAGE/usr/bin" "$STAGE/usr/share/applications" \
         "$STAGE/usr/share/doc/$PKG" "$STAGE/DEBIAN"

# Launcher wrapper (the Qt files themselves ship in the base auditxs package).
cat > "$STAGE/usr/bin/auditxs-gui-qt" <<'EOF'
#!/bin/sh
# AuditXS Qt GUI launcher. Elevates via pkexec (auditing needs root), passing
# the display through so the window appears on your session.
exec pkexec env DISPLAY="${DISPLAY}" XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
     WAYLAND_DISPLAY="${WAYLAND_DISPLAY}" auditxs qt "$@"
EOF
chmod 0755 "$STAGE/usr/bin/auditxs-gui-qt"

cp -a "$REPO/gui/auditxs-qt.desktop" "$STAGE/usr/share/applications/auditxs-qt.desktop"

cat > "$STAGE/usr/share/doc/$PKG/copyright" <<EOF
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: AuditXS
Source: https://github.com/digitalxs/AuditXS

Files: *
Copyright: 2026 DigitalXS <luis@digitalxs.ca>
License: GPL-3.0+
 On Debian systems the full text is at /usr/share/common-licenses/GPL-3.
EOF
{
    echo "$PKG ($VERSION) unstable; urgency=medium"
    echo
    echo "  * Native Qt/QML front-end for AuditXS."
    echo
    echo " -- $MAINT  $(date -R)"
} | gzip -9nc > "$STAGE/usr/share/doc/$PKG/changelog.Debian.gz"

cat > "$STAGE/DEBIAN/control" <<EOF
Package: $PKG
Version: $VERSION
Section: admin
Priority: optional
Architecture: $ARCH
Depends: auditxs (>= $VERSION), python3,
 python3-pyside6.qtquick | python3-pyside6,
 qml6-module-qtquick-controls | qml-module-qtquick-controls2,
 qml6-module-qtquick-layouts | qml-module-qtquick-layouts,
 policykit-1
Maintainer: $MAINT
Homepage: https://github.com/digitalxs/AuditXS
Description: native Qt/QML desktop interface for AuditXS
 A Material-styled native desktop front-end (PySide6 + Qt Quick Controls) for
 the AuditXS security auditing tool, with a dashboard, on/off feature toggles,
 snapshots and rollback. Optional: install it only if you want the native
 desktop app. On headless servers use the built-in web UI (auditxs web).
EOF

mkdir -p "$OUT_DIR"
DEB="$OUT_DIR/${PKG}_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$DEB" >/dev/null
echo "Built: $DEB"
dpkg-deb --info "$DEB" | sed -n '1,16p'
