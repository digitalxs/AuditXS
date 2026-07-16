#!/usr/bin/env bash
#
# AuditXS — scripts/release.sh
# Prepare a release locally: sanity-check the tree, build the .deb, produce a
# SHA256SUMS file and (optionally) a detached GPG signature, then print the
# exact git commands to tag and push — which triggers the automated GitHub
# release (.github/workflows/release.yml).
#
# Usage:
#   ./scripts/release.sh            # build + checksum for the current VERSION
#   ./scripts/release.sh --sign     # also GPG-sign SHA256SUMS (needs a key)
#   ./scripts/release.sh --tag      # additionally create the git tag locally
#
# The repository-root VERSION file is authoritative. Bump it (and add a note to
# docs/ROADMAP.md) before running this.
#
set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO"

VERSION=$(tr -d '[:space:]' < VERSION)
TAG="v$VERSION"
DIST="$REPO/dist"
SIGN=0 DO_TAG=0

for a in "$@"; do
    case $a in
        --sign) SIGN=1 ;;
        --tag)  DO_TAG=1 ;;
        -h|--help) sed -n '3,20p' "$0"; exit 0 ;;
        *) echo "release: unknown option '$a'" >&2; exit 2 ;;
    esac
done

say() { printf '\033[36m::\033[0m %s\n' "$*"; }
die() { printf '\033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }

# ---- sanity checks -------------------------------------------------------
say "Preparing AuditXS release $TAG"

[ "$(./auditxs version)" = "AuditXS v$VERSION" ] \
    || die "VERSION ($VERSION) does not match 'auditxs version' ($(./auditxs version)). Fix the single source of truth (VERSION)."

if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null 2>&1; then
    die "Tag $TAG already exists. Bump VERSION for a new release."
fi

if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
    say "Warning: working tree has uncommitted changes — commit them before tagging."
fi

# ---- quick test gate (best-effort) ---------------------------------------
if command -v shellcheck >/dev/null 2>&1; then
    say "Running shellcheck…"
    shellcheck -S warning auditxs setup.sh uninstall.sh gui/auditxs-gui gui/auditxs-tui.sh \
        scripts/*.sh lib/*.sh checks/*.sh
fi
say "Running unit + check + web tests…"
bash tests/unit.sh   >/dev/null
bash tests/check_test.sh >/dev/null
bash tests/web_test.sh   >/dev/null
say "Tests passed."

# ---- build + checksum ----------------------------------------------------
rm -rf "$DIST"; mkdir -p "$DIST"
say "Building the Debian package…"
./packaging/build-deb.sh "$DIST" >/dev/null

DEB=$(ls "$DIST"/auditxs_*_all.deb)
( cd "$DIST" && sha256sum ./*.deb > SHA256SUMS )
say "Artifacts in $DIST:"
( cd "$DIST" && ls -1 && echo && cat SHA256SUMS )

# ---- optional signing ----------------------------------------------------
if [ "$SIGN" = 1 ]; then
    command -v gpg >/dev/null 2>&1 || die "gpg not found (install gnupg) but --sign was requested."
    say "Signing SHA256SUMS with your default GPG key…"
    ( cd "$DIST" && gpg --batch --yes --armor --detach-sign --output SHA256SUMS.asc SHA256SUMS )
    say "Wrote $DIST/SHA256SUMS.asc"
fi

# ---- optional tag --------------------------------------------------------
if [ "$DO_TAG" = 1 ]; then
    say "Creating annotated tag $TAG…"
    git tag -a "$TAG" -m "AuditXS $TAG"
    say "Tag created. Push it to trigger the release workflow:  git push origin $TAG"
else
    cat <<EOF

Next steps to publish $TAG:
  git add -A && git commit -m "Release $TAG"      # if there are changes
  git tag -a $TAG -m "AuditXS $TAG"
  git push origin $TAG                            # triggers the GitHub release

The 'Release' workflow rebuilds the .deb on a clean runner, verifies the
checksum, signs it if a GPG key secret is configured, and publishes a GitHub
Release with the .deb, SHA256SUMS and the man page attached.
EOF
fi

printf '\033[32m✓\033[0m Verify a download with:  sha256sum -c SHA256SUMS\n'
[ -n "${DEB:-}" ] && printf '  Package: %s\n' "$DEB"
