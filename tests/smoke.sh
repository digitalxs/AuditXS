#!/usr/bin/env bash
#
# AuditXS smoke test — designed to run inside a DISPOSABLE container
# (see .github/workflows/ci.yml). It makes real changes and rolls them back,
# asserting exact restoration. Do NOT run it on a system you care about.
#
# Exercises: version/list/explain, read-only audit (asserting no snapshot is
# created), JSON output, dry-run (asserting nothing changed), a real harden
# of two checks, baseline diff in both directions, and a full rollback.
#
set -euo pipefail

cd "$(dirname "$0")/.."

fail() { echo "SMOKE FAIL: $*" >&2; exit 1; }
no_snapshots() { [ ! -d /var/lib/auditxs/snapshots ] || [ -z "$(ls -A /var/lib/auditxs/snapshots 2>/dev/null)" ]; }
# cmp/diff (diffutils) are missing from the fedora/archlinux container
# images — compare with sha256sum (coreutils) instead.
same_file() { [ "$(sha256sum < "$1")" = "$(sha256sum < "$2")" ]; }

[ "$(id -u)" -eq 0 ] || fail "smoke test must run as root (use a disposable container)"

echo "== environment =="
grep PRETTY_NAME /etc/os-release 2>/dev/null || true

echo "== unit tests =="
bash tests/unit.sh

echo "== version / list / explain / doctor =="
./auditxs version
./auditxs list > /dev/null
./auditxs list --markdown > /dev/null
./auditxs explain SSH-001 ACC-003 NET-002 MAC-001 PRV-001 DB-001 PHP-001 PFX-001 BND-001 VULN-001 > /dev/null
for _lvl in menu simple intermediate advanced pro all; do
    ./auditxs tutorial "$_lvl" > /dev/null || fail "tutorial $_lvl exited non-zero"
done
./auditxs tutorial simple | grep -q "auditxs start" || fail "tutorial simple missing the start command"
./auditxs doctor > /tmp/doctor.log || true   # containers legitimately miss tools
grep -q "AuditXS doctor" /tmp/doctor.log || fail "doctor produced no output"

echo "== new v0.4 surfaces (cve / tools / html report) =="
./auditxs cve > /tmp/cve.log 2>&1 || true    # non-zero if vulns present; either is fine here
grep -qiE "vulnerab|No known-vulnerable|Could not determine" /tmp/cve.log || fail "cve command produced no assessment"
./auditxs tools status > /tmp/tools.log 2>&1 || true
grep -q "Security tooling inventory" /tmp/tools.log || fail "tools status produced no output"
./auditxs tools vpn > /tmp/vpn.log 2>&1 || true
grep -qi "VPN configuration" /tmp/vpn.log || fail "tools vpn produced no output"
./auditxs report --format html --profile server --quiet > /tmp/report.html 2>/dev/null
grep -q 'class="card' /tmp/report.html || fail "HTML report is not the Material card layout"
grep -q '</html>' /tmp/report.html || fail "HTML report is truncated"

echo "== read-only audit =="
./auditxs audit --profile server > /tmp/audit.log
grep -q "Hardening score" /tmp/audit.log || fail "no score in audit output"
no_snapshots || fail "audit created a snapshot (audit must be read-only)"

echo "== JSON report =="
# (grep from a file, not a pipe: grep -q exits early and would SIGPIPE auditxs)
./auditxs audit --profile server --format json --quiet > /tmp/report.json
grep -q '"results"' /tmp/report.json || fail "JSON report broken"

echo "== dry-run changes nothing =="
cp -a /etc/login.defs /tmp/login.defs.before
./auditxs harden --profile server --dry-run --yes > /tmp/dryrun.log
grep -q "dry-run" /tmp/dryrun.log || fail "dry-run produced no dry-run output"
no_snapshots || fail "dry-run created a snapshot"
same_file /etc/login.defs /tmp/login.defs.before || fail "dry-run modified /etc/login.defs"

echo "== harden (ACC-003 + NET-002) =="
./auditxs harden --profile server --yes --check ACC-003 --check NET-002 > /tmp/harden.log
grep -Eq '^PASS_MAX_DAYS[[:space:]]+365' /etc/login.defs || fail "ACC-003 fix not applied"
[ -f /etc/modprobe.d/99-auditxs-netproto.conf ] || fail "NET-002 fix not applied"
[ -f /var/lib/auditxs/changes.log ] || fail "change ledger missing"
./auditxs snapshots > /tmp/snapshots.log
grep -q "actions=" /tmp/snapshots.log || fail "snapshot not listed"

echo "== baseline diff =="
# latest.json was saved by the pre-harden audit; the post-harden audit must
# show improvements and no regressions (exit 0)…
./auditxs audit --profile server --format json --quiet > /tmp/new.json
./auditxs diff /var/lib/auditxs/reports/latest.json /tmp/new.json > /tmp/diff.log \
    || fail "forward diff reported regressions"
grep -q "ACC-003" /tmp/diff.log || fail "diff did not report the ACC-003 improvement"
# …and the reverse comparison must report regressions (exit 1).
if ./auditxs diff /tmp/new.json /var/lib/auditxs/reports/latest.json > /dev/null; then
    fail "reverse diff should exit non-zero (regressions)"
fi
# audit --baseline prints the same comparison inline
./auditxs audit --profile server --baseline /tmp/new.json > /tmp/baseline.log
grep -q "Baseline comparison" /tmp/baseline.log || fail "audit --baseline printed no comparison"

echo "== rollback restores everything =="
./auditxs rollback latest --yes > /tmp/rollback.log
same_file /etc/login.defs /tmp/login.defs.before || fail "rollback did not restore /etc/login.defs exactly"
[ ! -f /etc/modprobe.d/99-auditxs-netproto.conf ] || fail "rollback did not remove the modprobe drop-in"

echo "SMOKE OK"
