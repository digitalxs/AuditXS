#!/usr/bin/env bash
#
# AuditXS web UI test — starts the localhost server and verifies the
# security-critical behaviours (token auth, CSRF guard, localhost binding,
# JSON routing). Read-only: does not apply any fix. Requires python3 + curl.
#
set -u
cd "$(dirname "$0")/.." || exit 1

command -v python3 >/dev/null 2>&1 || { echo "SKIP web_test: python3 not available"; exit 0; }
command -v curl    >/dev/null 2>&1 || { echo "SKIP web_test: curl not available"; exit 0; }

python3 -m py_compile gui/auditxs-web.py || { echo "FAIL: auditxs-web.py does not compile" >&2; exit 1; }

PASS=0; FAILED=0
ck(){ if [ "$2" = "$3" ]; then PASS=$((PASS+1)); else FAILED=$((FAILED+1)); echo "FAIL: $1 (want $2, got $3)" >&2; fi; }

PORT=8791
OUT=$(mktemp)
AUDITXS_BIN="$PWD/auditxs" AUDITXS_PROFILE=server \
    python3 gui/auditxs-web.py --no-open --port "$PORT" > "$OUT" 2>&1 &
WPID=$!
trap 'kill $WPID 2>/dev/null; rm -f "$OUT"' EXIT

# wait for the server to print its URL (token)
TOKEN=""
for _ in $(seq 1 30); do
    TOKEN=$(sed -n 's#.*/?t=\([A-Za-z0-9_-]*\).*#\1#p' "$OUT" | head -1)
    [ -n "$TOKEN" ] && break
    sleep 0.3
done
[ -n "$TOKEN" ] || { echo "FAIL: server did not start" >&2; cat "$OUT" >&2; exit 1; }

base="http://127.0.0.1:$PORT"
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }

ck "root page without token → 403"      403 "$(code "$base/")"
ck "root page with token → 200"         200 "$(code -H "X-Auth-Token: $TOKEN" "$base/")"
ck "api without token → 403"            403 "$(code "$base/api/meta")"
ck "api with bad token → 403"           403 "$(code -H "X-Auth-Token: nope" "$base/api/meta")"
ck "api meta with token → 200"          200 "$(code -H "X-Auth-Token: $TOKEN" "$base/api/meta")"
ck "POST harden without token → 403"    403 "$(code -X POST -H 'Content-Type: application/json' -d '{"checks":["ACC-003"]}' "$base/api/harden")"

# page carries the SPA and the audit endpoint returns valid JSON with a summary
curl -s -H "X-Auth-Token: $TOKEN" "$base/" | grep -q '<title>AuditXS</title>' \
    && ck "page is the SPA" yes yes || ck "page is the SPA" yes no
curl -s -H "X-Auth-Token: $TOKEN" "$base/api/audit" \
    | python3 -c 'import sys,json;d=json.load(sys.stdin);assert "summary" in d' 2>/dev/null \
    && ck "audit returns JSON with summary" yes yes || ck "audit returns JSON with summary" yes no

# never binds beyond loopback
if command -v ss >/dev/null 2>&1; then
    ss -tlnH 2>/dev/null | grep -q "127.0.0.1:$PORT" && ck "bound to loopback only" yes yes \
        || ck "bound to loopback only" yes no
fi

echo
echo "web tests: $PASS passed, $FAILED failed"
[ "$FAILED" -eq 0 ]
