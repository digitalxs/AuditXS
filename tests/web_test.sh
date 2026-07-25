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
    python3 -u gui/auditxs-web.py --no-open --port "$PORT" > "$OUT" 2>&1 &
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
ck "api progress without token → 403"   403 "$(code "$base/api/progress")"
ck "api progress with token → 200"      200 "$(code -H "X-Auth-Token: $TOKEN" "$base/api/progress")"
ck "cli console without token → 403"    403 "$(code -X POST -H 'Content-Type: application/json' -d '{"args":["version"]}' "$base/api/cli")"
ck "cli console runs auditxs cmds"      200 "$(code -X POST -H "X-Auth-Token: $TOKEN" -H 'Content-Type: application/json' -d '{"args":["version"]}' "$base/api/cli")"
ck "cli console rejects non-auditxs"    400 "$(code -X POST -H "X-Auth-Token: $TOKEN" -H 'Content-Type: application/json' -d '{"args":["rm","-rf","/"]}' "$base/api/cli")"
ck "cli console rejects shell chars"    400 "$(code -X POST -H "X-Auth-Token: $TOKEN" -H 'Content-Type: application/json' -d '{"args":["audit",";id"]}' "$base/api/cli")"
ck "tools action needs token"           403 "$(code -X POST -H 'Content-Type: application/json' -d '{"tool":"lynis","action":"install"}' "$base/api/tools/action")"
ck "tools action rejects bad action"    400 "$(code -X POST -H "X-Auth-Token: $TOKEN" -H 'Content-Type: application/json' -d '{"tool":"lynis","action":"pwn"}' "$base/api/tools/action")"
ck "tools action rejects bad tool"      400 "$(code -X POST -H "X-Auth-Token: $TOKEN" -H 'Content-Type: application/json' -d '{"tool":"a;b","action":"install"}' "$base/api/tools/action")"
ck "POST harden without token → 403"    403 "$(code -X POST -H 'Content-Type: application/json' -d '{"checks":["ACC-003"]}' "$base/api/harden")"
# web on/off switch (v0.20)
ck "webservice status needs token"      403 "$(code "$base/api/webservice")"
ck "webservice status with token → 200" 200 "$(code -H "X-Auth-Token: $TOKEN" "$base/api/webservice")"
ck "webservice action needs token"      403 "$(code -X POST -H 'Content-Type: application/json' -d '{"action":"disable"}' "$base/api/webservice")"
ck "webservice rejects bad action"      400 "$(code -X POST -H "X-Auth-Token: $TOKEN" -H 'Content-Type: application/json' -d '{"action":"pwn"}' "$base/api/webservice")"
ck "webservice rejects bad port"        400 "$(code -X POST -H "X-Auth-Token: $TOKEN" -H 'Content-Type: application/json' -d '{"action":"enable","port":"80x"}' "$base/api/webservice")"

# page carries the SPA and the audit endpoint returns valid JSON with a summary
curl -s -H "X-Auth-Token: $TOKEN" "$base/" | grep -q '<title>AuditXS</title>' \
    && ck "page is the SPA" yes yes || ck "page is the SPA" yes no
curl -s -H "X-Auth-Token: $TOKEN" "$base/api/audit" \
    | python3 -c 'import sys,json;d=json.load(sys.stdin);assert "summary" in d' 2>/dev/null \
    && ck "audit returns JSON with summary" yes yes || ck "audit returns JSON with summary" yes no

# The interactive wiring must be present in the served page (regression guard
# for the buttons/toggles verified end-to-end in a browser): Fix it / How to
# fix (onFix), Feature toggles (onToggle), the harden call, the fleet run with
# credential fields, and the console.
PAGEHTML=$(curl -s -H "X-Auth-Token: $TOKEN" "$base/")
for pat in 'onclick="onFix(' 'onchange="onToggle(this)"' '/api/harden' \
           'id="fleetRun"' 'id="fleetPass"' 'id="fleetSudoPass"' \
           'data-tab="web"' 'function renderWeb' 'id="webEnable"' '/api/webservice' \
           'id="conIn"' 'id="conToggle"' '/api/cli'; do
    printf '%s' "$PAGEHTML" | grep -qF "$pat" \
        && ck "page wiring: $pat" yes yes || ck "page wiring: $pat" yes no
done

# never binds beyond loopback by default
if command -v ss >/dev/null 2>&1; then
    ss -tlnH 2>/dev/null | grep -q "127.0.0.1:$PORT" && ck "bound to loopback only (default)" yes yes \
        || ck "bound to loopback only (default)" yes no
fi

# --remote (v0.22): binds all interfaces, populates an empty token file, and the
# token then authenticates. Run a second, short-lived instance for this.
RPORT=8792
RTOK=$(mktemp); : > "$RTOK"    # empty token file — must be populated on start
AUDITXS_BIN="$PWD/auditxs" AUDITXS_PROFILE=server \
    python3 -u gui/auditxs-web.py --no-open --remote --port "$RPORT" --token-file "$RTOK" \
    > "$OUT.remote" 2>&1 &
RPID=$!
for _ in $(seq 1 30); do [ -s "$RTOK" ] && break; sleep 0.3; done
tok=$(cat "$RTOK" 2>/dev/null)
ck "server profile + --remote starts"  yes "$([ -n "$tok" ] && echo yes || echo no)"
ck "empty --token-file is populated"   yes "$([ -n "$tok" ] && echo yes || echo no)"
ck "--remote authed request → 200"     200 "$(code "http://127.0.0.1:$RPORT/?t=$tok")"
if command -v ss >/dev/null 2>&1; then
    ss -tlnH 2>/dev/null | grep -qE "(0\.0\.0\.0|\*):$RPORT" && ck "--remote binds all interfaces" yes yes \
        || ck "--remote binds all interfaces" yes no
fi
kill "$RPID" 2>/dev/null; rm -f "$RTOK" "$OUT.remote"

echo
echo "web tests: $PASS passed, $FAILED failed"
[ "$FAILED" -eq 0 ]
