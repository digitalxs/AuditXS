#!/usr/bin/env bash
#
# AuditXS — checks/22-containers.sh
# Category: Containers — Docker / Podman host hardening. The container daemon
# is effectively root-equivalent, so its exposure and defaults matter a lot.
#
# Config checks read /etc/docker/daemon.json through axpath() (fixture-
# testable). Live checks (privileged containers) query the running daemon and
# SKIP when it is not available. All checks are report-only: daemon.json
# changes require a validated daemon restart, which is too disruptive to
# automate.
#

_docker_present() {
    have docker || have dockerd || [ -S /var/run/docker.sock ] \
        || [ -f "$(axpath /etc/docker/daemon.json)" ]
}
# daemon.json contents with whitespace collapsed (empty if absent).
_docker_daemon_json() {
    local f; f=$(axpath /etc/docker/daemon.json)
    [ -f "$f" ] && tr '\n' ' ' < "$f" | tr -s ' '
}

# ---------------------------------------------------------------- CON-001 ---
register_check "CON-001" "Containers" "high" "server,workstation" \
    "Docker daemon is not exposed over unencrypted TCP"
set_meta CON-001 desc "Checks that the Docker daemon is not listening on a TCP socket without TLS. An unauthenticated 'tcp://…:2375' socket grants full root-equivalent control of the host to anyone who can reach it — a frequent cause of server compromise. The default unix socket is fine. Report-only."
set_meta CON-001 revert "No change is made (report-only)."

audit_CON_001() {
    _docker_present || { DETAIL="Docker is not installed"; return 3; }
    local j; j=$(_docker_daemon_json)
    if printf '%s' "$j" | grep -qiE 'tcp://'; then
        if printf '%s' "$j" | grep -qiE '"tlsverify"[[:space:]]*:[[:space:]]*true'; then
            DETAIL="Docker exposes a TCP socket but with TLS client verification (tlsverify) — acceptable"; return 0
        fi
        DETAIL="Docker daemon listens on TCP without 'tlsverify' — this is remote root on the host. Remove the tcp:// host or require mutual TLS."
        return 1
    fi
    DETAIL="Docker is not exposed over TCP (unix socket only)"; return 0
}

# ---------------------------------------------------------------- CON-002 ---
register_check "CON-002" "Containers" "low" "server,workstation" \
    "Docker uses user-namespace remapping"
set_meta CON-002 desc "Checks for 'userns-remap' in daemon.json. Without it, UID 0 inside a container is UID 0 on the host, so a container breakout is immediate root. User-namespace remapping maps container root to an unprivileged host user — strong defence in depth. Report-only (enabling it changes volume ownership semantics, so it is a deliberate choice)."
set_meta CON-002 revert "No change is made (report-only)."

audit_CON_002() {
    _docker_present || { DETAIL="Docker is not installed"; return 3; }
    local j; j=$(_docker_daemon_json)
    if printf '%s' "$j" | grep -qiE '"userns-remap"[[:space:]]*:[[:space:]]*"[^"]'; then
        DETAIL="Docker user-namespace remapping is enabled"; return 0
    fi
    DETAIL="No 'userns-remap' — container root == host root. Consider 'userns-remap': 'default' in /etc/docker/daemon.json"
    return 2
}

# ---------------------------------------------------------------- CON-003 ---
register_check "CON-003" "Containers" "high" "server,workstation" \
    "No container is running with --privileged"
set_meta CON-003 desc "Checks the running containers for '--privileged' (Privileged=true). A privileged container disables almost all isolation and can trivially take over the host. Report-only — stopping a workload is the operator's call."
set_meta CON-003 revert "No change is made (report-only)."

audit_CON_003() {
    _docker_present || { DETAIL="Docker is not installed"; return 3; }
    have docker && docker info >/dev/null 2>&1 || { DETAIL="Docker daemon is not reachable — cannot inspect running containers"; return 3; }
    local ids priv=""
    ids=$(docker ps -q 2>/dev/null)
    [ -n "$ids" ] || { DETAIL="No running containers"; return 0; }
    local c
    for c in $ids; do
        [ "$(docker inspect -f '{{.HostConfig.Privileged}}' "$c" 2>/dev/null)" = true ] \
            && priv+="$(docker inspect -f '{{.Name}}' "$c" 2>/dev/null | sed 's#^/##') "
    done
    if [ -n "$priv" ]; then
        DETAIL="Privileged container(s) running: ${priv% } — these can take over the host; re-run them with specific --cap-add instead"
        return 1
    fi
    DETAIL="No running container is privileged"; return 0
}

# ---------------------------------------------------------------- CON-004 ---
register_check "CON-004" "Containers" "medium" "server,workstation" \
    "Membership of the 'docker' group is limited"
set_meta CON-004 desc "Lists members of the 'docker' group. Being in it is equivalent to root (you can mount the host filesystem into a container), so it should contain only trusted administrators. Report-only — verify each member should have that power."
set_meta CON-004 revert "No change is made (report-only)."

audit_CON_004() {
    _docker_present || { DETAIL="Docker is not installed"; return 3; }
    local grp members
    grp=$(grep -E '^docker:' "$(axpath /etc/group)" 2>/dev/null)
    [ -n "$grp" ] || { DETAIL="No 'docker' group present"; return 0; }
    members=$(printf '%s' "$grp" | awk -F: '{print $4}')
    if [ -n "$members" ]; then
        DETAIL="docker group members (root-equivalent): $members — confirm each should have full host control"
        return 2
    fi
    DETAIL="The docker group has no extra members (only root uses the socket)"; return 0
}

# ---------------------------------------------------------------- CON-005 ---
register_check "CON-005" "Containers" "low" "server" \
    "Docker live-restore is enabled"
set_meta CON-005 desc "Checks for 'live-restore' in daemon.json, which keeps containers running across a daemon restart/upgrade. Without it, a daemon restart (e.g. for a security update) stops every workload — encouraging admins to defer updates. Report-only."
set_meta CON-005 revert "No change is made (report-only)."

audit_CON_005() {
    _docker_present || { DETAIL="Docker is not installed"; return 3; }
    local j; j=$(_docker_daemon_json)
    if printf '%s' "$j" | grep -qiE '"live-restore"[[:space:]]*:[[:space:]]*true'; then
        DETAIL="Docker live-restore is enabled (containers survive a daemon restart)"; return 0
    fi
    DETAIL="live-restore is not enabled — a daemon restart stops all containers. Set 'live-restore': true in /etc/docker/daemon.json"
    return 2
}
