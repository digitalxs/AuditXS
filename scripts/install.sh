#!/usr/bin/env bash
#
# AuditXS one-line installer (bootstrap).
#
# It clones AuditXS to a temporary directory and runs the real installer
# (setup.sh), which detects your distribution, asks Server vs Workstation, and
# links the commands into place. Designed to be fetched and run:
#
#   curl -fsSL https://raw.githubusercontent.com/digitalxs/AuditXS/main/scripts/install.sh | sudo bash
#
#   # non-interactive (pass setup.sh flags after --):
#   curl -fsSL https://raw.githubusercontent.com/digitalxs/AuditXS/main/scripts/install.sh | sudo bash -s -- --workstation -y
#
# PLEASE read this script before running it. Never pipe an unread script into a
# root shell — least of all a security tool. If you prefer, just clone and run
# setup.sh yourself:
#
#   git clone https://github.com/digitalxs/AuditXS.git && cd AuditXS && sudo ./setup.sh
#
set -euo pipefail

REPO_URL="${AUDITXS_REPO:-https://github.com/digitalxs/AuditXS.git}"
REPO_BRANCH="${AUDITXS_BRANCH:-main}"

say() { printf '\033[1m:: %s\033[0m\n' "$*"; }
err() { printf '\033[31mauditxs-install: %s\033[0m\n' "$*" >&2; }

if [ "$(id -u)" -ne 0 ]; then
    err "must run as root — pipe into 'sudo bash', or run 'sudo bash $0'."
    exit 1
fi

if ! command -v git >/dev/null 2>&1; then
    err "git is required to fetch AuditXS. Install git and re-run"
    err "(or download the prebuilt .deb from https://github.com/digitalxs/AuditXS/releases)."
    exit 1
fi

tmp="$(mktemp -d)"
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT

say "Fetching AuditXS (${REPO_BRANCH})…"
git clone --depth 1 --branch "$REPO_BRANCH" "$REPO_URL" "$tmp/AuditXS" >/dev/null 2>&1 \
    || { err "clone failed — check the network and branch name '$REPO_BRANCH'."; exit 1; }

cd "$tmp/AuditXS"
say "Running the installer…"

# Feed setup.sh a real terminal for its Server/Workstation prompt even when this
# bootstrap arrived over a pipe (curl | sudo bash). With no terminal (CI), pass
# explicit flags like '--workstation -y' after '--'.
if [ -e /dev/tty ] && [ -r /dev/tty ]; then
    ./setup.sh "$@" < /dev/tty
else
    ./setup.sh "$@"
fi
