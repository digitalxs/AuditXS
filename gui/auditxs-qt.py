#!/usr/bin/env python3
"""
AuditXS Qt/QML native front-end — an optional desktop app built on
PySide6 + QtQuick Controls (Material style). Like the web UI and the zenity
GUI, it is a thin front-end over the `auditxs` CLI: every operation is the
same command you could type, preserving the transparency/reversibility model.

This is shipped by the optional `auditxs-gui-qt` package (which pulls in the
Qt runtime). Launched via:  sudo auditxs qt   (or the desktop launcher).

The data layer (functions below) has no Qt dependency and is exercised by
`python3 gui/auditxs-qt.py --selftest`, so its plumbing is testable without a
display; the QML view requires PySide6 + a desktop to render.
"""
import json
import os
import re
import shutil
import socket
import subprocess
import sys

_ID = re.compile(r"[A-Za-z0-9-]+")

# Subcommands that need root. When the GUI runs unprivileged (e.g. launched
# from the desktop), each of these is elevated per-operation via pkexec — the
# same model as the zenity GUI — so the window itself stays unprivileged and
# displays normally on X11 and Wayland.
_ROOT_CMDS = {"audit", "report", "harden", "rollback", "snapshots",
              "tools", "cve", "baseline", "doctor", "schedule"}


def _elevate(cmd):
    """Prefix a command with pkexec/sudo when elevation is needed and possible.

    `cmd` is [auditxs_bin, subcommand, ...]; elevation keys off the subcommand.
    """
    sub = cmd[1] if len(cmd) > 1 else ""
    if os.geteuid() == 0 or sub not in _ROOT_CMDS:
        return cmd
    if shutil.which("pkexec"):
        return ["pkexec"] + cmd
    # Fall back to sudo only with a terminal, so a windowed GUI never hangs
    # waiting for a password on stdin (matches the zenity GUI's elevate()).
    if shutil.which("sudo") and sys.stdin.isatty():
        return ["sudo"] + cmd
    return cmd


def run_auditxs(args, timeout=240):
    bin_ = os.environ.get("AUDITXS_BIN", "auditxs")
    cmd = _elevate([bin_] + list(args))
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timed out"
    except FileNotFoundError:
        return 127, "", "auditxs not found"


def strip_ansi(s):
    return re.sub(r"\x1b\[[0-9;]*m", "", s or "")


def _profile_args():
    p = os.environ.get("AUDITXS_PROFILE", "")
    return ["--profile", p] if p else []


# ---- data layer (Qt-free, unit-testable) ---------------------------------
def data_meta():
    rc, out, _ = run_auditxs(["version"])
    ver = out.strip().split()[-1].lstrip("v") if out.strip() else "?"
    return {"version": ver, "host": socket.gethostname(),
            "profile": os.environ.get("AUDITXS_PROFILE", "") or "(configured)"}


def data_audit():
    rc, out, err = run_auditxs(["audit", "--format", "json", "--quiet"] + _profile_args())
    try:
        return json.loads(out)
    except ValueError:
        return {"results": [], "summary": {"pass": 0, "fail": 0, "warn": 0, "skip": 0, "score": "-"},
                "error": strip_ansi(err)[:300]}


def data_explain(cid):
    if not (cid and _ID.fullmatch(cid)):
        return "invalid id"
    rc, out, _ = run_auditxs(["explain", cid])
    return strip_ansi(out)


def data_harden(cid):
    if not (cid and _ID.fullmatch(cid)):
        return {"rc": 1, "log": "invalid id"}
    args = ["harden", "--yes", "--quiet"] + _profile_args() + ["--check", cid]
    rc, out, err = run_auditxs(args, 300)
    return {"rc": rc, "log": strip_ansi(out + err)}


def data_snapshots():
    rc, out, _ = run_auditxs(["snapshots", "--format", "tsv"])
    rows = []
    for line in out.splitlines():
        f = line.split("\t")
        if len(f) >= 5:
            rows.append({"id": f[0], "date": f[1], "profile": f[2],
                         "actions": f[3], "status": f[4]})
    return rows


def data_rollback(sid):
    if not (sid and _ID.fullmatch(sid)):
        return {"rc": 1, "log": "invalid id"}
    rc, out, err = run_auditxs(["rollback", sid, "--yes"], 300)
    return {"rc": rc, "log": strip_ansi(out + err)}


# ---- selftest (no Qt) -----------------------------------------------------
def selftest():
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + " " + name)
        ok = ok and cond

    _bin = os.environ.get("AUDITXS_BIN", "auditxs")
    check("strip_ansi removes escapes", strip_ansi("\x1b[31mx\x1b[0m") == "x")
    check("non-privileged subcommand is never elevated",
          _elevate([_bin, "explain", "SSH-001"]) == [_bin, "explain", "SSH-001"])
    check("audit is treated as privileged", "audit" in _ROOT_CMDS)
    check("explain rejects bad id", data_explain("a;b") == "invalid id")
    check("harden rejects bad id", data_harden("a b")["rc"] == 1)
    check("rollback rejects bad id", data_rollback("../x")["rc"] == 1)
    m = data_meta()
    check("meta has version+host", "version" in m and "host" in m)
    a = data_audit()
    check("audit returns summary dict", isinstance(a, dict) and "summary" in a)
    check("snapshots returns a list", isinstance(data_snapshots(), list))
    return 0 if ok else 1


# ---- Qt view --------------------------------------------------------------
def run_gui():
    try:
        from PySide6.QtCore import QObject, Slot, QUrl
        from PySide6.QtGui import QGuiApplication
        from PySide6.QtQml import QQmlApplicationEngine
    except ImportError:
        sys.stderr.write(
            "AuditXS Qt GUI requires PySide6 (the 'auditxs-gui-qt' package installs it).\n"
            "  Debian/Ubuntu: sudo apt install python3-pyside6.qtquick "
            "qml6-module-qtquick-controls qml6-module-qtquick-layouts "
            "qml6-module-qtquick-window\n"
            "  (or just run 'auditxs qt', which offers to install these)\n"
            "  Fedora:        sudo dnf install python3-pyside6\n"
            "  Arch:          sudo pacman -S pyside6\n"
            "Or use the web UI instead:  sudo auditxs web\n")
        return 2

    os.environ.setdefault("QT_QUICK_CONTROLS_STYLE", "Material")
    os.environ.setdefault("QT_QUICK_CONTROLS_MATERIAL_THEME", "System")

    class Backend(QObject):
        @Slot(result=str)
        def meta(self):
            return json.dumps(data_meta())

        @Slot(result=str)
        def audit(self):
            return json.dumps(data_audit())

        @Slot(str, result=str)
        def explain(self, cid):
            return data_explain(cid)

        @Slot(str, result=str)
        def harden(self, cid):
            return json.dumps(data_harden(cid))

        @Slot(result=str)
        def snapshots(self):
            return json.dumps(data_snapshots())

        @Slot(str, result=str)
        def rollback(self, sid):
            return json.dumps(data_rollback(sid))

    app = QGuiApplication(sys.argv)
    app.setApplicationName("AuditXS")
    app.setApplicationDisplayName("AuditXS")
    engine = QQmlApplicationEngine()
    backend = Backend()
    engine.rootContext().setContextProperty("backend", backend)
    qml = os.path.join(os.path.dirname(os.path.abspath(__file__)), "auditxs.qml")
    engine.load(QUrl.fromLocalFile(qml))
    if not engine.rootObjects():
        sys.stderr.write("Failed to load the QML interface.\n")
        return 1
    return app.exec()


def main():
    if "--selftest" in sys.argv[1:]:
        return selftest()
    return run_gui()


if __name__ == "__main__":
    sys.exit(main())
