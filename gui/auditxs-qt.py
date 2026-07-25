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
import tempfile
import threading
import time

_ID = re.compile(r"[A-Za-z0-9-]+")

# Progress file: the audit runs with --progress-file so the elevated process
# (whose environment pkexec sanitizes) reports "PCT DONE TOTAL ID" here; the
# QML view polls it to drive a real percentage bar.
_PROGRESS_DIR = tempfile.mkdtemp(prefix="auditxs-qt-")
PROGRESS_FILE = os.path.join(_PROGRESS_DIR, "progress")


def read_progress():
    """Parse the progress file into a dict (pct/done/total/id)."""
    try:
        with open(PROGRESS_FILE) as f:
            parts = f.readline().split()
        return {"pct": int(parts[0]), "done": int(parts[1]),
                "total": int(parts[2]), "id": parts[3] if len(parts) > 3 else ""}
    except (OSError, ValueError, IndexError):
        return {"pct": 0, "done": 0, "total": 0, "id": ""}


# Any CLI operation the GUI may run (argv only, never a shell). First token
# must be one of these auditxs subcommands; every argument must match _OPARG.
_OP_CMDS = {"audit", "report", "harden", "rollback", "snapshots", "tools",
            "cve", "update", "baseline", "doctor", "schedule", "errors", "waive",
            "unwaive", "waivers", "alert", "fleet", "list", "explain",
            "diff", "version", "profile"}
_OPARG = re.compile(r"[A-Za-z0-9@.,:%/_=+~ -]+")


def op_allowed(args):
    return (args and args[0] in _OP_CMDS
            and all(a and _OPARG.fullmatch(a) for a in args))


# ---- fleet configuration (user-level; fleet mode is read-only over SSH and
# runs unprivileged with the user's own keys/agent) ------------------------
_CFG_DIR = os.path.join(os.environ.get("XDG_CONFIG_HOME",
                        os.path.expanduser("~/.config")), "auditxs")
FLEET_HOSTS = os.path.join(_CFG_DIR, "fleet-hosts")
FLEET_OUT_ROOT = os.path.join(os.environ.get("XDG_DATA_HOME",
                              os.path.expanduser("~/.local/share")),
                              "auditxs", "fleet")


def fleet_config():
    hosts, key, sudo = [], "", True
    try:
        with open(FLEET_HOSTS) as f:
            for ln in f:
                ln = ln.strip()
                if ln.startswith("#key="):
                    key = ln[5:]
                elif ln.startswith("#sudo="):
                    sudo = ln[6:] == "1"
                elif ln and not ln.startswith("#"):
                    hosts.append(ln)
    except OSError:
        pass
    return {"hosts": hosts, "key": key, "sudo": sudo}


def fleet_save(cfg):
    os.makedirs(_CFG_DIR, mode=0o700, exist_ok=True)
    with open(FLEET_HOSTS, "w") as f:
        f.write("# AuditXS fleet inventory (managed by the GUI)\n")
        if cfg.get("key"):
            f.write("#key=%s\n" % cfg["key"])
        f.write("#sudo=%s\n" % ("1" if cfg.get("sudo", True) else "0"))
        for h in cfg.get("hosts", []):
            h = h.strip()
            if h and _OPARG.fullmatch(h):
                f.write(h + "\n")
    os.chmod(FLEET_HOSTS, 0o600)
    return fleet_config()

# Subcommands that need root. When the GUI runs unprivileged (e.g. launched
# from the desktop), each of these is elevated per-operation via pkexec — the
# same model as the zenity GUI — so the window itself stays unprivileged and
# displays normally on X11 and Wayland.
_ROOT_CMDS = {"audit", "report", "harden", "rollback", "snapshots",
              "tools", "cve", "update", "baseline", "doctor", "schedule"}


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


def run_auditxs(args, timeout=240, env_extra=None):
    bin_ = os.environ.get("AUDITXS_BIN", "auditxs")
    cmd = _elevate([bin_] + list(args))
    env = None
    if env_extra:
        # Credentials (e.g. fleet passwords) travel in the child environment,
        # never on the command line. pkexec would strip them, but fleet is not
        # an elevated subcommand, so the environment is preserved.
        env = dict(os.environ)
        env.update(env_extra)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env=env)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timed out"
    except FileNotFoundError:
        return 127, "", "auditxs not found"


def run_auditxs_root(args, timeout=120):
    """Run a subcommand that always needs root (e.g. webservice enable/disable).

    Unlike run_auditxs, elevation does not depend on the subcommand being in
    _ROOT_CMDS — the caller has decided it needs root.
    """
    bin_ = os.environ.get("AUDITXS_BIN", "auditxs")
    cmd = [bin_] + list(args)
    if os.geteuid() != 0:
        if shutil.which("pkexec"):
            cmd = ["pkexec"] + cmd
        elif shutil.which("sudo") and sys.stdin.isatty():
            cmd = ["sudo"] + cmd
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
    try:
        open(PROGRESS_FILE, "w").close()
    except OSError:
        pass
    rc, out, err = run_auditxs(["audit", "--format", "json", "--quiet",
                                "--progress-file", PROGRESS_FILE] + _profile_args())
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
    check("run_auditxs_root is callable", callable(run_auditxs_root))
    check("terminal is a non-privileged op", "terminal" not in _ROOT_CMDS)
    check("explain rejects bad id", data_explain("a;b") == "invalid id")
    check("harden rejects bad id", data_harden("a b")["rc"] == 1)
    check("rollback rejects bad id", data_rollback("../x")["rc"] == 1)
    m = data_meta()
    check("meta has version+host", "version" in m and "host" in m)
    a = data_audit()
    check("audit returns summary dict", isinstance(a, dict) and "summary" in a)
    check("snapshots returns a list", isinstance(data_snapshots(), list))
    # Action plumbing (v0.14/0.15): the op whitelist and fleet round-trip.
    check("op_allowed permits a real op", op_allowed(["cve"]))
    check("op_allowed permits fleet+args", op_allowed(["fleet", "--inventory", "/tmp/h"]))
    check("op_allowed rejects non-auditxs", not op_allowed(["rm", "-rf", "/"]))
    check("op_allowed rejects shell metachars", not op_allowed(["audit", ";id"]))
    check("op_allowed rejects newline injection", not op_allowed(["audit\nrm"]))
    # Redirect the fleet config to a throwaway dir so the test never touches
    # the user's real inventory.
    global _CFG_DIR, FLEET_HOSTS
    _CFG_DIR = tempfile.mkdtemp(prefix="auditxs-selftest-")
    FLEET_HOSTS = os.path.join(_CFG_DIR, "fleet-hosts")
    cfg = fleet_save({"hosts": ["admin@web01", "bad host!"], "key": "/k", "sudo": False})
    check("fleet_save keeps valid host", "admin@web01" in cfg["hosts"])
    check("fleet_save drops invalid host", "bad host!" not in cfg["hosts"])
    check("fleet_save round-trips key+sudo", cfg["key"] == "/k" and cfg["sudo"] is False)
    check("read_progress tolerates missing file", isinstance(read_progress(), dict))
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
        def __init__(self):
            super().__init__()
            self._audit_thread = None
            self._audit_result = None

        @Slot(result=str)
        def meta(self):
            return json.dumps(data_meta())

        @Slot(result=str)
        def audit(self):
            return json.dumps(data_audit())

        # Async audit: auditStart() launches the audit in a worker thread so
        # the window stays live; the QML polls auditProgress() for the
        # percentage bar and collects auditResult() when running goes false.
        @Slot()
        def auditStart(self):
            if self._audit_thread and self._audit_thread.is_alive():
                return
            self._audit_result = None

            def _worker():
                self._audit_result = json.dumps(data_audit())

            self._audit_thread = threading.Thread(target=_worker, daemon=True)
            self._audit_thread.start()

        @Slot(result=str)
        def auditProgress(self):
            running = bool(self._audit_thread and self._audit_thread.is_alive())
            p = read_progress()
            p["running"] = running
            return json.dumps(p)

        @Slot(result=str)
        def auditResult(self):
            return self._audit_result or ""

        # Generic async CLI operation (whitelisted subcommands, argv only).
        # opStart → poll opState until running=false; output is in the state.
        @Slot(str, result=bool)
        def opStart(self, args_json):
            return self._op_start(args_json, None)

        def _op_start(self, args_json, env_extra):
            if getattr(self, "_op_thread", None) and self._op_thread.is_alive():
                return False
            try:
                args = json.loads(args_json)
            except ValueError:
                return False
            if not op_allowed(args):
                return False
            try:
                open(PROGRESS_FILE, "w").close()
            except OSError:
                pass
            self._op_output = None

            def _worker():
                rc, out, err = run_auditxs(
                    args + ["--progress-file", PROGRESS_FILE], timeout=1800,
                    env_extra=env_extra)
                text = strip_ansi(out)
                if rc != 0 and err:
                    text += "\n[exit %d] %s" % (rc, strip_ansi(err)[-800:])
                self._op_output = text

            self._op_thread = threading.Thread(target=_worker, daemon=True)
            self._op_thread.start()
            return True

        @Slot(result=str)
        def opState(self):
            running = bool(getattr(self, "_op_thread", None)
                           and self._op_thread.is_alive())
            st = read_progress()
            st["running"] = running
            st["output"] = "" if running else (getattr(self, "_op_output", "") or "")
            return json.dumps(st)

        # Console: line-based command runner (the user's own shell, the
        # window's own unprivileged rights — like typing in a terminal).
        @Slot(str, result=bool)
        def consoleRun(self, cmd):
            if getattr(self, "_con_thread", None) and self._con_thread.is_alive():
                return False
            cmd = (cmd or "").strip()
            if not cmd:
                return False

            def _worker():
                try:
                    p = subprocess.run(["bash", "-c", cmd], capture_output=True,
                                       text=True, timeout=600)
                    out = (p.stdout or "") + (p.stderr or "")
                    if p.returncode != 0:
                        out += "\n[exit %d]" % p.returncode
                except subprocess.TimeoutExpired:
                    out = "[timed out after 600s]"
                self._con_lines.append("$ %s\n%s" % (cmd, strip_ansi(out).rstrip()))

            self._con_lines = getattr(self, "_con_lines", [])
            self._con_thread = threading.Thread(target=_worker, daemon=True)
            self._con_thread.start()
            return True

        @Slot(result=str)
        def consolePoll(self):
            running = bool(getattr(self, "_con_thread", None)
                           and self._con_thread.is_alive())
            return json.dumps({"running": running,
                               "log": "\n\n".join(getattr(self, "_con_lines", []))})

        # Security tools: one {name, installed} record per manageable tool.
        @Slot(result=str)
        def toolsState(self):
            rc, out, _ = run_auditxs(["tools", "state"])
            tools = []
            for line in strip_ansi(out).splitlines():
                parts = line.split()
                if len(parts) == 2:
                    tools.append({"name": parts[0], "installed": parts[1] == "installed"})
            return json.dumps(tools)

        # Web-UI on/off switch (systemd service, local or — warned — remote).
        # status is read unprivileged (no password prompt on tab open); the
        # enable/disable/token actions elevate explicitly.
        @Slot(result=str)
        def webserviceStatus(self):
            rc, out, _ = run_auditxs(["webservice", "status"])
            txt = strip_ansi(out)
            active, bind, port, remote, has_systemd = False, "127.0.0.1", "9000", False, False
            for line in txt.splitlines():
                s = line.strip()
                if s.startswith("State:"):
                    has_systemd = True   # printed only when systemd is present
                    active = s.split(":", 1)[1].strip().startswith("active")
                elif s.startswith("Bind:"):
                    remote = "REMOTE" in s
                    hp = s.split()[1] if len(s.split()) > 1 else ""
                    if ":" in hp:
                        bind, port = hp.rsplit(":", 1)
            return json.dumps({"active": active, "bind": bind, "port": port,
                               "remote": remote, "systemd": has_systemd,
                               "text": txt.strip()})

        @Slot(str, bool, result=str)
        def webserviceEnable(self, port, remote):
            args = ["webservice", "enable"]
            if port and port.isdigit():
                args += ["--port", port]
            if remote:
                args += ["--remote"]
            rc, out, err = run_auditxs_root(args)
            return strip_ansi(out) + ("\n" + strip_ansi(err) if rc != 0 and err else "")

        @Slot(result=str)
        def webserviceDisable(self):
            rc, out, err = run_auditxs_root(["webservice", "disable"])
            return strip_ansi(out) + ("\n" + strip_ansi(err) if rc != 0 and err else "")

        @Slot(bool, result=str)
        def webserviceToken(self, reset):
            args = ["webservice", "token"]
            if reset:
                args += ["--reset"]
            rc, out, err = run_auditxs_root(args)
            return strip_ansi(out) + ("\n" + strip_ansi(err) if rc != 0 and err else "")

        # Fleet management (user-level inventory; read-only over SSH).
        @Slot(result=str)
        def fleetConfig(self):
            return json.dumps(fleet_config())

        @Slot(str, result=str)
        def fleetSave(self, cfg_json):
            try:
                return json.dumps(fleet_save(json.loads(cfg_json)))
            except (ValueError, OSError):
                return json.dumps(fleet_config())

        # Audit the saved fleet. ssh_pass / sudo_pass are entered per-run and
        # passed through the environment (never persisted, never on argv).
        @Slot(str, str, result=bool)
        def fleetAudit(self, ssh_pass, sudo_pass):
            cfg = fleet_config()
            if not cfg["hosts"]:
                return False
            ts = str(int(time.time()))
            outdir = os.path.join(FLEET_OUT_ROOT, ts)
            os.makedirs(outdir, exist_ok=True)
            self._fleet_outdir = outdir
            args = ["fleet", "--inventory", FLEET_HOSTS, "--output", outdir]
            if cfg["key"]:
                args += ["--key", cfg["key"]]
            env_extra = {}
            if ssh_pass:
                args += ["--ask-pass"]
                env_extra["AUDITXS_SSH_PASS"] = ssh_pass
            if sudo_pass:
                args += ["--ask-sudo-pass"]
                env_extra["AUDITXS_SUDO_PASS"] = sudo_pass
            elif cfg["sudo"]:
                args += ["--sudo"]
            return self._op_start(json.dumps(args), env_extra or None)

        @Slot(result=str)
        def fleetOverview(self):
            d = getattr(self, "_fleet_outdir", "")
            p = os.path.join(d, "index.html") if d else ""
            return p if p and os.path.exists(p) else ""

        @Slot(str)
        def openPath(self, path):
            if path and os.path.exists(path):
                subprocess.Popen(["xdg-open", path],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Open a real, fully-interactive terminal window (a shell — prefers
        # Konsole). Runs UNPRIVILEGED (a shell the user could open themselves);
        # the engine launches the emulator detached. Returns "" on success or
        # an error message to show.
        @Slot(result=str)
        def openTerminal(self):
            bin_ = os.environ.get("AUDITXS_BIN", "auditxs")
            try:
                p = subprocess.run([bin_, "terminal"], capture_output=True,
                                   text=True, timeout=60)
            except (OSError, subprocess.SubprocessError) as e:
                return str(e)
            if p.returncode != 0:
                return strip_ansi((p.stdout + p.stderr).strip()) or \
                    "Could not open a terminal."
            return ""

        @Slot(result=str)
        def openReport(self):
            rc, out, _ = run_auditxs(["report", "--format", "html", "--quiet"])
            if "<html" not in out:
                return "The report could not be generated (authentication cancelled?)."
            path = os.path.join(_PROGRESS_DIR, "report.html")
            with open(path, "w") as f:
                f.write(out)
            self.openPath(path)
            return ""

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
