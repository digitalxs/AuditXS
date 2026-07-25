#!/usr/bin/env python3
"""
AuditXS Qt/QML view test — loads gui/auditxs.qml offscreen with a stub backend
and exercises the window-control methods, so QML syntax errors, broken bindings
and typo'd method calls (which are runtime-only in QML) are caught in CI.

Requires PySide6 + a headless GL stack; if PySide6 cannot be imported the test
prints SKIP and exits 0, so it is safe to run anywhere.
"""
import os
import sys

os.environ["QT_QPA_PLATFORM"] = "offscreen"
os.environ.setdefault("QT_QUICK_CONTROLS_STYLE", "Material")
os.environ.setdefault("QT_QUICK_CONTROLS_MATERIAL_THEME", "System")

try:
    from PySide6.QtCore import QObject, Slot, QUrl, QTimer, Qt
    from PySide6.QtGui import QGuiApplication
    from PySide6.QtQml import QQmlApplicationEngine
except ImportError as e:  # PySide6 not installed — nothing to test here
    print(f"SKIP qml_test: PySide6 not available ({e})")
    sys.exit(0)

HERE = os.path.dirname(os.path.abspath(__file__))
QML = os.path.join(HERE, "..", "gui", "auditxs.qml")


class StubBackend(QObject):
    """Deterministic stand-in for the real CLI-backed backend."""

    @Slot(result=str)
    def meta(self):
        return '{"version":"0.0.0","host":"test","profile":"workstation"}'

    @Slot(result=str)
    def audit(self):
        return ('{"summary":{"pass":1,"fail":1,"warn":0,"skip":0,"score":"80"},'
                '"results":[{"id":"SSH-001","title":"root login","status":"FAIL",'
                '"severity":"critical","level":"1","cis":"5.1.20","detail":"x",'
                '"fixable":true}]}')

    # Async audit contract used by the progress bar (see gui/auditxs-qt.py):
    # start → poll progress until running=false → collect the result.
    @Slot()
    def auditStart(self):
        self._started = True

    @Slot(result=str)
    def auditProgress(self):
        return '{"pct":100,"done":1,"total":1,"id":"done","running":false}'

    @Slot(result=str)
    def auditResult(self):
        return self.audit()

    @Slot(str, result=str)
    def explain(self, cid):
        return "explain " + cid

    @Slot(str, result=str)
    def harden(self, cid):
        return '{"rc":0,"log":"ok"}'

    @Slot(result=str)
    def snapshots(self):
        return "[]"

    @Slot(str, result=str)
    def rollback(self, sid):
        return '{"rc":0,"log":"ok"}'

    # v0.14 contract: generic ops, console, fleet, report/open helpers.
    @Slot(str, result=bool)
    def opStart(self, args_json):
        return True

    @Slot(result=str)
    def opState(self):
        return '{"pct":100,"done":1,"total":1,"id":"done","running":false,"output":"ok"}'

    @Slot(str, result=bool)
    def consoleRun(self, cmd):
        return True

    @Slot(result=str)
    def consolePoll(self):
        return '{"running":false,"log":"$ true\\n"}'

    @Slot(result=str)
    def toolsState(self):
        return '[{"name":"lynis","installed":false},{"name":"auditd","installed":true}]'

    # v0.20 contract: web-UI on/off switch.
    @Slot(result=str)
    def webserviceStatus(self):
        return ('{"active":false,"bind":"127.0.0.1","port":"9000",'
                '"remote":false,"systemd":true,"text":"State: inactive"}')

    @Slot(str, bool, result=str)
    def webserviceEnable(self, port, remote):
        return "web service ON"

    @Slot(result=str)
    def webserviceDisable(self):
        return "web service OFF"

    @Slot(bool, result=str)
    def webserviceToken(self, reset):
        return "Access token: TESTTOKEN"

    @Slot(result=str)
    def fleetConfig(self):
        return '{"hosts":["admin@web01"],"key":"","sudo":true}'

    @Slot(str, result=str)
    def fleetSave(self, cfg):
        return self.fleetConfig()

    @Slot(str, str, result=bool)
    def fleetAudit(self, ssh_pass, sudo_pass):
        return True

    @Slot(result=str)
    def fleetOverview(self):
        return ""

    @Slot(str)
    def openPath(self, path):
        pass

    @Slot(result=str)
    def openReport(self):
        return ""


def main():
    app = QGuiApplication(sys.argv)
    engine = QQmlApplicationEngine()

    warnings = []
    engine.warnings.connect(
        lambda ws: warnings.extend(w.toString() for w in ws))

    backend = StubBackend()
    engine.rootContext().setContextProperty("backend", backend)
    engine.load(QUrl.fromLocalFile(os.path.abspath(QML)))

    roots = engine.rootObjects()
    if not roots:
        print("FAIL: QML did not load (no root object)")
        for w in warnings:
            print("  ", w)
        return 1
    win = roots[0]

    failures = []

    def runtime_warnings():
        bad = ("TypeError", "ReferenceError", "is not a function", "Unable to assign")
        return [w for w in warnings if any(b in w for b in bad)]

    def drive():
        try:
            # window-state controls used by the title-bar buttons
            assert win.property("isMax") is False, "window should start un-maximized"
            win.showMaximized()
            assert win.property("isMax") is True, "isMax should track showMaximized()"
            win.metaObject().invokeMethod(win, "toggleMaximize")
            assert win.property("isMax") is False, "toggleMaximize should restore"
            win.showMinimized()
            win.showNormal()
            # frameless move/resize entry points (QWindow methods)
            win.startSystemResize(Qt.Edge.RightEdge | Qt.Edge.BottomEdge)
            win.startSystemMove()
            # exercise the web-service tab bindings (v0.20)
            win.metaObject().invokeMethod(win, "refreshWeb")
            win.metaObject().invokeMethod(win, "webApplyEnable")
        except Exception as e:  # noqa: BLE001 — report any driving failure
            failures.append(repr(e))
        finally:
            app.quit()

    QTimer.singleShot(300, drive)
    app.exec()

    rt = runtime_warnings()
    if rt:
        failures.append("runtime QML warnings: " + " | ".join(rt))

    if failures:
        print("FAIL qml_test:")
        for f in failures:
            print("  -", f)
        return 1

    print("PASS qml_test: auditxs.qml loads and window controls work")
    return 0


if __name__ == "__main__":
    sys.exit(main())
