// AuditXS — Qt Quick Controls (Material) native interface.
// Bound to the Python `backend` (see gui/auditxs-qt.py). All actions call the
// auditxs CLI; hardening is only ever applied after the review dialog.
//
// The window is frameless with its own Material title bar: the min / maximize
// / close buttons, drag-to-move and edge-resize are provided in-app (client-
// side decorations) so the chrome matches the app on every desktop.
import QtQuick
import QtQuick.Window
import QtQuick.Controls.Material
import QtQuick.Layouts

ApplicationWindow {
    id: win
    visible: true
    width: 940
    height: 680
    minimumWidth: 680
    minimumHeight: 480
    title: "AuditXS"
    flags: Qt.Window | Qt.FramelessWindowHint

    Material.theme: Material.System
    Material.primary: Material.Indigo
    Material.accent: Material.Indigo

    property var summary: ({ pass: 0, fail: 0, warn: 0, skip: 0, score: "-" })
    property bool isMax: win.visibility === Window.Maximized || win.visibility === Window.FullScreen

    // Audit runs asynchronously (backend worker thread) so the window stays
    // live; auditTimer polls the percentage for the progress bar.
    property bool auditRunning: false
    property int auditPct: 0
    property string auditCheck: ""

    // Generic async CLI operation + console + app identity (status bar).
    property bool opRunning: false
    property int opPct: 0
    property string opLabel: ""
    property bool opShowDialog: true
    property bool opAfterFleet: false
    property bool consoleOpen: false
    property string appVersion: "?"
    property string appProfile: "?"
    property string appHost: "?"

    // Run any whitelisted auditxs operation asynchronously; progress shows in
    // the status bar and the output opens in a dialog when done.
    function runOp(args, label, showDialog) {
        if (win.opRunning || win.auditRunning) return;
        if (!backend.opStart(JSON.stringify(args))) return;
        win.opRunning = true; win.opPct = 0; win.opLabel = label;
        win.opShowDialog = (showDialog === undefined) ? true : showDialog;
        opTimer.start();
    }

    function saveFleet() {
        var hosts = [];
        for (var i = 0; i < fleetModel.count; i++) hosts.push(fleetModel.get(i).host);
        backend.fleetSave(JSON.stringify({ hosts: hosts,
                                           key: fleetKey.text.trim(),
                                           sudo: fleetSudo.checked }));
    }

    function loadFleet() {
        var c = JSON.parse(backend.fleetConfig());
        fleetModel.clear();
        for (var i = 0; i < c.hosts.length; i++) fleetModel.append({ host: c.hosts[i] });
        fleetKey.text = c.key || "";
        fleetSudo.checked = c.sudo === undefined ? true : c.sudo;
    }

    Timer {
        id: opTimer
        interval: 300; repeat: true
        onTriggered: {
            var s = JSON.parse(backend.opState());
            win.opPct = s.pct || 0;
            if (!s.running) {
                stop();
                win.opRunning = false;
                if (win.opAfterFleet) {
                    win.opAfterFleet = false;
                    fleetOverviewBtn.visible = backend.fleetOverview().length > 0;
                }
                if (win.opShowDialog) {
                    opText.text = s.output && s.output.length ? s.output : "(no output)";
                    opDialog.title = win.opLabel;
                    opDialog.open();
                }
            }
        }
    }

    Timer {
        id: conTimer
        interval: 300; repeat: true
        onTriggered: {
            var s = JSON.parse(backend.consolePoll());
            conOut.text = s.log;
            conOut.cursorPosition = conOut.length;
            if (!s.running) stop();
        }
    }

    function refreshAudit() {
        if (auditRunning) return;
        auditRunning = true; auditPct = 0; auditCheck = "";
        chips.text = "Auditing (read-only — nothing is changed)…";
        backend.auditStart();
        auditTimer.start();
    }

    function applyAudit(d) {
        summary = d.summary ? d.summary : summary;
        scoreLabel.text = "Score " + summary.score + "/100";
        chips.text = summary.pass + " passed · " + summary.fail + " failed · "
                   + summary.warn + " warnings · " + summary.skip + " skipped";
        dashModel.clear();
        featModel.clear();
        var rs = d.results ? d.results : [];
        for (var i = 0; i < rs.length; i++) {
            dashModel.append(rs[i]);
            if (rs[i].fixable)
                featModel.append(rs[i]);
        }
    }

    Timer {
        id: auditTimer
        interval: 300; repeat: true
        onTriggered: {
            var p = JSON.parse(backend.auditProgress());
            win.auditPct = p.pct;
            win.auditCheck = p.id || "";
            if (!p.running) {
                stop();
                win.auditRunning = false;
                var r = backend.auditResult();
                if (r.length) applyAudit(JSON.parse(r));
            }
        }
    }

    function refreshSnaps() {
        snapModel.clear();
        var s = JSON.parse(backend.snapshots());
        for (var i = 0; i < s.length; i++)
            snapModel.append(s[i]);
    }

    function badgeColor(status) {
        return status === "PASS" ? "#2e7d32"
             : status === "FAIL" ? "#c62828"
             : status === "WARN" ? "#b26a00" : "#78909c";
    }

    function toggleMaximize() {
        if (win.isMax) win.showNormal();
        else           win.showMaximized();
    }

    // A window-control button. Icons are drawn as shapes (no glyph-font
    // dependency), so they look identical on every system and follow the theme.
    component WinButton: ToolButton {
        id: wb
        property string kind: "min"      // min | max | restore | close
        property bool danger: false      // close button turns red on hover
        implicitWidth: 46
        implicitHeight: 38
        Layout.preferredWidth: 46
        Layout.preferredHeight: 38
        focusPolicy: Qt.NoFocus
        property color glyph: (danger && (hovered || down)) ? "white" : Material.foreground
        background: Rectangle {
            color: wb.down    ? (wb.danger ? "#b71c1c" : Qt.rgba(0.5, 0.5, 0.5, 0.30))
                 : wb.hovered ? (wb.danger ? "#e53935" : Qt.rgba(0.5, 0.5, 0.5, 0.16))
                 : "transparent"
        }
        contentItem: Item {
            Item {
                anchors.centerIn: parent
                width: 12; height: 12
                // minimize — a single bar
                Rectangle {
                    visible: wb.kind === "min"; anchors.centerIn: parent
                    width: 11; height: 2; radius: 1; color: wb.glyph
                }
                // maximize — one square outline
                Rectangle {
                    visible: wb.kind === "max"; anchors.fill: parent
                    color: "transparent"; border.color: wb.glyph; border.width: 1.6; radius: 1.5
                }
                // restore — two offset square outlines
                Item {
                    visible: wb.kind === "restore"; anchors.fill: parent
                    Rectangle {   // back square (upper-right)
                        x: 3; y: 0; width: 9; height: 9; radius: 1
                        color: "transparent"; border.color: wb.glyph; border.width: 1.5
                    }
                    Rectangle {   // front square (lower-left), fills to occlude
                        x: 0; y: 3; width: 9; height: 9; radius: 1
                        color: win.color; border.color: wb.glyph; border.width: 1.5
                    }
                }
                // close — an X of two crossed bars
                Rectangle {
                    visible: wb.kind === "close"; anchors.centerIn: parent
                    width: 15; height: 2; radius: 1; rotation: 45; color: wb.glyph
                }
                Rectangle {
                    visible: wb.kind === "close"; anchors.centerIn: parent
                    width: 15; height: 2; radius: 1; rotation: -45; color: wb.glyph
                }
            }
        }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        // ---- custom title bar (drag to move, double-click to maximize) ----
        ToolBar {
            id: titleBar
            Layout.fillWidth: true

            TapHandler {
                onDoubleTapped: win.toggleMaximize()
            }
            DragHandler {
                target: null
                onActiveChanged: if (active) win.startSystemMove()
            }

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: 6
                spacing: 6
                Label { text: "AuditXS"; font.pixelSize: 20; font.bold: true; Layout.leftMargin: 10 }
                Label { id: scoreLabel; text: "Score –/100"; opacity: 0.9; Layout.leftMargin: 10 }
                Item { Layout.fillWidth: true }   // draggable gap
                Button {
                    text: win.auditRunning ? win.auditPct + "%" : "Run audit"
                    enabled: !win.auditRunning
                    highlighted: true; focusPolicy: Qt.NoFocus; onClicked: refreshAudit()
                }
                Item { width: 10 }
                WinButton { kind: "min";                onClicked: win.showMinimized() }
                WinButton { kind: win.isMax ? "restore" : "max"; onClicked: win.toggleMaximize() }
                WinButton { kind: "close"; danger: true; onClicked: win.close() }
            }
        }

        Label {
            id: chips
            text: "Press Run audit to scan (read-only)."
            Layout.fillWidth: true
            Layout.margins: 12
            opacity: 0.8
        }

        // Live audit progress: percentage bar + current check id.
        ColumnLayout {
            visible: win.auditRunning
            Layout.fillWidth: true
            Layout.leftMargin: 12; Layout.rightMargin: 12
            spacing: 2
            ProgressBar {
                Layout.fillWidth: true
                from: 0; to: 100
                value: win.auditPct
            }
            Label {
                text: win.auditPct + "%" + (win.auditCheck.length ? " — " + win.auditCheck : "")
                font.pixelSize: 12
                opacity: 0.7
            }
        }

        TabBar {
            id: tabs
            Layout.fillWidth: true
            TabButton { text: "Dashboard" }
            TabButton { text: "Features" }
            TabButton { text: "Snapshots"; onClicked: refreshSnaps() }
            TabButton { text: "Tools" }
            TabButton { text: "Fleet" }
            TabButton { text: "Ops" }
        }

        StackLayout {
            currentIndex: tabs.currentIndex
            Layout.fillWidth: true
            Layout.fillHeight: true

            // --- Dashboard ---
            ListView {
                clip: true
                model: ListModel { id: dashModel }
                delegate: ItemDelegate {
                    width: ListView.view ? ListView.view.width : 0
                    contentItem: RowLayout {
                        spacing: 12
                        Rectangle {
                            radius: 6; implicitWidth: 54; implicitHeight: 22
                            color: badgeColor(status)
                            Label { anchors.centerIn: parent; text: status; color: "white"; font.pixelSize: 11; font.bold: true }
                        }
                        ColumnLayout {
                            Layout.fillWidth: true; spacing: 2
                            Label { text: id + "   " + title; font.pixelSize: 14; Layout.fillWidth: true; elide: Text.ElideRight }
                            Label { text: detail ? detail : ""; opacity: 0.7; font.pixelSize: 12; visible: detail && status !== "PASS"; wrapMode: Text.WordWrap; Layout.fillWidth: true }
                            Label { text: severity + " · Level " + level + (cis ? " · CIS " + cis : ""); opacity: 0.55; font.pixelSize: 11 }
                        }
                        Button {
                            visible: status === "FAIL" || status === "WARN"
                            text: (status === "FAIL" && fixable) ? "Fix it" : "How to fix"
                            highlighted: status === "FAIL" && fixable
                            focusPolicy: Qt.NoFocus
                            onClicked: {
                                reviewDialog.cid = id;
                                reviewDialog.canApply = (status === "FAIL" && fixable);
                                reviewText.text = backend.explain(id)
                                    + (reviewDialog.canApply ? "" :
                                       "\n────────────────────────────────\n"
                                       + "MANUAL FIX — this check has no automatic fix.\n"
                                       + "Follow the remediation guidance above (what the fix\n"
                                       + "changes / documentation links), make the change\n"
                                       + "yourself, then run the audit again to verify. The\n"
                                       + "console below (status bar → Console) is handy for it.");
                                reviewDialog.title = reviewDialog.canApply
                                    ? ("Fix " + id + "? (reversible — snapshotted)")
                                    : ("How to fix " + id);
                                reviewDialog.open();
                            }
                        }
                    }
                }
            }

            // --- Features (toggle switches) ---
            ListView {
                clip: true
                model: ListModel { id: featModel }
                delegate: ItemDelegate {
                    width: ListView.view ? ListView.view.width : 0
                    contentItem: RowLayout {
                        spacing: 12
                        ColumnLayout {
                            Layout.fillWidth: true; spacing: 2
                            Label { text: id + "   " + title; font.pixelSize: 14; Layout.fillWidth: true; elide: Text.ElideRight }
                            Label { text: severity + " · Level " + level + (cis ? " · CIS " + cis : ""); opacity: 0.55; font.pixelSize: 11 }
                        }
                        Switch {
                            checked: status === "PASS"
                            enabled: status !== "PASS"   // already-on controls: turn off via Snapshots
                            onClicked: {
                                checked = false;          // don't flip until confirmed
                                reviewDialog.cid = id;
                                reviewText.text = backend.explain(id);
                                reviewDialog.title = "Turn on " + id + "?";
                                reviewDialog.open();
                            }
                        }
                    }
                }
            }

            // --- Snapshots ---
            ListView {
                clip: true
                model: ListModel { id: snapModel }
                delegate: ItemDelegate {
                    width: ListView.view ? ListView.view.width : 0
                    contentItem: RowLayout {
                        spacing: 12
                        Label { text: id + "   " + date + "   " + actions + " action(s) · " + status; Layout.fillWidth: true }
                        Button {
                            text: "Roll back"; enabled: status === "applied"
                            onClicked: { rollbackDialog.sid = id; rollbackDialog.open(); }
                        }
                    }
                }
            }

            // --- Tools ---
            ColumnLayout {
                spacing: 8
                Label {
                    padding: 16; wrapMode: Text.WordWrap; Layout.fillWidth: true; opacity: 0.8
                    text: "Inventory, run and review the integrated security tools (Lynis, rkhunter, "
                        + "AIDE, ClamAV, OpenSCAP, …). Installing a tool is reversible like every "
                        + "other change — use the Console for 'auditxs tools install <tool>'."
                }
                Flow {
                    Layout.fillWidth: true; Layout.leftMargin: 16; spacing: 8
                    Button { text: "Tool status";  enabled: !win.opRunning; onClicked: runOp(["tools", "status"], "Security tool status") }
                    Button { text: "Run scanners"; enabled: !win.opRunning; onClicked: runOp(["tools", "scan"], "Scanner results") }
                    Button { text: "VPN review";   enabled: !win.opRunning; onClicked: runOp(["tools", "vpn"], "VPN configuration review") }
                }
                Item { Layout.fillHeight: true }
            }

            // --- Fleet (audit remote hosts over SSH — read-only) ---
            ColumnLayout {
                spacing: 8
                Label {
                    padding: 12; wrapMode: Text.WordWrap; Layout.fillWidth: true; opacity: 0.8
                    font.pixelSize: 12
                    text: "Audit many hosts over SSH from here — read-only by design (hardening stays "
                        + "per-host). Uses your own SSH keys/agent; add hosts as user@host. Each host "
                        + "needs AuditXS installed."
                }
                RowLayout {
                    Layout.leftMargin: 12; Layout.rightMargin: 12
                    TextField { id: fleetNew; Layout.fillWidth: true; placeholderText: "admin@web01" }
                    Button {
                        text: "Add host"
                        onClicked: {
                            if (fleetNew.text.trim().length) {
                                fleetModel.append({ host: fleetNew.text.trim() });
                                fleetNew.text = "";
                                saveFleet();
                            }
                        }
                    }
                }
                ListView {
                    Layout.fillWidth: true; Layout.fillHeight: true; clip: true
                    model: ListModel { id: fleetModel }
                    delegate: ItemDelegate {
                        width: ListView.view ? ListView.view.width : 0
                        contentItem: RowLayout {
                            Label { text: host; font.family: "monospace"; Layout.fillWidth: true }
                            Button { text: "Remove"; flat: true; onClicked: { fleetModel.remove(index); saveFleet(); } }
                        }
                    }
                }
                RowLayout {
                    Layout.leftMargin: 12; Layout.rightMargin: 12
                    TextField {
                        id: fleetKey; Layout.fillWidth: true
                        placeholderText: "SSH key path (empty = ssh-agent / default keys)"
                        onEditingFinished: saveFleet()
                    }
                    CheckBox { id: fleetSudo; text: "sudo on hosts"; checked: true; onClicked: saveFleet() }
                }
                RowLayout {
                    Layout.leftMargin: 12; Layout.rightMargin: 12; Layout.bottomMargin: 10
                    Button {
                        text: "Audit fleet"; highlighted: true
                        enabled: fleetModel.count > 0 && !win.opRunning && !win.auditRunning
                        onClicked: {
                            saveFleet();
                            if (backend.fleetAudit()) {
                                win.opRunning = true; win.opPct = 0;
                                win.opLabel = "Fleet audit"; win.opShowDialog = true;
                                win.opAfterFleet = true;
                                fleetOverviewBtn.visible = false;
                                opTimer.start();
                            }
                        }
                    }
                    Button {
                        id: fleetOverviewBtn; visible: false
                        text: "Open overview dashboard"
                        onClicked: backend.openPath(backend.fleetOverview())
                    }
                    Item { Layout.fillWidth: true }
                }
            }

            // --- Ops (everything else the CLI can do) ---
            ColumnLayout {
                spacing: 8
                Label {
                    padding: 12; wrapMode: Text.WordWrap; Layout.fillWidth: true; opacity: 0.8
                    font.pixelSize: 12
                    text: "Every other CLI operation, one click away. Output opens in a window when "
                        + "the operation finishes; privileged operations prompt via the system "
                        + "authentication dialog (remembered a few minutes)."
                }
                Flow {
                    Layout.fillWidth: true; Layout.leftMargin: 12; Layout.rightMargin: 12; spacing: 8
                    Button { text: "CVE scan";        enabled: !win.opRunning; onClicked: runOp(["cve"], "CVE / vulnerability warnings") }
                    Button { text: "Doctor";          enabled: !win.opRunning; onClicked: runOp(["doctor"], "Installation diagnosis") }
                    Button { text: "Open HTML report"; enabled: !win.opRunning
                        onClicked: { var e = backend.openReport(); if (e.length) { opText.text = e; opDialog.title = "Report"; opDialog.open(); } } }
                    Button { text: "Schedule status"; enabled: !win.opRunning; onClicked: runOp(["schedule", "status"], "Scheduled audits") }
                    Button { text: "Enable daily audit";  enabled: !win.opRunning; onClicked: runOp(["schedule", "enable"], "Enable scheduled audits") }
                    Button { text: "Disable daily audit"; enabled: !win.opRunning; onClicked: runOp(["schedule", "disable"], "Disable scheduled audits") }
                    Button { text: "Baseline: approve latest"; enabled: !win.opRunning; onClicked: runOp(["baseline", "set"], "Approve baseline") }
                    Button { text: "Baseline: show";  enabled: !win.opRunning; onClicked: runOp(["baseline", "show"], "Approved baseline") }
                    Button { text: "Waivers";         enabled: !win.opRunning; onClicked: runOp(["waivers"], "Accepted-risk waivers") }
                    Button { text: "Alert status";    enabled: !win.opRunning; onClicked: runOp(["alert", "status"], "Alert sinks") }
                    Button { text: "Alert test";      enabled: !win.opRunning; onClicked: runOp(["alert", "test"], "Alert test") }
                    Button { text: "Error catalogue"; enabled: !win.opRunning; onClicked: runOp(["errors"], "Error catalogue") }
                    Button { text: "Check catalogue"; enabled: !win.opRunning; onClicked: runOp(["list"], "Check catalogue") }
                }
                Item { Layout.fillHeight: true }
            }
        }

        // ---- collapsible console (line-based; the user's own privileges) ----
        ColumnLayout {
            visible: win.consoleOpen
            Layout.fillWidth: true
            Layout.preferredHeight: 190
            spacing: 0
            Rectangle { Layout.fillWidth: true; implicitHeight: 1; color: Qt.rgba(0.5, 0.5, 0.5, 0.3) }
            ScrollView {
                Layout.fillWidth: true; Layout.fillHeight: true
                TextArea {
                    id: conOut
                    readOnly: true; wrapMode: TextArea.Wrap
                    font.family: "monospace"; font.pixelSize: 12
                    placeholderText: "Console — runs commands with your user's own privileges, like a "
                        + "terminal (line-based: interactive/TUI programs need a real terminal). "
                        + "Try:  auditxs cve   ·   auditxs waivers   ·   sudo auditxs harden --dry-run --yes"
                }
            }
            RowLayout {
                Layout.fillWidth: true
                Label { text: "$"; font.family: "monospace"; Layout.leftMargin: 8; opacity: 0.7 }
                TextField {
                    id: conIn
                    Layout.fillWidth: true; Layout.rightMargin: 8
                    font.family: "monospace"; font.pixelSize: 12
                    placeholderText: "type a command and press Enter"
                    onAccepted: { if (backend.consoleRun(text)) { text = ""; conTimer.start(); } }
                }
            }
        }

        // ---- status bar: identity · live progress · console toggle ----
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: 34
            color: Qt.rgba(0.5, 0.5, 0.5, 0.06)
            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: 10; anchors.rightMargin: 4
                spacing: 10
                Label {
                    text: "🛡️ AuditXS v" + win.appVersion + " · " + win.appProfile + " · " + win.appHost
                    font.pixelSize: 11; opacity: 0.75; elide: Text.ElideRight
                }
                ProgressBar {
                    visible: win.auditRunning || win.opRunning
                    from: 0; to: 100
                    value: win.auditRunning ? win.auditPct : win.opPct
                    Layout.preferredWidth: 140
                }
                Label {
                    visible: win.auditRunning || win.opRunning
                    text: (win.auditRunning ? win.auditPct : win.opPct) + "%"
                        + (win.opRunning && win.opLabel.length ? " · " + win.opLabel : "")
                        + (win.auditRunning && win.auditCheck.length ? " · " + win.auditCheck : "")
                    font.pixelSize: 11; opacity: 0.75; elide: Text.ElideRight
                    Layout.maximumWidth: 260
                }
                Item { Layout.fillWidth: true }
                Label {
                    text: "Made with ❤ from Canada 🍁 · © 2026 DigitalXS"
                    font.pixelSize: 11; opacity: 0.6; elide: Text.ElideRight
                    Layout.maximumWidth: 300
                }
                Button {
                    text: win.consoleOpen ? "Console ▾" : "Console ▴"
                    flat: true; focusPolicy: Qt.NoFocus; font.pixelSize: 11
                    onClicked: {
                        win.consoleOpen = !win.consoleOpen;
                        if (win.consoleOpen) conTimer.start();
                    }
                }
            }
        }
    }

    // Review-before-apply dialog (transparency + consent). With canApply the
    // OK button applies the reversible fix; without it (manual fixes) the
    // dialog is read-only guidance.
    Dialog {
        id: reviewDialog
        property string cid: ""
        property bool canApply: true
        anchors.centerIn: parent
        width: Math.min(win.width - 60, 700)
        height: Math.min(win.height - 80, 560)
        modal: true
        standardButtons: canApply ? (Dialog.Ok | Dialog.Cancel) : Dialog.Close
        onAccepted: {
            if (!canApply) return;
            backend.harden(cid);
            refreshAudit();
        }
        ScrollView {
            anchors.fill: parent
            TextArea { id: reviewText; readOnly: true; wrapMode: Text.WordWrap; font.family: "monospace" }
        }
    }

    // Output window for Ops / Tools / Fleet operations.
    Dialog {
        id: opDialog
        anchors.centerIn: parent
        width: Math.min(win.width - 60, 760)
        height: Math.min(win.height - 80, 580)
        modal: true
        standardButtons: Dialog.Close
        ScrollView {
            anchors.fill: parent
            TextArea { id: opText; readOnly: true; wrapMode: TextArea.Wrap; font.family: "monospace"; font.pixelSize: 12 }
        }
    }

    Dialog {
        id: rollbackDialog
        property string sid: ""
        anchors.centerIn: parent
        modal: true
        title: "Roll back?"
        standardButtons: Dialog.Ok | Dialog.Cancel
        Label { text: "Revert every change recorded in snapshot " + rollbackDialog.sid + "?"; wrapMode: Text.WordWrap }
        onAccepted: {
            backend.rollback(sid);
            refreshSnaps();
        }
    }

    // ---- frameless-window resize grips (thin, so scrollbars stay reachable) ----
    // Declared last so they sit above the content at the window's very edges.
    MouseArea {   // left edge
        anchors { left: parent.left; top: parent.top; bottom: parent.bottom }
        width: 4; cursorShape: Qt.SizeHorCursor
        onPressed: win.startSystemResize(Qt.LeftEdge)
    }
    MouseArea {   // right edge
        anchors { right: parent.right; top: parent.top; bottom: parent.bottom }
        width: 4; cursorShape: Qt.SizeHorCursor
        onPressed: win.startSystemResize(Qt.RightEdge)
    }
    MouseArea {   // top edge
        anchors { top: parent.top; left: parent.left; right: parent.right }
        height: 4; cursorShape: Qt.SizeVerCursor
        onPressed: win.startSystemResize(Qt.TopEdge)
    }
    MouseArea {   // bottom edge
        anchors { bottom: parent.bottom; left: parent.left; right: parent.right }
        height: 4; cursorShape: Qt.SizeVerCursor
        onPressed: win.startSystemResize(Qt.BottomEdge)
    }
    MouseArea {   // top-left corner
        anchors { left: parent.left; top: parent.top }
        width: 10; height: 10; cursorShape: Qt.SizeFDiagCursor
        onPressed: win.startSystemResize(Qt.LeftEdge | Qt.TopEdge)
    }
    MouseArea {   // top-right corner
        anchors { right: parent.right; top: parent.top }
        width: 10; height: 10; cursorShape: Qt.SizeBDiagCursor
        onPressed: win.startSystemResize(Qt.RightEdge | Qt.TopEdge)
    }
    MouseArea {   // bottom-left corner
        anchors { left: parent.left; bottom: parent.bottom }
        width: 10; height: 10; cursorShape: Qt.SizeBDiagCursor
        onPressed: win.startSystemResize(Qt.LeftEdge | Qt.BottomEdge)
    }
    MouseArea {   // bottom-right corner
        anchors { right: parent.right; bottom: parent.bottom }
        width: 10; height: 10; cursorShape: Qt.SizeFDiagCursor
        onPressed: win.startSystemResize(Qt.RightEdge | Qt.BottomEdge)
    }

    Component.onCompleted: {
        var m = JSON.parse(backend.meta());
        win.appVersion = m.version || "?";
        win.appProfile = m.profile || "?";
        win.appHost = m.host || "?";
        loadFleet();
        refreshAudit();
    }
}
