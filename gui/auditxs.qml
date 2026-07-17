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

    function refreshAudit() {
        var d = JSON.parse(backend.audit());
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
                Button { text: "Run audit"; highlighted: true; focusPolicy: Qt.NoFocus; onClicked: refreshAudit() }
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

        TabBar {
            id: tabs
            Layout.fillWidth: true
            TabButton { text: "Dashboard" }
            TabButton { text: "Features" }
            TabButton { text: "Snapshots"; onClicked: refreshSnaps() }
            TabButton { text: "Tools" }
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
                    padding: 16; wrapMode: Text.WordWrap; Layout.fillWidth: true
                    text: "Install and run security tools from the command line:\n\n"
                        + "    sudo auditxs tools install lynis\n"
                        + "    sudo auditxs tools scan\n"
                        + "    auditxs tools vpn\n\n"
                        + "See 'auditxs tools status' for what is installed."
                }
                Item { Layout.fillHeight: true }
            }
        }

        // ---- branding footer ----
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: 30
            color: Qt.rgba(0.5, 0.5, 0.5, 0.06)
            Label {
                anchors.centerIn: parent
                width: parent.width - 24
                horizontalAlignment: Text.AlignHCenter
                elide: Text.ElideRight
                font.pixelSize: 11
                opacity: 0.7
                text: "🛡️ AuditXS  ·  Made with ❤ from Canada 🍁  ·  © 2026 DigitalXS — Programming & Development"
            }
        }
    }

    // Review-before-apply dialog (transparency + consent).
    Dialog {
        id: reviewDialog
        property string cid: ""
        anchors.centerIn: parent
        width: Math.min(win.width - 60, 700)
        height: Math.min(win.height - 80, 560)
        modal: true
        standardButtons: Dialog.Ok | Dialog.Cancel
        onAccepted: {
            backend.harden(cid);
            refreshAudit();
        }
        ScrollView {
            anchors.fill: parent
            TextArea { id: reviewText; readOnly: true; wrapMode: Text.WordWrap; font.family: "monospace" }
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

    Component.onCompleted: refreshAudit()
}
