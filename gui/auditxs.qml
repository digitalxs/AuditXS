// AuditXS — Qt Quick Controls (Material) native interface.
// Bound to the Python `backend` (see gui/auditxs-qt.py). All actions call the
// auditxs CLI; hardening is only ever applied after the review dialog.
import QtQuick
import QtQuick.Controls.Material
import QtQuick.Layouts

ApplicationWindow {
    id: win
    visible: true
    width: 940
    height: 680
    title: "AuditXS"

    Material.theme: Material.System
    Material.primary: Material.Indigo
    Material.accent: Material.Indigo

    property var summary: ({ pass: 0, fail: 0, warn: 0, skip: 0, score: "-" })

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

    header: ToolBar {
        RowLayout {
            anchors.fill: parent
            Label { text: "AuditXS"; font.pixelSize: 20; font.bold: true; Layout.leftMargin: 16 }
            Label { id: scoreLabel; text: "Score –/100"; opacity: 0.9; Layout.leftMargin: 12 }
            Item { Layout.fillWidth: true }
            Button { text: "Run audit"; highlighted: true; Layout.rightMargin: 12; onClicked: refreshAudit() }
        }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

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

    Component.onCompleted: refreshAudit()
}
