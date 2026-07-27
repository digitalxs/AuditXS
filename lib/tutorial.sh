#!/usr/bin/env bash
#
# AuditXS — lib/tutorial.sh
# A tiered, in-terminal tutorial: four progressive levels that take a user from
# "I just want my system safer" to professional automation, fleet and
# compliance use. Rendered in the house nala style; the GUIs surface the same
# four levels. Content is plain guidance — it never changes the system.
#

# _tut_head <level-name> <one-line subtitle>
_tut_head() {
    nala_box "AuditXS tutorial — $1"
    nala_row "$2"
    nala_end
    say ""
}

# _tut_step <n> <title> — a numbered step heading.
_tut_step() { say "${BOLD}$1.${RC} ${BOLD}$2${RC}"; }

# _tut_cmd <command> [comment] — show a copy-pasteable command line.
_tut_cmd() {
    if [ -n "${2:-}" ]; then
        say "     ${GREEN}\$${RC} ${BOLD}$1${RC}   ${DIM}# $2${RC}"
    else
        say "     ${GREEN}\$${RC} ${BOLD}$1${RC}"
    fi
}

# _tut_note <text> — an indented explanatory line.
_tut_note() { say "     ${DIM}$1${RC}"; }

_tut_more() { # <next-level> <why>
    say ""
    say "${CYAN}➜ Next:${RC} ${BOLD}auditxs tutorial $1${RC}  ${DIM}— $2${RC}"
}

# ------------------------------------------------------------------- menu
_tutorial_menu() {
    nala_box "AuditXS tutorial"
    nala_row "Learn AuditXS at your own depth. Four progressive levels:"
    nala_row ""
    nala_row "  ${BOLD}simple${RC}        First run in one command — audit and fix, safely."
    nala_row "  ${BOLD}intermediate${RC}  Day-to-day: audit vs harden, scope, explain, undo."
    nala_row "  ${BOLD}advanced${RC}      Baselines, drift, external scanners, waivers, profiles."
    nala_row "  ${BOLD}pro${RC}           Automation, fleet, CI/SARIF, alerts, compliance, extending."
    nala_end
    say ""
    _tut_cmd "auditxs tutorial simple" "start here if you are new"
    _tut_cmd "auditxs tutorial all" "print every level, top to bottom"
    say ""
    _tut_note "The same tutorial is available in the web, desktop and terminal UIs."
}

# ----------------------------------------------------------------- simple
_tutorial_simple() {
    _tut_head "1/4 · Simple" "The safest way to make this system more secure, in one command."
    say "AuditXS checks your Linux system against professional security baselines,"
    say "then — only if you allow it — fixes what is weak. It lives by three rules:"
    say "  ${GREEN}Transparent${RC} (auditing changes nothing) · ${GREEN}Reversible${RC} (every fix can be undone) · ${GREEN}Consented${RC} (it asks first)."
    say ""
    _tut_step 1 "Run the guided flow"
    _tut_cmd "sudo auditxs start"
    _tut_note "It audits (read-only), shows what is weak and why, then offers each fix —"
    _tut_note "one at a time, explained first, applied only when you say yes."
    say ""
    _tut_step 2 "Read your score"
    _tut_note "You get a hardening score out of 100 and a list of findings. Green is good;"
    _tut_note "red is a failed check that AuditXS can fix for you."
    say ""
    _tut_step 3 "Changed your mind? Undo everything"
    _tut_cmd "sudo auditxs rollback latest"
    _tut_note "Every change was snapshotted first, so this restores the previous state."
    say ""
    _tut_step 4 "Just look, never touch"
    _tut_cmd "sudo auditxs audit" "read-only — nothing is changed"
    _tut_more intermediate "the everyday commands, and how to target just one area"
}

# ----------------------------------------------------------- intermediate
_tutorial_intermediate() {
    _tut_head "2/4 · Intermediate" "The everyday commands: audit, harden, explain, undo."
    _tut_step 1 "Audit vs harden vs start"
    _tut_note "audit = look (read-only).  harden = fix (with consent).  start = both, guided."
    _tut_cmd "sudo auditxs audit" "saves an HTML + JSON report under /var/lib/auditxs/reports"
    _tut_cmd "sudo auditxs harden --dry-run" "show every intended change, change nothing"
    _tut_cmd "sudo auditxs harden" "apply fixes one by one, asking each time"
    say ""
    _tut_step 2 "No root? Still useful"
    _tut_cmd "auditxs audit" "unprivileged: runs what it can, marks root-only checks skipped"
    say ""
    _tut_step 3 "Target just one area"
    _tut_cmd "sudo auditxs audit --category SSH" "one category"
    _tut_cmd "sudo auditxs audit --domain Database" "one assessment domain"
    _tut_cmd "sudo auditxs harden --check SSH-001" "a single check"
    say ""
    _tut_step 4 "Understand any check before you trust it"
    _tut_cmd "auditxs explain SSH-001" "what it inspects, why, what the fix changes, how it reverts"
    _tut_cmd "auditxs list" "the whole catalogue"
    say ""
    _tut_step 5 "Undo, precisely"
    _tut_cmd "sudo auditxs snapshots" "list restore points"
    _tut_cmd "sudo auditxs rollback latest" "undo the last hardening run completely"
    say ""
    _tut_step 6 "Stay hardened over time"
    _tut_cmd "sudo auditxs schedule enable" "daily drift check; alerts if something regresses"
    _tut_more advanced "baselines, external scanners, waivers and profiles"
}

# --------------------------------------------------------------- advanced
_tutorial_advanced() {
    _tut_head "3/4 · Advanced" "Baselines, drift, external scanners, waivers, profiles."
    _tut_step 1 "Profiles decide what applies"
    _tut_note "A 'server' profile expects more than a 'workstation'. Override per run:"
    _tut_cmd "sudo auditxs audit --profile server"
    _tut_cmd "auditxs list --level 1" "only CIS Level 1 checks"
    say ""
    _tut_step 2 "Catch drift against a known-good baseline"
    _tut_cmd "sudo auditxs audit --format json > good.json" "capture a baseline"
    _tut_cmd "sudo auditxs audit --baseline good.json" "flag anything that regressed since"
    _tut_cmd "auditxs diff good.json new.json" "compare two reports (exit 1 on regressions)"
    say ""
    _tut_step 3 "Fold in independent scanners — one report"
    _tut_cmd "sudo auditxs audit --with-tools" "adds Lynis + rkhunter + chkrootkit + debsecan findings"
    _tut_cmd "sudo auditxs audit --tools-cached" "same, but reuse their last reports (fast)"
    _tut_cmd "sudo auditxs lynis" "Lynis on its own, as an AuditXS-style summary"
    _tut_note "These findings are advisory — they never move your AuditXS score."
    say ""
    _tut_step 4 "Accept a risk on purpose"
    _tut_cmd "auditxs waive SSH-005 \"kiosk needs X11 forwarding\"" "documented exception"
    _tut_cmd "auditxs waivers" "review everything you have waived"
    say ""
    _tut_step 5 "Vulnerabilities and updates"
    _tut_cmd "sudo auditxs cve" "installed packages with a known CVE + fix"
    _tut_cmd "sudo auditxs update" "apply security updates (snapshotted, asks first)"
    say ""
    _tut_step 6 "Pick your interface"
    _tut_cmd "sudo auditxs web --remote" "Material web UI on the LAN"
    _tut_cmd "sudo auditxs tui" "ncurses UI — works over SSH"
    _tut_more pro "automation, fleet, CI, alerts, compliance and writing your own checks"
}

# --------------------------------------------------------------------- pro
_tutorial_pro() {
    _tut_head "4/4 · Professional" "Automation, fleet, CI, alerts, compliance, extending."
    _tut_step 1 "Unattended runs"
    _tut_cmd "sudo auditxs harden --yes --quiet" "no prompts, minimal output (trust it first)"
    _tut_note "Exit status is non-zero when checks fail — usable as a gate in scripts."
    say ""
    _tut_step 2 "Feed your pipeline"
    _tut_cmd "sudo auditxs report --format sarif > audit.sarif" "GitHub code-scanning"
    _tut_cmd "sudo auditxs report --format csv" "spreadsheets; also json, tsv, html"
    say ""
    _tut_step 3 "Audit a whole fleet over SSH"
    _tut_cmd "auditxs fleet web01 db01 app03 --sudo" "read-only across many hosts, aggregated"
    _tut_note "Fleet mode never hardens remote hosts — it only reports."
    say ""
    _tut_step 4 "Get told when something drifts"
    _tut_cmd "auditxs alert status" "configure webhook / email drift & CVE alerts"
    say ""
    _tut_step 5 "Prove compliance"
    _tut_note "Every check maps to NIST CSF 2.0 and, where applicable, CIS / DISA STIG."
    _tut_cmd "auditxs explain SSH-001" "see the mappings per check"
    _tut_note "Framework overview: docs/COMPLIANCE.md · Full catalogue: docs/CHECKS.md"
    say ""
    _tut_step 6 "How reversibility actually works"
    _tut_note "Before any change, files are copied and service/sysctl/permission state is"
    _tut_note "logged into a timestamped snapshot; a global append-only ledger"
    _tut_note "(/var/lib/auditxs/changes.log) records every action; rollback replays it in"
    _tut_note "reverse. Nothing AuditXS does is a one-way door."
    say ""
    _tut_step 7 "Extend it — write your own check"
    _tut_note "A check is register_check + audit_<ID> (+ optional fix_<ID>) in checks/*.sh."
    _tut_note "Test it against a fake root tree with AUDITXS_ROOT_PREFIX — no privileges,"
    _tut_note "no host changes. See digitalxs-dev-doc.MD and tests/check_test.sh."
    _tut_cmd "auditxs errors" "the full error-code catalogue, for scripting and support"
    say ""
    say "${GREEN}You have the whole tool now.${RC} ${DIM}Revisit any level with 'auditxs tutorial <level>'.${RC}"
}

# ------------------------------------------------------------------ entry
cmd_tutorial() {
    case ${1:-menu} in
        menu|help|"")                _tutorial_menu ;;
        simple|1|basic|beginner)     _tutorial_simple ;;
        intermediate|2|inter|medium) _tutorial_intermediate ;;
        advanced|3|adv|power)        _tutorial_advanced ;;
        pro|professional|4|expert)   _tutorial_pro ;;
        all)
            _tutorial_simple;       hr
            _tutorial_intermediate; hr
            _tutorial_advanced;     hr
            _tutorial_pro ;;
        *) die "Usage: auditxs tutorial [simple|intermediate|advanced|pro|all]" ;;
    esac
}
