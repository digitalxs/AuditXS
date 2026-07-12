#!/usr/bin/env bash
#
# AuditXS — lib/report.sh
# Report generation: TSV (for the GUI/scripting), JSON and self-contained HTML.
#
# Part of AuditXS — transparent, reversible Linux security auditing.
#

json_escape() {
    local s=$1
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\t'/\\t}
    s=${s//$'\r'/}
    s=${s//$'\n'/\\n}
    printf '%s' "$s"
}

html_escape() {
    local s=$1
    s=${s//&/&amp;}
    s=${s//</&lt;}
    s=${s//>/&gt;}
    printf '%s' "$s"
}

# One line per audited check:
# STATUS <tab> ID <tab> SEVERITY <tab> CATEGORY <tab> FIXABLE <tab> TITLE <tab> DETAIL
results_tsv() {
    local id fixable detail
    for id in "${CHECK_IDS[@]}"; do
        [ -n "${RESULT_STATUS[$id]:-}" ] || continue
        if has_fix "$id"; then fixable=yes; else fixable=no; fi
        detail=${RESULT_DETAIL[$id]//$'\t'/ }
        detail=${detail//$'\n'/; }
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "${RESULT_STATUS[$id]}" "$id" "${CHECK_SEVERITY[$id]}" \
            "${CHECK_CATEGORY[$id]}" "$fixable" "${CHECK_TITLE[$id]}" "$detail"
    done
}

results_json() {
    local id first=1 fixable
    printf '{\n'
    printf '  "tool": "AuditXS",\n'
    printf '  "version": "%s",\n' "$AUDITXS_VERSION"
    printf '  "host": "%s",\n' "$(json_escape "$(hostname 2>/dev/null)")"
    printf '  "distro": "%s",\n' "$(json_escape "$DISTRO_NAME")"
    printf '  "profile": "%s",\n' "$(json_escape "$PROFILE")"
    printf '  "date": "%s",\n' "${AUDIT_DATE:-$(date -Is)}"
    printf '  "summary": { "pass": %s, "fail": %s, "warn": %s, "skip": %s, "score": "%s" },\n' \
        "$N_PASS" "$N_FAIL" "$N_WARN" "$N_SKIP" "$SCORE"
    printf '  "results": [\n'
    for id in "${CHECK_IDS[@]}"; do
        [ -n "${RESULT_STATUS[$id]:-}" ] || continue
        if has_fix "$id"; then fixable=true; else fixable=false; fi
        [ "$first" = 1 ] || printf ',\n'
        first=0
        printf '    { "id": "%s", "category": "%s", "severity": "%s", "status": "%s", "fixable": %s, "title": "%s", "detail": "%s" }' \
            "$id" "$(json_escape "${CHECK_CATEGORY[$id]}")" "${CHECK_SEVERITY[$id]}" \
            "${RESULT_STATUS[$id]}" "$fixable" \
            "$(json_escape "${CHECK_TITLE[$id]}")" "$(json_escape "${RESULT_DETAIL[$id]}")"
    done
    printf '\n  ]\n}\n'
}

results_html() {
    local id st col cat="" fixable
    cat <<HTMLHEAD
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AuditXS report — $(html_escape "$(hostname 2>/dev/null)")</title>
<style>
  body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; margin: 2rem auto; max-width: 60rem; padding: 0 1rem; color: #1a1d21; background: #f7f8fa; }
  h1 { font-size: 1.5rem; } h2 { font-size: 1.15rem; margin-top: 2rem; border-bottom: 1px solid #d5d9df; padding-bottom: .3rem; }
  .meta { color: #555; margin-bottom: 1.5rem; }
  table { border-collapse: collapse; width: 100%; background: #fff; }
  th, td { text-align: left; padding: .45rem .6rem; border-bottom: 1px solid #e4e7eb; vertical-align: top; font-size: .9rem; }
  th { background: #eef0f3; }
  .badge { display: inline-block; padding: .1rem .5rem; border-radius: .35rem; font-weight: 600; font-size: .78rem; color: #fff; }
  .PASS { background: #2e7d32; } .FAIL { background: #c62828; } .WARN { background: #b26a00; } .SKIP { background: #78909c; }
  .detail { color: #555; font-size: .82rem; white-space: pre-wrap; }
  .score { font-size: 2rem; font-weight: 700; }
  .note { background: #fff8e1; border: 1px solid #ecd9a0; padding: .7rem 1rem; border-radius: .4rem; margin: 1rem 0; font-size: .88rem; }
  footer { margin-top: 2rem; color: #777; font-size: .8rem; }
</style>
</head>
<body>
<h1>AuditXS security audit report</h1>
<p class="meta">
  Host: <strong>$(html_escape "$(hostname 2>/dev/null)")</strong> ·
  $(html_escape "$DISTRO_NAME") ·
  Profile: <strong>$(html_escape "$PROFILE")</strong> ·
  ${AUDIT_DATE:-$(date -Is)} ·
  AuditXS v$AUDITXS_VERSION
</p>
<p class="score">Hardening score: $SCORE/100</p>
<p>Passed: <strong>$N_PASS</strong> · Failed: <strong>$N_FAIL</strong> · Warnings: <strong>$N_WARN</strong> · Skipped: <strong>$N_SKIP</strong></p>
<div class="note">This report was produced by a <strong>read-only</strong> audit — nothing on the system
was changed. Fixes are only applied by <code>sudo auditxs harden</code>, after showing exactly what will
change, and every change is recorded in a snapshot that <code>sudo auditxs rollback</code> can restore.</div>
HTMLHEAD

    for id in "${CHECK_IDS[@]}"; do
        [ -n "${RESULT_STATUS[$id]:-}" ] || continue
        if [ "${CHECK_CATEGORY[$id]}" != "$cat" ]; then
            [ -n "$cat" ] && printf '</table>\n'
            cat=${CHECK_CATEGORY[$id]}
            printf '<h2>%s</h2>\n<table>\n<tr><th>Status</th><th>ID</th><th>Severity</th><th>Fix</th><th>Finding</th></tr>\n' "$(html_escape "$cat")"
        fi
        st=${RESULT_STATUS[$id]}
        if has_fix "$id"; then fixable=auto; else fixable=manual; fi
        printf '<tr><td><span class="badge %s">%s</span></td><td>%s</td><td>%s</td><td>%s</td><td>%s' \
            "$st" "$st" "$id" "${CHECK_SEVERITY[$id]}" "$fixable" "$(html_escape "${CHECK_TITLE[$id]}")"
        if [ -n "${RESULT_DETAIL[$id]}" ]; then
            printf '<div class="detail">%s</div>' "$(html_escape "${RESULT_DETAIL[$id]}")"
        fi
        printf '</td></tr>\n'
    done
    [ -n "$cat" ] && printf '</table>\n'

    cat <<'HTMLFOOT'
<footer>Generated by AuditXS — transparent, reversible Linux security auditing.
Check documentation: <code>auditxs explain &lt;ID&gt;</code> · Change ledger: <code>/var/lib/auditxs/changes.log</code></footer>
</body>
</html>
HTMLFOOT
}

# save_reports — persist JSON + HTML copies of the current results and print
# their locations. Called after a console audit.
save_reports() {
    local ts base
    if [ "$(id -u)" -eq 0 ]; then
        REPORT_DIR="${REPORT_DIR:-/var/lib/auditxs/reports}"
    else
        REPORT_DIR="${REPORT_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/auditxs/reports}"
    fi
    mkdir -p "$REPORT_DIR" 2>/dev/null || return 0
    chmod 750 "$REPORT_DIR" 2>/dev/null
    ts=$(date +%Y%m%d-%H%M%S)
    base="$REPORT_DIR/audit-$ts"
    results_json > "$base.json"
    results_html > "$base.html"
    cp -f "$base.json" "$REPORT_DIR/latest.json"
    cp -f "$base.html" "$REPORT_DIR/latest.html"
    say "Reports written:"
    say "  $base.html"
    say "  $base.json"
}
