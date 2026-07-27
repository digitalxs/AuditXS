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

# Replacements are quoted: since bash 5.2 (patsub_replacement) an unquoted
# '&' in ${var//pat/rep} expands to the matched text, which corrupts entities.
html_escape() {
    local s=$1
    s=${s//&/"&amp;"}
    s=${s//</"&lt;"}
    s=${s//>/"&gt;"}
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

# CSV — a spreadsheet-friendly flat export (RFC-4180-ish quoting).
results_csv() {
    local id fixable detail cell
    _csv() { cell=${1//\"/\"\"}; printf '"%s"' "$cell"; }
    printf 'status,id,severity,category,domain,level,cis,nist,fixable,title,detail\n'
    for id in "${CHECK_IDS[@]}"; do
        [ -n "${RESULT_STATUS[$id]:-}" ] || continue
        if has_fix "$id"; then fixable=yes; else fixable=no; fi
        detail=${RESULT_DETAIL[$id]//$'\n'/ }
        _csv "${RESULT_STATUS[$id]}"; printf ,; _csv "$id"; printf ,
        _csv "${CHECK_SEVERITY[$id]}"; printf ,; _csv "${CHECK_CATEGORY[$id]}"; printf ,
        _csv "$(domain_of "${CHECK_CATEGORY[$id]}")"; printf ,; _csv "$(level_of "$id")"; printf ,
        _csv "$(cis_of "$id")"; printf ,; _csv "$(nist_of "$id")"; printf ,
        _csv "$fixable"; printf ,; _csv "${CHECK_TITLE[$id]}"; printf ,; _csv "$detail"
        printf '\n'
    done
}

# SARIF 2.1.0 — the standard static-analysis format consumed by GitHub code
# scanning, Azure DevOps, and most security dashboards. FAIL→error,
# WARN→warning; WAIVED findings are emitted with a SARIF suppression carrying
# the justification (so accepted risks are represented, not hidden).
results_sarif() {
    local id st sev level first=1
    _sec_sev() { case $1 in critical) echo 9.0 ;; high) echo 7.0 ;; medium) echo 5.0 ;; *) echo 3.0 ;; esac; }
    printf '{\n  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",\n  "version": "2.1.0",\n  "runs": [\n    {\n'
    printf '      "tool": { "driver": {\n        "name": "AuditXS",\n        "version": "%s",\n' "$AUDITXS_VERSION"
    printf '        "informationUri": "https://github.com/digitalxs/AuditXS",\n        "rules": [\n'
    # rules — one per check that produced a reportable result
    for id in "${CHECK_IDS[@]}"; do
        st=${RESULT_STATUS[$id]:-}; case $st in FAIL|WARN|WAIVE) : ;; *) continue ;; esac
        [ "$first" = 1 ] || printf ',\n'; first=0
        printf '          { "id": "%s", "name": "%s", "shortDescription": { "text": "%s" }, "fullDescription": { "text": "%s" }, "helpUri": "https://github.com/digitalxs/AuditXS", "properties": { "security-severity": "%s", "category": "%s", "cis": "%s", "nist": "%s" } }' \
            "$id" "$(json_escape "${CHECK_CATEGORY[$id]}")" "$(json_escape "${CHECK_TITLE[$id]}")" \
            "$(json_escape "${CHECK_META_DESC[$id]:-${CHECK_TITLE[$id]}}")" "$(_sec_sev "${CHECK_SEVERITY[$id]}")" \
            "$(json_escape "${CHECK_CATEGORY[$id]}")" "$(json_escape "$(cis_of "$id")")" "$(json_escape "$(nist_of "$id")")"
    done
    printf '\n        ]\n      } },\n      "results": [\n'
    first=1
    for id in "${CHECK_IDS[@]}"; do
        st=${RESULT_STATUS[$id]:-}
        case $st in FAIL) level=error ;; WARN) level=warning ;; WAIVE) level=warning ;; *) continue ;; esac
        [ "$first" = 1 ] || printf ',\n'; first=0
        printf '        { "ruleId": "%s", "level": "%s", "message": { "text": "%s" }, "locations": [ { "logicalLocations": [ { "name": "%s", "fullyQualifiedName": "%s/%s", "kind": "resource" } ] } ], "partialFingerprints": { "auditxsCheckId": "%s" }' \
            "$id" "$level" "$(json_escape "${CHECK_TITLE[$id]}: ${RESULT_DETAIL[$id]:-}")" \
            "$(json_escape "$id")" "$(json_escape "${CHECK_CATEGORY[$id]}")" "$id" "$id"
        if [ "$st" = WAIVE ]; then
            printf ', "suppressions": [ { "kind": "external", "justification": "%s" } ]' \
                "$(json_escape "$(waiver_reason "$id")")"
        fi
        printf ' }'
    done
    printf '\n      ]\n    }\n  ]\n}\n'
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
    printf '  "summary": { "pass": %s, "fail": %s, "warn": %s, "skip": %s, "waive": %s, "score": "%s" },\n' \
        "$N_PASS" "$N_FAIL" "$N_WARN" "$N_SKIP" "${N_WAIVE:-0}" "$SCORE"
    printf '  "results": [\n'
    for id in "${CHECK_IDS[@]}"; do
        [ -n "${RESULT_STATUS[$id]:-}" ] || continue
        if has_fix "$id"; then fixable=true; else fixable=false; fi
        [ "$first" = 1 ] || printf ',\n'
        first=0
        printf '    { "id": "%s", "category": "%s", "domain": "%s", "nist": "%s", "cis": "%s", "level": %s, "severity": "%s", "status": "%s", "fixable": %s, "title": "%s", "detail": "%s" }' \
            "$id" "$(json_escape "${CHECK_CATEGORY[$id]}")" \
            "$(json_escape "$(domain_of "${CHECK_CATEGORY[$id]}")")" \
            "$(json_escape "$(nist_of "$id")")" "$(json_escape "$(cis_of "$id")")" \
            "$(level_of "$id")" "${CHECK_SEVERITY[$id]}" \
            "${RESULT_STATUS[$id]}" "$fixable" \
            "$(json_escape "${CHECK_TITLE[$id]}")" "$(json_escape "${RESULT_DETAIL[$id]}")"
    done
    printf '\n  ],\n'
    # External tool findings (Lynis/rkhunter), folded in with --with-tools.
    # Advisory — not part of "results" and not reflected in "summary.score".
    printf '  "external": [\n'
    local ei efirst=1
    if [ "${#EXT_IDS[@]}" -gt 0 ]; then
        for ei in "${EXT_IDS[@]}"; do
            [ "$efirst" = 1 ] || printf ',\n'; efirst=0
            printf '    { "id": "%s", "tool": "%s", "status": "%s", "detail": "%s" }' \
                "$ei" "$(json_escape "${EXT_TOOL[$ei]}")" "${EXT_STATUS[$ei]}" \
                "$(json_escape "${EXT_DETAIL[$ei]}")"
        done
        printf '\n'
    fi
    printf '  ]\n}\n'
}

# results_html — self-contained Material Design 3 report (theme-aware,
# responsive). Grouped by category within its assessment domain. Shows the
# severity-weighted score, a CVE warning banner when applicable, and per-check
# status/severity/NIST/finding.
results_html() {
    local id st cat="" fixable score_color cve_banner="" fixcmd fixlabel
    case $SCORE in
        [0-9]|[0-3][0-9]|4[0-9]) score_color="var(--err)" ;;
        5[0-9]|6[0-9]|7[0-4])    score_color="var(--warn)" ;;
        *)                       score_color="var(--ok)" ;;
    esac
    # CVE banner — CVE_COUNT is populated by VULN-001 during run_audit.
    case "${CVE_COUNT:-?}" in
        ''|'?'|0) : ;;
        *) cve_banner="<div class=\"alert\"><span class=\"alert-ic\">⚠</span><div><strong>Vulnerability warning:</strong> ${CVE_COUNT} installed package(s) have a reported security issue with a fix available (source: ${CVE_SOURCE}). Apply security updates promptly — see check VULN-001 below.</div></div>" ;;
    esac
    local waive_chip=""
    [ "${N_WAIVE:-0}" -gt 0 ] && waive_chip="<span class=\"chip waive\">● $N_WAIVE waived</span>"

    cat <<HTMLHEAD
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AuditXS report — $(html_escape "$(hostname 2>/dev/null)")</title>
<style>
  :root {
    --bg:#f6f6fa; --surface:#ffffff; --surface-2:#eef0f6; --on-surface:#1b1b21;
    --on-surface-var:#5a5c66; --outline:#e2e3ec; --primary:#4b56d2; --primary-c:#fff;
    --ok:#1e7d46; --err:#ba1a1a; --warn:#a25b00; --skip:#6b7280;
    --ok-c:#e6f4ea; --err-c:#ffe9e7; --warn-c:#fff3e0; --skip-c:#eceef2;
    --shadow:0 1px 2px rgba(0,0,0,.08),0 2px 8px rgba(0,0,0,.05);
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#121318; --surface:#1c1d24; --surface-2:#23252e; --on-surface:#e4e2e9;
      --on-surface-var:#c6c6d0; --outline:#33343d; --primary:#bcc2ff; --primary-c:#1a2277;
      --ok:#7fd99b; --err:#ffb4ab; --warn:#f5bd6e; --skip:#a8abb4;
      --ok-c:#12331f; --err-c:#3d1512; --warn-c:#3a2a12; --skip-c:#282a32; }
  }
  :root[data-theme="light"] { --bg:#f6f6fa; --surface:#fff; --on-surface:#1b1b21; }
  :root[data-theme="dark"]  { --bg:#121318; --surface:#1c1d24; --on-surface:#e4e2e9; }
  * { box-sizing:border-box; }
  body { font-family:"Segoe UI",system-ui,-apple-system,Roboto,sans-serif; margin:0;
    background:var(--bg); color:var(--on-surface); line-height:1.5;
    -webkit-font-smoothing:antialiased; }
  .wrap { max-width:70rem; margin:0 auto; padding:1.5rem 1.25rem 4rem; }
  header.top { display:flex; align-items:center; gap:.75rem; padding:.5rem 0 1.25rem; }
  .logo { width:2.5rem; height:2.5rem; border-radius:.9rem; background:var(--primary);
    color:var(--primary-c); display:grid; place-items:center; font-weight:700; font-size:1.1rem; }
  h1 { font-size:1.4rem; font-weight:600; margin:0; }
  .sub { color:var(--on-surface-var); font-size:.85rem; }
  .card { background:var(--surface); border:1px solid var(--outline); border-radius:1.25rem;
    box-shadow:var(--shadow); padding:1.25rem 1.4rem; margin:1rem 0; }
  .hero { display:flex; flex-wrap:wrap; gap:1.5rem; align-items:center; }
  .score { --v:$SCORE; width:8rem; height:8rem; border-radius:50%; flex:0 0 auto;
    background:conic-gradient($score_color calc(var(--v)*1%), var(--surface-2) 0);
    display:grid; place-items:center; }
  .score > div { width:6.2rem; height:6.2rem; border-radius:50%; background:var(--surface);
    display:grid; place-items:center; text-align:center; }
  .score b { font-size:1.8rem; } .score span { font-size:.7rem; color:var(--on-surface-var); }
  .chips { display:flex; flex-wrap:wrap; gap:.5rem; margin-top:.25rem; }
  .chip { display:inline-flex; align-items:center; gap:.35rem; padding:.35rem .75rem;
    border-radius:2rem; font-size:.82rem; font-weight:600; }
  .chip.pass { background:var(--ok-c); color:var(--ok); }
  .chip.fail { background:var(--err-c); color:var(--err); }
  .chip.warn { background:var(--warn-c); color:var(--warn); }
  .chip.skip { background:var(--skip-c); color:var(--skip); }
  .chip.waive { background:rgba(59,73,223,.14); color:#5b67e6; }
  .alert { display:flex; gap:.75rem; align-items:flex-start; background:var(--err-c);
    color:var(--err); border-radius:1rem; padding:1rem 1.2rem; margin:1rem 0; font-size:.9rem; }
  .alert-ic { font-size:1.3rem; line-height:1; }
  .note { background:var(--warn-c); color:var(--warn); border-radius:1rem; padding:.9rem 1.2rem;
    margin:1rem 0; font-size:.85rem; }
  h2 { font-size:1.05rem; font-weight:600; margin:2rem 0 .5rem; }
  h2 small { color:var(--on-surface-var); font-weight:400; font-size:.8rem; }
  .tablewrap { overflow-x:auto; }
  table { border-collapse:collapse; width:100%; min-width:40rem; }
  th,td { text-align:left; padding:.6rem .75rem; border-bottom:1px solid var(--outline);
    vertical-align:top; font-size:.88rem; }
  th { color:var(--on-surface-var); font-weight:600; font-size:.72rem; text-transform:uppercase;
    letter-spacing:.04em; }
  tr:last-child td { border-bottom:none; }
  .badge { display:inline-block; min-width:3.2rem; text-align:center; padding:.2rem .55rem;
    border-radius:.6rem; font-weight:700; font-size:.72rem; }
  .badge.PASS { background:var(--ok-c); color:var(--ok); }
  .badge.FAIL { background:var(--err-c); color:var(--err); }
  .badge.WARN { background:var(--warn-c); color:var(--warn); }
  .badge.SKIP { background:var(--skip-c); color:var(--skip); }
  .badge.WAIVE { background:rgba(59,73,223,.14); color:#5b67e6; }
  .cid { font-family:ui-monospace,"Cascadia Code",monospace; font-size:.8rem; white-space:nowrap; }
  .detail { color:var(--on-surface-var); font-size:.82rem; white-space:pre-wrap; margin-top:.25rem; }
  .nist { font-size:.72rem; color:var(--on-surface-var); white-space:nowrap; }
  footer { color:var(--on-surface-var); font-size:.78rem; margin-top:2.5rem;
    border-top:1px solid var(--outline); padding-top:1rem; text-align:center; line-height:1.7; }
  footer .brand { font-weight:700; font-size:.92rem; color:var(--on-surface); letter-spacing:.02em; }
  footer .heart { color:#e0245e; }
  footer .copy strong { color:var(--on-surface); }
  footer a { color:var(--primary); text-decoration:none; font-weight:600; }
  code { background:var(--surface-2); padding:.1rem .35rem; border-radius:.35rem; font-size:.82em; }
  .togglebar { display:flex; align-items:center; gap:.6rem; margin-top:.9rem;
    font-size:.85rem; font-weight:600; cursor:pointer; user-select:none; }
  .switch { position:relative; display:inline-block; width:2.6rem; height:1.4rem; flex:0 0 auto; }
  .switch input { opacity:0; width:0; height:0; }
  .slider { position:absolute; inset:0; background:var(--surface-2);
    border:1px solid var(--outline); border-radius:2rem; transition:.2s; cursor:pointer; }
  .slider:before { content:""; position:absolute; height:1rem; width:1rem; left:.15rem;
    top:.13rem; background:var(--on-surface-var); border-radius:50%; transition:.2s; }
  .switch input:checked + .slider { background:var(--primary); border-color:var(--primary); }
  .switch input:checked + .slider:before { transform:translateX(1.2rem); background:var(--primary-c); }
  .fixbtn { margin-top:.4rem; display:inline-flex; align-items:center; gap:.3rem;
    border:1px solid var(--outline); background:var(--surface-2); color:var(--primary);
    font-weight:700; font-size:.72rem; padding:.25rem .6rem; border-radius:.6rem;
    cursor:pointer; font-family:inherit; }
  .fixbtn:hover { background:var(--primary); color:var(--primary-c); border-color:var(--primary); }
  .fixcmd { display:block; margin-top:.3rem; font-size:.78rem; width:fit-content; }
  .fixcmd[hidden] { display:none; }
  @media (max-width:640px){ .hero{gap:1rem} .score{width:6.5rem;height:6.5rem}
    .score>div{width:5rem;height:5rem} }
</style>
</head>
<body>
<div class="wrap">
<header class="top">
  <div class="logo">A</div>
  <div>
    <h1>AuditXS security audit</h1>
    <div class="sub">$(html_escape "$(hostname 2>/dev/null)") · $(html_escape "$DISTRO_NAME") · profile <strong>$(html_escape "$PROFILE")</strong> · ${AUDIT_DATE:-$(date -Is)} · v$AUDITXS_VERSION</div>
  </div>
</header>

$cve_banner

<div class="card hero">
  <div class="score"><div><div><b>$SCORE</b><br><span>/ 100</span></div></div></div>
  <div style="flex:1 1 15rem">
    <div style="font-weight:600;margin-bottom:.4rem">Hardening score <span class="sub">(severity-weighted, PASS vs FAIL)</span></div>
    <div class="chips">
      <span class="chip pass">● $N_PASS passed</span>
      <span class="chip fail">● $N_FAIL failed</span>
      <span class="chip warn">● $N_WARN warnings</span>
      <span class="chip skip">● $N_SKIP skipped</span>
      $waive_chip
    </div>
    <label class="togglebar"><span class="switch"><input type="checkbox" id="onlyfind"><span class="slider"></span></span>
      Show only findings <span class="sub">(hide passed, skipped and waived checks)</span></label>
  </div>
</div>

<div class="note">This report was produced by a <strong>read-only</strong> audit — nothing on the system
was changed. Fixes are only applied by <code>sudo auditxs harden</code>, after showing exactly what will
change, and every change is recorded in a snapshot that <code>sudo auditxs rollback</code> can restore.</div>
HTMLHEAD

    for id in "${CHECK_IDS[@]}"; do
        [ -n "${RESULT_STATUS[$id]:-}" ] || continue
        if [ "${CHECK_CATEGORY[$id]}" != "$cat" ]; then
            [ -n "$cat" ] && printf '</table></div></div>\n'
            cat=${CHECK_CATEGORY[$id]}
            printf '<h2 class="cat">%s <small>— %s domain</small></h2>\n<div class="card catcard" style="padding:.5rem .5rem"><div class="tablewrap"><table>\n<tr><th>Status</th><th>Check</th><th>Sev</th><th>L</th><th>Fix</th><th>CIS</th><th>NIST CSF</th></tr>\n' \
                "$(html_escape "$cat")" "$(html_escape "$(domain_of "$cat")")"
        fi
        st=${RESULT_STATUS[$id]}
        if has_fix "$id"; then fixable=auto; else fixable=manual; fi
        printf '<tr data-st="%s"><td><span class="badge %s">%s</span></td><td><span class="cid">%s</span> %s' \
            "$st" "$st" "$st" "$id" "$(html_escape "${CHECK_TITLE[$id]}")"
        if [ -n "${RESULT_DETAIL[$id]}" ]; then
            printf '<div class="detail">%s</div>' "$(html_escape "${RESULT_DETAIL[$id]}")"
        fi
        # "Fix it" on findings: the report is a static page, so the button
        # reveals + copies the exact command rather than pretending to run it.
        if [ "$st" = FAIL ] || [ "$st" = WARN ]; then
            if [ "$st" = FAIL ] && has_fix "$id"; then
                fixcmd="sudo auditxs harden --check $id"; fixlabel="Fix it"
            else
                fixcmd="auditxs explain $id"; fixlabel="How to fix"
            fi
            printf '<button type="button" class="fixbtn" data-cmd="%s">%s</button><code class="fixcmd" hidden>%s</code>' \
                "$fixcmd" "$fixlabel" "$fixcmd"
        fi
        printf '</td><td>%s</td><td>%s</td><td>%s</td><td class="nist">%s</td><td class="nist">%s</td></tr>\n' \
            "${CHECK_SEVERITY[$id]}" "$(level_of "$id")" "$fixable" \
            "$(html_escape "$(cis_of "$id")")" "$(html_escape "$(nist_of "$id")")"
    done
    [ -n "$cat" ] && printf '</table></div></div>\n'

    # External tool findings (Lynis/rkhunter) folded in with --with-tools.
    _html_external_section

    cat <<'HTMLFOOT'
<footer>
<div>Generated by <strong>AuditXS</strong> — transparent, reversible Linux security auditing.</div>
<div>Check documentation: <code>auditxs explain &lt;ID&gt;</code> · Change ledger: <code>/var/lib/auditxs/changes.log</code> · CVE detail: <code>auditxs cve</code></div>
<div class="brand" style="margin-top:1rem">🛡️ AuditXS</div>
<div class="made">Made with <span class="heart">&#10084;</span> from Canada &#127809;</div>
<div class="copy">&copy; 2026 <strong>DigitalXS</strong> — Programming &amp; Development · <a href="https://digitalxs.ca">digitalxs.ca</a></div>
</footer>
</div>
<script>
(function () {
  "use strict";
  // "Show only findings" — hide PASS/SKIP/WAIVE rows, and any category whose
  // rows are all hidden. The report stays a static, self-contained file.
  var toggle = document.getElementById("onlyfind");
  function applyFilter() {
    var only = toggle && toggle.checked;
    document.querySelectorAll("tr[data-st]").forEach(function (row) {
      var st = row.getAttribute("data-st");
      row.style.display = (only && st !== "FAIL" && st !== "WARN") ? "none" : "";
    });
    document.querySelectorAll(".catcard").forEach(function (card) {
      var anyVisible = false;
      card.querySelectorAll("tr[data-st]").forEach(function (row) {
        if (row.style.display !== "none") anyVisible = true;
      });
      card.style.display = anyVisible ? "" : "none";
      var heading = card.previousElementSibling;
      if (heading && heading.classList.contains("cat"))
        heading.style.display = anyVisible ? "" : "none";
    });
  }
  if (toggle) toggle.addEventListener("change", applyFilter);
  // "Fix it" / "How to fix" — reveal the exact command and copy it to the
  // clipboard (a static page cannot run commands; auditxs asks for consent).
  document.querySelectorAll(".fixbtn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var code = btn.nextElementSibling;
      var cmd = btn.getAttribute("data-cmd");
      if (code) code.hidden = !code.hidden;
      if (code && !code.hidden && navigator.clipboard && cmd) {
        navigator.clipboard.writeText(cmd).then(function () {
          var old = btn.textContent;
          btn.textContent = "Copied ✓";
          setTimeout(function () { btn.textContent = old; }, 1200);
        }).catch(function () { /* command stays visible for manual copy */ });
      }
    });
  });
})();
</script>
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

# ------------------------------------------------------------------ baseline
# AuditXS JSON reports put one result per line, so they can be parsed
# reliably here without a JSON library.

parse_report_results() { # <file> — emits "ID STATUS" per line
    sed -n 's/.*"id": "\([^"]*\)".*"status": "\([^"]*\)".*/\1 \2/p' "$1"
}

parse_report_field() { # <file> <field> — first occurrence wins (meta/summary)
    sed -n "s/.*\"$2\": \"\([^\"]*\)\".*/\1/p" "$1" | head -n1
}

_status_rank() { # PASS < WARN < FAIL (SKIP handled separately)
    case $1 in PASS) echo 0 ;; WARN) echo 1 ;; FAIL) echo 2 ;; *) echo 0 ;; esac
}

# render_diff <old-map-name> <new-map-name> <old-label> <new-label> <old-score> <new-score>
# Prints the comparison; returns 1 when regressions were found (CI-friendly).
render_diff() {
    local -n _o=$1 _n=$2
    local ol=$3 nl=$4 os=$5 ns=$6
    local id o n unchanged=0
    local -a regressed=() improved=() other=()
    local -A seen=()
    local -a all=()

    # Stable ordering: registry order first, then anything else in the reports.
    for id in "${CHECK_IDS[@]}"; do
        if [ -n "${_o[$id]:-}" ] || [ -n "${_n[$id]:-}" ]; then
            all+=("$id"); seen[$id]=1
        fi
    done
    for id in "${!_o[@]}" "${!_n[@]}"; do
        [ -n "${seen[$id]:-}" ] || { all+=("$id"); seen[$id]=1; }
    done

    for id in "${all[@]}"; do
        o=${_o[$id]:-}; n=${_n[$id]:-}
        if [ -z "$o" ]; then other+=("$id: not in baseline → $n   ${CHECK_TITLE[$id]:-}"); continue; fi
        if [ -z "$n" ]; then other+=("$id: $o → not audited   ${CHECK_TITLE[$id]:-}"); continue; fi
        if [ "$o" = "$n" ]; then unchanged=$((unchanged + 1)); continue; fi
        if [ "$o" = "SKIP" ] || [ "$n" = "SKIP" ]; then
            other+=("$id: $o → $n   ${CHECK_TITLE[$id]:-}")
            continue
        fi
        if [ "$(_status_rank "$n")" -gt "$(_status_rank "$o")" ]; then
            regressed+=("$id: $o → $n   ${CHECK_TITLE[$id]:-}")
        else
            improved+=("$id: $o → $n   ${CHECK_TITLE[$id]:-}")
        fi
    done

    printf '%b\n' "${DIM}──────────────────────────────────────────────────────────────────${RC}"
    printf '%b\n' "${BOLD}Baseline comparison${RC}"
    printf '%b\n' "  Baseline: $ol${os:+  (score $os)}"
    printf '%b\n' "  Current:  $nl${ns:+  (score $ns)}"
    printf '%b\n' ""
    if [ ${#regressed[@]} -gt 0 ]; then
        printf '%b\n' "${RED}${BOLD}Regressions (${#regressed[@]}):${RC}"
        printf '  %s\n' "${regressed[@]}"
    else
        printf '%b\n' "${GREEN}No regressions.${RC}"
    fi
    if [ ${#improved[@]} -gt 0 ]; then
        printf '%b\n' "${GREEN}${BOLD}Improvements (${#improved[@]}):${RC}"
        printf '  %s\n' "${improved[@]}"
    fi
    if [ ${#other[@]} -gt 0 ]; then
        printf '%b\n' "${YELLOW}Other changes (${#other[@]}) — applicability/scope:${RC}"
        printf '  %s\n' "${other[@]}"
    fi
    printf '%b\n' "${DIM}Unchanged: $unchanged check(s)${RC}"
    printf '%b\n' "${DIM}──────────────────────────────────────────────────────────────────${RC}"

    [ ${#regressed[@]} -eq 0 ]
}

# cmd_diff <baseline.json> [current.json] — compare two saved reports.
# Exit status 1 when the current report regressed against the baseline.
cmd_diff() {
    local old=$1 new=${2:-}
    if [ -z "$new" ]; then
        if [ "$(id -u)" -eq 0 ]; then
            new=/var/lib/auditxs/reports/latest.json
        else
            new="${XDG_STATE_HOME:-$HOME/.local/state}/auditxs/reports/latest.json"
        fi
    fi
    [ -r "$old" ] || die "Cannot read baseline report: $old"
    [ -r "$new" ] || die "Cannot read report: $new — run 'sudo auditxs audit' first, or pass a second file"
    local -A omap=() nmap=()
    local id st
    while read -r id st; do [ -n "$id" ] && omap[$id]=$st; done < <(parse_report_results "$old")
    while read -r id st; do [ -n "$id" ] && nmap[$id]=$st; done < <(parse_report_results "$new")
    [ ${#omap[@]} -gt 0 ] || die "No results found in $old — is it an AuditXS JSON report?"
    [ ${#nmap[@]} -gt 0 ] || die "No results found in $new — is it an AuditXS JSON report?"
    render_diff omap nmap \
        "$old ($(parse_report_field "$old" date))" \
        "$new ($(parse_report_field "$new" date))" \
        "$(parse_report_field "$old" score)" "$(parse_report_field "$new" score)"
}

# diff_current_against <baseline.json> — compare the in-memory results of the
# audit that just ran against a saved baseline (used by 'audit --baseline'
# and 'schedule run'). Returns 1 when regressions were found.
diff_current_against() {
    local base=$1
    [ -r "$base" ] || { warn "Baseline report not readable: $base — skipping comparison"; return 0; }
    local -A omap=() nmap=()
    local id st
    while read -r id st; do [ -n "$id" ] && omap[$id]=$st; done < <(parse_report_results "$base")
    [ ${#omap[@]} -gt 0 ] || { warn "No results found in $base — skipping comparison"; return 0; }
    for id in "${CHECK_IDS[@]}"; do
        [ -n "${RESULT_STATUS[$id]:-}" ] && nmap[$id]=${RESULT_STATUS[$id]}
    done
    render_diff omap nmap \
        "$base ($(parse_report_field "$base" date))" \
        "current audit" \
        "$(parse_report_field "$base" score)" "$SCORE"
}
