#!/usr/bin/env python3
"""
AuditXS web UI — a localhost-only, token-authenticated Material Design 3
front-end that drives the `auditxs` command-line tool.

Design & security model (this is a security tool, so the front-end is too):
  * Binds 127.0.0.1 ONLY. It refuses to bind any non-loopback address, so the
    UI is never exposed to the network. Reach a remote server over an SSH
    tunnel:  ssh -L 9000:127.0.0.1:9000 user@host  then open the printed URL.
  * An ephemeral bearer token (new every launch) is required on every request.
    The launch URL embeds it once; the page then sends it as X-Auth-Token.
  * State-changing actions (harden, rollback, tool install) are POST-only,
    require the token in a header (CSRF defence), and the UI shows exactly
    what will change (the same `auditxs explain` text) before doing anything.
  * Every AuditXS invocation uses an argv list — never a shell — so nothing
    the browser sends can be interpreted as a command.
  * The server is a thin front-end: it runs the same `auditxs` commands you
    could type, so the transparency + reversibility guarantees are unchanged.

Stdlib only — no framework, no build step, minimal auditable surface.
Launched via:  sudo auditxs web  [--port N] [--no-open]
"""
import html
import json
import os
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

AUDITXS = os.environ.get("AUDITXS_BIN", "auditxs")
TOKEN = secrets.token_urlsafe(24)
PROFILE = os.environ.get("AUDITXS_PROFILE", "")   # empty → let auditxs decide
VERSION = "?"

# Progress file for long operations (audit): the CLI writes "PCT DONE TOTAL ID"
# via --progress-file; GET /api/progress serves it so the SPA can render a
# real percentage bar while the audit request is in flight.
PROGRESS_PATH = os.path.join(tempfile.mkdtemp(prefix="auditxs-web-"), "progress")


def read_progress():
    try:
        with open(PROGRESS_PATH) as f:
            parts = f.readline().split()
        return {"pct": int(parts[0]), "done": int(parts[1]),
                "total": int(parts[2]), "id": parts[3] if len(parts) > 3 else ""}
    except (OSError, ValueError, IndexError):
        return {"pct": 0, "done": 0, "total": 0, "id": ""}


# Console/CLI bridge: only auditxs subcommands, argv-only (never a shell),
# arguments restricted to a safe charset — same policy as every route here.
import re as _re
OP_CMDS = {"audit", "report", "harden", "rollback", "snapshots", "tools",
           "cve", "baseline", "doctor", "schedule", "errors", "waive",
           "unwaive", "waivers", "alert", "fleet", "list", "explain",
           "diff", "version", "profile"}
OP_ARG = _re.compile(r"[A-Za-z0-9@.,:%/_=+~ -]+")

# Fleet inventory managed by the web UI (the server runs as root).
FLEET_HOSTS_PATH = "/var/lib/auditxs/fleet-hosts"
FLEET_LAST_DIR = {"path": ""}

# --------------------------------------------------------------- CLI bridge
def run_auditxs(args, timeout=180, env_extra=None):
    """Run `auditxs <args>` with no shell; return (rc, stdout, stderr).

    env_extra (e.g. fleet passwords) is merged into the child environment only
    — never placed on the command line — and never logged.
    """
    cmd = [AUDITXS] + args
    env = None
    if env_extra:
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


def strip_ansi(s):
    import re
    return re.sub(r"\x1b\[[0-9;]*m", "", s or "")


def profile_args():
    return ["--profile", PROFILE] if PROFILE else []


# ------------------------------------------------------------------- HTML
PAGE = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>AuditXS</title>
<style>
:root{
 --bg:#f5f5fb;--surface:#fff;--surface2:#eef0f7;--on:#1b1b21;--onv:#5a5c66;
 --outline:#e2e3ec;--primary:#4b56d2;--primaryc:#fff;
 --ok:#1e7d46;--err:#ba1a1a;--warn:#a25b00;--skip:#6b7280;
 --okc:#e6f4ea;--errc:#ffe9e7;--warnc:#fff3e0;--skipc:#eceef2;
 --shadow:0 1px 2px rgba(0,0,0,.08),0 2px 10px rgba(0,0,0,.06);--r:1.1rem;
}
@media(prefers-color-scheme:dark){:root{
 --bg:#111218;--surface:#1b1c23;--surface2:#23252e;--on:#e5e2e9;--onv:#c6c6d0;
 --outline:#33343d;--primary:#bcc2ff;--primaryc:#1a2277;
 --ok:#7fd99b;--err:#ffb4ab;--warn:#f5bd6e;--skip:#a8abb4;
 --okc:#12331f;--errc:#3d1512;--warnc:#3a2a12;--skipc:#282a32;}}
*{box-sizing:border-box}
body{margin:0;font-family:"Segoe UI",system-ui,-apple-system,Roboto,sans-serif;
 background:var(--bg);color:var(--on);-webkit-font-smoothing:antialiased}
.appbar{position:sticky;top:0;z-index:5;display:flex;align-items:center;gap:.8rem;
 padding:.7rem 1.1rem;background:var(--surface);border-bottom:1px solid var(--outline);
 box-shadow:var(--shadow)}
.appbar::before{content:"";position:absolute;left:0;right:0;top:0;height:3px;
 background:linear-gradient(90deg,var(--primary),#7b84ff 55%,#38bdf8)}
.logo{width:2.4rem;height:2.4rem;border-radius:.75rem;color:#fff;font-size:1.3rem;
 background:linear-gradient(135deg,var(--primary),#7b84ff 70%,#38bdf8);
 display:grid;place-items:center;font-weight:700;box-shadow:0 2px 8px rgba(75,86,210,.35)}
.appbar h1{font-size:1.12rem;margin:0;font-weight:700;letter-spacing:.01em;display:flex;align-items:baseline;gap:.4rem}
.appbar h1 .by{font-size:.62rem;font-weight:600;color:var(--onv);letter-spacing:.02em}
.appbar .sub{font-size:.72rem;color:var(--onv)}
footer.brand{max-width:64rem;margin:.5rem auto 2.2rem;padding:1.4rem 1.1rem .4rem;text-align:center;
 color:var(--onv);font-size:.8rem;line-height:1.7;border-top:1px solid var(--outline)}
footer.brand .name{font-weight:700;font-size:.95rem;color:var(--on);letter-spacing:.02em}
footer.brand .made .heart{color:#e0245e}
footer.brand .copy b{color:var(--on)}
footer.brand a{color:var(--primary);text-decoration:none;font-weight:600}
footer.brand a:hover{text-decoration:underline}
footer.brand .links{margin-top:.15rem;font-size:.76rem}
.spacer{flex:1}
.btn{border:none;border-radius:2rem;padding:.55rem 1.1rem;font-weight:600;font-size:.85rem;
 cursor:pointer;background:var(--surface2);color:var(--on)}
.btn.primary{background:var(--primary);color:var(--primaryc)}
.btn:disabled{opacity:.5;cursor:default}
.wrap{max-width:64rem;margin:0 auto;padding:1.1rem}
.tabs{display:flex;gap:.4rem;margin:.2rem 0 1rem;flex-wrap:wrap}
.tab{padding:.45rem 1rem;border-radius:2rem;cursor:pointer;font-size:.85rem;font-weight:600;
 color:var(--onv);background:transparent}
.tab.active{background:var(--primary);color:var(--primaryc)}
.card{background:var(--surface);border:1px solid var(--outline);border-radius:var(--r);
 box-shadow:var(--shadow);padding:1.1rem 1.3rem;margin:.9rem 0}
.hero{display:flex;gap:1.4rem;align-items:center;flex-wrap:wrap}
.ring{--v:0;width:7rem;height:7rem;border-radius:50%;flex:0 0 auto;
 background:conic-gradient(var(--rc,var(--ok)) calc(var(--v)*1%),var(--surface2) 0);display:grid;place-items:center}
.ring>div{width:5.4rem;height:5.4rem;border-radius:50%;background:var(--surface);display:grid;place-items:center;text-align:center}
.ring b{font-size:1.6rem}.ring span{font-size:.65rem;color:var(--onv)}
.chips{display:flex;gap:.5rem;flex-wrap:wrap;margin-top:.4rem}
.chip{display:inline-flex;gap:.35rem;align-items:center;padding:.3rem .7rem;border-radius:2rem;font-size:.8rem;font-weight:600}
.chip.pass{background:var(--okc);color:var(--ok)}.chip.fail{background:var(--errc);color:var(--err)}
.chip.warn{background:var(--warnc);color:var(--warn)}.chip.skip{background:var(--skipc);color:var(--skip)}
.alert{display:flex;gap:.7rem;background:var(--errc);color:var(--err);border-radius:var(--r);padding:.9rem 1.1rem;margin:.9rem 0;font-size:.9rem}
.sect{margin:1.4rem 0 .4rem;font-size:.95rem;font-weight:600}
.sect small{color:var(--onv);font-weight:400}
.row{display:flex;align-items:flex-start;gap:.8rem;padding:.7rem .3rem;border-bottom:1px solid var(--outline)}
.row:last-child{border-bottom:none}
.badge{min-width:3rem;text-align:center;padding:.15rem .45rem;border-radius:.5rem;font-size:.68rem;font-weight:700}
.badge.PASS{background:var(--okc);color:var(--ok)}.badge.FAIL{background:var(--errc);color:var(--err)}
.badge.WARN{background:var(--warnc);color:var(--warn)}.badge.SKIP{background:var(--skipc);color:var(--skip)}
.rowmain{flex:1;min-width:0}
.rowtitle{font-size:.9rem}.cid{font-family:ui-monospace,monospace;font-size:.78rem;color:var(--onv)}
.rowdetail{font-size:.8rem;color:var(--onv);margin-top:.2rem;white-space:pre-wrap}
.meta{font-size:.68rem;color:var(--onv);margin-top:.15rem}
/* Material switch */
.sw{position:relative;width:2.6rem;height:1.5rem;flex:0 0 auto}
.sw input{opacity:0;width:0;height:0}
.sw .track{position:absolute;inset:0;background:var(--skip);border-radius:1rem;transition:.2s;cursor:pointer}
.sw .thumb{position:absolute;top:.15rem;left:.15rem;width:1.2rem;height:1.2rem;background:#fff;border-radius:50%;transition:.2s;box-shadow:var(--shadow)}
.sw input:checked+.track{background:var(--ok)}
.sw input:checked+.track .thumb{transform:translateX(1.1rem)}
.sw input:disabled+.track{opacity:.6;cursor:default}
.empty{color:var(--onv);text-align:center;padding:2rem;font-size:.9rem}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.5);display:none;place-items:center;z-index:10;padding:1rem}
.modal.open{display:grid}
.sheet{background:var(--surface);border-radius:var(--r);max-width:42rem;width:100%;max-height:85vh;overflow:auto;padding:1.3rem}
.sheet h3{margin:.2rem 0 .8rem}
.sheet pre{white-space:pre-wrap;font-size:.8rem;background:var(--surface2);padding:.8rem;border-radius:.6rem;color:var(--on)}
.sheet .actions{display:flex;gap:.6rem;justify-content:flex-end;margin-top:1rem}
.toast{position:fixed;bottom:1.2rem;left:50%;transform:translateX(-50%);background:var(--on);color:var(--bg);
 padding:.7rem 1.2rem;border-radius:2rem;font-size:.85rem;box-shadow:var(--shadow);opacity:0;transition:.3s;z-index:20}
.toast.show{opacity:1}
.snaprow{display:flex;align-items:center;gap:.8rem;padding:.6rem .3rem;border-bottom:1px solid var(--outline);font-size:.85rem}
.mono{font-family:ui-monospace,monospace}
.note{background:var(--warnc);color:var(--warn);border-radius:var(--r);padding:.8rem 1.1rem;font-size:.85rem;margin:.6rem 0}
.spin{width:1rem;height:1rem;border:2px solid var(--outline);border-top-color:var(--primary);border-radius:50%;display:inline-block;animation:sp .7s linear infinite;vertical-align:middle}
@keyframes sp{to{transform:rotate(360deg)}}
.pwrap{display:none;margin:.4rem 0 .2rem}
.pwrap.on{display:block}
.pbar{height:.4rem;border-radius:.3rem;background:var(--surface2);overflow:hidden}
.pbar>div{height:100%;width:0%;border-radius:.3rem;background:var(--primary);transition:width .25s}
.ptext{font-size:.75rem;color:var(--onv);margin-top:.25rem}
.console{position:fixed;left:0;right:0;bottom:2.4rem;background:var(--surface);
 border-top:1px solid var(--outline);box-shadow:0 -2px 10px rgba(0,0,0,.12);display:none;z-index:5}
.console.open{display:block}
.console .out{height:11rem;overflow:auto;font-family:ui-monospace,monospace;font-size:.78rem;
 white-space:pre-wrap;padding:.6rem .9rem;color:var(--on)}
.console .inrow{display:flex;gap:.5rem;border-top:1px solid var(--outline);padding:.45rem .9rem}
.console .inrow span{font-family:ui-monospace,monospace;color:var(--onv);align-self:center}
.console input{flex:1;background:var(--surface2);border:1px solid var(--outline);border-radius:.5rem;
 color:var(--on);font-family:ui-monospace,monospace;font-size:.82rem;padding:.4rem .6rem;outline:none}
.statusbar{position:fixed;left:0;right:0;bottom:0;height:2.4rem;background:var(--surface);
 border-top:1px solid var(--outline);display:flex;align-items:center;gap:1rem;
 padding:0 1rem;font-size:.75rem;color:var(--onv);z-index:6}
.statusbar b{color:var(--on)}
.statusbar .sp{flex:1}
.statusbar button{background:none;border:1px solid var(--outline);border-radius:.5rem;
 color:var(--primary);font-weight:700;font-size:.72rem;padding:.2rem .7rem;cursor:pointer}
body{padding-bottom:3rem}
.fleethosts{width:100%;min-height:9rem;background:var(--surface2);border:1px solid var(--outline);
 border-radius:.6rem;color:var(--on);font-family:ui-monospace,monospace;font-size:.85rem;padding:.6rem}
.fld{flex:1;min-width:14rem;background:var(--surface2);border:1px solid var(--outline);
 border-radius:.5rem;color:var(--on);padding:.45rem .6rem;font-size:.85rem}
</style></head><body>
<div class="appbar">
  <div class="logo" aria-hidden="true">A</div>
  <div><h1>AuditXS <span class="by">by DigitalXS</span></h1><div class="sub" id="hostmeta">loading…</div></div>
  <div class="spacer"></div>
  <button class="btn" id="reportBtn">Open report</button>
  <button class="btn primary" id="auditBtn">Run audit</button>
</div>
<div class="wrap">
  <div class="tabs">
    <div class="tab active" data-tab="dashboard">Dashboard</div>
    <div class="tab" data-tab="features">Features</div>
    <div class="tab" data-tab="snapshots">Snapshots</div>
    <div class="tab" data-tab="tools">Tools</div>
    <div class="tab" data-tab="fleet">Fleet</div>
  </div>
  <div class="pwrap" id="pwrap">
    <div class="pbar"><div id="pfill"></div></div>
    <div class="ptext" id="ptext">0%</div>
  </div>
  <div id="cveHolder"></div>
  <div id="view"></div>
</div>
<footer class="brand">
  <div class="name">🛡️ AuditXS</div>
  <div class="made">Made with <span class="heart">❤</span> from Canada 🍁</div>
  <div class="copy">© 2026 <b>DigitalXS</b> — Programming &amp; Development</div>
  <div class="links"><a href="https://digitalxs.ca" target="_blank" rel="noopener noreferrer">digitalxs.ca</a> · <a href="https://github.com/digitalxs/AuditXS" target="_blank" rel="noopener noreferrer">github.com/digitalxs/AuditXS</a></div>
</footer>

<div class="console" id="console">
  <div class="out" id="conOut">AuditXS console — runs auditxs subcommands only (argv, never a shell).
Try:  cve   ·   waivers   ·   errors AX6002   ·   schedule status   ·   list --framework cis</div>
  <div class="inrow"><span>auditxs&nbsp;$</span><input id="conIn" placeholder="type an auditxs command and press Enter (e.g. cve)" autocomplete="off"></div>
</div>
<div class="statusbar">
  <span>🛡️ <b>AuditXS</b> <span id="sbVer"></span></span>
  <span id="sbState"></span>
  <span class="sp"></span>
  <span>Made with ❤ from Canada 🍁 · © 2026 <b>DigitalXS</b></span>
  <button id="conToggle">Console ▴</button>
</div>
<div class="modal" id="modal"><div class="sheet">
  <h3 id="mTitle">Review</h3><div id="mBody"></div>
  <div class="actions">
    <button class="btn" id="mCancel">Cancel</button>
    <button class="btn primary" id="mConfirm">Apply</button>
  </div>
</div></div>
<div class="toast" id="toast"></div>
<script>
const TOKEN="__TOKEN__";
const H={"X-Auth-Token":TOKEN};
let RESULTS=[], SUMMARY={}, META={};
const $=s=>document.querySelector(s);
function toast(m){const t=$("#toast");t.textContent=m;t.classList.add("show");setTimeout(()=>t.classList.remove("show"),2600);}
async function api(path,opts){opts=opts||{};opts.headers=Object.assign({},H,opts.headers||{});
 const r=await fetch(path,opts);if(!r.ok)throw new Error(await r.text());return r.json();}
function ringColor(s){return s>=75?"var(--ok)":s>=50?"var(--warn)":"var(--err)";}

async function loadMeta(){META=await api("/api/meta");
 $("#hostmeta").textContent=`${META.host} · ${META.distro} · profile ${META.profile} · v${META.version}`;}

let PTIMER=null;
function progressStart(){
 $("#pwrap").classList.add("on");$("#pfill").style.width="0%";$("#ptext").textContent="0%";
 PTIMER=setInterval(async()=>{try{
  const p=await api("/api/progress");
  $("#pfill").style.width=(p.pct||0)+"%";
  $("#ptext").textContent=(p.pct||0)+"%"+(p.total?` — ${p.done}/${p.total}`:"")+(p.id&&p.id!=="done"?` · ${p.id}`:"");
 }catch(e){}},400);
}
function progressStop(){
 if(PTIMER){clearInterval(PTIMER);PTIMER=null;}
 $("#pfill").style.width="100%";$("#ptext").textContent="100%";
 setTimeout(()=>$("#pwrap").classList.remove("on"),600);
}
async function runAudit(){
 $("#auditBtn").innerHTML='<span class="spin"></span>';
 progressStart();
 try{const d=await api("/api/audit");RESULTS=d.results;SUMMARY=d.summary;await loadCve();render();toast("Audit complete");}
 catch(e){toast("Audit failed: "+e.message);}
 progressStop();
 $("#auditBtn").textContent="Run audit";
}
async function loadCve(){try{const c=await api("/api/cve");const h=$("#cveHolder");
 if(c.count && c.count!=="0" && c.count!=="?"){h.innerHTML=`<div class="alert"><span>⚠</span><div><b>Vulnerability warning:</b> ${c.count} installed package(s) have a reported security issue with a fix available (source: ${c.source}). Apply security updates promptly.</div></div>`;}
 else h.innerHTML="";}catch(e){}}

let TAB="dashboard";
document.querySelectorAll(".tab").forEach(t=>t.onclick=()=>{
 document.querySelectorAll(".tab").forEach(x=>x.classList.remove("active"));
 t.classList.add("active");TAB=t.dataset.tab;render();});

function render(){
 if(TAB==="dashboard")renderDash();
 else if(TAB==="features")renderFeatures();
 else if(TAB==="snapshots")renderSnaps();
 else if(TAB==="tools")renderTools();
 else if(TAB==="fleet")renderFleet();
}
function groupByCat(list){const g={};list.forEach(r=>{(g[r.category]=g[r.category]||[]).push(r);});return g;}

function renderDash(){
 if(!RESULTS.length){$("#view").innerHTML='<div class="empty">Press <b>Run audit</b> to scan this system (read-only).</div>';return;}
 const s=SUMMARY,score=s.score==="-"?0:parseInt(s.score);
 let h=`<div class="card hero"><div class="ring" style="--v:${score};--rc:${ringColor(score)}"><div><div><b>${s.score}</b><br><span>/ 100</span></div></div></div>
 <div style="flex:1 1 14rem"><div style="font-weight:600;margin-bottom:.3rem">Hardening score</div>
 <div class="chips"><span class="chip pass">● ${s.pass} passed</span><span class="chip fail">● ${s.fail} failed</span>
 <span class="chip warn">● ${s.warn} warnings</span><span class="chip skip">● ${s.skip} skipped</span></div></div></div>`;
 const g=groupByCat(RESULTS);
 for(const cat in g){h+=`<div class="sect">${cat} <small>— ${g[cat][0].domain} domain</small></div><div class="card">`;
  g[cat].forEach(r=>{const fixBtn=(r.status==="FAIL"||r.status==="WARN")
   ?`<button class="btn ${r.status==="FAIL"&&r.fixable?"primary":""}" style="align-self:center;white-space:nowrap"
      onclick="onFix('${r.id}',${r.status==="FAIL"&&r.fixable})">${r.status==="FAIL"&&r.fixable?"Fix it":"How to fix"}</button>`:"";
   h+=`<div class="row"><span class="badge ${r.status}">${r.status}</span><div class="rowmain">
   <div class="rowtitle"><span class="cid">${r.id}</span> ${esc(r.title)}</div>
   ${r.detail?`<div class="rowdetail">${esc(r.detail)}</div>`:""}
   <div class="meta">${r.severity} · Level ${r.level}${r.cis?" · CIS "+r.cis:""}${r.nist?" · "+r.nist:""}</div></div>${fixBtn}</div>`;});
  h+="</div>";}
 $("#view").innerHTML=h;
}
function renderFeatures(){
 if(!RESULTS.length){$("#view").innerHTML='<div class="empty">Run an audit first.</div>';return;}
 const fixable=RESULTS.filter(r=>r.fixable);
 let h=`<div class="note">Each switch is a security control. Turning one <b>on</b> applies its fix (you review it first) and is fully reversible via Snapshots. Controls already on are locked here; turn them off from the Snapshots tab.</div>`;
 const g=groupByCat(fixable);
 for(const cat in g){h+=`<div class="sect">${cat} <small>— ${g[cat][0].domain} domain</small></div><div class="card">`;
  g[cat].forEach(r=>{const on=r.status==="PASS";
   h+=`<div class="row"><div class="rowmain"><div class="rowtitle"><span class="cid">${r.id}</span> ${esc(r.title)}</div>
    <div class="meta">${r.severity} · Level ${r.level}${r.cis?" · CIS "+r.cis:""}</div></div>
    <label class="sw"><input type="checkbox" ${on?"checked disabled":""} data-id="${r.id}" onchange="onToggle(this)">
    <span class="track"><span class="thumb"></span></span></label></div>`;});
  h+="</div>";}
 $("#view").innerHTML=h;
}
let PENDING=null;
async function onToggle(el){
 const id=el.dataset.id;el.checked=false; // don't flip until confirmed
 try{const ex=await api("/api/explain?id="+encodeURIComponent(id));
  PENDING=id;$("#mTitle").textContent="Turn on "+id+"?";
  $("#mBody").innerHTML=`<p>Review exactly what this will change. It is recorded in a snapshot and reversible.</p><pre>${esc(ex.text)}</pre>`;
  $("#mConfirm").style.display="";
  $("#modal").classList.add("open");}catch(e){toast("Could not load details");}
}
// Fix it (reversible, consented) / How to fix (detailed manual guidance).
async function onFix(id,canApply){
 try{const ex=await api("/api/explain?id="+encodeURIComponent(id));
  if(canApply){
   PENDING=id;$("#mTitle").textContent="Fix "+id+"? (reversible — snapshotted)";
   $("#mBody").innerHTML=`<p>Review exactly what this fix will change before applying it.</p><pre>${esc(ex.text)}</pre>`;
   $("#mConfirm").style.display="";
  }else{
   PENDING=null;$("#mTitle").textContent="How to fix "+id+" (manual)";
   $("#mBody").innerHTML=`<pre>${esc(ex.text)}</pre>
    <div class="note"><b>Manual fix</b> — this finding has no automatic fix. The "fix" section above
    describes exactly what to change; make the change (the Console below runs auditxs commands,
    e.g. <span class="mono">explain ${esc(id)}</span>), then run the audit again to verify.</div>`;
   $("#mConfirm").style.display="none";
  }
  $("#modal").classList.add("open");}catch(e){toast("Could not load details");}
}
$("#mCancel").onclick=()=>{$("#modal").classList.remove("open");PENDING=null;};
$("#mConfirm").onclick=async()=>{if(!PENDING)return;$("#mConfirm").innerHTML='<span class="spin"></span>';
 try{await api("/api/harden",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({checks:[PENDING]})});
  toast("Applied "+PENDING);$("#modal").classList.remove("open");await runAudit();}
 catch(e){toast("Failed: "+e.message);}$("#mConfirm").textContent="Apply";PENDING=null;};

async function renderSnaps(){
 $("#view").innerHTML='<div class="empty"><span class="spin"></span> loading…</div>';
 try{const d=await api("/api/snapshots");
  if(!d.snapshots.length){$("#view").innerHTML='<div class="empty">No snapshots yet. They are created when you turn on a control.</div>';return;}
  let h='<div class="card">';
  d.snapshots.forEach(s=>{h+=`<div class="snaprow"><span class="mono">${s.id}</span><span style="flex:1">${s.date} · ${s.actions} action(s) · ${s.status}</span>
   ${s.status==="applied"?`<button class="btn" onclick="rollback('${s.id}')">Roll back</button>`:'<span class="chip skip">rolled back</span>'}</div>`;});
  $("#view").innerHTML=h+"</div>";}catch(e){$("#view").innerHTML='<div class="empty">Failed to load snapshots.</div>';}
}
async function rollback(id){if(!confirm("Revert every change recorded in snapshot "+id+"?"))return;
 try{await api("/api/rollback",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id})});
  toast("Rolled back "+id);renderSnaps();}catch(e){toast("Rollback failed: "+e.message);}}

async function renderTools(){
 $("#view").innerHTML='<div class="empty"><span class="spin"></span> loading…</div>';
 try{const d=await api("/api/tools");let h='<div class="card"><div class="sect" style="margin-top:0">Security tooling</div>';
  d.tools.forEach(t=>{h+=`<div class="snaprow"><span style="flex:1">${t.name}</span>
   <span class="chip ${t.installed?"pass":"skip"}">${t.installed?"installed":"not installed"}</span></div>`;});
  h+=`</div><div class="note">Install and run scanners from the command line: <span class="mono">sudo auditxs tools install lynis</span> · <span class="mono">sudo auditxs tools scan</span>. VPN review: <span class="mono">auditxs tools vpn</span>.</div>`;
  $("#view").innerHTML=h;}catch(e){$("#view").innerHTML='<div class="empty">Failed to load tools.</div>';}
}
async function renderFleet(){
 $("#view").innerHTML='<div class="empty"><span class="spin"></span> loading…</div>';
 let hosts="";try{const d=await api("/api/fleet/hosts");hosts=d.hosts||"";}catch(e){}
 $("#view").innerHTML=`<div class="card">
  <div class="sect" style="margin-top:0">Fleet — audit remote hosts over SSH (read-only)</div>
  <div class="note">Fleet mode never hardens over SSH; every host needs AuditXS installed.
   One <span class="mono">user@host</span> per line, <span class="mono">#</span> comments allowed.
   Key authentication uses the server's own SSH keys.</div>
  <textarea class="fleethosts" id="fleetHosts" placeholder="admin@web01\nadmin@db01   # database">${esc(hosts)}</textarea>
  <div class="sect" style="font-size:.8rem">Login</div>
  <div style="display:flex;gap:.6rem;flex-wrap:wrap;align-items:center">
   <input id="fleetKey" class="mono fld" placeholder="SSH key path (leave empty to use a password →)">
   <input id="fleetPass" type="password" class="mono fld" placeholder="SSH login password (optional)" autocomplete="off">
  </div>
  <div class="sect" style="font-size:.8rem">Privilege on the host</div>
  <div style="display:flex;gap:.6rem;flex-wrap:wrap;align-items:center">
   <input id="fleetSudoPass" type="password" class="mono fld" placeholder="sudo password (for interactive sudo)" autocomplete="off">
   <label style="font-size:.85rem"><input type="checkbox" id="fleetSudo" checked> use sudo (uncheck only if already root)</label>
  </div>
  <div class="note" style="font-size:.78rem">Passwords are used only for this run — never saved. Leave the sudo password empty if the host has passwordless sudo (<span class="mono">NOPASSWD</span>).</div>
  <div style="display:flex;gap:.6rem;margin-top:.7rem;flex-wrap:wrap;align-items:center">
   <button class="btn" id="fleetSave">Save hosts</button>
   <button class="btn primary" id="fleetRun">Audit fleet</button>
   <a class="btn" id="fleetOverview" style="display:none" target="_blank" rel="noopener">Open overview</a>
  </div>
  <pre id="fleetOut" style="display:none;white-space:pre-wrap;font-size:.78rem;background:var(--surface2);padding:.8rem;border-radius:.6rem;margin-top:.8rem;max-height:20rem;overflow:auto"></pre>
 </div>`;
 $("#fleetSave").onclick=async()=>{try{await api("/api/fleet/hosts",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({hosts:$("#fleetHosts").value})});toast("Fleet hosts saved");}catch(e){toast("Save failed: "+e.message);}};
 $("#fleetRun").onclick=async()=>{
  try{await api("/api/fleet/hosts",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({hosts:$("#fleetHosts").value})});}catch(e){}
  $("#fleetRun").innerHTML='<span class="spin"></span>';progressStart();
  try{const d=await api("/api/fleet/run",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({key:$("#fleetKey").value.trim(),sudo:$("#fleetSudo").checked,ssh_pass:$("#fleetPass").value,sudo_pass:$("#fleetSudoPass").value})});
   const o=$("#fleetOut");o.style.display="block";o.textContent=d.output||"(no output)";
   if(d.overview){const a=$("#fleetOverview");a.style.display="";a.href="/api/fleet/overview?t="+encodeURIComponent(TOKEN);}
   toast(d.rc===0?"Fleet audit complete — all clean":"Fleet audit finished (rc "+d.rc+") — see output");}
  catch(e){toast("Fleet audit failed: "+e.message);}
  progressStop();$("#fleetRun").textContent="Audit fleet";};
}
function esc(s){const d=document.createElement("div");d.textContent=s||"";return d.innerHTML;}
$("#auditBtn").onclick=runAudit;
$("#reportBtn").onclick=()=>window.open("/api/report?t="+encodeURIComponent(TOKEN),"_blank");
// ---- console (auditxs subcommands only; argv, never a shell) ----
$("#conToggle").onclick=()=>{const c=$("#console");c.classList.toggle("open");
 $("#conToggle").textContent=c.classList.contains("open")?"Console ▾":"Console ▴";
 if(c.classList.contains("open"))$("#conIn").focus();};
$("#conIn").addEventListener("keydown",async ev=>{
 if(ev.key!=="Enter")return;
 const line=$("#conIn").value.trim();if(!line)return;
 $("#conIn").value="";
 const out=$("#conOut");out.textContent+=`\n\nauditxs $ ${line}\n…`;out.scrollTop=out.scrollHeight;
 const args=line.replace(/^auditxs\s+/,"").split(/\s+/);
 progressStart();
 try{const d=await api("/api/cli",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({args})});
  out.textContent=out.textContent.slice(0,-1)+(d.output||d.error||"(no output)")+(d.rc?`\n[exit ${d.rc}]`:"");}
 catch(e){out.textContent=out.textContent.slice(0,-1)+"error: "+e.message;}
 progressStop();out.scrollTop=out.scrollHeight;});
loadMeta().then(()=>{ $("#sbVer").textContent="v"+(META.version||"?")+" · "+(META.profile||"");return runAudit();});
</script></body></html>"""


# --------------------------------------------------------------- handler
class Handler(BaseHTTPRequestHandler):
    server_version = "AuditXS"

    def log_message(self, *a):  # quiet
        pass

    def _authed(self, qs):
        supplied = self.headers.get("X-Auth-Token") or (qs.get("t", [""])[0])
        return secrets.compare_digest(supplied or "", TOKEN)

    def _same_origin(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        return host in ("127.0.0.1", "localhost")

    def _send(self, code, body, ctype="application/json"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj), "application/json")

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        if not self._same_origin():
            return self._send(400, "bad host", "text/plain")
        if u.path == "/":
            if not self._authed(qs):
                return self._send(403, "Missing or invalid token. Launch with the URL printed by 'auditxs web'.", "text/plain")
            return self._send(200, PAGE.replace("__TOKEN__", TOKEN), "text/html; charset=utf-8")
        if not self._authed(qs):
            return self._json({"error": "unauthorized"}, 403)
        if u.path == "/api/meta":
            return self._json(self._meta())
        if u.path == "/api/audit":
            return self._json(self._audit())
        if u.path == "/api/progress":
            return self._json(read_progress())
        if u.path == "/api/explain":
            cid = qs.get("id", [""])[0]
            if not cid.replace("-", "").isalnum():
                return self._json({"error": "bad id"}, 400)
            rc, out, _ = run_auditxs(["explain", cid])
            return self._json({"text": strip_ansi(out)})
        if u.path == "/api/snapshots":
            return self._json({"snapshots": self._snapshots()})
        if u.path == "/api/cve":
            return self._json(self._cve())
        if u.path == "/api/tools":
            return self._json(self._tools())
        if u.path == "/api/report":
            rc, out, _ = run_auditxs(["report", "--format", "html"] + profile_args() + ["--quiet"])
            return self._send(200, out, "text/html; charset=utf-8")
        if u.path == "/api/fleet/hosts":
            try:
                with open(FLEET_HOSTS_PATH) as f:
                    text = f.read()
            except OSError:
                text = ""
            return self._json({"hosts": text})
        if u.path == "/api/fleet/overview":
            p = os.path.join(FLEET_LAST_DIR["path"], "index.html") if FLEET_LAST_DIR["path"] else ""
            if not (p and os.path.exists(p)):
                return self._send(404, "no fleet overview yet — run a fleet audit first", "text/plain")
            with open(p) as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        u = urlparse(self.path)
        if not self._same_origin():
            return self._send(400, "bad host", "text/plain")
        # CSRF: state-changing calls require the token in a header, not a query.
        if not secrets.compare_digest(self.headers.get("X-Auth-Token", ""), TOKEN):
            return self._json({"error": "unauthorized"}, 403)
        length = int(self.headers.get("Content-Length", 0) or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self._json({"error": "bad json"}, 400)
        if u.path == "/api/harden":
            checks = body.get("checks", [])
            if not checks or not all(isinstance(c, str) and c.replace("-", "").isalnum() for c in checks):
                return self._json({"error": "bad checks"}, 400)
            args = ["harden", "--yes", "--quiet"] + profile_args()
            for c in checks:
                args += ["--check", c]
            rc, out, err = run_auditxs(args, timeout=300)
            return self._json({"rc": rc, "log": strip_ansi(out + err)})
        if u.path == "/api/rollback":
            sid = body.get("id", "")
            if not sid.replace("-", "").isalnum():
                return self._json({"error": "bad id"}, 400)
            rc, out, err = run_auditxs(["rollback", sid, "--yes"], timeout=300)
            return self._json({"rc": rc, "log": strip_ansi(out + err)})
        if u.path == "/api/cli":
            args = body.get("args", [])
            if (not isinstance(args, list) or not args
                    or not all(isinstance(a, str) and a and OP_ARG.fullmatch(a) for a in args)
                    or args[0] not in OP_CMDS):
                return self._json({"error": "only auditxs subcommands are allowed here"}, 400)
            try:
                open(PROGRESS_PATH, "w").close()
            except OSError:
                pass
            rc, out, err = run_auditxs(args + ["--progress-file", PROGRESS_PATH],
                                       timeout=1800)
            return self._json({"rc": rc, "output": strip_ansi(out + ("\n" + err if err else ""))})
        if u.path == "/api/fleet/hosts":
            text = body.get("hosts", "")
            if not isinstance(text, str) or len(text) > 20000:
                return self._json({"error": "bad hosts"}, 400)
            lines = []
            for ln in text.splitlines():
                ln = ln.strip()
                if ln and (ln.startswith("#") or OP_ARG.fullmatch(ln)):
                    lines.append(ln)
            try:
                with open(FLEET_HOSTS_PATH, "w") as f:
                    f.write("\n".join(lines) + "\n")
                os.chmod(FLEET_HOSTS_PATH, 0o600)
            except OSError as e:
                return self._json({"error": str(e)}, 500)
            return self._json({"ok": True, "hosts": "\n".join(lines)})
        if u.path == "/api/fleet/run":
            key = body.get("key", "")
            sudo = bool(body.get("sudo", True))
            ssh_pass = body.get("ssh_pass", "")     # SSH login password (optional)
            sudo_pass = body.get("sudo_pass", "")   # remote sudo password (optional)
            if key and not OP_ARG.fullmatch(key):
                return self._json({"error": "bad key path"}, 400)
            if not os.path.exists(FLEET_HOSTS_PATH):
                return self._json({"error": "no hosts saved yet"}, 400)
            try:
                open(PROGRESS_PATH, "w").close()
            except OSError:
                pass
            outdir = "/var/lib/auditxs/reports/fleet/web-%d" % int(time.time())
            args = ["fleet", "--inventory", FLEET_HOSTS_PATH, "--output", outdir,
                    "--progress-file", PROGRESS_PATH]
            if key:
                args += ["--key", key]
            # Credentials go through the environment (never the command line).
            env_extra = {}
            if ssh_pass:
                args += ["--ask-pass"]
                env_extra["AUDITXS_SSH_PASS"] = ssh_pass
            if sudo_pass:
                args += ["--ask-sudo-pass"]
                env_extra["AUDITXS_SUDO_PASS"] = sudo_pass
            elif sudo:
                args += ["--sudo"]
            rc, out, err = run_auditxs(args, timeout=1800, env_extra=env_extra or None)
            FLEET_LAST_DIR["path"] = outdir
            return self._json({"rc": rc, "output": strip_ansi(out + ("\n" + err if err else "")),
                               "overview": os.path.exists(os.path.join(outdir, "index.html"))})
        return self._json({"error": "not found"}, 404)

    # ---- data helpers ----
    def _meta(self):
        import socket
        return {"version": VERSION, "host": socket.gethostname(),
                "distro": _osname(), "profile": PROFILE or "(configured)"}

    def _audit(self):
        try:
            open(PROGRESS_PATH, "w").close()
        except OSError:
            pass
        rc, out, err = run_auditxs(["audit", "--format", "json", "--quiet",
                                    "--progress-file", PROGRESS_PATH] + profile_args(), timeout=240)
        try:
            return json.loads(out)
        except ValueError:
            return {"results": [], "summary": {"pass": 0, "fail": 0, "warn": 0, "skip": 0, "score": "-"},
                    "error": strip_ansi(err)[:400]}

    def _snapshots(self):
        rc, out, _ = run_auditxs(["snapshots", "--format", "tsv"])
        snaps = []
        for line in out.splitlines():
            f = line.split("\t")
            if len(f) >= 5:
                snaps.append({"id": f[0], "date": f[1], "profile": f[2], "actions": f[3], "status": f[4]})
        return snaps

    def _cve(self):
        rc, out, _ = run_auditxs(["cve"], timeout=180)
        txt = strip_ansi(out)
        import re
        m = re.search(r"(\d+) package\(s\) have a reported vulnerability", txt)
        src = re.search(r"source: ([\w-]+)", txt)
        if m:
            return {"count": m.group(1), "source": src.group(1) if src else "?"}
        return {"count": "0", "source": ""}

    def _tools(self):
        rc, out, _ = run_auditxs(["tools", "status"])
        txt = strip_ansi(out)
        known = {"lynis", "rkhunter", "chkrootkit", "tiger", "checksecurity",
                 "lsat", "aide", "debsecan", "fail2ban", "crowdsec", "suricata"}
        tools = []
        for line in txt.splitlines():
            parts = line.strip().lstrip("│").strip().split()
            if len(parts) >= 2 and parts[0] in known:
                installed = parts[-1] == "installed" and "not" not in parts
                tools.append({"name": parts[0], "installed": installed})
        return {"tools": tools}


def _osname():
    try:
        with open("/etc/os-release") as f:
            for ln in f:
                if ln.startswith("PRETTY_NAME="):
                    return ln.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return "Linux"


# ------------------------------------------------------------------- main
def main():
    global VERSION
    port = 9000
    do_open = True
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--port" and i + 1 < len(args):
            port = int(args[i + 1]); i += 2; continue
        if args[i] == "--no-open":
            do_open = False; i += 1; continue
        i += 1

    rc, out, _ = run_auditxs(["version"])
    VERSION = (out.strip().split()[-1].lstrip("v") if out.strip() else "?")

    # SECURITY: loopback only, always.
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}/?t={TOKEN}"
    line = "─" * 66
    print(f"\n\033[36m╭─\033[0m \033[1mAuditXS web UI\033[0m \033[36m{line[:48]}╮\033[0m")
    print(f"\033[36m│\033[0m  Open: \033[1m{url}\033[0m")
    print(f"\033[36m│\033[0m  Bound to 127.0.0.1 only. Remote server? Tunnel first:")
    print(f"\033[36m│\033[0m    ssh -L {port}:127.0.0.1:{port} user@host")
    print(f"\033[36m│\033[0m  Stop with Ctrl-C.")
    print(f"\033[36m╰{line}╯\033[0m\n")
    sys.stdout.flush()   # ensure the URL/token is visible immediately, even when
                         # stdout is redirected to a file/pipe (block-buffered)

    if do_open:
        # Open as the invoking desktop user when launched via sudo.
        try:
            sudo_user = os.environ.get("SUDO_USER")
            if sudo_user and os.geteuid() == 0:
                subprocess.Popen(["runuser", "-u", sudo_user, "--", "xdg-open", url],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                threading.Thread(target=lambda: (time.sleep(.5), webbrowser.open(url)), daemon=True).start()
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nAuditXS web UI stopped.")
        httpd.shutdown()


if __name__ == "__main__":
    main()
