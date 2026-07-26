#!/usr/bin/env python3
"""AuditXS — scripts/build-site.py

Build the static documentation website: one branded, self-contained HTML page
per Markdown document into docs/, a docs/index.html hub, and the project
landing page (index.html) in the repository root. Python standard library
only — no Markdown package, no external assets, publishable as-is at
https://auditxs.digitalxs.ca/ (landing) and /docs (documentation).

Usage:  python3 scripts/build-site.py
"""

import html
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION = (ROOT / "VERSION").read_text().strip()

# page definitions: (source md, output html name, nav title, hub description)
PAGES = [
    ("docs/USAGE.md", "usage.html", "User manual",
     "Installing, auditing, hardening, rollback, baselines, fleet mode and every command."),
    ("docs/CHECKS.md", "checks.html", "Check catalogue",
     "Every check: what it inspects, why it matters, what the fix changes and how it reverts."),
    ("docs/ERRORS.md", "errors.html", "Error catalogue",
     "Every AXnnnn error number with a plain explanation and fix."),
    ("docs/ARCHITECTURE.md", "architecture.html", "Architecture",
     "The engine, the check API, the snapshot format and the fleet data flow."),
    ("docs/SECURITY-GUIDE.md", "security-guide.html", "Security guide",
     "Cybersecurity best practices that pair with AuditXS hardening."),
    ("docs/COMPLIANCE.md", "compliance.html", "Compliance",
     "CIS Benchmark, DISA STIG alignment and NIST CSF 2.0 mappings."),
    ("docs/WEBUI.md", "webui.html", "Web UI",
     "The Material Design web interface — local by default, or reachable on the network — its security model and usage."),
    ("docs/ROADMAP.md", "roadmap.html", "Roadmap",
     "What shipped in each release, what comes next, and deliberate non-goals."),
    ("CHANGELOG.md", "changelog.html", "Changelog",
     "Release notes for every AuditXS version."),
    ("digitalxs-dev-doc.MD", "dev-guide.html", "Developer guide",
     "Contributing: code map, check API, debugging, testing and releases."),
]

# .md link targets → generated pages (for rewriting cross-links)
MD_TO_HTML = {Path(src).name: out for src, out, _, _ in PAGES}

GITHUB = "https://github.com/digitalxs/AuditXS"

# ---------------------------------------------------------------- inline md

_CODE_TOKEN = "\x00CODE{}\x00"


def _slug(text):
    """GitHub-compatible heading slug (so the docs' own #anchors keep working):
    lowercase, drop punctuation, each space becomes a hyphen (not collapsed —
    'a & b' → 'a--b', matching GitHub's anchors)."""
    text = re.sub(r"[`*]", "", text)
    text = re.sub(r"[^\w\s-]", "", text.lower())
    return re.sub(r"\s", "-", text.strip()) or "section"


def _rewrite_href(href):
    """Point links at generated pages: FOO.md → foo.html (same directory)."""
    if href.startswith(("http://", "https://", "#", "mailto:")):
        return href
    path, _, frag = href.partition("#")
    name = Path(path).name
    if name in MD_TO_HTML:
        return MD_TO_HTML[name] + ("#" + frag if frag else "")
    if name.lower().endswith(".md"):
        # not part of the generated site (e.g. README.md) — view it on GitHub
        return "%s/blob/main/%s" % (GITHUB, path.lstrip("./"))
    return href


def inline(text):
    """Escape, then apply inline markdown (code, bold, italic, links)."""
    codes = []

    def stash(m):
        codes.append("<code>%s</code>" % html.escape(m.group(1)))
        return _CODE_TOKEN.format(len(codes) - 1)

    text = re.sub(r"`([^`]+)`", stash, text)
    text = html.escape(text, quote=False)
    text = re.sub(r"!\[([^\]]*)\]\(([^)\s]+)\)",
                  lambda m: '<img src="%s" alt="%s">' % (m.group(2), m.group(1)), text)
    text = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)",
                  lambda m: '<a href="%s">%s</a>' % (_rewrite_href(m.group(2)), m.group(1)),
                  text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"(?<![\w*])\*([^*\n]+)\*(?![\w*])", r"<em>\1</em>", text)
    for i, c in enumerate(codes):
        text = text.replace(_CODE_TOKEN.format(i), c)
    return text


# ---------------------------------------------------------------- block md

def md_to_html(md):
    """Convert the Markdown subset the AuditXS docs use to HTML.

    Handles: h1–h6 (anchored), paragraphs, fenced code, tables, ordered and
    unordered lists (one nesting level via indent), blockquotes and rules.
    Returns (body_html, [(level, slug, title), ...]).
    """
    out, toc = [], []
    lines = md.splitlines()
    i, n = 0, len(lines)
    para = []

    def flush_para():
        if para:
            out.append("<p>%s</p>" % inline(" ".join(para)))
            para.clear()

    while i < n:
        line = lines[i]

        # fenced code
        m = re.match(r"^```(\w*)\s*$", line)
        if m:
            flush_para()
            lang = m.group(1)
            block = []
            i += 1
            while i < n and not lines[i].startswith("```"):
                block.append(lines[i]); i += 1
            i += 1
            cls = ' class="lang-%s"' % lang if lang else ""
            out.append("<pre%s><code>%s</code></pre>" % (cls, html.escape("\n".join(block))))
            continue

        # heading
        m = re.match(r"^(#{1,6})\s+(.*)$", line)
        if m:
            flush_para()
            level = len(m.group(1)); title = m.group(2).strip()
            slug = _slug(title)
            seen = sum(1 for _, s, _ in toc if s == slug or s.startswith(slug + "-"))
            if seen:
                slug = "%s-%d" % (slug, seen)
            toc.append((level, slug, re.sub(r"[`*]", "", title)))
            out.append('<h%d id="%s">%s</h%d>' % (level, slug, inline(title), level))
            i += 1
            continue

        # horizontal rule
        if re.match(r"^(\s*)(-{3,}|\*{3,}|_{3,})\s*$", line):
            flush_para(); out.append("<hr>"); i += 1
            continue

        # table
        if line.startswith("|") and i + 1 < n and re.match(r"^\|[\s:|-]+\|?\s*$", lines[i + 1]):
            flush_para()
            rows = []
            while i < n and lines[i].startswith("|"):
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                rows.append(cells); i += 1
            head, body = rows[0], rows[2:]
            t = ['<div class="tablewrap"><table>']
            t.append("<tr>%s</tr>" % "".join("<th>%s</th>" % inline(c) for c in head))
            for r in body:
                t.append("<tr>%s</tr>" % "".join("<td>%s</td>" % inline(c) for c in r))
            t.append("</table></div>")
            out.append("\n".join(t))
            continue

        # blockquote
        if line.startswith(">"):
            flush_para()
            block = []
            while i < n and lines[i].startswith(">"):
                block.append(lines[i].lstrip("> ")); i += 1
            out.append("<blockquote><p>%s</p></blockquote>" % inline(" ".join(block)))
            continue

        # list (ul/ol, one nesting level by indent). Item text is buffered
        # across wrapped source lines so inline spans (e.g. `code` broken over
        # a line break) render as one unit.
        m = re.match(r"^(\s*)([-*+]|\d+\.)\s+(.*)$", line)
        if m:
            flush_para()
            stack = []          # open list tags: [("ul"|"ol", indent)]
            buf = None          # pending item text

            def emit_buf(close=True):
                nonlocal buf
                if buf is not None:
                    out.append("<li>%s%s" % (inline(buf), "</li>" if close else ""))
                    buf = None

            while i < n:
                mm = re.match(r"^(\s*)([-*+]|\d+\.)\s+(.*)$", lines[i])
                if mm:
                    indent = len(mm.group(1))
                    kind = "ol" if mm.group(2).rstrip(".").isdigit() else "ul"
                    if not stack:
                        out.append("<%s>" % kind); stack.append((kind, indent))
                    elif indent > stack[-1][1]:
                        emit_buf(close=False)      # nested list lives inside this li
                        out.append("<%s>" % kind); stack.append((kind, indent))
                    else:
                        emit_buf()
                        while len(stack) > 1 and indent < stack[-1][1]:
                            out.append("</%s></li>" % stack.pop()[0])
                    buf = mm.group(3)
                    i += 1
                elif lines[i].strip() and re.match(r"^\s{2,}", lines[i]):
                    buf = ((buf or "") + " " + lines[i].strip())   # wrapped line
                    i += 1
                elif not lines[i].strip():
                    # blank: the list continues only if another item follows
                    j = i + 1
                    while j < n and not lines[j].strip():
                        j += 1
                    if j < n and re.match(r"^(\s*)([-*+]|\d+\.)\s+", lines[j]):
                        i = j
                    else:
                        break
                else:
                    break
            emit_buf()
            while stack:
                kind, _ = stack.pop()
                out.append("</%s>%s" % (kind, "</li>" if stack else ""))
            continue

        # paragraph / blank
        if line.strip():
            para.append(line.strip())
        else:
            flush_para()
        i += 1

    flush_para()
    return "\n".join(out), toc


# ---------------------------------------------------------------- template

CSS = """
  :root {
    --bg:#f6f6fa; --surface:#ffffff; --surface-2:#eef0f6; --on-surface:#1b1b21;
    --on-surface-var:#5a5c66; --outline:#e2e3ec; --primary:#4b56d2; --primary-c:#fff;
    --ok:#1e7d46; --err:#ba1a1a; --warn:#a25b00;
    --ok-c:#e6f4ea; --err-c:#ffe9e7; --warn-c:#fff3e0;
    --shadow:0 1px 2px rgba(0,0,0,.08),0 2px 8px rgba(0,0,0,.05);
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#121318; --surface:#1c1d24; --surface-2:#23252e; --on-surface:#e4e2e9;
      --on-surface-var:#c6c6d0; --outline:#33343d; --primary:#bcc2ff; --primary-c:#1a2277;
      --ok:#7fd99b; --err:#ffb4ab; --warn:#f5bd6e;
      --ok-c:#12331f; --err-c:#3d1512; --warn-c:#3a2a12; }
  }
  * { box-sizing:border-box; }
  body { font-family:"Segoe UI",system-ui,-apple-system,Roboto,sans-serif; margin:0;
    background:var(--bg); color:var(--on-surface); line-height:1.6;
    -webkit-font-smoothing:antialiased; }
  a { color:var(--primary); text-decoration:none; }
  a:hover { text-decoration:underline; }
  .layout { display:flex; max-width:78rem; margin:0 auto; min-height:100vh; }
  nav.side { flex:0 0 15.5rem; padding:1.5rem 1rem 2rem; border-right:1px solid var(--outline);
    position:sticky; top:0; align-self:flex-start; max-height:100vh; overflow-y:auto; }
  .brandrow { display:flex; align-items:center; gap:.6rem; margin-bottom:1.2rem; }
  .logo { width:2.2rem; height:2.2rem; border-radius:.8rem; background:var(--primary);
    color:var(--primary-c); display:grid; place-items:center; font-weight:700; }
  .brandrow b { font-size:1.02rem; }
  .brandrow .v { display:block; color:var(--on-surface-var); font-size:.72rem; }
  nav.side a.pg { display:block; padding:.42rem .7rem; border-radius:.6rem; font-size:.88rem;
    color:var(--on-surface); margin:.1rem 0; }
  nav.side a.pg:hover { background:var(--surface-2); text-decoration:none; }
  nav.side a.pg.active { background:var(--primary); color:var(--primary-c); font-weight:600; }
  nav.side .grp { font-size:.7rem; text-transform:uppercase; letter-spacing:.05em;
    color:var(--on-surface-var); margin:1.1rem .7rem .3rem; }
  main { flex:1 1 auto; min-width:0; padding:2rem 2.2rem 4rem; }
  main h1 { font-size:1.7rem; margin:.2rem 0 1rem; line-height:1.25; }
  main h2 { font-size:1.25rem; margin:2.2rem 0 .6rem; padding-top:.5rem;
    border-top:1px solid var(--outline); }
  main h3 { font-size:1.05rem; margin:1.6rem 0 .4rem; }
  main h4 { font-size:.95rem; margin:1.2rem 0 .3rem; }
  p { margin:.65rem 0; }
  pre { background:var(--surface-2); border:1px solid var(--outline); border-radius:.8rem;
    padding:.9rem 1.1rem; overflow-x:auto; font-size:.84rem; line-height:1.5; }
  code { font-family:ui-monospace,"Cascadia Code",Menlo,monospace; font-size:.88em;
    background:var(--surface-2); padding:.08rem .35rem; border-radius:.35rem; }
  pre code { background:none; padding:0; font-size:1em; }
  .tablewrap { overflow-x:auto; margin:.8rem 0; border:1px solid var(--outline);
    border-radius:.8rem; }
  table { border-collapse:collapse; width:100%; font-size:.86rem; }
  th,td { text-align:left; padding:.5rem .8rem; border-bottom:1px solid var(--outline);
    vertical-align:top; }
  th { background:var(--surface-2); font-size:.72rem; text-transform:uppercase;
    letter-spacing:.04em; color:var(--on-surface-var); }
  tr:last-child td { border-bottom:none; }
  blockquote { border-left:3px solid var(--primary); margin:.8rem 0; padding:.2rem 1rem;
    color:var(--on-surface-var); background:var(--surface-2); border-radius:0 .6rem .6rem 0; }
  ul,ol { padding-left:1.4rem; margin:.5rem 0; }
  li { margin:.25rem 0; }
  hr { border:none; border-top:1px solid var(--outline); margin:1.6rem 0; }
  img { max-width:100%; }
  .onpage { background:var(--surface); border:1px solid var(--outline); border-radius:.9rem;
    padding:.8rem 1.1rem; font-size:.84rem; margin:1rem 0 1.4rem; }
  .onpage b { display:block; margin-bottom:.3rem; font-size:.72rem; text-transform:uppercase;
    letter-spacing:.05em; color:var(--on-surface-var); }
  .onpage a { display:inline-block; margin:.15rem .8rem .15rem 0; }
  footer { color:var(--on-surface-var); font-size:.78rem; margin-top:3rem;
    border-top:1px solid var(--outline); padding-top:1.1rem; text-align:center; line-height:1.7; }
  footer .brand { font-weight:700; color:var(--on-surface); }
  footer .heart { color:#e0245e; }
  .menubtn { display:none; }
  @media (max-width:860px) {
    .layout { flex-direction:column; }
    nav.side { position:static; max-height:none; border-right:none;
      border-bottom:1px solid var(--outline); flex-basis:auto; }
    main { padding:1.2rem 1.1rem 3rem; }
  }
"""

FOOTER = """<footer>
<div class="brand">\U0001F6E1️ AuditXS</div>
<div>Made with <span class="heart">&#10084;</span> from Canada \U0001F341</div>
<div>&copy; 2026 <strong>DigitalXS</strong> — Programming &amp; Development ·
 <a href="https://digitalxs.ca">digitalxs.ca</a> ·
 <a href="%s">GitHub</a></div>
</footer>""" % GITHUB


def nav_html(active):
    links = ['<div class="brandrow"><div class="logo">A</div>'
             '<div><b>AuditXS docs</b><span class="v">v%s</span></div></div>' % VERSION]
    links.append('<a class="pg%s" href="index.html">Documentation home</a>'
                 % (" active" if active == "index.html" else ""))
    links.append('<div class="grp">Guides</div>')
    for _, out, title, _ in PAGES:
        cls = " active" if out == active else ""
        links.append('<a class="pg%s" href="%s">%s</a>' % (cls, out, html.escape(title)))
    links.append('<div class="grp">Project</div>')
    links.append('<a class="pg" href="../index.html">AuditXS home</a>')
    links.append('<a class="pg" href="%s">GitHub repository</a>' % GITHUB)
    return "<nav class=\"side\">%s</nav>" % "\n".join(links)


def page(title, active, content):
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s — AuditXS documentation</title>
<meta name="description" content="AuditXS — transparent, reversible Linux security auditing and hardening. Documentation.">
<style>%s</style>
</head>
<body>
<div class="layout">
%s
<main>
%s
%s
</main>
</div>
</body>
</html>
""" % (html.escape(title), CSS, nav_html(active), content, FOOTER)


def build_doc(src, out_name, title):
    md = (ROOT / src).read_text()
    body, toc = md_to_html(md)
    h2s = [(s, t) for lvl, s, t in toc if lvl == 2]
    onpage = ""
    if len(h2s) >= 4:
        onpage = ('<div class="onpage"><b>On this page</b>%s</div>'
                  % "".join('<a href="#%s">%s</a>' % (s, html.escape(t)) for s, t in h2s))
    # insert the on-page TOC right after the first h1 (or at the top)
    if onpage:
        parts = body.split("</h1>", 1)
        body = (parts[0] + "</h1>" + onpage + parts[1]) if len(parts) == 2 else onpage + body
    (ROOT / "docs" / out_name).write_text(page(title, out_name, body))


def build_hub():
    cards = []
    for _, out, title, desc in PAGES:
        cards.append(
            '<a class="card" href="%s"><b>%s</b><span>%s</span></a>'
            % (out, html.escape(title), html.escape(desc)))
    content = """
<h1>AuditXS documentation</h1>
<p><strong>AuditXS</strong> is a transparent, reversible Linux security audit and hardening
tool for Debian, Ubuntu, Pop!_OS, Arch, Fedora and openSUSE. Audits are strictly
read-only; every fix is explained first, applied only with consent, and recorded in a
snapshot that <code>auditxs rollback</code> can restore.</p>
<style>
 .cards { display:grid; grid-template-columns:repeat(auto-fill,minmax(16rem,1fr));
   gap:.9rem; margin:1.4rem 0; }
 .card { display:flex; flex-direction:column; gap:.35rem; background:var(--surface);
   border:1px solid var(--outline); border-radius:1rem; padding:1.1rem 1.2rem;
   box-shadow:var(--shadow); color:var(--on-surface); }
 .card:hover { border-color:var(--primary); text-decoration:none; }
 .card b { font-size:.98rem; }
 .card span { font-size:.82rem; color:var(--on-surface-var); }
</style>
<div class="cards">
%s
</div>
<h2 id="quick-start">Quick start</h2>
<pre><code>git clone https://github.com/digitalxs/AuditXS.git
cd AuditXS
sudo ./setup.sh           # or:  sudo ./install-gui.sh  (graphical installer)

sudo auditxs audit        # read-only audit + HTML/JSON report + score
sudo auditxs harden       # review and apply fixes, one by one, with consent
sudo auditxs rollback latest</code></pre>
<p>The full command reference lives in the <a href="usage.html">user manual</a>;
the complete check documentation is in the <a href="checks.html">check catalogue</a>.</p>
""" % "\n".join(cards)
    (ROOT / "docs" / "index.html").write_text(page("Documentation", "index.html", content))


# ---------------------------------------------------------------- landing

def build_landing():
    tpl = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AuditXS — transparent, reversible Linux security auditing</title>
<meta name="description" content="AuditXS audits Linux systems against professional security baselines and hardens them with fully reversible, consented changes. Free and open source, by DigitalXS.">
<style>
  :root {
    --bg:#f6f6fa; --surface:#ffffff; --surface-2:#eef0f6; --on-surface:#1b1b21;
    --on-surface-var:#5a5c66; --outline:#e2e3ec; --primary:#4b56d2; --primary-c:#fff;
    --ok:#1e7d46; --ok-c:#e6f4ea;
    --shadow:0 1px 2px rgba(0,0,0,.08),0 2px 8px rgba(0,0,0,.05);
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#121318; --surface:#1c1d24; --surface-2:#23252e; --on-surface:#e4e2e9;
      --on-surface-var:#c6c6d0; --outline:#33343d; --primary:#bcc2ff; --primary-c:#1a2277;
      --ok:#7fd99b; --ok-c:#12331f; }
  }
  * { box-sizing:border-box; }
  body { font-family:"Segoe UI",system-ui,-apple-system,Roboto,sans-serif; margin:0;
    background:var(--bg); color:var(--on-surface); line-height:1.6;
    -webkit-font-smoothing:antialiased; }
  a { color:var(--primary); text-decoration:none; }
  .wrap { max-width:64rem; margin:0 auto; padding:0 1.25rem 4rem; }
  header.top { display:flex; align-items:center; gap:.7rem; padding:1.2rem 0; }
  .logo { width:2.4rem; height:2.4rem; border-radius:.85rem; background:var(--primary);
    color:var(--primary-c); display:grid; place-items:center; font-weight:700; font-size:1.1rem; }
  header.top b { font-size:1.1rem; }
  header.top .links { margin-left:auto; display:flex; gap:1.1rem; font-size:.9rem; font-weight:600; }
  .hero { text-align:center; padding:3.2rem 0 2.4rem; }
  .hero .shield { font-size:3.2rem; line-height:1; }
  .hero h1 { font-size:2.3rem; margin:.6rem 0 .4rem; letter-spacing:-.02em; }
  .hero h1 .x { color:var(--primary); }
  .hero p.tag { font-size:1.12rem; color:var(--on-surface-var); max-width:38rem; margin:0 auto; }
  .cta { display:flex; gap:.8rem; justify-content:center; margin-top:1.6rem; flex-wrap:wrap; }
  .btn { display:inline-block; padding:.7rem 1.5rem; border-radius:2rem; font-weight:700;
    font-size:.95rem; }
  .btn.primary { background:var(--primary); color:var(--primary-c); box-shadow:var(--shadow); }
  .btn.ghost { border:1px solid var(--outline); color:var(--on-surface); background:var(--surface); }
  .btn:hover { filter:brightness(1.06); }
  .badges { display:flex; gap:.5rem; justify-content:center; margin-top:1.2rem; flex-wrap:wrap; }
  .b { font-size:.74rem; font-weight:700; padding:.3rem .7rem; border-radius:2rem;
    background:var(--surface-2); color:var(--on-surface-var); border:1px solid var(--outline); }
  .b.ok { background:var(--ok-c); color:var(--ok); border-color:transparent; }
  .grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(17rem,1fr));
    gap:1rem; margin:2.5rem 0; }
  .f { background:var(--surface); border:1px solid var(--outline); border-radius:1.1rem;
    padding:1.2rem 1.3rem; box-shadow:var(--shadow); }
  .f .ic { font-size:1.5rem; }
  .f b { display:block; margin:.4rem 0 .25rem; font-size:1rem; }
  .f p { margin:0; font-size:.87rem; color:var(--on-surface-var); }
  h2.sec { text-align:center; font-size:1.45rem; margin:3rem 0 .4rem; }
  p.secsub { text-align:center; color:var(--on-surface-var); margin:0 0 1.2rem; }
  pre.install { background:var(--surface-2); border:1px solid var(--outline);
    border-radius:.9rem; padding:1rem 1.2rem; overflow-x:auto; font-size:.9rem;
    max-width:34rem; margin:0 auto; line-height:1.7; }
  pre.install .c { color:var(--on-surface-var); }
  code { font-family:ui-monospace,"Cascadia Code",Menlo,monospace; }
  .docs-band { background:var(--surface); border:1px solid var(--outline);
    border-radius:1.2rem; box-shadow:var(--shadow); padding:1.6rem 1.8rem; margin:2.6rem 0;
    display:flex; align-items:center; gap:1.2rem; flex-wrap:wrap; }
  .docs-band .txt { flex:1 1 20rem; }
  .docs-band b { font-size:1.08rem; }
  .docs-band p { margin:.3rem 0 0; font-size:.9rem; color:var(--on-surface-var); }
  footer { color:var(--on-surface-var); font-size:.78rem; margin-top:3rem;
    border-top:1px solid var(--outline); padding-top:1.2rem; text-align:center; line-height:1.8; }
  footer .brand { font-weight:700; font-size:.95rem; color:var(--on-surface); }
  footer .heart { color:#e0245e; }
  @media (max-width:640px){ .hero h1{font-size:1.8rem} .hero{padding-top:2rem} }
</style>
</head>
<body>
<div class="wrap">

<header class="top">
  <div class="logo">A</div><b>AuditXS</b>
  <nav class="links">
    <a href="docs/index.html">Documentation</a>
    <a href="@GITHUB@">GitHub</a>
  </nav>
</header>

<section class="hero">
  <div class="shield">\U0001F6E1️</div>
  <h1>Audit<span class="x">XS</span></h1>
  <p class="tag">Transparent, reversible Linux security auditing and hardening.
  Professional baselines, every change explained, every change undoable.</p>
  <div class="cta">
    <a class="btn primary" href="docs/index.html">Read the documentation</a>
    <a class="btn ghost" href="@GITHUB@">View on GitHub</a>
  </div>
  <div class="badges">
    <span class="b ok">v@VERSION@</span>
    <span class="b">GPL-3.0</span>
    <span class="b">125 checks · 26 categories</span>
    <span class="b">CIS · STIG aligned</span>
    <span class="b">NIST CSF 2.0 mapped</span>
  </div>
</section>

<div class="grid">
  <div class="f"><span class="ic">\U0001F50E</span><b>Read-only audits</b>
    <p>An audit never changes anything. You get a severity-weighted score, a Material
    HTML report and machine-readable JSON, SARIF and CSV.</p></div>
  <div class="f"><span class="ic">↩️</span><b>Fully reversible hardening</b>
    <p>Every fix is explained first, applied only with consent, snapshotted before it
    touches anything, and undone by <code>auditxs rollback</code>.</p></div>
  <div class="f"><span class="ic">\U0001F9EA</span><b>Validate-or-restore</b>
    <p>Changes to critical daemons (sshd, sudoers) are syntax-checked and auto-reverted
    on failure — with SSH and firewall lockout guards.</p></div>
  <div class="f"><span class="ic">\U0001F5A7</span><b>Fleet mode over SSH</b>
    <p>Audit many hosts read-only from one machine: aggregated dashboard, per-host
    reports, CI-friendly exit codes. Never hardens remotely.</p></div>
  <div class="f"><span class="ic">\U0001F4CA</span><b>Baselines &amp; drift</b>
    <p>Approve a baseline, schedule daily audits, and get webhook or e-mail alerts the
    moment configuration drifts or a CVE lands.</p></div>
  <div class="f"><span class="ic">\U0001F5A5️</span><b>Every interface</b>
    <p>CLI, ncurses terminal UI, a web UI (localhost or your LAN), native Qt and
    Electron desktop apps and a zenity GUI — same engine, same consent model.</p></div>
</div>

<h2 class="sec">Install in a minute</h2>
<p class="secsub">Debian · Ubuntu · Pop!_OS · Arch · Fedora · openSUSE</p>
<pre class="install"><code><span class="c"># clone and install</span>
git clone @GITHUB@.git
cd AuditXS
sudo ./setup.sh

<span class="c"># first audit — read-only, with report and score</span>
sudo auditxs audit</code></pre>

<div class="docs-band">
  <div class="txt">
    <b>Everything is documented.</b>
    <p>The user manual, the full check and error catalogues, architecture, compliance
    mappings, the security guide and the developer guide — all in one place.</p>
  </div>
  <a class="btn primary" href="docs/index.html">Browse the docs</a>
</div>

<footer>
  <div class="brand">\U0001F6E1️ AuditXS</div>
  <div>Made with <span class="heart">&#10084;</span> from Canada \U0001F341</div>
  <div>&copy; 2026 <strong>DigitalXS</strong> — Programming &amp; Development ·
    <a href="https://digitalxs.ca">digitalxs.ca</a> ·
    <a href="mailto:luis@digitalxs.ca">luis@digitalxs.ca</a></div>
</footer>

</div>
</body>
</html>
"""
    out = tpl.replace("@VERSION@", VERSION).replace("@GITHUB@", GITHUB)
    (ROOT / "index.html").write_text(out)


def main():
    built = []
    for src, out, title, _ in PAGES:
        if not (ROOT / src).exists():
            print("SKIP (missing): %s" % src, file=sys.stderr)
            continue
        build_doc(src, out, title)
        built.append("docs/" + out)
    build_hub(); built.append("docs/index.html")
    build_landing(); built.append("index.html")
    print("built %d pages (v%s):" % (len(built), VERSION))
    for b in built:
        print("  " + b)


if __name__ == "__main__":
    main()
