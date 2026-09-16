#!/usr/bin/env python3
"""What the reports share: the stylesheet, and the vocabulary of a verdict.

`report.py` renders the tenant -- the whole scan on one page, in the order the
data moves -- and `report_design.py` renders what a design run produced. They
have to look like one product and use one set of words for the same thing.
Keeping the CSS and the verdict labels in one place is what stops them
drifting: a chip that means "covered" in one report and something else in the
other is the confusion this split was meant to end.

The four state suffixes -- ok, partial, none, void -- are that vocabulary, and
they are the four the layout proposal was drawn around: working, waiting on an
earlier fix, broken, and not checked.

Nothing here reads a file or computes a figure. It is presentation only.
"""

from __future__ import annotations

import html

# A charset declaration, first, before anything a browser could mis-read.
# The document is written as UTF-8 and contains arrows, em dashes and whatever
# a resource is named; without this a browser applies its own default and the
# report renders mojibake on someone else's machine. It is two lines from the
# top for a reason -- browsers only scan the first 1024 bytes for it.
HEAD = """<meta charset="utf-8">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@400;500;600&family=JetBrains+Mono:wght@400;500;700&family=Newsreader:opsz,wght@6..72,300;6..72,400;6..72,500&display=swap">
<style>
/* The four states, named for the answer they carry rather than for a colour:
   ok is working, partial is waiting on an earlier fix, none is broken, void
   is not checked. Those are the class suffixes everywhere in both reports,
   and the palette is the one agreed on the layout proposal.

   `void` is the one that earns its own entry. "Could not check" is an answer,
   and giving it the same grey as a disabled control -- or worse, the red of a
   fault -- is how a report ends up calling something broken that nobody
   looked at. It is drawn as a dashed rule, never a solid one. */
:root {
  --paper:#FAF9F7; --raise:#FFFFFF; --sunk:#F2F0EC;
  --ink:#191C22; --slate:#6B7280; --faint:#9AA1AC;
  --rule:#E2DFD9; --rule-soft:#EDEAE4;
  --accent:#25324D;
  --ok:#1B7A5A;      --ok-bg:#E7F2ED;
  --partial:#9C6A1B; --partial-bg:#FAF1E2;
  --none:#B0382C;    --none-bg:#FAEAE7;
  --void:#818A99;    --void-bg:#EFF1F4;
  --measure:64ch;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --paper:#14161A; --raise:#1B1F25; --sunk:#111317;
    --ink:#E9E6E1; --slate:#98A0AC; --faint:#6E7682;
    --rule:#2B3038; --rule-soft:#22262C;
    --accent:#A9BCE4;
    --ok:#5CBF98;      --ok-bg:#12271F;
    --partial:#D8A44E; --partial-bg:#2A2114;
    --none:#E28075;    --none-bg:#2B1815;
    --void:#7C8593;    --void-bg:#1A1E24;
  }
}
:root[data-theme="dark"] {
  --paper:#14161A; --raise:#1B1F25; --sunk:#111317;
  --ink:#E9E6E1; --slate:#98A0AC; --faint:#6E7682;
  --rule:#2B3038; --rule-soft:#22262C;
  --accent:#A9BCE4;
  --ok:#5CBF98;      --ok-bg:#12271F;
  --partial:#D8A44E; --partial-bg:#2A2114;
  --none:#E28075;    --none-bg:#2B1815;
  --void:#7C8593;    --void-bg:#1A1E24;
}
* { box-sizing:border-box; }
body {
  background:var(--paper); color:var(--ink);
  font-family:Archivo, system-ui, -apple-system, sans-serif;
  font-size:16px; line-height:1.6; margin:0;
  -webkit-font-smoothing:antialiased;
}
.wrap { max-width:min(1060px, 100%); margin:0 auto; padding-block:0 5rem;
  padding-left:clamp(20px,4vw,48px); padding-right:clamp(20px,4vw,48px); }
h1,h2,h3,h4 { font-family:Newsreader, Georgia, serif; text-wrap:balance;
  margin:0; font-weight:400; letter-spacing:-.005em; }
h1 { font-size:clamp(2.1rem,4.6vw,3rem); line-height:1.08; }
h2 { font-size:clamp(1.35rem,2.5vw,1.7rem); line-height:1.22; }
h3 { font-size:1.06rem; }
h4 { font-size:.95rem; font-family:Archivo,sans-serif; font-weight:600; }
p { margin:0; max-width:var(--measure); }
code { font-family:"JetBrains Mono", ui-monospace, monospace; font-size:.85em;
  font-variant-numeric:tabular-nums; }
.muted { color:var(--slate); }
/* The design proposal calls this a label. It is the same element under the
   same rules; the class keeps the name the rest of the codebase, and every
   test that finds a section by its step number, already uses. */
.eyebrow { font-family:"JetBrains Mono",monospace; font-size:.68rem;
  letter-spacing:.13em; text-transform:uppercase; color:var(--slate);
  font-weight:500; }

/* masthead */
/* Theme toggle. Fixed rather than placed in the header because the two
   reports build their headers separately -- putting it in HEAD means both get
   it and neither can drift. */
.themetoggle { position:fixed; top:1.1rem; right:1.1rem; z-index:10;
  font-family:"JetBrains Mono",monospace; font-size:.66rem; letter-spacing:.1em;
  text-transform:uppercase; color:var(--slate); background:var(--raise);
  border:1px solid var(--rule); border-radius:2px; padding:.4rem .7rem;
  cursor:pointer; line-height:1; }
.themetoggle:hover { color:var(--ink); border-color:var(--slate); }
@media print { .themetoggle { display:none; } }

header { padding:3.5rem 0 2rem; display:flex; flex-direction:column; gap:1.1rem; }
.meta { display:flex; flex-wrap:wrap; gap:.35rem 2rem; font-family:"JetBrains Mono",monospace;
  font-size:.76rem; color:var(--slate); padding-top:.4rem; }
.meta div { display:flex; gap:.5rem; padding:.15rem 0; }
/* Label light, value dark. The contrast carries which is which, so neither
   needs to be bigger than the other. */
.meta span:first-child { font-weight:500; color:var(--faint); }
.meta code { font-size:inherit; font-weight:400; color:var(--ink); }

section.block { display:flex; flex-direction:column; gap:1.05rem;
  padding-block:2.25rem; border-top:1px solid var(--rule-soft); }
section.block:last-of-type { border-bottom:0; }

/* ── the step rail ────────────────────────────────────────────────────────
   Six checks in the order the data moves, and the state of each. It is the
   one thing on the page that answers "where am I" before anything answers
   "what is wrong", and every bar is drawn from the same measurement the
   section below it states. */
.steps { background:var(--raise); border:1px solid var(--rule); border-radius:5px;
  padding:clamp(1.25rem,3vw,1.85rem); display:flex; flex-direction:column;
  gap:1.4rem; margin-bottom:2.5rem; }
.steps__track { display:flex; align-items:flex-start; gap:0; overflow-x:auto;
  padding-bottom:.25rem; }
.step { flex:1 1 0; min-width:124px; display:flex; flex-direction:column; gap:.5rem; }
.step + .step { padding-left:.8rem; }
.step__bar { height:4px; border-radius:2px; }
.step--ok .step__bar { background:var(--ok); }
.step--none .step__bar { background:var(--none); }
/* Dashed, not solid: waiting and unchecked are not states you fix here, and
   a solid bar reads as a measurement of this step. */
.step--partial .step__bar { background:repeating-linear-gradient(90deg,var(--partial) 0 5px,transparent 5px 10px); }
.step--void .step__bar { background:repeating-linear-gradient(90deg,var(--void) 0 3px,transparent 3px 8px); }
.step__n { font-family:"JetBrains Mono",monospace; font-size:.66rem;
  color:var(--faint); letter-spacing:.1em; }
.step__name { font-size:.92rem; font-weight:500; line-height:1.25; }
.step__state { font-family:"JetBrains Mono",monospace; font-size:.68rem; }
.step--ok .step__state { color:var(--ok); }
.step--none .step__state { color:var(--none); font-weight:700; }
.step--partial .step__state { color:var(--partial); }
.step--void .step__state { color:var(--void); }
.step--partial .step__name, .step--void .step__name { color:var(--slate); }
.steps__key { display:flex; gap:1.25rem; flex-wrap:wrap; font-size:.85rem;
  color:var(--slate); border-top:1px solid var(--rule-soft); padding-top:1rem; }
.steps__key i { width:18px; height:3px; border-radius:2px; display:inline-block;
  margin-right:.45rem; vertical-align:middle; font-style:normal; }
/* The key's own swatch classes. They cannot reuse the rail's, because those
   are written as `.step--ok .step__bar` -- a descendant selector, and a key
   swatch is one element, so it drew nothing at all. */
.steps__key i.key--ok { background:var(--ok); }
.steps__key i.key--none { background:var(--none); }
.steps__key i.key--partial { background:repeating-linear-gradient(90deg,var(--partial) 0 5px,transparent 5px 10px); }
.steps__key i.key--void { background:repeating-linear-gradient(90deg,var(--void) 0 3px,transparent 3px 8px); }

/* ── fix this first ──────────────────────────────────────────────────────── */
.fix { border-left:3px solid var(--none); padding:1.1rem 0 1.1rem 1.4rem;
  display:flex; flex-direction:column; gap:.7rem; margin-bottom:3rem; }
.fix h2 { max-width:30ch; }
.fix p { font-size:1.02rem; }
.howto { background:var(--sunk); border-radius:3px; padding:.85rem 1.1rem;
  font-size:.9rem; max-width:var(--measure); display:flex;
  flex-direction:column; gap:.3rem; }
.howto b { font-family:"JetBrains Mono",monospace; font-size:.66rem;
  letter-spacing:.11em; text-transform:uppercase; color:var(--slate);
  font-weight:500; }
.howto code { color:var(--ink); }

/* ── a stage: one step of the chain ──────────────────────────────────────── */
.stage__top { display:flex; align-items:baseline; gap:.8rem; flex-wrap:wrap; }
.stage__num { font-family:"JetBrains Mono",monospace; font-size:.7rem;
  font-weight:700; color:var(--paper); background:var(--accent);
  padding:.18rem .42rem; border-radius:2px; }
.stage--dim .stage__num { background:var(--slate); }
.stage__q { font-size:.88rem; color:var(--slate); }
/* The finding, in one line, with the number that carries it coloured. */
h2.stage__verdict { font-size:1.28rem; line-height:1.34; max-width:44ch; }
.t-ok { color:var(--ok); font-weight:500; }
.t-partial { color:var(--partial); font-weight:500; }
.t-none { color:var(--none); font-weight:500; }
.t-void { color:var(--void); font-weight:500; }
/* A stage whose findings are all consequences of an earlier step demotes its
   TABLE and keeps its heading at full contrast -- the same rule `block--ref`
   follows, and for the reason recorded there: three sections that state
   findings once rendered as footnotes because the whole section was faded. */
.stage--dim .scroll { opacity:.88; }

/* ── one cause, said once ────────────────────────────────────────────────── */
.why { display:flex; flex-direction:column; gap:.3rem; padding:.9rem 1.1rem;
  border-radius:3px; font-size:.92rem; max-width:var(--measure); }
.why--partial { background:var(--partial-bg); border-left:2px solid var(--partial); }
.why--void { background:var(--void-bg); border-left:2px solid var(--void); }
.why--none { background:var(--none-bg); border-left:2px solid var(--none); }
.why__k { font-family:"JetBrains Mono",monospace; font-size:.66rem;
  letter-spacing:.11em; text-transform:uppercase; font-weight:500; }
.why--partial .why__k { color:var(--partial); }
.why--void .why__k { color:var(--slate); }
.why--none .why__k { color:var(--none); }
.why code { color:inherit; }

/* the motif: a partition drawn to scale */
.bar { display:flex; height:8px; border-radius:2px; overflow:hidden; gap:2px;
  background:transparent; max-width:var(--measure); }
.seg { display:block; }
.seg--ok { background:var(--ok); } .seg--partial { background:var(--partial); }
.seg--none { background:var(--none); } .seg--void { background:var(--void); opacity:.45; }
.key { list-style:none; padding:0; margin:0; display:flex; flex-wrap:wrap; gap:.35rem 1.4rem;
  font-size:.84rem; color:var(--slate); }
.key li { display:flex; align-items:center; gap:.45rem; }
.dot { width:8px; height:8px; border-radius:50%; flex:none; }
.dot--ok { background:var(--ok); } .dot--partial { background:var(--partial); }
.dot--none { background:var(--none); } .dot--void { background:var(--void); opacity:.5; }
.k-n { font-family:"JetBrains Mono",monospace; font-variant-numeric:tabular-nums;
  color:var(--ink); font-weight:500; }

.block--lead { padding-top:0; border-top:0; }
.lead__1 { font-family:Newsreader,Georgia,serif; font-size:1.5rem;
           line-height:1.3; margin:0 0 .35rem; max-width:34ch; }
.lead__2 { font-size:.95rem; color:var(--slate); margin:0 0 1.4rem; max-width:52ch; }
.lead__do { border-top:1px solid var(--rule-soft); padding-top:1.1rem; }
.lead__do h3 { font-family:"JetBrains Mono",monospace; font-size:.68rem;
               letter-spacing:.09em; text-transform:uppercase; color:var(--slate);
               margin:0 0 .35rem; font-weight:500; }
/* A heading row inside a table, so a grouped table reads as its groups. */
tr.grouprow th { text-align:left; font-family:"JetBrains Mono",monospace;
                 font-size:.66rem; letter-spacing:.09em; text-transform:uppercase;
                 color:var(--slate); font-weight:500; padding-top:1.1rem;
                 border-bottom:1px solid var(--rule); }
tr.grouprow:first-child th { padding-top:.2rem; }
tr.grouprow th .more { text-transform:none; letter-spacing:0; font-weight:400;
                       margin-left:.6rem; }
.lead__axis { margin:0 0 .8rem; font-size:.8rem; color:var(--slate); }
.lead__do ol { margin:0; padding-left:1.35rem; }
.lead__do li { margin-bottom:.55rem; font-size:.95rem; }
.lead__do li span { display:block; font-size:.8rem; color:var(--slate); margin-top:.15rem; }
.lead__do li .lead__cost { color:var(--none); font-weight:500; }
/* Colour is spent where a decision is made, and nowhere else. Reference tiers
   keep the shape of a chip and drop its colour. */
.block--ref .chip { background:var(--rule-soft); color:var(--slate); }
.block--ref table { font-size:.82rem; }
.block--ref .scroll, .block--ref .note { opacity:.86; }

.deadlist { margin:0; display:flex; flex-direction:column; }
.dead { padding:.7rem 0; border-bottom:1px solid var(--rule-soft); }
.dead:last-child { border-bottom:0; }
.dead h4 { margin:0 0 .2rem; font-size:.95rem; font-weight:600; }
.method { display:grid; grid-template-columns:auto 1fr; gap:.3rem 1.1rem;
          margin:0 0 1rem; font-size:.85rem; max-width:60ch; }
.method dt { font-family:"JetBrains Mono",monospace; font-size:.7rem;
             letter-spacing:.06em; text-transform:uppercase; color:var(--slate); }
.method dd { margin:0; }
.method__note { font-size:.82rem; color:var(--slate); max-width:66ch; margin:0 0 1rem; }
.lead__caveat { margin:0; font-size:.8rem; color:var(--slate);
                border-left:2px solid var(--partial); padding-left:.7rem; }
.chip { display:inline-block; font-family:"JetBrains Mono",monospace; font-size:.68rem;
  padding:.16rem .45rem; border-radius:2px; letter-spacing:.02em; white-space:nowrap; }
.chip--ok { background:var(--ok-bg); color:var(--ok); }
.chip--partial { background:var(--partial-bg); color:var(--partial); }
.chip--none { background:var(--none-bg); color:var(--none); }
.chip--void { background:var(--void-bg); color:var(--slate); }

/* scope spine */
.scope { display:grid; grid-template-columns:minmax(180px,220px) 1fr; gap:2rem;
  padding:1.15rem 0; border-top:1px solid var(--rule-soft); align-items:start; }
.scope__head p { font-size:.85rem; color:var(--slate); margin-top:.15rem; }
.scope__body { display:flex; flex-direction:column; gap:.7rem; }
.one { display:flex; gap:.6rem; align-items:baseline; flex-wrap:wrap; font-size:.88rem; }
/* forces the connector list onto its own row inside the flex line */
.one .stack { flex-basis:100%; font-size:.78rem; color:var(--slate); margin:.1rem 0 0; }
.one .stack div { padding:.12rem 0; }
@media (max-width:720px) { .scope { grid-template-columns:1fr; gap:.7rem; } }

.scroll { overflow-x:auto; max-width:100%; }
table { border-collapse:collapse; width:100%; font-size:.87rem; min-width:620px; }
th { text-align:left; font-family:"JetBrains Mono",monospace; font-weight:500;
  font-size:.66rem; letter-spacing:.1em; text-transform:uppercase; color:var(--faint);
  padding:0 1rem .5rem 0; border-bottom:1px solid var(--rule); white-space:nowrap; }
td { padding:.6rem 1rem .6rem 0; border-bottom:1px solid var(--rule-soft);
  vertical-align:top; }
td.num { font-family:"JetBrains Mono",monospace; font-variant-numeric:tabular-nums; }
td.cats code { display:inline-block; margin:0 .3rem .2rem 0; color:var(--slate); }
td.detail { color:var(--slate); font-size:.82rem; }
.more { font-size:.75rem; color:var(--slate); }
.rule-names { font-size:.76rem; color:var(--slate); margin-top:.2rem; }
/* Microsoft's own sentence about what the detection watches. */
.tpl-desc { font-size:.76rem; color:var(--slate); margin-top:.3rem;
            max-width:52ch; line-height:1.45; }
.unlock strong { font-family:"JetBrains Mono",monospace; }

.stat-row { display:flex; flex-wrap:wrap; gap:2.5rem; padding:.4rem 0 .2rem; }
.stat { display:flex; flex-direction:column; }
.stat__n { font-family:Newsreader,Georgia,serif; font-size:1.75rem; font-weight:400;
  font-variant-numeric:tabular-nums; line-height:1.2; }
.stat__l { font-size:.76rem; color:var(--slate); }
.techlist { list-style:none; padding:0; margin:0; display:flex; flex-direction:column; gap:.35rem;
  font-size:.87rem; max-width:var(--measure); }
.techlist li { display:flex; gap:.7rem; align-items:baseline;
  border-bottom:1px solid var(--rule-soft); padding-bottom:.35rem; }
.techlist span:nth-child(2) { flex:1; color:var(--slate); }
.note { font-size:.85rem; color:var(--slate); }
/* The basis line under a priced table. Mono and quiet: it is the footnote
   that makes the figure above it checkable, not a finding of its own. */
.pricebar { display:flex; gap:.5rem; align-items:baseline; flex-wrap:wrap;
  font-family:"JetBrains Mono",monospace; font-size:.78rem; color:var(--slate);
  max-width:none; }
.pricebar strong { color:var(--ink); font-weight:500; }

/* ── what was not checked, and how to read the page ──────────────────────── */
.panel { border:1px solid var(--rule); border-radius:5px;
  padding:clamp(1.25rem,3vw,1.85rem); display:flex; flex-direction:column;
  gap:.9rem; margin-top:2.25rem; }
.unchecked-list { list-style:none; margin:0; padding:0; display:flex;
  flex-direction:column; gap:.7rem; }
.unchecked-list li { display:flex; gap:.9rem; align-items:baseline;
  font-size:.92rem; padding-bottom:.7rem; border-bottom:1px solid var(--rule-soft); }
.unchecked-list li:last-child { border-bottom:0; padding-bottom:0; }
.unchecked-list b { font-weight:500; min-width:190px; flex:none; }
.notes { display:grid; grid-template-columns:repeat(auto-fit,minmax(230px,1fr));
  gap:1.5rem; padding-top:2.25rem; border-top:1px solid var(--rule); }
.notecard { display:flex; flex-direction:column; gap:.5rem; }
.notecard p { font-size:.92rem; color:var(--slate); }

.limits { display:flex; flex-direction:column; gap:0; }
.limit { padding:1.15rem 0; border-top:1px solid var(--rule-soft); }
.limit h4 { margin-bottom:.35rem; }
.limit div { font-size:.86rem; color:var(--slate); max-width:var(--measure); }
.limit .one { margin-top:.3rem; }
footer { border-top:1px solid var(--rule); padding-top:1.5rem; margin-top:3rem;
  font-size:.78rem; color:var(--slate); font-family:"JetBrains Mono",monospace; }
@media (prefers-reduced-motion:reduce) { * { animation:none!important; transition:none!important; } }
@media (max-width:620px) {
  .steps__track { flex-direction:column; gap:1rem; }
  .step { min-width:0; }
  .step + .step { padding-left:0; }
  .unchecked-list li { flex-direction:column; gap:.2rem; }
  .unchecked-list b { min-width:0; }
}
/* ── the detections page ─────────────────────────────────────────────────── */
.chips { display:flex; flex-wrap:wrap; gap:.4rem; max-width:none; }
pre.kql { font-family:"JetBrains Mono", ui-monospace, monospace; font-size:.8rem;
  line-height:1.55; margin:0; padding:1rem 1.1rem; background:var(--sunk);
  border:1px solid var(--rule); border-radius:4px; white-space:pre; }
.det dl.method { margin:0; }
.det .note { border-left:2px solid var(--partial); padding-left:.8rem;
  max-width:var(--measure); }

/* ── print ────────────────────────────────────────────────────────────────
   The page is meant to be exported. Ctrl+P on any platform produces the PDF
   with no dependency, and the same rules render the file weasyprint writes.

   Colours are forced light: the viewer's dark mode is a screen preference, and
   inheriting it puts a dark rectangle on every sheet of a printed document.
   A detection is the unit a reader judges, so it must not split across a page
   break, and the query cannot sit in a horizontal scroller on paper -- there
   is nothing to scroll -- so it wraps instead. */
@media print {
  :root, :root[data-theme="dark"], :root:not([data-theme="light"]) {
    --paper:#FFFFFF; --raise:#FFFFFF; --sunk:#F4F2EE; --ink:#191C22;
    --slate:#4A5560; --faint:#6C7783;
    --rule:#D5D0C8; --rule-soft:#EDEAE4;
    --ok:#1B7A5A; --ok-bg:#E7F2ED; --partial:#9C6A1B; --partial-bg:#FAF1E2;
    --none:#B0382C; --none-bg:#FAEAE7; --void:#6C7783; --void-bg:#EFF1F4;
  }
  @page { margin:16mm 14mm; }
  body { font-size:10.5pt; }
  .wrap { max-width:none; width:100%; padding:0; }
  header { padding:0 0 1.2rem; }
  h1 { font-size:22pt; }
  h2 { font-size:13pt; }
  h2.stage__verdict { font-size:12pt; }
  section.block { break-inside:avoid; page-break-inside:avoid; padding:1.1rem 0; }
  .steps, .panel { break-inside:avoid; page-break-inside:avoid; }
  .steps__track { overflow-x:visible; }
  .why, .howto, .fix { break-inside:avoid; page-break-inside:avoid; }
  .stage--dim .scroll, .block--ref .scroll { opacity:1; }
  .scroll { overflow-x:visible; }
  pre.kql { white-space:pre-wrap; word-break:break-word; font-size:8.5pt; }
  table { min-width:0; font-size:8.5pt; }
  a { text-decoration:none; color:inherit; }
}

</style>
<button class="themetoggle" id="themetoggle" type="button" hidden>Dark</button>
<script>
(function () {
  var root = document.documentElement, KEY = "pylon-theme";
  // Wrapped because localStorage THROWS rather than returning null in a
  // private window and in some embedded viewers -- an unhandled error here
  // would stop the rest of this script and leave the button dead.
  function remembered() {
    try { return localStorage.getItem(KEY); } catch (e) { return null; }
  }
  function remember(v) {
    try { localStorage.setItem(KEY, v); } catch (e) { /* nothing to do */ }
  }
  // What the page is showing right now: an explicit choice if one was made,
  // otherwise whatever the operating system asked for.
  function showing() {
    return root.getAttribute("data-theme")
      || (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches
          ? "dark" : "light");
  }
  var saved = remembered();
  if (saved === "dark" || saved === "light") root.setAttribute("data-theme", saved);

  var button = document.getElementById("themetoggle");
  // The label names where the click GOES, not where the page is -- a button
  // reading "Dark" on a dark page is a statement, and people press it
  // expecting something to happen.
  function label() { button.textContent = showing() === "dark" ? "Light" : "Dark"; }
  button.hidden = false;
  label();
  button.addEventListener("click", function () {
    var next = showing() === "dark" ? "light" : "dark";
    root.setAttribute("data-theme", next);
    remember(next);
    label();
  });
})();
</script>
"""


def e(text) -> str:
    return html.escape(str(text if text is not None else ""))


def bar(segments) -> str:
    """The one recurring motif: a partition drawn to scale.

    Segments are (label, count, class). Zero-count segments are dropped rather
    than drawn as slivers that imply a presence they do not have.
    """
    live = [(lab, n, cls) for lab, n, cls in segments if n]
    cells = "".join(
        f'<span class="seg seg--{cls}" style="flex:{n}" '
        f'title="{e(lab)}: {n}"></span>' for lab, n, cls in live)
    keys = "".join(
        f'<li><span class="dot dot--{cls}"></span>'
        f'<span class="k-n">{n}</span> {e(lab)}</li>' for lab, n, cls in live)
    return ('<div class="bar" role="img" aria-label="'
            + e(", ".join(f"{n} {lab}" for lab, n, _ in live))
            + f'">{cells}</div><ul class="key">{keys}</ul>')


def short(rid: str) -> str:
    if "/providers/" in rid:
        return rid.split("/providers/")[-1]
    return rid.rsplit("/", 1)[-1] or rid


# A verdict is the answer to two questions -- are the logs arriving, is
# something watching them -- and both reports have to answer them the same
# way. GAP_INPUTS is those two answers; GAP_LABEL is the phrase for the pair.
GAP_LABEL = {
    "covered": "Covered",
    "needs_confirmation": "Needs confirmation",
    "available_not_deployed": "Template ready to deploy",
    "no_data_no_rule": "No telemetry",
    "data_no_rule": "Data, no rule",
    "covered_by_product": "Covered by a product",
    "plan_available_not_enabled": "Plan available, not enabled",
    "no_content": "Nothing addresses it",
}
GAP_INPUTS = {                       # (logs arriving, something watching)
    "covered": ("yes", "yes"),
    "covered_by_product": ("&mdash;", "Defender"),
    "needs_confirmation": ("no", "yes"),
    "available_not_deployed": ("yes", "no"),
    "data_no_rule": ("yes", "no"),
    "no_data_no_rule": ("no", "no"),
    "plan_available_not_enabled": ("&mdash;", "&mdash;"),
    "no_content": ("&mdash;", "no rule, no template"),
}
GAP_CLASS = {"covered": "ok", "covered_by_product": "ok",
             "needs_confirmation": "partial",
             "available_not_deployed": "none", "no_data_no_rule": "void",
             "data_no_rule": "none", "plan_available_not_enabled": "partial",
             "no_content": "none"}

# Ordering used wherever verdicts are listed, in both reports. Strongest
# answer first, and every GapType present so a partition drawn from it sums
# to the whole -- a verdict left out of this list vanishes silently.
GAP_ORDER = ["covered", "covered_by_product", "needs_confirmation",
             "available_not_deployed", "data_no_rule", "no_data_no_rule",
             "no_content", "plan_available_not_enabled"]


def page(title: str, meta: list[tuple[str, str]], sections: str,
         footer: str = "") -> str:
    """The shell both reports are poured into: same head, same header shape.

    An empty `footer` omits the element rather than rendering an empty one:
    `footer` carries a top border and padding, so a blank string leaves a rule
    across the bottom of the page with nothing under it.
    """
    rows = "".join(f"<div><span>{e(k)}</span><code>{e(v)}</code></div>"
                   for k, v in meta)
    return (f"<title>{e(title)}</title>\n" + HEAD
            + f'''
<div class="wrap">
<header>
  <h1>{e(title)}</h1>
  <div class="meta">{rows}</div>
</header>
{sections}'''
            + (f"\n<footer>{footer}</footer>" if footer else "")
            + "\n</div>")
