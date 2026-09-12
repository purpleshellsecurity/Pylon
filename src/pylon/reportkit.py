#!/usr/bin/env python3
"""What the two reports share: the stylesheet, and the vocabulary of a verdict.

There are two documents now -- `report.py` renders health and telemetry,
`report_detections.py` renders what to deploy -- and they have to look like
one product and use one set of words for the same thing. Keeping the CSS and
the verdict labels in one place is what stops them drifting: a chip that means
"covered" in one report and something else in the other is the confusion this
split was meant to end.

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
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Serif:wght@400;500;600&display=swap">
<style>
:root {
  --paper:#FBFCFD; --raise:#FFFFFF; --ink:#0F1620; --slate:#5A6673;
  --rule:#DDE3E9; --rule-soft:#EDF1F4;
  --ok:#1F7A5C; --ok-bg:#E6F2ED;
  --partial:#B0741A; --partial-bg:#FaF0DF;
  --none:#A33A32; --none-bg:#F9E9E7;
  --void:#8892A0; --void-bg:#EEF1F4;
  --measure:68ch;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --paper:#0C1218; --raise:#131C24; --ink:#E7ECF1; --slate:#96A3B0;
    --rule:#26313C; --rule-soft:#1B242D;
    --ok:#5FBE9A; --ok-bg:#13291F;
    --partial:#E0A64E; --partial-bg:#2C2214;
    --none:#E3766B; --none-bg:#2E1A18;
    --void:#7A8794; --void-bg:#1A222A;
  }
}
:root[data-theme="dark"] {
  --paper:#0C1218; --raise:#131C24; --ink:#E7ECF1; --slate:#96A3B0;
  --rule:#26313C; --rule-soft:#1B242D;
  --ok:#5FBE9A; --ok-bg:#13291F;
  --partial:#E0A64E; --partial-bg:#2C2214;
  --none:#E3766B; --none-bg:#2E1A18;
  --void:#7A8794; --void-bg:#1A222A;
}
* { box-sizing:border-box; }
body {
  background:var(--paper); color:var(--ink);
  font-family:"IBM Plex Sans", system-ui, -apple-system, sans-serif;
  font-size:16px; line-height:1.6; margin:0;
  -webkit-font-smoothing:antialiased;
}
.wrap { max-width:min(1080px, 92vw); margin:0 auto; padding:0 0 6rem; }
h1,h2,h3,h4 { font-family:"IBM Plex Serif", Georgia, serif; text-wrap:balance;
  margin:0; font-weight:500; letter-spacing:-.01em; }
h1 { font-size:clamp(2.1rem,4.4vw,3.1rem); line-height:1.1; }
h2 { font-size:1.55rem; }
h3 { font-size:1.06rem; }
h4 { font-size:.95rem; font-family:"IBM Plex Sans",sans-serif; font-weight:600; }
p { margin:0; max-width:var(--measure); }
code { font-family:"IBM Plex Mono", ui-monospace, monospace; font-size:.86em; }
.muted { color:var(--slate); }
.eyebrow { font-family:"IBM Plex Mono",monospace; font-size:.72rem;
  letter-spacing:.14em; text-transform:uppercase; color:var(--slate); }

/* masthead */
/* Theme toggle. Fixed rather than placed in the header because the two
   reports build their headers separately -- putting it in HEAD means both get
   it and neither can drift. */
.themetoggle { position:fixed; top:1.1rem; right:1.1rem; z-index:10;
  font-family:"IBM Plex Mono",monospace; font-size:.68rem; letter-spacing:.06em;
  text-transform:uppercase; color:var(--slate); background:var(--raise);
  border:1px solid var(--rule); border-radius:4px; padding:.4rem .7rem;
  cursor:pointer; line-height:1; }
.themetoggle:hover { color:var(--ink); border-color:var(--slate); }
@media print { .themetoggle { display:none; } }

/* One line under the header and nothing else near it. The lead section used
   to add a 2px border of its own 3.5rem below this one, so the top of every
   report was a grey rule, a gap, then a heavy black rule -- two dividers
   dividing the same thing. */
header { border-bottom:1px solid var(--rule); padding:4.5rem 0 2.5rem;
  margin-bottom:2.75rem; display:flex; flex-direction:column; gap:1.4rem; }
.meta { display:flex; flex-wrap:wrap; gap:0 2.5rem; font-family:"IBM Plex Mono",monospace;
  font-size:.78rem; color:var(--slate); }
.meta div { display:flex; gap:.5rem; padding:.15rem 0; }
/* Label bold and light, value plain and dark. The contrast carries which is
   which, so neither needs to be bigger than the other.

   It used to be the other way round twice over: the value is a <code>, and the
   global `code` rule shrank it to .86em, so at .78rem the VALUE rendered
   smaller than its own label -- while the label was ALSO the darker of the two.
   The thing you are meant to read was both smaller and quieter. `.meta` sets
   the mono family itself, so the <code> wrapper was only ever contributing
   the shrink. */
.meta span:first-child { font-weight:600; color:var(--slate); opacity:.75; }
.meta code { font-size:inherit; font-weight:400; color:var(--ink); }

section.block { display:flex; flex-direction:column; gap:1.25rem;
  padding-bottom:3.25rem; margin-bottom:3.25rem; border-bottom:1px solid var(--rule-soft); }
section.block:last-of-type { border-bottom:0; }

/* the motif: a partition drawn to scale */
.bar { display:flex; height:12px; border-radius:2px; overflow:hidden; gap:2px; background:transparent; }
.seg { display:block; }
.seg--ok { background:var(--ok); } .seg--partial { background:var(--partial); }
.seg--none { background:var(--none); } .seg--void { background:var(--void); opacity:.45; }
.key { list-style:none; padding:0; margin:0; display:flex; flex-wrap:wrap; gap:.4rem 1.6rem;
  font-size:.85rem; color:var(--slate); }
.key li { display:flex; align-items:center; gap:.45rem; }
.dot { width:8px; height:8px; border-radius:50%; flex:none; }
.dot--ok { background:var(--ok); } .dot--partial { background:var(--partial); }
.dot--none { background:var(--none); } .dot--void { background:var(--void); opacity:.5; }
.k-n { font-family:"IBM Plex Mono",monospace; font-variant-numeric:tabular-nums;
  color:var(--ink); font-weight:500; }

/* No border. The header's line already separates this from what is above,
   and the serif lead line is distinct enough without being fenced in. */
.block--lead { padding-top:0; }
.lead__1 { font-family:"IBM Plex Serif",Georgia,serif; font-size:1.5rem;
           line-height:1.3; margin:0 0 .35rem; max-width:34ch; }
.lead__2 { font-size:.95rem; color:var(--slate); margin:0 0 1.4rem; max-width:52ch; }
/* --rule-soft, not --rule. A divider INSIDE a block should be lighter than
   the ones between blocks, or the page reads as a stack of equal fragments
   with no hierarchy. */
.lead__do { border-top:1px solid var(--rule-soft); padding-top:1.1rem; }
.lead__do h3 { font-family:"IBM Plex Mono",monospace; font-size:.68rem;
               letter-spacing:.09em; text-transform:uppercase; color:var(--slate);
               margin:0 0 .35rem; font-weight:600; }
/* The axis, on its own line under the heading. It used to be an em-dashed
   clause inside the heading, which is a construction almost nobody writes by
   hand. A short sentence does the same job. */
/* A heading row inside a table, so a grouped table reads as its groups. The
   XDR table counts families in its own heading; without this the reader had a
   Family column repeated on twenty-two rows and no visible grouping. */
tr.grouprow th { text-align:left; font-family:"IBM Plex Mono",monospace;
                 font-size:.68rem; letter-spacing:.09em; text-transform:uppercase;
                 color:var(--slate); font-weight:600; padding-top:1.1rem;
                 border-bottom:1px solid var(--rule); }
tr.grouprow:first-child th { padding-top:.2rem; }
tr.grouprow th .more { text-transform:none; letter-spacing:0; font-weight:400;
                       margin-left:.6rem; }
.lead__axis { margin:0 0 .8rem; font-size:.8rem; color:var(--slate); }
.lead__do ol { margin:0; padding-left:1.35rem; }
.lead__do li { margin-bottom:.55rem; font-size:.95rem; }
.lead__do li span { display:block; font-size:.8rem; color:var(--slate); margin-top:.15rem; }
.lead__do li .lead__cost { color:var(--none); font-weight:500; }
/* Three tiers, so a reader can tell a finding from a reference table without
   reading either. Everything used to be one weight in one long scroll: a
   22-row XDR table with mostly-zero rows carried the same visual authority as
   the summary. */
/* Colour is spent where a decision is made, and nowhere else. Every section
   used to carry green/amber/red chips, so a red chip in the summary competed
   with a red chip in a reference table twelve screens down -- and when
   everything is emphasised nothing is. Reference tiers keep the shape of a
   chip and drop its colour. */
/* The reference tier. These sections carry a finding in the heading and a
   reference dump in the table, so only the table is demoted.

   It used to fade the whole section -- opacity .82 on the block, the h2
   dropped from 1.55rem serif to 1.05rem sans, the eyebrow faded again. Three
   sections that state findings were then styled as footnotes, and the page
   visibly changed typographic scale two thirds of the way down. Headings now
   match every other section; the smaller table is what marks the tier. */
.block--ref .chip { background:var(--rule-soft); color:var(--slate); }
.block--ref table { font-size:.82rem; }
.block--ref .scroll, .block--ref .note { opacity:.86; }

.deadlist { margin:0 0 1.4rem; }
.dead { padding:.7rem 0; border-bottom:1px solid var(--rule-soft); }
.dead:last-child { border-bottom:0; }
.dead h4 { margin:0 0 .2rem; font-size:.95rem; font-weight:600; }
.method { display:grid; grid-template-columns:auto 1fr; gap:.3rem 1.1rem;
          margin:0 0 1rem; font-size:.85rem; max-width:60ch; }
.method dt { font-family:"IBM Plex Mono",monospace; font-size:.7rem;
             letter-spacing:.06em; text-transform:uppercase; color:var(--slate); }
.method dd { margin:0; }
.method__note { font-size:.82rem; color:var(--slate); max-width:66ch; margin:0 0 1rem; }
.lead__caveat { margin:1.1rem 0 0; font-size:.8rem; color:var(--slate);
                border-left:2px solid var(--partial); padding-left:.7rem; }
.chip { display:inline-block; font-family:"IBM Plex Mono",monospace; font-size:.68rem;
  padding:.14rem .45rem; border-radius:3px; letter-spacing:.02em; white-space:nowrap; }
.chip--ok { background:var(--ok-bg); color:var(--ok); }
.chip--partial { background:var(--partial-bg); color:var(--partial); }
.chip--none { background:var(--none-bg); color:var(--none); }
.chip--void { background:var(--void-bg); color:var(--void); }

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

.scroll { overflow-x:auto; }
table { border-collapse:collapse; width:100%; font-size:.87rem; min-width:640px; }
th { text-align:left; font-family:"IBM Plex Mono",monospace; font-weight:500;
  font-size:.7rem; letter-spacing:.1em; text-transform:uppercase; color:var(--slate);
  padding:0 1rem .6rem 0; border-bottom:1px solid var(--rule); white-space:nowrap; }
td { padding:.72rem 1rem .72rem 0; border-bottom:1px solid var(--rule-soft);
  vertical-align:top; }
td.num { font-family:"IBM Plex Mono",monospace; font-variant-numeric:tabular-nums; }
td.cats code { display:inline-block; margin:0 .3rem .2rem 0; color:var(--slate); }
td.detail { color:var(--slate); font-size:.82rem; }
.more { font-size:.75rem; color:var(--slate); }
.rule-names { font-size:.76rem; color:var(--slate); margin-top:.2rem; }
/* Microsoft's own sentence about what the detection watches. Carried because
   the table check cannot say whether the thing it watches exists here. */
.tpl-desc { font-size:.76rem; color:var(--slate); margin-top:.3rem;
            max-width:52ch; line-height:1.45; }
.unlock strong { font-family:"IBM Plex Mono",monospace; }

.stat-row { display:flex; flex-wrap:wrap; gap:2.5rem; padding:.4rem 0 .2rem; }
.stat { display:flex; flex-direction:column; }
.stat__n { font-family:"IBM Plex Mono",monospace; font-size:1.75rem; font-weight:500;
  font-variant-numeric:tabular-nums; line-height:1.2; }
.stat__l { font-size:.76rem; color:var(--slate); }
.techlist { list-style:none; padding:0; margin:0; display:flex; flex-direction:column; gap:.35rem;
  font-size:.87rem; max-width:var(--measure); }
.techlist li { display:flex; gap:.7rem; align-items:baseline;
  border-bottom:1px solid var(--rule-soft); padding-bottom:.35rem; }
.techlist span:nth-child(2) { flex:1; color:var(--slate); }
.note { font-size:.85rem; color:var(--slate); }
/* The basis line under a priced table. Mono and quiet: it is the footnote
   that makes the figure above it checkable, not a finding of its own.
   `max-width:none` because the global `p` measure would wrap three short
   clauses onto three lines. */
.pricebar { display:flex; gap:.5rem; align-items:baseline; flex-wrap:wrap;
  font-family:"IBM Plex Mono",monospace; font-size:.78rem; color:var(--slate);
  max-width:none; }
.pricebar strong { color:var(--ink); font-weight:500; }

.limits { display:flex; flex-direction:column; gap:0; }
.limit { padding:1.15rem 0; border-top:1px solid var(--rule-soft); }
.limit h4 { margin-bottom:.35rem; }
.limit div { font-size:.86rem; color:var(--slate); max-width:var(--measure); }
.limit .one { margin-top:.3rem; }
footer { border-top:1px solid var(--rule); padding-top:1.5rem; margin-top:3rem;
  font-size:.78rem; color:var(--slate); font-family:"IBM Plex Mono",monospace; }
@media (prefers-reduced-motion:reduce) { * { animation:none!important; transition:none!important; } }
/* ── the detections page ─────────────────────────────────────────────────── */
.chips { display:flex; flex-wrap:wrap; gap:.4rem; max-width:none; }
pre.kql { font-family:"IBM Plex Mono", ui-monospace, monospace; font-size:.8rem;
  line-height:1.55; margin:0; padding:1rem 1.1rem; background:var(--rule-soft);
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
    --paper:#FFFFFF; --raise:#FFFFFF; --ink:#0F1620; --slate:#4A5560;
    --rule:#C8D0D8; --rule-soft:#EDF1F4;
    --ok:#1F7A5C; --ok-bg:#E6F2ED; --partial:#B0741A; --partial-bg:#FaF0DF;
    --none:#A33A32; --none-bg:#F9E9E7; --void:#6C7783; --void-bg:#EEF1F4;
  }
  @page { margin:16mm 14mm; }
  body { font-size:10.5pt; }
  .wrap { max-width:none; width:100%; padding:0; }
  header { padding:0 0 1.2rem; margin-bottom:1.6rem; }
  h1 { font-size:22pt; }
  h2 { font-size:13pt; }
  section.block { break-inside:avoid; page-break-inside:avoid; padding:1.1rem 0; }
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


def plural(n, singular: str, many: str | None = None) -> str:
    """`1 window`, `3 windows`.

    The `(s)` habit is honest and it is also unmistakably machine output. A
    document a person wrote agrees its nouns with its numbers.
    """
    word = singular if n == 1 else (many or singular + "s")
    return f"{n:,} {word}"


def bar(segments) -> str:
    """The one recurring motif: a partition drawn to scale.

    Segments are (label, count, class). Zero-count segments are dropped rather
    than drawn as slivers that imply a presence they do not have.
    """
    live = [(lab, n, cls) for lab, n, cls in segments if n]
    total = sum(n for _, n, _ in live) or 1
    cells = "".join(
        f'<span class="seg seg--{cls}" style="flex:{n}" '
        f'title="{e(lab)}: {n}"></span>' for lab, n, cls in live)
    keys = "".join(
        f'<li><span class="dot dot--{cls}"></span>'
        f'<span class="k-n">{n}</span> {e(lab)}</li>' for lab, n, cls in live)
    return (f'<div class="bar" role="img" aria-label="'
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
