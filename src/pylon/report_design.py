#!/usr/bin/env python3
"""Render a design run's detections as a document a person can read.

The third page, and the one that was missing. `report.py` answers "is the
telemetry healthy" and `report_detections.py` answers "what should I switch on";
both describe a TENANT. This one describes what a `design` run produced.

Until now a five-minute run left a directory of .kql files and a report.json.
The query was in one file, the technique it claims in another, and the reason
that technique fits in a YAML catalogue the reader has no cause to open. Nothing
put the three next to each other, so the only way to judge a detection was to
already know the answer.

That gap had a cost beyond convenience. Asked how the operation-to-technique
mapping gets reviewed, the honest answer was that someone reads 78 abstract rows
of YAML and disagrees where they can -- which is not a review, it is an audit
with no context. Reading a query, the operation it fires on, and two sentences
on why it matters and why it is mapped that way is an ordinary engineering
judgment. This page is the unit that makes that judgment possible.

Every detection carries BOTH rationales, because they answer different
questions and either alone is unreviewable:

    why it matters      the run's own account of what the operation does
    why this technique  the curated basis from table-techniques.yaml

A renderer, not a source of truth. Every figure comes from the report; nothing
is recomputed, and where the catalogue and the run disagree the page shows both
rather than picking one.
"""

from __future__ import annotations


from .reportkit import e, page, plural

OUT = "detections.html"


def _technique_names() -> dict[str, str]:
    """ATT&CK id -> name. Read from the vendored index rather than the YAML
    catalogue so the page renders without the `design` extra installed."""
    from .knowledge import technique_names

    return technique_names()


def _bases(table: str) -> dict[str, str]:
    """technique -> the curated argument for it on this table.

    Guarded: the index loader needs PyYAML, which the base install deliberately
    does not carry. Without it the page still renders and simply omits the
    mapping argument, rather than refusing to render at all.
    """
    # Returns the LOOKUP, not a dict. Keying by technique alone kept whichever
    # claim came last: `T1685.002` on AzureActivity has three, and a diagnostic
    # settings detection was rendered with the SQL auditing argument under a
    # heading that says "why this technique".
    try:
        from .catalog.table_techniques import basis_for
    except ImportError:
        return lambda _operation, _technique: ""
    return lambda operation, technique: basis_for(table, operation, technique)


def _disagreement(table: str, operation: str, claimed: str) -> tuple[str, ...]:
    """What the catalogue pins for this operation when the run chose otherwise."""
    try:
        from .catalog.table_techniques import second_opinion
    except ImportError:
        return ()
    return second_opinion(table, operation, claimed)


def _detail(term: str, body: str) -> str:
    return f"<dt>{e(term)}</dt><dd>{e(body)}</dd>" if body else ""


# A measured verdict, in the page's own chip vocabulary. `dead` and `over` are
# defects; `no-ground-truth` and `aggregates` are the workspace saying it could
# not settle the question, which must never render as either a pass or a fault.
_VERDICT_CLASS = {
    "exact": "ok", "fires": "ok",
    "under": "partial", "aggregates": "partial",
    "dead": "none", "over": "none", "error": "none",
    # Neither a fault nor a pass: the query narrows past the operation and
    # nothing in the window had that shape. Rendered `void` like
    # `no-ground-truth`, because both are the workspace declining to settle it.
    "no-match": "void",
    "no-ground-truth": "void",
}
_VERDICT_WORD = {
    "exact": "matches real events",
    "under": "filters, deliberately or not",
    "aggregates": "summarises, not comparable",
    "dead": "matched nothing real",
    "over": "over-matches",
    "error": "did not run",
    "no-match": "no event matched what it asks for",
    "no-ground-truth": "no events to test against",
}


def _one(vector: dict, det: dict | None, names: dict, bases: dict) -> str:
    """One detection: what it fires on, the query, and both rationales."""
    technique = (det or {}).get("detection", {}).get(
        "mitre_technique") or vector.get("mitre_technique", "")
    label = names.get(technique, "")
    table = vector.get("log_table", "")
    operation = vector.get("operation", "")

    chips = [f'<span class="chip chip--void">{e(operation)}</span>']
    if technique and technique != "unmapped":
        chips.append(f'<span class="chip chip--ok">{e(technique)}'
                     + (f" &middot; {e(label)}" if label else "") + "</span>")
    else:
        chips.append('<span class="chip chip--partial">no technique</span>')
    if det is not None and not det.get("valid", True):
        chips.append('<span class="chip chip--none">did not validate</span>')
    # PLANNED, NOT BUILT. A plan enumerates a service's whole vocabulary and
    # `--pick` builds a few; the rest reach this page as proposals. Nothing said
    # so -- the query block was simply omitted for them -- so a run that built 5
    # of 25 rendered 20 cards identical to a built detection minus its code, and
    # read as twenty detections that had lost their queries.
    if det is None:
        chips.append('<span class="chip chip--partial">planned &mdash; '
                     'not built in this run</span>')

    # What was MEASURED, beside what was written. The page used to show only
    # `valid`, which answers "is this well formed" -- and a detection that
    # parses, deploys and never fires is exactly the thing `design verify`
    # exists to catch. It was caught, written into report.json, handed to this
    # renderer in its own argument, and dropped on the floor.
    graded = (det or {}).get("verification") or {}
    verdict = graded.get("verdict") or ""
    if verdict:
        # Prefixed "measured:" because the plain-English wording alone did not
        # read as a verdict -- a reviewer looking directly at this page for one
        # reported there was none. A chip that has to be recognised as a
        # measurement should say it is one.
        chips.append(f'<span class="chip chip--{_VERDICT_CLASS.get(verdict, "void")}">'
                     f'measured: {e(_VERDICT_WORD.get(verdict, verdict))}</span>')

    # "deployed" is the only one of the three that is a measurement. The other
    # two are said plainly rather than left as a bare word nobody can read.
    # What was measured, and nothing after it. "Received no data" is a fact;
    # "the workspace does not hold this table" was a conclusion, and the wrong
    # one -- a quiet resource and one logging to AzureDiagnostics look the same
    # from here. The reasoning belongs in this comment, not on the page.
    basis_words = {
        "deployed": "Had data in the scan window.",
        "catalogue": "No data in the scan window.",
        "unchecked": "No scan was run.",
    }
    # `table_basis` is a property of a BUILT detection. Defaulting an unbuilt
    # vector to "unchecked" made every one of them report "No scan was run." on
    # a run where a scan had been run and had answered for the built ones.
    table_note = ("Not built in this run, so nothing was measured."
                  if det is None else
                  basis_words.get(det.get("table_basis", "unchecked"), ""))

    # The verdict's own sentence, and every warning the validator raised.
    # `warnings` was populated on every detection and read by nothing outside
    # the eval harness, so a run whose column list could not be fetched said
    # "could not be fetched, verify before deploying" in the object and
    # "every query passed the validator" on the page.
    notes = []
    if graded.get("detail"):
        notes.append(e(graded["detail"]))
    offline = (det or {}).get("offline_check") or {}
    if offline.get("ran") and not offline.get("ok"):
        notes.append("The KQL engine refused this query.")
    for warning in (det or {}).get("warnings") or []:
        notes.append(e(warning))
    warn_html = "" if not notes else (
        '<div class="more">' + "<br>".join(notes) + "</div>")

    pinned = _disagreement(table, operation, technique)
    clash = ""
    if pinned:
        # "Catalogue" is our word for a file the reader has never heard of.
        # Pylon is the thing they ran, so Pylon is what disagreed with them.
        clash = (f'<p class="note">Pylon maps {e(operation)} to '
                 f'{e(", ".join(pinned))}. This run chose '
                 f'{e(technique or "no technique")}.</p>')

    kql = (det or {}).get("detection", {}).get("kql", "")
    if kql:
        query = f'<div class="scroll"><pre class="kql">{e(kql)}</pre></div>'
    elif det is None:
        query = ('<p class="note">No query: this vector was planned but not '
                 'built. Re-run <code>design detections</code> with this '
                 'number in <code>--pick</code> to build it.</p>')
    else:
        # Built, and produced nothing. A different failure from not building,
        # and collapsing the two is what this whole block exists to stop.
        query = ('<p class="note">This detection was built but produced no '
                 'query.</p>')

    details = "".join([
        _detail("why it matters", " ".join(str(vector.get("rationale", "")).split())),
        _detail("why this technique",
                " ".join(bases(operation, technique).split())),
        _detail("alert condition", str(vector.get("alert_condition", ""))),
        _detail("tuning", (det or {}).get("detection", {}).get("tuning_guidance", "")),
        _detail("most likely false positive",
                (det or {}).get("detection", {}).get("false_positive_notes", "")),
        _detail("table", table_note),
    ])

    return f"""
<section class="block det">
  <div class="eyebrow">{e(vector.get("priority", ""))}</div>
  <h2>{e(vector.get("name", operation))}</h2>
  <p class="chips">{"".join(chips)}</p>
  {warn_html}
  {clash}
  {query}
  <dl class="method">{details}</dl>
</section>"""


def build(report: dict) -> str:
    """The whole page from one design run's report."""
    vectors = (report.get("analysis") or {}).get("attack_vectors") or []
    detections = report.get("detections") or []
    by_name = {d.get("detection", {}).get("vector_name"): d for d in detections}
    names = _technique_names()
    table = vectors[0].get("log_table", "") if vectors else report.get("service", "")
    bases = _bases(table)

    valid = sum(1 for d in detections if d.get("valid"))
    # Three states, never two. `deployed.py` is explicit that a table WITH data
    # proves the mode is in use, a table WITHOUT proves nothing at all -- an
    # idle vault and one logging to AzureDiagnostics are identical from here --
    # and no scan document means nobody looked. Counting the last two together
    # reports absence of evidence as evidence of absence, which is the one
    # mistake this whole codebase is arranged to prevent.
    quiet = sum(1 for d in detections if d.get("table_basis") == "catalogue")
    unchecked = sum(1 for d in detections if d.get("table_basis") == "unchecked")
    clashes = sum(
        1 for v in vectors
        if _disagreement(v.get("log_table", ""), v.get("operation", ""),
                         (by_name.get(v.get("name")) or {}).get("detection", {})
                         .get("mitre_technique") or v.get("mitre_technique", ""))
    )
    techniques = sorted({
        d.get("detection", {}).get("mitre_technique")
        for d in detections
        if d.get("detection", {}).get("mitre_technique") not in (None, "", "unmapped")
    })

    # The second line used to explain how to read the page -- that each block
    # carries a query and two arguments, and that disagreeing changes the
    # mapping in one line. Both were wrong to print. The first describes what
    # the reader can already see, and the second is an instruction about editing
    # a catalogue file, which means nothing to anyone who did not build this.
    #
    # What a reader needs before trusting the page is what is WRONG with it, so
    # the line carries the caveats and nothing else. Silence where there are
    # none would read as a page with nothing to say, so the clean case states
    # the one limit that always applies: the validator checks the query, never
    # whether it fires.
    def says(n: int, verb: str, rest: str) -> str:
        """`1 detection names ...`, `33 detections name ...`. plural() agrees the
        noun with the number and the verb was left behind, so the page said
        "33 detections names a table"."""
        return f"{plural(n, 'detection')} {verb}{'s' if n == 1 else ''} {rest}"

    caveats = []
    if len(detections) - valid:
        caveats.append(f"{plural(len(detections) - valid, 'detection')} failed "
                       "the query validator.")
    if clashes:
        caveats.append(says(clashes, "use",
                            "a different technique than Pylon's own mapping."))
    if quiet:
        caveats.append(f"{e(table)} had no data in the scan window.")
    if unchecked:
        caveats.append("No scan was run, so the table is unconfirmed.")
    # `valid` answers "is it well formed". It was the only thing this page said,
    # and it was said as though it meant "it works" -- while `design verify` had
    # already measured that ten of them matched nothing real and written the
    # answer into the same file this function is reading.
    graded = [(d.get("verification") or {}).get("verdict") for d in detections]
    measured = [v for v in graded if v]
    defects = sum(1 for v in measured if v in ("dead", "over", "error"))
    ungraded = sum(1 for v in measured if v == "no-ground-truth")
    warned = sum(1 for d in detections if d.get("warnings"))

    if defects:
        caveats.insert(0, f"{plural(defects, 'detection')} matched nothing real, "
                          "over-matched, or failed to run.")
    if ungraded:
        caveats.append(f"{plural(ungraded, 'detection')} had no events to test "
                       "against, which is not a pass.")
    unmatched = sum(1 for v in measured if v == "no-match")
    if unmatched:
        caveats.append(f"{plural(unmatched, 'detection')} matched no event, "
                       "while filtering on more than the operation -- either "
                       "the behaviour did not happen here or the filter is "
                       "wrong, and counting the operation cannot tell which.")
    if warned:
        caveats.append(f"{plural(warned, 'detection')} carries a validator "
                       "warning; see the detection.")
    # "matched real events" was said for an `under` verdict, which means the
    # detection matched FEWER rows than the operation produced and nobody can
    # say whether that filtering was deliberate. Technically true, read as a
    # pass. A clean-room reviewer saw "2 detections matched real events" above
    # two detections at x0.25 and x0.10 of expected and called it a
    # contradiction, correctly.
    exact = sum(1 for v in measured if v == "exact")
    filtered = sum(1 for v in measured if v == "under")
    summarised = sum(1 for v in measured if v == "aggregates")
    if exact:
        caveats.append(f"{plural(exact, 'detection')} matched every event of "
                       "its operation.")
    if filtered:
        caveats.append(f"{plural(filtered, 'detection')} matched fewer rows "
                       "than its operation produced, which may be deliberate "
                       "filtering or too narrow a query -- see the ratio on "
                       "each.")
    if summarised:
        caveats.append(f"{plural(summarised, 'detection')} summarises, so its "
                       "rows are not comparable to an event count.")

    second = " ".join(caveats) if caveats else (
        "Every query passed the validator. It checks syntax and field names, "
        "not whether a rule fires -- run `pylon design verify` to measure that."
    )

    lead = f"""
<section class="block block--lead">
  <p class="lead__1">{plural(len(detections), "detection")} over
     {e(", ".join(sorted({v.get("log_table", "") for v in vectors if v.get("log_table")})) or table)},
     mapped to {plural(len(techniques), "ATT&amp;CK technique")}.</p>
  <p class="lead__2">{second}</p>
</section>"""

    # One card per vector, joined to its detection BY NAME -- and a model that
    # renames the vector breaks that join silently. It happened: three
    # detections rendered with their rationale and alert condition and no query
    # and no verdict, while report.json held both. The engine now stamps
    # `vector_name` so the key is Pylon's rather than the model's, and this is
    # the second line of defence, because a page that drops a query it was
    # given is worse than a page that admits it has an extra one.
    body = "".join(
        _one(v, by_name.get(v.get("name")), names, bases) for v in vectors
    )
    claimed = {v.get("name") for v in vectors}
    orphans = [d for d in detections
               if d.get("detection", {}).get("vector_name") not in claimed]
    for orphan in orphans:
        name = orphan.get("detection", {}).get("vector_name") or ""
        body += _one({"name": name, "log_table": table,
                      "operation": orphan.get("operation", ""),
                      "mitre_technique": orphan.get("detection", {})
                      .get("mitre_technique", ""),
                      "priority": orphan.get("priority", ""),
                      "rationale": orphan.get("rationale", "")},
                     orphan, names, bases)
    return page(
        "Detections",
        [("platform", report.get("platform", "?")),
         ("log table", table or "?"),
         ("detections", str(len(detections))),
         ("techniques", str(len(techniques)))],
        lead + body,
    )


def write(report: dict, out_dir) -> list[str]:
    """Write the page beside the .kql files. Returns the paths written.

    HTML always; PDF only where WeasyPrint imports. It is an optional extra
    rather than a dependency because the base install is deliberately one
    package, and because on some platforms it wants system libraries that a
    Sentinel engineer should not have to install to read a report.

    Nothing is lost when it is absent. The stylesheet carries real print rules
    -- forced light colours, no detection split across a page break, the query
    wrapped rather than in a scroller -- so Ctrl+P in any browser produces the
    same document with no dependency at all. The extra buys headless
    generation, not a better page.
    """
    from pathlib import Path

    out = Path(out_dir)
    html = build(report)
    html_path = out / OUT
    html_path.write_text(html, encoding="utf-8")
    written = [str(html_path)]

    try:
        from weasyprint import HTML
    except ImportError:
        return written
    pdf_path = out / OUT.replace(".html", ".pdf")
    # base_url lets the print stylesheet resolve; the page has no local assets,
    # so a failure here can only be the renderer itself. A report that exists
    # must not be lost to a PDF that could not be made.
    try:
        HTML(string=html, base_url=str(out)).write_pdf(str(pdf_path))
    except Exception as exc:  # noqa: BLE001 - any renderer fault, same answer
        print(f"  (no PDF: {type(exc).__name__}: {exc})")
        return written
    written.append(str(pdf_path))
    return written
