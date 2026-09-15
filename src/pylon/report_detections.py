#!/usr/bin/env python3
"""Render the recommendations: what to turn on in this tenant.

The second of two documents. `report.py` answers "is the telemetry healthy";
this one answers "what should I switch on".

This page used to be a technique-coverage report with a deploy list in the
middle: the ATT&CK partition over 195 techniques, an 82-row unaddressed
bucket, an 82-row per-technique detail table, and one row per Microsoft rule
template whose tables held data. The deploy list went from 119 rows to 72 by
filtering on the connector each template declares, and 72 templates covering
37 techniques is still not a decision -- it ranks Microsoft's catalogue rather
than naming something to do.

So the page is two questions now, both with an answer a person can carry out:

    Content Hub   which solutions to enable, update, install or check
    Enable rules  detections installed and never switched on
    Telemetry     which tables this tenant could produce and does not

Defender plans are deliberately NOT here. They are measured and rendered by the
health report, and a plan that is off is a state of the tenant rather than a
decision about content. Carrying it in both places is the same one-page-two-
arguments problem that splitting these reports was meant to fix.

The sections that were removed are coverage MEASUREMENT, not recommendation.
They belong with the health report, and leaving them here made the page argue
about 195 techniques while the actionable content was eight solutions that are
installed and delivering nothing. The old renderer is preserved in git history
if that material needs a home.

A renderer, not a source of truth. Every figure comes from `analysis.json` and
`recommendations.json`; nothing is recomputed here.
"""

from __future__ import annotations

import collections
import json
import sys

from .reportkit import e, page

OUT = "content_hub_recommendations.html"
# Renamed from detection_recommendations.html. The page is the Content Hub
# work list -- install the solution, then create the rules -- and the old
# name said "detections", which is what the OTHER report is about. A run in
# a folder that has one leaves it behind untouched; .gitignore still covers
# the old name so a stale copy cannot be committed by accident.

# The verdict a row carries, and how it reads. `enable` and `remove` are the
# red ones because both mean something installed is not doing what it looks
# like it is doing.
ACTION_CLASS = {"remove": "none", "connect": "none", "update": "partial",
                "enable": "partial",
                "install": "partial", "review": "void", "none": "ok"}
ACTION_WORD = {"remove": "remove", "connect": "connect data", "update": "update",
               "enable": "enable detections",
               "install": "install", "review": "unproven", "none": "nothing to do"}


def build(a: dict, rec: dict | None) -> str:
    solutions = (rec or {}).get("solutions", [])
    acts = collections.Counter(x["action"] for x in solutions)

    def stat(n, label):
        return (f'<div class="stat"><span class="stat__n">{n}</span>'
                f'<span class="stat__l">{e(label)}</span></div>')

    # ---- Content Hub -------------------------------------------------------
    if not rec:
        hub = '<p class="muted">No recommendations document was produced.</p>'
    else:
        rows = "".join(f"""
      <tr>
        <td>{e(x['display_name'])}"""
                       f"""{'<div class="rule-names">not installed</div>' if not x['installed'] else ''}</td>
        <td><span class="chip chip--{ACTION_CLASS[x['action']]}">{e(ACTION_WORD[x['action']])}</span></td>
        <td class="num">{e(x.get('version_installed') or '') or '&mdash;'}</td>
        <td class="num">{e(x.get('version_available') or '') or '&mdash;'}</td>
        <td class="num">{x.get('analytics_rules') or 0}</td>
        <td class="detail">{e(x['action_detail'])}</td>
      </tr>""" for x in solutions)
        hub = f"""
      <div class="stat-row">
        {stat(acts.get('enable', 0), 'delivering, nothing enabled')}
        {stat(acts.get('connect', 0), 'installed, delivering nothing')}
        {stat(acts.get('update', 0), 'behind the catalogue')}
        {stat(acts.get('install', 0), 'worth installing')}
        {stat(acts.get('remove', 0), 'installed for a product not here')}
        {stat(acts.get('review', 0), 'this scan could not judge')}
        {stat(acts.get('none', 0), 'current and delivering')}
      </div>
      <div class="scroll"><table>
        <thead><tr><th>Solution</th><th>Do</th><th>Installed</th><th>Available</th>
            <th>Rules</th><th>Why</th></tr></thead>
        <tbody>{rows}</tbody>
      </table></div>
      <p class="note"><em>Unproven</em> means this scan could not judge the solution. It is not a clean bill.</p>"""

    # ---- rules installed but never switched on ------------------------------
    # Installing a solution does not enable its detections. Each one is created
    # by hand from Analytics > Rule templates, so a workspace can carry 306 rule
    # templates and run one. Nothing else in this report says that, and it is
    # the largest gap between what is installed and what is watching.
    #
    # Only solutions whose data is ARRIVING appear. A rule enabled over a table
    # with nothing in it runs on schedule and finds nothing, which is the
    # never-fires rule the health report already counts.
    live_sol = [x for x in solutions
                if x.get("alignment") == "fed" and (x.get("analytics_rules") or 0)]
    shipped = sum(x["analytics_rules"] for x in live_sol)
    on = sum(x.get("rules_enabled") or 0 for x in live_sol)
    if live_sol:
        rule_rows = "".join(f"""
      <tr>
        <td>{e(x['display_name'])}</td>
        <td class="num">{x['analytics_rules']}</td>
        <td class="num">{x.get('rules_enabled') or 0}</td>
        <td class="detail">{e(x.get('collects_from') or '')}</td>
      </tr>""" for x in sorted(live_sol, key=lambda v: -v["analytics_rules"]))
        enable = f"""
      <div class="stat-row">
        {stat(shipped, 'rule templates whose data is arriving')}
        {stat(on, 'of them switched on')}
        {stat(shipped - on, 'installed and never enabled')}
      </div>
      <div class="scroll"><table>
        <thead><tr><th>Solution</th><th>Rule templates</th><th>Enabled</th>
            <th>Data source</th></tr></thead>
        <tbody>{rule_rows}</tbody>
      </table></div>
      <p class="note">Create each one in <strong>Analytics &rarr; Rule templates</strong>. Only solutions whose data is arriving are listed.</p>"""
    else:
        enable = ('<p class="note">No solution is both delivering data and '
                  'shipping analytics rules.</p>')

    # There was an "Ingestion" section here listing tables a resource in this
    # tenant would emit and nothing is sending. It is gone.
    #
    # The health report already answers that question in its Ingestion gaps
    # table, from the same `coverage_gaps` rows, with two columns this one did
    # not have: when the table last received anything, and which analytics
    # rules the gap blocks. This one filtered to tables absent from the window
    # and so showed a SMALLER number for what read as the same question --
    # seven there, four here, with nothing on either page reconciling them.
    #
    # Two tables answering one question with two numbers is worse than one
    # table. The data question belongs to the telemetry report; this report is
    # the Content Hub work list: install the solution, then create the rules.

    generated = (rec or {}).get("generated_at") or a.get("generated_at") or ""
    sections = f"""
<section class="block">
  <div class="eyebrow">Content Hub</div>
  <h2>{len(solutions)} solutions assessed, {sum(n for a, n in acts.items() if a != "none")} need an action</h2>
  {hub}
</section>

<section class="block">
  <div class="eyebrow">Rule templates</div>
  <h2>{shipped - on} of {shipped} rule templates were never turned into an analytics rule</h2>
  {enable}
</section>
"""

    return page(
        "Content Hub Recommendations",
        [("workspace", a.get("workspace") or "?"),
         ("generated", str(generated)[:19].replace("T", " ")),
         ("solutions", f"{len(solutions)} assessed")],
        sections)


def main() -> int:
    with open("analysis.json", encoding="utf-8") as f:
        analysis = json.load(f)
    try:
        with open("recommendations.json", encoding="utf-8") as f:
            rec = json.load(f)
    except FileNotFoundError:
        rec = None
    # The recommendations are derived from one specific scan. Rendering them
    # against a newer analysis.json would show a work list computed from
    # telemetry that has since changed, with nothing on the page saying so.
    if rec and rec.get("analysis_generated_at") != analysis.get("generated_at"):
        print("REFUSED: recommendations.json was built from a different scan "
              f"({rec.get('analysis_generated_at')}) than analysis.json "
              f"({analysis.get('generated_at')}). Re-run the scan.",
              file=sys.stderr)
        return 2
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(build(analysis, rec))
    # Indented and verbless, so under `pylon analyze` it lands as another
    # line in the scan's WROTE block rather than restating the verb.
    print(f"  {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
