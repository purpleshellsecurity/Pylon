"""Transforms that must exist exactly once in the source tree.

Three issues (#52, #53, #54) were all the same shape: one fact written down
twice, drifting independently. Two are fixed; these guards keep them fixed,
because a second copy is added by someone who did not know the first existed —
which no code review reliably catches and a grep does.
"""

import re
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[1] / "src" / "pylon"
_PY = sorted(_SRC.rglob("*.py"))


def _hits(pattern: str) -> list[str]:
    """Files containing `pattern` in CODE. Comment text is stripped first: the
    comment explaining why there is only one registration named the call it was
    describing, and matched itself."""
    rx = re.compile(pattern)
    out = []
    for path in _PY:
        for line in path.read_text().splitlines():
            code = line.split("#", 1)[0]
            if rx.search(code):
                out.append(str(path.relative_to(_SRC)))
                break
    return sorted(set(out))


def test_the_slug_transform_is_written_once():
    """`library._slug` and `report.slugify` disagreed on the empty case — '' vs
    'unnamed' — and callers depend on BOTH, so a careless merge is a bug, not a
    tidy-up. One transform in text.py; the fallback is the caller's."""
    # `re.sub(..., "-")` specifically — catalog/__init__ RE.SPLITS on the same
    # character class to tokenize a name, which is a different operation.
    hits = _hits(r're\.sub\(r"\[\^a-z0-9\]\+",\s*"-"')
    assert hits == ["text.py"], f"the slug transform should exist once, found {hits}"


def test_the_yaml_str_representer_is_registered_once():
    """`yaml.add_representer(str, ...)` mutates the GLOBAL PyYAML dumper. Two
    modules each registering their own meant the winner was decided by import
    order — harmless while the two bodies agreed, and silent when they stopped."""
    hits = _hits(r"yaml\.add_representer\(")
    assert len(hits) == 1, f"expected one global registration, found {hits}"


@pytest.mark.parametrize(
    "value,expected_slug,expected_slugify",
    [("Azure Bastion", "azure-bastion", "azure-bastion"), ("", "", "unnamed"),
     (None, "", "unnamed"), ("!!!", "", "unnamed")],
)
def test_the_empty_case_behaviour_is_preserved(value, expected_slug, expected_slugify):
    """The whole risk of deduping these two: `catalog.table_techniques` filters on
    `if slug(o)`, so an 'unnamed' fallback there keeps every empty operation."""
    from pylon.text import slug, slugify

    assert slug(value) == expected_slug
    assert slugify(value) == expected_slugify


def test_the_graph_permission_catalog_is_read_once():
    """This vocabulary was vendored TWICE — `catalog/graph-permissions.json` and
    the `.gz` — and the harvests drifted 153 scopes apart. The PowerShell scope
    gate read the smaller one and rejected 163 real permissions, including
    `AuditLogsQuery-Entra.Read.All`, while `operation_grounding` handed the model
    the larger one. Its own docstring warns that a gate failing valid input is one
    people learn to ignore.

    One reader, so a second harvest cannot be introduced without this failing."""
    hits = _hits(r'"graph-permissions')
    assert hits == ["graph_permissions.py"], (
        f"the Graph permission catalog should be loaded in one module, found {hits}"
    )


def test_the_graph_permission_catalog_is_vendored_once():
    """The code guard above is only half of it: two data files carrying one
    vocabulary is the condition that produced the bug."""
    catalog = _SRC / "catalog"
    copies = sorted(p.name for p in catalog.glob("graph-permissions*"))
    assert copies == ["graph-permissions.json.gz"], (
        f"one harvest of the Graph permission reference, found {copies}"
    )


def test_the_operator_is_one_fact():
    """The KQL rules and `operation_match` both tell the model which operator to
    compare an operation string with, in the SAME prompt.

    They disagreed. The ARM rules said "filter on OperationNameValue using =~ for
    case-insensitive matching"; `operation_match("AzureActivity")` returned `==`
    from its unconsidered fallthrough. A model handed both picks one, and the one
    that loses produces a rule that matches nothing and looks healthy -- the exact
    failure the AuditLogs half of that function was written to stop.
    """
    import re

    from pylon.prompts import _KQL_RULES, _TABLE_RULES_KEY
    from pylon.services import all_tables, operation_column, operation_match

    checked = 0
    for table in sorted(all_tables()):
        column = operation_column(table)
        operator, _why = operation_match(table)
        # Only the chain that serves THIS table. Scanning every chain matched the
        # ARM line "use OperationNameValue ... not OperationName" against the
        # data-plane tables, whose column really is OperationName -- a substring
        # collision, and the wrong rule to judge them by.
        chain = _TABLE_RULES_KEY.get(table)
        rules = _KQL_RULES.get(chain, "")
        for line in rules.splitlines():
            # `\b` so OperationName does not match inside OperationNameValue.
            if not re.search(rf"\b{re.escape(column)}\b", line):
                continue
            stated = [s for pair in re.findall(r"using (=~|==)|(=~|==) for", line)
                      for s in pair if s]
            if not stated:
                continue
            checked += 1
            assert operator in stated, (
                f"the {chain} rules tell the model to use {stated} on {column}, "
                f"and operation_match({table!r}) returns {operator!r}. Both go "
                f"into the same prompt."
            )
    assert checked, "no rule line states an operator -- this check found nothing"


def test_no_asset_spells_an_operator_that_disagrees():
    """`test_the_operator_is_one_fact` scanned `_KQL_RULES` only, so the prompt
    ASSETS were free to disagree with it, and two did. The data-plane playbook
    hardcoded `=~` on OperationName where `operation_match` says `==`, and the
    Entra detection skeleton hardcoded `==` where it says `=~` -- the second is
    the exact silent-zero-rows failure `operation_match` was written to stop,
    sitting in the skeleton the model copies.

    Query skeletons now ask for __OPERATOR__ and cannot drift at all. A teaching
    block that shows a WRONG example still spells one on purpose, so this checks
    agreement rather than banning the literal outright.
    """
    import re
    from pathlib import Path

    from pylon import prompts
    from pylon.prompts import _CHAIN_TABLE, _TABLE_RULES_KEY
    from pylon.services import operation_match

    def allowed(chain: str) -> set[str]:
        """Every operator valid for the tables this chain serves."""
        fixed = _CHAIN_TABLE.get(chain)
        tables = [fixed] if fixed else [t for t, c in _TABLE_RULES_KEY.items()
                                        if c == chain]
        assert tables, f"no table maps to the {chain!r} chain"
        return {operation_match(t)[0] for t in tables}

    root = Path(prompts.__file__).parent / "assets"
    offenders, checked = [], 0
    for asset in sorted(root.rglob("*.md")):
        chain = asset.parent.name
        if chain not in _CHAIN_TABLE and not any(
                c == chain for c in _TABLE_RULES_KEY.values()):
            continue                     # tables/, which teaches no operator
        wrong = False
        for n, line in enumerate(asset.read_text().splitlines(), 1):
            stripped = line.strip()
            # A WRONG: heading opens a block of deliberate counter-examples and
            # the next blank line closes it. Those lines are wrong on purpose.
            if stripped.upper().startswith("WRONG"):
                wrong = True
                continue
            if not stripped:
                wrong = False
                continue
            if wrong or stripped.startswith(("//", "#")):
                continue
            m = re.search(r"\|\s*where\s+OperationName(?:Value)?\s*(=~|==)\s",
                          line)
            if not m:
                continue
            checked += 1
            if m.group(1) not in allowed(chain):
                offenders.append(
                    f"{asset.relative_to(root)}:{n} spells {m.group(1)!r}, but "
                    f"operation_match says {sorted(allowed(chain))} for the "
                    f"{chain} chain: {stripped}")
    assert checked, "no asset line states an operator -- this check found nothing"
    assert not offenders, "\n  ".join(["assets disagree with operation_match():"]
                                      + offenders)


def test_the_query_skeletons_ask_for_the_operator():
    """The lines the model copies verbatim must carry no operator of their own.
    Agreement is checked above; this makes drift impossible in the one place it
    would reach a deployed rule."""
    from pathlib import Path

    from pylon import prompts

    root = Path(prompts.__file__).parent / "assets"
    found = [a for a in sorted(root.rglob("*.md")) if "__OPERATOR__" in a.read_text()]
    names = {f"{a.parent.name}/{a.name}" for a in found}
    for chain in ("arm", "entra", "dataplane"):
        assert f"{chain}/playbook.md" in names, chain
    for chain in ("arm", "entra"):
        assert f"{chain}/detection.md" in names, chain


def test_the_operator_token_resolves_per_table():
    """The token is worth nothing if it renders to the same thing everywhere.
    AzureActivity and AuditLogs need `=~`; the data-plane tables need `==`."""
    from pylon.prompts import _render
    from pylon.services import operation_match

    for table in ("AzureActivity", "AuditLogs", "AZKVAuditLogs", "StorageBlobLogs"):
        out = _render('| where X __OPERATOR__ "Op"', service=table, target=None,
                      chain="arm", platform_id="arm")
        assert "__OPERATOR__" not in out
        assert out == f'| where X {operation_match(table)[0]} "Op"', table


def test_an_operation_is_judged_once_per_technique():
    """One operation, one technique, one basis. `MICROSOFT.KEYVAULT/VAULTS/DELETE`
    and `MICROSOFT.SQL/SERVERS/DATABASES/DELETE` were each listed under T1485
    twice -- once in the generic "destructive ARM deletes" block and again in
    their own service's block, with a different reason each time. Two answers to
    one question, and the reader cannot tell which was meant.

    An operation under two DIFFERENT techniques is fine and deliberate: a storage
    read is both T1530 and T1552.001.
    """
    import collections
    import pathlib

    import yaml

    root = pathlib.Path(__file__).resolve().parents[1]
    doc = yaml.safe_load(
        (root / "src/pylon/catalog/table-techniques.yaml").read_text(encoding="utf-8")
    )
    offenders = []
    for table, block in doc["tables"].items():
        seen = collections.defaultdict(list)
        for tech in block.get("techniques", []):
            for op in tech.get("operations") or []:
                seen[op].append(tech["id"])
        offenders += [
            (table, op, ids) for op, ids in seen.items() if len(ids) != len(set(ids))
        ]
    assert offenders == [], offenders


def test_every_alignment_the_scan_emits_is_one_the_model_accepts():
    """The producer and the model both own this vocabulary and nothing joined
    them.

    `contenthub` assigns `alignment`; `analysis_model.Solution` constrains it to
    a Literal. Three values were added to the producer and the Literal was not
    widened. 1,862 tests passed and `pylon analyze` died on a live tenant with
    eleven validation errors, because no test ran the scan's own output through
    the model that has to accept it.

    Derived from the source rather than listed here. A hand-written copy of the
    vocabulary would be a third place for it to drift.
    """
    import ast
    import pathlib
    import typing

    from pylon.analysis_model import Solution

    accepted = set(typing.get_args(Solution.model_fields["alignment"].annotation))

    src = pathlib.Path(__file__).resolve().parents[1] / "src/pylon/contenthub.py"
    tree = ast.parse(src.read_text(encoding="utf-8"))
    emitted: set[str] = set()
    for node in ast.walk(tree):
        # alignment = "..."
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (isinstance(target, ast.Name) and target.id == "alignment"
                        and isinstance(node.value, ast.Constant)
                        and isinstance(node.value.value, str)):
                    emitted.add(node.value.value)
        # return "...", evidence   -- the shape _unfed uses
        elif isinstance(node, ast.Return) and isinstance(node.value, ast.Tuple):
            head = node.value.elts[0] if node.value.elts else None
            if isinstance(head, ast.Constant) and isinstance(head.value, str):
                emitted.add(head.value)
        # "alignment": "..."  in the row dict
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if (isinstance(key, ast.Constant) and key.value == "alignment"
                        and isinstance(value, ast.Constant)
                        and isinstance(value.value, str)):
                    emitted.add(value.value)

    assert emitted, "this check found no alignment values and would pass for ever"
    assert emitted <= accepted, (
        f"contenthub emits {sorted(emitted - accepted)}, which "
        f"analysis_model.Solution rejects. A scan that writes it will fail "
        f"validation on a live tenant."
    )
