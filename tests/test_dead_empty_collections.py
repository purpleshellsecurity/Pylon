"""A clause that tests an empty list is not a filter, it is a promise.

Twice now a generated detection has shipped with this shape:

    let AllowedSinks = dynamic([]);
    | extend allowlistConfigured = array_length(AllowedSinks) > 0
    | where crossSubscription or (allowlistConfigured and not(inAllowlist))

`allowlistConfigured` is false for the life of the query, so the right half of
that `or` never runs. The detection's own description says it finds sinks
outside an allowlist AND cross-subscription redirects. It finds the second only.

All three existing gates pass it. The static checks see valid KQL, the engine
accepts it, and it matches real events, because the half that still works
matches. Nothing in the pipeline reads the boolean algebra, which is the only
place the defect lives.

The check is deliberately narrow: `let` bindings only. An inline
`coalesce(x, dynamic([]))` is a legitimate default and is not this.
"""

from pylon.validation.validate_kql import _dead_empty_collections, validate_kql


def _q(body: str) -> str:
    return f"AzureActivity\n| where TimeGenerated > ago(1h)\n{body}"


def test_the_shape_that_shipped_twice_is_caught():
    kql = ("let Allowed = dynamic([]);\n" + _q(
        "| extend configured = array_length(Allowed) > 0\n"
        "| extend inList = configured and array_index_of(Allowed, Caller) != -1\n"
        "| where configured and not(inList)"))
    problems = _dead_empty_collections(kql)
    assert problems, "the allowlist shape must be caught"
    assert "Allowed" in problems[0], "name the binding"
    assert "configured" in problems[0], "and the name that is stuck"
    assert "always false" in problems[0], "and say what it is stuck at"


def test_a_direct_test_of_the_empty_list_is_caught():
    kql = "let Allowed = dynamic([]);\n" + _q("| where Caller in (Allowed)")
    assert _dead_empty_collections(kql)


def test_an_always_true_test_is_caught_too():
    """`array_index_of(empty, x) == -1` is true for every row, so the clause
    passes everything. That is the same defect wearing the opposite sign: the
    description claims a filter and there is none."""
    kql = "let Allowed = dynamic([]);\n" + _q(
        "| extend notListed = array_index_of(Allowed, Caller) == -1\n"
        "| where notListed")
    problems = _dead_empty_collections(kql)
    assert problems and "always true" in problems[0]


def test_it_reaches_the_validator_and_fails_the_detection():
    """The helper being right is worth nothing if nothing calls it."""
    kql = "let Allowed = dynamic([]);\n" + _q(
        "| extend configured = array_length(Allowed) > 0\n"
        "| where configured\n| project TimeGenerated, Caller")
    result = validate_kql(kql, "AzureActivity")
    assert not result.valid
    assert any("empty collection" in e for e in result.errors), result.errors


# --- what must NOT be flagged ----------------------------------------------

def test_an_inline_empty_default_is_not_this():
    """`coalesce(x, dynamic([]))` supplies a default when a field is absent. It
    is correct, common, and has nothing to do with a dead allowlist."""
    kql = _q("| extend cats = coalesce(todynamic(Properties), dynamic([]))\n"
             "| where array_length(cats) > 0")
    assert _dead_empty_collections(kql) == []


def test_a_populated_list_is_not_this():
    kql = 'let Allowed = dynamic(["a","b"]);\n' + _q("| where Caller in (Allowed)")
    assert _dead_empty_collections(kql) == []


def test_an_empty_list_that_is_never_tested_is_left_alone():
    """Bound and unused is a tidiness problem, not a lie about what the query
    does. Flagging it would train people to ignore this check."""
    kql = "let Allowed = dynamic([]);\n" + _q("| project TimeGenerated, Caller")
    assert _dead_empty_collections(kql) == []


def test_the_name_inside_a_string_is_not_a_use():
    kql = "let Allowed = dynamic([]);\n" + _q('| where Caller == "Allowed"')
    assert _dead_empty_collections(kql) == []


def test_a_real_generated_detection_that_is_clean_stays_clean():
    """The Start/Success join with a body array, which is the shape the contract
    teaches. It must not trip this."""
    kql = _q(
        "| extend Body = parse_json(tostring(parse_json(Properties).requestbody))\n"
        "| where isnotempty(Body.properties.logs)\n"
        "| mv-expand entry = Body.properties.logs\n"
        "| where tobool(entry.enabled) == false\n"
        "| project TimeGenerated, Caller, entry")
    assert _dead_empty_collections(kql) == []


# --- the same defect wearing a different hat --------------------------------
#
# The generator reaches for a Sentinel watchlist on its own; it was never in a
# prompt. Measured on a tenant with no watchlist called ApprovedAutomation:
#
#     let A = _GetWatchlist('ApprovedAutomation') | project SearchKey;
#     ... | where clientInfo_ObjectId_g !in (A)
#
# does NOT error. It returns empty, the `!in` passes all 8 rows, and the
# detection promises an allowlist it never applies. `dynamic([])` at least looks
# empty on the page; this looks like configuration someone did.

from pylon.validation.validate_kql import _unverified_watchlists


def test_a_watchlist_filter_is_flagged():
    kql = ("let Allowed = _GetWatchlist('ApprovedAutomation') | project SearchKey;\n"
           + _q("| where Caller !in (Allowed)"))
    problems = _unverified_watchlists(kql)
    assert problems, "a watchlist the query cannot verify must be called out"
    assert "ApprovedAutomation" in problems[0], "name the watchlist"
    assert "!in" in problems[0] or "in" in problems[0]


def test_both_directions_are_covered():
    """`in` matches nothing and `!in` matches everything. Both are wrong and
    neither fails, so the message has to cover the pair."""
    for op in ("in", "!in"):
        kql = ("let A = _GetWatchlist('Approved') | project SearchKey;\n"
               + _q(f"| where Caller {op} (A)"))
        assert _unverified_watchlists(kql), f"{op} not caught"


def test_it_reaches_the_validator():
    kql = ("let Allowed = _GetWatchlist('Approved') | project SearchKey;\n"
           + _q("| where Caller !in (Allowed)\n| project TimeGenerated, Caller"))
    result = validate_kql(kql, "AzureActivity")
    assert not result.valid
    assert any("watchlist" in e for e in result.errors), result.errors


def test_a_watchlist_that_is_bound_and_never_filtered_on_is_left_alone():
    """Enriching with a watchlist is legitimate -- joining to add context does
    not silently change what matches. Only a membership filter does."""
    kql = ("let Owners = _GetWatchlist('Owners');\n"
           + _q("| join kind=leftouter (Owners) on $left.Caller == $right.SearchKey"))
    assert _unverified_watchlists(kql) == []


def test_a_query_with_no_watchlist_is_untouched():
    assert _unverified_watchlists(_q("| project TimeGenerated, Caller")) == []
