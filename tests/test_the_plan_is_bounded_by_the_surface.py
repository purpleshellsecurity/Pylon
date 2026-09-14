"""Phase 1 was told to be exhaustive and never told how big the surface is.

Microsoft.Insights/diagnosticSettings records exactly two operations in
AzureActivity, Write and Delete, and maps to one technique. The honest plan is
two vectors. A run produced five, subdividing Write four ways by request-body
fields, and one of the four asked for a write where every destination is empty
-- a state the ARM API does not produce, and one the tenant confirms: workspaceId
appears on 31 of 31 observed writes and the other three destinations never
appear at all.

The cause was an instruction without a bound. "Cover the surface, do not sample
it" is right for a vault with 78 operations and is an instruction to invent on a
surface with two, and the operation vocabulary was only consulted in Phase 2,
per vector, long after the count had been decided.

Two halves here. The list now reaches Phase 1, and what comes back is checked
against it. Prose was tried for the check first and abandoned: reading field
names out of an English alert condition cannot distinguish "sink" and "remains"
from a field name, so the plan declares them instead.
"""


from pylon import contracts
from pylon.engine import EngineRequest, _surface_size, operation_vocabulary_for
from pylon.models import AttackVector

_WRITE = "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/WRITE"
_TABLE = "AzureActivity"


def _vector(operation=_WRITE, fields=(), name="v"):
    return AttackVector(
        name=name, priority="high", mitre_technique="T1685.002",
        operation=operation, log_table=_TABLE, alert_condition="c",
        rationale="r r.", distinguishing_fields=list(fields))


def _request():
    return EngineRequest(platform="azure",
                         resource="Microsoft.Insights/diagnosticSettings",
                         surfaces=("AzureActivity",), service="AzureActivity")


# --- the list must reach Phase 1 -------------------------------------------

def test_phase_one_is_told_how_big_the_surface_is():
    text = _surface_size(_request())
    assert "exactly these 2 operations" in text
    assert "Microsoft.Insights/DiagnosticSettings/Write" in text
    assert "Microsoft.Insights/DiagnosticSettings/Delete" in text


def test_an_uncatalogued_target_says_nothing_rather_than_nothing_exists():
    """An empty vocabulary means nobody catalogued this surface. Telling the
    model it records zero operations would be a lie that stops the run."""
    blank = EngineRequest(platform="azure", service="AuditLogs")
    assert operation_vocabulary_for(blank, "AuditLogs") == ()
    assert _surface_size(blank) == ""


# --- and what comes back is checked against it -----------------------------

def test_one_vector_per_operation_needs_no_justification():
    """The shape this is trying to get back to. Two operations, two vectors,
    nothing to declare."""
    vectors = [_vector(_WRITE), _vector("MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE")]
    assert contracts.plan_problems(vectors, _TABLE) == {}


def test_two_vectors_sharing_an_operation_must_say_what_differs():
    vectors = [_vector(_WRITE, name="a"), _vector(_WRITE, name="b")]
    problems = contracts.plan_problems(vectors, _TABLE)
    assert set(problems) == {0, 1}
    assert "names no request-body field" in problems[0][0]


def test_a_declared_field_that_was_measured_is_accepted():
    """`logs` is real: 21 of 31 observed writes carry it."""
    vectors = [_vector(_WRITE, ["logs"], "a"), _vector(_WRITE, ["metrics"], "b")]
    assert contracts.plan_problems(vectors, _TABLE) == {}


def test_a_nested_field_counts_as_measured():
    """`retentionPolicy` is not a top-level property. It sits inside entries of
    `logs`, on 21 of 63 of them, and reading only the top level would report a
    measured field as never observed."""
    vectors = [_vector(_WRITE, ["retentionPolicy"], "a"), _vector(_WRITE, ["logs"], "b")]
    assert contracts.plan_problems(vectors, _TABLE) == {}


def test_the_vector_that_shipped_impossible_is_flagged():
    """The one that asked for a write with no destination at all. Those three
    destination fields have never appeared in an observed request body."""
    vectors = [
        _vector(_WRITE, ["storageAccountId", "eventHubAuthorizationRuleId"], "a"),
        _vector(_WRITE, ["logs"], "b")]
    problems = contracts.plan_problems(vectors, _TABLE)
    assert 0 in problems and 1 not in problems
    # Worded as evidence from this tenant, not as a law. A lab with no
    # storage-destination diagnostic settings has never seen storageAccountId;
    # that says nothing about anyone else's tenant.
    assert "not seen in the 31 events measured here" in problems[0][0]
    assert "workspaceId" in problems[0][0], "say what HAS been measured"
    assert "trigger it and re-measure" in problems[0][0], (
        "an absence report must say how to disprove it")


def test_an_operation_outside_the_vocabulary_is_flagged():
    vectors = [_vector("MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/READ")]
    problems = contracts.plan_problems(
        vectors, _TABLE, vocabulary=["Microsoft.Insights/DiagnosticSettings/Write",
                                     "Microsoft.Insights/DiagnosticSettings/Delete"])
    assert 0 in problems and "not one this table records" in problems[0][0]


def test_an_unmeasured_table_reports_that_rather_than_guessing():
    """No measurement is not the same answer as no such field, and a verdict
    that conflates them is the failure this whole gate exists to avoid."""
    vectors = [_vector("SOMETHING/ELSE", ["x"], "a"), _vector("SOMETHING/ELSE", ["y"], "b")]
    problems = contracts.plan_problems(vectors, _TABLE)
    assert "nothing has measured" in problems[0][0]


def test_a_saved_plan_read_from_disk_is_checked_the_same_way():
    """Vectors arrive as pydantic models from the engine and as plain dicts from
    a saved plan.json. Both are real callers."""
    as_dicts = [{"operation": _WRITE, "distinguishing_fields": []},
                {"operation": _WRITE, "distinguishing_fields": []}]
    assert set(contracts.plan_problems(as_dicts, _TABLE)) == {0, 1}


# --- and the gate has to actually run --------------------------------------

def test_the_gate_is_reachable_from_the_engine():
    import inspect

    from pylon import engine

    source = inspect.getsource(engine)
    assert "contracts.plan_problems(" in source, "the plan gate is dead code"
    assert "plan_warnings.append" in source, (
        "a plan warning that never reaches the report is a warning nobody sees")
    assert "_surface_size(request)" in source, (
        "Phase 1 is no longer told how big the surface is")


def test_the_model_cannot_write_the_plan_gate_s_own_findings():
    """`plan_warnings` is Pylon's answer about the plan. It is on a schema the
    model can see, and the model filled it with its own KQL advice -- true, and
    in the field a reader takes for a measurement Pylon made. Cleared after the
    response is unwrapped, exactly as `target` is stamped there."""
    import inspect

    from pylon import engine

    source = inspect.getsource(engine)
    assert "analysis.plan_warnings = []" in source, (
        "the model's own text can reach plan_warnings and be read as a finding")
    assert source.index("analysis.plan_warnings = []") < source.index(
        "plan_warnings.append"), "it must be cleared before the gate writes to it"
