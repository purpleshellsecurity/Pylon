"""Which table answers which question, per resource.

The operation catalogue says what can HAPPEN to a resource. This says where you
would SEE it. Both are needed and only the first existed: `RESOURCE_OVERLAY`
was written for two resources as a pilot, the note said to add more as they came
in, and six offered targets never got one.

What filled the gap instead was the hand-typed one-target-one-table list in the
picker, and for App Service that list chose the table recording publishing
logons -- so a function app writes eleven resource log tables, Pylon offered one,
and a stolen access key being USED was invisible. The table that sees it,
AppServiceHTTPLogs, was not in the tool at all.
"""

import pytest

from pylon.catalog import (
    NO_DATA_PLANE,
    RESOURCE_OVERLAY,
    data_plane_state,
    log_surfaces,
    resolve_resource,
)
from pylon.services import targets

# Entra is not an ARM resource type and has no resource type to resolve.
_TYPES = sorted(t.resource_type for t in targets().values()
                if t.resource_type)


def test_there_are_targets_to_check():
    assert len(_TYPES) > 12


@pytest.mark.parametrize("rt", _TYPES)
def test_every_target_is_a_resource_type_the_catalogue_knows(rt):
    """The target IS the resource type now, so this is no longer a lookup that
    can fail -- but the catalogue still has to recognise its own key, or
    log_surfaces would route it by a provider prefix alone."""
    assert resolve_resource(rt) == rt


@pytest.mark.parametrize("rt", _TYPES)
def test_every_offered_target_has_a_decided_data_plane(rt):
    """Control-plane-only is two different answers wearing one face.

    log_surfaces returns AzureActivity alone both when a resource HAS no data
    plane and when nobody has written its routing down. Only one of those is a
    gap, and a caller cannot tell them apart. Every target must be one or the
    other deliberately: surfaces in RESOURCE_OVERLAY, or an entry in
    NO_DATA_PLANE saying why there will never be any.
    """
    state = data_plane_state(rt)
    assert state != "unwritten", (
        f"{rt} has no data-plane routing and no reason recorded. "
        f"Either author its surfaces in RESOURCE_OVERLAY, or record in "
        f"NO_DATA_PLANE why it has none."
    )


def test_a_reason_for_having_no_data_plane_is_a_reason_and_not_a_label():
    thin = [rt for rt, why in NO_DATA_PLANE.items()
            if len(" ".join(str(why).split())) < 40]
    assert thin == [], f"NO_DATA_PLANE entries with no argument in them: {thin}"


def test_no_resource_claims_both_surfaces_and_none():
    """A resource in both maps asserts two contradictory things."""
    both = sorted(set(RESOURCE_OVERLAY) & set(NO_DATA_PLANE))
    assert both == [], f"claimed as having surfaces AND as having none: {both}"


def test_every_surface_says_what_it_is_for():
    """The note is the whole point of this file. Table names and categories come
    from Microsoft; what a table is FOR, and what it cannot answer, does not."""
    thin = [(rt, s.table) for rt, surfaces in RESOURCE_OVERLAY.items()
            for s in surfaces if len(" ".join(s.note.split())) < 60]
    assert thin == [], f"surfaces with a label instead of a routing note: {thin}"


def test_the_control_plane_surface_is_always_present_and_write_only():
    """Every ARM resource's creates, changes and deletes land in AzureActivity,
    and none of its reads do. A run that offers only data-plane tables would
    miss every configuration change; one that offers only AzureActivity would
    miss every read."""
    for label in _TYPES:
        surfaces = log_surfaces(resolve_resource(label))
        control = [s for s in surfaces if s.mode == "control-plane"]
        assert len(control) == 1, label
        assert control[0].table == "AzureActivity"
        assert control[0].covers == ("write",)


def test_the_app_service_routing_carries_the_table_that_sees_a_key_being_used():
    """The regression this file exists for. AzureActivity records a function key
    being READ; only the HTTP log records the request that then uses it."""
    tables = {s.table for s in log_surfaces("Microsoft.Web/sites")}
    assert "AppServiceHTTPLogs" in tables
    assert "AppServiceFileAuditLogs" in tables
    assert "AzureActivity" in tables
