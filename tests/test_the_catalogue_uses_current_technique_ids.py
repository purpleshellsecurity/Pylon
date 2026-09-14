"""A revoked technique id in the catalogue outlives the run that relabels it.

`verify_mitre_ids` relabels a revoked id at generation time, so a detection came
out carrying T1685 while `table-techniques.yaml` still said T1562. The output was
right and the file was wrong, which is the split that survives for years: nobody
reading the catalogue sees a problem, and nobody reading a detection does either.

Three were revoked and the engine was papering over all three:

    T1562     -> T1685        Impair Defenses
    T1562.007 -> T1686.001
    T1562.008 -> T1685.002

MITRE revokes ids continuously, so this is not a one-time cleanup. It is a test
because the next revocation will arrive the same way, silently.
"""

import re

import pytest

from pylon import mitre

_CATALOGUE = "src/pylon/catalog/table-techniques.yaml"


def _ids() -> list[str]:
    text = open(_CATALOGUE, encoding="utf-8").read()
    return sorted(set(re.findall(r"^\s*-\s*id:\s*(T\d+(?:\.\d+)?)", text, re.M)))


def test_the_catalogue_has_techniques_at_all():
    """An empty list would make the test below pass on a broken file."""
    assert len(_ids()) > 30


@pytest.mark.parametrize("technique", _ids())
def test_no_catalogued_technique_has_been_revoked(technique):
    try:
        current, why = mitre.current(technique)
    except Exception:                      # bundle unreachable: cannot check
        pytest.skip("the MITRE bundle is not available")
    assert current == technique, (
        f"{technique} is revoked and the catalogue still uses it. {why} "
        f"The engine relabels at generation time, so detections come out "
        f"correct while this file stays wrong.")


def test_the_revoked_ids_are_gone_by_name():
    """Belt and braces. The three that were wrong, asserted directly, so a
    future edit that reintroduces one fails even if the bundle is unreachable."""
    text = open(_CATALOGUE, encoding="utf-8").read()
    for revoked in ("T1562", "T1562.007", "T1562.008"):
        assert revoked not in text, f"{revoked} is back in the catalogue"
