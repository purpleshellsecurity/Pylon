"""`catalog/service_files/` is load-bearing, and every reader of it fails quiet.

48 files, 291 tables. Three things read them:

  validate_kql._known_tables   table NAMES -- 271 of the 307 tables this tool
                               recognises come from here and nowhere else
  kusto_offline.schema_for_table   typed COLUMNS -- and a table with no typed
                               schema makes the offline KQL parser gate return
                               "no typed schema" and NOT RUN
  solutions.load -> contenthub.build   the whole file, for the Content Hub
                               recommendations

Every one of those degrades in silence. `service_files()` returns `{}` on any
OSError; `_known_tables` falls back to the schema'd set; `schema_for_table`
falls back to the vendored types; `solutions.load` skips a file it cannot open.
Nothing raises, so the tool keeps running and gets quietly worse.

WHAT WAS ALREADY COVERED, AND WHAT WAS NOT
------------------------------------------
Deleting the directory from the checkout DOES turn eight existing tests red
(`test_sources_agree`, `test_keyvault_catalogue`, `test_console`) -- measured,
not assumed. But every one of those reads `src/pylon/catalog/service_files/` as
a FILESYSTEM PATH from the repo root, so they are all blind to the failure that
actually ships: a wheel built without the `package-data` line carries no
catalogue at all, and a suite that reads the source checkout never finds out.
That is the release-drop shape this repo has been bitten by five times --
LICENSE, the CI workflow, the release checklist, dependabot, the security fixes
-- every one an explicit list nobody updated.

So the checks here go through `importlib.resources`, which is the read a wheel
answers the same way a checkout does, and `scripts/make-release.sh` now counts
these files in the tree it produces.

WHAT THIS CANNOT DO
-------------------
It proves the data is reachable and that each consumer reads it. It says
nothing about whether the CONTENT is current -- `scripts/refresh-supported-
logs.py` is that, and staleness is a known finding of its own.
"""

import pathlib

import pytest

from pylon.catalog import service_files

CATALOG = pathlib.Path(__file__).resolve().parents[1] / "src" / "pylon" / "catalog"


# ── the data is there and reachable through the package ──────────────────────

def test_the_directory_loads_through_importlib_resources():
    """Not `open(__file__/../..)`. A wheel is what a user installs, and
    `resources.files` is the only read that behaves the same in both."""
    assert len(service_files()) >= 40, (
        f"only {len(service_files())} services loaded; the catalogue is "
        "missing or unreadable")


def test_every_file_on_disk_is_loaded():
    """A file that fails to parse is skipped in silence by the loader, so the
    count on disk and the count in memory have to agree.

    The floor is asserted too: nought equals nought, and without it this check
    is green on the one case it most needs to catch.
    """
    on_disk = {p for p in (CATALOG / "service_files").glob("*.json")
               if not p.name.startswith("_")}
    assert len(on_disk) >= 40, f"only {len(on_disk)} files in the directory"
    assert len(service_files()) == len(on_disk), (
        f"{len(on_disk)} files on disk, {len(service_files())} loaded -- "
        "one of them is unparseable or carries no resource_type")


def test_the_index_is_build_output_and_nothing_reads_it():
    """`_index.json` is written by scripts/build_service_files.py and skipped by
    both readers. Recorded so nobody wires it up by mistake."""
    assert (CATALOG / "service_files" / "_index.json").exists()
    assert "_index" not in {s.get("resource_type") for s in service_files().values()}


# ── each consumer actually reads it ──────────────────────────────────────────
# Spot-checked on a table the catalogue is the ONLY source for: it is absent
# from TABLE_SCHEMAS and from the vendored column types, so anything it
# resolves through came from here.

ONLY_HERE = "AACAudit"


def test_the_spot_check_table_really_is_only_in_the_catalogue():
    """The premise. If this table ever gains a hardcoded schema the two checks
    below stop proving anything."""
    from pylon.kusto_offline import _vendored_column_types
    from pylon.validation.schemas import TABLE_SCHEMAS

    assert ONLY_HERE not in TABLE_SCHEMAS
    assert ONLY_HERE not in _vendored_column_types()
    assert any(ONLY_HERE in (s.get("tables") or {}) for s in service_files().values())


def test_the_validator_knows_the_table_is_real():
    """Without this the validator calls 271 real tables hallucinated."""
    from pylon.validation.validate_kql import _known_tables

    assert ONLY_HERE in _known_tables()


def test_the_offline_parser_gate_gets_a_typed_schema():
    """`engine._offline` returns `ran=False, error="no typed schema for X"` when
    this is empty -- the gate is skipped and a syntax error ships."""
    from pylon.kusto_offline import schema_for_table

    schema = schema_for_table(ONLY_HERE)
    assert schema, "the offline KQL gate cannot run against this table"
    assert all(isinstance(v, str) and v for v in schema.values()), schema


def test_content_hub_recommendations_have_a_catalogue_to_work_from():
    """`solutions.load` reads the same directory by path rather than through
    `service_files()`, so it is a separate wire and gets its own check."""
    import pylon.solutions as solutions

    catalog = solutions.load()
    assert len(catalog) >= 40, catalog.keys()
    assert (catalog.get("key vault") or {}).get("resource_type") == \
        "microsoft.keyvault/vaults"


# ── the two counts a silent fallback would hide ──────────────────────────────

def test_most_known_tables_come_from_the_catalogue():
    """The number that says how much is at stake. If it collapses, a reader of
    a green suite should still find out."""
    from pylon.validation.validate_kql import _known_tables
    from pylon.validation.schemas import TABLE_SCHEMAS

    hardcoded = set(TABLE_SCHEMAS) | {"AzureActivity", "AzureDiagnostics", "AzureMetrics"}
    from_catalogue = _known_tables() - hardcoded
    assert len(from_catalogue) >= 200, (
        f"only {len(from_catalogue)} tables are coming from the catalogue; "
        "it is partially loaded")


@pytest.mark.parametrize("name", ["service_manifest.json", "mitre_index.json"])
def test_the_other_catalogues_the_package_declares_are_present(name):
    """Same class, same silent failure: `service_manifest` returns {} and
    `mitre_index` is the technique index behind every coverage number."""
    assert (CATALOG / name).exists(), f"{name} is declared in pyproject and absent"


def test_pyproject_declares_the_catalogue_as_package_data():
    """A wheel built without this line carries no catalogue at all, and the
    source checkout every test runs from would never notice."""
    text = (CATALOG.parents[2] / "pyproject.toml").read_text(encoding="utf-8")
    assert 'catalog/service_files/*.json' in text, (
        "package-data does not ship the service catalogue")
