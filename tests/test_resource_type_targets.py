"""The command line takes a resource type, and hands the engine what the gate allowed.

`tests/test_target_gate.py` covers WHICH resource types are targets. This covers
the wiring: what a typed string resolves to, and what request it builds.

The wiring is where the gate can be quietly undone. The engine falls back to the
curated routing overlay when a request carries a resource and no surfaces -- and
the overlay is where the six ungrounded App Service tables live. A decision made
in the registry and not passed down would be reversed one layer lower, with
nothing failing.
"""

import argparse

import pytest

from pylon import cli, deployed, engine
from pylon.services import ENTRA_KEY, resolve_target


def _run(monkeypatch, target: str):
    """Build the request `design detections <target>` would send, without spending."""
    built = {}

    class _Stub:
        EngineRequest = engine.EngineRequest

        @staticmethod
        def runnable():
            """`engine.runnable()` owns the version difference in
            `@workflow` -- 1.13 returned the runnable, 1.18 returns a
            definition you `.build()`. The CLI goes through it, so the stub
            stands in for it rather than for `pylon`."""

            class _Workflow:
                @staticmethod
                def run(request):
                    built["request"] = request
                    raise SystemExit(0)   # stop before any model call

            return _Workflow

    monkeypatch.setattr(cli, "_engine", lambda: _Stub)
    monkeypatch.setattr(deployed, "from_analysis", lambda: (None, "not checked"))
    # This asserts what reaches the engine, not whether the tenant was
    # scanned, so the confirmation gate is answered explicitly.
    args = argparse.Namespace(target=target, max_cost=1.0, max_tokens=0,
                              out=None, unconfirmed_tables=True)
    with pytest.raises(SystemExit):
        cli._design_detections(args)
    return built["request"]


def test_a_resource_type_matches_whatever_case_azure_used_this_time():
    """Azure's casing is inconsistent between its docs, its ARM responses and its
    operation names, so the match is case-insensitive and the canonical spelling
    comes back from the catalogue rather than from what was typed."""
    for typed in ("Microsoft.Web/sites", "microsoft.web/sites",
                  "MICROSOFT.WEB/SITES", "  Microsoft.Web/sites  "):
        target = resolve_target(typed)
        assert target is not None and target.key == "Microsoft.Web/sites"


def test_key_vault_is_one_target_carrying_both_planes():
    """Two runs against one vault meant no detection could follow an attack from
    the ARM change into the secret it unlocked, which is the shape of the attack."""
    assert resolve_target("Microsoft.KeyVault/vaults").tables == (
        "AzureActivity", "AZKVAuditLogs")


def test_the_gated_surfaces_reach_the_engine_not_just_the_resource(monkeypatch):
    request = _run(monkeypatch, "Microsoft.Web/sites")
    assert request.resource == "Microsoft.Web/sites"
    # The point of this test is that the GATE decides what reaches the engine,
    # not the resource type. When all six App Service tables were ungrounded,
    # that meant AzureActivity alone; three earned a contract, and
    # AppServiceFileAuditLogs became the fourth once it could be measured --
    # which needed a WINDOWS PREMIUM app, because Microsoft offers the category
    # on Windows only and above Premium tier, and the lab app was Linux on
    # Consumption. Measuring a table is what moves it across this line.
    reached = [s.table for s in request.surfaces]
    assert reached[0] == "AzureActivity"
    assert set(reached) == {"AzureActivity", "AppServiceAuditLogs",
                            "AppServiceIPSecAuditLogs", "FunctionAppLogs",
                            "AppServiceFileAuditLogs"}
    for refused in ("AppServiceHTTPLogs", "AppServiceAuthenticationLogs"):
        assert refused not in reached, f"{refused} is ungrounded and must not reach the engine"


def test_a_two_plane_target_sends_both_tables(monkeypatch):
    request = _run(monkeypatch, "Microsoft.Storage/storageAccounts/queueServices")
    assert [s.table for s in request.surfaces] == ["AzureActivity", "StorageQueueLogs"]


def test_entra_does_not_go_through_resource_mode(monkeypatch):
    """A directory is not an ARM resource. Resource mode would have nothing to
    resolve and would build its prompt around an empty surface list."""
    request = _run(monkeypatch, ENTRA_KEY)
    assert request.resource == ""
    assert (request.platform, request.service) == ("entra", "AuditLogs")


def test_an_unusable_target_never_reaches_the_engine(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_engine", lambda: object())
    args = argparse.Namespace(target="Microsoft.DataFactory/factories", max_cost=1.0,
                              max_tokens=0, out=None)
    assert cli._design_detections(args) == 2
    assert "not a target this tool can ground" in capsys.readouterr().err


def test_the_readme_and_the_scripts_type_real_targets():
    """Documentation naming a target the parser rejects is worse than none: it is
    the first thing a new reader copies. The old command line survived in three
    files after the flags it used were gone."""
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[1]
    # Every shipped doc and script, found rather than listed. The first version
    # named three files and `docs/testing.md` was not one of them, so the release
    # tree went out telling a new reader to run `--platform arm --service
    # "Key Vault"` -- a command the parser now rejects, in the file whose whole
    # job is the first-run checklist.
    shipped = [p for p in ([root / "README.md"]
                           + sorted(root.glob("docs/*.md"))
                           + sorted(root.glob("scripts/*.sh"))
                           + sorted(root.glob("scripts/*.ps1")))
               if p.is_file() and p.name != "findings.md"]
    typed: list[tuple[str, str]] = []
    for path in shipped:
        name = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8")
        # Only strings in TARGET position. A doc that quotes an ARM operation
        # ("Microsoft.Insights/diagnosticSettingsCategories/read") is not naming a
        # target, and matching every Microsoft.* in prose made this fail on one.
        typed += [(name, m) for m in re.findall(
            r"design detections\s+\\?\s*(Microsoft\.[A-Za-z0-9]+/[A-Za-z0-9/]+|entra)",
            text)]
        typed += [(name, m) for m in re.findall(
            r"Args\s*=\s*@\(\s*'(Microsoft\.[A-Za-z0-9]+/[A-Za-z0-9/]+|entra)'",
            text)]
        typed += [(name, m) for m in re.findall(
            r"^\s*gen\s+\"[a-z-]+\"\s+(Microsoft\.[A-Za-z0-9]+/[A-Za-z0-9/]+|entra)",
            text, re.M)]
        # Only where they would be PYLON flags. `--platform` is also Docker's
        # own flag, and the README needs it: the Kusto image is amd64-only and
        # the plain `docker run` exits 133 on Apple silicon. Matching the bare
        # string failed on a line that has nothing to do with this CLI.
        for gone in ("--platform", "--service"):
            # `pylon` as a COMMAND, not as a substring: the Kusto container is
            # named `pylon-kustainer`, and `docker run --platform` on that line
            # is Docker's flag on a container whose name happens to start with
            # the tool's.
            offending = [line for line in text.splitlines()
                         if gone in line and re.search(r"(?:^|\s)pylon\s", line)]
            assert offending == [], (
                f"{name} still passes the removed {gone} to pylon: {offending[:1]}")

    assert typed, "no target appears in the docs at all"
    for name, target in typed:
        assert resolve_target(target) is not None, (
            f"{name} names {target}, which the CLI would refuse")


def test_the_eval_harness_cannot_reach_what_the_command_line_refuses():
    """A harness that can reach what the product cannot is measuring a different
    product.

    `scripts/eval.py` parsed its own "resource:NAME" and "platform:service" forms
    and assembled the request itself, so it bypassed the gate entirely -- and its
    own default target was AKS, whose vocabulary is eight bare Kubernetes verbs
    with no verdict on any of them. An unattended `scripts/eval.py` spent money
    generating detections nothing could check, and then reported metrics on them.
    """
    import importlib.util
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("_eval", root / "scripts" / "eval.py")
    harness = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(harness)

    for target in harness._DEFAULT_TARGETS:
        assert resolve_target(target), f"default eval target {target!r} is not askable"

    for refused in ("Microsoft.ContainerService/managedClusters", "resource:AKS",
                    "arm:Storage Account", "Microsoft.DataFactory/factories"):
        with pytest.raises(SystemExit):
            harness._request_for(refused, 1.0)

    label, request = harness._request_for("Microsoft.KeyVault/vaults", 1.0)
    assert [s.table for s in request.surfaces] == ["AzureActivity", "AZKVAuditLogs"]
