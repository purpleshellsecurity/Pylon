"""What `pylon design detections` prints when it finishes."""

from __future__ import annotations

from types import SimpleNamespace as NS

import pytest

from pylon import cli


def _det(tech, name, valid=True):
    return NS(valid=valid, errors=[] if valid else ["some error"],
              detection=NS(mitre_technique=tech, vector_name=name))


def _vector(i):
    """A stand-in attack vector. It carries the three fields the summary reads
    -- table, operation, technique -- because the report now asks the curated
    index for a second opinion on each one. `list(range(n))` stood in while the
    only thing anyone wanted was len(); it stopped being a vector the moment
    something read a field off it."""
    return NS(name=f"vector {i}", operation=f"OPERATION_{i}",
              log_table="AzureActivity", mitre_technique="T1078.004")


def _result(detections, vectors=4, **over):
    """A stub of the report the CLI renders.

    `vectors_planned` has to be here even though it defaults to 0 on the real
    model: a SimpleNamespace has no defaults, so every field the renderer reads
    must be spelled out. That is the standing cost of stubbing instead of
    building the real EngineReport, and adding one field to the model has broken
    this helper twice now.
    """
    base = dict(platform="arm", service="Key Vault",
                analysis=NS(attack_vectors=[_vector(i) for i in range(vectors)]),
                detections=detections, generation_yield=100,
                vectors_planned=0,
                catalog_covered=3, catalog_total=101, model_calls=11,
                input_tokens=100_000, output_tokens=18_803,
                estimated_cost_usd=0.80, unreported_calls=0)
    return NS(**{**base, **over})


@pytest.fixture
def show(capsys):
    def run(result):
        cli._print_report(result)
        return capsys.readouterr().out
    return run


def test_yield_and_coverage_are_two_sentences_not_one_line(show):
    """They used to read "yield 100% | catalog coverage 3/101", which only its
    author can parse. They are different questions: did generation do its job
    on what it enumerated, and how much of the platform's catalogue is watched.
    A run scores 100% on the first while covering three of a hundred."""
    out = show(_result([_det("T1485", "Delete Key Vault")], vectors=1))
    assert "yield" not in out.lower()
    # Counted, not scored. This asserted the old sentence, which said
    # "100% of the N enumerated vectors produced a valid detection" -- and the
    # percentage was computed over distinct, weight-scored TECHNIQUE ids, so
    # two vectors sharing a technique with one valid detection printed 100%
    # four lines under the word BAD.
    assert "enumerated vector produced a valid detection" in out
    assert "1 of 1" in out
    assert "3 of 101 ATT&CK techniques catalogued for arm are now covered" in out


def test_an_invalid_detection_still_shows_its_first_error(show):
    out = show(_result([_det("T1485", "Delete Key Vault", valid=False)], vectors=1))
    assert "BAD" in out
    assert "some error" in out


def test_the_counts_agree_their_nouns_with_their_numbers(show):
    out = show(_result([_det("T1485", "Delete Key Vault")], vectors=1))
    assert "1  attack vector enumerated" in out
    assert "(s)" not in out


# ── what the run says it covers, before the money is spent ───────────────────

def test_every_platform_can_describe_the_track_it_covers():
    """The header line naming the track is built from the platform's own
    description, so it cannot drift from what `design list` prints.

    A run against `arm / Key Vault` enumerates control-plane operations and
    correctly finds none of SecretGet, KeyDecrypt or CertificatePurge --
    reading a secret never touches ARM. Four detections then read as "Key
    Vault covered" to anyone who does not know the planes are separate
    tracks."""
    from pylon.prompts import PLATFORMS
    assert PLATFORMS, "no platforms to describe"
    for plat in PLATFORMS:
        assert plat.covers and plat.covers.strip(), plat.id
        # The exclusion is the half that stops a partial result reading as a
        # complete one, so a platform that states only what it covers is not
        # describing itself -- it is doing the thing this test exists to catch.
        assert plat.not_covered and plat.not_covered.strip(), plat.id


def test_the_arm_track_says_it_is_the_control_plane():
    from pylon.prompts import PLATFORMS
    arm = next(p for p in PLATFORMS if p.id == "arm")
    assert "control plane" in arm.covers.lower()
    assert "data" in arm.not_covered.lower()


def test_the_covers_line_names_no_sibling_target():
    """Deliberate. Naming "Key Vault Secrets" needs a map from an ARM service
    to its data-plane tables; the relationship is one-to-many, ARM "Storage"
    being both Blob Storage and File Storage; and a hand-written map of that
    shape is exactly what `tabledrift` exists to catch going stale. Pointing
    at `design list` costs one command and stays correct."""
    from pylon.prompts import PLATFORMS
    from pylon.services import targets

    # The catalogue's labels. This read `PLATFORMS[*].services`, which is empty
    # for two of the three platforms now, so the set it compared against had one
    # member and the check was passing on an empty question.
    labels = {t.label for t in targets().values() if t.label}
    assert len(labels) >= 10, f"only {len(labels)} labels -- the source emptied"
    for plat in PLATFORMS:
        # Only the exclusion. `covers` naming a service is ordinary description
        # -- the Entra track really does cover Graph API calls -- while a name
        # in `not_covered` is the tool telling you to go run THAT instead, and
        # that is the claim which needs a map to stay right.
        named = sorted(lbl for lbl in labels if lbl in plat.not_covered)
        assert named == [], (
            f"{plat.id} names {named} — a sibling target, which needs an "
            f"ARM-service to data-plane-table map to stay right. That map is "
            f"one-to-many and goes stale with nothing to notice, so these two "
            f"sentences name the LOG SOURCE instead and cannot rot."
        )


def test_a_technique_the_catalogue_pins_differently_is_reported(show):
    """The live case. A run mapped CertificateGet, SecretList and KeyList to
    T1555.006 and then wrote "unmapped" for CertificateList, which the index
    pins to that same technique. One wrong label in thirty-three, and the
    summary said nothing because nothing compared the two."""
    vector = NS(name="Certificate listing", operation="CertificateList",
                log_table="AZKVAuditLogs", mitre_technique="unmapped")
    out = show(_result([_det("unmapped", "Certificate listing")],
                       analysis=NS(attack_vectors=[vector])))
    assert "TECHNIQUE DISAGREEMENTS" in out
    assert "CertificateList" in out
    assert "T1555.006" in out


def test_agreement_and_ignorance_both_stay_silent(show):
    """Two different things the catalogue can say, and neither earns a line.

    An operation it pins to exactly what the run chose is a non-event. So is one
    it has no opinion about -- VaultGet is a considered rejection, not a mapping,
    and reporting "no disagreement" for it would turn every clean run into a
    wall of nothing-happened."""
    agrees = NS(name="Secret read", operation="SecretGet",
                log_table="AZKVAuditLogs", mitre_technique="T1555.006")
    unknown = NS(name="Vault read", operation="VaultGet",
                 log_table="AZKVAuditLogs", mitre_technique="T1078.004")
    out = show(_result([_det("T1555.006", "Secret read")],
                       analysis=NS(attack_vectors=[agrees, unknown])))
    assert "TECHNIQUE DISAGREEMENTS" not in out


def test_the_run_is_reported_never_rewritten(show):
    """The label the model chose is what the detection line shows, even where
    the catalogue disagrees. Correcting it silently would make the disagreement
    rate unobservable -- and that rate is the whole signal, since ten rows means
    the prompt is fighting the index rather than the model having slipped."""
    vector = NS(name="Certificate listing", operation="CertificateList",
                log_table="AZKVAuditLogs", mitre_technique="unmapped")
    out = show(_result([_det("unmapped", "Certificate listing")],
                       analysis=NS(attack_vectors=[vector])))
    detection_line = next(l for l in out.splitlines() if "ok " in l)
    assert "unmapped" in detection_line
