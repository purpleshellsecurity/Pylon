from pylon.scoring import normalize_technique_id, score_program


def test_normalize_strips_name_suffix():
    assert normalize_technique_id("T1485 - Data Destruction") == "T1485"
    assert normalize_technique_id("T1552.001 - Credentials In Files") == "T1552.001"
    assert normalize_technique_id("T1078.004") == "T1078.004"


def test_embellished_ids_still_count_as_covered():
    score = score_program(
        threats_in_scope=["T1552.001", "T1485"],
        threats_covered=["T1552.001 - Credentials In Files", "T1485 - Data Destruction"],
    )
    assert score.generation_yield == 100
    assert score.critical_gaps == []


def test_full_yield_scores_100():
    score = score_program(
        threats_in_scope=["T1078.004", "T1530"],
        threats_covered=["T1078.004", "T1530"],
    )
    assert score.generation_yield == 100


def test_generation_yield_is_weighted():
    # in-scope: T1078.004 (weight 10) + T1087.004 (weight 7); only the weight-7 is
    # covered -> weighted yield = 7 / 17 = 41%, NOT a flat 50%. Missing the weight-10
    # costs more than missing the weight-7.
    score = score_program(
        threats_in_scope=["T1078.004", "T1087.004"],
        threats_covered=["T1087.004"],
    )
    assert score.generation_yield == 41
    assert "T1078.004" in [g["mitre_id"] for g in score.critical_gaps]  # weight 10 -> gap


def test_low_weight_gap_is_not_critical():
    score = score_program(threats_in_scope=["T1087.004"], threats_covered=[])
    assert score.critical_gaps == []


def test_empty_scope_scores_zero():
    score = score_program(threats_in_scope=[], threats_covered=[])
    assert score.generation_yield == 0
    assert score.catalog_coverage is None


def test_catalog_coverage_uses_external_denominator():
    # generation_yield can be 100 (all enumerated vectors detected) while true
    # coverage is low — the model enumerated only 1 of a 3-technique catalog.
    score = score_program(
        threats_in_scope=["T1078.004"],
        threats_covered=["T1078.004"],
        catalog_ids=["T1078.004", "T1530", "T1485"],
    )
    assert score.generation_yield == 100
    assert score.catalog_coverage is not None and score.catalog_coverage < 100
    assert score.catalog_covered == 1
    assert score.catalog_total == 3
    # T1530 (w9) and T1485 (w8) uncovered -> both are critical gaps from the catalog
    assert {g["mitre_id"] for g in score.critical_gaps} == {"T1530", "T1485"}


def test_no_catalog_means_no_coverage_number():
    score = score_program(threats_in_scope=["T1530"], threats_covered=["T1530"])
    assert score.catalog_coverage is None
    assert score.catalog_total == 0
