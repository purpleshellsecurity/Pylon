"""Hard cost/token caps, enforced in code (not by the model)."""

from pylon.usage import over_budget, record, reset_meter


def test_no_cap_never_over():
    reset_meter()
    record({"input_token_count": 10_000_000, "output_token_count": 10_000_000})
    assert over_budget(0.0, 0) is False  # 0 = unlimited


def test_token_cap_trips():
    reset_meter()
    record({"input_token_count": 600, "output_token_count": 500})  # 1100 total
    assert over_budget(0.0, 1000) is True
    assert over_budget(0.0, 2000) is False


def test_cost_cap_trips():
    reset_meter()
    # 1M input @ $1.25 + 1M output @ $10 = $11.25
    record({"input_token_count": 1_000_000, "output_token_count": 1_000_000})
    assert over_budget(5.0, 0) is True
    assert over_budget(20.0, 0) is False


def test_cap_checked_against_running_total():
    reset_meter()
    assert over_budget(1.0, 0) is False
    record({"input_token_count": 0, "output_token_count": 200_000})  # $2.00
    assert over_budget(1.0, 0) is True
