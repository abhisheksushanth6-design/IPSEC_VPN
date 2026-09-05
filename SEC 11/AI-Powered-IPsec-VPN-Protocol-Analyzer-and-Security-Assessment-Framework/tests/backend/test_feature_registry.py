"""Layer 05 registry integrity and output validation.

The registry is the contract later sections read, so these tests pin the
things that would silently corrupt a downstream model: a duplicate name, a
feature emitted without a definition, a value that escaped validation as NaN
or infinity, or a missing observation quietly stored as a zero.
"""

from __future__ import annotations

import math

import pytest

from app.layers.layer05_feature_engineering import (
    FEATURE_DEFINITIONS,
    FEATURE_VERSION,
    definition,
    definitions_for,
    has_definition,
)
from app.layers.layer05_feature_engineering.validation import (
    FeatureSet,
    round_float,
    safe_divide,
    validate,
)

LEVELS = ("PACKET", "SESSION", "SA")


# ----- registry integrity ---------------------------------------------------


def test_feature_version_is_declared() -> None:
    assert FEATURE_VERSION == "1.0"


def test_every_level_has_definitions() -> None:
    for level in LEVELS:
        assert definitions_for(level), f"no definitions registered for {level}"


def test_names_are_unique_per_level() -> None:
    for level in LEVELS:
        names = [d.name for d in definitions_for(level)]
        assert len(names) == len(set(names))


def test_names_are_snake_case_and_meaningful() -> None:
    for spec in FEATURE_DEFINITIONS:
        assert spec.name == spec.name.lower()
        assert " " not in spec.name and "-" not in spec.name
        # Names like value1 / metric2 / data3 are explicitly disallowed.
        assert not spec.name.rstrip("0123456789") != spec.name, spec.name


def test_every_definition_is_documented() -> None:
    for spec in FEATURE_DEFINITIONS:
        assert spec.display_name and spec.display_name != spec.name
        assert len(spec.description) > 20, spec.name
        assert spec.source, spec.name
        assert spec.data_type in ("INTEGER", "FLOAT", "BOOLEAN", "CATEGORICAL", "TIMESTAMP")
        assert spec.category in (
            "TRAFFIC", "TIMING", "PROTOCOL", "IPSEC", "IKE", "SA_LIFECYCLE", "DIRECTIONAL", "STATISTICAL"
        )


def test_numeric_features_declare_a_unit() -> None:
    for spec in FEATURE_DEFINITIONS:
        if spec.data_type in ("INTEGER", "FLOAT") and spec.category != "PROTOCOL":
            if spec.name in ("ip_version", "source_port", "destination_port", "ike_exchange_type", "ike_message_id", "sequence_number"):
                continue  # identifiers and enumerations, not measurements
            assert spec.unit, f"{spec.name} is numeric but declares no unit"


def test_ratio_features_are_bounded() -> None:
    for spec in FEATURE_DEFINITIONS:
        if spec.name.endswith("_ratio") and "inbound_outbound" not in spec.name:
            assert spec.minimum_expected_value == 0
            assert spec.maximum_expected_value == 1


def test_lookup_rejects_unknown_names() -> None:
    assert has_definition("SESSION", "packet_count")
    assert not has_definition("SESSION", "value1")
    with pytest.raises(KeyError):
        definition("SESSION", "not_a_feature")


def test_same_name_may_span_levels_with_one_meaning() -> None:
    # ike_version is registered at three levels and means the same thing.
    for level in LEVELS:
        assert definition(level, "ike_version").data_type == "CATEGORICAL"


# ----- helpers --------------------------------------------------------------


@pytest.mark.parametrize(
    "numerator,denominator",
    [(1, 0), (0, 0), (None, 5), (5, None), (1.0, 0.0)],
)
def test_safe_divide_never_returns_infinity(numerator, denominator) -> None:
    assert safe_divide(numerator, denominator) is None


def test_safe_divide_computes_normally() -> None:
    assert safe_divide(9, 4) == 2.25


def test_round_float_keeps_precision_sensible() -> None:
    assert round_float(1.2345678912345) == 1.234568
    assert round_float(None) is None


# ----- output validation ----------------------------------------------------


def test_nan_and_infinity_are_rejected() -> None:
    for bad in (float("nan"), float("inf"), float("-inf")):
        assert validate("SESSION", "packets_per_second", bad) is not None


def test_negative_counts_are_rejected() -> None:
    assert validate("SESSION", "packet_count", -1) is not None
    assert validate("SESSION", "packet_count", 0) is None


def test_out_of_range_ratios_are_rejected() -> None:
    assert validate("SESSION", "ike_ratio", 1.5) is not None
    assert validate("SESSION", "ike_ratio", -0.1) is not None
    assert validate("SESSION", "ike_ratio", 0.5) is None


def test_wrong_types_are_rejected() -> None:
    assert validate("SESSION", "packet_count", "seven") is not None
    assert validate("SESSION", "packet_count", True) is not None  # bool is not an int here
    assert validate("SESSION", "nat_traversal_observed", 1) is not None
    assert validate("SESSION", "session_state", "") is not None


def test_invalid_values_become_unavailable_not_zero() -> None:
    fs = FeatureSet("SESSION")
    fs.add("packets_per_second", float("inf"))
    fs.add("packet_count", -5)
    for value in fs.values:
        assert value.value is None
        assert value.availability == "UNAVAILABLE"
        assert value.quality == "MISSING_SOURCE_DATA"
        assert value.detail


def test_zero_and_missing_are_distinguishable() -> None:
    fs = FeatureSet("SA")
    fs.add("rekey_count", 0)
    fs.missing("child_sa_count", "Only an IKE SA can have child SAs.")
    zero, missing = fs.values
    assert zero.value == 0 and zero.availability == "AVAILABLE"
    assert missing.value is None and missing.availability == "UNAVAILABLE"


def test_partial_values_are_marked_not_dropped() -> None:
    fs = FeatureSet("SESSION")
    fs.add("ike_payload_count", 4, partial=True, partial_detail="Encrypted payloads not decoded.")
    value = fs.values[0]
    assert value.value == 4
    assert value.availability == "PARTIAL"
    assert value.quality == "PARTIAL"


def test_unregistered_names_cannot_be_emitted() -> None:
    fs = FeatureSet("SESSION")
    with pytest.raises(KeyError):
        fs.add("made_up_feature", 1)


def test_a_feature_cannot_be_emitted_twice() -> None:
    fs = FeatureSet("SESSION")
    fs.add("packet_count", 1)
    with pytest.raises(Exception):
        fs.add("packet_count", 2)


def test_normalization_is_architecture_only() -> None:
    """Section 8 builds the normalization surface but fits no parameters."""
    fs = FeatureSet("SESSION")
    fs.add("packet_count", 3)
    assert fs.values[0].normalized_value is None
    assert not any(math.isnan(d.minimum_expected_value or 0) for d in FEATURE_DEFINITIONS)
