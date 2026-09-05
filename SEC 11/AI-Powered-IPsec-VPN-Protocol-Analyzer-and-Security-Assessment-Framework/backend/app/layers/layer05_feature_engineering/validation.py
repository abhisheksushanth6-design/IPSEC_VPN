"""Feature validation and the emit surface used by calculators.

Two rules drive everything here.

**Zero is not null.** ``rekey_count = 0`` is a finding: the evidence was
present and no rekey happened. ``rekey_count = null`` means the question
could not be answered. Calculators must therefore say which one they mean,
so there is no default that quietly turns missing data into a zero.

**A value that fails validation is not emitted.** NaN, infinity, a negative
count, a ratio above one or a value of the wrong type all become UNAVAILABLE
with the reason attached, rather than travelling downstream as a number a
later model would treat as real.
"""

from __future__ import annotations

import math
from typing import Optional

from .models import (
    FeatureAvailability,
    FeatureQuality,
    FeatureScalar,
    FeatureValue,
)
from .registry import definition


class FeatureValidationError(ValueError):
    """Raised when a calculator emits a name that is not registered."""


def _type_ok(data_type: str, value: object) -> bool:
    if data_type == "BOOLEAN":
        return isinstance(value, bool)
    if data_type == "INTEGER":
        # bool is an int subclass; an integer feature must not be a bool.
        return isinstance(value, int) and not isinstance(value, bool)
    if data_type == "FLOAT":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if data_type in ("CATEGORICAL", "TIMESTAMP"):
        return isinstance(value, str) and value != ""
    return False


def validate(level: str, name: str, value: FeatureScalar) -> Optional[str]:
    """Return None when the value is usable, otherwise the reason it is not."""
    spec = definition(level, name)

    if value is None:
        return "No value was calculated."

    if isinstance(value, float):
        if math.isnan(value):
            return "Calculation produced NaN."
        if math.isinf(value):
            return "Calculation produced an infinite value."

    if not _type_ok(spec.data_type, value):
        return f"Value is not a valid {spec.data_type.lower()}."

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if spec.minimum_expected_value is not None and value < spec.minimum_expected_value:
            return f"Value {value} is below the valid minimum of {spec.minimum_expected_value:g}."
        if spec.maximum_expected_value is not None and value > spec.maximum_expected_value:
            return f"Value {value} is above the valid maximum of {spec.maximum_expected_value:g}."

    return None


def safe_divide(numerator: float | int | None, denominator: float | int | None) -> Optional[float]:
    """Division that returns None instead of raising, or producing inf/NaN."""
    if numerator is None or denominator is None:
        return None
    if denominator == 0:
        return None
    result = numerator / denominator
    if math.isnan(result) or math.isinf(result):
        return None
    return result


def round_float(value: Optional[float], places: int = 6) -> Optional[float]:
    """Keep stored precision sensible; the UI formats for display separately."""
    return None if value is None else round(float(value), places)


class FeatureSet:
    """Collects validated features for one entity at one level.

    Calculators call :meth:`add` when they have a fact and :meth:`missing`
    when they do not. Both paths are explicit, which is what keeps a missing
    observation from being emitted as a zero.
    """

    def __init__(self, level: str) -> None:
        self.level = level
        self._values: list[FeatureValue] = []
        self._seen: set[str] = set()

    def _record(
        self,
        name: str,
        value: FeatureScalar,
        availability: FeatureAvailability,
        quality: FeatureQuality,
        detail: Optional[str],
        source: Optional[str],
    ) -> None:
        spec = definition(self.level, name)  # raises for unregistered names
        if name in self._seen:
            raise FeatureValidationError(f"Feature {self.level}/{name} was emitted twice.")
        self._seen.add(name)
        self._values.append(
            FeatureValue(
                name=name,
                value=value,
                availability=availability,
                quality=quality,
                source=source or spec.source,
                detail=detail,
                normalized_value=None,
                normalization_method=spec.normalization_method,
            )
        )

    def add(
        self,
        name: str,
        value: FeatureScalar,
        *,
        detail: Optional[str] = None,
        source: Optional[str] = None,
        partial: bool = False,
        partial_detail: Optional[str] = None,
    ) -> None:
        """Emit a calculated value.

        ``partial=True`` marks a value that was calculated over source data
        known to be incomplete — a count of payloads when some were encrypted,
        for instance. The number is real, but it is a floor, not a total.
        """
        reason = validate(self.level, name, value)
        if reason is not None:
            self._record(name, None, "UNAVAILABLE", "MISSING_SOURCE_DATA", reason, source)
            return
        if partial:
            combined = partial_detail or detail
            self._record(name, value, "PARTIAL", "PARTIAL", combined, source)
            return
        self._record(name, value, "AVAILABLE", "COMPLETE", detail, source)

    def missing(self, name: str, detail: str, *, source: Optional[str] = None) -> None:
        """Record that a feature could not be calculated, and why."""
        self._record(name, None, "UNAVAILABLE", "MISSING_SOURCE_DATA", detail, source)

    def add_or_missing(
        self,
        name: str,
        value: FeatureScalar,
        missing_detail: str,
        *,
        detail: Optional[str] = None,
        source: Optional[str] = None,
        partial: bool = False,
    ) -> None:
        """Emit ``value`` when it is not None, otherwise record it as missing."""
        if value is None:
            self.missing(name, missing_detail, source=source)
        else:
            self.add(name, value, detail=detail, source=source, partial=partial)

    @property
    def values(self) -> list[FeatureValue]:
        return list(self._values)
