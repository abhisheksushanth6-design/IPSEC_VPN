"""Layer 05 — feature model.

Plain dataclasses, like Layers 03 and 04, so calculation has no web-framework
dependency. The API layer converts these to Pydantic schemas.

A feature is a *fact* about an observed entity plus the metadata needed to
know how far to trust it. Three ideas matter and are kept apart:

- ``value`` is the raw calculated fact. It is never overwritten by a
  normalized value; ``normalized_value`` is a separate slot that stays None
  until a later section fits normalization parameters on real data.
- ``availability`` says whether the source data allowed the feature to be
  calculated at all. UNAVAILABLE means "not calculated", never "zero".
- ``quality`` says how complete the source data was for a value that *was*
  calculated. A count over partially visible evidence is PARTIAL, not
  COMPLETE, even though it has a number.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Optional, Union

FeatureLevel = Literal["PACKET", "SESSION", "SA"]
EntityType = Literal["PACKET", "SESSION", "SA"]
FeatureType = Literal["INTEGER", "FLOAT", "BOOLEAN", "CATEGORICAL", "TIMESTAMP"]
FeatureCategory = Literal[
    "TRAFFIC", "TIMING", "PROTOCOL", "IPSEC", "IKE", "SA_LIFECYCLE", "DIRECTIONAL", "STATISTICAL"
]
FeatureAvailability = Literal["AVAILABLE", "PARTIAL", "UNAVAILABLE"]
FeatureQuality = Literal["COMPLETE", "PARTIAL", "MISSING_SOURCE_DATA"]
NormalizationMethod = Literal["NONE", "MIN_MAX", "STANDARD", "ROBUST", "CATEGORICAL_ENCODING"]

FeatureScalar = Union[int, float, bool, str, None]

#: Schema version for the feature set. Bump when a feature's *meaning*
#: changes, never silently reuse a name for a different calculation.
FEATURE_VERSION = "1.0"


@dataclass(frozen=True)
class FeatureDefinition:
    """Static description of one feature. Owned by the registry."""

    name: str
    display_name: str
    description: str
    level: FeatureLevel
    category: FeatureCategory
    data_type: FeatureType
    unit: Optional[str]
    source: str
    nullable: bool
    formula: Optional[str] = None
    normalization_method: NormalizationMethod = "NONE"
    minimum_expected_value: Optional[float] = None
    maximum_expected_value: Optional[float] = None


@dataclass
class FeatureValue:
    """One calculated feature, with its lineage and quality metadata."""

    name: str
    value: FeatureScalar
    availability: FeatureAvailability
    quality: FeatureQuality
    source: str
    detail: Optional[str] = None
    #: Reserved for Section 9+ normalization. Raw values are never replaced.
    normalized_value: Optional[float] = None
    normalization_method: NormalizationMethod = "NONE"


@dataclass
class SourceAvailability:
    """What source data the extraction actually had to work with."""

    name: str
    available: bool
    detail: str


@dataclass
class FeatureVector:
    """Features calculated for a single entity at one point in time."""

    entity_id: str
    entity_type: EntityType
    entity_label: str
    capture_id: str
    feature_version: str
    generated_at: str
    features: list[FeatureValue] = field(default_factory=list)
    sources: list[SourceAvailability] = field(default_factory=list)

    @property
    def available_count(self) -> int:
        return sum(1 for f in self.features if f.availability == "AVAILABLE")

    @property
    def partial_count(self) -> int:
        return sum(1 for f in self.features if f.availability == "PARTIAL")

    @property
    def unavailable_count(self) -> int:
        return sum(1 for f in self.features if f.availability == "UNAVAILABLE")
