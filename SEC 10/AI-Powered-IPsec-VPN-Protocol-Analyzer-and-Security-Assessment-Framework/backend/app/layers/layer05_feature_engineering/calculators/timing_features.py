"""Timing feature calculation.

Time-series features need more than one observation to exist. A single
timestamped packet has no interarrival gap and a single rekey has no
interval, so those features are reported unavailable rather than emitted as
zero — a zero gap would later read as "packets arrived simultaneously",
which is a different claim entirely.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional, Sequence

from ..validation import FeatureSet, round_float


def epoch(timestamp: Optional[str]) -> Optional[float]:
    """Parse an ISO timestamp to epoch seconds, matching Sections 6 and 7."""
    if not timestamp:
        return None
    try:
        return datetime.fromisoformat(timestamp).timestamp()
    except ValueError:
        return None


def duration_between(start: Optional[str], end: Optional[str]) -> Optional[float]:
    """Elapsed seconds between two ISO timestamps, or None if not derivable."""
    first, last = epoch(start), epoch(end)
    if first is None or last is None:
        return None
    value = last - first
    return round_float(value if value >= 0 else None)


def interarrival_gaps(timestamps: Sequence[str]) -> list[float]:
    """Gaps between consecutive timestamps, in chronological order."""
    points = sorted(t for t in (epoch(ts) for ts in timestamps) if t is not None)
    return [points[i] - points[i - 1] for i in range(1, len(points))]


def _variance(values: Sequence[float]) -> Optional[float]:
    if not values:
        return None
    mean = sum(values) / len(values)
    return sum((v - mean) ** 2 for v in values) / len(values)


def add_interarrival_features(
    fs: FeatureSet,
    timestamps: Sequence[str],
    *,
    source: Optional[str] = None,
    unavailable_detail: Optional[str] = None,
) -> None:
    """Mean, minimum, maximum and variance of packet interarrival gaps."""
    names = (
        "mean_interarrival_time",
        "min_interarrival_time",
        "max_interarrival_time",
        "interarrival_variance",
    )
    gaps = interarrival_gaps(timestamps)
    if not gaps:
        detail = unavailable_detail or (
            "At least two timestamped packets are needed to measure an interarrival gap; "
            f"{len(timestamps)} timestamped packet(s) available."
        )
        for name in names:
            fs.missing(name, detail, source=source)
        return

    fs.add("mean_interarrival_time", round_float(sum(gaps) / len(gaps)), source=source)
    fs.add("min_interarrival_time", round_float(min(gaps)), source=source)
    fs.add("max_interarrival_time", round_float(max(gaps)), source=source)
    fs.add("interarrival_variance", round_float(_variance(gaps)), source=source)


def add_rekey_interval_features(
    fs: FeatureSet,
    rekey_timestamps: Sequence[str],
    *,
    source: Optional[str] = None,
) -> None:
    """Rekey timing, which needs two rekeys before an interval exists."""
    usable = sorted(t for t in rekey_timestamps if epoch(t) is not None)
    if usable:
        fs.add("last_rekey_time", usable[-1], source=source)
    else:
        fs.missing(
            "last_rekey_time",
            "No timestamped rekey exchange was observed for this SA."
            if not rekey_timestamps
            else "Observed rekey events carry no usable timestamp.",
            source=source,
        )

    gaps = interarrival_gaps(usable)
    if not gaps:
        detail = (
            "At least two observed rekeys are needed to measure an interval; "
            f"{len(usable)} observed."
        )
        for name in ("mean_rekey_interval", "min_rekey_interval", "max_rekey_interval"):
            fs.missing(name, detail, source=source)
        return

    fs.add("mean_rekey_interval", round_float(sum(gaps) / len(gaps)), source=source)
    fs.add("min_rekey_interval", round_float(min(gaps)), source=source)
    fs.add("max_rekey_interval", round_float(max(gaps)), source=source)
