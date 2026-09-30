"""Labelled ESP-flow dataset built through the real analysis pipeline.

Every sample is a complete IPsec capture produced by the Layer 01 software testbed
(real RFC 4303 ESP framing and encryption, model-generated application traffic), decoded
by the Layer 03 parser and reduced to the Layer 07 feature vector by the *same*
``FlowFeatures.from_packets`` the classifier uses at inference time. There is therefore
no train/serve skew: the model only ever sees numbers the deployed pipeline produces.

Provenance, stated plainly: the application traffic is synthetic (statistical models of
VoIP, messaging, e-mail, web, ICMP, video and background flows), the IPsec framing and
encryption are real, no real user traffic is included. Real captures from the VM testbed
can be appended with :func:`features_from_pcap` and re-training keeps working unchanged.
"""

from __future__ import annotations

import csv
import json
import random
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from app.layers.layer01_test_environment.software_testbed import DEFAULT_PROFILES, TRAFFIC_TYPES, generate_capture
from app.layers.layer03_protocol_analysis import analyze_capture
from app.layers.layer08_ai_ml.traffic_classifier import FEATURE_NAMES, FEATURE_VECTOR_VERSION, FlowFeatures

DATASET_VERSION = "2.0"
META_COLUMNS = ["sample_id", "traffic_type", "profile_id", "seed", "duration_seconds", "include_ike", "packet_count", "data_packets",
                "cipher_family", "mode", "ip_version", "tfc_padding", "nat_traversal", "traffic_parameters"]

# Profiles used for dataset generation. AH-only (08) is excluded from training because its
# cleartext data plane is not the ESP problem; it stays available for assessment demos.
TRAINING_PROFILES = [p.profile_id for p in DEFAULT_PROFILES if p.protocol == "ESP"]


@dataclass
class DatasetRow:
    sample_id: str
    traffic_type: str
    profile_id: str
    seed: int
    duration_seconds: float
    include_ike: bool
    packet_count: int
    data_packets: int
    cipher_family: str
    mode: str
    ip_version: int
    tfc_padding: bool
    nat_traversal: bool
    traffic_parameters: Dict[str, Any]
    features: Dict[str, float]

    def to_csv_row(self) -> Dict[str, Any]:
        row = {
            "sample_id": self.sample_id, "traffic_type": self.traffic_type, "profile_id": self.profile_id, "seed": self.seed,
            "duration_seconds": self.duration_seconds, "include_ike": self.include_ike, "packet_count": self.packet_count,
            "data_packets": self.data_packets, "cipher_family": self.cipher_family, "mode": self.mode, "ip_version": self.ip_version,
            "tfc_padding": self.tfc_padding, "nat_traversal": self.nat_traversal, "traffic_parameters": json.dumps(self.traffic_parameters, sort_keys=True),
        }
        row.update({name: self.features[name] for name in FEATURE_NAMES})
        return row


def features_from_pcap(pcap_bytes: bytes, initiator: Optional[str] = None, session_id: str = "FLOW") -> Tuple[FlowFeatures, int]:
    """Decode a capture and compute the flow feature vector from its ESP/AH packets."""
    _meta, packets = analyze_capture(pcap_bytes, 60_000)
    data = [p for p in packets if p.ipsec is not None and (p.ipsec.esp is not None or p.ipsec.ah is not None)]
    if initiator is None and data:
        initiator = data[0].source
    return FlowFeatures.from_packets(data, session_id=session_id, initiator=initiator), len(packets)


def _build_one(spec: Tuple[str, str, int, float, bool, str]) -> Dict[str, Any]:
    traffic_type, profile_id, seed, duration, include_ike, sample_id = spec
    cap = generate_capture(profile_id, seed=seed, traffic_type=traffic_type, duration=duration, include_ike=include_ike)
    feats, total = features_from_pcap(cap.pcap_bytes, initiator=None, session_id=sample_id)
    truth = cap.ground_truth
    return {
        "sample_id": sample_id, "traffic_type": traffic_type, "profile_id": profile_id, "seed": seed, "duration_seconds": duration,
        "include_ike": include_ike, "packet_count": total, "data_packets": feats.packet_count, "cipher_family": truth["cipher_family"],
        "mode": truth["mode"], "ip_version": truth["ip_version"], "tfc_padding": truth["tfc_padding"], "nat_traversal": truth["nat_traversal"],
        "traffic_parameters": truth["traffic_parameters"], "features": dict(zip(FEATURE_NAMES, feats.vector())),
        "pcap": cap.pcap_bytes, "filename": cap.filename, "ground_truth": truth,
    }


def build_specs(samples_per_class: int, base_seed: int, profiles: Sequence[str], classes: Sequence[str] = TRAFFIC_TYPES,
                duration_range: Tuple[float, float] = (5.0, 60.0)) -> List[Tuple[str, str, int, float, bool, str]]:
    rng = random.Random(base_seed)
    specs = []
    for cls in classes:
        for i in range(samples_per_class):
            profile = profiles[i % len(profiles)]
            seed = base_seed + rng.randint(1, 10_000_000)
            duration = round(rng.uniform(*duration_range), 1)
            include_ike = rng.random() < 0.6
            specs.append((cls, profile, seed, duration, include_ike, f"FLOW-{cls}-{i + 1:04d}"))
    return specs


def generate_dataset(
    samples_per_class: int = 200,
    base_seed: int = 20240,
    profiles: Sequence[str] = tuple(TRAINING_PROFILES),
    out_dir: Optional[Path] = None,
    sample_pcaps_per_class: int = 3,
    workers: int = 1,
    progress: Optional[Any] = None,
) -> List[DatasetRow]:
    specs = build_specs(samples_per_class, base_seed, profiles)
    rows: List[DatasetRow] = []
    saved: Dict[str, int] = {}
    samples_dir = (out_dir / "samples") if out_dir else None
    if samples_dir:
        samples_dir.mkdir(parents=True, exist_ok=True)

    def _consume(result: Dict[str, Any]) -> None:
        cls = result["traffic_type"]
        if samples_dir is not None and saved.get(cls, 0) < sample_pcaps_per_class:
            saved[cls] = saved.get(cls, 0) + 1
            cls_dir = samples_dir / cls.lower()
            cls_dir.mkdir(parents=True, exist_ok=True)
            (cls_dir / result["filename"]).write_bytes(result["pcap"])
            (cls_dir / (result["filename"].rsplit(".", 1)[0] + ".ground_truth.json")).write_text(
                json.dumps(result["ground_truth"], indent=2, sort_keys=True), encoding="utf-8"
            )
        rows.append(DatasetRow(**{k: v for k, v in result.items() if k not in ("pcap", "filename", "ground_truth")}))
        if progress:
            progress(len(rows), len(specs))

    if workers > 1:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            for result in pool.map(_build_one, specs, chunksize=4):
                _consume(result)
    else:
        for spec in specs:
            _consume(_build_one(spec))

    if out_dir is not None:
        write_dataset(rows, out_dir)
    return rows


def write_dataset(rows: Iterable[DatasetRow], out_dir: Path) -> Tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = list(rows)
    csv_path = out_dir / f"esp_flow_features_v{DATASET_VERSION}.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=META_COLUMNS + FEATURE_NAMES)
        writer.writeheader()
        for r in rows:
            writer.writerow(r.to_csv_row())
    meta_path = out_dir / f"esp_flow_dataset_v{DATASET_VERSION}.json"
    counts: Dict[str, int] = {}
    for r in rows:
        counts[r.traffic_type] = counts.get(r.traffic_type, 0) + 1
    meta = {
        "dataset_version": DATASET_VERSION,
        "feature_vector_version": FEATURE_VECTOR_VERSION,
        "feature_names": FEATURE_NAMES,
        "classes": TRAFFIC_TYPES,
        "samples": len(rows),
        "samples_per_class": counts,
        "profiles": sorted({r.profile_id for r in rows}),
        "generator": "app.layers.layer01_test_environment.software_testbed (real RFC 4303 ESP framing + encryption, model-generated application traffic)",
        "pipeline": "generate_capture → Layer 03 analyze_capture → FlowFeatures.from_packets (identical to inference path)",
        "provenance": "SYNTHETIC_APPLICATION_TRAFFIC / REAL_IPSEC_FRAMING",
        "real_user_traffic": False,
        "csv": csv_path.name,
    }
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return csv_path, meta_path


def load_dataset(csv_path: Path) -> Tuple[List[List[float]], List[str], List[Dict[str, Any]]]:
    X: List[List[float]] = []
    y: List[str] = []
    meta: List[Dict[str, Any]] = []
    with csv_path.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            X.append([float(row[name]) for name in FEATURE_NAMES])
            y.append(row["traffic_type"])
            meta.append({k: row[k] for k in META_COLUMNS})
    return X, y, meta
