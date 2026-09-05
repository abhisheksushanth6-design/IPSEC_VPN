"""Integration tests for DriftService and domain orchestration."""

from __future__ import annotations

import pytest

from app.db.init_db import initialize_database
from app.layers.layer06_session_fingerprinting.fingerprint import build_session_fingerprint
from app.layers.layer06_session_fingerprinting.service import build_baseline_profile
from app.services.baseline_service import baseline_service
from app.services.drift_service import drift_service
from app.services.feature_service import feature_service
from app.services.fingerprint_service import fingerprint_service
from app.services.session_service import session_service
from test_fingerprint import _make_sample_session_vector


@pytest.fixture(autouse=True)
def setup_db():
    initialize_database()
    drift_service.clear()
    baseline_service.clear()
    feature_service.clear()
    session_service.clear()
    yield
    drift_service.clear()
    baseline_service.clear()
    feature_service.clear()
    session_service.clear()


def test_drift_service_status_empty():
    """When no baselines exist, status is NOT INITIALIZED."""
    st = drift_service.get_status()
    assert st.state == "NOT INITIALIZED"
    assert st.total_analyses == 0


def test_drift_service_analyze_and_retrieve():
    """Build a baseline from sample fingerprints, persist a session vector, and execute drift analysis."""
    # 1. Register sample session vectors and fingerprint them
    v1 = _make_sample_session_vector(session_id="SESS-01", packet_count=50, byte_count=20000)
    v2 = _make_sample_session_vector(session_id="SESS-02", packet_count=60, byte_count=25000)
    v3 = _make_sample_session_vector(session_id="SESS-03", packet_count=55, byte_count=22000)

    fp1 = build_session_fingerprint(v1, "cap-1")
    fp2 = build_session_fingerprint(v2, "cap-1")
    fp3 = build_session_fingerprint(v3, "cap-1")

    fingerprint_service._persist_fingerprint(fp1)
    fingerprint_service._persist_fingerprint(fp2)
    fingerprint_service._persist_fingerprint(fp3)

    # 2. Build baseline from fingerprints and persist
    profile = build_baseline_profile(
        baseline_id="BASE-TEST-01",
        name="Production Reference Baseline",
        fingerprints=[fp1, fp2, fp3],
        minimum_sessions=2,
    )
    baseline_service._persist_profile(profile, fingerprints=[fp1, fp2, fp3], activate=True)

    # 3. Status should now be READY
    st = drift_service.get_status()
    assert st.state == "READY"
    assert st.active_baseline_id == "BASE-TEST-01"

    # 4. Analyze session SESS-01
    analysis = drift_service.analyze(session_id="SESS-01")
    assert analysis is not None
    assert analysis.session_id == "SESS-01"
    assert analysis.baseline_id == "BASE-TEST-01"
    assert analysis.status in ("WITHIN BASELINE", "DRIFT DETECTED")
    assert len(analysis.feature_results) > 0

    # 5. Verify retrieval by ID
    fetched = drift_service.get_analysis(analysis.id)
    assert fetched is not None
    assert fetched.id == analysis.id
    assert len(fetched.feature_results) == len(analysis.feature_results)

    # 6. Verify listing
    analyses = drift_service.list_analyses(session_id="SESS-01")
    assert len(analyses) >= 1
    assert analyses[0].id == analysis.id

    # 7. Status should now be AVAILABLE
    st_after = drift_service.get_status()
    assert st_after.state == "AVAILABLE"
    assert st_after.total_analyses == 1
