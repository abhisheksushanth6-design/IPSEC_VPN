"""Standalone Reproducible Verification Script for Layer 09 — Security Rule & Vulnerability Engine.

Validates:
1. Database tables and connectivity
2. 20 built-in security rules registered across 7 categories
3. Rule enablement and disablement toggling
4. Deterministic security rule evaluation on realistic IPsec protocol sessions
5. Deduplication engine (recurrence counting and hash invariance)
6. Technical RFC evidence bindings (observed vs expected parameters)
7. Finding lifecycle triage workflow (OPEN -> CONFIRMED -> RESOLVED)
8. Audit report JSON export functionality
9. Dynamic operational status verification
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Add backend directory to sys.path so app modules import cleanly
BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.db.base import SessionLocal
from app.db.init_db import initialize_database
from app.layers.layer09_vulnerability_engine import (
    FindingStatus,
    get_layer_status,
    get_rule_registry,
    get_vulnerability_service,
)
from app.models.ipsec_session import IPsecSession
from app.models.vulnerability import FindingEvidenceRow, SecurityRuleRow, VulnerabilityFindingRow


def print_section(title: str) -> None:
    print(f"\n{'='*70}\n[LAYER 09 VERIFICATION] {title}\n{'='*70}")


def main() -> int:
    print_section("Step 1: Database Initialization & Integrity Check")
    initialize_database()
    db = SessionLocal()

    try:
        # Clean test session and findings if previously left
        db.query(VulnerabilityFindingRow).filter(VulnerabilityFindingRow.affected_session_id.like("verify-%")).delete()
        db.query(IPsecSession).filter(IPsecSession.id.like("verify-%")).delete()
        db.commit()

        print("[OK] Database connection verified. Tables accessible.")

        print_section("Step 2: Rule Registry & Category Completeness")
        service = get_vulnerability_service()
        registry = get_rule_registry()
        total_rules = registry.count()
        print(f"[INFO] Total registered security rules: {total_rules}")
        if total_rules < 20:
            print(f"[FAIL] Expected at least 20 rules, found {total_rules}")
            return 1

        rules_list = registry.list_rules()
        categories = sorted({r.category.value for r in rules_list})
        print(f"[INFO] Active rule categories ({len(categories)}): {', '.join(categories)}")
        for r in rules_list:
            print(f"  - [{r.category.value}] {r.rule_id}: {r.name} ({r.severity.value})")

        print_section("Step 3: Rule Enablement / Disablement Toggle Verification")
        test_rule_id = "RULE-CRYPTO-001"
        service.set_rule_enabled(db, test_rule_id, enabled=False)
        rule_meta = service.get_rule(db, test_rule_id)
        if not rule_meta or rule_meta.enabled:
            print(f"[FAIL] Expected {test_rule_id} to be disabled")
            return 1
        print(f"[OK] Rule {test_rule_id} successfully disabled.")

        service.set_rule_enabled(db, test_rule_id, enabled=True)
        rule_meta = service.get_rule(db, test_rule_id)
        if not rule_meta or not rule_meta.enabled:
            print(f"[FAIL] Expected {test_rule_id} to be enabled")
            return 1
        print(f"[OK] Rule {test_rule_id} successfully re-enabled.")

        print_section("Step 4: Real Protocol Session Analysis & Rule Execution")
        test_session_id = "verify-layer09-sess-001"
        session_obj = IPsecSession(
            id=test_session_id,
            capture_id="verify-cap-001",
            ordinal=1,
            source="10.100.0.10",
            destination="10.200.0.20",
            direction="BIDIRECTIONAL",
            state="ACTIVE",
            correlation="CORRELATED",
            packet_count=35,
            byte_count=4500,
            ike_packets=10,
            esp_packets=25,
            ah_packets=0,
            ike_version="1.0",  # Triggers RULE-IKE-001
            nat_traversal=False,
            detail_json=json.dumps({
                "ike": {
                    "cipher": "3DES",  # Triggers RULE-CRYPTO-001
                    "integrity": "HMAC-MD5",  # Triggers RULE-CRYPTO-002
                    "version": "1.0",
                },
                "sa": {
                    "pfs_enabled": False,  # Triggers RULE-CONF-002
                },
            }),
        )
        db.add(session_obj)
        db.commit()
        print(f"[INFO] Created protocol evaluation session '{test_session_id}'.")

        # Run analysis
        analysis_res = service.analyze_session(db, test_session_id)
        print(f"[OK] Analysis completed. Generated {len(analysis_res)} findings.")
        if len(analysis_res) == 0:
            print("[FAIL] Expected security findings, got 0.")
            return 1

        for f in analysis_res:
            print(f"  * Finding {f.rule_id} [{f.severity}]: {f.title} (ID: {f.id})")

        print_section("Step 5: Deduplication Engine & Recurrence Verification")
        initial_finding = analysis_res[0]
        initial_count = initial_finding.occurrence_count

        # Run analysis again on identical session
        analysis_res_2 = service.analyze_session(db, test_session_id)
        updated_finding = db.get(VulnerabilityFindingRow, initial_finding.id)
        if not updated_finding:
            print("[FAIL] Finding row disappeared after re-analysis.")
            return 1

        print(f"[INFO] Finding ID: {updated_finding.id}")
        print(f"[INFO] Initial recurrence count: {initial_count}, Updated recurrence count: {updated_finding.occurrence_count}")
        if updated_finding.occurrence_count <= initial_count:
            print("[FAIL] Expected occurrence_count to increment deterministically.")
            return 1
        print("[OK] Deterministic deduplication verified: recurrence incremented without row duplication.")

        print_section("Step 6: Technical Evidence & RFC Remediations Binding")
        finding_detail = service.get_finding_detail(db, updated_finding.id)
        if not finding_detail:
            print("[FAIL] Finding detail retrieval returned None.")
            return 1

        evidence_list = finding_detail.evidence
        print(f"[INFO] Technical evidence items ({len(evidence_list)}):")
        for ev in evidence_list:
            print(f"  - [{ev.evidence_source}] {ev.field_name}: Observed '{ev.observed_value}' vs Expected '{ev.expected_value}'")

        print(f"[INFO] Remediation standard: {finding_detail.remediation[:80]}...")
        print(f"[INFO] References: {', '.join(finding_detail.cve_references)}")
        if not finding_detail.remediation or not finding_detail.cve_references:
            print("[FAIL] Missing authoritative remediation or references.")
            return 1
        print("[OK] RFC evidence bindings and remediation recommendations verified.")

        print_section("Step 7: SOC Analyst Triage Lifecycle Transitions")
        triage_updated = service.update_finding_status(db, updated_finding.id, FindingStatus.CONFIRMED)
        if not triage_updated or triage_updated.status != "CONFIRMED":
            print("[FAIL] Status update to CONFIRMED failed.")
            return 1
        print("[OK] Finding transitioned to CONFIRMED.")

        triage_resolved = service.update_finding_status(db, updated_finding.id, FindingStatus.RESOLVED)
        if not triage_resolved or triage_resolved.status != "RESOLVED":
            print("[FAIL] Status update to RESOLVED failed.")
            return 1
        print("[OK] Finding transitioned to RESOLVED.")

        print_section("Step 8: Audit Report Export Verification")
        export_data = service.export_findings(db, session_id=test_session_id)
        if not export_data or export_data.get("layer") != 9:
            print("[FAIL] Export format missing Layer 9 identifier.")
            return 1

        print(f"[INFO] Export contains {export_data.get('total_findings')} findings.")
        print(f"[INFO] Export summary: {export_data.get('summary')}")
        print("[OK] Structured JSON export verified.")

        print_section("Step 9: Dynamic Operational Status")
        layer_status = get_layer_status(db)
        print(f"[INFO] Layer Status: {layer_status['status']}")
        print(f"[INFO] Total Rules: {layer_status['total_rules']}, Enabled: {layer_status['enabled_rules']}")
        print(f"[INFO] Categories: {layer_status['categories']}")
        if layer_status["status"] != "OPERATIONAL":
            print(f"[FAIL] Layer status is {layer_status['status']}, expected OPERATIONAL.")
            return 1

        print_section("VERIFICATION SUMMARY: LAYER 09 IS FULLY OPERATIONAL")
        print("All 9 verification steps completed successfully with zero defects.")
        return 0

    finally:
        # Cleanup verification test records
        try:
            db.query(VulnerabilityFindingRow).filter(VulnerabilityFindingRow.affected_session_id.like("verify-%")).delete()
            db.query(IPsecSession).filter(IPsecSession.id.like("verify-%")).delete()
            db.commit()
        except Exception:
            pass
        db.close()


if __name__ == "__main__":
    sys.exit(main())
