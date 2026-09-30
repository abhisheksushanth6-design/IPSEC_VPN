"""Layer 02 Live Capture Service.

Orchestrates the live packet capture lifecycle:
IDLE -> STARTING -> CAPTURING -> STOPPING -> INGESTING -> COMPLETED.
Interfaces directly with VirtualBox NIC tracing and hands finalized PCAP files
to Layer 03 and downstream session/SA engines.
"""

from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.layers.layer01_test_environment.service import get_environment_service
from app.layers.layer01_test_environment.vbox_manager import VBoxManager
from app.layers.layer02_packet_capture.capture_engine import (
    DEFAULT_LIVE_CAPTURE_DIR,
    VBoxCaptureEngine,
    count_pcap_packets,
)
from app.schemas.live_capture import (
    CaptureSourceInterface,
    LiveCaptureInterfacesResponse,
    LiveCaptureStatusResponse,
    ScapyPacketSummary,
    StopCaptureResponse,
)
from app.services.packet_service import packet_service
from app.services.sa_lifecycle_service import sa_lifecycle_service
from app.services.session_service import session_service

logger = logging.getLogger(__name__)


class LiveCaptureService:
    """Singleton service managing live packet capture sessions."""

    def __init__(
        self,
        vbox_manager: Optional[VBoxManager] = None,
        capture_engine: Optional[VBoxCaptureEngine] = None,
    ) -> None:
        self.vbox_manager = vbox_manager or VBoxManager()
        self.capture_engine = capture_engine or VBoxCaptureEngine(self.vbox_manager)
        self._lock = threading.Lock()

        # State machine fields
        self._state: str = "IDLE"  # IDLE, STARTING, CAPTURING, STOPPING, INGESTING, COMPLETED, ERROR
        self._capture_id: Optional[str] = None
        self._source_vm: Optional[str] = None
        self._nic_number: Optional[int] = None
        self._output_file: Optional[str] = None
        self._started_at_epoch: Optional[float] = None
        self._started_at_iso: Optional[str] = None
        self._last_error: Optional[str] = None
        self._last_ingestion_result: Optional[dict] = None

    def get_interfaces(self) -> LiveCaptureInterfacesResponse:
        """Query VirtualBox and Layer 01 to list real available capture interfaces."""
        env_service = get_environment_service()
        vms = env_service.get_vms_info()

        interfaces: list[CaptureSourceInterface] = []
        default_vm: Optional[str] = None
        default_nic: Optional[int] = None

        for vm in vms:
            # Query machine-readable info to inspect all NICs
            details = self.vbox_manager.get_vm_info(vm.uuid) or {}
            raw = details.get("raw", {})

            for i in range(1, 9):
                nic_mode = raw.get(f"nic{i}")
                if not nic_mode or nic_mode == "none":
                    continue

                mac = raw.get(f"macaddress{i}")
                adapter_name = raw.get(f"hostonlyadapter{i}") or raw.get(f"natnet{i}") or nic_mode
                is_recommended = (nic_mode == "hostonly" and vm.role in {"server", "client"})
                is_running = vm.state.lower() == "running"

                if is_recommended and is_running and not default_vm:
                    default_vm = vm.name
                    default_nic = i

                interfaces.append(
                    CaptureSourceInterface(
                        vm_name=vm.name,
                        vm_uuid=vm.uuid,
                        vm_state=vm.state,
                        role=vm.role,
                        nic_number=i,
                        nic_type=nic_mode,
                        adapter_name=adapter_name,
                        mac_address=mac,
                        is_recommended=is_recommended,
                    )
                )

        if not default_vm and interfaces:
            # Fallback to recommended, then running, then first
            recs = [iface for iface in interfaces if iface.is_recommended]
            running = [iface for iface in interfaces if iface.vm_state.lower() == "running"]
            if recs:
                default_vm = recs[0].vm_name
                default_nic = recs[0].nic_number
            elif running:
                default_vm = running[0].vm_name
                default_nic = running[0].nic_number
            else:
                default_vm = interfaces[0].vm_name
                default_nic = interfaces[0].nic_number

        return LiveCaptureInterfacesResponse(
            interfaces=interfaces,
            default_vm=default_vm,
            default_nic=default_nic or 1,
        )

    def get_status(self) -> LiveCaptureStatusResponse:
        """Return real current live capture status and statistics."""
        with self._lock:
            state = self._state
            capture_id = self._capture_id
            source_vm = self._source_vm
            nic_number = self._nic_number
            output_file = self._output_file
            started_iso = self._started_at_iso
            started_epoch = self._started_at_epoch
            last_err = self._last_error

        elapsed = 0.0
        packet_count = 0
        file_size = 0

        recent_packets: list[ScapyPacketSummary] = []
        if output_file and os.path.isfile(output_file):
            try:
                file_size = os.path.getsize(output_file)
                packet_count = count_pcap_packets(output_file)
                if state in {"CAPTURING", "COMPLETED"} and packet_count > 0:
                    from app.layers.layer02_packet_capture.scapy_reader import parse_pcap_with_scapy
                    try:
                        pcap_summary = parse_pcap_with_scapy(output_file, max_packets=200)
                        recent_packets = [
                            ScapyPacketSummary(
                                packet_number=p.packet_number,
                                timestamp=p.timestamp,
                                source_ip=p.source_ip,
                                destination_ip=p.destination_ip,
                                protocol=p.protocol,
                                source_port=p.source_port,
                                destination_port=p.destination_port,
                                length=p.length,
                                summary=p.summary,
                                is_ipsec=p.is_ipsec,
                            )
                            for p in pcap_summary.packets[-30:]
                        ]
                    except Exception as parse_err:
                        logger.debug("Live packet parsing non-critical warning: %s", parse_err)
            except Exception:
                pass

        if started_epoch and state in {"CAPTURING", "STOPPING", "INGESTING"}:
            elapsed = max(0.0, time.time() - started_epoch)

        return LiveCaptureStatusResponse(
            state=state,
            capture_id=capture_id,
            source_vm=source_vm,
            nic_number=nic_number,
            output_file=output_file,
            started_at=started_iso,
            elapsed_seconds=round(elapsed, 1),
            packet_count=packet_count,
            file_size_bytes=file_size,
            recent_packets=recent_packets,
            error=last_err,
        )

    def start_capture(self, vm_name_or_uuid: str, nic_number: Optional[int] = None) -> LiveCaptureStatusResponse:
        """Start a real packet capture on the selected VM and NIC."""
        with self._lock:
            if self._state == "CAPTURING":
                raise ValueError("A capture session is already actively running. Stop it before starting a new one.")
            self._state = "STARTING"
            self._last_error = None

        try:
            # 1. Validate VM exists
            vms = self.vbox_manager.list_vms()
            matching = [v for v in vms if v["uuid"] == vm_name_or_uuid or v["name"] == vm_name_or_uuid]
            if not matching:
                raise ValueError(f"VM '{vm_name_or_uuid}' is not registered in VirtualBox.")

            target_vm_name = matching[0]["name"]
            target_vm_uuid = matching[0]["uuid"]

            # 2. Check VM power state
            vm_info = self.vbox_manager.get_vm_info(target_vm_uuid)
            if not vm_info or vm_info["state"].lower() != "running":
                curr_state = vm_info["state"] if vm_info else "unknown"
                raise RuntimeError(
                    f"VM_NOT_RUNNING: VM '{target_vm_name}' is currently {curr_state}. "
                    "Start the VM in the Test Environment console before beginning packet capture."
                )

            # 3. Resolve NIC number dynamically if not specified
            raw = vm_info.get("raw", {})
            resolved_nic = nic_number
            if resolved_nic is None:
                for i in range(1, 9):
                    if raw.get(f"nic{i}") == "hostonly":
                        resolved_nic = i
                        break
                if resolved_nic is None:
                    resolved_nic = 1

            # 4. Generate unique output PCAP path
            timestamp = int(time.time())
            unique_suffix = uuid.uuid4().hex[:6]
            filename = f"live_session_{timestamp}_{unique_suffix}.pcap"
            output_path = str(DEFAULT_LIVE_CAPTURE_DIR / filename)

            # 5. Engage VirtualBox NIC tracing
            success, msg = self.capture_engine.start_trace(target_vm_uuid, resolved_nic, output_path)
            if not success:
                raise RuntimeError(f"VirtualBox NIC tracing failure: {msg}")

            with self._lock:
                self._state = "CAPTURING"
                self._capture_id = f"CAP-{unique_suffix.upper()}"
                self._source_vm = target_vm_name
                self._nic_number = resolved_nic
                self._output_file = output_path
                self._started_at_epoch = time.time()
                self._started_at_iso = datetime.now(timezone.utc).isoformat()
                self._last_error = None

            return self.get_status()

        except Exception as exc:
            with self._lock:
                self._state = "ERROR"
                self._last_error = str(exc)
            logger.exception("Failed to start live capture: %s", exc)
            raise

    def stop_capture(self) -> StopCaptureResponse:
        """Stop active capture, finalize PCAP, and pass automatically to Layer 03."""
        with self._lock:
            if self._state != "CAPTURING":
                raise ValueError(f"Cannot stop capture; current state is {self._state}")
            self._state = "STOPPING"
            target_vm = self._source_vm
            target_nic = self._nic_number
            output_file = self._output_file
            capture_id = self._capture_id or f"CAP-{uuid.uuid4().hex[:6].upper()}"

        try:
            # 1. Stop VirtualBox NIC tracing
            if target_vm and target_nic:
                self.capture_engine.stop_trace(target_vm, target_nic)

            # Allow filesystem a moment to flush buffers
            time.sleep(0.5)

            # 2. Count final packets and size
            packet_count = 0
            file_size = 0
            if output_file and os.path.isfile(output_file):
                file_size = os.path.getsize(output_file)
                packet_count = count_pcap_packets(output_file)

            with self._lock:
                self._state = "INGESTING"

            # 3. Layer 03 automatic ingestion
            ingest_status = "COMPLETED"
            analysis_id: Optional[str] = None
            sessions_count = 0

            if output_file and os.path.isfile(output_file) and file_size > 0:
                with open(output_file, "rb") as f:
                    pcap_bytes = f.read()

                # Ingest into Layer 03 Packet Store
                l3_status = packet_service.load(pcap_bytes, os.path.basename(output_file))
                analysis_id = packet_service.capture_id

                # Trigger session discovery and SA lifecycle engines
                try:
                    session_res = session_service.discover()
                    sessions_count = session_res.statistics.total if session_res.statistics else 0
                except Exception as ex:
                    logger.warning("Downstream session discovery warning: %s", ex)

                try:
                    sa_lifecycle_service.discover()
                except Exception as ex:
                    logger.warning("Downstream SA lifecycle discovery warning: %s", ex)

                # Trigger downstream analysis pipeline (Layers 05 to 10) for discovered sessions
                try:
                    from sqlalchemy import select
                    from app.db.base import SessionLocal
                    from app.models.ipsec_session import IPsecSession
                    from app.models.baseline import BaselineProfileRow
                    from app.services.feature_service import feature_service
                    from app.services.fingerprint_service import fingerprint_service
                    from app.services.drift_service import drift_service
                    from app.layers.layer08_ai_ml.service import AIAnomalyService
                    from app.layers.layer08_ai_ml.schemas import AnomalyInferenceRequest
                    from app.layers.layer09_vulnerability_engine.service import VulnerabilityService
                    from app.layers.layer10_risk_engine.service import get_risk_engine_service

                    with SessionLocal() as db:
                        target_sessions = (
                            db.scalars(
                                select(IPsecSession).where(IPsecSession.capture_id == analysis_id)
                            ).all()
                            if analysis_id
                            else []
                        )

                        active_baseline = db.scalar(
                            select(BaselineProfileRow).where(BaselineProfileRow.is_active.is_(True))
                        )

                        risk_svc = get_risk_engine_service()
                        anomaly_svc = AIAnomalyService(db)
                        vuln_svc = VulnerabilityService()

                        for s in target_sessions:
                            # Layer 05: Feature Extraction
                            try:
                                feature_service.extract("SESSION", s.id, capture_id=analysis_id or capture_id)
                            except Exception as ex:
                                logger.warning("Downstream Layer 05 extraction error for %s: %s", s.id, ex)

                            # Layer 06: Session Fingerprinting
                            try:
                                fingerprint_service.get_or_create_for_session(s.id)
                            except Exception as ex:
                                logger.warning("Downstream Layer 06 fingerprinting error for %s: %s", s.id, ex)

                            # Layer 07: Security Drift Detection (only when active baseline precondition is satisfied)
                            if active_baseline is not None:
                                try:
                                    drift_service.analyze(s.id, baseline_id=active_baseline.id)
                                except Exception as ex:
                                    logger.warning("Downstream Layer 07 drift error for %s: %s", s.id, ex)

                            # Layer 08: AI/ML Anomaly Detection (using active model, e.g. model_cicids_xgb_local)
                            try:
                                anomaly_svc.run_inference(AnomalyInferenceRequest(session_id=s.id))
                            except Exception as ex:
                                logger.warning("Downstream Layer 08 ML inference error for %s: %s", s.id, ex)

                            # Layer 08: Supervised Random Forest Traffic Classifier (Encrypted ESP)
                            try:
                                from app.layers.layer08_ai_ml.traffic_classifier import TrafficClassificationService
                                traf_classifier_svc = TrafficClassificationService(db)
                                traf_classifier_svc.classify_session(s)
                            except Exception as ex:
                                logger.warning("Downstream Layer 08 RF classification error for %s: %s", s.id, ex)

                            # Layer 09: Vulnerability Engine
                            try:
                                vuln_svc.analyze_session(db, s.id)
                            except Exception as ex:
                                logger.warning("Downstream Layer 09 vulnerability evaluation error for %s: %s", s.id, ex)

                            # Layer 10: Risk Assessment
                            try:
                                risk_svc.evaluate_session(db, s.id, force_refresh=True)
                            except Exception as ex:
                                logger.warning("Downstream Layer 10 risk evaluation error for %s: %s", s.id, ex)

                except Exception as ex:
                    logger.warning("Downstream pipeline execution warning: %s", ex)
            else:
                ingest_status = "EMPTY_CAPTURE"

            with self._lock:
                self._state = "COMPLETED"

            return StopCaptureResponse(
                capture_id=capture_id,
                pcap_path=output_file or "",
                packet_count=packet_count,
                file_size_bytes=file_size,
                ingestion_status=ingest_status,
                analysis_id=analysis_id,
                sessions_discovered=sessions_count,
                error=None,
            )

        except Exception as exc:
            with self._lock:
                self._state = "ERROR"
                self._last_error = str(exc)
            logger.exception("Failed to stop live capture: %s", exc)
            return StopCaptureResponse(
                capture_id=capture_id,
                pcap_path=output_file or "",
                packet_count=0,
                file_size_bytes=0,
                ingestion_status="ERROR",
                analysis_id=None,
                sessions_discovered=0,
                error=str(exc),
            )

    def get_layer_status(self) -> str:
        """Derive dynamic Layer 02 status."""
        with self._lock:
            state = self._state
        if state == "CAPTURING":
            return "CAPTURING"
        if state == "ERROR":
            return "ERROR"
        if self.vbox_manager.is_available:
            return "READY"
        # Live VM capture needs the VirtualBox testbed; offline PCAP ingestion and
        # software-testbed captures still flow through this layer, so the layer is
        # partially operational rather than uninitialised.
        return "PARTIALLY_OPERATIONAL"


# Singleton instance accessor
_live_capture_service_instance: Optional[LiveCaptureService] = None


def get_live_capture_service() -> LiveCaptureService:
    """Return singleton LiveCaptureService instance."""
    global _live_capture_service_instance
    if _live_capture_service_instance is None:
        _live_capture_service_instance = LiveCaptureService()
    return _live_capture_service_instance
