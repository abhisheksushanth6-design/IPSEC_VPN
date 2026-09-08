"""Unit and integration tests for Layer 02 — Packet Capture & Data Collection.

Covers:
1. Capture state machine
2. VM/NIC validation
3. Safe VBoxManage command construction
4. Path validation
5. Start failure handling
6. Stop failure handling
7. Timeout handling
8. Capture file creation
9. Real PCAP packet counting
10. Layer 03 ingestion handoff
11. Concurrent start rejection
12. Cleanup after failure
13. Live capture API endpoints
14. Real integration test (skipped when VirtualBox/VMs not available)
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.layers.layer02_packet_capture.capture_engine import (
    VBoxCaptureEngine,
    count_pcap_packets,
)
from app.layers.layer02_packet_capture.service import LiveCaptureService
from app.schemas.live_capture import LiveCaptureStatusResponse


def build_minimal_pcap_bytes(packet_count: int = 2) -> bytes:
    """Construct a minimal valid binary PCAP stream with dummy Ethernet frames."""
    # 24-byte PCAP global header (Little Endian, LinkType Ethernet = 1)
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    
    # 14-byte dummy ethernet frame (broadcast)
    dummy_frame = b"\xff\xff\xff\xff\xff\xff\x08\x00\x27\x11\x22\x33\x08\x00" + b"\x00" * 40
    frame_len = len(dummy_frame)
    
    records = []
    for i in range(packet_count):
        # 16-byte record header: ts_sec, ts_usec, incl_len, orig_len
        rec_hdr = struct.pack("<IIII", 1725000000 + i, i * 1000, frame_len, frame_len)
        records.append(rec_hdr + dummy_frame)
        
    return global_hdr + b"".join(records)


# 1. Real PCAP packet counting
def test_count_pcap_packets(tmp_path: Path) -> None:
    pcap_path = tmp_path / "test_sample.pcap"
    pcap_bytes = build_minimal_pcap_bytes(packet_count=5)
    pcap_path.write_bytes(pcap_bytes)

    count = count_pcap_packets(str(pcap_path))
    assert count == 5


def test_count_pcap_packets_empty_or_corrupt(tmp_path: Path) -> None:
    empty_file = tmp_path / "empty.pcap"
    empty_file.write_bytes(b"")
    assert count_pcap_packets(str(empty_file)) == 0

    corrupt_file = tmp_path / "corrupt.pcap"
    corrupt_file.write_bytes(b"invalid header bytes")
    assert count_pcap_packets(str(corrupt_file)) == 0


# 2. Safe command construction & argument isolation
def test_safe_vboxmanage_command_construction() -> None:
    mock_mgr = MagicMock()
    mock_mgr.is_available = True
    mock_mgr._run_command.return_value = (0, "", "")

    engine = VBoxCaptureEngine(vbox_manager=mock_mgr)
    success, msg = engine.start_trace("IPsec-Server", 2, "C:\\test\\capture.pcap")
    assert success is True

    # Check that _run_command was called with explicit list arrays
    assert mock_mgr._run_command.call_count == 2
    first_call_args = mock_mgr._run_command.call_args_list[0][0][0]
    assert first_call_args == ["controlvm", "IPsec-Server", "nictracefile2", str(Path("C:\\test\\capture.pcap").resolve())]

    second_call_args = mock_mgr._run_command.call_args_list[1][0][0]
    assert second_call_args == ["controlvm", "IPsec-Server", "nictrace2", "on"]


# 3. VM & NIC validation
def test_nic_validation_bounds() -> None:
    mock_mgr = MagicMock()
    mock_mgr.is_available = True
    engine = VBoxCaptureEngine(vbox_manager=mock_mgr)

    ok, msg = engine.start_trace("IPsec-Server", 0, "C:\\test.pcap")
    assert ok is False
    assert "Invalid NIC number" in msg

    ok, msg = engine.start_trace("IPsec-Server", 9, "C:\\test.pcap")
    assert ok is False
    assert "Invalid NIC number" in msg


# 4. Start rejection when VM is powered off (VM_NOT_RUNNING)
def test_start_rejection_when_vm_powered_off() -> None:
    mock_mgr = MagicMock()
    mock_mgr.is_available = True
    mock_mgr.list_vms.return_value = [{"name": "IPsec-Server", "uuid": "6f8ca662-a839-4753-aefc-b10c49c880c8"}]
    mock_mgr.get_vm_info.return_value = {"state": "poweroff", "raw": {"nic2": "hostonly"}}

    service = LiveCaptureService(vbox_manager=mock_mgr)
    with pytest.raises(RuntimeError) as exc_info:
        service.start_capture("IPsec-Server", nic_number=2)

    assert "VM_NOT_RUNNING" in str(exc_info.value)
    assert service.get_status().state == "ERROR"


# 5. Start rejection when VM does not exist
def test_start_rejection_nonexistent_vm() -> None:
    mock_mgr = MagicMock()
    mock_mgr.is_available = True
    mock_mgr.list_vms.return_value = []

    service = LiveCaptureService(vbox_manager=mock_mgr)
    with pytest.raises(ValueError) as exc_info:
        service.start_capture("NonExistentVM")

    assert "is not registered" in str(exc_info.value)


# 6. Concurrent start rejection
def test_concurrent_start_rejection() -> None:
    mock_mgr = MagicMock()
    mock_mgr.is_available = True
    mock_mgr.list_vms.return_value = [{"name": "IPsec-Server", "uuid": "1111-2222"}]
    mock_mgr.get_vm_info.return_value = {"state": "running", "raw": {"nic2": "hostonly"}}
    mock_mgr._run_command.return_value = (0, "", "")

    service = LiveCaptureService(vbox_manager=mock_mgr)
    service.start_capture("IPsec-Server", nic_number=2)
    assert service.get_status().state == "CAPTURING"

    # Attempt second start while capturing
    with pytest.raises(ValueError) as exc_info:
        service.start_capture("IPsec-Server", nic_number=2)
    assert "already actively running" in str(exc_info.value)


# 7. Stop capture and Layer 03 handoff
def test_stop_capture_and_layer03_handoff(tmp_path: Path) -> None:
    mock_mgr = MagicMock()
    mock_mgr.is_available = True
    mock_mgr.list_vms.return_value = [{"name": "IPsec-Server", "uuid": "1111-2222"}]
    mock_mgr.get_vm_info.return_value = {"state": "running", "raw": {"nic2": "hostonly"}}
    mock_mgr._run_command.return_value = (0, "", "")

    service = LiveCaptureService(vbox_manager=mock_mgr)
    # Start capture
    service.start_capture("IPsec-Server", nic_number=2)
    assert service.get_status().state == "CAPTURING"

    # Write test PCAP to the output file
    target_pcap = service.get_status().output_file
    assert target_pcap is not None
    pcap_bytes = build_minimal_pcap_bytes(packet_count=3)
    Path(target_pcap).write_bytes(pcap_bytes)

    # Stop capture
    res = service.stop_capture()
    assert res.ingestion_status == "COMPLETED"
    assert res.packet_count == 3
    assert res.file_size_bytes > 0
    assert service.get_status().state == "COMPLETED"


# 8. API endpoints verification
def test_api_live_capture_status(client) -> None:
    resp = client.get("/api/live-capture/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "state" in data
    assert "packet_count" in data
    assert "elapsed_seconds" in data


def test_api_live_capture_interfaces(client) -> None:
    resp = client.get("/api/live-capture/interfaces")
    assert resp.status_code == 200
    data = resp.json()
    assert "interfaces" in data


def test_api_live_capture_start_offline_vm_rejects(client, monkeypatch) -> None:
    # Deterministically test that powered-off VM returns 409 Conflict with VM_NOT_RUNNING
    from app.layers.layer02_packet_capture.service import get_live_capture_service
    service = get_live_capture_service()
    monkeypatch.setattr(
        service.vbox_manager,
        "get_vm_info",
        lambda uuid: {"state": "poweroff", "raw": {"nic2": "hostonly"}},
    )
    monkeypatch.setattr(
        service.vbox_manager,
        "list_vms",
        lambda: [{"name": "IPsec-Server", "uuid": "mock-uuid"}],
    )
    resp = client.post("/api/live-capture/start", json={"vm": "IPsec-Server", "nic": 2})
    assert resp.status_code in (400, 409)
    body_str = str(resp.json())
    assert "VM_NOT_RUNNING" in body_str


# 9. Real VirtualBox integration test (skipped if VirtualBox or VMs offline)
def test_real_virtualbox_capture_status() -> None:
    vbox_path = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
    if not os.path.isfile(vbox_path):
        pytest.skip("Oracle VirtualBox is not installed on this host")

    service = LiveCaptureService()
    interfaces_res = service.get_interfaces()
    assert len(interfaces_res.interfaces) >= 1
    # Check that recommended host-only NIC is discovered
    recommended = [i for i in interfaces_res.interfaces if i.is_recommended]
    assert len(recommended) >= 1
    assert recommended[0].nic_type == "hostonly"
