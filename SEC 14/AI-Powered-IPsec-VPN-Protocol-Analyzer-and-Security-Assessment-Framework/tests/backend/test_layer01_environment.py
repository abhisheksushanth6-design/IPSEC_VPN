"""Unit and integration tests for Layer 01 — IPsec VPN Test Environment.

Covers:
1. VBoxManage output parsing
2. VM discovery
3. VM state parsing
4. Role mapping
5. Host-only adapter parsing
6. IP extraction & MAC normalization
7. Command timeout handling
8. Command failure handling
9. Safe command construction (no shell=True)
10. API response schemas
11. Real integration test (skipped when VBoxManage not installed)
"""

from __future__ import annotations

import os
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from app.layers.layer01_test_environment.network_discovery import (
    NetworkDiscovery,
    normalize_mac,
)
from app.layers.layer01_test_environment.service import EnvironmentService
from app.layers.layer01_test_environment.strongswan_checker import (
    StrongSwanChecker,
    scrub_secrets,
)
from app.layers.layer01_test_environment.vbox_manager import VBoxManager

# Sample fixture outputs from real VBoxManage CLI
SAMPLE_LIST_VMS = """
"Kali" {058c8670-1feb-4f73-b803-aadb44f1630a}
"IPsec-Client" {2a23bdb9-58a1-4b07-8d49-07d679531b44}
"IPsec-Server" {6f8ca662-a839-4753-aefc-b10c49c880c8}
"Name: IPsec-Analyzer" {399a8a05-79ec-4ca1-9998-8cc8b17bd4d1}
"""

SAMPLE_SHOWVMINFO = """
name="IPsec-Client"
UUID="2a23bdb9-58a1-4b07-8d49-07d679531b44"
ostype="Ubuntu (64-bit)"
memory=2048
cpus=2
VMState="poweroff"
nic1="nat"
nic2="hostonly"
hostonlyadapter2="VirtualBox Host-Only Ethernet Adapter"
macaddress2="08002786308E"
"""

SAMPLE_HOSTONLYIFS = """
Name:            VirtualBox Host-Only Ethernet Adapter
GUID:            c4f6813c-692b-444b-a11e-0b92a97804f0
DHCP:            Disabled
IPAddress:       192.168.56.1
NetworkMask:     255.255.255.0
HardwareAddress: 0a:00:27:00:00:11
Status:          Up
"""


# 1. VBoxManage output parsing
def test_parse_vm_list() -> None:
    vms = VBoxManager.parse_vm_list(SAMPLE_LIST_VMS)
    assert len(vms) == 4
    names = [v["name"] for v in vms]
    assert "IPsec-Client" in names
    assert "IPsec-Server" in names
    assert "Name: IPsec-Analyzer" in names
    client_vm = next(v for v in vms if v["name"] == "IPsec-Client")
    assert client_vm["uuid"] == "2a23bdb9-58a1-4b07-8d49-07d679531b44"


# 2. VM discovery and info parsing
def test_parse_machine_readable_info() -> None:
    raw = VBoxManager.parse_machine_readable(SAMPLE_SHOWVMINFO)
    assert raw["name"] == "IPsec-Client"
    assert raw["VMState"] == "poweroff"
    assert raw["ostype"] == "Ubuntu (64-bit)"
    assert raw["macaddress2"] == "08002786308E"
    assert raw["hostonlyadapter2"] == "VirtualBox Host-Only Ethernet Adapter"


# 3. VM state parsing
def test_get_vm_info_state_extraction() -> None:
    mgr = VBoxManager(vboxmanage_path="dummy_path")
    with patch.object(mgr, "_run_command", return_value=(0, SAMPLE_SHOWVMINFO, "")):
        info = mgr.get_vm_info("IPsec-Client")
        assert info is not None
        assert info["name"] == "IPsec-Client"
        assert info["state"] == "poweroff"
        assert info["memory_mb"] == 2048
        assert info["cpus"] == 2
        assert info["hostonly_mac"] == "08002786308E"
        assert info["hostonly_adapter"] == "VirtualBox Host-Only Ethernet Adapter"


# 4. Role mapping
def test_role_mapping_exact_and_inferred() -> None:
    service = EnvironmentService()
    role, configured = service._determine_vm_role("IPsec-Client")
    assert role == "client"
    assert configured is True

    role, configured = service._determine_vm_role("IPsec-Server")
    assert role == "server"
    assert configured is True

    role, configured = service._determine_vm_role("Name: IPsec-Analyzer")
    assert role == "analyzer"
    assert configured is True

    role, configured = service._determine_vm_role("Custom-Client-Test")
    assert role == "client"
    assert configured is False

    role, configured = service._determine_vm_role("Kali")
    assert role == "other"
    assert configured is False


# 5. Host-only adapter parsing
def test_parse_hostonly_interfaces() -> None:
    ifaces = VBoxManager.parse_hostonly_interfaces(SAMPLE_HOSTONLYIFS)
    assert len(ifaces) == 1
    assert ifaces[0]["Name"] == "VirtualBox Host-Only Ethernet Adapter"
    assert ifaces[0]["IPAddress"] == "192.168.56.1"
    assert ifaces[0]["NetworkMask"] == "255.255.255.0"
    assert ifaces[0]["Status"] == "Up"


# 6. IP extraction & MAC normalization
def test_mac_normalization() -> None:
    assert normalize_mac("08:00:27:86:30:8e") == "08002786308e"
    assert normalize_mac("08-00-27-86-30-8E") == "08002786308e"
    assert normalize_mac("0800.2786.308e") == "08002786308e"
    assert normalize_mac(None) == ""


def test_ip_discovery_with_fallback() -> None:
    discovery = NetworkDiscovery()
    # Mock ARP table and DHCP leases
    with patch.object(discovery, "get_arp_table", return_value={"08002786308e": "192.168.56.104"}), \
         patch.object(discovery, "find_dhcp_leases", return_value={}):
        ips = discovery.discover_ip_for_mac("08:00:27:86:30:8E", static_fallback="192.168.56.104")
        assert "192.168.56.104" in ips


# 7. Command timeout handling
def test_command_timeout_handling() -> None:
    mgr = VBoxManager(vboxmanage_path="dummy_path")
    with patch("os.path.isfile", return_value=True), \
         patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["test"], timeout=5.0)):
        code, stdout, stderr = mgr._run_command(["list", "vms"], timeout=5.0)
        assert code == -2
        assert "timed out" in stderr


# 8. Command failure handling
def test_command_failure_handling() -> None:
    mgr = VBoxManager(vboxmanage_path="dummy_path")
    with patch("os.path.isfile", return_value=True), \
         patch("subprocess.run", side_effect=Exception("Permission denied")):
        code, stdout, stderr = mgr._run_command(["list", "vms"], timeout=5.0)
        assert code == -3
        assert "Permission denied" in stderr


# 9. Safe command construction (never shell=True, arguments array)
def test_safe_command_construction() -> None:
    mgr = VBoxManager(vboxmanage_path="dummy_path")
    with patch("os.path.isfile", return_value=True), \
         patch("subprocess.run") as mock_run:
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = SAMPLE_LIST_VMS
        mock_res.stderr = ""
        mock_run.return_value = mock_res

        mgr.list_vms()
        assert mock_run.called
        kwargs = mock_run.call_args[1]
        args = mock_run.call_args[0][0]
        assert kwargs.get("shell") is False
        assert isinstance(args, list)
        assert "list" in args
        assert "vms" in args


def test_secret_scrubbing() -> None:
    dirty = "user=admin&password=SuperSecretPassword123!&token=xyz789"
    cleaned = scrub_secrets(dirty)
    assert "SuperSecretPassword123!" not in cleaned
    assert "password=********" in cleaned


# 10. API response schemas
def test_api_environment_status(client) -> None:
    resp = client.get("/api/environment/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "virtualbox" in data
    assert "host_only_network" in data
    assert "vms" in data
    assert "layer_status" in data
    assert "health_summary" in data
    assert data["layer_number"] == 1


def test_api_environment_verify(client) -> None:
    resp = client.post("/api/environment/verify")
    assert resp.status_code == 200
    data = resp.json()
    assert "overall_status" in data
    assert "checks" in data
    assert len(data["checks"]) >= 5


def test_api_environment_evidence(client) -> None:
    resp = client.get("/api/environment/evidence")
    assert resp.status_code == 200
    data = resp.json()
    assert "virtualbox" in data
    assert "network" in data
    assert "vms" in data
    assert "reachability" in data


# 11. Real integration test (automatically skipped when VirtualBox is not present)
def test_real_virtualbox_integration() -> None:
    vbox_path = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
    if not os.path.isfile(vbox_path):
        pytest.skip("Oracle VirtualBox is not installed on this host")

    mgr = VBoxManager(vboxmanage_path=vbox_path)
    assert mgr.is_available is True
    ok, ver, err = mgr.get_version()
    assert ok is True
    assert ver is not None
    assert "7." in ver or "6." in ver or "5." in ver

    vms = mgr.list_vms()
    assert len(vms) >= 1
    vm_names = [v["name"] for v in vms]
    assert "IPsec-Client" in vm_names or "IPsec-Server" in vm_names
