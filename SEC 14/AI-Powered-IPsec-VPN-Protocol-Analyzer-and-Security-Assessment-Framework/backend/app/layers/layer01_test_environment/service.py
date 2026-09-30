"""Layer 01 Environment Service.

Orchestrates VirtualBox VM discovery, host-only networking inspection,
reachability checks, and StrongSwan / IPsec status verification.
Provides dynamic layer status derivation and factual evidence collection.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from app.core.config import get_settings
from app.layers.layer01_test_environment.network_discovery import NetworkDiscovery
from app.layers.layer01_test_environment.strongswan_checker import StrongSwanChecker
from app.layers.layer01_test_environment.vbox_manager import VBoxManager
from app.schemas.environment import (
    EnvironmentEvidenceResponse,
    EnvironmentHealthSummary,
    EnvironmentStatusResponse,
    EnvironmentVerificationResponse,
    HostOnlyNetworkInfo,
    VerificationCheckItem,
    VirtualBoxInfo,
    VMActionResponse,
    VMInfo,
)

logger = logging.getLogger(__name__)


class EnvironmentService:
    """Core service for Layer 01 — IPsec VPN Test Environment."""

    def __init__(
        self,
        vbox_manager: Optional[VBoxManager] = None,
        network_discovery: Optional[NetworkDiscovery] = None,
        strongswan_checker: Optional[StrongSwanChecker] = None,
    ) -> None:
        settings = get_settings()
        self.settings = settings
        self.vbox_manager = vbox_manager or VBoxManager(settings.vboxmanage_path)
        self.network_discovery = network_discovery or NetworkDiscovery(settings.host_only_adapter_name)
        self.strongswan_checker = strongswan_checker or StrongSwanChecker(
            ssh_user=settings.guest_ssh_user,
            ssh_key_path=settings.guest_ssh_key_path,
            ssh_password=settings.guest_ssh_password,
        )
        self._is_verifying = False

    def _determine_vm_role(self, vm_name: str) -> tuple[str, bool]:
        """Map a VM name to its configured or inferred role."""
        name_lower = vm_name.lower().strip()
        client_cfg = self.settings.client_vm_name.lower().strip()
        server_cfg = self.settings.server_vm_name.lower().strip()
        analyzer_cfg = self.settings.analyzer_vm_name.lower().strip()

        # Exact / configured role match
        if name_lower == client_cfg or name_lower == "ipsec-client":
            return "client", True
        if name_lower == server_cfg or name_lower == "ipsec-server":
            return "server", True
        if name_lower == analyzer_cfg or name_lower == "name: ipsec-analyzer" or name_lower == "ipsec-analyzer":
            return "analyzer", True

        # Inferred fallback
        if "client" in name_lower:
            return "client", False
        if "server" in name_lower:
            return "server", False
        if "analyzer" in name_lower:
            return "analyzer", False

        return "other", False

    def _get_static_ip_for_role(self, role: str) -> Optional[str]:
        """Return static fallback IP for standard roles if defined."""
        if role == "client":
            return self.settings.client_static_ip or "192.168.56.104"
        if role == "server":
            return self.settings.server_static_ip or "192.168.56.20"
        return None

    def get_vms_info(self) -> list[VMInfo]:
        """Discover all VMs, query power state and host-only MAC/IP addresses."""
        raw_vms = self.vbox_manager.list_vms()
        vms_info: list[VMInfo] = []

        for vm in raw_vms:
            details = self.vbox_manager.get_vm_info(vm["uuid"]) or {}
            role, is_configured = self._determine_vm_role(vm["name"])
            mac = details.get("hostonly_mac")
            static_fallback = self._get_static_ip_for_role(role)
            ips = self.network_discovery.discover_ip_for_mac(mac, static_fallback=static_fallback)

            vms_info.append(
                VMInfo(
                    name=vm["name"],
                    uuid=vm["uuid"],
                    role=role,
                    state=details.get("state", "unknown"),
                    os_type=details.get("os_type"),
                    mac_address=mac,
                    ip_addresses=ips,
                    is_configured_role=is_configured,
                )
            )

        return vms_info

    def get_host_only_network_info(self) -> HostOnlyNetworkInfo:
        """Inspect host-only network adapters."""
        interfaces = self.vbox_manager.list_hostonly_interfaces()
        if not interfaces:
            return HostOnlyNetworkInfo(
                available=False,
                error="No VirtualBox host-only network interfaces found",
            )

        # Look for target adapter name or pick first
        target_name = self.settings.host_only_adapter_name.lower()
        selected: Optional[dict[str, str]] = None
        for iface in interfaces:
            if target_name in iface.get("Name", "").lower():
                selected = iface
                break
        if not selected and interfaces:
            selected = interfaces[0]

        if not selected:
            return HostOnlyNetworkInfo(available=False, error="Adapter not located")

        return HostOnlyNetworkInfo(
            available=True,
            name=selected.get("Name"),
            ip_address=selected.get("IPAddress"),
            network_mask=selected.get("NetworkMask"),
            status=selected.get("Status", "Up"),
        )

    def get_layer_status(self) -> str:
        """Derive dynamic Layer 01 status based on real environment state.

        The layer has two back-ends: the VirtualBox/strongSwan VM testbed and the in-process
        software testbed (real RFC 4303 ESP framing and encryption, model-generated traffic).
        Without a hypervisor the layer is PARTIALLY_OPERATIONAL, not broken.
        """
        if self._is_verifying:
            return "INITIALIZING"

        if not self.vbox_manager.is_available:
            return "PARTIALLY_OPERATIONAL"

        vbox_ok, _, _ = self.vbox_manager.get_version()
        if not vbox_ok:
            return "PARTIALLY_OPERATIONAL"

        net = self.get_host_only_network_info()
        if not net.available:
            return "WARNING"

        vms = self.vbox_manager.list_vms()
        if not vms:
            return "WARNING"

        # Check if configured client and server VMs are discovered
        discovered_names = {v["name"].lower() for v in vms}
        client_name = self.settings.client_vm_name.lower()
        server_name = self.settings.server_vm_name.lower()

        has_client = client_name in discovered_names or any("client" in n for n in discovered_names)
        has_server = server_name in discovered_names or any("server" in n for n in discovered_names)

        if has_client and has_server:
            return "READY"

        return "WARNING"

    def get_status(self) -> EnvironmentStatusResponse:
        """Assemble full real environment status."""
        vbox_installed = self.vbox_manager.is_available
        version_ok, version_str, vbox_err = self.vbox_manager.get_version() if vbox_installed else (False, None, "VBoxManage not found")

        vbox_info = VirtualBoxInfo(
            installed=vbox_installed and version_ok,
            version=version_str,
            vboxmanage_path=self.vbox_manager.vboxmanage_path,
            error=vbox_err,
        )

        net_info = self.get_host_only_network_info()
        vms = self.get_vms_info()

        running_count = sum(1 for v in vms if v.state.lower() == "running")
        has_client = any(v.role == "client" for v in vms)
        has_server = any(v.role == "server" for v in vms)
        has_analyzer = any(v.role == "analyzer" for v in vms)

        health = EnvironmentHealthSummary(
            all_roles_discovered=has_client and has_server and has_analyzer,
            running_count=running_count,
            total_count=len([v for v in vms if v.role in {"client", "server", "analyzer"}]),
            network_ready=net_info.available and net_info.status == "Up",
        )

        return EnvironmentStatusResponse(
            layer_number=1,
            layer_name="IPsec VPN Test Environment",
            layer_status=self.get_layer_status(),
            virtualbox=vbox_info,
            host_only_network=net_info,
            vms=vms,
            health_summary=health,
        )

    def start_vm(self, vm_id: str) -> VMActionResponse:
        """Start a discovered VM safely."""
        success, msg = self.vbox_manager.start_vm(vm_id, headless=True)
        new_state = "running" if success else "error"
        return VMActionResponse(
            success=success,
            vm_id=vm_id,
            state=new_state,
            message=msg,
            error=None if success else msg,
        )

    def stop_vm(self, vm_id: str, force: bool = False) -> VMActionResponse:
        """Stop a discovered VM gracefully (ACPI) or forcibly."""
        success, msg = self.vbox_manager.stop_vm(vm_id, force=force)
        new_state = "poweroff" if success and force else "stopping" if success else "error"
        return VMActionResponse(
            success=success,
            vm_id=vm_id,
            state=new_state,
            message=msg,
            error=None if success else msg,
        )

    def verify_environment(self) -> EnvironmentVerificationResponse:
        """Execute active factual checks across the test environment."""
        self._is_verifying = True
        try:
            checks: list[VerificationCheckItem] = []
            now = datetime.now(timezone.utc).isoformat()

            # 1. VirtualBox availability
            vbox_ok, version, vbox_err = self.vbox_manager.get_version()
            if vbox_ok:
                checks.append(
                    VerificationCheckItem(
                        id="vbox_installed",
                        name="VirtualBox Hypervisor Availability",
                        status="PASS",
                        evidence=f"Oracle VirtualBox {version} operational at '{self.vbox_manager.vboxmanage_path}'",
                    )
                )
            else:
                checks.append(
                    VerificationCheckItem(
                        id="vbox_installed",
                        name="VirtualBox Hypervisor Availability",
                        status="FAIL",
                        evidence=f"VirtualBox unavailable: {vbox_err}",
                        error=vbox_err,
                    )
                )

            # 2. VM Discovery
            vms = self.get_vms_info()
            client_vm = next((v for v in vms if v.role == "client"), None)
            server_vm = next((v for v in vms if v.role == "server"), None)
            analyzer_vm = next((v for v in vms if v.role == "analyzer"), None)

            if client_vm and server_vm and analyzer_vm:
                checks.append(
                    VerificationCheckItem(
                        id="vm_roles_discovered",
                        name="Configured Role VM Discovery",
                        status="PASS",
                        evidence=(
                            f"Discovered Client ('{client_vm.name}', state={client_vm.state}), "
                            f"Server ('{server_vm.name}', state={server_vm.state}), "
                            f"Analyzer ('{analyzer_vm.name}', state={analyzer_vm.state})"
                        ),
                    )
                )
            elif client_vm and server_vm:
                checks.append(
                    VerificationCheckItem(
                        id="vm_roles_discovered",
                        name="Configured Role VM Discovery",
                        status="PASS",
                        evidence=f"Discovered Client ('{client_vm.name}') and Server ('{server_vm.name}')",
                    )
                )
            else:
                checks.append(
                    VerificationCheckItem(
                        id="vm_roles_discovered",
                        name="Configured Role VM Discovery",
                        status="FAIL",
                        evidence=f"Found {len(vms)} VMs, but missing client or server role VM",
                        error="Configured IPsec role VMs not fully discovered",
                    )
                )

            # 3. Host-Only Network
            net = self.get_host_only_network_info()
            if net.available and net.status == "Up":
                checks.append(
                    VerificationCheckItem(
                        id="host_only_network",
                        name="Host-Only Network Interface",
                        status="PASS",
                        evidence=f"Interface '{net.name}' active on IP {net.ip_address}/{net.network_mask}",
                    )
                )
            elif net.available:
                checks.append(
                    VerificationCheckItem(
                        id="host_only_network",
                        name="Host-Only Network Interface",
                        status="WARNING",
                        evidence=f"Interface '{net.name}' detected but status is '{net.status}'",
                    )
                )
            else:
                checks.append(
                    VerificationCheckItem(
                        id="host_only_network",
                        name="Host-Only Network Interface",
                        status="FAIL",
                        evidence=net.error or "Host-only adapter not found",
                        error=net.error,
                    )
                )

            # 4. Client reachability check
            client_ip = client_vm.ip_addresses[0] if client_vm and client_vm.ip_addresses else self.settings.client_static_ip
            if client_vm and client_vm.state.lower() == "running" and client_ip:
                reachable, msg, _ = self.network_discovery.ping_host(client_ip)
                checks.append(
                    VerificationCheckItem(
                        id="client_reachability",
                        name=f"Client VM Reachability ({client_ip})",
                        status="PASS" if reachable else "FAIL",
                        evidence=msg,
                    )
                )
            else:
                reason = f"VM state is '{client_vm.state}'" if client_vm else "VM not found"
                checks.append(
                    VerificationCheckItem(
                        id="client_reachability",
                        name=f"Client VM Reachability ({client_ip or 'No IP'})",
                        status="UNKNOWN",
                        evidence=f"Client VM is not reachable ({reason})",
                    )
                )

            # 5. Server reachability check
            server_ip = server_vm.ip_addresses[0] if server_vm and server_vm.ip_addresses else self.settings.server_static_ip
            if server_vm and server_vm.state.lower() == "running" and server_ip:
                reachable, msg, _ = self.network_discovery.ping_host(server_ip)
                checks.append(
                    VerificationCheckItem(
                        id="server_reachability",
                        name=f"Server VM Reachability ({server_ip})",
                        status="PASS" if reachable else "FAIL",
                        evidence=msg,
                    )
                )
            else:
                reason = f"VM state is '{server_vm.state}'" if server_vm else "VM not found"
                checks.append(
                    VerificationCheckItem(
                        id="server_reachability",
                        name=f"Server VM Reachability ({server_ip or 'No IP'})",
                        status="UNKNOWN",
                        evidence=f"Server VM is not reachable ({reason})",
                    )
                )

            # 6. StrongSwan Service Check
            target_ip = server_ip or client_ip
            power_state = server_vm.state if server_vm else client_vm.state if client_vm else "poweroff"
            strongswan_res = self.strongswan_checker.inspect_vm_ipsec(
                ip_address=target_ip,
                vm_power_state=power_state,
                vm_role="server" if server_vm else "client",
            )
            checks.append(
                VerificationCheckItem(
                    id="strongswan_service",
                    name="StrongSwan Daemon Status",
                    status="PASS" if strongswan_res["strongswan_status"] == "RUNNING" else "UNKNOWN" if strongswan_res["strongswan_status"] == "UNKNOWN" else "FAIL",
                    evidence=strongswan_res["evidence"] or f"StrongSwan status: {strongswan_res['strongswan_status']}",
                )
            )

            # 7. IPsec SA Status Check
            checks.append(
                VerificationCheckItem(
                    id="ipsec_sa_status",
                    name="IKE / Child SA Status",
                    status="PASS" if strongswan_res["ipsec_status"] == "ESTABLISHED" else "UNKNOWN" if strongswan_res["ipsec_status"] == "UNKNOWN" else "WARNING" if strongswan_res["ipsec_status"] == "NO SA" else "FAIL",
                    evidence=f"SA state: {strongswan_res['ike_sa_state']}, Child SA: {strongswan_res['child_sa_state']}",
                )
            )

            # Determine overall status
            statuses = {c.status for c in checks}
            overall = "FAIL" if "FAIL" in statuses else "WARNING" if "WARNING" in statuses or "UNKNOWN" in statuses else "PASS"

            return EnvironmentVerificationResponse(
                timestamp=now,
                overall_status=overall,
                checks=checks,
            )
        finally:
            self._is_verifying = False

    def get_evidence(self) -> EnvironmentEvidenceResponse:
        """Gather factual evidence snapshot without invented data."""
        now = datetime.now(timezone.utc).isoformat()
        vbox_ok, version, vbox_err = self.vbox_manager.get_version()

        vbox_evidence = {
            "installed": vbox_ok,
            "version": version,
            "path": self.vbox_manager.vboxmanage_path,
            "error": vbox_err,
        }

        net = self.get_host_only_network_info()
        net_evidence = {
            "name": net.name,
            "ip_address": net.ip_address,
            "network_mask": net.network_mask,
            "status": net.status,
            "arp_table": self.network_discovery.get_arp_table(),
            "dhcp_leases": self.network_discovery.find_dhcp_leases(),
        }

        vms = self.get_vms_info()
        vms_evidence = [v.model_dump() for v in vms]

        reachability_evidence: dict[str, Any] = {}
        for v in vms:
            for ip in v.ip_addresses:
                reach, msg, rtt = self.network_discovery.ping_host(ip, timeout_ms=500)
                reachability_evidence[ip] = {
                    "reachable": reach,
                    "rtt_ms": rtt,
                    "message": msg,
                    "vm": v.name,
                }

        strongswan_evidence: dict[str, Any] = {}
        for v in vms:
            if v.role in {"client", "server"} and v.ip_addresses:
                res = self.strongswan_checker.inspect_vm_ipsec(
                    ip_address=v.ip_addresses[0],
                    vm_power_state=v.state,
                    vm_role=v.role,
                )
                strongswan_evidence[v.role] = res

        return EnvironmentEvidenceResponse(
            timestamp=now,
            virtualbox=vbox_evidence,
            network=net_evidence,
            vms=vms_evidence,
            reachability=reachability_evidence,
            strongswan=strongswan_evidence,
        )

    def get_testbed_profiles(self) -> list[dict[str, Any]]:
        """Return canonical SIH 26160 testbed profile configurations.

        The first six profiles are the VM testbed configurations; every profile can also be
        generated by the software testbed (``simulate_testbed_profile``), which adds the
        downgrade, AH-only, NAT-T and TFC-padded demonstrations.
        """
        from app.layers.layer01_test_environment.software_testbed import DEFAULT_PROFILES

        legacy = {p["id"]: p for p in self._legacy_profiles()}
        merged: list[dict[str, Any]] = []
        for cfg in DEFAULT_PROFILES:
            base = dict(legacy.get(cfg.profile_id, {}))
            base.update({
                "id": cfg.profile_id,
                "name": cfg.name,
                "mode": cfg.mode,
                "encryption": cfg.encryption if cfg.protocol == "ESP" else "AH (no encryption)",
                "integrity": cfg.integrity if cfg.integrity != "AEAD" else "AEAD (integrated)",
                "dh_group": f"Group {cfg.dh_group}",
                "dh_group_number": cfg.dh_group,
                "pfs_enabled": cfg.pfs_enabled,
                "ip_version": cfg.ip_version,
                "ike_version": cfg.ike_version,
                "ipsec_protocol": cfg.protocol,
                "nat_traversal": cfg.nat_traversal,
                "tfc_padding": cfg.tfc_padding,
                "downgrade_demo": cfg.downgrade,
                "traffic_type": cfg.traffic_type,
                "description": base.get("description") or cfg.description,
                "software_testbed": True,
            })
            base.setdefault("security_rating", "DEMO")
            base.setdefault("compliance_standard", "See compliance profiles after simulation")
            merged.append(base)
        return merged

    def _legacy_profiles(self) -> list[dict[str, Any]]:
        return [
            {
                "id": "PROFILE-01-TUNNEL-AES256GCM-PFS-IPV4",
                "name": "Standard Secure Gateway (Tunnel, AES-256-GCM, DH19, PFS, IPv4)",
                "mode": "TUNNEL",
                "encryption": "AES-256-GCM",
                "integrity": "AEAD",
                "dh_group": "Group 19 (256-bit ECP)",
                "pfs_enabled": True,
                "ip_version": 4,
                "traffic_type": "WEB_BROWSING",
                "security_rating": "HIGH",
                "compliance_standard": "NIST SP 800-77 Rev 1 / CNSA",
                "description": "Standard high-security site-to-site IPsec tunnel utilizing modern AEAD encryption and ephemeral elliptic curve Diffie-Hellman.",
            },
            {
                "id": "PROFILE-02-TRANSPORT-AES128CBC-PFS-IPV4",
                "name": "Host-to-Host Voice Tunnel (Transport, AES-128-CBC+HMAC, DH14, PFS, IPv4)",
                "mode": "TRANSPORT",
                "encryption": "AES-128-CBC",
                "integrity": "HMAC-SHA2-256",
                "dh_group": "Group 14 (2048-bit MODP)",
                "pfs_enabled": True,
                "ip_version": 4,
                "traffic_type": "VOIP",
                "security_rating": "ACCEPTABLE",
                "compliance_standard": "RFC 8221 Enterprise Baseline",
                "description": "Transport mode end-to-end IPsec session carrying isochronous VoIP RTP streams with 20ms cadence.",
            },
            {
                "id": "PROFILE-03-TUNNEL-AES128GCM-NOPFS-IPV4",
                "name": "Streaming Gateway (Tunnel, AES-128-GCM, DH14, PFS Disabled, IPv4)",
                "mode": "TUNNEL",
                "encryption": "AES-128-GCM",
                "integrity": "AEAD",
                "dh_group": "Group 14 (2048-bit MODP)",
                "pfs_enabled": False,
                "ip_version": 4,
                "traffic_type": "VIDEO_STREAMING",
                "security_rating": "MODERATE",
                "compliance_standard": "Standard Tunnel (PFS Warning)",
                "description": "Fast tunnel with hardware-accelerated AES-GCM streaming HLS video chunks; lacks phase 2 PFS rekeying.",
            },
            {
                "id": "PROFILE-04-TRANSPORT-AES256CBC-PFS-IPV6",
                "name": "Next-Gen Enterprise IPv6 (Transport, AES-256-CBC+HMAC, DH20, PFS, IPv6)",
                "mode": "TRANSPORT",
                "encryption": "AES-256-CBC",
                "integrity": "HMAC-SHA2-512",
                "dh_group": "Group 20 (384-bit ECP)",
                "pfs_enabled": True,
                "ip_version": 6,
                "traffic_type": "EMAIL",
                "security_rating": "HIGH",
                "compliance_standard": "IPv6 RFC 4301 / CNSA Suite",
                "description": "Transport mode over pure IPv6 network with hop-by-hop and routing headers, carrying batch email transfers.",
            },
            {
                "id": "PROFILE-05-TUNNEL-3DESCBC-NOPFS-IPV4",
                "name": "Legacy Deprecated Baseline (Tunnel, 3DES-CBC+MD5, DH2, PFS Disabled, IPv4)",
                "mode": "TUNNEL",
                "encryption": "3DES-CBC",
                "integrity": "HMAC-MD5-96",
                "dh_group": "Group 2 (1024-bit MODP)",
                "pfs_enabled": False,
                "ip_version": 4,
                "traffic_type": "ICMP",
                "security_rating": "CRITICAL_RISK",
                "compliance_standard": "NON-COMPLIANT (Sweet32 Vulnerable)",
                "description": "Legacy insecure tunnel configuration for demonstrating vulnerability detection, sweet32 exposure, and compliance rule violations.",
            },
            {
                "id": "PROFILE-06-TUNNEL-AES256GCM-PFS-IPV6",
                "name": "Government Critical Infrastructure (Tunnel, AES-256-GCM, DH21, PFS, IPv6)",
                "mode": "TUNNEL",
                "encryption": "AES-256-GCM",
                "integrity": "AEAD",
                "dh_group": "Group 21 (521-bit ECP)",
                "pfs_enabled": True,
                "ip_version": 6,
                "traffic_type": "WEB_BROWSING",
                "security_rating": "HIGH",
                "compliance_standard": "CNSA 2.0 / Post-Quantum Transition",
                "description": "Government-grade tunnel configuration utilizing 256-bit Galois/Counter Mode over IPv6 with maximum curve DH21.",
            },
        ]

    def simulate_testbed_profile(
        self,
        profile_id: str,
        seed: int = 1,
        traffic_type: Optional[str] = None,
        duration: Optional[float] = None,
        include_ike: bool = True,
        persist: bool = True,
    ) -> dict[str, Any]:
        """Generate a real-framing IPsec capture for the profile and load it into the analysis pipeline.

        The capture is produced by the software testbed (RFC 4303 ESP with real encryption,
        RFC 7296 / RFC 2409 IKE framing, model-generated application traffic), loaded into
        the packet store, and sessions + Security Associations are discovered. The ground
        truth of the generated configuration is registered so the dashboard can compare the
        platform's inferences against it.
        """
        from app.layers.layer01_test_environment.software_testbed import generate_capture, profile_by_id
        from app.services.packet_service import packet_service
        from app.services.sa_lifecycle_service import sa_lifecycle_service
        from app.services.session_service import session_service

        cfg = profile_by_id(profile_id)
        if cfg is None:
            raise ValueError(f"Unknown testbed profile '{profile_id}'")
        if traffic_type is not None and traffic_type not in ("VOIP", "WHATSAPP", "EMAIL", "WEB_BROWSING", "ICMP", "VIDEO_STREAMING", "OTHER"):
            raise ValueError(f"Unknown traffic type '{traffic_type}'")

        generated = generate_capture(profile_id, seed=seed, traffic_type=traffic_type, duration=duration, include_ike=include_ike)
        status = packet_service.load(generated.pcap_bytes, generated.filename)
        capture_id = packet_service.capture_id or generated.ground_truth["capture_id"]
        generated.ground_truth["capture_id"] = capture_id
        register_ground_truth(capture_id, generated.ground_truth)

        stored_path: Optional[str] = None
        if persist:
            try:
                from app.core.config import DEFAULT_DATA_DIR

                out_dir = DEFAULT_DATA_DIR / "captures" / "testbed"
                out_dir.mkdir(parents=True, exist_ok=True)
                path = out_dir / generated.filename
                path.write_bytes(generated.pcap_bytes)
                (out_dir / (generated.filename.rsplit(".", 1)[0] + ".ground_truth.json")).write_text(
                    json.dumps(generated.ground_truth, indent=2, sort_keys=True), encoding="utf-8"
                )
                stored_path = str(path)
            except OSError as exc:  # noqa: BLE001 - persistence is best effort
                logger.warning("Could not persist testbed capture: %s", exc)

        session_status = session_service.discover()
        sa_status = sa_lifecycle_service.discover()

        return {
            "status": "GENERATED",
            "generator": "software_testbed",
            "profile_id": profile_id,
            "profile_name": cfg.name,
            "capture_id": capture_id,
            "filename": generated.filename,
            "stored_path": stored_path,
            "packets_generated": generated.packet_count,
            "packets_loaded": status.capture.packet_count if status.capture else generated.packet_count,
            "sessions_discovered": session_status.statistics.total if session_status.statistics else 0,
            "security_associations_discovered": sa_status.statistics.total if sa_status.statistics else 0,
            "mode": cfg.mode,
            "traffic_type": generated.ground_truth["traffic_type"],
            "encryption": cfg.encryption if cfg.protocol == "ESP" else "AH (no encryption)",
            "integrity": cfg.integrity,
            "dh_group": cfg.dh_group,
            "pfs_enabled": cfg.pfs_enabled,
            "ike_version": cfg.ike_version,
            "seed": seed,
            "ground_truth": generated.ground_truth,
        }

    def get_ground_truth(self, capture_id: str) -> Optional[dict[str, Any]]:
        return _GROUND_TRUTH.get(capture_id)

    def list_generated_captures(self) -> list[dict[str, Any]]:
        return [dict(v, capture_id=k) for k, v in _GROUND_TRUTH.items()]


# Ground truth of captures produced by the software testbed, keyed by capture id.
_GROUND_TRUTH: dict[str, dict[str, Any]] = {}


def register_ground_truth(capture_id: str, truth: dict[str, Any]) -> None:
    _GROUND_TRUTH[capture_id] = truth


# Singleton instance accessor
_service_instance: Optional[EnvironmentService] = None


def get_environment_service() -> EnvironmentService:
    """Return singleton EnvironmentService instance."""
    global _service_instance
    if _service_instance is None:
        _service_instance = EnvironmentService()
    return _service_instance
