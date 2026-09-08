"""Pydantic schemas for Layer 01 — IPsec VPN Test Environment."""

from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, Field


class VirtualBoxInfo(BaseModel):
    """VirtualBox hypervisor details."""
    installed: bool = Field(..., description="Whether VirtualBox is installed and executable")
    version: Optional[str] = Field(default=None, description="VBoxManage version string")
    vboxmanage_path: str = Field(..., description="Path to VBoxManage executable")
    error: Optional[str] = Field(default=None, description="Error message if discovery failed")


class HostOnlyNetworkInfo(BaseModel):
    """VirtualBox host-only adapter network details."""
    available: bool = Field(..., description="Whether a host-only network adapter was detected")
    name: Optional[str] = Field(default=None, description="Network adapter interface name")
    ip_address: Optional[str] = Field(default=None, description="Host-only IP address")
    network_mask: Optional[str] = Field(default=None, description="Host-only subnet mask")
    status: Optional[str] = Field(default=None, description="Adapter status (Up/Down)")
    error: Optional[str] = Field(default=None, description="Error if network check failed")


class VMInfo(BaseModel):
    """Information about a discovered VirtualBox VM."""
    name: str = Field(..., description="Virtual machine name")
    uuid: str = Field(..., description="Virtual machine unique identifier")
    role: str = Field(..., description="Configured or inferred role (client, server, analyzer, other)")
    state: str = Field(..., description="VM power state (running, poweroff, paused, saved, aborted, error)")
    os_type: Optional[str] = Field(default=None, description="Guest operating system type")
    mac_address: Optional[str] = Field(default=None, description="Host-only interface MAC address")
    ip_addresses: list[str] = Field(default_factory=list, description="Discovered or configured IP addresses")
    is_configured_role: bool = Field(default=False, description="Whether this VM matches a configured role setting")


class EnvironmentHealthSummary(BaseModel):
    """Summary of environment health and readiness."""
    all_roles_discovered: bool = Field(..., description="Whether client, server, and analyzer VMs are discovered")
    running_count: int = Field(..., description="Number of currently running VMs")
    total_count: int = Field(..., description="Total number of role VMs")
    network_ready: bool = Field(..., description="Whether host-only network is operational")


class EnvironmentStatusResponse(BaseModel):
    """Complete environment status response for GET /api/environment/status."""
    layer_number: int = Field(default=1, description="Architecture layer number")
    layer_name: str = Field(default="IPsec VPN Test Environment", description="Architecture layer name")
    layer_status: str = Field(..., description="Dynamic layer readiness status (NOT INITIALIZED, INITIALIZING, READY, WARNING, ERROR)")
    virtualbox: VirtualBoxInfo = Field(..., description="VirtualBox installation state")
    host_only_network: HostOnlyNetworkInfo = Field(..., description="Host-only network state")
    vms: list[VMInfo] = Field(default_factory=list, description="List of discovered VMs")
    health_summary: EnvironmentHealthSummary = Field(..., description="Overall health summary")


class VMActionResponse(BaseModel):
    """Response for VM start and stop operations."""
    success: bool = Field(..., description="Whether the operation succeeded")
    vm_id: str = Field(..., description="Target VM identifier (name or UUID)")
    state: str = Field(..., description="Resulting VM state")
    message: str = Field(..., description="Human-readable result message")
    error: Optional[str] = Field(default=None, description="Error detail if operation failed")


class VerificationCheckItem(BaseModel):
    """A single environment verification check."""
    id: str = Field(..., description="Unique check identifier")
    name: str = Field(..., description="Display name of the check")
    status: str = Field(..., description="Check result (PASS, WARNING, FAIL, UNKNOWN)")
    evidence: str = Field(..., description="Factual evidence string collected during check")
    error: Optional[str] = Field(default=None, description="Error message if check failed")


class EnvironmentVerificationResponse(BaseModel):
    """Complete response for POST /api/environment/verify."""
    timestamp: str = Field(..., description="ISO 8601 verification timestamp")
    overall_status: str = Field(..., description="Overall status (PASS, WARNING, FAIL)")
    checks: list[VerificationCheckItem] = Field(default_factory=list, description="List of individual checks")


class EnvironmentEvidenceResponse(BaseModel):
    """Response for GET /api/environment/evidence containing only factual data."""
    timestamp: str = Field(..., description="ISO 8601 timestamp")
    virtualbox: dict[str, Any] = Field(default_factory=dict, description="VirtualBox version and path")
    network: dict[str, Any] = Field(default_factory=dict, description="Network interfaces and ARP details")
    vms: list[dict[str, Any]] = Field(default_factory=list, description="Discovered VMs and MAC addresses")
    reachability: dict[str, Any] = Field(default_factory=dict, description="Factual reachability and ping results")
    strongswan: dict[str, Any] = Field(default_factory=dict, description="StrongSwan and IPsec SA state details")
