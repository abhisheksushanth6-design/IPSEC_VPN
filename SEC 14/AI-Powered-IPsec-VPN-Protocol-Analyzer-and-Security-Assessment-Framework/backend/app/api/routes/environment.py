"""FastAPI route definitions for Layer 01 — IPsec VPN Test Environment."""

from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, HTTPException, Query, status

from app.layers.layer01_test_environment.service import get_environment_service
from app.schemas.environment import (
    EnvironmentEvidenceResponse,
    EnvironmentStatusResponse,
    EnvironmentVerificationResponse,
    VMActionResponse,
)

router = APIRouter(prefix="/environment", tags=["environment"])


@router.get(
    "/status",
    response_model=EnvironmentStatusResponse,
    summary="Get test environment status",
    description="Returns current VirtualBox hypervisor state, host-only network details, and discovered role VMs.",
)
def get_environment_status() -> EnvironmentStatusResponse:
    service = get_environment_service()
    return service.get_status()


@router.post(
    "/vm/{vm_id}/start",
    response_model=VMActionResponse,
    summary="Start a virtual machine",
    description="Starts the specified VM in headless mode via VBoxManage.",
)
def start_vm(vm_id: str) -> VMActionResponse:
    service = get_environment_service()
    # Validate VM exists
    vms = service.vbox_manager.list_vms()
    matching = [v for v in vms if v["uuid"] == vm_id or v["name"] == vm_id]
    if not matching:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"VM '{vm_id}' not found among registered VirtualBox VMs",
        )
    return service.start_vm(vm_id)


@router.post(
    "/vm/{vm_id}/stop",
    response_model=VMActionResponse,
    summary="Stop a virtual machine",
    description="Sends ACPI shutdown or forced poweroff to the specified VM via VBoxManage.",
)
def stop_vm(
    vm_id: str,
    force: bool = Query(default=False, description="If true, perform forced poweroff instead of graceful ACPI"),
) -> VMActionResponse:
    service = get_environment_service()
    vms = service.vbox_manager.list_vms()
    matching = [v for v in vms if v["uuid"] == vm_id or v["name"] == vm_id]
    if not matching:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"VM '{vm_id}' not found among registered VirtualBox VMs",
        )
    return service.stop_vm(vm_id, force=force)


@router.post(
    "/verify",
    response_model=EnvironmentVerificationResponse,
    summary="Verify test environment",
    description="Performs live factual verification of VirtualBox, VM roles, host-only networking, reachability, and StrongSwan status.",
)
def verify_environment() -> EnvironmentVerificationResponse:
    service = get_environment_service()
    return service.verify_environment()


@router.get(
    "/evidence",
    response_model=EnvironmentEvidenceResponse,
    summary="Collect environment evidence",
    description="Returns a factual evidence snapshot of hypervisor version, network adapters, ARP table, and VM state.",
)
def get_environment_evidence() -> EnvironmentEvidenceResponse:
    service = get_environment_service()
    return service.get_evidence()


@router.get(
    "/testbed-profiles",
    summary="List supported SIH 26160 testbed configuration profiles",
    description="Returns canonical IPsec configurations including Tunnel/Transport, AES-128/256, GCM/CBC, DH groups, PFS, and traffic profiles.",
)
def list_testbed_profiles() -> list[dict]:
    service = get_environment_service()
    return service.get_testbed_profiles()


@router.post(
    "/simulate-profile/{profile_id}",
    summary="Simulate a target testbed configuration profile",
    description="Generates, decodes, and discovers sessions for a target SIH testbed profile for rapid demonstration.",
)
def simulate_testbed_profile(profile_id: str) -> dict:
    service = get_environment_service()
    try:
        return service.simulate_testbed_profile(profile_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

