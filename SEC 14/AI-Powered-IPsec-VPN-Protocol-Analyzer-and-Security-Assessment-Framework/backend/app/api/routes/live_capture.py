"""FastAPI route definitions for Layer 02 — Packet Capture & Data Collection."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from app.layers.layer02_packet_capture.service import get_live_capture_service
from app.schemas.live_capture import (
    LiveCaptureInterfacesResponse,
    LiveCaptureStatusResponse,
    StartCaptureRequest,
    StopCaptureResponse,
)

router = APIRouter(prefix="/live-capture", tags=["live-capture"])


@router.get(
    "/status",
    response_model=LiveCaptureStatusResponse,
    summary="Get live capture status",
    description="Returns the current state, elapsed duration, real packet count, and PCAP size.",
)
def get_status() -> LiveCaptureStatusResponse:
    service = get_live_capture_service()
    return service.get_status()


@router.get(
    "/interfaces",
    response_model=LiveCaptureInterfacesResponse,
    summary="List available capture sources",
    description="Returns available VirtualBox VMs and NIC interfaces discovered from the hypervisor.",
)
def get_interfaces() -> LiveCaptureInterfacesResponse:
    service = get_live_capture_service()
    return service.get_interfaces()


@router.post(
    "/start",
    response_model=LiveCaptureStatusResponse,
    summary="Start live packet capture",
    description="Engages hypervisor NIC tracing on the specified running VM and NIC.",
)
def start_capture(req: StartCaptureRequest) -> LiveCaptureStatusResponse:
    service = get_live_capture_service()
    try:
        return service.start_capture(req.vm, nic_number=req.nic)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )
    except RuntimeError as run_err:
        err_str = str(run_err)
        if "VM_NOT_RUNNING" in err_str:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=err_str,
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=err_str,
        )


@router.post(
    "/stop",
    response_model=StopCaptureResponse,
    summary="Stop live packet capture",
    description="Finalizes the PCAP and automatically ingests it into Layer 03 and downstream engines.",
)
def stop_capture() -> StopCaptureResponse:
    service = get_live_capture_service()
    try:
        return service.stop_capture()
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )
