"""FastAPI route definitions for Layer 02 — Packet Capture & Data Collection."""

from __future__ import annotations

from fastapi import APIRouter, File, HTTPException, UploadFile, status

from app.layers.layer02_packet_capture.scapy_reader import parse_pcap_with_scapy
from app.layers.layer02_packet_capture.service import get_live_capture_service
from app.schemas.live_capture import (
    CaptureConversationSummary,
    LiveCaptureInterfacesResponse,
    LiveCaptureStatusResponse,
    ScapyPacketSummary,
    ScapyPcapAnalysisResponse,
    StartCaptureRequest,
    StopCaptureResponse,
)

router = APIRouter(prefix="/live-capture", tags=["live-capture"])

MAX_PCAP_UPLOAD_BYTES = 100 * 1024 * 1024  # 100 MB


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


@router.post(
    "/upload",
    response_model=ScapyPcapAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Upload and analyze PCAP via Scapy (Layer 02)",
    description=(
        "Reads an uploaded PCAP/PCAPNG file using Scapy, extracting packet counts, "
        "protocol detection (IKE, ESP, AH, TCP, UDP, ICMP), source/destination IPs, and conversations."
    ),
)
async def upload_pcap(file: UploadFile = File(...)) -> ScapyPcapAnalysisResponse:
    """Read an uploaded PCAP with Scapy and extract Layer 02 telemetry."""
    filename = file.filename or "uploaded.pcap"
    ext = filename.lower().split(".")[-1]
    if ext not in {"pcap", "pcapng", "cap"}:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"Unsupported file extension '.{ext}'. Must be .pcap, .pcapng, or .cap.",
        )

    # Read uploaded file chunks safely with memory limits
    chunks: list[bytes] = []
    total_bytes = 0
    chunk_size = 1024 * 1024

    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        total_bytes += len(chunk)
        if total_bytes > MAX_PCAP_UPLOAD_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Capture file exceeds maximum allowed limit of {MAX_PCAP_UPLOAD_BYTES // (1024 * 1024)} MB.",
            )
        chunks.append(chunk)

    if total_bytes < 24:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="PCAP file is too small or truncated to contain a valid header.",
        )

    pcap_data = b"".join(chunks)

    try:
        summary = parse_pcap_with_scapy(pcap_data, filename=filename, max_packets=10000)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Corrupt or invalid PCAP format: {val_err}",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scapy failed to parse PCAP: {exc}",
        )

    # Return structured Pydantic response
    return ScapyPcapAnalysisResponse(
        status="success",
        filename=summary.filename,
        file_size_bytes=summary.file_size_bytes,
        total_packets=summary.total_packets,
        ike_packets=summary.ike_packets,
        esp_packets=summary.esp_packets,
        ah_packets=summary.ah_packets,
        other_packets=summary.other_packets,
        protocol_counts=summary.protocol_counts,
        source_ips=summary.source_ips,
        destination_ips=summary.destination_ips,
        all_ips=summary.all_ips,
        conversations=[
            CaptureConversationSummary(
                source_ip=c.source_ip,
                destination_ip=c.destination_ip,
                packet_count=c.packet_count,
                total_bytes=c.total_bytes,
                protocols=c.protocols,
            )
            for c in summary.conversations
        ],
        packets=[
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
            for p in summary.packets[:500]  # Cap packet list to 500 records for fast response payload
        ],
        analysis_duration_seconds=summary.analysis_duration_seconds,
        error=None,
    )


# Alias router for /api/capture/upload
capture_router = APIRouter(prefix="/capture", tags=["capture"])
capture_router.add_api_route(
    "/upload",
    upload_pcap,
    methods=["POST"],
    response_model=ScapyPcapAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Upload and analyze PCAP via Scapy (Layer 02 alias)",
    description="Alias endpoint for POST /api/live-capture/upload.",
)


