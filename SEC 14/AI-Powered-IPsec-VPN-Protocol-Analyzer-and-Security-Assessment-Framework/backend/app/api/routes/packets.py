"""Packet-analysis endpoints (Layer 03)."""

from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, File, Query, Request, UploadFile
from fastapi.responses import JSONResponse

from app.schemas.packets import (
    AnalysisStatusSchema,
    IKEProposalSchema,
    IPsecStreamSummarySchema,
    PacketAnalysisResultSchema,
    PacketErrorSchema,
    PacketPageSchema,
    ProtocolAnalysisReportSchema,
    ProtocolAnomalySchema,
    TunnelEndpointSummarySchema,
)
from app.services.packet_service import MAX_UPLOAD_BYTES, PacketServiceError, packet_service

router = APIRouter(prefix="/packets", tags=["packets"])

ERROR_RESPONSES = {
    404: {"model": PacketErrorSchema},
    409: {"model": PacketErrorSchema},
    413: {"model": PacketErrorSchema},
    415: {"model": PacketErrorSchema},
    422: {"model": PacketErrorSchema},
}


def register_packet_error_handler(app) -> None:  # type: ignore[no-untyped-def]
    @app.exception_handler(PacketServiceError)
    async def _handler(_request: Request, exc: PacketServiceError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"error": exc.code, "message": exc.message})


@router.get("/status", response_model=AnalysisStatusSchema, summary="Analyzer state and statistics")
def read_status() -> AnalysisStatusSchema:
    return packet_service.status()


@router.get("/protocol-analysis", response_model=ProtocolAnalysisReportSchema, summary="Full Layer 3 IPsec protocol analysis report")
def get_protocol_analysis() -> ProtocolAnalysisReportSchema:
    return packet_service.protocol_analysis()


@router.get("/anomalies", response_model=list[ProtocolAnomalySchema], summary="Protocol anomalies detected in capture")
def get_anomalies() -> list[ProtocolAnomalySchema]:
    return packet_service.get_anomalies()


@router.get("/streams", response_model=list[IPsecStreamSummarySchema], summary="ESP/AH streams and sequence tracking")
def get_streams() -> list[IPsecStreamSummarySchema]:
    return packet_service.get_streams()


@router.get("/tunnel-endpoints", response_model=list[TunnelEndpointSummarySchema], summary="Discovered IPsec tunnel endpoints")
def get_tunnel_endpoints() -> list[TunnelEndpointSummarySchema]:
    return packet_service.get_tunnel_endpoints()


@router.get("/ike-proposals", response_model=list[IKEProposalSchema], summary="Extracted IKE security association proposals")
def get_ike_proposals() -> list[IKEProposalSchema]:
    return packet_service.get_ike_proposals()


@router.get("", response_model=PacketPageSchema, summary="List analysed packets")
def list_packets(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    protocol: Optional[str] = Query(None, pattern="^(?i)(IKE|ESP|AH|TCP|UDP|ICMP|IP|OTHER)$"),
    source: Optional[str] = Query(None, max_length=64),
    destination: Optional[str] = Query(None, max_length=64),
    port: Optional[int] = Query(None, ge=0, le=65535),
    ipsec: Optional[str] = Query(None, pattern="^(?i)(ALL|IKE|ESP|AH|NON-IPSEC)$"),
    search: Optional[str] = Query(None, max_length=128),
    sort: Literal["number", "timestamp", "length", "source", "destination", "protocol"] = "number",
    order: Literal["asc", "desc"] = "asc",
) -> PacketPageSchema:
    return packet_service.query(
        page=page, page_size=page_size, protocol=protocol, source=source, destination=destination,
        port=port, ipsec=None if (ipsec or "").upper() == "ALL" else ipsec, search=search, sort=sort, order=order,
    )


@router.get("/{packet_id}", response_model=PacketAnalysisResultSchema, responses=ERROR_RESPONSES, summary="Packet detail")
def read_packet(packet_id: str) -> PacketAnalysisResultSchema:
    return PacketAnalysisResultSchema.model_validate(packet_service.get(packet_id))


@router.post("/upload", response_model=AnalysisStatusSchema, responses=ERROR_RESPONSES, status_code=201, summary="Upload a capture file")
async def upload_capture(file: UploadFile = File(...)) -> AnalysisStatusSchema:
    # Read in bounded chunks so an oversize upload is rejected without buffering it all.
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_UPLOAD_BYTES:
            raise PacketServiceError("UPLOAD_TOO_LARGE", f"Capture exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit.", 413)
        chunks.append(chunk)
    packet_service.validate_upload(file.filename, total)
    return packet_service.load(b"".join(chunks), file.filename)


@router.post("/analyze", response_model=AnalysisStatusSchema, responses=ERROR_RESPONSES, summary="Re-run analysis on the loaded capture")
def analyze() -> AnalysisStatusSchema:
    return packet_service.reanalyze()


@router.delete("", response_model=AnalysisStatusSchema, summary="Clear the loaded capture")
def clear_packets() -> AnalysisStatusSchema:
    from app.services.sa_lifecycle_service import sa_lifecycle_service
    from app.services.session_service import session_service

    capture_id = packet_service.capture_id
    status = packet_service.clear()
    if capture_id:
        sa_lifecycle_service.clear(capture_id)
        session_service.clear(capture_id)
    return status
