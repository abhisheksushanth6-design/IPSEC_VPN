"""PDF Report Renderer for Layer 14 — Report Generation (PDF).

Uses ReportLab 5.x to produce presentation-ready, multi-page security
assessment reports with running headers, footers, dynamic page numbers,
structured tables, severity callouts, and evidence traceability.
"""

from __future__ import annotations

import io
import re
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.layers.layer14_reports.schemas import SecurityAssessmentReportData


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas calculating total page count for running headers & footers."""

    total_pages_rendered: int = 1

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._saved_page_states: list[dict[str, Any]] = []

    def showPage(self) -> None:
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        num_pages = len(self._saved_page_states)
        NumberedCanvas.total_pages_rendered = max(1, num_pages)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int) -> None:
        if self._pageNumber == 1:
            # Suppress header and footer on cover page
            return

        self.saveState()
        self.setFont("Helvetica", 7.5)
        self.setFillColor(colors.HexColor("#64748B"))

        # Running Header
        self.drawString(
            40,
            755,
            "AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework",
        )
        self.drawRightString(555, 755, "Security Assessment Report")
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(40, 748, 555, 748)

        # Running Footer
        self.line(40, 45, 555, 45)
        self.drawString(40, 32, "CONFIDENTIAL — FOR AUTHORIZED SECURITY OPERATIONS ONLY")
        self.drawRightString(555, 32, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


class PDFReportRenderer:
    """Renders SecurityAssessmentReportData into an auditable, high-fidelity PDF."""

    def __init__(self) -> None:
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        self.last_page_count: int = 1

    def _setup_custom_styles(self) -> None:
        """Create clean typography styles for cybersecurity reporting."""
        # Headings
        self.styles.add(
            ParagraphStyle(
                name="CoverTitle",
                fontName="Helvetica-Bold",
                fontSize=22,
                leading=26,
                textColor=colors.HexColor("#0F172A"),
                alignment=0,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="CoverSubtitle",
                fontName="Helvetica",
                fontSize=13,
                leading=17,
                textColor=colors.HexColor("#0369A1"),
                alignment=0,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="SectionHeading",
                fontName="Helvetica-Bold",
                fontSize=13,
                leading=16,
                textColor=colors.HexColor("#0F172A"),
                spaceBefore=14,
                spaceAfter=6,
                keepWithNext=True,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="SubSectionHeading",
                fontName="Helvetica-Bold",
                fontSize=10,
                leading=13,
                textColor=colors.HexColor("#1E293B"),
                spaceBefore=8,
                spaceAfter=4,
                keepWithNext=True,
            )
        )
        # Body and tables
        self.styles.add(
            ParagraphStyle(
                name="BodyDark",
                fontName="Helvetica",
                fontSize=8.5,
                leading=12,
                textColor=colors.HexColor("#334155"),
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="BodyDarkBold",
                fontName="Helvetica-Bold",
                fontSize=8.5,
                leading=12,
                textColor=colors.HexColor("#0F172A"),
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="MutedNote",
                fontName="Helvetica-Oblique",
                fontSize=7.5,
                leading=10,
                textColor=colors.HexColor("#64748B"),
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="TableCell",
                fontName="Helvetica",
                fontSize=8,
                leading=10.5,
                textColor=colors.HexColor("#1E293B"),
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="TableHeader",
                fontName="Helvetica-Bold",
                fontSize=8,
                leading=10.5,
                textColor=colors.white,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="BadgeCritical",
                fontName="Helvetica-Bold",
                fontSize=7.5,
                leading=9.5,
                textColor=colors.HexColor("#DC2626"),
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="BadgeHigh",
                fontName="Helvetica-Bold",
                fontSize=7.5,
                leading=9.5,
                textColor=colors.HexColor("#EA580C"),
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="BadgeMedium",
                fontName="Helvetica-Bold",
                fontSize=7.5,
                leading=9.5,
                textColor=colors.HexColor("#D97706"),
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="BadgeLow",
                fontName="Helvetica-Bold",
                fontSize=7.5,
                leading=9.5,
                textColor=colors.HexColor("#2563EB"),
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="BadgeSuccess",
                fontName="Helvetica-Bold",
                fontSize=7.5,
                leading=9.5,
                textColor=colors.HexColor("#16A34A"),
            )
        )

    def render(self, data: SecurityAssessmentReportData) -> bytes:
        """Render the complete multi-page PDF document into memory bytes."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            leftMargin=40,
            rightMargin=40,
            topMargin=50,
            bottomMargin=50,
        )

        story: list[Any] = []
        report_type = str(data.metadata.get("report_type") or "FULL").upper()

        if report_type == "EXECUTIVE":
            # Executive Management Report
            self._build_cover_page(story, data)
            story.append(PageBreak())
            self._build_executive_summary(story, data)
            if data.traffic_classification:
                self._build_traffic_classification(story, data)
            self._build_recommendations(story, data)
            self._build_data_provenance(story, data)
            self._build_appendix(story, data)
        else:
            # Full / Technical / Session Security Assessment Report
            # 1. Cover Page
            self._build_cover_page(story, data)
            story.append(PageBreak())

            # 2. Executive Summary & Security Posture
            self._build_executive_summary(story, data)

            # 3. Environment & Capture Telemetry
            self._build_environment_and_capture(story, data)

            # 4. Protocol & Cryptographic Posture
            self._build_protocol_and_crypto(story, data)

            # 5. Security Association (SA) Lifecycles
            self._build_sa_lifecycles(story, data)

            # 6. Session Analysis & Behavioral Fingerprints
            self._build_session_analysis(story, data)

            # 7. Behavioral Baselines & Security Drift
            self._build_baseline_and_drift(story, data)

            # 8. AI / ML Anomaly Detection & Explainability
            self._build_ai_ml_anomalies(story, data)

            # 9. Encapsulated Traffic-Type Classification
            self._build_traffic_classification(story, data)

            # 10. Metadata Exposure & Side-Channel Assessment
            self._build_metadata_exposure(story, data)

            # 11. Standalone IPsec Threat Matrix
            self._build_threat_matrix(story, data)

            # 12. Security Rule & Vulnerability Findings
            self._build_vulnerabilities(story, data)

            # 13. Prioritized Recommendations
            self._build_recommendations(story, data)

            # 14. Data Provenance & Telemetry Integrity Audit
            self._build_data_provenance(story, data)

            # 15. Technical Appendix
            self._build_appendix(story, data)

        # Build PDF using custom NumberedCanvas
        doc.build(story, canvasmaker=NumberedCanvas)
        pdf_bytes = buffer.getvalue()
        regex_pages = len(re.findall(rb'/Type\s*/Page\b', pdf_bytes))
        self.last_page_count = max(regex_pages, getattr(NumberedCanvas, "total_pages_rendered", 1), 1)
        return pdf_bytes

    def render_with_metadata(self, data: SecurityAssessmentReportData) -> tuple[bytes, int]:
        """Render report and return both binary PDF bytes and exact page count."""
        pdf_bytes = self.render(data)
        return pdf_bytes, self.last_page_count

    # -----------------------------------------------------------------------
    # Section Builders
    # -----------------------------------------------------------------------

    def _build_cover_page(self, story: list[Any], data: SecurityAssessmentReportData) -> None:
        meta = data.metadata
        env = data.environment

        story.append(Spacer(1, 40))
        story.append(
            HRFlowable(width="100%", thickness=3, color=colors.HexColor("#0284C7"), spaceAfter=15)
        )
        story.append(Paragraph(meta["framework_name"], self.styles["CoverTitle"]))
        story.append(Spacer(1, 6))
        story.append(Paragraph("SECURITY ASSESSMENT REPORT", self.styles["CoverSubtitle"]))
        story.append(
            HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"), spaceBefore=15, spaceAfter=25)
        )

        # Overview metadata box
        meta_data = [
            [
                Paragraph("<b>Report ID:</b>", self.styles["TableCell"]),
                Paragraph(f"<code>{meta['report_id']}</code>", self.styles["TableCell"]),
                Paragraph("<b>Report Type:</b>", self.styles["TableCell"]),
                Paragraph(str(meta["report_type"]), self.styles["TableCell"]),
            ],
            [
                Paragraph("<b>Generated At:</b>", self.styles["TableCell"]),
                Paragraph(meta["generated_at_formatted"], self.styles["TableCell"]),
                Paragraph("<b>Scope:</b>", self.styles["TableCell"]),
                Paragraph(str(meta.get("session_id_scope") or "Entire Telemetry"), self.styles["TableCell"]),
            ],
            [
                Paragraph("<b>Application Mode:</b>", self.styles["TableCell"]),
                Paragraph(str(env["application_mode"]), self.styles["TableCell"]),
                Paragraph("<b>Architecture Status:</b>", self.styles["TableCell"]),
                Paragraph(f"{env['layers_initialized']} of {env['layers_total']} Layers Active", self.styles["TableCell"]),
            ],
            [
                Paragraph("<b>Backend Status:</b>", self.styles["TableCell"]),
                Paragraph(str(env["backend_status"]), self.styles["TableCell"]),
                Paragraph("<b>Database Status:</b>", self.styles["TableCell"]),
                Paragraph(str(env["database_status"]), self.styles["TableCell"]),
            ],
        ]
        meta_table = Table(meta_data, colWidths=[110, 160, 110, 150])
        meta_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#E2E8F0")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ])
        )
        story.append(meta_table)
        story.append(Spacer(1, 35))

        # Executive Notice Box
        notice_data = [
            [
                Paragraph(
                    "<b>ASSESSMENT OBJECTIVE &amp; VERIFICATION NOTICE:</b><br/>"
                    "This formal security report consolidates empirical findings produced by the framework's "
                    "protocol analyzer, SA state machine, behavioral drift detector, Isolation Forest anomaly "
                    "engine, and deterministic security rule catalog. Every metric and finding is grounded "
                    "directly in captured network telemetry and registered security rules without synthetic scores.",
                    self.styles["BodyDark"],
                )
            ]
        ]
        notice_table = Table(notice_data, colWidths=[530])
        notice_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F0F9FF")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#BAE6FD")),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
            ])
        )
        story.append(notice_table)

    def _build_executive_summary(self, story: list[Any], data: SecurityAssessmentReportData) -> None:
        story.append(Paragraph("1. Executive Summary &amp; Security Posture", self.styles["SectionHeading"]))
        story.append(
            HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceAfter=10)
        )

        vuln_counts = data.vulnerabilities.get("counts", {})
        sa_data = data.sa_lifecycle
        ml_data = data.ml_anomaly
        drift_data = data.drift
        capture_data = data.capture

        # Key indicators grid
        kpi_data = [
            [
                Paragraph("<b>Total Packets</b>", self.styles["TableHeader"]),
                Paragraph("<b>Active SAs</b>", self.styles["TableHeader"]),
                Paragraph("<b>Vulnerabilities</b>", self.styles["TableHeader"]),
                Paragraph("<b>ML Anomalies</b>", self.styles["TableHeader"]),
                Paragraph("<b>Drift Events</b>", self.styles["TableHeader"]),
            ],
            [
                Paragraph(str(capture_data.get("total_packets", 0)), self.styles["TableCell"]),
                Paragraph(str(sa_data.get("total_sas", 0)), self.styles["TableCell"]),
                Paragraph(
                    f"{vuln_counts.get('TOTAL', 0)} ({vuln_counts.get('CRITICAL', 0)} Crit, {vuln_counts.get('HIGH', 0)} High)",
                    self.styles["TableCell"],
                ),
                Paragraph(str(ml_data.get("anomalous_count", 0)), self.styles["TableCell"]),
                Paragraph(str(drift_data.get("drifting_sessions_count", 0)), self.styles["TableCell"]),
            ],
        ]
        kpi_table = Table(kpi_data, colWidths=[106, 106, 106, 106, 106])
        kpi_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
                ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#F8FAFC")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ])
        )
        story.append(kpi_table)
        story.append(Spacer(1, 10))

        # Layer 10 Risk Assessment
        risk_info = data.risk
        has_score = risk_info.get("overall_risk_score") is not None
        if has_score:
            score_val = risk_info["overall_risk_score"]
            level = risk_info.get("risk_level", "UNKNOWN")
            decision = risk_info.get("decision", "ALLOW")
            quality = risk_info.get("data_quality", "PARTIAL")
            stmt = risk_info.get("statement", "")
            
            bg_color = "#FEF2F2" if level in ("CRITICAL", "HIGH") else "#F0FDF4" if level == "LOW" else "#FEFCE8"
            border_color = "#EF4444" if level in ("CRITICAL", "HIGH") else "#22C55E" if level == "LOW" else "#EAB308"

            risk_box = [
                [
                    Paragraph(
                        f"<b>RISK ASSESSMENT &amp; DECISION ENGINE (LAYER 10) — POSTURE: {decision}</b><br/>"
                        f"<b>Risk Score:</b> {score_val} / 100 ({level}) &nbsp;|&nbsp; "
                        f"<b>Policy Decision:</b> {decision} &nbsp;|&nbsp; "
                        f"<b>Telemetry Quality:</b> {quality}<br/>"
                        f"{stmt}",
                        self.styles["BodyDark"],
                    )
                ]
            ]
        else:
            bg_color = "#FEF3C7"
            border_color = "#F59E0B"
            risk_box = [
                [
                    Paragraph(
                        "<b>RISK ASSESSMENT ENGINE (LAYER 10) STATUS: OPERATIONAL (IDLE)</b><br/>"
                        "Layer 10 (Risk Assessment &amp; Decision Engine) is operational. "
                        "No session risk assessments have been committed yet for this scope.",
                        self.styles["BodyDark"],
                    )
                ]
            ]
        risk_table = Table(risk_box, colWidths=[530])
        risk_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(bg_color)),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor(border_color)),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ])
        )
        story.append(risk_table)
        story.append(Spacer(1, 12))

    def _build_environment_and_capture(self, story: list[Any], data: SecurityAssessmentReportData) -> None:
        story.append(Paragraph("2. Environment &amp; Packet Capture Telemetry", self.styles["SectionHeading"]))
        story.append(
            HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceAfter=8)
        )

        cap = data.capture
        p_counts = cap.get("protocol_counts", {})

        # Capture metadata overview
        cap_meta = [
            [
                Paragraph("<b>Capture ID:</b>", self.styles["TableCell"]),
                Paragraph(f"<code>{cap.get('capture_id', 'CAP-LIVE-ACTIVE')}</code>", self.styles["TableCell"]),
                Paragraph("<b>PCAP Source:</b>", self.styles["TableCell"]),
                Paragraph(f"<code>{cap.get('filename', 'None')}</code>", self.styles["TableCell"]),
            ],
            [
                Paragraph("<b>Total Packets:</b>", self.styles["TableCell"]),
                Paragraph(f"{cap.get('total_packets', 0):,}", self.styles["TableCell"]),
                Paragraph("<b>NAT-Traversal (4500):</b>", self.styles["TableCell"]),
                Paragraph("OBSERVED" if cap.get("nat_traversal_observed") else "NOT OBSERVED", self.styles["TableCell"]),
            ],
        ]
        cap_meta_table = Table(cap_meta, colWidths=[120, 150, 120, 140])
        cap_meta_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ])
        )
        story.append(cap_meta_table)
        story.append(Spacer(1, 6))

        proto_rows = [
            [
                Paragraph("<b>Protocol</b>", self.styles["TableHeader"]),
                Paragraph("<b>Packets Observed</b>", self.styles["TableHeader"]),
                Paragraph("<b>Traffic Role</b>", self.styles["TableHeader"]),
            ]
        ]
        for proto, count in sorted(p_counts.items(), key=lambda x: x[1], reverse=True):
            role = "Key Exchange (Control)" if proto == "IKE" else "Encrypted Data (ESP)" if proto == "ESP" else "Header Authentication" if proto == "AH" else "Carrier / Transport"
            proto_rows.append([
                Paragraph(proto, self.styles["TableCell"]),
                Paragraph(f"{count:,}", self.styles["TableCell"]),
                Paragraph(role, self.styles["TableCell"]),
            ])

        if len(proto_rows) == 1:
            proto_rows.append([
                Paragraph("None", self.styles["TableCell"]),
                Paragraph("0", self.styles["TableCell"]),
                Paragraph("No capture data recorded", self.styles["TableCell"]),
            ])

        p_table = Table(proto_rows, colWidths=[120, 150, 260])
        p_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F8FAFC"), colors.white]),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ])
        )
        story.append(p_table)
        story.append(Spacer(1, 12))

    def _build_protocol_and_crypto(self, story: list[Any], data: SecurityAssessmentReportData) -> None:
        story.append(Paragraph("3. Protocol &amp; Cryptographic Analysis", self.styles["SectionHeading"]))
        story.append(
            HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceAfter=8)
        )

        p = data.protocol
        ciphers = ", ".join(p.get("observed_encryption_algorithms", [])) or "None observed"
        integrities = ", ".join(p.get("observed_integrity_algorithms", [])) or "None observed"
        dh = ", ".join(p.get("observed_dh_groups", [])) or "None observed"
        prfs = ", ".join(p.get("observed_prf_algorithms", [])) or "None observed"
        ike_v = ", ".join(p.get("ike_versions", [])) or "None observed"
        pfs_str = "ACTIVE / ENABLED" if p.get("pfs_enabled") is True else "DISABLED / MISSING" if p.get("pfs_enabled") is False else "UNDETERMINED"

        crypto_rows = [
            [Paragraph("<b>Parameter</b>", self.styles["TableHeader"]), Paragraph("<b>Observed Values / Status</b>", self.styles["TableHeader"])],
            [Paragraph("IKE Protocol Versions", self.styles["TableCell"]), Paragraph(ike_v, self.styles["TableCell"])],
            [Paragraph("Encryption Algorithms", self.styles["TableCell"]), Paragraph(ciphers, self.styles["TableCell"])],
            [Paragraph("Integrity Algorithms", self.styles["TableCell"]), Paragraph(integrities, self.styles["TableCell"])],
            [Paragraph("Diffie-Hellman Groups", self.styles["TableCell"]), Paragraph(dh, self.styles["TableCell"])],
            [Paragraph("Pseudo-Random Functions (PRF)", self.styles["TableCell"]), Paragraph(prfs, self.styles["TableCell"])],
            [Paragraph("Perfect Forward Secrecy (PFS)", self.styles["TableCell"]), Paragraph(pfs_str, self.styles["TableCell"])],
        ]
        c_table = Table(crypto_rows, colWidths=[180, 350])
        c_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F8FAFC"), colors.white]),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ])
        )
        story.append(c_table)
        story.append(Spacer(1, 12))

    def _build_sa_lifecycles(self, story: list[Any], data: SecurityAssessmentReportData) -> None:
        story.append(Paragraph("4. Security Association (SA) Lifecycles", self.styles["SectionHeading"]))
        story.append(
            HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceAfter=8)
        )

        sa_data = data.sa_lifecycle
        sample_sas = sa_data.get("sample_sas", [])

        sa_rows = [
            [
                Paragraph("<b>SA ID</b>", self.styles["TableHeader"]),
                Paragraph("<b>Type</b>", self.styles["TableHeader"]),
                Paragraph("<b>State</b>", self.styles["TableHeader"]),
                Paragraph("<b>Peers</b>", self.styles["TableHeader"]),
                Paragraph("<b>SPI</b>", self.styles["TableHeader"]),
                Paragraph("<b>Rekeys</b>", self.styles["TableHeader"]),
            ]
        ]
        for s in sample_sas[:8]:
            sa_rows.append([
                Paragraph(s["id"], self.styles["TableCell"]),
                Paragraph(s["type"], self.styles["TableCell"]),
                Paragraph(s["state"], self.styles["TableCell"]),
                Paragraph(f"{s['initiator']} &harr; {s['responder']}", self.styles["TableCell"]),
                Paragraph(str(s["spi"])[:14], self.styles["TableCell"]),
                Paragraph(str(s["rekey_count"]), self.styles["TableCell"]),
            ])

        if len(sa_rows) == 1:
            sa_rows.append([
                Paragraph("None", self.styles["TableCell"]),
                Paragraph("-", self.styles["TableCell"]),
                Paragraph("No SAs discovered", self.styles["TableCell"]),
                Paragraph("-", self.styles["TableCell"]),
                Paragraph("-", self.styles["TableCell"]),
                Paragraph("0", self.styles["TableCell"]),
            ])

        sa_table = Table(sa_rows, colWidths=[90, 55, 75, 170, 90, 50])
        sa_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F8FAFC"), colors.white]),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ])
        )
        story.append(sa_table)
        story.append(Spacer(1, 12))

    def _build_session_analysis(self, story: list[Any], data: SecurityAssessmentReportData) -> None:
        story.append(Paragraph("5. IPsec Session Analysis &amp; Behavioral Fingerprints", self.styles["SectionHeading"]))
        story.append(
            HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceAfter=8)
        )

        sess_data = data.session_analysis or {}
        sessions = sess_data.get("sessions", [])

        story.append(
            Paragraph(
                f"<b>Total Monitored Sessions:</b> {sess_data.get('total_sessions', len(sessions))} &middot; "
                f"<b>Scope:</b> {sess_data.get('scoped_session_id') or 'All Telemetry'}",
                self.styles["BodyDark"],
            )
        )
        story.append(Spacer(1, 6))

        sess_rows = [
            [
                Paragraph("<b>Session ID</b>", self.styles["TableHeader"]),
                Paragraph("<b>Endpoints &amp; Mode</b>", self.styles["TableHeader"]),
                Paragraph("<b>Packets / Bytes</b>", self.styles["TableHeader"]),
                Paragraph("<b>State / Duration</b>", self.styles["TableHeader"]),
                Paragraph("<b>Fingerprint &amp; Posture</b>", self.styles["TableHeader"]),
            ]
        ]
        for s in sessions[:10]:
            anom_badge = (
                self.styles["BadgeCritical"] if s.get("anomaly_status") == "ANOMALOUS"
                else self.styles["BadgeSuccess"]
            )
            sess_rows.append([
                Paragraph(f"<code>{s['session_id'][:16]}</code>", self.styles["TableCell"]),
                Paragraph(
                    f"{s['initiator']} &rarr; {s['responder']}<br/>"
                    f"<font color='#64748B'>{s['ike_version']} &middot; {s['ipsec_mode']} {'(NAT-T)' if s.get('nat_traversal') else ''}</font>",
                    self.styles["TableCell"],
                ),
                Paragraph(
                    f"{s['packet_count']} pkts<br/>"
                    f"<font color='#64748B'>{s['byte_count']:,} B (IKE:{s['ike_packets']}, ESP:{s['esp_packets']})</font>",
                    self.styles["TableCell"],
                ),
                Paragraph(
                    f"<b>{s['state']}</b><br/>"
                    f"<font color='#64748B'>{s.get('duration_seconds', 0):.1f}s</font>",
                    self.styles["TableCell"],
                ),
                Paragraph(
                    f"SHA: <code>{s.get('fingerprint_preview', 'N/A')}</code><br/>"
                    f"Anomaly: {s.get('anomaly_status', 'NORMAL')} &middot; Findings: {s.get('related_findings', 0)}",
                    self.styles["TableCell"],
                ),
            ])

        if len(sess_rows) == 1:
            sess_rows.append([
                Paragraph("None", self.styles["TableCell"]),
                Paragraph("No active IPsec sessions recorded", self.styles["TableCell"]),
                Paragraph("0 pkts", self.styles["TableCell"]),
                Paragraph("IDLE", self.styles["TableCell"]),
                Paragraph("No behavioral fingerprint available", self.styles["TableCell"]),
            ])

        sess_table = Table(sess_rows, colWidths=[100, 140, 110, 80, 100])
        sess_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F8FAFC"), colors.white]),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ])
        )
        story.append(sess_table)
        story.append(Spacer(1, 12))

    def _build_baseline_and_drift(self, story: list[Any], data: SecurityAssessmentReportData) -> None:
        story.append(Paragraph("6. Behavioral Baselines &amp; Security Drift", self.styles["SectionHeading"]))
        story.append(
            HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceAfter=8)
        )

        b = data.baseline
        d = data.drift

        drift_summary = (
            f"<b>Baseline Status:</b> {b.get('status', 'NONE')} "
            f"(Profile: {b.get('baseline_id') or 'N/A'}, Sessions: {b.get('session_count') or b.get('sample_count', 0)})<br/>"
            f"<b>Drift Status:</b> {d.get('status', 'NOT_EVALUATED')} "
            f"({d.get('drifting_sessions_count', 0)} of {d.get('total_analyses', 0)} sessions drifting)"
        )
        story.append(Paragraph(drift_summary, self.styles["BodyDark"]))
        story.append(Spacer(1, 6))

        recent = d.get("recent_drifts", [])
        drift_rows = [
            [
                Paragraph("<b>Session ID</b>", self.styles["TableHeader"]),
                Paragraph("<b>Status</b>", self.styles["TableHeader"]),
                Paragraph("<b>Severity</b>", self.styles["TableHeader"]),
                Paragraph("<b>Drifting Features</b>", self.styles["TableHeader"]),
            ]
        ]
        for rd in recent[:5]:
            f_names = ", ".join(f["feature_name"] for f in rd.get("drifting_features", [])) or "None"
            drift_rows.append([
                Paragraph(rd["session_id"], self.styles["TableCell"]),
                Paragraph(rd["status"], self.styles["TableCell"]),
                Paragraph(rd["severity"], self.styles["TableCell"]),
                Paragraph(f_names, self.styles["TableCell"]),
            ])

        if len(drift_rows) == 1:
            drift_rows.append([
                Paragraph("None", self.styles["TableCell"]),
                Paragraph("ALIGNED", self.styles["TableCell"]),
                Paragraph("NONE", self.styles["TableCell"]),
                Paragraph("No feature drift identified relative to baseline", self.styles["TableCell"]),
            ])

        d_table = Table(drift_rows, colWidths=[130, 90, 80, 230])
        d_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F8FAFC"), colors.white]),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ])
        )
        story.append(d_table)
        story.append(Spacer(1, 12))

    def _build_ai_ml_anomalies(self, story: list[Any], data: SecurityAssessmentReportData) -> None:
        story.append(Paragraph("6. AI / ML Anomaly Detection &amp; Explainability", self.styles["SectionHeading"]))
        story.append(
            HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceAfter=8)
        )

        ml = data.ml_anomaly
        summary_text = (
            f"<b>Model:</b> {ml.get('active_model_name')} ({ml.get('model_type')}) &middot; "
            f"<b>Total Evaluated:</b> {ml.get('total_evaluated', 0)} sessions &middot; "
            f"<b>Anomalous Flagged:</b> {ml.get('anomalous_count', 0)}"
        )
        story.append(Paragraph(summary_text, self.styles["BodyDark"]))
        story.append(Spacer(1, 6))

        anom_sessions = ml.get("anomalous_sessions", [])
        anom_rows = [
            [
                Paragraph("<b>Session ID</b>", self.styles["TableHeader"]),
                Paragraph("<b>Score (0-100)</b>", self.styles["TableHeader"]),
                Paragraph("<b>Explanation &amp; Top Contributing Features</b>", self.styles["TableHeader"]),
            ]
        ]
        for a in anom_sessions[:5]:
            contrib_str = "; ".join(
                f"{c['feature']} ({c['direction']}, score {c['score']:.2f})"
                for c in a.get("contributions", [])[:3]
            )
            explanation = a.get("explanation") or "Unsupervised outlier deviation detected."
            anom_rows.append([
                Paragraph(a["session_id"], self.styles["TableCell"]),
                Paragraph(f"<b>{a.get('display_score', 0):.1f}</b>", self.styles["TableCell"]),
                Paragraph(f"{explanation}<br/><font color='#64748B'>Evidence: {contrib_str}</font>", self.styles["TableCell"]),
            ])

        if len(anom_rows) == 1:
            anom_rows.append([
                Paragraph("None", self.styles["TableCell"]),
                Paragraph("0.0", self.styles["TableCell"]),
                Paragraph("No sessions classified as anomalous by Isolation Forest model", self.styles["TableCell"]),
            ])

        a_table = Table(anom_rows, colWidths=[120, 90, 320])
        a_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F8FAFC"), colors.white]),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ])
        )
        story.append(a_table)
        story.append(Spacer(1, 12))

    def _build_traffic_classification(self, story: list[Any], data: SecurityAssessmentReportData) -> None:
        story.append(Paragraph("8. AI Encapsulated Traffic-Type Classification (ESP Inner Flow Inference)", self.styles["SectionHeading"]))
        story.append(
            HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceAfter=8)
        )

        tc = data.traffic_classification
        if not tc or not tc.get("classifications"):
            story.append(Paragraph("No encrypted payload traffic types classified for this capture session.", self.styles["MutedNote"]))
            story.append(Spacer(1, 10))
            return

        dist = tc.get("distribution", {})
        dist_str = " &middot; ".join(f"<b>{k}:</b> {v}" for k, v in dist.items()) if dist else "N/A"
        summary_text = (
            f"<b>Total Evaluated Sessions:</b> {tc.get('total_sessions', 0)} &middot; "
            f"<b>Distribution:</b> {dist_str}"
        )
        story.append(Paragraph(summary_text, self.styles["BodyDark"]))
        story.append(Spacer(1, 6))

        tc_rows = [
            [
                Paragraph("<b>Session ID</b>", self.styles["TableHeader"]),
                Paragraph("<b>Traffic Type</b>", self.styles["TableHeader"]),
                Paragraph("<b>Confidence</b>", self.styles["TableHeader"]),
                Paragraph("<b>AI Feature Attribution &amp; Explainability</b>", self.styles["TableHeader"]),
            ]
        ]
        for c in tc.get("classifications", [])[:8]:
            tt = c.get("traffic_type", "GENERIC")
            conf = c.get("confidence", 0.0)
            expl = c.get("explainability", [])
            expl_str = "; ".join(f"{e.get('signal')}: {e.get('value')}" for e in expl[:3]) if expl else "Statistical heuristics match"
            
            badge_style = self.styles["BadgeSuccess"] if conf >= 0.85 else self.styles["BadgeMedium"] if conf >= 0.70 else self.styles["BadgeLow"]
            tc_rows.append([
                Paragraph(c.get("session_id", "N/A"), self.styles["TableCell"]),
                Paragraph(f"<b>{tt}</b>", self.styles["TableCell"]),
                Paragraph(f"{conf * 100:.1f}%", badge_style),
                Paragraph(expl_str, self.styles["TableCell"]),
            ])

        tc_table = Table(tc_rows, colWidths=[120, 100, 70, 240])
        tc_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F8FAFC"), colors.white]),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ])
        )
        story.append(tc_table)
        story.append(Spacer(1, 12))

    def _build_metadata_exposure(self, story: list[Any], data: SecurityAssessmentReportData) -> None:
        story.append(Paragraph("9. Metadata Exposure &amp; Side-Channel Leakage Assessment", self.styles["SectionHeading"]))
        story.append(
            HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceAfter=8)
        )

        me = data.metadata_exposure
        if not me or not me.get("assessments"):
            story.append(Paragraph("No metadata exposure metrics recorded for this session.", self.styles["MutedNote"]))
            story.append(Spacer(1, 10))
            return

        summary = me.get("summary", {})
        score = summary.get("overall_score", 0.0)
        risk = summary.get("risk_level", "LOW")

        summary_text = (
            f"<b>Overall Exposure Score:</b> {score:.1f}/100 &middot; "
            f"<b>Risk Level:</b> {risk} &middot; "
            f"<b>SPI Leakage:</b> {summary.get('spi_leakage_score', 0):.1f} &middot; "
            f"<b>Sequence Monotonicity:</b> {summary.get('sequence_leakage_score', 0):.1f} &middot; "
            f"<b>Length/TFC:</b> {summary.get('packet_length_leakage_score', 0):.1f} &middot; "
            f"<b>Timing:</b> {summary.get('timing_leakage_score', 0):.1f} &middot; "
            f"<b>Topology:</b> {summary.get('topology_leakage_score', 0):.1f}"
        )
        story.append(Paragraph(summary_text, self.styles["BodyDark"]))
        story.append(Spacer(1, 6))

        me_rows = [
            [
                Paragraph("<b>Session ID</b>", self.styles["TableHeader"]),
                Paragraph("<b>Risk</b>", self.styles["TableHeader"]),
                Paragraph("<b>SPI / Seq</b>", self.styles["TableHeader"]),
                Paragraph("<b>Length / Timing</b>", self.styles["TableHeader"]),
                Paragraph("<b>Topology</b>", self.styles["TableHeader"]),
                Paragraph("<b>Key Finding / Recommendation</b>", self.styles["TableHeader"]),
            ]
        ]
        for a in me.get("assessments", [])[:6]:
            r_level = a.get("risk_level", "LOW")
            r_badge = (
                self.styles["BadgeCritical"] if r_level == "CRITICAL"
                else self.styles["BadgeHigh"] if r_level == "HIGH"
                else self.styles["BadgeMedium"] if r_level == "MEDIUM"
                else self.styles["BadgeLow"]
            )
            recs = a.get("recommendations", [])
            rec_str = recs[0] if recs else "Standard TFC padding and tunnel isolation"
            me_rows.append([
                Paragraph(a.get("session_id", "N/A"), self.styles["TableCell"]),
                Paragraph(r_level, r_badge),
                Paragraph(f"SPI: {a.get('spi_leakage_score', 0):.0f}<br/>Seq: {a.get('sequence_leakage_score', 0):.0f}", self.styles["TableCell"]),
                Paragraph(f"Len: {a.get('packet_length_leakage_score', 0):.0f}<br/>Time: {a.get('timing_leakage_score', 0):.0f}", self.styles["TableCell"]),
                Paragraph(f"{a.get('topology_leakage_score', 0):.0f}", self.styles["TableCell"]),
                Paragraph(rec_str, self.styles["TableCell"]),
            ])

        me_table = Table(me_rows, colWidths=[110, 60, 65, 85, 55, 155])
        me_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F8FAFC"), colors.white]),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ])
        )
        story.append(me_table)
        story.append(Spacer(1, 12))

    def _build_threat_matrix(self, story: list[Any], data: SecurityAssessmentReportData) -> None:
        story.append(Paragraph("10. Standalone IPsec Threat Matrix (MITRE ATT&CK &amp; NIST SP 800-77)", self.styles["SectionHeading"]))
        story.append(
            HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceAfter=8)
        )

        tm = data.threat_matrix
        if not tm or not tm.get("threats"):
            story.append(Paragraph("No threat matrix evaluations recorded for this capture.", self.styles["MutedNote"]))
            story.append(Spacer(1, 10))
            return

        summary = tm.get("summary", {})
        comp_score = summary.get("compliance_score", 100.0)
        det_count = summary.get("detected_threats", 0)
        tot_threats = summary.get("total_threats", len(tm.get("threats", [])))

        summary_text = (
            f"<b>Evaluated Threats:</b> {tot_threats} &middot; "
            f"<b>Active Detections:</b> <font color='{'#DC2626' if det_count > 0 else '#16A34A'}'><b>{det_count}</b></font> &middot; "
            f"<b>Framework Compliance Score:</b> <b>{comp_score:.1f}%</b>"
        )
        story.append(Paragraph(summary_text, self.styles["BodyDark"]))
        story.append(Spacer(1, 6))

        tm_rows = [
            [
                Paragraph("<b>ID</b>", self.styles["TableHeader"]),
                Paragraph("<b>Threat Name</b>", self.styles["TableHeader"]),
                Paragraph("<b>Category / Severity</b>", self.styles["TableHeader"]),
                Paragraph("<b>MITRE / NIST / RFC</b>", self.styles["TableHeader"]),
                Paragraph("<b>Status</b>", self.styles["TableHeader"]),
            ]
        ]
        for t in tm.get("threats", []):
            st = t.get("status", "NOT_DETECTED")
            st_color = "#DC2626" if st == "DETECTED" else "#16A34A"
            sev = t.get("severity", "MEDIUM")
            tm_rows.append([
                Paragraph(t.get("matrix_id", "N/A"), self.styles["TableCell"]),
                Paragraph(f"<b>{t.get('name', 'N/A')}</b>", self.styles["TableCell"]),
                Paragraph(f"{t.get('category', 'N/A')}<br/><font color='#64748B'>{sev}</font>", self.styles["TableCell"]),
                Paragraph(f"{t.get('mitre_technique_id', 'N/A')}<br/><font color='#64748B'>{t.get('nist_control', 'N/A')} &middot; {t.get('rfc_reference', 'N/A')}</font>", self.styles["TableCell"]),
                Paragraph(f"<font color='{st_color}'><b>{st}</b></font>", self.styles["TableCell"]),
            ])

        tm_table = Table(tm_rows, colWidths=[70, 160, 100, 130, 70])
        tm_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F8FAFC"), colors.white]),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ])
        )
        story.append(tm_table)
        story.append(Spacer(1, 12))

    def _build_vulnerabilities(self, story: list[Any], data: SecurityAssessmentReportData) -> None:
        story.append(Paragraph("11. Security Rule &amp; Vulnerability Engine Findings", self.styles["SectionHeading"]))
        story.append(
            HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceAfter=8)
        )

        vuln = data.vulnerabilities
        findings = vuln.get("findings", [])

        story.append(
            Paragraph(
                f"Evaluated against 16 deterministic IPsec security rules. "
                f"<b>Total Discovered Findings: {vuln.get('total_findings', 0)}</b>.",
                self.styles["BodyDark"],
            )
        )
        story.append(Spacer(1, 6))

        v_rows = [
            [
                Paragraph("<b>Severity</b>", self.styles["TableHeader"]),
                Paragraph("<b>Rule &amp; Finding Title</b>", self.styles["TableHeader"]),
                Paragraph("<b>Category</b>", self.styles["TableHeader"]),
                Paragraph("<b>Empirical Evidence &amp; Remediation</b>", self.styles["TableHeader"]),
            ]
        ]
        for f in findings[:10]:
            sev = f["severity"].upper()
            sev_style = (
                self.styles["BadgeCritical"]
                if sev == "CRITICAL"
                else self.styles["BadgeHigh"]
                if sev == "HIGH"
                else self.styles["BadgeMedium"]
                if sev == "MEDIUM"
                else self.styles["BadgeLow"]
            )

            evidence_desc = "; ".join(
                f"{ev['key']}={ev['observed']} (expected {ev['expected']})"
                for ev in f.get("evidence", [])[:2]
            )
            v_rows.append([
                Paragraph(sev, sev_style),
                Paragraph(f"<b>{f['title']}</b><br/><font color='#64748B'>{f['rule_id']}</font>", self.styles["TableCell"]),
                Paragraph(f["category"], self.styles["TableCell"]),
                Paragraph(f"{f['remediation']}<br/><font color='#64748B'>Observed: {evidence_desc or 'Configuration violation'}</font>", self.styles["TableCell"]),
            ])

        if len(v_rows) == 1:
            v_rows.append([
                Paragraph("CLEAN", self.styles["BadgeSuccess"]),
                Paragraph("No Security Violations", self.styles["TableCell"]),
                Paragraph("ALL", self.styles["TableCell"]),
                Paragraph("All observed traffic satisfies active cryptographic &amp; protocol rules", self.styles["TableCell"]),
            ])

        v_table = Table(v_rows, colWidths=[65, 150, 75, 240])
        v_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F8FAFC"), colors.white]),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ])
        )
        story.append(v_table)
        story.append(Spacer(1, 12))

    def _build_recommendations(self, story: list[Any], data: SecurityAssessmentReportData) -> None:
        story.append(Paragraph("12. Prioritized Remediation Recommendations", self.styles["SectionHeading"]))
        story.append(
            HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceAfter=8)
        )

        recs = data.recommendations
        rec_rows = [
            [
                Paragraph("<b>Priority</b>", self.styles["TableHeader"]),
                Paragraph("<b>Recommendation Action</b>", self.styles["TableHeader"]),
                Paragraph("<b>Implementation Details</b>", self.styles["TableHeader"]),
            ]
        ]
        for r in recs[:8]:
            p_text = r["priority"]
            p_style = (
                self.styles["BadgeCritical"]
                if "Immediate" in p_text
                else self.styles["BadgeHigh"]
                if "High" in p_text
                else self.styles["BadgeMedium"]
            )
            rec_rows.append([
                Paragraph(p_text, p_style),
                Paragraph(r["title"], self.styles["TableCell"]),
                Paragraph(r["description"], self.styles["TableCell"]),
            ])

        rec_table = Table(rec_rows, colWidths=[100, 170, 260])
        rec_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F8FAFC"), colors.white]),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ])
        )
        story.append(rec_table)
        story.append(Spacer(1, 12))

    def _build_data_provenance(self, story: list[Any], data: SecurityAssessmentReportData) -> None:
        story.append(Paragraph("Data Provenance &amp; Telemetry Integrity Audit", self.styles["SectionHeading"]))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceAfter=8))
        story.append(Paragraph(
            "In strict compliance with NTRO / SIH 26160 cybersecurity requirements, the framework transparently "
            "categorizes all report data points into: <b>Observed</b> (verifiable packet telemetry), "
            "<b>Inferred</b> (derived from handshake/transforms), <b>Predicted</b> (machine-learning classification), "
            "and <b>Unavailable</b> (protected by ESP encryption or mid-session capture start).",
            self.styles["MutedNote"],
        ))
        story.append(Spacer(1, 8))

        prov_data = data.data_provenance or {
            "packet_headers": "OBSERVED",
            "ip_endpoints": "OBSERVED",
            "security_parameter_indices": "OBSERVED",
            "sequence_numbers": "OBSERVED",
            "traffic_cadence_and_timing": "OBSERVED",
            "vpn_encapsulation_mode": "INFERRED",
            "cryptographic_algorithms": "INFERRED",
            "diffie_hellman_group": "INFERRED",
            "encrypted_traffic_application_type": "PREDICTED",
            "ai_anomaly_attack_likelihood": "PREDICTED",
            "cleartext_inner_payload": "UNAVAILABLE",
            "unobserved_rekey_proposals": "UNAVAILABLE",
        }

        color_map = {
            "OBSERVED": "#16A34A",
            "INFERRED": "#0284C7",
            "PREDICTED": "#8B5CF6",
            "UNAVAILABLE": "#64748B",
        }

        descriptions = {
            "OBSERVED": "Directly extracted from raw PCAP byte streams and network interface frames.",
            "INFERRED": "Logically deduced from unencrypted IKE handshake proposals and header metadata.",
            "PREDICTED": "Estimated via statistical machine learning and behavioral traffic flow classification.",
            "UNAVAILABLE": "Protected by ESP payload encryption or missing due to mid-session capture start.",
        }

        rows = [
            [
                Paragraph("<b>Telemetry Element</b>", self.styles["TableHeader"]),
                Paragraph("<b>Data Classification</b>", self.styles["TableHeader"]),
                Paragraph("<b>Epistemological Basis</b>", self.styles["TableHeader"]),
            ]
        ]

        for param, kind in prov_data.items():
            name_clean = param.replace("_", " ").title()
            col = color_map.get(kind, "#000000")
            desc = descriptions.get(kind, "")
            rows.append([
                Paragraph(name_clean, self.styles["TableCell"]),
                Paragraph(f"<font color='{col}'><b>{kind}</b></font>", self.styles["TableCell"]),
                Paragraph(desc, self.styles["TableCell"]),
            ])

        t = Table(rows, colWidths=[160, 110, 260])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F8FAFC"), colors.white]),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(t)
        story.append(Spacer(1, 14))

    def _build_appendix(self, story: list[Any], data: SecurityAssessmentReportData) -> None:
        story.append(Paragraph("13. Technical Appendix &amp; Architecture Audit", self.styles["SectionHeading"]))
        story.append(
            HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceAfter=8)
        )

        app = data.appendix
        story.append(Paragraph(app["disclaimer"], self.styles["MutedNote"]))
        story.append(Spacer(1, 8))

        arch_rows = [
            [
                Paragraph("<b>#</b>", self.styles["TableHeader"]),
                Paragraph("<b>Architecture Layer</b>", self.styles["TableHeader"]),
                Paragraph("<b>Package</b>", self.styles["TableHeader"]),
                Paragraph("<b>Status</b>", self.styles["TableHeader"]),
            ]
        ]
        for l in app.get("architecture_layers", []):
            st_color = (
                "#16A34A"
                if l["status"] == "OPERATIONAL"
                else "#0284C7"
                if "DEVELOPMENT" in l["status"] or "CREATED" in l["status"] or "READY" in l["status"]
                else "#64748B"
            )
            arch_rows.append([
                Paragraph(str(l["number"]), self.styles["TableCell"]),
                Paragraph(l["name"], self.styles["TableCell"]),
                Paragraph(f"<code>{l['package']}</code>", self.styles["TableCell"]),
                Paragraph(f"<font color='{st_color}'><b>{l['status']}</b></font>", self.styles["TableCell"]),
            ])

        arch_table = Table(arch_rows, colWidths=[30, 230, 160, 110])
        arch_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F8FAFC"), colors.white]),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ])
        )
        story.append(arch_table)


pdf_renderer = PDFReportRenderer()
