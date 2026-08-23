import html
import io
from abc import ABC, abstractmethod
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from src.services.report.types import InvestigationReportData


class ReportGenerator(ABC):
    """Abstract interface for investigation report generation."""

    @abstractmethod
    def generate_pdf(self, report_data: InvestigationReportData) -> bytes:
        """Compiles investigation report data into binary PDF bytes."""
        pass


class MockReportGenerator(ReportGenerator):
    """Deterministic mock report generator for fast testing."""

    def generate_pdf(self, report_data: InvestigationReportData) -> bytes:
        """Returns dummy PDF bytes containing key metadata for testing assertions."""
        header = b"%PDF-1.4\n"
        content = (
            f"Case ID: {report_data.case_id}\n"
            f"Score: {report_data.threat_score}\n"
            f"Severity: {report_data.threat_severity}\n"
            f"Classification: {report_data.threat_classification}\n"
            f"IOCs: {len(report_data.iocs)}\n"
            f"Timeline: {len(report_data.timeline_events)}\n"
        ).encode()
        footer = b"\n%%EOF"
        return header + content + footer


class PDFReportGenerator(ReportGenerator):
    """Production ReportLab PDF generator compiling comprehensive SOC investigation reports."""

    def __init__(self) -> None:
        self.styles = getSampleStyleSheet()
        self._init_custom_styles()

    def _init_custom_styles(self) -> None:
        """Initializes typography hierarchy and styling rules."""
        # Main Header Title
        self.title_style = ParagraphStyle(
            "ReportTitle",
            parent=self.styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=4,
        )

        # Section Heading
        self.heading_style = ParagraphStyle(
            "ReportHeading",
            parent=self.styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#0891b2"),  # Cyan accent
            spaceBefore=8,
            spaceAfter=4,
        )

        # Body Text
        self.body_style = ParagraphStyle(
            "ReportBody",
            parent=self.styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#1e293b"),
        )

        # Small Text / Captions
        self.caption_style = ParagraphStyle(
            "ReportCaption",
            parent=self.styles["Normal"],
            fontName="Helvetica-Oblique",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#64748b"),
        )

        # Code / Monospace
        self.code_style = ParagraphStyle(
            "ReportCode",
            parent=self.styles["Normal"],
            fontName="Courier",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#0f172a"),
        )

    def _get_severity_color(self, severity: str) -> colors.HexColor:
        """Returns visual color mapped to risk severity level."""
        sev = str(severity or "").upper()
        if sev == "CRITICAL":
            return colors.HexColor("#dc2626")  # Red
        if sev == "HIGH":
            return colors.HexColor("#ea580c")  # Orange
        if sev == "MEDIUM":
            return colors.HexColor("#d97706")  # Amber
        return colors.HexColor("#16a34a")  # Green (LOW)

    def _safe_escape(self, val: Any) -> str:
        """Converts value to string and safely escapes HTML characters for ReportLab XML parser."""
        if val is None:
            return "N/A"
        text = str(val)
        return html.escape(text) if text else "N/A"

    def generate_pdf(self, report_data: InvestigationReportData) -> bytes:
        """Builds and returns formatted multi-page investigation PDF report bytes."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        story: list[Any] = []

        # ==========================================
        # 1. Header Banner & Branding
        # ==========================================
        header_table_data = [
            [
                Paragraph("<b>THREATTRACE AI</b> &bull; SOC Incident Report", self.title_style),
                Paragraph(
                    f"<b>Date:</b> {self._safe_escape(report_data.generated_at_iso[:19])} UTC<br/>"
                    f"<b>Version:</b> {self._safe_escape(report_data.version)}",
                    self.caption_style,
                ),
            ]
        ]
        header_table = Table(header_table_data, colWidths=[4.2 * inch, 3.2 * inch])
        header_table.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ALIGN", (1, 0), (1, 0), "RIGHT"),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(header_table)
        story.append(
            HRFlowable(width="100%", thickness=2, color=colors.HexColor("#0891b2"), spaceAfter=10)
        )

        # ==========================================
        # 2. Case Identification & Custody Summary
        # ==========================================
        story.append(Paragraph("1. Investigation Identification & Custody", self.heading_style))
        case_meta_data = [
            [
                Paragraph("<b>Case ID:</b>", self.body_style),
                Paragraph(self._safe_escape(report_data.case_id), self.code_style),
                Paragraph("<b>File Name:</b>", self.body_style),
                Paragraph(self._safe_escape(report_data.file_name), self.body_style),
            ],
            [
                Paragraph("<b>SHA-256 Hash:</b>", self.body_style),
                Paragraph(self._safe_escape(report_data.sha256_hash), self.code_style),
                Paragraph("<b>File Size:</b>", self.body_style),
                Paragraph(f"{report_data.file_size_bytes} bytes", self.body_style),
            ],
            [
                Paragraph("<b>Assigned Analyst:</b>", self.body_style),
                Paragraph(
                    f"{self._safe_escape(report_data.analyst_name or 'SOC Analyst')} ({self._safe_escape(report_data.analyst_email or 'N/A')})",
                    self.body_style,
                ),
                Paragraph("<b>Custody Status:</b>", self.body_style),
                Paragraph(
                    f"<b>{self._safe_escape(report_data.custody_verification)}</b>", self.body_style
                ),
            ],
        ]
        meta_table = Table(
            case_meta_data, colWidths=[1.4 * inch, 2.3 * inch, 1.4 * inch, 2.3 * inch]
        )
        meta_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(meta_table)
        story.append(Spacer(1, 10))

        # ==========================================
        # 3. Incident Executive Summary
        # ==========================================
        story.append(Paragraph("2. Executive Summary", self.heading_style))
        summary_raw = (
            report_data.incident_summary
            or f"Analysis of evidence '{report_data.file_name}' concluded a {report_data.threat_classification.upper()} attack pattern with a deterministic risk score of {report_data.threat_score:.1f}/100 ({report_data.threat_severity.upper()})."
        )
        story.append(Paragraph(self._safe_escape(summary_raw), self.body_style))
        story.append(Spacer(1, 10))

        # ==========================================
        # 4 & 5. Threat Assessment & Risk Breakdown
        # ==========================================
        story.append(Paragraph("3. Threat Assessment & Risk Scoring", self.heading_style))
        sev_color = self._get_severity_color(report_data.threat_severity)

        threat_summary_data = [
            [
                Paragraph("<b>Classification:</b>", self.body_style),
                Paragraph(
                    f"<b>{self._safe_escape(report_data.threat_classification.upper())}</b> (Confidence: {report_data.threat_confidence * 100:.0f}%)",
                    self.body_style,
                ),
                Paragraph("<b>Total Risk Score:</b>", self.body_style),
                Paragraph(
                    f"<b>{report_data.threat_score:.1f} / 100</b> ({self._safe_escape(report_data.threat_severity.upper())})",
                    ParagraphStyle("SevText", parent=self.body_style, textColor=sev_color),
                ),
            ],
            [
                Paragraph("<b>Model Version:</b>", self.body_style),
                Paragraph(self._safe_escape(report_data.threat_model_version), self.body_style),
                Paragraph("<b>Risk Severity:</b>", self.body_style),
                Paragraph(
                    f"<b>{self._safe_escape(report_data.threat_severity.upper())}</b>",
                    self.body_style,
                ),
            ],
        ]
        threat_table = Table(
            threat_summary_data, colWidths=[1.4 * inch, 2.3 * inch, 1.4 * inch, 2.3 * inch]
        )
        threat_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(threat_table)
        story.append(Spacer(1, 8))

        # AI Heuristic Explainability
        if report_data.explainability_reasons:
            story.append(Paragraph("<b>Heuristic Detection Reasons:</b>", self.body_style))
            for reason in report_data.explainability_reasons:
                story.append(Paragraph(f"&bull; {self._safe_escape(reason)}", self.body_style))
            story.append(Spacer(1, 10))

        # ==========================================
        # 6. Email Envelope & RFC Header Metadata
        # ==========================================
        story.append(Paragraph("4. Email Envelope & RFC Headers", self.heading_style))
        email_header_data = [
            [
                Paragraph("<b>From:</b>", self.body_style),
                Paragraph(
                    f"{self._safe_escape(report_data.from_name or '')} &lt;{self._safe_escape(report_data.from_address or report_data.sender)}&gt;",
                    self.body_style,
                ),
            ],
            [
                Paragraph("<b>To:</b>", self.body_style),
                Paragraph(
                    self._safe_escape(
                        ", ".join(report_data.recipients) if report_data.recipients else "N/A"
                    ),
                    self.body_style,
                ),
            ],
            [
                Paragraph("<b>Subject:</b>", self.body_style),
                Paragraph(
                    self._safe_escape(report_data.subject or "(No Subject)"), self.body_style
                ),
            ],
            [
                Paragraph("<b>Date Declared:</b>", self.body_style),
                Paragraph(self._safe_escape(report_data.date_declared), self.body_style),
            ],
            [
                Paragraph("<b>Message-ID:</b>", self.body_style),
                Paragraph(self._safe_escape(report_data.message_id), self.code_style),
            ],
        ]
        if report_data.reply_to:
            email_header_data.append(
                [
                    Paragraph("<b>Reply-To:</b>", self.body_style),
                    Paragraph(self._safe_escape(", ".join(report_data.reply_to)), self.body_style),
                ]
            )
        email_table = Table(email_header_data, colWidths=[1.4 * inch, 6.0 * inch])
        email_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        story.append(email_table)
        story.append(Spacer(1, 10))

        # ==========================================
        # 7. Authentication Status (SPF / DKIM / DMARC)
        # ==========================================
        story.append(Paragraph("5. Email Authentication Verification", self.heading_style))
        auth_data = [
            [
                Paragraph("<b>Protocol</b>", self.body_style),
                Paragraph("<b>Status</b>", self.body_style),
                Paragraph("<b>Forensic Details</b>", self.body_style),
            ],
            [
                Paragraph("SPF", self.body_style),
                Paragraph(
                    f"<b>{self._safe_escape(report_data.spf_status.upper())}</b>", self.body_style
                ),
                Paragraph(
                    self._safe_escape(
                        report_data.authentication_details.get("spf", {}).get(
                            "explanation", "Evaluated from headers"
                        )
                    ),
                    self.body_style,
                ),
            ],
            [
                Paragraph("DKIM", self.body_style),
                Paragraph(
                    f"<b>{self._safe_escape(report_data.dkim_status.upper())}</b>", self.body_style
                ),
                Paragraph(
                    self._safe_escape(
                        report_data.authentication_details.get("dkim", {}).get(
                            "explanation", "Evaluated from headers"
                        )
                    ),
                    self.body_style,
                ),
            ],
            [
                Paragraph("DMARC", self.body_style),
                Paragraph(
                    f"<b>{self._safe_escape(report_data.dmarc_status.upper())}</b>", self.body_style
                ),
                Paragraph(
                    self._safe_escape(
                        report_data.authentication_details.get("dmarc", {}).get(
                            "explanation", "Evaluated from headers"
                        )
                    ),
                    self.body_style,
                ),
            ],
        ]
        auth_table = Table(auth_data, colWidths=[1.2 * inch, 1.4 * inch, 4.8 * inch])
        auth_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(auth_table)
        story.append(Spacer(1, 10))

        # ==========================================
        # 8. Indicators of Compromise (IOCs) Table
        # ==========================================
        story.append(
            Paragraph(
                f"6. Extracted Indicators of Compromise ({report_data.total_iocs_count} IOCs)",
                self.heading_style,
            )
        )
        if report_data.iocs:
            ioc_rows = [
                [
                    Paragraph("<b>Type</b>", self.body_style),
                    Paragraph("<b>Indicator Value</b>", self.body_style),
                    Paragraph("<b>Source</b>", self.body_style),
                ]
            ]
            for ioc in report_data.iocs[:15]:  # Limit to 15 key rows in print view
                ioc_rows.append(
                    [
                        Paragraph(self._safe_escape(ioc.get("ioc_type")), self.body_style),
                        Paragraph(self._safe_escape(ioc.get("value")), self.code_style),
                        Paragraph(self._safe_escape(ioc.get("source")), self.caption_style),
                    ]
                )
            ioc_table = Table(ioc_rows, colWidths=[1.2 * inch, 4.5 * inch, 1.7 * inch])
            ioc_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ]
                )
            )
            story.append(ioc_table)
        else:
            story.append(
                Paragraph(
                    "No external indicators of compromise extracted from evidence.", self.body_style
                )
            )
        story.append(Spacer(1, 10))

        # ==========================================
        # 9. Threat Intelligence & Geo Infrastructure
        # ==========================================
        story.append(
            Paragraph("7. Threat Intelligence & Infrastructure Origin", self.heading_style)
        )
        intel_geo_data = [
            [
                Paragraph("<b>IP Threat Intel Provider:</b>", self.body_style),
                Paragraph(
                    f"{self._safe_escape(report_data.ip_intel_provider)} (Max Risk: {self._safe_escape(report_data.max_ip_risk_score)})",
                    self.body_style,
                ),
            ],
            [
                Paragraph("<b>Domain Threat Intel Provider:</b>", self.body_style),
                Paragraph(
                    f"{self._safe_escape(report_data.domain_intel_provider)} (Max Risk: {self._safe_escape(report_data.max_domain_risk_score)})",
                    self.body_style,
                ),
            ],
            [
                Paragraph("<b>Probable Infrastructure Origin:</b>", self.body_style),
                Paragraph(
                    f"{self._safe_escape(report_data.probable_infrastructure_origin)} (Country: {self._safe_escape(report_data.origin_country)})",
                    self.body_style,
                ),
            ],
            [
                Paragraph("<b>Origin Network / ASN:</b>", self.body_style),
                Paragraph(
                    f"ASN {self._safe_escape(report_data.origin_asn)} &bull; ISP: {self._safe_escape(report_data.origin_isp)}",
                    self.body_style,
                ),
            ],
        ]
        intel_table = Table(intel_geo_data, colWidths=[2.2 * inch, 5.2 * inch])
        intel_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        story.append(intel_table)
        story.append(Spacer(1, 4))
        # Rule 14 Mandatory Disclaimer
        story.append(
            Paragraph(
                f"<b>Disclaimer:</b> {self._safe_escape(report_data.geo_disclaimer or 'Geolocation describes network infrastructure and does not establish the physical location or identity of an attacker.')}",
                self.caption_style,
            )
        )
        story.append(Spacer(1, 10))

        # ==========================================
        # 10. Chronological Evidence Timeline
        # ==========================================
        story.append(
            Paragraph(
                f"8. Forensic Milestone Timeline ({report_data.timeline_events_count} Milestones)",
                self.heading_style,
            )
        )
        if report_data.timeline_events:
            timeline_rows = [
                [
                    Paragraph("<b>Milestone Event</b>", self.body_style),
                    Paragraph("<b>Timestamp (UTC)</b>", self.body_style),
                    Paragraph("<b>Quality Grade</b>", self.body_style),
                    Paragraph("<b>Transit Delay</b>", self.body_style),
                ]
            ]
            for evt in report_data.timeline_events[:10]:
                raw_ts = evt.get("timestamp_iso") or evt.get("timestamp_raw") or "N/A"
                ts_text = self._safe_escape(raw_ts)[:19]
                delay_sec = evt.get("delay_from_previous_seconds")
                delay_text = f"+{delay_sec:.0f}s" if delay_sec and delay_sec > 0 else "-"
                timeline_rows.append(
                    [
                        Paragraph(self._safe_escape(evt.get("title")), self.body_style),
                        Paragraph(ts_text, self.code_style),
                        Paragraph(self._safe_escape(evt.get("timestamp_quality")), self.body_style),
                        Paragraph(delay_text, self.body_style),
                    ]
                )
            timeline_table = Table(
                timeline_rows, colWidths=[2.8 * inch, 2.0 * inch, 1.4 * inch, 1.2 * inch]
            )
            timeline_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ]
                )
            )
            story.append(timeline_table)
        else:
            story.append(Paragraph("No timeline milestones recorded.", self.body_style))
        story.append(Spacer(1, 10))

        # ==========================================
        # 11. Actionable SOC Remediation Recommendations
        # ==========================================
        story.append(
            KeepTogether(
                [
                    Paragraph("9. Actionable SOC Remediation Recommendations", self.heading_style),
                    *[
                        Paragraph(f"{idx + 1}. {self._safe_escape(rec)}", self.body_style)
                        for idx, rec in enumerate(
                            report_data.recommendations
                            or ["No immediate action required. Maintain standard email monitoring."]
                        )
                    ],
                    Spacer(1, 12),
                    HRFlowable(
                        width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=6
                    ),
                    Paragraph(
                        f"Generated by ThreatTrace AI &bull; Evidence SHA-256: {self._safe_escape(report_data.sha256_hash)} &bull; Confidential Incident Documentation",
                        self.caption_style,
                    ),
                ]
            )
        )

        # Build document
        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes
