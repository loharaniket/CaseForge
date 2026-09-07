import html
import io
import re
from abc import ABC, abstractmethod
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
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


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas that renders dynamic 'Page X of Y' footers and running headers."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._saved_page_states: list[dict[str, Any]] = []

    def showPage(self) -> None:
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int) -> None:
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Running header on pages 2 and subsequent
        if self._pageNumber > 1:
            self.drawString(36, 760, "CASEFORGE \u2022 SOC Forensic Incident Report")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(36, 752, 576, 752)

        # Running footer on all pages
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(36, 42, 576, 42)

        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(576, 28, page_str)
        self.drawString(36, 28, "CONFIDENTIAL \u2022 FOR AUTHORIZED FORENSIC USE ONLY")
        self.restoreState()


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
    """Production ReportLab PDF generator compiling publication-grade SOC forensic investigation reports."""

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
            fontSize=17,
            leading=21,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=3,
        )

        # Section Heading
        self.heading_style = ParagraphStyle(
            "ReportHeading",
            parent=self.styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=15,
            textColor=colors.HexColor("#0284c7"),  # Professional Sky Blue
            spaceBefore=8,
            spaceAfter=4,
        )

        # Body Text
        self.body_style = ParagraphStyle(
            "ReportBody",
            parent=self.styles["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11.5,
            textColor=colors.HexColor("#1e293b"),
        )

        # Small Text / Captions
        self.caption_style = ParagraphStyle(
            "ReportCaption",
            parent=self.styles["Normal"],
            fontName="Helvetica-Oblique",
            fontSize=7.5,
            leading=9.5,
            textColor=colors.HexColor("#64748b"),
        )

        # Monospace Code
        self.code_style = ParagraphStyle(
            "ReportCode",
            parent=self.styles["Normal"],
            fontName="Courier",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#0f172a"),
        )

        # Compact Monospace for Hashes
        self.code_small_style = ParagraphStyle(
            "ReportCodeSmall",
            parent=self.styles["Normal"],
            fontName="Courier",
            fontSize=7,
            leading=9,
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

    def _format_file_size(self, size_bytes: Any) -> str:
        """Formats byte count into human-readable representation."""
        try:
            bytes_val = int(size_bytes)
            if bytes_val < 1024:
                return f"{bytes_val} bytes"
            if bytes_val < 1024 * 1024:
                kb = bytes_val / 1024.0
                return f"{kb:.2f} KB ({bytes_val:,} bytes)"
            mb = bytes_val / (1024.0 * 1024.0)
            return f"{mb:.2f} MB ({bytes_val:,} bytes)"
        except (ValueError, TypeError):
            return "N/A"

    def _format_custody_badge(self, status: Any) -> str:
        """Returns human-friendly custody status badge."""
        s = str(status or "").strip().upper()
        if "VERIFIED" in s or "AUTHENTIC" in s:
            return '<font color="#16a34a"><b>&#x2714; Verified Authentic</b></font>'
        if "TAMPERED" in s or "CORRUPT" in s or "FAIL" in s:
            return '<font color="#dc2626"><b>&#x2716; Integrity Compromised</b></font>'
        return f"<b>{html.escape(s.replace('_', ' ').title())}</b>"

    def _format_model_version(self, version_str: Any) -> str:
        """Formats internal model string into professional public display label."""
        v = str(version_str or "").strip()
        if not v or v == "N/A":
            return "Production Rule Engine (v1.0)"
        if "rule-based-heuristic" in v:
            return "Rule-Based Heuristics (v1.0.0)"
        return html.escape(v)

    def _format_duration(self, seconds: float | None) -> str:
        """Formats transit delay seconds into human-readable notation."""
        if seconds is None or seconds <= 0:
            return "-"
        sec = int(round(seconds))
        if sec < 60:
            return f"+{sec}s"
        if sec < 3600:
            m = sec // 60
            s = sec % 60
            return f"+{m}m {s}s" if s > 0 else f"+{m}m"
        h = sec // 3600
        m = (sec % 3600) // 60
        return f"+{h}h {m}m" if m > 0 else f"+{h}h"

    def _format_quality_grade(self, grade: Any) -> str:
        """Formats quality grade enum string into neat human-readable label."""
        g = str(grade or "").strip().upper()
        mapping = {
            "SERVER_INGESTION": "Server Ingestion",
            "HEADER_DECLARED": "Header Declared",
            "DERIVED": "Verified Derived",
            "MISSING": "Missing",
        }
        return mapping.get(g, g.replace("_", " ").title() or "-")

    def _clean_source_label(self, source: str | None) -> str:
        """Converts raw code source identifier into clean human-readable label."""
        if not source:
            return "Observed Evidence"
        s = str(source).strip()
        mapping = {
            "header.from": "From Header",
            "header.to": "To Header",
            "header.cc": "Cc Header",
            "header.bcc": "Bcc Header",
            "header.reply_to": "Reply-To Header",
            "header.return_path": "Return-Path Header",
            "header.received": "Received Relay Header",
            "header.received_host": "Relay MTA Host",
            "header.authentication-results": "Authentication Results Header",
            "header.arc-authentication-results": "ARC Auth Results Header",
            "header.received-spf": "Received SPF Header",
            "body.url": "Extracted Body URL",
            "body.url.url_domain": "Extracted URL Domain",
            "body.url.url_host": "Extracted URL Host",
            "header.from.email_domain": "From Domain",
            "header.to.email_domain": "To Domain",
            "header.return_path.email_domain": "Return-Path Domain",
            "body.text": "Body Text Mention",
            "system.ingestion": "System Ingestion",
        }
        if s in mapping:
            return mapping[s]
        if s.startswith("header."):
            return s.replace("header.", "Header: ").replace("-", " ").title()
        if s.startswith("attachment."):
            return f"Attachment: {s.replace('attachment.', '')}"
        return s.replace("_", " ").title()

    def generate_pdf(self, report_data: InvestigationReportData) -> bytes:
        """Builds and returns formatted multi-page investigation PDF report bytes."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=44,
            bottomMargin=44,
        )

        story: list[Any] = []

        # ==========================================
        # 1. Header Banner & Branding
        # ==========================================
        sev_color = self._get_severity_color(report_data.threat_severity)
        header_table_data = [
            [
                Paragraph("<b>CASEFORGE</b> &bull; SOC Incident Report", self.title_style),
                Paragraph(
                    f"<b>Report Date:</b> {self._safe_escape(report_data.generated_at_iso[:19])} UTC<br/>"
                    f"<b>Engine Version:</b> {self._safe_escape(report_data.version)}",
                    self.caption_style,
                ),
            ]
        ]
        header_table = Table(header_table_data, colWidths=[4.3 * inch, 3.2 * inch])
        header_table.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("ALIGN", (1, 0), (1, 0), "RIGHT"),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        story.append(header_table)
        story.append(
            HRFlowable(width="100%", thickness=2, color=colors.HexColor("#0284c7"), spaceAfter=8)
        )

        # ==========================================
        # 2. Case Identification & Custody Summary
        # ==========================================
        story.append(Paragraph("1. Investigation Identification & Custody", self.heading_style))
        case_meta_data = [
            [
                Paragraph("<b>Case ID:</b>", self.body_style),
                Paragraph(f"<font name='Courier'>{self._safe_escape(report_data.case_id)}</font>", self.body_style),
                Paragraph("<b>Evidence File:</b>", self.body_style),
                Paragraph(self._safe_escape(report_data.file_name), self.body_style),
            ],
            [
                Paragraph("<b>SHA-256 Hash:</b>", self.body_style),
                Paragraph(f"<font name='Courier'>{self._safe_escape(report_data.sha256_hash)}</font>", self.code_small_style),
                "",
                "",
            ],
            [
                Paragraph("<b>File Size:</b>", self.body_style),
                Paragraph(self._format_file_size(report_data.file_size_bytes), self.body_style),
                Paragraph("<b>Custody Status:</b>", self.body_style),
                Paragraph(self._format_custody_badge(report_data.custody_verification), self.body_style),
            ],
            [
                Paragraph("<b>Assigned Analyst:</b>", self.body_style),
                Paragraph(
                    f"{self._safe_escape(report_data.analyst_name or 'SOC Analyst')} ({self._safe_escape(report_data.analyst_email or 'N/A')})",
                    self.body_style,
                ),
                Paragraph("<b>Case Status:</b>", self.body_style),
                Paragraph(f"<b>{self._safe_escape(str(report_data.case_status).upper())}</b>", self.body_style),
            ],
        ]
        meta_table = Table(
            case_meta_data, colWidths=[1.3 * inch, 2.5 * inch, 1.2 * inch, 2.5 * inch]
        )
        meta_table.setStyle(
            TableStyle(
                [
                    ("SPAN", (1, 1), (3, 1)),  # Let SHA-256 span full width to avoid wrapping!
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 3.5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
                ]
            )
        )
        story.append(meta_table)
        story.append(Spacer(1, 8))

        # ==========================================
        # 3. Incident Executive Summary
        # ==========================================
        story.append(Paragraph("2. Executive Summary", self.heading_style))
        summary_raw = (
            report_data.incident_summary
            or f"Automated SOC forensic investigation of evidence '{report_data.file_name}' concluded a {report_data.threat_classification.upper()} classification with a deterministic risk score of {report_data.threat_score:.1f}/100 ({report_data.threat_severity.upper()})."
        )
        story.append(Paragraph(self._safe_escape(summary_raw), self.body_style))
        story.append(Spacer(1, 8))

        # ==========================================
        # 4. Threat Assessment & Risk Scoring
        # ==========================================
        story.append(Paragraph("3. Threat Assessment & Risk Scoring", self.heading_style))

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
                Paragraph(self._format_model_version(report_data.threat_model_version), self.body_style),
                Paragraph("<b>Risk Severity:</b>", self.body_style),
                Paragraph(
                    f"<b>{self._safe_escape(report_data.threat_severity.upper())}</b>",
                    ParagraphStyle("SevBadge", parent=self.body_style, textColor=sev_color),
                ),
            ],
        ]
        threat_table = Table(
            threat_summary_data, colWidths=[1.3 * inch, 2.5 * inch, 1.2 * inch, 2.5 * inch]
        )
        threat_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 3.5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
                ]
            )
        )
        story.append(threat_table)
        story.append(Spacer(1, 6))

        # Heuristic Explainability
        if report_data.explainability_reasons:
            story.append(Paragraph("<b>Heuristic Detection Reasons:</b>", self.body_style))
            for reason in report_data.explainability_reasons:
                story.append(Paragraph(f"&bull; {self._safe_escape(reason)}", self.body_style))
            story.append(Spacer(1, 8))

        # ==========================================
        # 5. Email Envelope & RFC Header Metadata
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
                Paragraph(self._safe_escape(report_data.message_id), self.code_small_style),
            ],
        ]
        if report_data.reply_to:
            email_header_data.append(
                [
                    Paragraph("<b>Reply-To:</b>", self.body_style),
                    Paragraph(self._safe_escape(", ".join(report_data.reply_to)), self.body_style),
                ]
            )
        email_table = Table(email_header_data, colWidths=[1.3 * inch, 6.2 * inch])
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
        story.append(Spacer(1, 8))

        # ==========================================
        # 6. Authentication Status (SPF / DKIM / DMARC)
        # ==========================================
        story.append(Paragraph("5. Email Authentication Verification", self.heading_style))

        # Format descriptive forensic explanation per protocol
        auth_details_dict = report_data.authentication_details or {}

        spf_exp = (
            auth_details_dict.get("spf_details")
            or auth_details_dict.get("spf", {}).get("explanation")
            or ("SPF passed: sending host is authorized by domain policy." if report_data.spf_status.lower() == "pass"
                else "SPF check evaluated from headers.")
        )
        dkim_exp = (
            auth_details_dict.get("dkim_details")
            or auth_details_dict.get("dkim", {}).get("explanation")
            or ("Cryptographic signature verified: domain signature is authentic." if report_data.dkim_status.lower() == "pass"
                else "DKIM signature check evaluated from headers.")
        )
        dmarc_exp = (
            auth_details_dict.get("dmarc_details")
            or auth_details_dict.get("dmarc", {}).get("explanation")
            or ("DMARC alignment verified: message conforms to sender domain policy." if report_data.dmarc_status.lower() == "pass"
                else "DMARC policy alignment check evaluated from headers.")
        )

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
                Paragraph(self._safe_escape(spf_exp), self.body_style),
            ],
            [
                Paragraph("DKIM", self.body_style),
                Paragraph(
                    f"<b>{self._safe_escape(report_data.dkim_status.upper())}</b>", self.body_style
                ),
                Paragraph(self._safe_escape(dkim_exp), self.body_style),
            ],
            [
                Paragraph("DMARC", self.body_style),
                Paragraph(
                    f"<b>{self._safe_escape(report_data.dmarc_status.upper())}</b>", self.body_style
                ),
                Paragraph(self._safe_escape(dmarc_exp), self.body_style),
            ],
        ]
        auth_table = Table(auth_data, colWidths=[1.1 * inch, 1.3 * inch, 5.1 * inch])
        auth_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 3.5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
                ]
            )
        )
        story.append(auth_table)
        story.append(Spacer(1, 8))

        # ==========================================
        # 7. Indicators of Compromise (IOCs) Table
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
                clean_src = self._clean_source_label(ioc.get("source"))
                ioc_rows.append(
                    [
                        Paragraph(self._safe_escape(str(ioc.get("ioc_type", "")).upper()), self.body_style),
                        Paragraph(self._safe_escape(ioc.get("value")), self.code_small_style),
                        Paragraph(self._safe_escape(clean_src), self.caption_style),
                    ]
                )
            ioc_table = Table(ioc_rows, colWidths=[1.1 * inch, 4.1 * inch, 2.3 * inch], repeatRows=1)
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
            if report_data.total_iocs_count > 15:
                story.append(
                    Paragraph(
                        f"<i>Showing top 15 of {report_data.total_iocs_count} indicators. Complete IOC manifest is archived with the case record.</i>",
                        self.caption_style,
                    )
                )
        else:
            story.append(
                Paragraph(
                    "No external indicators of compromise extracted from evidence.", self.body_style
                )
            )
        story.append(Spacer(1, 8))

        # ==========================================
        # 8. Threat Intelligence & Geo Infrastructure
        # ==========================================
        story.append(
            Paragraph("7. Threat Intelligence & Infrastructure Origin", self.heading_style)
        )

        origin_infra = report_data.probable_infrastructure_origin
        origin_ctry = report_data.origin_country
        if (not origin_ctry or origin_ctry == "N/A" or origin_ctry == "Not available") and (not origin_infra or origin_infra == "N/A" or origin_infra == "Not available"):
            infra_summary = "Private / internal relay infrastructure or undisclosed origin IP (GeoIP not applicable)"
        else:
            infra_summary = f"{self._safe_escape(origin_infra)} (Country: {self._safe_escape(origin_ctry)})"

        asn_info = f"ASN {self._safe_escape(report_data.origin_asn)} &bull; ISP: {self._safe_escape(report_data.origin_isp)}" if report_data.origin_asn else "Not advertised / Private AS"

        intel_geo_data = [
            [
                Paragraph("<b>IP Threat Intel Provider:</b>", self.body_style),
                Paragraph(
                    f"{self._safe_escape(report_data.ip_intel_provider)} (Max Risk: {self._safe_escape(report_data.max_ip_risk_score or 0.0)})",
                    self.body_style,
                ),
            ],
            [
                Paragraph("<b>Domain Threat Intel Provider:</b>", self.body_style),
                Paragraph(
                    f"{self._safe_escape(report_data.domain_intel_provider)} (Max Risk: {self._safe_escape(report_data.max_domain_risk_score or 0.0)})",
                    self.body_style,
                ),
            ],
            [
                Paragraph("<b>Probable Infrastructure Origin:</b>", self.body_style),
                Paragraph(infra_summary, self.body_style),
            ],
            [
                Paragraph("<b>Origin Network / ASN:</b>", self.body_style),
                Paragraph(asn_info, self.body_style),
            ],
        ]
        intel_table = Table(intel_geo_data, colWidths=[2.2 * inch, 5.3 * inch])
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
        story.append(
            Paragraph(
                f"<b>Disclaimer:</b> {self._safe_escape(report_data.geo_disclaimer or 'Geolocation describes network infrastructure and does not establish the physical location or identity of an attacker.')}",
                self.caption_style,
            )
        )
        story.append(Spacer(1, 8))

        # ==========================================
        # 9. Chronological Evidence Timeline
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
            for evt in report_data.timeline_events[:12]:
                raw_ts = evt.get("timestamp_iso") or evt.get("timestamp_raw") or "N/A"
                ts_text = self._safe_escape(raw_ts)[:19].replace("T", " ")
                delay_sec = evt.get("delay_from_previous_seconds")
                delay_text = self._format_duration(delay_sec)
                grade_text = self._format_quality_grade(evt.get("timestamp_quality"))

                timeline_rows.append(
                    [
                        Paragraph(self._safe_escape(evt.get("title")), self.body_style),
                        Paragraph(ts_text, self.code_small_style),
                        Paragraph(self._safe_escape(grade_text), self.body_style),
                        Paragraph(delay_text, self.body_style),
                    ]
                )
            timeline_table = Table(
                timeline_rows, colWidths=[2.6 * inch, 1.9 * inch, 1.6 * inch, 1.4 * inch], repeatRows=1
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
        story.append(Spacer(1, 8))

        # ==========================================
        # 10. Analyst Conclusion (KeepTogether for clean page break)
        # ==========================================
        conclusion_flowables = [
            Paragraph("9. Automated Analyst Conclusion", self.heading_style),
        ]
        conclusion_data = [
            [
                Paragraph("<b>Verdict:</b>", self.body_style),
                Paragraph(f"<b>{self._safe_escape(report_data.conclusion_classification)}</b>", self.body_style)
            ],
            [
                Paragraph("<b>Attribution:</b>", self.body_style),
                Paragraph(self._safe_escape(report_data.conclusion_attribution), self.body_style)
            ]
        ]
        conc_table = Table(conclusion_data, colWidths=[1.3 * inch, 6.2 * inch])
        conc_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        conclusion_flowables.append(conc_table)
        conclusion_flowables.append(Spacer(1, 5))

        if report_data.conclusion_primary_findings:
            conclusion_flowables.append(Paragraph("<b>Primary Findings:</b>", self.body_style))
            for finding in report_data.conclusion_primary_findings:
                conclusion_flowables.append(Paragraph(f"&bull; {self._safe_escape(finding)}", self.body_style))
            conclusion_flowables.append(Spacer(1, 4))
        if report_data.conclusion_limitations:
            conclusion_flowables.append(Paragraph("<b>Analysis Limitations:</b>", self.body_style))
            for lim in report_data.conclusion_limitations:
                conclusion_flowables.append(Paragraph(f"&bull; {self._safe_escape(lim)}", self.body_style))
            conclusion_flowables.append(Spacer(1, 8))

        story.append(KeepTogether(conclusion_flowables))

        # ==========================================
        # 11. Related Campaigns
        # ==========================================
        story.append(Paragraph("10. Related Campaigns", self.heading_style))
        if report_data.related_campaigns:
            camp_rows = [
                [
                    Paragraph("<b>Campaign ID</b>", self.body_style),
                    Paragraph("<b>Correlation Confidence</b>", self.body_style),
                    Paragraph("<b>First Seen</b>", self.body_style)
                ]
            ]
            for camp in report_data.related_campaigns:
                c_val = float(camp.get("confidence", 0.0))
                # Fix confidence bug: if already > 1.0, it is 0-100 scale, don't multiply by 100!
                conf_pct = c_val if c_val > 1.0 else c_val * 100.0
                camp_rows.append([
                    Paragraph(self._safe_escape(camp.get("campaign_id")), self.code_style),
                    Paragraph(f"{conf_pct:.0f}%", self.body_style),
                    Paragraph(self._safe_escape(str(camp.get("first_seen", "N/A"))[:10]), self.body_style)
                ])
            camp_table = Table(camp_rows, colWidths=[3.3 * inch, 2.1 * inch, 2.1 * inch], repeatRows=1)
            camp_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(camp_table)
        else:
            story.append(Paragraph("No related malicious campaigns correlated with this evidence.", self.body_style))
        story.append(Spacer(1, 8))

        # ==========================================
        # 12. Analysis History Trail
        # ==========================================
        story.append(Paragraph("11. Analysis History Trail", self.heading_style))
        if report_data.analysis_history:
            hist_rows = [
                [
                    Paragraph("<b>Timestamp (UTC)</b>", self.body_style),
                    Paragraph("<b>Component</b>", self.body_style),
                    Paragraph("<b>Version / Provider</b>", self.body_style),
                    Paragraph("<b>Status</b>", self.body_style)
                ]
            ]
            for hist in report_data.analysis_history:
                ts_hist = self._safe_escape(str(hist.get("timestamp", "N/A"))[:19]).replace("T", " ")
                hist_rows.append([
                    Paragraph(ts_hist, self.code_small_style),
                    Paragraph(self._safe_escape(hist.get("component")), self.body_style),
                    Paragraph(self._safe_escape(hist.get("version")), self.body_style),
                    Paragraph(self._safe_escape(hist.get("status")), self.body_style)
                ])
            hist_table = Table(hist_rows, colWidths=[1.8 * inch, 2.5 * inch, 2.0 * inch, 1.2 * inch], repeatRows=1)
            hist_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(hist_table)
        else:
            story.append(Paragraph("No automated analysis history recorded.", self.body_style))
        story.append(Spacer(1, 8))

        # ==========================================
        # 13. Actionable SOC Remediation Recommendations
        # ==========================================
        story.append(
            KeepTogether(
                [
                    Paragraph("12. Actionable SOC Remediation Recommendations", self.heading_style),
                    *[
                        Paragraph(f"<b>{idx + 1}.</b> {self._safe_escape(rec)}", self.body_style)
                        for idx, rec in enumerate(
                            report_data.recommendations
                            or ["No immediate remediation action required. Maintain standard email monitoring."]
                        )
                    ],
                    Spacer(1, 10),
                    HRFlowable(
                        width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=5
                    ),
                    Paragraph(
                        f"Generated by CaseForge &bull; Evidence SHA-256: {self._safe_escape(report_data.sha256_hash)} &bull; Official Forensic Record",
                        self.caption_style,
                    ),
                ]
            )
        )

        # Build document with NumberedCanvas for professional running headers and footers
        doc.build(story, canvasmaker=NumberedCanvas)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes
