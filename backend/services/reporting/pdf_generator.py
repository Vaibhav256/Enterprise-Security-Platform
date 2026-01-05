"""
Advanced PDF Report Generator

Generates comprehensive PDF reports with:
- Executive summary
- Vulnerability statistics
- Remediation priorities
- Detailed findings

Uses ReportLab for PDF generation and matplotlib for charts.
"""

import io
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph,
    Spacer,
    PageBreak,
    Image as RLImage,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from io import BytesIO
from PIL import Image

logger = logging.getLogger(__name__)


class PDFReportGenerator:
    """Generate comprehensive PDF vulnerability reports"""

    def __init__(self, page_size=letter):
        """
        Initialize PDF report generator

        Args:
            page_size: Page size (letter or A4)
        """
        self.page_size = page_size
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        """Setup custom paragraph styles with enhanced visual design"""
        # Title style - Large, bold, professional blue
        self.styles.add(
            ParagraphStyle(
                name="CustomTitle",
                parent=self.styles["Heading1"],
                fontSize=28,
                textColor=colors.HexColor("#0f172a"),  # Slate-900
                spaceAfter=12,  # Reduced from 20
                spaceBefore=6,   # Reduced from 10
                alignment=TA_CENTER,
                fontName="Helvetica-Bold",
                leading=34,
            )
        )

        # Subtitle style - Medium, elegant blue
        self.styles.add(
            ParagraphStyle(
                name="CustomSubtitle",
                parent=self.styles["Heading2"],
                fontSize=18,
                textColor=colors.HexColor("#1e40af"),  # Blue-800
                spaceAfter=8,   # Reduced from 16
                spaceBefore=12,  # Reduced from 24
                fontName="Helvetica-Bold",
                leading=22,
                borderPadding=8,
                borderColor=colors.HexColor("#3b82f6"),  # Blue-500
                borderWidth=0,
                leftIndent=0,
            )
        )

        # Section header - Bold, darker
        self.styles.add(
            ParagraphStyle(
                name="SectionHeader",
                parent=self.styles["Heading3"],
                fontSize=14,
                textColor=colors.HexColor("#0f172a"),  # Slate-900
                spaceAfter=6,   # Reduced from 12
                spaceBefore=10,  # Reduced from 18
                fontName="Helvetica-Bold",
                leading=18,
                leftIndent=0,
            )
        )

        # Body text - Readable, justified
        self.styles.add(
            ParagraphStyle(
                name="CustomBody",
                parent=self.styles["BodyText"],
                fontSize=10,
                textColor=colors.HexColor("#1f2937"),  # Gray-800
                alignment=TA_LEFT,
                spaceAfter=4,   # Reduced from 8
                leading=14,
            )
        )

        # CVE style - Monospace, red for emphasis
        self.styles.add(
            ParagraphStyle(
                name="CVEStyle",
                parent=self.styles["Code"],
                fontSize=9,
                textColor=colors.HexColor("#dc2626"),  # Red-600
                fontName="Courier-Bold",
            )
        )
        
        # Info box style - For highlighted information
        self.styles.add(
            ParagraphStyle(
                name="InfoBox",
                parent=self.styles["BodyText"],
                fontSize=10,
                textColor=colors.HexColor("#1f2937"),
                alignment=TA_LEFT,
                spaceAfter=12,
                spaceBefore=12,
                leading=14,
                leftIndent=12,
                rightIndent=12,
            )
        )

    def generate_full_report(
        self,
        scan_data: Dict[str, Any],
        output_path: Path,
        organization: str = "NTRO",
        classification: str = "CONFIDENTIAL"
    ) -> Path:
        """
        Generate comprehensive vulnerability report

        Args:
            scan_data: Scan results and analysis data
            output_path: Path to save PDF
            organization: Organization name for cover page
            classification: Security classification for cover page

        Returns:
            Path to generated PDF
        """
        logger.info(f"Generating PDF report: {output_path}")
        
        # Store organization and classification for use in cover page
        self.organization = organization
        self.classification = classification

        # Create document
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=self.page_size,
            rightMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            topMargin=inch,
            bottomMargin=0.75 * inch,
        )

        # Build content
        story = []

        # Cover page
        story.extend(self._build_cover_page(scan_data))
        story.append(PageBreak())

        # Executive summary
        story.extend(self._build_executive_summary(scan_data))
        story.append(PageBreak())

        # Statistics and charts
        story.extend(self._build_statistics_section(scan_data))
        story.append(PageBreak())

        # Detailed findings
        story.extend(self._build_findings_section(scan_data))
        story.append(PageBreak())

        # Remediation priorities
        story.extend(self._build_remediation_section(scan_data))

        # Build PDF
        doc.build(story)
        logger.info(f"PDF report generated successfully: {output_path}")

        return output_path

    def _build_cover_page(self, scan_data: Dict[str, Any]) -> List:
        """Build cover page with enhanced visual design"""
        elements = []

        # Top spacer - reduced for compact layout
        elements.append(Spacer(1, 0.8 * inch))  # Reduced from 1.5

        # Add decorative line at top
        line_table = Table([['']], colWidths=[6.5 * inch])
        line_table.setStyle(TableStyle([
            ('LINEABOVE', (0, 0), (-1, 0), 3, colors.HexColor("#1e40af")),
            ('TOPPADDING', (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(line_table)
        
        # Title with icon/badge
        title = Paragraph(
            "<font size=32 color='#0f172a'><b>VULNERABILITY</b></font><br/>"
            "<font size=28 color='#1e40af'><b>ASSESSMENT REPORT</b></font>",
            ParagraphStyle(
                'CoverTitle',
                parent=self.styles["CustomTitle"],
                fontSize=32,
                alignment=TA_CENTER,
                spaceAfter=16,
                leading=38,
            )
        )
        elements.append(title)
        
        # Decorative divider
        elements.append(Spacer(1, 0.1 * inch))  # Reduced from 0.2
        divider_table = Table([['']], colWidths=[4 * inch])
        divider_table.setStyle(TableStyle([
            ('LINEABOVE', (0, 0), (-1, 0), 1, colors.HexColor("#3b82f6")),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ]))
        elements.append(divider_table)
        elements.append(Spacer(1, 0.2 * inch))  # Reduced from 0.4

        # Organization with better styling
        org_name = getattr(self, 'organization', 'National Technical Research Organisation (NTRO)')
        org = Paragraph(
            f"<font size=14 color='#1e40af'><b>{org_name}</b></font>",
            ParagraphStyle(
                'CoverOrg',
                parent=self.styles["CustomSubtitle"],
                alignment=TA_CENTER,
                spaceAfter=10,
            )
        )
        elements.append(org)
        elements.append(Spacer(1, 0.3 * inch))  # Reduced from 0.6

        # Scan info in styled box
        classification = getattr(self, 'classification', 'CONFIDENTIAL')
        scan_info = [
            ["Scan ID", scan_data.get("scan_id", "N/A")],
            ["Date", scan_data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))],
            ["Target", scan_data.get("target", {}).get("name", scan_data.get("target", "N/A")) if isinstance(scan_data.get("target"), dict) else scan_data.get("target", "N/A")],
            ["Classification", classification],
        ]

        info_table = Table(scan_info, colWidths=[2.2 * inch, 4 * inch])
        info_table.setStyle(
            TableStyle([
                # Header styling
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),  # Slate-50
                ("FONT", (0, 0), (-1, -1), "Helvetica", 11),
                ("FONT", (0, 0), (0, -1), "Helvetica-Bold", 11),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#1e40af")),  # Blue-800
                ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#1f2937")),  # Gray-800
                
                # Alignment
                ("ALIGN", (0, 0), (0, -1), "RIGHT"),
                ("ALIGN", (1, 0), (1, -1), "LEFT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                
                # Padding
                ("TOPPADDING", (0, 0), (-1, -1), 12),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                ("LEFTPADDING", (0, 0), (-1, -1), 16),
                ("RIGHTPADDING", (0, 0), (-1, -1), 16),
                
                # Border
                ("BOX", (0, 0), (-1, -1), 2, colors.HexColor("#3b82f6")),  # Blue-500
                ("LINEBELOW", (0, 0), (-1, -2), 0.5, colors.HexColor("#cbd5e1")),  # Slate-300
            ])
        )
        elements.append(info_table)
        
        # Bottom spacer and decorative element
        elements.append(Spacer(1, 0.5 * inch))  # Reduced from 1
        
        # Classification badge at bottom
        class_color = colors.HexColor("#dc2626") if "CONFIDENTIAL" in classification.upper() else colors.HexColor("#16a34a")
        class_badge = Paragraph(
            f"<font size=10 color='white'><b>  {classification}  </b></font>",
            ParagraphStyle(
                'ClassBadge',
                parent=self.styles["Normal"],
                alignment=TA_CENTER,
                backColor=class_color,
                borderPadding=8,
            )
        )
        elements.append(class_badge)

        return elements

    def _build_executive_summary(self, scan_data: Dict[str, Any]) -> List:
        """Build executive summary section with enhanced visuals"""
        elements = []

        # Section title with decorative line
        elements.append(
            Paragraph(
                "<font color='#1e40af'><b>EXECUTIVE SUMMARY</b></font>", 
                self.styles["CustomSubtitle"]
            )
        )
        
        # Decorative underline
        line_table = Table([['']], colWidths=[6.5 * inch])
        line_table.setStyle(TableStyle([
            ('LINEBELOW', (0, 0), (-1, 0), 2, colors.HexColor("#3b82f6")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ]))
        elements.append(line_table)
        elements.append(Spacer(1, 0.15 * inch))  # Reduced from 0.25

        # Summary statistics
        stats = scan_data.get("statistics", {})
        total_vulns = stats.get("total", 0)  # Fixed: use 'total' not 'total_vulnerabilities'
        critical = stats.get("critical", 0)
        high = stats.get("high", 0)
        medium = stats.get("medium", 0)
        low = stats.get("low", 0)
        info = stats.get("info", 0)
        hosts_scanned = stats.get("hosts_scanned", 1)

        # Key metrics in colored boxes
        metrics_data = [
            [
                Paragraph(f"<para align='center'><font size=24 color='#dc2626'><b>{critical}</b></font><br/>"
                         f"<font size=9 color='#991b1b'>CRITICAL</font></para>", self.styles["Normal"]),
                Paragraph(f"<para align='center'><font size=24 color='#ea580c'><b>{high}</b></font><br/>"
                         f"<font size=9 color='#9a3412'>HIGH</font></para>", self.styles["Normal"]),
                Paragraph(f"<para align='center'><font size=24 color='#f59e0b'><b>{medium}</b></font><br/>"
                         f"<font size=9 color='#92400e'>MEDIUM</font></para>", self.styles["Normal"]),
                Paragraph(f"<para align='center'><font size=24 color='#16a34a'><b>{low}</b></font><br/>"
                         f"<font size=9 color='#14532d'>LOW</font></para>", self.styles["Normal"]),
            ]
        ]
        
        metrics_table = Table(metrics_data, colWidths=[1.5 * inch] * 4)
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), colors.HexColor("#fef2f2")),  # Red-50
            ('BACKGROUND', (1, 0), (1, 0), colors.HexColor("#fff7ed")),  # Orange-50
            ('BACKGROUND', (2, 0), (2, 0), colors.HexColor("#fffbeb")),  # Amber-50
            ('BACKGROUND', (3, 0), (3, 0), colors.HexColor("#f0fdf4")),  # Green-50
            ('BOX', (0, 0), (0, 0), 2, colors.HexColor("#dc2626")),
            ('BOX', (1, 0), (1, 0), 2, colors.HexColor("#ea580c")),
            ('BOX', (2, 0), (2, 0), 2, colors.HexColor("#f59e0b")),
            ('BOX', (3, 0), (3, 0), 2, colors.HexColor("#16a34a")),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 16),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 16),
        ]))
        elements.append(metrics_table)
        elements.append(Spacer(1, 0.15 * inch))  # Reduced from 0.3

        # Summary text with better formatting - use simple Paragraph without nested para tags
        summary_text_1 = f"""
        This report presents findings from an automated vulnerability assessment 
        conducted on <b>{hosts_scanned} host(s)</b>. The scan identified <b><font color='#dc2626'>{total_vulns} 
        total vulnerabilities</font></b>, including <b><font color='#dc2626'>{critical} critical</font></b> and 
        <b><font color='#ea580c'>{high} high-severity</font></b> 
        findings that require immediate attention.
        """
        
        summary_text_2 = f"""
        The assessment includes network scanning and vulnerability detection.
        Recommendations are prioritized based on risk score and ease of exploitation.
        """

        # Create two paragraphs instead of nested paras
        summary_para_1 = Paragraph(summary_text_1, self.styles["InfoBox"])
        summary_para_2 = Paragraph(summary_text_2, self.styles["InfoBox"])
        
        # Combine in a table for background styling
        summary_data = [[summary_para_1], [summary_para_2]]
        summary_table = Table(summary_data, colWidths=[6.5 * inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('LEFTPADDING', (0, 0), (-1, -1), 16),
            ('RIGHTPADDING', (0, 0), (-1, -1), 16),
        ]))
        elements.append(summary_table)

        # Key findings - enhanced table
        elements.append(Spacer(1, 0.2 * inch))
        elements.append(
            Paragraph("<font color='#1e40af'><b>Key Findings</b></font>", self.styles["SectionHeader"])
        )

        key_findings = [
            ["Finding", "Count"],
            ["Total Vulnerabilities", str(total_vulns)],
            ["Critical Severity", str(critical)],
            ["High Severity", str(high)],
            ["Medium Severity", str(medium)],
            ["Low Severity", str(low)],
            ["Informational", str(info)],
            ["Hosts Scanned", str(hosts_scanned)],
        ]

        findings_table = Table(key_findings, colWidths=[4.5 * inch, 2 * inch])
        findings_table.setStyle(
            TableStyle([
                # Header row
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e40af")),  # Blue-800
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 11),
                ("ALIGN", (0, 0), (0, 0), "LEFT"),
                ("ALIGN", (1, 0), (1, 0), "CENTER"),
                
                # Data rows
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 1), (-1, -1), 10),
                ("ALIGN", (0, 1), (0, -1), "LEFT"),
                ("ALIGN", (1, 1), (1, -1), "CENTER"),
                
                # Padding
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                
                # Borders and colors
                ("BOX", (0, 0), (-1, -1), 1.5, colors.HexColor("#3b82f6")),
                ("LINEBELOW", (0, 0), (-1, 0), 2, colors.HexColor("#1e40af")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("GRID", (0, 1), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),  # Slate-200
            ])
        )
        elements.append(findings_table)

        return elements

    def _build_statistics_section(self, scan_data: Dict[str, Any]) -> List:
        """Build statistics section with charts"""
        elements = []

        elements.append(
            Paragraph("Vulnerability Statistics", self.styles["CustomSubtitle"])
        )
        elements.append(Spacer(1, 0.2 * inch))

        # Get statistics
        stats = scan_data.get("statistics", {})

        # Severity distribution pie chart
        severity_chart = self._create_severity_pie_chart(stats)
        elements.append(severity_chart)
        elements.append(Spacer(1, 0.3 * inch))

        # Top vulnerabilities bar chart (optional - if we have vulnerability data)
        findings = scan_data.get("findings", [])
        if findings and len(findings) > 0:
            # Sort by CVSS score and take top 10
            top_findings = sorted(
                [f for f in findings if f.get('cvss_score')],
                key=lambda x: x.get('cvss_score', 0),
                reverse=True
            )[:10]
            
            if top_findings:
                cve_chart = self._create_top_cves_chart(top_findings)
                elements.append(cve_chart)

        return elements

    def _create_severity_pie_chart(self, stats: Dict[str, Any]) -> Drawing:
        """Create severity distribution pie chart"""
        drawing = Drawing(400, 200)

        pie = Pie()
        pie.x = 150
        pie.y = 50
        pie.width = 150
        pie.height = 150

        pie.data = [
            stats.get("critical", 0),
            stats.get("high", 0),
            stats.get("medium", 0),
            stats.get("low", 0),
            stats.get("info", 0),
        ]
        pie.labels = ["Critical", "High", "Medium", "Low", "Info"]
        pie.slices.strokeWidth = 0.5
        pie.slices[0].fillColor = colors.HexColor("#dc2626")
        pie.slices[1].fillColor = colors.HexColor("#f97316")
        pie.slices[2].fillColor = colors.HexColor("#f59e0b")
        pie.slices[3].fillColor = colors.HexColor("#3b82f6")
        pie.slices[4].fillColor = colors.HexColor("#6b7280")

        drawing.add(pie)

        return drawing

    def _create_top_cves_chart(self, cves: List[Dict[str, Any]]) -> RLImage:
        """Create top CVEs bar chart using matplotlib"""
        # Create matplotlib figure
        fig, ax = plt.subplots(figsize=(8, 4))

        # Extract CVE IDs and scores
        cve_ids = [cve.get("cve_id", "Unknown")[:15] for cve in cves[:10]]  # Truncate long IDs
        scores = [float(cve.get("cvss_score", 0)) for cve in cves[:10]]
        
        colors_list = [
            "#dc2626" if s >= 9.0 else "#f97316" if s >= 7.0 else "#f59e0b"
            for s in scores
        ]

        ax.barh(cve_ids, scores, color=colors_list)
        ax.set_xlabel("CVSS Score")
        ax.set_title("Top 10 CVEs by Severity")
        ax.set_xlim(0, 10)

        # Save to BytesIO
        buf = BytesIO()
        plt.tight_layout()
        plt.savefig(buf, format="png", dpi=100)
        plt.close(fig)
        buf.seek(0)

        # Convert to ReportLab Image
        img = RLImage(buf, width=6 * inch, height=3 * inch)
        return img

    def _build_findings_section(self, scan_data: Dict[str, Any]) -> List:
        """Build detailed findings section"""
        elements = []

        elements.append(
            Paragraph("Detailed Findings", self.styles["CustomSubtitle"])
        )
        elements.append(Spacer(1, 0.1 * inch))  # Reduced from 0.2

        vulnerabilities = scan_data.get("vulnerabilities", [])
        
        if not vulnerabilities:
            elements.append(
                Paragraph("No vulnerabilities found in this scan.", self.styles["CustomBody"])
            )
            return elements

        # Group by severity (case-insensitive)
        by_severity = {}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "INFO").upper()
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(vuln)

        # Critical findings first
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if severity not in by_severity:
                continue

            vulns = by_severity[severity]
            
            # Color code severity headers
            severity_colors = {
                "CRITICAL": "#dc2626",
                "HIGH": "#ea580c",
                "MEDIUM": "#f59e0b",
                "LOW": "#84cc16",
                "INFO": "#3b82f6"
            }
            
            severity_style = ParagraphStyle(
                'SeverityHeader',
                parent=self.styles["SectionHeader"],
                textColor=colors.HexColor(severity_colors.get(severity, "#1f2937"))
            )
            
            elements.append(
                Paragraph(f"{severity} Severity ({len(vulns)} findings)", severity_style)
            )

            for vuln in vulns[:50]:  # Limit to 50 per severity
                elements.extend(self._format_vulnerability(vuln))

            elements.append(Spacer(1, 0.15 * inch))  # Reduced from 0.3

        return elements

    def _format_vulnerability(self, vuln: Dict[str, Any]) -> List:
        """Format individual vulnerability entry with enhanced styling"""
        elements = []

        # Title with CVE ID if available - enhanced with color
        title = vuln.get('title', 'Untitled Vulnerability')
        cve_id = vuln.get('cve_id')
        severity = vuln.get('severity', 'INFO').upper()
        
        # Color based on severity
        title_colors = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#f59e0b",
            "LOW": "#16a34a",
            "INFO": "#3b82f6"
        }
        title_color = title_colors.get(severity, "#1f2937")
        
        if cve_id and cve_id != 'N/A':
            title_text = f"<font color='{title_color}'><b>{cve_id}</b></font> - {title}"
        else:
            title_text = f"<font color='{title_color}'><b>• {title}</b></font>"
        
        elements.append(Paragraph(title_text, self.styles["CustomBody"]))
        elements.append(Spacer(1, 0.04 * inch))  # Reduced from 0.08

        # Details table - build dynamically based on available data
        details = []
        
        # Host
        host = vuln.get("host", "N/A")
        if host and host != "N/A":
            details.append(["Host:", host])
        
        # Port and Service
        port = vuln.get("port")
        service = vuln.get("service")
        protocol = vuln.get("protocol")
        
        if port:
            port_str = str(port)
            if protocol:
                port_str += f"/{protocol}"
            if service:
                port_str += f" ({service})"
            details.append(["Port/Service:", port_str])
        elif service:
            details.append(["Service:", service])
        
        # CVSS Score
        cvss_score = vuln.get('cvss_score')
        if cvss_score and cvss_score not in (None, 'N/A'):
            try:
                score_val = float(cvss_score)
                details.append(["CVSS Score:", f"{score_val:.1f}"])
            except (ValueError, TypeError):
                pass
        
        # Description - use Paragraph for text wrapping
        description = vuln.get("description", "")
        if description and description != "N/A":
            # Don't truncate - let it wrap
            desc_para = Paragraph(description, self.styles["CustomBody"])
            details.append(["Description:", desc_para])
        
        # Solution/Remediation - use Paragraph for text wrapping
        solution = vuln.get("solution")
        if solution and solution not in (None, 'N/A', ''):
            # Don't truncate - let it wrap
            sol_para = Paragraph(solution, self.styles["CustomBody"])
            details.append(["Solution:", sol_para])

        # Only create table if we have details
        if details:
            details_table = Table(details, colWidths=[1.5 * inch, 5.0 * inch])
            details_table.setStyle(
                TableStyle([
                    # Fonts
                    ("FONT", (0, 0), (0, -1), "Helvetica-Bold", 9),
                    ("FONT", (1, 0), (1, -1), "Helvetica", 9),
                    ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#1e40af")),  # Blue labels
                    ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#1f2937")),  # Dark text
                    
                    # Alignment
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ALIGN", (0, 0), (0, -1), "LEFT"),  # Left align labels for consistency
                    
                    # Compact padding
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    
                    # Background and borders
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),  # Slate-50
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),  # Slate-300
                    ("LINEBELOW", (0, 0), (-1, -2), 0.25, colors.HexColor("#e2e8f0")),  # Slate-200
                ])
            )
            elements.append(details_table)
        
        elements.append(Spacer(1, 0.1 * inch))  # Reduced from 0.25

        return elements

    def _build_remediation_section(self, scan_data: Dict[str, Any]) -> List:
        """Build remediation priorities section"""
        elements = []

        elements.append(
            Paragraph("Remediation Priorities", self.styles["CustomSubtitle"])
        )
        elements.append(Spacer(1, 0.1 * inch))

        intro_text = """
        The following remediation actions are prioritized based on severity 
        and exploitability. Critical and High severity items require immediate action.
        """
        elements.append(Paragraph(intro_text, self.styles["CustomBody"]))
        elements.append(Spacer(1, 0.15 * inch))

        # Get mitigations or generate from vulnerabilities
        mitigations = scan_data.get("mitigations", [])
        
        # If no mitigations, generate from vulnerabilities
        if not mitigations:
            vulnerabilities = scan_data.get("vulnerabilities", [])
            mitigations = []
            
            # Group by severity and create remediation items
            severity_order = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}
            
            # Sort by severity
            sorted_vulns = sorted(
                vulnerabilities,
                key=lambda v: (severity_order.get(v.get("severity", "INFO").upper(), 5), v.get("title", ""))
            )
            
            for vuln in sorted_vulns[:20]:  # Top 20
                severity = vuln.get("severity", "INFO").upper()
                solution = vuln.get("solution") or "Review and patch"
                title = vuln.get("title") or "Unknown Vulnerability"
                
                # Determine effort based on severity
                effort_map = {"CRITICAL": "High", "HIGH": "Medium", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Low"}
                
                mitigations.append({
                    "priority": severity,
                    "title": title[:60] + "..." if len(title) > 60 else title,
                    "action": solution[:80] + "..." if len(solution) > 80 else solution,
                    "effort": effort_map.get(severity, "Medium")
                })
        
        if mitigations:
            table_data = [["Priority", "Vulnerability", "Recommended Action", "Effort"]]
            
            for mitigation in mitigations[:15]:  # Top 15 to fit on page
                priority = mitigation.get("priority", "MEDIUM").upper()
                
                # Color code priority
                if priority == "CRITICAL":
                    priority_cell = Paragraph(f"<b><font color='#dc2626'>{priority}</font></b>", self.styles["Normal"])
                elif priority == "HIGH":
                    priority_cell = Paragraph(f"<b><font color='#ea580c'>{priority}</font></b>", self.styles["Normal"])
                elif priority == "MEDIUM":
                    priority_cell = Paragraph(f"<b><font color='#f59e0b'>{priority}</font></b>", self.styles["Normal"])
                else:
                    priority_cell = Paragraph(f"<font color='#16a34a'>{priority}</font>", self.styles["Normal"])
                
                title = mitigation.get("title", "N/A")
                action = mitigation.get("action", mitigation.get("solution", "Review and remediate"))
                effort = mitigation.get("effort", "Medium")
                
                table_data.append([
                    priority_cell,
                    Paragraph(title, self.styles["CustomBody"]),
                    Paragraph(action, self.styles["CustomBody"]),
                    effort
                ])

            remediation_table = Table(
                table_data, colWidths=[1 * inch, 2.5 * inch, 2.5 * inch, 0.8 * inch]
            )
            remediation_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#3b82f6")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("TOPPADDING", (0, 0), (-1, 0), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                    ("TOPPADDING", (0, 1), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                     [colors.white, colors.HexColor("#f9fafb")]),
                ])
            )
            elements.append(remediation_table)
        else:
            elements.append(
                Paragraph("No specific remediation actions identified.", self.styles["CustomBody"])
            )

        return elements


def generate_pdf_report(
    scan_data: Dict[str, Any], 
    output_path: str,
    organization: str = "NTRO",
    classification: str = "CONFIDENTIAL"
) -> str:
    """
    Convenience function to generate PDF report

    Args:
        scan_data: Scan results dictionary
        output_path: Path to save PDF
        organization: Organization name (optional)
        classification: Security classification (optional)

    Returns:
        Path to generated PDF
    """
    generator = PDFReportGenerator()
    result_path = generator.generate_full_report(
        scan_data, 
        Path(output_path), 
        organization=organization,
        classification=classification
    )
    return str(result_path)
