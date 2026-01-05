"""
Export Service Exporters

Implementations of various export formats for vulnerability scan results.

Author: NTRO Security Team
Date: 2025-10-23
"""

import csv
import io
import json
import logging
from datetime import datetime
from io import BytesIO
from typing import Any, BinaryIO, Dict

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (PageBreak, Paragraph, SimpleDocTemplate,
                                Spacer, Table, TableStyle)

logger = logging.getLogger(__name__)


class BaseExporter:
    """Base class for all exporters"""

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    def export(self, scan_data: Dict[str, Any], output: BinaryIO) -> None:
        """
        Export scan data to specified format

        Args:
            scan_data: Complete scan data including results
            output: Output stream to write to
        """
        raise NotImplementedError("Subclasses must implement export()")


class JSONExporter(BaseExporter):
    """Export scan results as JSON"""

    def export(self, scan_data: Dict[str, Any], output: BinaryIO) -> None:
        """Export to JSON format"""
        try:
            # Convert datetime objects to strings
            json_data = self._serialize_data(scan_data)

            # Write formatted JSON
            json_str = json.dumps(json_data, indent=2, ensure_ascii=False)
            output.write(json_str.encode("utf-8"))

            self.logger.info("JSON export completed successfully")
        except Exception as e:
            self.logger.error("JSON export failed: %s", e)
            raise

    def _serialize_data(self, data: Any) -> Any:
        """Recursively serialize data to JSON-compatible format"""
        if isinstance(data, datetime):
            return data.isoformat()
        elif isinstance(data, dict):
            return {k: self._serialize_data(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._serialize_data(item) for item in data]
        else:
            return data


class CSVExporter(BaseExporter):
    """Export scan results as CSV"""

    def export(self, scan_data: Dict[str, Any], output: BinaryIO) -> None:
        """Export to CSV format"""
        try:
            # Create string buffer for CSV
            text_output = io.StringIO()
            writer = csv.writer(text_output)

            # Write header
            writer.writerow(["Scan Information"])
            writer.writerow(["Target", scan_data.get("target", "N/A")])
            writer.writerow(["Tool", scan_data.get("tool_name", "N/A")])
            writer.writerow(["Scan Type", scan_data.get("scan_type", "N/A")])
            writer.writerow(["Status", scan_data.get("status", "N/A")])
            writer.writerow(["Created", scan_data.get("created_at", "N/A")])
            writer.writerow(["Completed", scan_data.get("completed_at", "N/A")])
            writer.writerow([])

            # Write summary if available
            summary = scan_data.get("summary", {})
            if summary:
                writer.writerow(["Summary"])
                writer.writerow(
                    ["Total Vulnerabilities", summary.get("vulnerabilities_found", 0)]
                )
                writer.writerow(["Critical", summary.get("critical_count", 0)])
                writer.writerow(["High", summary.get("high_count", 0)])
                writer.writerow(["Medium", summary.get("medium_count", 0)])
                writer.writerow(["Low", summary.get("low_count", 0)])
                writer.writerow(["Info", summary.get("info_count", 0)])
                writer.writerow([])

            # Write vulnerabilities header
            writer.writerow(["Vulnerabilities"])
            writer.writerow(
                [
                    "ID",
                    "Severity",
                    "Title",
                    "Description",
                    "Host",
                    "Port",
                    "Protocol",
                    "CVE",
                    "CVSS Score",
                    "Solution",
                ]
            )

            # Write vulnerability details
            parsed_results = scan_data.get("parsed_results", [])
            vuln_count = 0

            for result in parsed_results:
                result_data = result.get("data", {})
                vulnerabilities = result_data.get("vulnerabilities", [])

                for vuln in vulnerabilities:
                    vuln_count += 1
                    writer.writerow(
                        [
                            vuln_count,
                            vuln.get("severity", "N/A"),
                            vuln.get("title", vuln.get("name", "N/A")),
                            (
                                vuln.get("description", "N/A")[:100] + "..."
                                if len(vuln.get("description", "")) > 100
                                else vuln.get("description", "N/A")
                            ),
                            vuln.get("host", vuln.get("ip", "N/A")),
                            vuln.get("port", "N/A"),
                            vuln.get("protocol", "N/A"),
                            vuln.get("cve_id", vuln.get("cve", "N/A")),
                            vuln.get("cvss_score", vuln.get("cvss", "N/A")),
                            (
                                vuln.get("solution", vuln.get("recommendation", "N/A"))[
                                    :100
                                ]
                                + "..."
                                if len(
                                    vuln.get("solution", vuln.get("recommendation", ""))
                                )
                                > 100
                                else vuln.get(
                                    "solution", vuln.get("recommendation", "N/A")
                                )
                            ),
                        ]
                    )

            # Convert to bytes
            output.write(
                text_output.getvalue().encode("utf-8-sig")
            )  # UTF-8 with BOM for Excel

            self.logger.info(
                "CSV export completed successfully (%d vulnerabilities)", vuln_count
            )
        except Exception as e:
            self.logger.error("CSV export failed: %s", e)
            raise


class XLSXExporter(BaseExporter):
    """Export scan results as Excel workbook"""

    def export(self, scan_data: Dict[str, Any], output: BinaryIO) -> None:
        """Export to XLSX format"""
        try:
            wb = Workbook()

            # Create sheets
            self._create_summary_sheet(wb, scan_data)
            self._create_vulnerabilities_sheet(wb, scan_data)
            self._create_details_sheet(wb, scan_data)

            # Remove default sheet if it exists
            if "Sheet" in wb.sheetnames:
                del wb["Sheet"]

            # Save to output stream
            wb.save(output)
            output.seek(0)  # Reset file pointer to beginning

            self.logger.info("XLSX export completed successfully")
        except Exception as e:
            self.logger.error("XLSX export failed: %s", e)
            raise

    def _create_summary_sheet(self, wb: Workbook, scan_data: Dict[str, Any]) -> None:
        """Create summary overview sheet"""
        ws = wb.active
        ws.title = "Summary"

        # Header style
        header_fill = PatternFill(
            start_color="4472C4", end_color="4472C4", fill_type="solid"
        )
        header_font = Font(bold=True, color="FFFFFF", size=14)

        # Title
        ws["A1"] = "Vulnerability Scan Report"
        ws["A1"].font = Font(bold=True, size=16)
        ws.merge_cells("A1:B1")

        # Scan information
        ws["A3"] = "Scan Information"
        ws["A3"].font = header_font
        ws["A3"].fill = header_fill
        ws.merge_cells("A3:B3")

        row = 4
        info_items = [
            ("Target", scan_data.get("target", "N/A")),
            ("Tool", scan_data.get("tool_name", "N/A")),
            ("Scan Type", scan_data.get("scan_type", "N/A")),
            ("Status", scan_data.get("status", "N/A")),
            ("Created", scan_data.get("created_at", "N/A")),
            ("Completed", scan_data.get("completed_at", "N/A")),
        ]

        for label, value in info_items:
            ws[f"A{row}"] = label
            ws[f"A{row}"].font = Font(bold=True)
            ws[f"B{row}"] = str(value)
            row += 1

        # Summary statistics
        summary = scan_data.get("summary", {})
        row += 1
        ws[f"A{row}"] = "Vulnerability Summary"
        ws[f"A{row}"].font = header_font
        ws[f"A{row}"].fill = header_fill
        ws.merge_cells(f"A{row}:B{row}")

        row += 1
        severity_data = [
            ("Total Vulnerabilities", summary.get("vulnerabilities_found", 0)),
            ("Critical", summary.get("critical_count", 0)),
            ("High", summary.get("high_count", 0)),
            ("Medium", summary.get("medium_count", 0)),
            ("Low", summary.get("low_count", 0)),
            ("Info", summary.get("info_count", 0)),
        ]

        # Color coding for severities
        severity_colors = {
            "Critical": "C00000",
            "High": "FF0000",
            "Medium": "FFC000",
            "Low": "FFFF00",
            "Info": "00B0F0",
        }

        for label, value in severity_data:
            ws[f"A{row}"] = label
            ws[f"A{row}"].font = Font(bold=True)
            ws[f"B{row}"] = value

            # Color code severity rows
            if label in severity_colors:
                fill_color = severity_colors[label]
                ws[f"A{row}"].fill = PatternFill(
                    start_color=fill_color, end_color=fill_color, fill_type="solid"
                )
                ws[f"B{row}"].fill = PatternFill(
                    start_color=fill_color, end_color=fill_color, fill_type="solid"
                )

            row += 1

        # Adjust column widths
        ws.column_dimensions["A"].width = 25
        ws.column_dimensions["B"].width = 40

    def _create_vulnerabilities_sheet(
        self, wb: Workbook, scan_data: Dict[str, Any]
    ) -> None:
        """Create vulnerabilities listing sheet"""
        ws = wb.create_sheet("Vulnerabilities")

        # Headers
        headers = [
            "ID",
            "Severity",
            "Title",
            "Host",
            "Port",
            "CVE",
            "CVSS Score",
            "Description",
        ]
        for col, header in enumerate(headers, start=1):
            cell = ws.cell(row=1, column=col, value=header)
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill(
                start_color="4472C4", end_color="4472C4", fill_type="solid"
            )
            cell.alignment = Alignment(horizontal="center")

        # Write vulnerabilities
        row = 2
        parsed_results = scan_data.get("parsed_results", [])

        severity_fills = {
            "critical": PatternFill(
                start_color="C00000", end_color="C00000", fill_type="solid"
            ),
            "high": PatternFill(
                start_color="FF0000", end_color="FF0000", fill_type="solid"
            ),
            "medium": PatternFill(
                start_color="FFC000", end_color="FFC000", fill_type="solid"
            ),
            "low": PatternFill(
                start_color="FFFF00", end_color="FFFF00", fill_type="solid"
            ),
            "info": PatternFill(
                start_color="00B0F0", end_color="00B0F0", fill_type="solid"
            ),
        }

        vuln_id = 1
        for result in parsed_results:
            result_data = result.get("data", {})
            vulnerabilities = result_data.get("vulnerabilities", [])

            for vuln in vulnerabilities:
                severity = vuln.get("severity", "info").lower()

                ws.cell(row=row, column=1, value=vuln_id)
                ws.cell(row=row, column=2, value=vuln.get("severity", "N/A"))
                ws.cell(
                    row=row, column=3, value=vuln.get("title", vuln.get("name", "N/A"))
                )
                ws.cell(
                    row=row, column=4, value=vuln.get("host", vuln.get("ip", "N/A"))
                )
                ws.cell(row=row, column=5, value=vuln.get("port", "N/A"))
                ws.cell(
                    row=row, column=6, value=vuln.get("cve_id", vuln.get("cve", "N/A"))
                )
                ws.cell(
                    row=row,
                    column=7,
                    value=vuln.get("cvss_score", vuln.get("cvss", "N/A")),
                )

                # Truncate description
                description = vuln.get("description", "N/A")
                if len(description) > 100:
                    description = description[:100] + "..."
                ws.cell(row=row, column=8, value=description)

                # Color code severity
                if severity in severity_fills:
                    ws.cell(row=row, column=2).fill = severity_fills[severity]
                    ws.cell(row=row, column=2).font = Font(bold=True, color="FFFFFF")

                row += 1
                vuln_id += 1

        # Adjust column widths
        ws.column_dimensions["A"].width = 8
        ws.column_dimensions["B"].width = 12
        ws.column_dimensions["C"].width = 40
        ws.column_dimensions["D"].width = 20
        ws.column_dimensions["E"].width = 10
        ws.column_dimensions["F"].width = 15
        ws.column_dimensions["G"].width = 12
        ws.column_dimensions["H"].width = 50

        # Freeze header row
        ws.freeze_panes = "A2"

    def _create_details_sheet(self, wb: Workbook, scan_data: Dict[str, Any]) -> None:
        """Create detailed findings sheet"""
        ws = wb.create_sheet("Details")

        # Title
        ws["A1"] = "Detailed Vulnerability Information"
        ws["A1"].font = Font(bold=True, size=14)
        ws.merge_cells("A1:D1")

        row = 3
        parsed_results = scan_data.get("parsed_results", [])
        vuln_id = 1

        for result in parsed_results:
            result_data = result.get("data", {})
            vulnerabilities = result_data.get("vulnerabilities", [])

            for vuln in vulnerabilities:
                # Vulnerability header
                ws[f"A{row}"] = f"Vulnerability #{vuln_id}"
                ws[f"A{row}"].font = Font(bold=True, size=12)
                ws.merge_cells(f"A{row}:D{row}")
                row += 1

                # Details
                details = [
                    ("Severity", vuln.get("severity", "N/A")),
                    ("Title", vuln.get("title", vuln.get("name", "N/A"))),
                    ("Host", vuln.get("host", vuln.get("ip", "N/A"))),
                    ("Port", vuln.get("port", "N/A")),
                    ("Protocol", vuln.get("protocol", "N/A")),
                    ("CVE ID", vuln.get("cve_id", vuln.get("cve", "N/A"))),
                    ("CVSS Score", vuln.get("cvss_score", vuln.get("cvss", "N/A"))),
                    ("Description", vuln.get("description", "N/A")),
                    (
                        "Solution",
                        vuln.get("solution", vuln.get("recommendation", "N/A")),
                    ),
                    (
                        "References",
                        (
                            ", ".join(vuln.get("references", []))
                            if isinstance(vuln.get("references"), list)
                            else vuln.get("references", "N/A")
                        ),
                    ),
                ]

                for label, value in details:
                    ws[f"A{row}"] = label
                    ws[f"A{row}"].font = Font(bold=True)
                    ws[f"B{row}"] = str(value)
                    ws.merge_cells(f"B{row}:D{row}")
                    row += 1

                row += 1  # Spacing between vulnerabilities
                vuln_id += 1

        # Adjust column widths
        ws.column_dimensions["A"].width = 20
        ws.column_dimensions["B"].width = 80


class PDFExporter(BaseExporter):
    """Export scan results as PDF report"""

    def export(self, scan_data: Dict[str, Any], output: BinaryIO) -> None:
        """Export to PDF format"""
        try:
            # Create PDF document
            doc = SimpleDocTemplate(
                output,
                pagesize=letter,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18,
            )

            # Build story
            story = []
            styles = getSampleStyleSheet()

            # Add custom styles
            title_style = ParagraphStyle(
                "CustomTitle",
                parent=styles["Heading1"],
                fontSize=24,
                textColor=colors.HexColor("#1a1a1a"),
                spaceAfter=30,
                alignment=TA_CENTER,
            )

            heading_style = ParagraphStyle(
                "CustomHeading",
                parent=styles["Heading2"],
                fontSize=16,
                textColor=colors.HexColor("#2e5090"),
                spaceAfter=12,
                spaceBefore=12,
            )

            # Title
            story.append(Paragraph("Vulnerability Scan Report", title_style))
            story.append(Spacer(1, 0.2 * inch))

            # Executive Summary Section
            story.append(Paragraph("Executive Summary", heading_style))

            summary = scan_data.get("summary", {})
            total_vulns = summary.get("vulnerabilities_found", 0)
            critical = summary.get("critical_count", 0)
            high = summary.get("high_count", 0)
            medium = summary.get("medium_count", 0)
            low = summary.get("low_count", 0)
            info = summary.get("info_count", 0)

            exec_summary_text = f"""
            This report presents the findings of a security vulnerability assessment performed on
            <b>{scan_data.get('target', 'N/A')}</b> using <b>{scan_data.get('tool_name', 'N/A')}</b>.
            <br/><br/>
            The scan identified a total of <b>{total_vulns} vulnerabilities</b>, including
            <b>{critical} Critical</b>, <b>{high} High</b>, <b>{medium} Medium</b>,
            <b>{low} Low</b>, and <b>{info} Informational</b> findings.
            """

            story.append(Paragraph(exec_summary_text, styles["BodyText"]))
            story.append(Spacer(1, 0.3 * inch))

            # Scan Information Table
            story.append(Paragraph("Scan Information", heading_style))

            scan_info_data = [
                ["Property", "Value"],
                ["Target", scan_data.get("target", "N/A")],
                ["Tool", scan_data.get("tool_name", "N/A")],
                ["Scan Type", scan_data.get("scan_type", "N/A")],
                ["Status", scan_data.get("status", "N/A")],
                ["Created", scan_data.get("created_at", "N/A")],
                ["Completed", scan_data.get("completed_at", "N/A")],
            ]

            scan_table = Table(scan_info_data, colWidths=[2 * inch, 4 * inch])
            scan_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2e5090")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 12),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                        ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                        ("GRID", (0, 0), (-1, -1), 1, colors.black),
                        ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
                    ]
                )
            )

            story.append(scan_table)
            story.append(Spacer(1, 0.3 * inch))

            # Severity Distribution Chart
            if total_vulns > 0:
                story.append(Paragraph("Severity Distribution", heading_style))

                # Create pie chart
                drawing = Drawing(400, 200)
                pie = Pie()
                pie.x = 150
                pie.y = 50
                pie.width = 150
                pie.height = 150

                pie.data = [critical, high, medium, low, info]
                pie.labels = ["Critical", "High", "Medium", "Low", "Info"]
                pie.slices.strokeWidth = 0.5

                # Color slices by severity
                colors_list = [
                    colors.HexColor("#C00000"),  # Critical - Dark Red
                    colors.HexColor("#FF0000"),  # High - Red
                    colors.HexColor("#FFC000"),  # Medium - Orange
                    colors.HexColor("#FFFF00"),  # Low - Yellow
                    colors.HexColor("#00B0F0"),  # Info - Blue
                ]

                for i, color in enumerate(colors_list):
                    pie.slices[i].fillColor = color

                drawing.add(pie)
                story.append(drawing)
                story.append(Spacer(1, 0.3 * inch))

            # Summary Statistics Table
            story.append(Paragraph("Vulnerability Summary", heading_style))

            summary_data = [
                ["Severity", "Count", "Percentage"],
                [
                    "Critical",
                    critical,
                    f"{(critical/total_vulns*100):.1f}%" if total_vulns > 0 else "0%",
                ],
                [
                    "High",
                    high,
                    f"{(high/total_vulns*100):.1f}%" if total_vulns > 0 else "0%",
                ],
                [
                    "Medium",
                    medium,
                    f"{(medium/total_vulns*100):.1f}%" if total_vulns > 0 else "0%",
                ],
                [
                    "Low",
                    low,
                    f"{(low/total_vulns*100):.1f}%" if total_vulns > 0 else "0%",
                ],
                [
                    "Info",
                    info,
                    f"{(info/total_vulns*100):.1f}%" if total_vulns > 0 else "0%",
                ],
                ["Total", total_vulns, "100%"],
            ]

            summary_table = Table(
                summary_data, colWidths=[2 * inch, 1.5 * inch, 1.5 * inch]
            )
            summary_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2e5090")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 12),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                        ("BACKGROUND", (0, 1), (0, 1), colors.HexColor("#C00000")),
                        ("BACKGROUND", (0, 2), (0, 2), colors.HexColor("#FF0000")),
                        ("BACKGROUND", (0, 3), (0, 3), colors.HexColor("#FFC000")),
                        ("BACKGROUND", (0, 4), (0, 4), colors.HexColor("#FFFF00")),
                        ("BACKGROUND", (0, 5), (0, 5), colors.HexColor("#00B0F0")),
                        ("BACKGROUND", (0, 6), (-1, 6), colors.grey),
                        ("TEXTCOLOR", (0, 1), (0, 5), colors.whitesmoke),
                        ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
                        ("FONTNAME", (0, 6), (-1, 6), "Helvetica-Bold"),
                        ("GRID", (0, 0), (-1, -1), 1, colors.black),
                    ]
                )
            )

            story.append(summary_table)
            story.append(PageBreak())

            # Detailed Findings Section
            story.append(Paragraph("Detailed Findings", heading_style))
            story.append(Spacer(1, 0.2 * inch))

            parsed_results = scan_data.get("parsed_results", [])
            vuln_num = 1

            for result in parsed_results:
                result_data = result.get("data", {})
                vulnerabilities = result_data.get("vulnerabilities", [])

                # Limit to first 20 to avoid huge PDFs
                for vuln in vulnerabilities[:20]:
                    # Vulnerability header
                    vuln_title = (
                        f"{vuln_num}. [{vuln.get('severity', 'N/A')}] "
                        f"{vuln.get('title', vuln.get('name', 'Unnamed'))}"
                    )
                    story.append(Paragraph(vuln_title, heading_style))

                    # Vulnerability details table
                    vuln_data = [
                        ["Host", vuln.get("host", vuln.get("ip", "N/A"))],
                        ["Port", str(vuln.get("port", "N/A"))],
                        ["CVE", vuln.get("cve_id", vuln.get("cve", "N/A"))],
                        [
                            "CVSS Score",
                            str(vuln.get("cvss_score", vuln.get("cvss", "N/A"))),
                        ],
                    ]

                    vuln_table = Table(vuln_data, colWidths=[1.5 * inch, 4.5 * inch])
                    vuln_table.setStyle(
                        TableStyle(
                            [
                                (
                                    "BACKGROUND",
                                    (0, 0),
                                    (0, -1),
                                    colors.HexColor("#e0e0e0"),
                                ),
                                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                                ("GRID", (0, 0), (-1, -1), 1, colors.black),
                                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ]
                        )
                    )

                    story.append(vuln_table)
                    story.append(Spacer(1, 0.1 * inch))

                    # Description
                    if vuln.get("description"):
                        story.append(
                            Paragraph("<b>Description:</b>", styles["BodyText"])
                        )
                        desc_text = vuln.get("description", "No description available")
                        if len(desc_text) > 500:
                            desc_text = desc_text[:500] + "..."
                        story.append(Paragraph(desc_text, styles["BodyText"]))
                        story.append(Spacer(1, 0.1 * inch))

                    # Solution
                    if vuln.get("solution") or vuln.get("recommendation"):
                        story.append(
                            Paragraph("<b>Remediation:</b>", styles["BodyText"])
                        )
                        solution_text = vuln.get(
                            "solution",
                            vuln.get("recommendation", "No solution provided"),
                        )
                        if len(solution_text) > 500:
                            solution_text = solution_text[:500] + "..."
                        story.append(Paragraph(solution_text, styles["BodyText"]))

                    story.append(Spacer(1, 0.2 * inch))
                    vuln_num += 1

            # Footer
            story.append(Spacer(1, 0.5 * inch))
            footer_text = f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | NTRO Vulnerability Scanner"
            story.append(
                Paragraph(
                    footer_text,
                    ParagraphStyle(
                        "Footer",
                        parent=styles["Normal"],
                        fontSize=8,
                        textColor=colors.grey,
                        alignment=TA_CENTER,
                    ),
                )
            )

            # Build PDF
            doc.build(story)
            output.seek(0)  # Reset file pointer to beginning

            self.logger.info(
                "PDF export completed successfully (%d vulnerabilities)", vuln_num - 1
            )
        except Exception as e:
            self.logger.error("PDF export failed: %s", e)
            raise


class XMLExporter(BaseExporter):
    """XML format exporter"""

    def export(self, scan_data: Dict[str, Any], output: BinaryIO):
        """Export scan data as XML"""
        import xml.etree.ElementTree as ET
        from xml.dom import minidom

        try:
            # Create root element
            root = ET.Element("scan")

            # Add basic info
            info = ET.SubElement(root, "info")
            ET.SubElement(info, "scan_id").text = str(scan_data.get("scan_id", ""))
            ET.SubElement(info, "target").text = str(scan_data.get("target", ""))
            ET.SubElement(info, "tool").text = str(scan_data.get("tool_name", ""))
            ET.SubElement(info, "scan_type").text = str(scan_data.get("scan_type", ""))
            ET.SubElement(info, "status").text = str(scan_data.get("status", ""))
            ET.SubElement(info, "created_at").text = str(
                scan_data.get("created_at", "")
            )
            ET.SubElement(info, "completed_at").text = str(
                scan_data.get("completed_at", "")
            )

            # Add summary
            if "summary" in scan_data and scan_data["summary"]:
                summary = ET.SubElement(root, "summary")
                for key, value in scan_data["summary"].items():
                    if key != "additional_data":
                        ET.SubElement(summary, key).text = str(value)

            # Add results
            if "parsed_results" in scan_data and scan_data["parsed_results"]:
                results = ET.SubElement(root, "results")
                for result in scan_data["parsed_results"]:
                    result_elem = ET.SubElement(results, "result")
                    ET.SubElement(result_elem, "tool").text = str(
                        result.get("tool_name", "")
                    )
                    ET.SubElement(result_elem, "timestamp").text = str(
                        result.get("timestamp", "")
                    )

                    # Add result data
                    data = result.get("data", {})
                    if isinstance(data, dict):
                        for key, value in data.items():
                            elem = ET.SubElement(result_elem, str(key))
                            elem.text = (
                                str(value)
                                if not isinstance(value, (dict, list))
                                else str(value)
                            )

            # Pretty print XML
            xml_str = ET.tostring(root, encoding="utf-8")
            dom = minidom.parseString(xml_str)
            pretty_xml = dom.toprettyxml(indent="  ", encoding="utf-8")

            output.write(pretty_xml)
            self.logger.info("XML export completed successfully")
        except Exception as e:
            self.logger.error("XML export failed: %s", e)
            raise


class ExportManager:
    """Manager class for handling exports"""

    EXPORTERS = {
        "json": JSONExporter,
        "csv": CSVExporter,
        "xlsx": XLSXExporter,
        "pdf": PDFExporter,
        "xml": XMLExporter,
    }

    @classmethod
    def export_scan(cls, scan_data: Dict[str, Any], format: str) -> BytesIO:
        """
        Export scan data in specified format

        Args:
            scan_data: Complete scan data
            format: Export format (json, csv, xlsx, pdf)

        Returns:
            BytesIO buffer with exported data

        Raises:
            ValueError: If format is not supported
        """
        format = format.lower()

        if format not in cls.EXPORTERS:
            raise ValueError(
                f"Unsupported export format: {format}. Supported: {list(cls.EXPORTERS.keys())}"
            )

        # Create exporter instance
        exporter_class = cls.EXPORTERS[format]
        exporter = exporter_class()

        # Create output buffer
        output = BytesIO()

        # Perform export
        exporter.export(scan_data, output)

        # Reset buffer position
        output.seek(0)

        return output

    @classmethod
    def get_content_type(cls, format: str) -> str:
        """Get MIME content type for format"""
        content_types = {
            "json": "application/json",
            "csv": "text/csv",
            "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "pdf": "application/pdf",
            "xml": "application/xml",
        }
        format_lower = format.lower()
        if format_lower not in content_types:
            raise ValueError(f"Unsupported export format: {format}")
        return content_types[format_lower]

    @classmethod
    def get_file_extension(cls, format: str) -> str:
        """Get file extension for format"""
        return format.lower()
