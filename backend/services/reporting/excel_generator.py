"""
Excel Report Generator

Generates comprehensive Excel reports with multiple worksheets,
charts, and conditional formatting using XlsxWriter.
"""

from datetime import datetime
from typing import Dict, List, Any, Optional
import xlsxwriter
from xlsxwriter.workbook import Workbook
from xlsxwriter.worksheet import Worksheet
from xlsxwriter.chart import Chart


class ExcelReportGenerator:
    """
    Generate formatted Excel reports for vulnerability scans.
    
    Features:
    - Multiple worksheets (Summary, Vulnerabilities, Mitigations)
    - Conditional formatting (severity-based colors)
    - Charts (pie, bar, histogram)
    - Auto-column sizing
    - Freeze panes
    - Hyperlinks
    """
    
    def __init__(self, filepath: str):
        """
        Initialize Excel report generator.
        
        Args:
            filepath: Output file path for Excel report
        """
        self.filepath = filepath
        self.workbook: Optional[Workbook] = None
        self.formats: Dict[str, Any] = {}
        
    def generate_full_report(
        self,
        scan_data: Dict[str, Any],
        organization: str = "NTRO",
        classification: str = "CONFIDENTIAL"
    ) -> str:
        """
        Generate complete Excel report with all worksheets.
        
        Args:
            scan_data: Scan results dictionary containing:
                - scan_id: Scan identifier
                - timestamp: Scan timestamp
                - target: Target information
                - summary: Executive summary
                - statistics: Vulnerability statistics
                - findings: List of vulnerabilities
                - mitigations: List of mitigations
            organization: Organization name
            classification: Security classification
        
        Returns:
            str: Path to generated Excel file
        """
        # Create workbook
        self.workbook = xlsxwriter.Workbook(self.filepath)
        
        # Setup custom formats
        self._setup_formats()
        
        # Build worksheets
        self._build_summary_sheet(scan_data, organization, classification)
        self._build_vulnerabilities_sheet(scan_data)
        self._build_mitigations_sheet(scan_data)
        self._build_charts_sheet(scan_data)
        
        # Close workbook
        self.workbook.close()
        
        return self.filepath
    
    def _setup_formats(self):
        """Setup cell formats for consistent styling with enhanced visuals."""
        wb = self.workbook
        
        # Title format - Professional dark blue
        self.formats['title'] = wb.add_format({
            'bold': True,
            'font_size': 20,
            'font_color': '#0f172a',  # Slate-900
            'bg_color': '#e0e7ff',    # Indigo-100
            'align': 'center',
            'valign': 'vcenter',
            'border': 2,
            'border_color': '#1e40af',  # Blue-800
        })
        
        # Header format - Blue-800 background
        self.formats['header'] = wb.add_format({
            'bold': True,
            'font_size': 11,
            'bg_color': '#1e40af',  # Blue-800
            'font_color': 'white',
            'align': 'center',
            'valign': 'vcenter',
            'border': 1,
            'border_color': '#1e3a8a',
        })
        
        # Subheader format - Blue-600 background
        self.formats['subheader'] = wb.add_format({
            'bold': True,
            'font_size': 10,
            'bg_color': '#2563eb',  # Blue-600
            'font_color': 'white',
            'align': 'left',
            'valign': 'vcenter',
            'border': 1,
        })
        
        # Cell format - Light background
        self.formats['cell'] = wb.add_format({
            'font_size': 10,
            'font_color': '#1f2937',  # Gray-800
            'bg_color': '#ffffff',
            'align': 'left',
            'valign': 'top',
            'border': 1,
            'border_color': '#e5e7eb',  # Gray-200
            'text_wrap': True,
        })
        
        # Alternate row format
        self.formats['cell_alt'] = wb.add_format({
            'font_size': 10,
            'font_color': '#1f2937',
            'bg_color': '#f8fafc',  # Slate-50
            'align': 'left',
            'valign': 'top',
            'border': 1,
            'border_color': '#e5e7eb',
            'text_wrap': True,
        })
        
        # Severity formats - Enhanced colors matching PDF
        self.formats['critical'] = wb.add_format({
            'bg_color': '#dc2626',  # Red-600
            'font_color': 'white',
            'bold': True,
            'align': 'center',
            'valign': 'vcenter',
            'border': 1,
            'border_color': '#991b1b',
        })
        
        self.formats['high'] = wb.add_format({
            'bg_color': '#ea580c',  # Orange-600
            'font_color': 'white',
            'bold': True,
            'align': 'center',
            'valign': 'vcenter',
            'border': 1,
            'border_color': '#9a3412',
        })
        
        self.formats['medium'] = wb.add_format({
            'bg_color': '#f59e0b',  # Amber-500
            'font_color': 'white',
            'bold': True,
            'align': 'center',
            'valign': 'vcenter',
            'border': 1,
            'border_color': '#92400e',
        })
        
        self.formats['low'] = wb.add_format({
            'bg_color': '#16a34a',  # Green-600
            'font_color': 'white',
            'bold': True,
            'align': 'center',
            'valign': 'vcenter',
            'border': 1,
            'border_color': '#14532d',
        })
        
        self.formats['info'] = wb.add_format({
            'bg_color': '#3b82f6',  # Blue-500
            'font_color': 'white',
            'bold': True,
            'align': 'center',
            'valign': 'vcenter',
            'border': 1,
            'border_color': '#1e40af',
        })
        
        # Number format - Better styling
        self.formats['number'] = wb.add_format({
            'num_format': '#,##0.0',
            'align': 'center',
            'valign': 'vcenter',
            'border': 1,
            'border_color': '#e5e7eb',
            'font_color': '#1f2937',
        })
        
        # Date format
        self.formats['date'] = wb.add_format({
            'num_format': 'yyyy-mm-dd',
            'align': 'center',
            'valign': 'vcenter',
            'border': 1,
            'border_color': '#e5e7eb',
        })
        
        # URL format - Blue links
        self.formats['url'] = wb.add_format({
            'font_color': '#2563eb',  # Blue-600
            'underline': True,
            'border': 1,
            'border_color': '#e5e7eb',
        })
        
        # Classification format - For header info
        self.formats['classification'] = wb.add_format({
            'bold': True,
            'font_size': 11,
            'bg_color': '#dc2626',  # Red-600 for CONFIDENTIAL
            'font_color': 'white',
            'align': 'center',
            'valign': 'vcenter',
            'border': 2,
        })
        
        # Metric box formats - For statistics display
        self.formats['metric_label'] = wb.add_format({
            'bold': True,
            'font_size': 9,
            'bg_color': '#f1f5f9',  # Slate-100
            'font_color': '#475569',  # Slate-600
            'align': 'center',
            'valign': 'vcenter',
            'border': 1,
        })
        
        self.formats['metric_value'] = wb.add_format({
            'bold': True,
            'font_size': 14,
            'align': 'center',
            'valign': 'vcenter',
            'border': 2,
        })
    
    def _build_summary_sheet(
        self,
        scan_data: Dict[str, Any],
        organization: str,
        classification: str
    ):
        """Build executive summary worksheet with enhanced visuals."""
        ws: Worksheet = self.workbook.add_worksheet('Summary')
        
        # Set column widths for better appearance
        ws.set_column('A:A', 28)
        ws.set_column('B:B', 55)
        ws.set_column('C:C', 3)  # Spacer
        ws.set_column('D:E', 12)  # Metrics
        
        row = 0
        
        # Title with enhanced styling
        ws.merge_range(row, 0, row, 1, 
                      f'{organization}',
                      self.formats['title'])
        ws.set_row(row, 35)
        row += 1
        
        ws.merge_range(row, 0, row, 1, 
                      'Vulnerability Assessment Report',
                      self.formats['subheader'])
        ws.set_row(row, 25)
        row += 2
        
        # Classification badge
        ws.write(row, 0, 'Classification:', self.formats['subheader'])
        ws.write(row, 1, classification, self.formats['classification'])
        row += 2
        
        # Get scan info
        scan_info = scan_data.get('scan_info', {})
        target = scan_data.get('target', {})
        
        # Scan metadata with better formatting
        ws.write(row, 0, 'SCAN INFORMATION', self.formats['subheader'])
        ws.write(row, 1, '', self.formats['subheader'])
        row += 1
        
        metadata = [
            ('Scan ID:', scan_data.get('scan_id', 'N/A')),
            ('Scan Date:', scan_data.get('timestamp', datetime.now().isoformat())),
            ('Target:', target.get('name', 'N/A') if isinstance(target, dict) else str(target)),
            ('IP Range:', target.get('ip_range', 'N/A') if isinstance(target, dict) else 'N/A'),
            ('Tool:', scan_info.get('tool', 'N/A') if isinstance(scan_info, dict) else 'N/A'),
            ('Scan Type:', scan_info.get('scan_type', 'N/A') if isinstance(scan_info, dict) else 'N/A'),
            ('Status:', scan_info.get('status', 'N/A') if isinstance(scan_info, dict) else 'N/A'),
        ]
        
        for idx, (label, value) in enumerate(metadata):
            cell_format = self.formats['cell'] if idx % 2 == 0 else self.formats['cell_alt']
            ws.write(row, 0, label, self.formats['metric_label'])
            ws.write(row, 1, str(value), cell_format)
            row += 1
        
        row += 1
        
        # Statistics section with visual metrics dashboard
        ws.write(row, 0, 'VULNERABILITY STATISTICS', self.formats['subheader'])
        ws.write(row, 1, '', self.formats['subheader'])
        row += 1
        
        stats = scan_data.get('statistics', {})
        total_vulns = stats.get('total', 0)
        critical = stats.get('critical', 0)
        high = stats.get('high', 0)
        medium = stats.get('medium', 0)
        low = stats.get('low', 0)
        info = stats.get('info', 0)
        
        # Create visual severity metrics (4 boxes in a row)
        severity_row = row
        
        # Critical box
        ws.write(severity_row, 0, 'CRITICAL', self.formats['metric_label'])
        critical_format = self.workbook.add_format({
            'bold': True, 'font_size': 18, 'align': 'center', 'valign': 'vcenter',
            'bg_color': '#fef2f2', 'font_color': '#dc2626', 'border': 2, 'border_color': '#dc2626'
        })
        ws.write(severity_row + 1, 0, critical, critical_format)
        ws.set_row(severity_row + 1, 30)
        
        # High box
        ws.write(severity_row, 1, 'HIGH', self.formats['metric_label'])
        high_format = self.workbook.add_format({
            'bold': True, 'font_size': 18, 'align': 'center', 'valign': 'vcenter',
            'bg_color': '#fff7ed', 'font_color': '#ea580c', 'border': 2, 'border_color': '#ea580c'
        })
        ws.write(severity_row + 1, 1, high, high_format)
        
        row = severity_row + 3
        
        # Medium box
        ws.write(severity_row, 3, 'MEDIUM', self.formats['metric_label'])
        medium_format = self.workbook.add_format({
            'bold': True, 'font_size': 18, 'align': 'center', 'valign': 'vcenter',
            'bg_color': '#fffbeb', 'font_color': '#f59e0b', 'border': 2, 'border_color': '#f59e0b'
        })
        ws.write(severity_row + 1, 3, medium, medium_format)
        
        # Low box
        ws.write(severity_row, 4, 'LOW', self.formats['metric_label'])
        low_format = self.workbook.add_format({
            'bold': True, 'font_size': 18, 'align': 'center', 'valign': 'vcenter',
            'bg_color': '#f0fdf4', 'font_color': '#16a34a', 'border': 2, 'border_color': '#16a34a'
        })
        ws.write(severity_row + 1, 4, low, low_format)
        
        # Detailed statistics table
        stat_rows = [
            ('Total Vulnerabilities', total_vulns),
            ('Informational', info),
            ('', ''),  # Blank row
            ('Hosts Scanned', stats.get('hosts_scanned', 1)),
            ('Vulnerable Hosts', stats.get('vulnerable_hosts', 1 if total_vulns > 0 else 0)),
            ('Total Ports Scanned', stats.get('total_ports', 0)),
        ]
        
        for idx, (label, value) in enumerate(stat_rows):
            if label:  # Skip blank rows for label
                cell_format = self.formats['cell'] if idx % 2 == 0 else self.formats['cell_alt']
                ws.write(row, 0, label, self.formats['metric_label'])
                ws.write(row, 1, value, cell_format)
            row += 1
        
        row += 1
        
        # Executive summary section
        ws.write(row, 0, 'EXECUTIVE SUMMARY', self.formats['subheader'])
        ws.write(row, 1, '', self.formats['subheader'])
        row += 1
        
        summary_text = scan_data.get('summary', 
            f'This automated vulnerability assessment identified {total_vulns} total vulnerabilities ' +
            f'including {critical} critical and {high} high-severity issues that require immediate attention.')
        
        # Use text wrap for summary
        summary_format = self.workbook.add_format({
            'font_size': 10,
            'text_wrap': True,
            'align': 'left',
            'valign': 'top',
            'bg_color': '#f8fafc',
            'border': 1,
            'border_color': '#cbd5e1',
        })
        
        ws.merge_range(row, 0, row + 3, 1, summary_text, summary_format)
        ws.set_row(row, 60)
        row += 4
        
        # Freeze panes at row 3
        ws.freeze_panes(3, 0)
    
    def _build_vulnerabilities_sheet(self, scan_data: Dict[str, Any]):
        """Build detailed vulnerabilities worksheet."""
        ws: Worksheet = self.workbook.add_worksheet('Vulnerabilities')
        
        # Set column widths - optimized for readability
        ws.set_column('A:A', 20)  # CVE ID
        ws.set_column('B:B', 50)  # Title (wider)
        ws.set_column('C:C', 12)  # Severity
        ws.set_column('D:D', 10)  # CVSS
        ws.set_column('E:E', 25)  # Host
        ws.set_column('F:F', 70)  # Description (much wider)
        ws.set_column('G:G', 20)  # Discovered
        ws.set_column('H:H', 20)  # Port/Service
        ws.set_column('I:I', 55)  # Solution (wider)
        
        # Headers
        headers = ['CVE ID', 'Title', 'Severity', 'CVSS', 'Host', 
                  'Description', 'Discovered', 'Port/Service', 'Solution']
        
        for col, header in enumerate(headers):
            ws.write(0, col, header, self.formats['header'])
        
        # Data rows - use 'findings' or 'vulnerabilities'
        findings = scan_data.get('findings', scan_data.get('vulnerabilities', []))
        
        # Deduplicate findings by title + host to avoid repeated entries
        seen = set()
        unique_findings = []
        for finding in findings:
            title = finding.get('title', '')
            host = finding.get('host', '')
            key = f"{title}|{host}"
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
        
        # Set header row height
        ws.set_row(0, 25)
        
        for row_idx, finding in enumerate(unique_findings, start=1):
            # Set row height for better text wrapping display
            ws.set_row(row_idx, 75)  # Taller rows for better readability
            
            # Determine cell format for alternating rows
            cell_fmt = self.formats['cell'] if row_idx % 2 == 1 else self.formats['cell_alt']
            
            # CVE ID with hyperlink - improved handling for OpenVAS
            cve_id = finding.get('cve_id')
            
            # If no CVE ID, try to extract from metadata or generate identifier
            if not cve_id or cve_id == 'N/A' or cve_id == '' or cve_id is None:
                metadata = finding.get('metadata', {})
                
                # Try to parse metadata if it's a string (JSON)
                if isinstance(metadata, str):
                    try:
                        import json
                        metadata = json.loads(metadata)
                    except:
                        metadata = {}
                
                # Look for OID in metadata
                if isinstance(metadata, dict):
                    oid = metadata.get('oid') or metadata.get('id') or metadata.get('nvt_oid')
                    if oid:
                        # Clean OID format
                        oid_clean = str(oid).replace('.', '')[:10]
                        cve_id = f"OID-{oid_clean}"
                    else:
                        # Use title-based unique ID
                        title = finding.get('title', 'Unknown')
                        cve_id = f"VULN-{abs(hash(title)) % 100000:05d}"
                else:
                    cve_id = f"VULN-{row_idx:05d}"
            
            # Write CVE ID with hyperlink if it's a real CVE
            if cve_id and str(cve_id).startswith('CVE'):
                url = f'https://nvd.nist.gov/vuln/detail/{cve_id}'
                url_fmt = self.workbook.add_format({
                    'font_color': '#2563eb',
                    'underline': True,
                    'border': 1,
                    'border_color': '#e5e7eb',
                    'bg_color': '#ffffff' if row_idx % 2 == 1 else '#f8fafc',
                    'text_wrap': True,
                    'valign': 'top',
                })
                ws.write_url(row_idx, 0, url, url_fmt, cve_id)
            else:
                ws.write(row_idx, 0, str(cve_id), cell_fmt)
            
            # Title
            title = finding.get('title', 'N/A') or 'Untitled Vulnerability'
            ws.write(row_idx, 1, title, cell_fmt)
            
            # Severity (with conditional formatting - case insensitive)
            severity = (finding.get('severity', 'INFO') or 'INFO').upper()
            severity_format = self.formats.get(severity.lower(), self.formats['cell'])
            ws.write(row_idx, 2, severity, severity_format)
            
            # CVSS Score - improved handling
            cvss = finding.get('cvss_score')
            cvss_val = 0.0
            
            # Try to convert to float or estimate from severity
            if cvss is not None and cvss != 'N/A' and cvss != '':
                try:
                    cvss_val = float(cvss)
                except (ValueError, TypeError):
                    cvss_val = 0.0
            
            # If CVSS is 0, estimate from severity
            if cvss_val == 0.0:
                severity_cvss_map = {
                    'CRITICAL': 9.5,
                    'HIGH': 7.5,
                    'MEDIUM': 5.0,
                    'LOW': 2.5,
                    'INFO': 0.0,
                    'INFORMATIONAL': 0.0
                }
                cvss_val = severity_cvss_map.get(severity, 0.0)
            
            # Color code CVSS score based on value
            if cvss_val >= 9.0:
                cvss_fmt = self.workbook.add_format({
                    'num_format': '#,##0.0', 'align': 'center', 'valign': 'vcenter',
                    'border': 1, 'bold': True, 'font_color': '#dc2626',
                    'bg_color': '#ffffff' if row_idx % 2 == 1 else '#f8fafc',
                })
            elif cvss_val >= 7.0:
                cvss_fmt = self.workbook.add_format({
                    'num_format': '#,##0.0', 'align': 'center', 'valign': 'vcenter',
                    'border': 1, 'bold': True, 'font_color': '#ea580c',
                    'bg_color': '#ffffff' if row_idx % 2 == 1 else '#f8fafc',
                })
            elif cvss_val >= 4.0:
                cvss_fmt = self.workbook.add_format({
                    'num_format': '#,##0.0', 'align': 'center', 'valign': 'vcenter',
                    'border': 1, 'font_color': '#f59e0b',
                    'bg_color': '#ffffff' if row_idx % 2 == 1 else '#f8fafc',
                })
            else:
                cvss_fmt = self.workbook.add_format({
                    'num_format': '#,##0.0', 'align': 'center', 'valign': 'vcenter',
                    'border': 1, 'font_color': '#16a34a',
                    'bg_color': '#ffffff' if row_idx % 2 == 1 else '#f8fafc',
                })
            
            ws.write(row_idx, 3, cvss_val, cvss_fmt)
            
            # Host
            host = finding.get('host', 'N/A') or 'N/A'
            ws.write(row_idx, 4, host, cell_fmt)
            
            # Description - clean and truncate if too long
            description = finding.get('description') or 'No description available'
            # Remove excessive line breaks and clean up text
            description = ' '.join(description.split())
            # Truncate very long descriptions for better readability
            if len(description) > 1000:
                description = description[:997] + '...'
            ws.write(row_idx, 5, description, cell_fmt)
            
            # Discovered/Published Date
            discovered = finding.get('discovered_at', finding.get('published_date', 'N/A'))
            if discovered and discovered != 'N/A':
                # Format datetime if it's a datetime object
                if hasattr(discovered, 'strftime'):
                    discovered = discovered.strftime('%Y-%m-%d %H:%M')
                ws.write(row_idx, 6, str(discovered), cell_fmt)
            else:
                ws.write(row_idx, 6, 'N/A', cell_fmt)
            
            # Port/Service (combined for better readability)
            port = finding.get('port')
            service = finding.get('service')
            protocol = finding.get('protocol')
            
            port_service_text = ''
            if port is not None and port != '':
                port_service_text = str(port)
                if protocol:
                    port_service_text += f"/{protocol}"
                if service:
                    port_service_text += f" ({service})"
            elif service:
                port_service_text = str(service) if service else 'N/A'
            else:
                port_service_text = 'N/A'
            
            ws.write(row_idx, 7, port_service_text, cell_fmt)
            
            # Solution - clean and format
            solution = finding.get('solution') or 'No solution provided'
            # Clean up solution text
            solution = ' '.join(solution.split())
            # Truncate very long solutions
            if len(solution) > 800:
                solution = solution[:797] + '...'
            ws.write(row_idx, 8, solution, cell_fmt)
        
        # Freeze panes
        ws.freeze_panes(1, 0)
        
        # Auto-filter - use unique findings count
        if unique_findings:
            ws.autofilter(0, 0, len(unique_findings), len(headers) - 1)
    
    def _build_mitigations_sheet(self, scan_data: Dict[str, Any]):
        """Build mitigation recommendations worksheet."""
        ws: Worksheet = self.workbook.add_worksheet('Mitigations')
        
        # Set column widths
        ws.set_column('A:A', 10)  # Priority
        ws.set_column('B:B', 15)  # Type
        ws.set_column('C:C', 30)  # Title
        ws.set_column('D:D', 50)  # Description
        ws.set_column('E:E', 30)  # Impact
        ws.set_column('F:F', 10)  # Effort
        ws.set_column('G:G', 15)  # Affected Paths
        
        # Headers
        headers = ['Priority', 'Type', 'Title', 'Description', 
                  'Impact', 'Effort', 'Affected Paths']
        
        for col, header in enumerate(headers):
            ws.write(0, col, header, self.formats['header'])
        
        # Data rows
        mitigations = scan_data.get('mitigations', [])
        
        for row_idx, mitigation in enumerate(mitigations, start=1):
            # Priority (with conditional formatting)
            priority = mitigation.get('priority', 'medium').upper()
            if priority == 'CRITICAL':
                priority_format = self.formats['critical']
            elif priority == 'HIGH':
                priority_format = self.formats['high']
            elif priority == 'MEDIUM':
                priority_format = self.formats['medium']
            else:
                priority_format = self.formats['low']
            
            ws.write(row_idx, 0, priority.capitalize(), priority_format)
            
            # Type
            ws.write(row_idx, 1, mitigation.get('type', 'N/A'), self.formats['cell'])
            
            # Title
            ws.write(row_idx, 2, mitigation.get('title', 'N/A'), self.formats['cell'])
            
            # Description
            ws.write(row_idx, 3, mitigation.get('description', 'N/A'), self.formats['cell'])
            
            # Impact
            ws.write(row_idx, 4, mitigation.get('impact', 'N/A'), self.formats['cell'])
            
            # Effort
            ws.write(row_idx, 5, mitigation.get('effort', 'medium').capitalize(), 
                    self.formats['cell'])
            
            # Affected Paths Count
            affected = len(mitigation.get('affected_paths', []))
            ws.write(row_idx, 6, affected, self.formats['cell'])
        
        # Freeze panes
        ws.freeze_panes(1, 0)
        
        # Auto-filter
        if mitigations:
            ws.autofilter(0, 0, len(mitigations), len(headers) - 1)
    
    def _build_charts_sheet(self, scan_data: Dict[str, Any]):
        """Build charts worksheet with visual analytics."""
        ws: Worksheet = self.workbook.add_worksheet('Charts')
        
        stats = scan_data.get('statistics', {})
        
        # Title
        title_format = self.workbook.add_format({
            'bold': True,
            'font_size': 16,
            'font_color': '#1e40af',
        })
        ws.write('A1', 'Vulnerability Analysis Charts', title_format)
        
        # Severity Distribution Pie Chart
        pie_chart = self.workbook.add_chart({'type': 'pie'})
        
        # Data for pie chart - write to cells A3:B8
        ws.write('A3', 'Severity', self.formats['header'])
        ws.write('B3', 'Count', self.formats['header'])
        
        ws.write('A4', 'Critical', self.formats['cell'])
        ws.write('B4', stats.get('critical', 0), self.formats['cell'])
        
        ws.write('A5', 'High', self.formats['cell'])
        ws.write('B5', stats.get('high', 0), self.formats['cell'])
        
        ws.write('A6', 'Medium', self.formats['cell'])
        ws.write('B6', stats.get('medium', 0), self.formats['cell'])
        
        ws.write('A7', 'Low', self.formats['cell'])
        ws.write('B7', stats.get('low', 0), self.formats['cell'])
        
        ws.write('A8', 'Info', self.formats['cell'])
        ws.write('B8', stats.get('info', 0), self.formats['cell'])
        
        # Configure pie chart with correct references
        pie_chart.add_series({
            'name': 'Severity Distribution',
            'categories': '=Charts!$A$4:$A$8',
            'values': '=Charts!$B$4:$B$8',
            'points': [
                {'fill': {'color': '#dc2626'}},  # Critical - Red
                {'fill': {'color': '#ea580c'}},  # High - Orange
                {'fill': {'color': '#f59e0b'}},  # Medium - Amber
                {'fill': {'color': '#84cc16'}},  # Low - Lime
                {'fill': {'color': '#3b82f6'}},  # Info - Blue
            ],
        })
        
        pie_chart.set_title({'name': 'Vulnerability Severity Distribution'})
        pie_chart.set_style(10)
        pie_chart.set_legend({'position': 'right'})
        
        # Insert pie chart at row 3
        ws.insert_chart('D3', pie_chart, {'x_scale': 1.5, 'y_scale': 1.5})
        
        # CVSS Score Histogram (Bar Chart)
        bar_chart = self.workbook.add_chart({'type': 'column'})
        
        # Group findings by CVSS ranges
        cvss_ranges = {
            '0.0-2.9': 0,
            '3.0-4.9': 0,
            '5.0-6.9': 0,
            '7.0-8.9': 0,
            '9.0-10.0': 0,
        }
        
        for finding in scan_data.get('findings', []):
            score = finding.get('cvss_score')
            # Handle None/null scores by treating as 0.0
            if score is None:
                score = 0.0
            else:
                try:
                    score = float(score)
                except (ValueError, TypeError):
                    score = 0.0
            
            if score < 3.0:
                cvss_ranges['0.0-2.9'] += 1
            elif score < 5.0:
                cvss_ranges['3.0-4.9'] += 1
            elif score < 7.0:
                cvss_ranges['5.0-6.9'] += 1
            elif score < 9.0:
                cvss_ranges['7.0-8.9'] += 1
            else:
                cvss_ranges['9.0-10.0'] += 1
        
        # Write CVSS data to cells A26:B31 (moved down to avoid overlap)
        ws.write('A26', 'CVSS Range', self.formats['header'])
        ws.write('B26', 'Count', self.formats['header'])
        
        row = 27
        for cvss_range, count in cvss_ranges.items():
            ws.write(f'A{row}', cvss_range, self.formats['cell'])
            ws.write(f'B{row}', count, self.formats['cell'])
            row += 1
        
        # Configure bar chart with correct references
        bar_chart.add_series({
            'name': 'CVSS Score Distribution',
            'categories': '=Charts!$A$27:$A$31',
            'values': '=Charts!$B$27:$B$31',
            'fill': {'color': '#3b82f6'},
        })
        
        bar_chart.set_title({'name': 'CVSS Score Distribution'})
        bar_chart.set_x_axis({'name': 'CVSS Range'})
        bar_chart.set_y_axis({'name': 'Number of Vulnerabilities'})
        bar_chart.set_style(11)
        bar_chart.set_legend({'position': 'none'})
        
        # Insert bar chart at row 26 (moved down from row 20)
        ws.insert_chart('D26', bar_chart, {'x_scale': 1.5, 'y_scale': 1.5})


def generate_excel_report(
    scan_data: Dict[str, Any],
    output_path: str,
    organization: str = "NTRO",
    classification: str = "CONFIDENTIAL"
) -> str:
    """
    Convenience function to generate Excel report.
    
    Args:
        scan_data: Scan results dictionary
        output_path: Output file path
        organization: Organization name
        classification: Security classification
    
    Returns:
        str: Path to generated Excel file
    """
    generator = ExcelReportGenerator(output_path)
    return generator.generate_full_report(scan_data, organization, classification)
