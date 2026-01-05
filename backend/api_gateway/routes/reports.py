"""
Report Generation API Routes

Endpoints for generating and downloading PDF/Excel reports.
"""

from flask import Blueprint, request, jsonify, send_file
from flask_cors import cross_origin
import os
import uuid
from datetime import datetime
from typing import Dict, Any

from services.reporting.pdf_generator import generate_pdf_report
from services.reporting.excel_generator import generate_excel_report
from config.database import get_db_connection, release_db_connection
from utils.validators import validate_scan_id

# Create blueprint
reports_bp = Blueprint('reports', __name__, url_prefix='/api/reports')


@reports_bp.route('/pdf', methods=['POST'])
@cross_origin()
def generate_pdf():
    """
    Generate PDF report for a scan.
    
    Request JSON:
        {
            "scan_id": "string",
            "include_attack_paths": true,
            "include_charts": true,
            "organization": "NTRO",
            "classification": "CONFIDENTIAL"
        }
    
    Response:
        {
            "report_id": "uuid",
            "scan_id": "string",
            "format": "pdf",
            "status": "completed",
            "download_url": "/api/reports/{report_id}/download",
            "created_at": "iso8601"
        }
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data or 'scan_id' not in data:
            return jsonify({'error': 'scan_id is required'}), 400
        
        scan_id = data['scan_id']
        
        # Validate scan exists
        if not validate_scan_id(scan_id):
            return jsonify({'error': f'Scan {scan_id} not found'}), 404
        
        # Get scan data from database
        scan_data = _get_scan_report_data(scan_id)
        
        # Generate report
        report_id = str(uuid.uuid4())
        
        # Use absolute path from backend directory
        backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        output_dir = os.path.join(backend_dir, 'reports', 'generated')
        os.makedirs(output_dir, exist_ok=True)
        
        output_path = os.path.join(output_dir, f'{report_id}.pdf')
        
        generate_pdf_report(
            scan_data,
            output_path,
            organization=data.get('organization', 'NTRO'),
            classification=data.get('classification', 'CONFIDENTIAL')
        )
        
        # Save report metadata to database
        _save_report_metadata(
            report_id=report_id,
            scan_id=scan_id,
            format='pdf',
            filepath=output_path,
            options=data
        )
        
        return jsonify({
            'report_id': report_id,
            'scan_id': scan_id,
            'format': 'pdf',
            'status': 'completed',
            'download_url': f'/api/reports/{report_id}/download',
            'created_at': datetime.now().isoformat(),
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@reports_bp.route('/excel', methods=['POST'])
@cross_origin()
def generate_excel():
    """
    Generate Excel report for a scan.
    
    Request JSON:
        {
            "scan_id": "string",
            "include_attack_paths": true,
            "include_charts": true,
            "organization": "NTRO",
            "classification": "CONFIDENTIAL"
        }
    
    Response:
        {
            "report_id": "uuid",
            "scan_id": "string",
            "format": "excel",
            "status": "completed",
            "download_url": "/api/reports/{report_id}/download",
            "created_at": "iso8601"
        }
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data or 'scan_id' not in data:
            return jsonify({'error': 'scan_id is required'}), 400
        
        scan_id = data['scan_id']
        
        # Validate scan exists
        if not validate_scan_id(scan_id):
            return jsonify({'error': f'Scan {scan_id} not found'}), 404
        
        # Get scan data from database
        scan_data = _get_scan_report_data(scan_id)
        
        # Generate report
        report_id = str(uuid.uuid4())
        
        # Use absolute path from backend directory
        backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        output_dir = os.path.join(backend_dir, 'reports', 'generated')
        os.makedirs(output_dir, exist_ok=True)
        
        output_path = os.path.join(output_dir, f'{report_id}.xlsx')
        
        generate_excel_report(
            scan_data,
            output_path,
            organization=data.get('organization', 'NTRO'),
            classification=data.get('classification', 'CONFIDENTIAL')
        )
        
        # Save report metadata to database
        _save_report_metadata(
            report_id=report_id,
            scan_id=scan_id,
            format='excel',
            filepath=output_path,
            options=data
        )
        
        return jsonify({
            'report_id': report_id,
            'scan_id': scan_id,
            'format': 'excel',
            'status': 'completed',
            'download_url': f'/api/reports/{report_id}/download',
            'created_at': datetime.now().isoformat(),
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@reports_bp.route('/<report_id>/download', methods=['GET'])
def download_report(report_id: str):
    """
    Download generated report.
    
    Args:
        report_id: Report UUID
    
    Response:
        File download (PDF or Excel)
    """
    try:
        # Get report metadata from database
        report_meta = _get_report_metadata(report_id)
        
        if not report_meta:
            return jsonify({'error': f'Report {report_id} not found'}), 404
        
        filepath = report_meta.get('filepath')
        
        if not filepath or not os.path.exists(filepath):
            return jsonify({'error': 'Report file not found on disk'}), 404
        
        # Determine MIME type and filename
        report_format = report_meta.get('format', 'pdf')
        scan_id = report_meta.get('scan_id', 'unknown')
        
        if report_format == 'pdf':
            mimetype = 'application/pdf'
            filename = f'scan-report-{scan_id}.pdf'
        else:
            mimetype = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            filename = f'scan-report-{scan_id}.xlsx'
        
        # Send file with proper headers
        response = send_file(
            filepath,
            mimetype=mimetype,
            as_attachment=True,
            download_name=filename
        )
        
        # Add CORS headers manually for file downloads
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Expose-Headers'] = 'Content-Disposition'
        
        return response
        
    except Exception as e:
        import traceback
        print(f"Error in download_report: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500


@reports_bp.route('/scan/<scan_id>', methods=['GET'])
@cross_origin()
def get_scan_reports(scan_id: str):
    """
    Get all reports for a scan.
    
    Args:
        scan_id: Scan identifier
    
    Response:
        {
            "reports": [
                {
                    "report_id": "uuid",
                    "format": "pdf",
                    "created_at": "iso8601",
                    "download_url": "string"
                }
            ]
        }
    """
    try:
        reports = _get_reports_by_scan(scan_id)
        
        return jsonify({
            'reports': [
                {
                    'report_id': r['id'],
                    'format': r['format'],
                    'created_at': r['created_at'],
                    'download_url': f'/api/reports/{r["id"]}/download',
                }
                for r in reports
            ]
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@reports_bp.route('/<report_id>', methods=['DELETE'])
@cross_origin()
def delete_report(report_id: str):
    """
    Delete a generated report.
    
    Args:
        report_id: Report UUID
    
    Response:
        {"message": "Report deleted successfully"}
    """
    try:
        # Get report metadata
        report_meta = _get_report_metadata(report_id)
        
        if not report_meta:
            return jsonify({'error': f'Report {report_id} not found'}), 404
        
        # Delete file
        filepath = report_meta['filepath']
        if os.path.exists(filepath):
            os.remove(filepath)
        
        # Delete metadata from database
        _delete_report_metadata(report_id)
        
        return jsonify({'message': 'Report deleted successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# Helper Functions
# ============================================================================

def _get_scan_report_data(scan_id: str) -> Dict[str, Any]:
    """
    Fetch scan data formatted for report generation.
    
    Args:
        scan_id: Scan identifier
    
    Returns:
        dict: Formatted scan data
    """
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get scan metadata from correct table
        cursor.execute("""
            SELECT id, target, tool_name, scan_type, status, created_at, 
                   started_at, completed_at, options
            FROM scans
            WHERE id = %s
        """, (scan_id,))
        
        scan_row = cursor.fetchone()
        
        if not scan_row:
            raise ValueError(f'Scan {scan_id} not found')
        
        # Convert row to dict
        scan = dict(zip([desc[0] for desc in cursor.description], scan_row))
        
        # Get vulnerabilities (correct table name)
        cursor.execute("""
            SELECT 
                cve_id, title, severity, cvss_score, 
                description, port, protocol, service, solution,
                discovered_at, metadata
            FROM vulnerabilities
            WHERE scan_id = %s
            ORDER BY 
                CASE severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    ELSE 5
                END,
                COALESCE(cvss_score, 0.0) DESC
        """, (scan_id,))
        
        findings = [dict(zip([desc[0] for desc in cursor.description], row)) for row in cursor.fetchall()]
        
        # Add host information from scan target
        for finding in findings:
            finding['host'] = scan.get('target', 'N/A')
            finding['published_date'] = finding.get('discovered_at', 'N/A')
            finding['exploit_available'] = False  # Default value
        
        # Get scan summary statistics
        cursor.execute("""
            SELECT 
                total_hosts, total_ports, total_vulnerabilities,
                critical_count, high_count, medium_count, low_count, info_count
            FROM scan_summaries
            WHERE scan_id = %s
        """, (scan_id,))
        
        summary_row = cursor.fetchone()
        
        # Calculate statistics from actual data
        # Use scan_summaries if available AND has data, otherwise calculate from findings
        if summary_row:
            summary_dict = dict(zip([desc[0] for desc in cursor.description], summary_row))
            total_vulns = summary_dict.get('total_vulnerabilities', 0)
            
            # If summary exists but has zero counts, it might be stale - recalculate
            if total_vulns == 0 and len(findings) > 0:
                stats = {
                    'total': len(findings),
                    'critical': sum(1 for f in findings if f.get('severity', '').upper() == 'CRITICAL'),
                    'high': sum(1 for f in findings if f.get('severity', '').upper() == 'HIGH'),
                    'medium': sum(1 for f in findings if f.get('severity', '').upper() == 'MEDIUM'),
                    'low': sum(1 for f in findings if f.get('severity', '').upper() == 'LOW'),
                    'info': sum(1 for f in findings if f.get('severity', '').upper() in ('INFO', 'INFORMATIONAL')),
                    'hosts_scanned': summary_dict.get('total_hosts', 1),
                    'total_ports': summary_dict.get('total_ports', 0),
                    'vulnerable_hosts': 1 if len(findings) > 0 else 0,
                }
            else:
                stats = {
                    'total': summary_dict.get('total_vulnerabilities', len(findings)),
                    'critical': summary_dict.get('critical_count', 0),
                    'high': summary_dict.get('high_count', 0),
                    'medium': summary_dict.get('medium_count', 0),
                    'low': summary_dict.get('low_count', 0),
                    'info': summary_dict.get('info_count', 0),
                    'hosts_scanned': summary_dict.get('total_hosts', 1),
                    'total_ports': summary_dict.get('total_ports', 0),
                    'vulnerable_hosts': 1 if len(findings) > 0 else 0,
                }
        else:
            # Fallback: calculate from findings (case-insensitive)
            stats = {
                'total': len(findings),
                'critical': sum(1 for f in findings if f.get('severity', '').upper() == 'CRITICAL'),
                'high': sum(1 for f in findings if f.get('severity', '').upper() == 'HIGH'),
                'medium': sum(1 for f in findings if f.get('severity', '').upper() == 'MEDIUM'),
                'low': sum(1 for f in findings if f.get('severity', '').upper() == 'LOW'),
                'info': sum(1 for f in findings if f.get('severity', '').upper() in ('INFO', 'INFORMATIONAL')),
                'hosts_scanned': 1,
                'total_ports': 0,
                'vulnerable_hosts': 1 if len(findings) > 0 else 0,
            }
        
        # Generate mitigations from vulnerabilities
        mitigations = _generate_mitigations(findings)
        
        cursor.close()
        
        # Format target information
        target_info = {
            'name': scan.get('target', 'Unknown'),
            'ip_range': scan.get('target', 'N/A'),
        }
        
        return {
            'scan_id': scan_id,
            'timestamp': scan.get('created_at', datetime.now()).isoformat() if scan.get('created_at') else datetime.now().isoformat(),
            'target': target_info,
            'summary': _generate_executive_summary(stats, findings),
            'statistics': stats,
            'findings': findings,
            'vulnerabilities': findings,  # Alias for compatibility
            'mitigations': mitigations,
            'scan_info': {
                'tool': scan.get('tool_name', 'N/A'),
                'scan_type': scan.get('scan_type', 'N/A'),
                'status': scan.get('status', 'N/A'),
                'started_at': scan.get('started_at'),
                'completed_at': scan.get('completed_at'),
            }
        }
    finally:
        if conn:
            release_db_connection(conn)


def _generate_executive_summary(
    stats: Dict[str, Any],
    findings: list
) -> str:
    """Generate executive summary text."""
    critical_count = stats['critical']
    high_count = stats['high']
    
    summary = f"This security assessment identified {stats['total']} vulnerabilities across {stats['hosts_scanned']} hosts. "
    
    if critical_count > 0:
        summary += f"Of particular concern are {critical_count} CRITICAL severity issues requiring immediate attention. "
    
    if high_count > 0:
        summary += f"Additionally, {high_count} HIGH severity vulnerabilities were discovered. "
    
    summary += "Detailed findings and prioritized remediation recommendations are provided in this report."
    
    return summary


def _generate_mitigations(findings: list) -> list:
    """
    Generate prioritized mitigation recommendations from vulnerabilities.
    
    Args:
        findings: List of vulnerability findings
    
    Returns:
        list: Prioritized mitigation recommendations
    """
    # Severity priority mapping
    severity_priority = {
        'CRITICAL': ('critical', 1),
        'HIGH': ('high', 2),
        'MEDIUM': ('medium', 3),
        'LOW': ('low', 4),
        'INFO': ('low', 5),
        'INFORMATIONAL': ('low', 5)
    }
    
    # Effort estimation based on vulnerability type
    def estimate_effort(finding: Dict[str, Any]) -> str:
        """Estimate remediation effort."""
        title = (finding.get('title') or '').lower()
        description = (finding.get('description') or '').lower()
        
        # Configuration issues are typically low effort
        if any(term in title or term in description for term in ['configuration', 'misconfiguration', 'setting', 'header']):
            return 'low'
        
        # Code changes are medium effort
        if any(term in title or term in description for term in ['code', 'injection', 'xss', 'csrf']):
            return 'medium'
        
        # Infrastructure changes are high effort
        if any(term in title or term in description for term in ['upgrade', 'patch', 'update', 'replace']):
            return 'high'
        
        return 'medium'  # Default
    
    mitigations = []
    
    # Group vulnerabilities by type/category
    vuln_groups = {}
    for finding in findings:
        title = finding.get('title', 'Unknown Vulnerability')
        severity = finding.get('severity', 'INFO').upper()
        
        # Create a grouping key (first few words of title)
        group_key = ' '.join(title.split()[:5])
        
        if group_key not in vuln_groups:
            vuln_groups[group_key] = {
                'findings': [],
                'severity': severity,
                'title': title
            }
        
        vuln_groups[group_key]['findings'].append(finding)
        
        # Upgrade severity if higher severity found in group
        current_priority = severity_priority.get(vuln_groups[group_key]['severity'], ('low', 999))[1]
        new_priority = severity_priority.get(severity, ('low', 999))[1]
        if new_priority < current_priority:
            vuln_groups[group_key]['severity'] = severity
    
    # Create mitigations from grouped vulnerabilities
    for group_key, group_data in vuln_groups.items():
        findings_list = group_data['findings']
        severity = group_data['severity']
        priority_name, _ = severity_priority.get(severity, ('low', 999))
        
        # Get solution from first finding (they're grouped so likely similar)
        solution = findings_list[0].get('solution') or 'Apply security patches and updates'
        description = findings_list[0].get('description') or 'Security vulnerability detected'
        
        # Determine affected paths (hosts/ports)
        affected_paths = []
        for f in findings_list:
            host = f.get('host', 'N/A')
            port = f.get('port', '')
            service = f.get('service', '')
            
            path_desc = f"{host}"
            if port:
                path_desc += f":{port}"
            if service:
                path_desc += f" ({service})"
            
            if path_desc not in affected_paths:
                affected_paths.append(path_desc)
        
        # Determine mitigation type
        title_lower = group_data['title'].lower()
        if 'ssl' in title_lower or 'tls' in title_lower or 'certificate' in title_lower:
            mit_type = 'Cryptography'
        elif 'injection' in title_lower or 'xss' in title_lower or 'csrf' in title_lower:
            mit_type = 'Input Validation'
        elif 'authentication' in title_lower or 'authorization' in title_lower:
            mit_type = 'Access Control'
        elif 'configuration' in title_lower or 'misconfiguration' in title_lower:
            mit_type = 'Configuration'
        elif 'update' in title_lower or 'patch' in title_lower or 'version' in title_lower:
            mit_type = 'Patch Management'
        else:
            mit_type = 'Security Hardening'
        
        # Estimate impact
        if severity in ['CRITICAL', 'HIGH']:
            impact = 'Significantly reduces attack surface and prevents potential system compromise'
        elif severity == 'MEDIUM':
            impact = 'Reduces risk of security incidents and improves overall security posture'
        else:
            impact = 'Enhances security posture and reduces information disclosure risks'
        
        # Safely truncate solution (handle None)
        safe_solution = solution if solution else 'Apply security patches and updates'
        truncated_solution = safe_solution[:500] if len(safe_solution) > 500 else safe_solution
        
        mitigation = {
            'priority': priority_name,
            'type': mit_type,
            'title': group_data['title'],
            'description': truncated_solution,
            'impact': impact,
            'effort': estimate_effort(findings_list[0]),
            'affected_paths': affected_paths
        }
        
        mitigations.append(mitigation)
    
    # Sort by priority (critical first)
    mitigations.sort(key=lambda m: severity_priority.get(m['priority'].upper(), ('low', 999))[1])
    
    return mitigations


def _save_report_metadata(
    report_id: str,
    scan_id: str,
    format: str,
    filepath: str,
    options: Dict[str, Any]
):
    """Save report metadata to database."""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO reports (id, scan_id, format, filepath, options, created_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            report_id,
            scan_id,
            format,
            filepath,
            str(options),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        cursor.close()
    finally:
        if conn:
            release_db_connection(conn)


def _get_report_metadata(report_id: str) -> Dict[str, Any]:
    """Retrieve report metadata from database."""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, scan_id, format, filepath, created_at
            FROM reports
            WHERE id = %s
        """, (report_id,))
        
        row = cursor.fetchone()
        
        if row:
            # Get column names before closing cursor
            columns = [desc[0] for desc in cursor.description]
            cursor.close()
            return dict(zip(columns, row))
        
        cursor.close()
        return None
    finally:
        if conn:
            release_db_connection(conn)


def _get_reports_by_scan(scan_id: str) -> list:
    """Get all reports for a scan."""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, format, created_at
            FROM reports
            WHERE scan_id = %s
            ORDER BY created_at DESC
        """, (scan_id,))
        
        reports = [dict(zip([desc[0] for desc in cursor.description], row)) for row in cursor.fetchall()]
        cursor.close()
        
        return reports
    finally:
        if conn:
            release_db_connection(conn)


def _delete_report_metadata(report_id: str):
    """Delete report metadata from database."""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM reports WHERE id = %s", (report_id,))
        
        conn.commit()
        cursor.close()
    finally:
        if conn:
            release_db_connection(conn)
