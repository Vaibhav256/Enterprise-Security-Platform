"""
Scan File Processing
Parses vulnerability scan outputs from various tools and extracts findings
Supports: Nessus, OpenVAS, Qualys, and generic JSON formats

Updated: Now integrates with AI summary generator for AI-powered analysis
"""

import json
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ScanFormatType(Enum):
    """Supported scan file formats"""
    NESSUS = "nessus"
    OPENVAS = "openvas"
    QUALYS = "qualys"
    GENERIC_JSON = "generic_json"
    UNKNOWN = "unknown"


@dataclass
class Vulnerability:
    """Represents a single vulnerability finding"""
    
    id: str  # Unique identifier
    cve_id: Optional[str] = None  # CVE-XXXX-XXXXX format
    cwe_id: Optional[str] = None  # CWE-XXX format
    title: str = ""
    description: str = ""
    severity: str = "medium"  # critical, high, medium, low, info
    cvss_score: float = 0.0
    plugin_id: Optional[str] = None  # For Nessus
    host: str = ""
    port: Optional[int] = None
    protocol: str = "tcp"
    service: str = ""
    remediation: str = ""
    references: List[str] = None
    first_seen: str = ""
    last_seen: str = ""
    affected_assets: int = 1
    
    def __post_init__(self):
        if self.references is None:
            self.references = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'cve_id': self.cve_id,
            'cwe_id': self.cwe_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'host': self.host,
            'port': self.port,
            'service': self.service,
            'remediation': self.remediation,
            'references': self.references,
            'affected_assets': self.affected_assets
        }


@dataclass
class ScanReport:
    """Represents a complete scan report"""
    
    scan_name: str
    scan_type: str  # vulnerability, configuration, compliance, etc.
    source_tool: str  # nessus, openvas, qualys, etc.
    scan_date: str
    total_findings: int
    findings_by_severity: Dict[str, int]
    vulnerabilities: List[Vulnerability]
    scan_notes: str = ""
    ai_summary: Optional[Dict[str, Any]] = None  # AI-generated summary
    ai_summary_text: str = ""  # Plain text AI summary
    
    def summary(self) -> Dict[str, Any]:
        """Get summary of scan"""
        return {
            'scan_name': self.scan_name,
            'source_tool': self.source_tool,
            'scan_date': self.scan_date,
            'total_findings': self.total_findings,
            'findings_by_severity': self.findings_by_severity,
            'unique_cves': len(set(v.cve_id for v in self.vulnerabilities if v.cve_id)),
            'has_ai_summary': self.ai_summary is not None
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert scan report to dictionary"""
        return {
            'scan_name': self.scan_name,
            'scan_type': self.scan_type,
            'source_tool': self.source_tool,
            'scan_date': self.scan_date,
            'total_findings': self.total_findings,
            'findings_by_severity': self.findings_by_severity,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'scan_notes': self.scan_notes,
            'ai_summary': self.ai_summary,
            'ai_summary_text': self.ai_summary_text
        }


class ScanParser:
    """
    Parse vulnerability scan files from various tools
    """
    
    @staticmethod
    def detect_format(data: Any) -> ScanFormatType:
        """
        Detect the scan file format
        
        Args:
            data: Parsed JSON/dict or raw content
        
        Returns:
            ScanFormatType enum indicating detected format
        """
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except:
                return ScanFormatType.UNKNOWN
        
        if not isinstance(data, dict):
            return ScanFormatType.UNKNOWN
        
        # Nessus format indicators
        if 'reply' in data and 'contents' in data.get('reply', {}):
            return ScanFormatType.NESSUS
        
        if 'nessus' in data:
            return ScanFormatType.NESSUS
        
        # OpenVAS format indicators
        if 'report' in data and 'results' in data.get('report', {}):
            return ScanFormatType.OPENVAS
        
        if 'openvas' in data or 'gmp' in data:
            return ScanFormatType.OPENVAS
        
        # Qualys format indicators
        if 'SCAN' in data or 'ServiceResponse' in data:
            return ScanFormatType.QUALYS
        
        # Generic format - look for vulnerabilities/findings
        if 'vulnerabilities' in data or 'findings' in data or 'results' in data:
            return ScanFormatType.GENERIC_JSON
        
        return ScanFormatType.UNKNOWN
    
    @staticmethod
    def parse_nessus(data: Dict[str, Any]) -> Optional[ScanReport]:
        """
        Parse Nessus scan export (JSON format)
        
        Nessus exports have structure:
        {
            "reply": {
                "contents": {
                    "scanners": [...],
                    "vulnerabilities": [...]
                }
            }
        }
        """
        try:
            logger.info("Parsing Nessus format scan...")
            
            # Extract scan info
            contents = data.get('reply', {}).get('contents', {})
            
            # Try alternate Nessus format
            if not contents and 'nessus' in data:
                contents = data['nessus']
            
            scan_name = contents.get('policy', {}).get('policyName', 'Nessus Scan')
            scan_date = contents.get('policy', {}).get('policyComments', '').split('Scan date:')[-1].strip() if 'policyComments' in contents.get('policy', {}) else ''
            
            vulnerabilities = []
            findings_by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            
            # Parse vulnerabilities
            for vuln in contents.get('vulnerabilities', []):
                try:
                    severity_map = {
                        '0': 'info',
                        '1': 'low',
                        '2': 'medium',
                        '3': 'high',
                        '4': 'critical'
                    }
                    
                    severity = severity_map.get(str(vuln.get('severity', 1)), 'medium')
                    findings_by_severity[severity] += 1
                    
                    # Extract CVE from plugin output
                    cve_id = None
                    plugin_output = vuln.get('plugin_output', '')
                    cve_match = re.search(r'CVE-\d{4}-\d{4,}', plugin_output)
                    if cve_match:
                        cve_id = cve_match.group()
                    
                    vuln_obj = Vulnerability(
                        id=f"nessus_{vuln.get('plugin_id', 'unknown')}",
                        cve_id=cve_id,
                        title=vuln.get('plugin_name', 'Unknown Vulnerability'),
                        description=vuln.get('plugin_output', '')[:500],
                        severity=severity,
                        cvss_score=float(vuln.get('cvss_score', 0) or 0),
                        plugin_id=str(vuln.get('plugin_id', '')),
                        host=vuln.get('host', ''),
                        port=vuln.get('port'),
                        protocol=vuln.get('protocol', 'tcp'),
                        service=vuln.get('service_name', ''),
                        references=[p.get('url', '') for p in vuln.get('see_also', []) if 'url' in p]
                    )
                    vulnerabilities.append(vuln_obj)
                
                except Exception as e:
                    logger.warning(f"Error parsing Nessus vulnerability: {e}")
                    continue
            
            report = ScanReport(
                scan_name=scan_name,
                scan_type='vulnerability',
                source_tool='nessus',
                scan_date=scan_date,
                total_findings=len(vulnerabilities),
                findings_by_severity=findings_by_severity,
                vulnerabilities=vulnerabilities
            )
            
            logger.info(f"Successfully parsed Nessus scan: {len(vulnerabilities)} findings")
            return report
        
        except Exception as e:
            logger.error(f"Error parsing Nessus format: {e}")
            return None
    
    @staticmethod
    def parse_openvas(data: Dict[str, Any]) -> Optional[ScanReport]:
        """
        Parse OpenVAS scan export
        
        OpenVAS exports have structure with report containing tasks/results
        """
        try:
            logger.info("Parsing OpenVAS format scan...")
            
            report_data = data.get('report', data.get('openvas', {}))
            
            vulnerabilities = []
            findings_by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            
            # Parse results
            for result in report_data.get('results', []):
                try:
                    # OpenVAS severity is 0-10
                    raw_severity = float(result.get('severity', 5))
                    if raw_severity >= 9:
                        severity = 'critical'
                    elif raw_severity >= 7:
                        severity = 'high'
                    elif raw_severity >= 5:
                        severity = 'medium'
                    elif raw_severity >= 2:
                        severity = 'low'
                    else:
                        severity = 'info'
                    
                    findings_by_severity[severity] += 1
                    
                    # Extract CVE
                    cve_id = None
                    nvt = result.get('nvt', {})
                    refs = nvt.get('refs', {}).get('ref', [])
                    if isinstance(refs, dict):
                        refs = [refs]
                    
                    for ref in refs:
                        if isinstance(ref, dict) and ref.get('id', '').startswith('CVE-'):
                            cve_id = ref['id']
                            break
                    
                    vuln_obj = Vulnerability(
                        id=f"openvas_{result.get('id', 'unknown')}",
                        cve_id=cve_id,
                        title=result.get('name', 'Unknown Vulnerability'),
                        description=result.get('comment', '')[:500],
                        severity=severity,
                        cvss_score=raw_severity,
                        host=result.get('host', {}).get('ip', ''),
                        port=result.get('port'),
                        protocol='tcp',
                        service=result.get('service', '')
                    )
                    vulnerabilities.append(vuln_obj)
                
                except Exception as e:
                    logger.warning(f"Error parsing OpenVAS result: {e}")
                    continue
            
            report = ScanReport(
                scan_name=report_data.get('name', 'OpenVAS Scan'),
                scan_type='vulnerability',
                source_tool='openvas',
                scan_date=report_data.get('created', ''),
                total_findings=len(vulnerabilities),
                findings_by_severity=findings_by_severity,
                vulnerabilities=vulnerabilities
            )
            
            logger.info(f"Successfully parsed OpenVAS scan: {len(vulnerabilities)} findings")
            return report
        
        except Exception as e:
            logger.error(f"Error parsing OpenVAS format: {e}")
            return None
    
    @staticmethod
    def parse_qualys(data: Dict[str, Any]) -> Optional[ScanReport]:
        """
        Parse Qualys scan export
        
        Qualys exports have ServiceResponse structure
        """
        try:
            logger.info("Parsing Qualys format scan...")
            
            # Navigate Qualys structure
            response = data.get('ServiceResponse', data.get('SCAN', {}))
            
            vulnerabilities = []
            findings_by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            
            # Parse scan results
            scan_ref = response.get('data', {})
            for host in scan_ref.get('Host', []):
                if isinstance(host, dict):
                    hosts = [host]
                else:
                    hosts = [host]
                
                for h in hosts:
                    host_ip = h.get('ip', '')
                    
                    for vuln in h.get('Vulnerabilities', {}).get('Vulnerability', []):
                        if not isinstance(vuln, dict):
                            continue
                        
                        try:
                            # Qualys severity: 1-5
                            severity_val = int(vuln.get('Severity', 2))
                            severity_map = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical', 5: 'critical'}
                            severity = severity_map.get(severity_val, 'medium')
                            findings_by_severity[severity] += 1
                            
                            # Extract CVE
                            cve_id = None
                            cves = vuln.get('CveIds', {}).get('CveId', [])
                            if isinstance(cves, dict):
                                cves = [cves]
                            if cves and isinstance(cves[0], dict):
                                cve_id = cves[0].get('id')
                            elif cves:
                                cve_id = str(cves[0])
                            
                            vuln_obj = Vulnerability(
                                id=f"qualys_{vuln.get('QualysIds', {}).get('QualysId', 'unknown')}",
                                cve_id=cve_id,
                                title=vuln.get('Title', 'Unknown Vulnerability'),
                                description=vuln.get('Description', '')[:500],
                                severity=severity,
                                cvss_score=float(vuln.get('CvssScore', 0) or 0),
                                host=host_ip
                            )
                            vulnerabilities.append(vuln_obj)
                        
                        except Exception as e:
                            logger.warning(f"Error parsing Qualys vulnerability: {e}")
                            continue
            
            report = ScanReport(
                scan_name=response.get('name', 'Qualys Scan'),
                scan_type='vulnerability',
                source_tool='qualys',
                scan_date=response.get('date', ''),
                total_findings=len(vulnerabilities),
                findings_by_severity=findings_by_severity,
                vulnerabilities=vulnerabilities
            )
            
            logger.info(f"Successfully parsed Qualys scan: {len(vulnerabilities)} findings")
            return report
        
        except Exception as e:
            logger.error(f"Error parsing Qualys format: {e}")
            return None
    
    @staticmethod
    def parse_generic_json(data: Dict[str, Any]) -> Optional[ScanReport]:
        """
        Parse generic JSON format with vulnerabilities/findings
        
        Expected structure:
        {
            "scan_name": "string",
            "vulnerabilities": [
                {
                    "cve_id": "CVE-XXXX-XXXXX",
                    "title": "string",
                    "severity": "high|medium|low",
                    "description": "string",
                    ...
                }
            ]
        }
        """
        try:
            logger.info("Parsing generic JSON format scan...")
            
            vulnerabilities = []
            findings_by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            
            # Get vulnerabilities from various possible keys
            vuln_list = data.get('vulnerabilities', data.get('findings', data.get('results', [])))
            
            for vuln_data in vuln_list:
                try:
                    if not isinstance(vuln_data, dict):
                        continue
                    
                    severity = vuln_data.get('severity', 'medium').lower()
                    if severity not in findings_by_severity:
                        severity = 'medium'
                    
                    findings_by_severity[severity] += 1
                    
                    vuln_obj = Vulnerability(
                        id=vuln_data.get('id', f"generic_{len(vulnerabilities)}"),
                        cve_id=vuln_data.get('cve_id') or vuln_data.get('cve'),
                        cwe_id=vuln_data.get('cwe_id') or vuln_data.get('cwe'),
                        title=vuln_data.get('title', 'Unknown Vulnerability'),
                        description=vuln_data.get('description', '')[:500],
                        severity=severity,
                        cvss_score=float(vuln_data.get('cvss_score', 0) or 0),
                        host=vuln_data.get('host', ''),
                        port=vuln_data.get('port'),
                        service=vuln_data.get('service', ''),
                        remediation=vuln_data.get('remediation', ''),
                        references=vuln_data.get('references', [])
                    )
                    vulnerabilities.append(vuln_obj)
                
                except Exception as e:
                    logger.warning(f"Error parsing generic vulnerability: {e}")
                    continue
            
            report = ScanReport(
                scan_name=data.get('scan_name', 'Generic Scan'),
                scan_type=data.get('scan_type', 'vulnerability'),
                source_tool=data.get('source_tool', 'unknown'),
                scan_date=data.get('scan_date', ''),
                total_findings=len(vulnerabilities),
                findings_by_severity=findings_by_severity,
                vulnerabilities=vulnerabilities,
                scan_notes=data.get('notes', '')
            )
            
            logger.info(f"Successfully parsed generic JSON scan: {len(vulnerabilities)} findings")
            return report
        
        except Exception as e:
            logger.error(f"Error parsing generic JSON format: {e}")
            return None
    
    @staticmethod
    def parse_scan(data: Any) -> Optional[ScanReport]:
        """
        Auto-detect format and parse scan data
        
        Args:
            data: Scan data (JSON string or dict)
        
        Returns:
            ScanReport object or None if parsing failed
        """
        try:
            # Parse if string
            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except:
                    logger.error("Failed to parse input as JSON")
                    return None
            
            # Detect format
            format_type = ScanParser.detect_format(data)
            logger.info(f"Detected format: {format_type.value}")
            
            # Route to appropriate parser
            if format_type == ScanFormatType.NESSUS:
                return ScanParser.parse_nessus(data)
            elif format_type == ScanFormatType.OPENVAS:
                return ScanParser.parse_openvas(data)
            elif format_type == ScanFormatType.QUALYS:
                return ScanParser.parse_qualys(data)
            elif format_type == ScanFormatType.GENERIC_JSON:
                return ScanParser.parse_generic_json(data)
            else:
                logger.error(f"Unknown scan format: {format_type}")
                return None
        
        except Exception as e:
            logger.error(f"Unexpected error parsing scan: {e}")
            return None


class ScanEnricher:
    """
    Enrich parsed vulnerabilities with real-time data
    """
    
    def __init__(self, real_time_manager=None):
        """
        Initialize enricher
        
        Args:
            real_time_manager: RealTimeSourceManager instance
        """
        self.real_time_manager = real_time_manager
    
    def enrich_vulnerability(self, vuln: Vulnerability) -> Vulnerability:
        """
        Enrich a single vulnerability with real-time data
        
        Args:
            vuln: Vulnerability object to enrich
        
        Returns:
            Enhanced Vulnerability object
        """
        try:
            # If we have real-time manager, fetch CVE details
            if self.real_time_manager and vuln.cve_id:
                logger.info(f"Enriching {vuln.cve_id} with NVD data...")
                
                cve_details = self.real_time_manager.nvd.get_cve_details(vuln.cve_id)
                
                if cve_details:
                    # Update vuln with real-time data
                    vuln.cvss_score = max(vuln.cvss_score, cve_details.get('cvss_score', 0))
                    if not vuln.description or len(vuln.description) < 50:
                        vuln.description = cve_details.get('description', vuln.description)
                    vuln.references.extend(cve_details.get('references', []))
                    vuln.references = list(set(vuln.references))  # Remove duplicates
                    
                    # Update severity if NVD has higher
                    severity_order = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
                    if cve_details.get('severity', '').lower() in severity_order:
                        if severity_order.get(cve_details['severity'].lower(), 0) > severity_order.get(vuln.severity, 0):
                            vuln.severity = cve_details['severity'].lower()
            
            return vuln
        
        except Exception as e:
            logger.warning(f"Error enriching vulnerability: {e}")
            return vuln
    
    def enrich_report(self, report: ScanReport) -> ScanReport:
        """
        Enrich all vulnerabilities in a report
        
        Args:
            report: ScanReport to enrich
        
        Returns:
            Enhanced ScanReport
        """
        try:
            logger.info(f"Enriching scan report with {len(report.vulnerabilities)} vulnerabilities...")
            
            for vuln in report.vulnerabilities:
                self.enrich_vulnerability(vuln)
            
            logger.info("Scan enrichment complete")
            return report
        
        except Exception as e:
            logger.error(f"Error enriching report: {e}")
            return report


class ScanAnalyzer:
    """
    Analyze scan reports and generate insights
    """
    
    @staticmethod
    def prioritize_vulnerabilities(
        vulnerabilities: List[Vulnerability],
        by_severity: bool = True,
        by_cve_count: bool = False
    ) -> List[Vulnerability]:
        """
        Prioritize vulnerabilities for remediation
        
        Args:
            vulnerabilities: List of vulnerabilities
            by_severity: Sort by severity
            by_cve_count: Sort by affected asset count
        
        Returns:
            Sorted list of vulnerabilities
        """
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        
        if by_severity:
            return sorted(
                vulnerabilities,
                key=lambda v: (severity_order.get(v.severity, 5), -v.cvss_score)
            )
        
        if by_cve_count:
            return sorted(
                vulnerabilities,
                key=lambda v: (-v.affected_assets, severity_order.get(v.severity, 5))
            )
        
        return vulnerabilities
    
    @staticmethod
    def generate_remediation_plan(report: ScanReport) -> Dict[str, Any]:
        """
        Generate a remediation plan from scan report
        
        Args:
            report: ScanReport to analyze
        
        Returns:
            Remediation plan with priorities
        """
        plan = {
            'scan_name': report.scan_name,
            'total_vulns': report.total_findings,
            'severity_breakdown': report.findings_by_severity,
            'critical_actions': [],
            'high_priority_actions': [],
            'medium_priority_actions': []
        }
        
        # Prioritize
        prioritized = ScanAnalyzer.prioritize_vulnerabilities(
            report.vulnerabilities,
            by_severity=True
        )
        
        for vuln in prioritized:
            action = {
                'vulnerability': vuln.title,
                'cve': vuln.cve_id,
                'severity': vuln.severity,
                'affected_systems': [vuln.host] if vuln.host else ['Unknown'],
                'remediation': vuln.remediation or 'See remediation in NVD'
            }
            
            if vuln.severity == 'critical':
                plan['critical_actions'].append(action)
            elif vuln.severity == 'high':
                plan['high_priority_actions'].append(action)
            elif vuln.severity == 'medium':
                plan['medium_priority_actions'].append(action)
        
        return plan


class ScanAISummarizer:
    """
    Generate AI-powered summaries for scan reports.
    Integrates with AISummaryGenerator to create intelligent summaries.
    """
    
    def __init__(self, summary_generator=None):
        """
        Initialize AI summarizer.
        
        Args:
            summary_generator: AISummaryGenerator instance (lazy-loaded if None)
        """
        self.summary_generator = summary_generator
    
    def _get_generator(self):
        """Get or initialize summary generator"""
        if self.summary_generator is None:
            try:
                from intelligence_layer.rag.ai_summary_generator import (
                    get_summary_generator,
                    ScanData
                )
                self.summary_generator = get_summary_generator()
            except ImportError:
                logger.error("AI Summary Generator not available")
                return None
        return self.summary_generator
    
    def generate_ai_summary(self, report: ScanReport) -> Optional[Dict[str, Any]]:
        """
        Generate AI summary for a scan report.
        
        Args:
            report: ScanReport to summarize
        
        Returns:
            AI summary as dictionary (or None if generator unavailable)
        """
        try:
            generator = self._get_generator()
            if not generator:
                logger.warning("AI Summary Generator unavailable, skipping AI summary")
                return None
            
            # Prepare scan data for AI generator
            from intelligence_layer.rag.ai_summary_generator import ScanData
            
            scan_data = ScanData(
                scan_id=f"scan_{report.scan_name}",
                tool_name=report.source_tool,
                scan_type=report.scan_type,
                findings=[v.to_dict() for v in report.vulnerabilities],
                scan_date=report.scan_date,
                metadata={'notes': report.scan_notes}
            )
            
            # Generate executive summary
            ai_summary = generator.generate_scan_summary(
                scan_data,
                summary_type="scan_executive"
            )
            
            logger.info(f"Generated AI summary for scan {report.scan_name}")
            
            # Return as dictionary for storage
            return {
                'type': ai_summary.type,
                'title': ai_summary.title,
                'executive_summary': ai_summary.executive_summary,
                'key_findings': ai_summary.key_findings,
                'risk_score': ai_summary.risk_score,
                'risk_level': ai_summary.risk_level,
                'recommendations': ai_summary.recommendations,
                'related_cves': ai_summary.related_cves,
                'source_tool': ai_summary.source_tool,
                'confidence': ai_summary.confidence
            }
        
        except Exception as e:
            logger.error(f"Error generating AI summary: {e}")
            return None
    
    def generate_ai_finding_summaries(
        self,
        report: ScanReport,
        top_n: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Generate AI summaries for top N findings.
        
        Args:
            report: ScanReport with findings
            top_n: Number of top findings to summarize
        
        Returns:
            List of AI summaries for findings
        """
        try:
            generator = self._get_generator()
            if not generator:
                return []
            
            summaries = []
            
            # Get prioritized findings
            prioritized = ScanAnalyzer.prioritize_vulnerabilities(
                report.vulnerabilities,
                by_severity=True
            )[:top_n]
            
            for finding in prioritized:
                summary = generator.generate_finding_summary(
                    finding.to_dict(),
                    tool_name=report.source_tool
                )
                
                summaries.append({
                    'finding_id': finding.id,
                    'cve_id': finding.cve_id,
                    'title': summary.title,
                    'executive_summary': summary.executive_summary,
                    'key_findings': summary.key_findings,
                    'risk_level': summary.risk_level,
                    'recommendations': summary.recommendations
                })
            
            logger.info(f"Generated AI summaries for {len(summaries)} findings")
            return summaries
        
        except Exception as e:
            logger.error(f"Error generating finding summaries: {e}")
            return []
    
    def generate_risk_assessment(self, report: ScanReport) -> Optional[Dict[str, Any]]:
        """
        Generate AI risk assessment for scan.
        
        Args:
            report: ScanReport to assess
        
        Returns:
            Risk assessment as dictionary
        """
        try:
            generator = self._get_generator()
            if not generator:
                return None
            
            from intelligence_layer.rag.ai_summary_generator import ScanData
            
            scan_data = ScanData(
                scan_id=f"risk_{report.scan_name}",
                tool_name=report.source_tool,
                scan_type=report.scan_type,
                findings=[v.to_dict() for v in report.vulnerabilities],
                scan_date=report.scan_date
            )
            
            risk_summary = generator.generate_risk_assessment(scan_data)
            
            return {
                'type': risk_summary.type,
                'title': risk_summary.title,
                'executive_summary': risk_summary.executive_summary,
                'key_findings': risk_summary.key_findings,
                'risk_score': risk_summary.risk_score,
                'risk_level': risk_summary.risk_level,
                'recommendations': risk_summary.recommendations
            }
        
        except Exception as e:
            logger.error(f"Error generating risk assessment: {e}")
            return None
    
    def enrich_report_with_ai_summary(self, report: ScanReport) -> ScanReport:
        """
        Enrich a scan report with AI-generated summaries.
        
        Args:
            report: ScanReport to enrich
        
        Returns:
            Enhanced ScanReport with ai_summary and ai_summary_text
        """
        try:
            logger.info(f"Enriching report {report.scan_name} with AI summaries...")
            
            # Generate AI summary
            ai_summary = self.generate_ai_summary(report)
            if ai_summary:
                report.ai_summary = ai_summary
            
            # Generate markdown text version
            if report.ai_summary:
                markdown = self._format_summary_as_markdown(report.ai_summary)
                report.ai_summary_text = markdown
            
            logger.info("AI summary enrichment complete")
            return report
        
        except Exception as e:
            logger.error(f"Error enriching report with AI summary: {e}")
            return report
    
    @staticmethod
    def _format_summary_as_markdown(summary: Dict[str, Any]) -> str:
        """Format AI summary as markdown"""
        md = f"""# {summary.get('title', 'Security Summary')}

**Risk Level:** {summary.get('risk_level', 'UNKNOWN')} (Score: {summary.get('risk_score', 0):.2f})

## Executive Summary
{summary.get('executive_summary', 'No summary available')}

## Key Findings
{chr(10).join(f"- {finding}" for finding in summary.get('key_findings', []))}

## Recommendations
{chr(10).join(f"{i+1}. {rec}" for i, rec in enumerate(summary.get('recommendations', [])))}

---
*Generated by AI Summary Engine | Confidence: {summary.get('confidence', 0):.0%}*
"""
        return md
