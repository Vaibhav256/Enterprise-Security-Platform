"""
Parser Utilities

This module provides utilities for parsing outputs from various security scanning tools.
Includes parsers for Nmap XML, OpenVAS XML, and other tool formats.

Author: NTRO Security Team
Date: 2025-10-22
"""

import json
import logging
# Use defusedxml when available to mitigate XML vulnerabilities
try:
    from defusedxml import ElementTree as ET
    try:
        # Harden stdlib XML parsers when defusedxml is installed
        from defusedxml import defuse_stdlib
        defuse_stdlib()
    except Exception:
        pass
except Exception:
    import xml.etree.ElementTree as ET

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class Port:
    """Data class for port information"""

    port: int
    protocol: str
    state: str
    service_name: Optional[str] = None
    service_product: Optional[str] = None
    service_version: Optional[str] = None
    service_extra: Optional[str] = None
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class Host:
    """Data class for host information"""

    ip_address: str
    hostname: Optional[str] = None
    status: str = "unknown"
    os_name: Optional[str] = None
    os_accuracy: Optional[int] = None
    ports: List[Port] = field(default_factory=list)
    vulnerabilities: List["Vulnerability"] = field(default_factory=list)

    def __post_init__(self):
        if self.ports is None:
            self.ports = []
        if self.vulnerabilities is None:
            self.vulnerabilities = []


@dataclass
class Vulnerability:
    """Data class for vulnerability information"""

    vuln_id: str
    name: str
    severity: str
    cvss_score: Optional[float] = None
    description: Optional[str] = None
    affected_component: Optional[str] = None
    solution: Optional[str] = None
    references: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.references is None:
            self.references = []


class NmapParser:
    """Parser for Nmap XML output"""

    @staticmethod
    def parse_xml(xml_content: str) -> Dict[str, Any]:
        """
        Parse Nmap XML output

        Args:
            xml_content: XML content as string

        Returns:
            Dictionary containing parsed scan results
        """
        try:
            root = ET.fromstring(xml_content)

            # Extract scan metadata
            scan_info = NmapParser._parse_scan_info(root)

            # Extract host information
            hosts = []
            for host_elem in root.findall(".//host"):
                host = NmapParser._parse_host(host_elem)
                if host:
                    hosts.append(host)

            # Build summary
            summary = {
                "hosts_scanned": len(hosts),
                "hosts_up": sum(1 for h in hosts if h.status == "up"),
                "total_ports": sum(len(h.ports) for h in hosts),
                "open_ports": sum(
                    1 for h in hosts for p in h.ports if p.state == "open"
                ),
            }

            result = {
                "scan_info": scan_info,
                "summary": summary,
                "hosts": [asdict(h) for h in hosts],
                # ✅ ADD: Required keys for consistency with other adapters
                "vulnerability_count": 0,  # Nmap is a port scanner, not a vulnerability scanner
                "severity_counts": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0
                }
            }

            logger.info(
                "Parsed Nmap output: %d hosts, %d open ports",
                summary["hosts_scanned"],
                summary["open_ports"],
            )

            return result

        except ET.ParseError as e:
            logger.error("Failed to parse Nmap XML: %s", str(e))
            raise ValueError(f"Invalid Nmap XML format: {str(e)}")
        except Exception as e:
            logger.error("Error parsing Nmap output: %s", str(e))
            raise

    @staticmethod
    def _parse_scan_info(root: ET.Element) -> Dict[str, Any]:
        """Extract scan metadata"""
        scan_info = {}

        # Scanner info
        nmaprun = root.attrib
        scan_info["nmap_version"] = nmaprun.get("version", "unknown")
        scan_info["start_time"] = nmaprun.get("start", "unknown")
        scan_info["command"] = nmaprun.get("args", "unknown")

        # Scan type
        scaninfo = root.find(".//scaninfo")
        if scaninfo is not None:
            scan_info["scan_type"] = scaninfo.get("type", "unknown")
            scan_info["protocol"] = scaninfo.get("protocol", "unknown")
            scan_info["services"] = scaninfo.get("services", "unknown")

        return scan_info

    @staticmethod
    def _parse_host(host_elem: ET.Element) -> Optional[Host]:
        """Parse individual host element"""
        # Get status
        status_elem = host_elem.find(".//status")
        if status_elem is None:
            return None

        status = status_elem.get("state", "unknown")

        # Get IP address
        address_elem = host_elem.find('.//address[@addrtype="ipv4"]')
        if address_elem is None:
            address_elem = host_elem.find('.//address[@addrtype="ipv6"]')

        if address_elem is None:
            return None

        ip_address = address_elem.get("addr")

        # Get hostname
        hostname = None
        hostname_elem = host_elem.find(".//hostname")
        if hostname_elem is not None:
            hostname = hostname_elem.get("name")

        # Get OS detection
        os_name = None
        os_accuracy = None
        osmatch = host_elem.find(".//osmatch")
        if osmatch is not None:
            os_name = osmatch.get("name")
            try:
                os_accuracy = int(osmatch.get("accuracy", 0))
            except ValueError:
                pass

        # Parse ports
        ports = []
        for port_elem in host_elem.findall(".//port"):
            port = NmapParser._parse_port(port_elem)
            if port:
                ports.append(port)

        return Host(
            ip_address=ip_address or "unknown",
            hostname=hostname,
            status=status,
            os_name=os_name,
            os_accuracy=os_accuracy,
            ports=ports,
        )

    @staticmethod
    def _parse_port(port_elem: ET.Element) -> Optional[Port]:
        """Parse individual port element"""
        try:
            port_id = port_elem.get("portid")
            if port_id is None:
                return None
            port_num = int(port_id)
            protocol = port_elem.get("protocol", "tcp")

            state_elem = port_elem.find(".//state")
            state = (
                state_elem.get("state", "unknown")
                if state_elem is not None
                else "unknown"
            )

            # Parse service info
            service_elem = port_elem.find(".//service")
            service_name = None
            service_product = None
            service_version = None
            service_extra = None

            if service_elem is not None:
                service_name = service_elem.get("name")
                service_product = service_elem.get("product")
                service_version = service_elem.get("version")
                service_extra = service_elem.get("extrainfo")

            # Parse NSE script vulnerabilities (e.g., vulners script)
            vulnerabilities = []
            for script_elem in port_elem.findall(".//script"):
                script_id = script_elem.get("id", "")
                if script_id == "vulners":
                    # Get the output text which contains tab-separated vulnerability data
                    output = script_elem.get("output", "")
                    if output:
                        # Parse tab-separated vulnerability data
                        # Format: CVE-ID\tCVSS\tURL\t[*EXPLOIT*]
                        lines = output.strip().split('\n')
                        for line in lines:
                            line = line.strip()
                            # Skip empty lines and section headers (CPE lines start with "cpe:")
                            if not line or line.startswith('cpe:'):
                                continue
                            
                            parts = line.split('\t')
                            if len(parts) >= 2:
                                vuln_id = parts[0].strip()
                                cvss_str = parts[1].strip()
                                
                                # Only process if it looks like a CVE or known vulnerability format
                                if vuln_id and (vuln_id.startswith('CVE-') or 'PACKETSTORM' in vuln_id or 'EDB-ID' in vuln_id or '-' in vuln_id):
                                    try:
                                        cvss = float(cvss_str)
                                        vuln_dict = {
                                            'id': vuln_id,
                                            'cvss': str(cvss),
                                            'type': 'CVE' if vuln_id.startswith('CVE-') else 'EXPLOIT'
                                        }
                                        vulnerabilities.append(vuln_dict)
                                    except (ValueError, IndexError):
                                        pass

            port = Port(
                port=port_num,
                protocol=protocol,
                state=state,
                service_name=service_name,
                service_product=service_product,
                service_version=service_version,
                service_extra=service_extra,
                vulnerabilities=vulnerabilities if vulnerabilities else [],
            )
            
            return port

        except (ValueError, TypeError) as e:
            logger.warning("Failed to parse port: %s", str(e))
            return None


class OpenVASParser:
    """Parser for OpenVAS/GVM XML report output"""

    @staticmethod
    def parse_xml(xml_content: str) -> Dict[str, Any]:
        """
        Parse OpenVAS XML report

        Args:
            xml_content: XML content as string

        Returns:
            Dictionary containing parsed vulnerability scan results
        """
        try:
            root = ET.fromstring(xml_content)

            # Extract report metadata
            report_info = OpenVASParser._parse_report_info(root)

            # Extract results (vulnerabilities)
            hosts_dict = {}

            for result_elem in root.findall(".//result"):
                host_ip, vuln = OpenVASParser._parse_result(result_elem)

                if host_ip and vuln:
                    if host_ip not in hosts_dict:
                        hosts_dict[host_ip] = Host(ip_address=host_ip, status="up")

                    # Add vulnerability to host (we'll store in a
                    # vulnerabilities list)
                    if not hasattr(hosts_dict[host_ip], "vulnerabilities"):
                        hosts_dict[host_ip].vulnerabilities = []
                    hosts_dict[host_ip].vulnerabilities.append(vuln)

            # Convert hosts dict to list
            hosts: List[Dict[str, Any]] = []
            for host_obj in hosts_dict.values():
                host_dict = asdict(host_obj)
                if hasattr(host_obj, "vulnerabilities"):
                    host_dict["vulnerabilities"] = [
                        asdict(v) for v in host_obj.vulnerabilities
                    ]
                else:
                    host_dict["vulnerabilities"] = []
                hosts.append(host_dict)

            # Build summary
            total_vulns = sum(len(h.get("vulnerabilities", [])) for h in hosts)

            # Count by severity
            severity_counts = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            }
            for host in hosts:
                for vuln in host.get("vulnerabilities", []):
                    severity = vuln.get("severity", "info").lower()
                    if severity in severity_counts:
                        severity_counts[severity] += 1

            summary = {
                "hosts_scanned": len(hosts),
                "vulnerabilities_found": total_vulns,
                "by_severity": severity_counts,
            }

            result = {
                "report_info": report_info, 
                "summary": summary, 
                "hosts": hosts,
                # Add top-level keys for compatibility with scan orchestrator
                "vulnerability_count": total_vulns,
                "severity_counts": severity_counts,
                "vulnerabilities": [v for host in hosts for v in host.get("vulnerabilities", [])]
            }

            logger.info(
                "Parsed OpenVAS output: %d vulnerabilities across %d hosts",
                total_vulns,
                len(hosts),
            )

            return result

        except ET.ParseError as e:
            logger.error("Failed to parse OpenVAS XML: %s", str(e))
            raise ValueError(f"Invalid OpenVAS XML format: {str(e)}")
        except Exception as e:
            logger.error("Error parsing OpenVAS output: %s", str(e))
            raise

    @staticmethod
    def _parse_report_info(root: ET.Element) -> Dict[str, Any]:
        """Extract report metadata"""
        report_info = {}

        # Check if root is the report element or find it
        report = root if root.tag == "report" else root.find(".//report")
        if report is not None:
            report_info["report_id"] = report.get("id", "unknown")
            report_info["format_id"] = report.get("format_id", "unknown")

            # Get creation time
            creation_time = root.find(".//creation_time")
            if creation_time is not None and creation_time.text:
                report_info["creation_time"] = creation_time.text

        return report_info

    @staticmethod
    def _parse_result(result_elem: ET.Element) -> tuple:
        """Parse individual vulnerability result"""
        # Get host IP
        host_elem = result_elem.find(".//host")
        if host_elem is None or not host_elem.text:
            return None, None

        host_ip = host_elem.text.strip()

        # Get vulnerability details
        nvt = result_elem.find(".//nvt")
        if nvt is None:
            return host_ip, None

        vuln_id = nvt.get("oid", "unknown")
        name_elem = nvt.find(".//name")
        name = name_elem.text if name_elem is not None and name_elem.text else "Unknown"

        # Get severity/threat
        threat_elem = result_elem.find(".//threat")
        severity = (
            threat_elem.text.lower()
            if threat_elem is not None and threat_elem.text
            else "info"
        )

        # Map OpenVAS threat levels to standard severity
        severity_map = {
            "high": "high",
            "medium": "medium",
            "low": "low",
            "log": "info",
            "debug": "info",
        }
        severity = severity_map.get(severity, "info")

        # Get CVSS score
        cvss_score = None
        severity_elem = result_elem.find(".//severity")
        if severity_elem is not None and severity_elem.text:
            try:
                cvss_score = float(severity_elem.text)
            except ValueError:
                pass

        # Get description
        description_elem = result_elem.find(".//description")
        description = (
            description_elem.text
            if description_elem is not None and description_elem.text
            else None
        )

        # Get port/component
        port_elem = result_elem.find(".//port")
        affected_component = (
            port_elem.text if port_elem is not None and port_elem.text else None
        )

        # Get solution
        solution_elem = nvt.find(".//solution")
        solution = (
            solution_elem.text
            if solution_elem is not None and solution_elem.text
            else None
        )

        # Get references (CVEs, etc.)
        references = []
        for ref_elem in nvt.findall(".//ref"):
            ref_id = ref_elem.get("id")
            if ref_id:
                references.append(ref_id)

        vuln = Vulnerability(
            vuln_id=vuln_id,
            name=name,
            severity=severity,
            cvss_score=cvss_score,
            description=description,
            affected_component=affected_component,
            solution=solution,
            references=references,
        )

        return host_ip, vuln


def parse_tool_output(tool: str, output: str, format: str = "xml") -> Dict[str, Any]:
    """
    Parse tool output based on tool type

    Args:
        tool: Tool name (nmap, openvas, etc.)
        output: Raw tool output
        format: Output format (xml, json, text)

    Returns:
        Parsed output as dictionary

    Raises:
        ValueError: If tool or format is not supported
    """
    tool = tool.lower()
    format = format.lower()

    if tool == "nmap" and format == "xml":
        return NmapParser.parse_xml(output)
    elif tool == "openvas" and format == "xml":
        return OpenVASParser.parse_xml(output)
    else:
        raise ValueError(f"Unsupported tool/format combination: {tool}/{format}")


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)

    print("=== Parser Utilities Test ===\n")

    # Example Nmap XML (simplified)
    nmap_xml = """<?xml version="1.0"?>
    <nmaprun scanner="nmap" args="nmap -A 192.168.1.1" start="1634567890" version="7.91">
        <scaninfo type="syn" protocol="tcp" services="1-1000"/>
        <host>
            <status state="up"/>
            <address addr="192.168.1.1" addrtype="ipv4"/>
            <hostnames><hostname name="example.com"/></hostnames>
            <ports>
                <port protocol="tcp" portid="80">
                    <state state="open"/>
                    <service name="http" product="Apache" version="2.4.41"/>
                </port>
                <port protocol="tcp" portid="443">
                    <state state="open"/>
                    <service name="https" product="Apache" version="2.4.41"/>
                </port>
            </ports>
            <os>
                <osmatch name="Linux 3.2 - 4.9" accuracy="95"/>
            </os>
        </host>
    </nmaprun>
    """

    print("Testing Nmap parser:")
    try:
        result = NmapParser.parse_xml(nmap_xml)
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"Error: {str(e)}")
