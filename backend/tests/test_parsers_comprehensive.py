"""
Comprehensive tests for parser utilities
Tests for Nmap, OpenVAS, and generic parsing functionality
"""
import pytest
from utils.parsers import (
    NmapParser, 
    OpenVASParser,
    parse_tool_output,
    Port, 
    Host, 
    Vulnerability
)


class TestDataClasses:
    """Test the data classes used by parsers"""
    
    def test_port_creation(self):
        """Test Port dataclass creation"""
        port = Port(
            port=80,
            protocol="tcp",
            state="open",
            service_name="http",
            service_product="Apache",
            service_version="2.4.41"
        )
        assert port.port == 80
        assert port.protocol == "tcp"
        assert port.state == "open"
        assert port.service_name == "http"
    
    def test_host_creation_with_defaults(self):
        """Test Host dataclass with default values"""
        host = Host(ip_address="192.168.1.1")
        assert host.ip_address == "192.168.1.1"
        assert host.hostname is None
        assert host.status == "unknown"
        assert host.ports == []
        assert host.vulnerabilities == []
    
    def test_host_with_ports(self):
        """Test Host with port list"""
        port = Port(port=22, protocol="tcp", state="open")
        host = Host(ip_address="10.0.0.1", ports=[port])
        assert len(host.ports) == 1
        assert host.ports[0].port == 22
    
    def test_vulnerability_creation(self):
        """Test Vulnerability dataclass"""
        vuln = Vulnerability(
            vuln_id="CVE-2021-1234",
            name="Test Vulnerability",
            severity="high",
            cvss_score=8.5
        )
        assert vuln.vuln_id == "CVE-2021-1234"
        assert vuln.severity == "high"
        assert vuln.cvss_score == 8.5
        assert vuln.references == []


class TestNmapParser:
    """Test Nmap XML parsing"""
    
    def test_parse_empty_results(self):
        """Test parsing Nmap XML with no hosts"""
        xml = """<?xml version='1.0'?>
        <nmaprun scanner="nmap" version="7.91">
        </nmaprun>
        """
        result = NmapParser.parse_xml(xml)
        assert result["summary"]["hosts_scanned"] == 0
        assert result["summary"]["hosts_up"] == 0
        assert result["summary"]["total_ports"] == 0
    
    def test_parse_single_host_no_ports(self):
        """Test parsing host without open ports"""
        xml = """<?xml version='1.0'?>
        <nmaprun scanner="nmap" version="7.91">
            <host>
                <status state='up'/>
                <address addr='192.168.1.1' addrtype='ipv4'/>
            </host>
        </nmaprun>
        """
        result = NmapParser.parse_xml(xml)
        assert result["summary"]["hosts_scanned"] == 1
        assert result["summary"]["hosts_up"] == 1
        assert result["summary"]["total_ports"] == 0
        assert len(result["hosts"]) == 1
        assert result["hosts"][0]["ip_address"] == "192.168.1.1"
    
    def test_parse_host_with_hostname(self):
        """Test parsing host with hostname"""
        xml = """<?xml version='1.0'?>
        <nmaprun>
            <host>
                <status state='up'/>
                <address addr='10.0.0.1' addrtype='ipv4'/>
                <hostnames>
                    <hostname name='server.example.com' type='PTR'/>
                </hostnames>
            </host>
        </nmaprun>
        """
        result = NmapParser.parse_xml(xml)
        assert result["hosts"][0]["hostname"] == "server.example.com"
    
    def test_parse_multiple_hostnames(self):
        """Test parsing host with multiple hostnames - should use first"""
        xml = """<?xml version='1.0'?>
        <nmaprun>
            <host>
                <status state='up'/>
                <address addr='10.0.0.1' addrtype='ipv4'/>
                <hostnames>
                    <hostname name='primary.example.com'/>
                    <hostname name='secondary.example.com'/>
                </hostnames>
            </host>
        </nmaprun>
        """
        result = NmapParser.parse_xml(xml)
        assert result["hosts"][0]["hostname"] == "primary.example.com"
    
    def test_parse_port_with_service_info(self):
        """Test parsing port with complete service information"""
        xml = """<?xml version='1.0'?>
        <nmaprun>
            <host>
                <status state='up'/>
                <address addr='10.0.0.1' addrtype='ipv4'/>
                <ports>
                    <port protocol='tcp' portid='443'>
                        <state state='open'/>
                        <service name='https' product='nginx' version='1.18.0' extrainfo='Ubuntu'/>
                    </port>
                </ports>
            </host>
        </nmaprun>
        """
        result = NmapParser.parse_xml(xml)
        port = result["hosts"][0]["ports"][0]
        assert port["port"] == 443
        assert port["service_name"] == "https"
        assert port["service_product"] == "nginx"
        assert port["service_version"] == "1.18.0"
        assert port["service_extra"] == "Ubuntu"
    
    def test_parse_os_detection(self):
        """Test OS detection parsing"""
        xml = """<?xml version='1.0'?>
        <nmaprun>
            <host>
                <status state='up'/>
                <address addr='10.0.0.1' addrtype='ipv4'/>
                <os>
                    <osmatch name='Ubuntu Linux 20.04' accuracy='98'/>
                    <osmatch name='Ubuntu Linux 18.04' accuracy='92'/>
                </os>
            </host>
        </nmaprun>
        """
        result = NmapParser.parse_xml(xml)
        host = result["hosts"][0]
        assert host["os_name"] == "Ubuntu Linux 20.04"
        assert host["os_accuracy"] == 98
    
    def test_parse_host_down(self):
        """Test parsing host with 'down' status"""
        xml = """<?xml version='1.0'?>
        <nmaprun>
            <host>
                <status state='down'/>
                <address addr='10.0.0.99' addrtype='ipv4'/>
            </host>
        </nmaprun>
        """
        result = NmapParser.parse_xml(xml)
        assert result["summary"]["hosts_scanned"] == 1
        assert result["summary"]["hosts_up"] == 0
        assert result["hosts"][0]["status"] == "down"


class TestOpenVASParser:
    """Test OpenVAS XML parsing"""
    
    def test_parse_empty_report(self):
        """Test parsing empty OpenVAS report"""
        xml = """<?xml version='1.0'?>
        <report id='test-report'>
        </report>
        """
        result = OpenVASParser.parse_xml(xml)
        assert "hosts" in result
        assert len(result["hosts"]) == 0
    
    def test_parse_report_with_vulnerability(self):
        """Test parsing OpenVAS report with a vulnerability"""
        xml = """<?xml version='1.0'?>
        <report id='test-report'>
            <result>
                <host>192.168.1.100</host>
                <port>443/tcp</port>
                <nvt oid='1.3.6.1.4.1.25623.1.0.12345'>
                    <name>SSL/TLS Test Vuln</name>
                    <cvss_base>7.5</cvss_base>
                </nvt>
                <severity>7.5</severity>
                <description>Test vulnerability description</description>
                <threat>High</threat>
            </result>
        </report>
        """
        result = OpenVASParser.parse_xml(xml)
        assert len(result["hosts"]) == 1
        host = result["hosts"][0]
        assert host["ip_address"] == "192.168.1.100"
        assert len(host["vulnerabilities"]) == 1
        vuln = host["vulnerabilities"][0]
        assert vuln["name"] == "SSL/TLS Test Vuln"
        assert vuln["severity"].lower() == "high"


class TestParseToolOutput:
    """Test the generic parse_tool_output dispatcher"""
    
    def test_dispatch_nmap_xml(self):
        """Test dispatching to Nmap parser"""
        xml = """<?xml version='1.0'?>
        <nmaprun scanner="nmap">
            <host><status state='up'/><address addr='10.0.0.1' addrtype='ipv4'/></host>
        </nmaprun>
        """
        result = parse_tool_output("nmap", xml, "xml")
        assert "summary" in result
        assert result["summary"]["hosts_scanned"] == 1
    
    def test_dispatch_openvas_xml(self):
        """Test dispatching to OpenVAS parser"""
        xml = """<?xml version='1.0'?>
        <report id='test'></report>
        """
        result = parse_tool_output("openvas", xml, "xml")
        assert "hosts" in result
    
    def test_unsupported_tool(self):
        """Test handling of unsupported tool"""
        with pytest.raises(ValueError, match="Unsupported tool"):
            parse_tool_output("unknown_tool", "data", "xml")
    
    def test_unsupported_format(self):
        """Test handling of unsupported format"""
        with pytest.raises(ValueError, match="Unsupported tool/format"):
            parse_tool_output("nmap", "data", "yaml")
    
    def test_empty_content(self):
        """Test handling of empty content"""
        with pytest.raises(ValueError):
            parse_tool_output("nmap", "", "xml")
    
    def test_none_content(self):
        """Test handling of None content"""
        with pytest.raises((ValueError, TypeError)):
            parse_tool_output("nmap", None, "xml")


class TestErrorHandling:
    """Test error handling in parsers"""
    
    def test_nmap_invalid_xml(self):
        """Test Nmap parser with invalid XML"""
        with pytest.raises(ValueError):
            NmapParser.parse_xml("not valid xml <<<<")
    
    def test_nmap_incomplete_xml(self):
        """Test Nmap parser with incomplete XML"""
        with pytest.raises(ValueError):
            NmapParser.parse_xml("<nmaprun><host>")
    
    def test_openvas_invalid_xml(self):
        """Test OpenVAS parser with invalid XML"""
        with pytest.raises(ValueError):
            OpenVASParser.parse_xml("invalid")


class TestEdgeCases:
    """Test edge cases and boundary conditions"""
    
    def test_nmap_very_large_port_number(self):
        """Test handling of edge case port numbers"""
        xml = """<?xml version='1.0'?>
        <nmaprun>
            <host>
                <status state='up'/>
                <address addr='10.0.0.1' addrtype='ipv4'/>
                <ports>
                    <port protocol='tcp' portid='65535'>
                        <state state='open'/>
                    </port>
                </ports>
            </host>
        </nmaprun>
        """
        result = NmapParser.parse_xml(xml)
        assert result["hosts"][0]["ports"][0]["port"] == 65535
    
    def test_nmap_zero_cvss_score(self):
        """Test handling of zero CVSS score"""
        xml = """<?xml version='1.0'?>
        <nmaprun>
            <host>
                <status state='up'/>
                <address addr='10.0.0.1' addrtype='ipv4'/>
                <os><osmatch name='Test OS' accuracy='0'/></os>
            </host>
        </nmaprun>
        """
        result = NmapParser.parse_xml(xml)
        # accuracy of 0 should still be captured
        assert result["hosts"][0]["os_accuracy"] == 0
    
    def test_special_characters_in_hostname(self):
        """Test special characters in hostname"""
        xml = """<?xml version='1.0'?>
        <nmaprun>
            <host>
                <status state='up'/>
                <address addr='10.0.0.1' addrtype='ipv4'/>
                <hostnames>
                    <hostname name='test-server_01.example.com'/>
                </hostnames>
            </host>
        </nmaprun>
        """
        result = NmapParser.parse_xml(xml)
        assert result["hosts"][0]["hostname"] == "test-server_01.example.com"


class TestDataClassEdgeCases:
    """Test edge cases in dataclass initialization"""

    def test_host_post_init_with_none_ports(self):
        """Test Host __post_init__ when ports is None"""
        # Create Host with ports=None explicitly
        host = Host(
            ip_address="192.168.1.1",
            status="up",
            ports=None,
            vulnerabilities=None
        )
        # __post_init__ should initialize to empty lists
        assert host.ports == []
        assert host.vulnerabilities == []

    def test_vulnerability_post_init_with_none_references(self):
        """Test Vulnerability __post_init__ when references is None"""
        vuln = Vulnerability(
            vuln_id="CVE-2024-1234",
            name="Test Vuln",
            severity="high",
            references=None
        )
        # __post_init__ should initialize to empty list
        assert vuln.references == []

    def test_nmap_parse_port_with_missing_portid(self):
        """Test _parse_port with missing portid attribute"""
        from xml.etree import ElementTree as ET
        # Create port element without portid
        port_xml = '<port protocol="tcp"><state state="open"/></port>'
        port_elem = ET.fromstring(port_xml)
        
        port = NmapParser._parse_port(port_elem)
        # Should return None when portid is missing
        assert port is None

    def test_nmap_host_without_vulnerabilities_attribute(self):
        """Test host dict conversion when no vulnerabilities"""
        xml = """<?xml version='1.0'?>
        <nmaprun>
            <host>
                <status state='up'/>
                <address addr='10.0.0.1' addrtype='ipv4'/>
            </host>
        </nmaprun>
        """
        result = NmapParser.parse_xml(xml)
        # Should have empty vulnerabilities list
        assert result["hosts"][0]["vulnerabilities"] == []
