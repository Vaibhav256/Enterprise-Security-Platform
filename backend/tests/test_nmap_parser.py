import pytest

from utils.parsers import NmapParser, parse_tool_output


BASIC_NMAP_XML = """<?xml version="1.0"?>
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


def test_parse_basic_nmap_xml():
    result = NmapParser.parse_xml(BASIC_NMAP_XML)

    # Basic metadata
    assert "scan_info" in result
    assert result["scan_info"]["nmap_version"] == "7.91"
    assert "nmap -A 192.168.1.1" in result["scan_info"]["command"]

    # Summary
    summary = result["summary"]
    assert summary["hosts_scanned"] == 1
    assert summary["hosts_up"] == 1
    assert summary["total_ports"] == 2
    assert summary["open_ports"] == 2

    # Host structure
    hosts = result["hosts"]
    assert isinstance(hosts, list) and len(hosts) == 1
    host = hosts[0]
    assert host["ip_address"] == "192.168.1.1"
    assert host["hostname"] == "example.com"
    assert host["os_name"] == "Linux 3.2 - 4.9"
    assert host["os_accuracy"] == 95

    # Ports
    ports = host["ports"]
    assert len(ports) == 2
    p0 = ports[0]
    assert p0["port"] == 80
    assert p0["state"] == "open"
    assert p0["service_name"] == "http"
    assert p0["service_product"] == "Apache"


def test_parse_missing_address_skips_host():
    xml = """<?xml version='1.0'?><nmaprun><host><status state='up'/></host></nmaprun>"""
    result = NmapParser.parse_xml(xml)
    assert result["summary"]["hosts_scanned"] == 0


def test_parse_no_status_skips_host():
    xml = """<?xml version='1.0'?><nmaprun><host><address addr='10.0.0.1' addrtype='ipv4'/></host></nmaprun>"""
    result = NmapParser.parse_xml(xml)
    assert result["summary"]["hosts_scanned"] == 0


def test_port_with_invalid_portid_is_ignored():
    xml = """<?xml version='1.0'?>
    <nmaprun>
      <host>
        <status state='up'/>
        <address addr='10.0.0.5' addrtype='ipv4'/>
        <ports>
          <port protocol='tcp' portid='abc'>
            <state state='open'/>
          </port>
          <port protocol='tcp' portid='22'>
            <state state='open'/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """
    result = NmapParser.parse_xml(xml)
    # Only one valid port should be counted
    assert result["summary"]["total_ports"] == 1
    assert result["summary"]["open_ports"] == 1


def test_parse_ipv6_address():
    xml = """<?xml version='1.0'?><nmaprun><host><status state='up'/><address addr='2001:db8::1' addrtype='ipv6'/><ports></ports></host></nmaprun>"""
    result = NmapParser.parse_xml(xml)
    assert result["summary"]["hosts_scanned"] == 1
    assert result["hosts"][0]["ip_address"] == '2001:db8::1'


def test_parse_os_accuracy_non_int_results_in_none():
    xml = """<?xml version='1.0'?><nmaprun><host><status state='up'/><address addr='10.0.0.6' addrtype='ipv4'/><os><osmatch name='TestOS' accuracy='bad'/></os></host></nmaprun>"""
    result = NmapParser.parse_xml(xml)
    assert result["hosts"][0]["os_accuracy"] is None


def test_parse_malformed_xml_raises_value_error():
    with pytest.raises(ValueError):
        NmapParser.parse_xml("<nmaprun><host>")


def test_parse_tool_output_dispatch_and_errors():
    # dispatch
    parsed = parse_tool_output("nmap", BASIC_NMAP_XML, "xml")
    assert parsed["summary"]["hosts_scanned"] == 1

    # unsupported combination
    with pytest.raises(ValueError):
        parse_tool_output("nmap", BASIC_NMAP_XML, "json")
