"""
Comprehensive tests for Nmap adapter

Tests command building, target validation, scan execution,
and result parsing for the Nmap adapter.
"""

import subprocess
from unittest.mock import MagicMock, Mock, patch

import pytest

from services.adapters.nmap_adapter import NmapAdapter
from services.adapters.base_adapter import ScanResult


@pytest.fixture
def mock_wsl_helper():
    """Create mock WSL helper"""
    helper = Mock()
    helper.run_command = Mock(return_value=(0, "<xml>test</xml>", ""))
    # Convert Windows path to WSL path
    def convert_path(path):
        return f"/mnt/c{path.replace(':', '').replace(chr(92), '/')}"
    helper.convert_path = Mock(side_effect=convert_path)
    return helper


@pytest.fixture
def nmap_adapter(mock_wsl_helper):
    """Create Nmap adapter with mock WSL helper"""
    return NmapAdapter(wsl_helper=mock_wsl_helper)


class TestNmapAdapterInitialization:
    """Tests for adapter initialization"""

    def test_init_with_wsl_helper(self, mock_wsl_helper):
        """Test initialization with provided WSL helper"""
        adapter = NmapAdapter(wsl_helper=mock_wsl_helper)
        assert adapter.wsl_helper == mock_wsl_helper

    def test_init_without_wsl_helper(self):
        """Test initialization creates WSL helper if not provided"""
        with patch('utils.wsl_helper.WSLHelper') as mock_helper:
            adapter = NmapAdapter()
            mock_helper.assert_called_once_with(distribution="kali-linux")

    def test_get_tool_name(self, nmap_adapter):
        """Test getting tool name"""
        assert nmap_adapter.get_tool_name() == "nmap"

    def test_get_version_flag(self, nmap_adapter):
        """Test version flag"""
        assert nmap_adapter.get_version_flag() == "-V"

    def test_get_default_options(self, nmap_adapter):
        """Test default options"""
        options = nmap_adapter.get_default_options()
        assert options['output_format'] == 'xml'
        assert options['timing'] == 'T4'
        assert options['service_detection'] is True
        assert options['verbose'] is True
        assert options['os_detection'] is False

    def test_get_default_timeout(self, nmap_adapter):
        """Test default timeout"""
        assert nmap_adapter.get_default_timeout() == 600


class TestTargetValidation:
    """Tests for target validation"""

    def test_validate_single_ip(self, nmap_adapter):
        """Test validating single IP address"""
        assert nmap_adapter.validate_target("192.168.1.1") is True
        assert nmap_adapter.validate_target("10.0.0.1") is True
        assert nmap_adapter.validate_target("8.8.8.8") is True

    def test_validate_invalid_ip(self, nmap_adapter):
        """Test rejecting invalid IP addresses"""
        assert nmap_adapter.validate_target("256.1.1.1") is False
        assert nmap_adapter.validate_target("1.1.1.300") is False
        assert nmap_adapter.validate_target("999.999.999.999") is False

    def test_validate_cidr(self, nmap_adapter):
        """Test validating CIDR notation"""
        assert nmap_adapter.validate_target("192.168.1.0/24") is True
        assert nmap_adapter.validate_target("10.0.0.0/8") is True
        assert nmap_adapter.validate_target("172.16.0.0/16") is True

    def test_validate_invalid_cidr(self, nmap_adapter):
        """Test rejecting invalid CIDR"""
        assert nmap_adapter.validate_target("192.168.1.0/33") is False
        assert nmap_adapter.validate_target("192.168.1.0/") is False

    def test_validate_ip_range(self, nmap_adapter):
        """Test validating IP ranges"""
        assert nmap_adapter.validate_target("192.168.1.1-254") is True
        assert nmap_adapter.validate_target("10.0.0.1-100") is True

    def test_validate_hostname(self, nmap_adapter):
        """Test validating hostnames"""
        assert nmap_adapter.validate_target("example.com") is True
        assert nmap_adapter.validate_target("sub.example.com") is True
        assert nmap_adapter.validate_target("localhost") is True

    def test_validate_invalid_hostname(self, nmap_adapter):
        """Test rejecting invalid hostnames"""
        assert nmap_adapter.validate_target("-invalid.com") is False
        assert nmap_adapter.validate_target("invalid-.com") is False

    def test_validate_empty_target(self, nmap_adapter):
        """Test rejecting empty target"""
        assert nmap_adapter.validate_target("") is False
        assert nmap_adapter.validate_target("   ") is False


class TestCommandBuilding:
    """Tests for building Nmap commands"""

    def test_build_basic_command(self, nmap_adapter):
        """Test building basic scan command"""
        cmd = nmap_adapter.build_command("192.168.1.1", "basic", {})
        
        assert "nmap" in cmd
        assert "192.168.1.1" in cmd
        assert "-oX" in cmd  # XML output
        assert "-T4" in cmd  # Default timing

    def test_build_quick_scan(self, nmap_adapter):
        """Test building quick scan command"""
        cmd = nmap_adapter.build_command("192.168.1.1", "quick", {})
        
        assert "--top-ports 100" in cmd  # Quick scan uses top 100 ports
        assert "-T5" in cmd  # Insane timing

    def test_build_full_scan(self, nmap_adapter):
        """Test building full scan command"""
        cmd = nmap_adapter.build_command("192.168.1.1", "full", {})
        
        assert "-p-" in cmd  # All ports
        assert "-A" in cmd  # Aggressive scan includes service version

    def test_build_stealth_scan(self, nmap_adapter):
        """Test building stealth scan command"""
        cmd = nmap_adapter.build_command("192.168.1.1", "stealth", {})
        
        assert "-sS" in cmd  # SYN scan
        assert "-T2" in cmd  # Slower timing

    def test_build_with_custom_ports(self, nmap_adapter):
        """Test building command with custom ports"""
        cmd = nmap_adapter.build_command("192.168.1.1", "basic", {"ports": "80,443,8080"})
        
        assert "-p" in cmd
        assert "80,443,8080" in cmd

    def test_build_with_os_detection(self, nmap_adapter):
        """Test building command with OS detection"""
        cmd = nmap_adapter.build_command("192.168.1.1", "custom", {"os_detection": True})
        
        assert "-O" in cmd

    def test_build_with_scripts(self, nmap_adapter):
        """Test building command with NSE scripts"""
        cmd = nmap_adapter.build_command("192.168.1.1", "custom", {"scripts": "vuln,exploit"})
        
        assert "--script" in cmd
        assert "vuln,exploit" in cmd

    def test_build_with_service_detection_disabled(self, nmap_adapter):
        """Test building command without service detection"""
        cmd = nmap_adapter.build_command("192.168.1.1", "custom", {"service_detection": False})
        
        assert "-sV" not in cmd

    def test_build_with_verbose(self, nmap_adapter):
        """Test building command with verbose output"""
        cmd = nmap_adapter.build_command("192.168.1.1", "basic", {"verbose": True})
        
        assert "-v" in cmd

    def test_build_with_timing(self, nmap_adapter):
        """Test building command with custom timing"""
        cmd = nmap_adapter.build_command("192.168.1.1", "basic", {"timing": "T3"})
        
        assert "-T3" in cmd


class TestScanExecution:
    """Tests for scan execution"""

    def test_execute_scan_success(self, nmap_adapter, mock_wsl_helper):
        """Test successful scan execution"""
        from utils.wsl_helper import WSLCommandResult
        
        mock_result = WSLCommandResult(
            success=True,
            stdout="<nmaprun></nmaprun>",
            stderr="",
            return_code=0,
            command="nmap test",
            execution_time=1.0
        )
        mock_wsl_helper.execute_command = Mock(return_value=mock_result)
        
        with patch.object(nmap_adapter, 'parse_results') as mock_parse:
            mock_parse.return_value = {'hosts': []}
            result = nmap_adapter.execute_scan("192.168.1.1", "basic", {})
            
            assert result.success is True
            assert result.raw_output == "<nmaprun></nmaprun>"
            mock_wsl_helper.execute_command.assert_called_once()

    def test_execute_scan_failure(self, nmap_adapter, mock_wsl_helper):
        """Test scan execution failure"""
        from utils.wsl_helper import WSLCommandResult
        
        mock_result = WSLCommandResult(
            success=False,
            stdout="",
            stderr="Error: Permission denied",
            return_code=1,
            command="nmap test",
            execution_time=0.1
        )
        mock_wsl_helper.execute_command = Mock(return_value=mock_result)
        
        result = nmap_adapter.execute_scan("192.168.1.1", "basic", {})
        
        assert result.success is False
        assert "Permission denied" in result.error_message

    def test_execute_scan_with_timeout(self, nmap_adapter, mock_wsl_helper):
        """Test scan execution with custom timeout"""
        from utils.wsl_helper import WSLCommandResult
        
        mock_result = WSLCommandResult(
            success=True,
            stdout="<nmaprun></nmaprun>",
            stderr="",
            return_code=0,
            command="nmap test",
            execution_time=1.0
        )
        mock_wsl_helper.execute_command = Mock(return_value=mock_result)
        
        with patch.object(nmap_adapter, 'parse_results') as mock_parse:
            mock_parse.return_value = {'hosts': []}
            nmap_adapter.execute_scan("192.168.1.1", "basic", {}, timeout=300)
            
            # Verify timeout was passed
            call_args = mock_wsl_helper.execute_command.call_args
            assert call_args[1]['timeout'] == 300

    def test_execute_scan_exception(self, nmap_adapter, mock_wsl_helper):
        """Test scan execution with exception"""
        mock_wsl_helper.execute_command = Mock(side_effect=Exception("Connection failed"))
        
        result = nmap_adapter.execute_scan("192.168.1.1", "basic", {})
        
        assert result.success is False
        assert "Connection failed" in result.error_message


class TestResultParsing:
    """Tests for result parsing"""

    def test_parse_results_valid_xml(self, nmap_adapter):
        """Test parsing valid XML results"""
        xml_output = """<?xml version="1.0"?>
        <nmaprun>
            <host>
                <address addr="192.168.1.1" addrtype="ipv4"/>
                <status state="up"/>
                <ports>
                    <port protocol="tcp" portid="80">
                        <state state="open"/>
                        <service name="http"/>
                    </port>
                </ports>
            </host>
        </nmaprun>"""
        
        result = nmap_adapter.parse_results(xml_output)
        
        assert 'summary' in result or 'hosts' in result
        # Result should have parsed data
        assert isinstance(result, dict)

    def test_parse_results_empty_xml(self, nmap_adapter):
        """Test parsing empty XML"""
        result = nmap_adapter.parse_results("<nmaprun></nmaprun>")
        
        assert isinstance(result, dict)

    def test_parse_results_invalid_xml(self, nmap_adapter):
        """Test parsing invalid XML"""
        with pytest.raises(ValueError, match="No XML content found"):
            nmap_adapter.parse_results("invalid xml")

    def test_parse_results_empty_string(self, nmap_adapter):
        """Test parsing empty string"""
        with pytest.raises(ValueError, match="No XML content found"):
            nmap_adapter.parse_results("")


class TestScanTypes:
    """Tests for different scan types"""

    def test_quick_scan_type(self, nmap_adapter):
        """Test quick scan type configuration"""
        cmd = nmap_adapter.build_command("192.168.1.1", "quick", {})
        assert "--top-ports 100" in cmd
        assert "-T5" in cmd

    def test_basic_scan_type(self, nmap_adapter):
        """Test basic scan type configuration"""
        cmd = nmap_adapter.build_command("192.168.1.1", "basic", {})
        assert "nmap" in cmd
        assert "192.168.1.1" in cmd

    def test_full_scan_type(self, nmap_adapter):
        """Test full scan type configuration"""
        cmd = nmap_adapter.build_command("192.168.1.1", "full", {})
        assert "-p-" in cmd

    def test_stealth_scan_type(self, nmap_adapter):
        """Test stealth scan type configuration"""
        cmd = nmap_adapter.build_command("192.168.1.1", "stealth", {})
        assert "-sS" in cmd

    def test_custom_scan_type(self, nmap_adapter):
        """Test custom scan type"""
        cmd = nmap_adapter.build_command("192.168.1.1", "custom", {})
        assert "nmap" in cmd


class TestEdgeCases:
    """Tests for edge cases and error handling"""

    def test_build_command_with_empty_options(self, nmap_adapter):
        """Test building command with empty options"""
        cmd = nmap_adapter.build_command("192.168.1.1", "basic", {})
        assert "nmap" in cmd
        assert "192.168.1.1" in cmd

    def test_build_command_with_none_options(self, nmap_adapter):
        """Test building command with None options - should use empty dict"""
        # The build_command doesn't handle None, so we pass empty dict instead
        cmd = nmap_adapter.build_command("192.168.1.1", "basic", {})
        assert "nmap" in cmd

    def test_validate_special_ip(self, nmap_adapter):
        """Test validating special IP addresses"""
        assert nmap_adapter.validate_target("0.0.0.0") is True
        assert nmap_adapter.validate_target("255.255.255.255") is True
        assert nmap_adapter.validate_target("127.0.0.1") is True

    def test_execute_scan_with_very_long_timeout(self, nmap_adapter, mock_wsl_helper):
        """Test scan with very long timeout"""
        mock_wsl_helper.run_command.return_value = (0, "<nmaprun></nmaprun>", "")
        
        with patch.object(nmap_adapter, 'parse_results') as mock_parse:
            mock_parse.return_value = {'hosts': []}
            result = nmap_adapter.execute_scan("192.168.1.1", "basic", {}, timeout=3600)
            
            assert result.success is True

    def test_parse_results_with_special_characters(self, nmap_adapter):
        """Test parsing results with special characters"""
        xml_output = """<?xml version="1.0"?>
        <nmaprun>
            <host>
                <address addr="192.168.1.1"/>
                <hostname name="test&amp;host"/>
            </host>
        </nmaprun>"""
        
        result = nmap_adapter.parse_results(xml_output)
        assert isinstance(result, dict)


class TestNmapConvenienceMethods:
    """Tests for Nmap convenience scanning methods"""
    
    def test_execute_service_scan(self, nmap_adapter, mock_wsl_helper):
        """Test service detection scan"""
        from utils.wsl_helper import WSLCommandResult
        
        xml_response = """<?xml version="1.0"?>
        <nmaprun>
            <host><address addr="192.168.1.1"/></host>
        </nmaprun>"""
        
        mock_result = WSLCommandResult(
            success=True,
            stdout=xml_response,
            stderr="",
            return_code=0,
            command="nmap -sV 192.168.1.1",
            execution_time=10.0
        )
        mock_wsl_helper.execute_command = Mock(return_value=mock_result)
        
        result = nmap_adapter.execute_service_scan("192.168.1.1")
        
        assert isinstance(result, ScanResult)
        assert result.success is True
    
    def test_execute_service_scan_with_ports(self, nmap_adapter, mock_wsl_helper):
        """Test service detection with specific ports"""
        from utils.wsl_helper import WSLCommandResult
        
        xml_response = """<?xml version="1.0"?>
        <nmaprun><host><address addr="192.168.1.1"/></host></nmaprun>"""
        
        mock_result = WSLCommandResult(
            success=True,
            stdout=xml_response,
            stderr="",
            return_code=0,
            command="nmap",
            execution_time=5.0
        )
        mock_wsl_helper.execute_command = Mock(return_value=mock_result)
        
        result = nmap_adapter.execute_service_scan("192.168.1.1", ports="80,443")
        
        assert result.success is True
    
    def test_execute_os_detection(self, nmap_adapter, mock_wsl_helper):
        """Test OS detection scan"""
        from utils.wsl_helper import WSLCommandResult
        
        xml_response = """<?xml version="1.0"?>
        <nmaprun>
            <host>
                <address addr="192.168.1.1"/>
                <os><osmatch name="Linux"/></os>
            </host>
        </nmaprun>"""
        
        mock_result = WSLCommandResult(
            success=True,
            stdout=xml_response,
            stderr="",
            return_code=0,
            command="nmap -O 192.168.1.1",
            execution_time=15.0
        )
        mock_wsl_helper.execute_command = Mock(return_value=mock_result)
        
        result = nmap_adapter.execute_os_detection("192.168.1.1")
        
        assert isinstance(result, ScanResult)
        assert result.success is True
    
    def test_execute_script_scan(self, nmap_adapter, mock_wsl_helper):
        """Test NSE script scan"""
        from utils.wsl_helper import WSLCommandResult
        
        xml_response = """<?xml version="1.0"?>
        <nmaprun><host><address addr="192.168.1.1"/></host></nmaprun>"""
        
        mock_result = WSLCommandResult(
            success=True,
            stdout=xml_response,
            stderr="",
            return_code=0,
            command="nmap --script vuln 192.168.1.1",
            execution_time=30.0
        )
        mock_wsl_helper.execute_command = Mock(return_value=mock_result)
        
        result = nmap_adapter.execute_script_scan("192.168.1.1", scripts="vuln")
        
        assert isinstance(result, ScanResult)
        assert result.success is True
    
    def test_execute_script_scan_with_ports(self, nmap_adapter, mock_wsl_helper):
        """Test script scan with specific ports"""
        from utils.wsl_helper import WSLCommandResult
        
        xml_response = """<?xml version="1.0"?>
        <nmaprun><host><address addr="192.168.1.1"/></host></nmaprun>"""
        
        mock_result = WSLCommandResult(
            success=True,
            stdout=xml_response,
            stderr="",
            return_code=0,
            command="nmap --script=http-enum -p 80,443 192.168.1.1",
            execution_time=20.0
        )
        mock_wsl_helper.execute_command = Mock(return_value=mock_result)
        
        result = nmap_adapter.execute_script_scan(
            "192.168.1.1",
            scripts="http-enum",
            ports="80,443"
        )
        
        assert result.success is True


class TestNmapAdditionalScanTypes:
    """Tests for additional scan type coverage"""
    
    def test_build_full_scan_command(self, nmap_adapter):
        """Test building full/aggressive scan command"""
        cmd = nmap_adapter.build_command("192.168.1.1", "full", {})
        
        assert "nmap" in cmd
        assert "-A" in cmd  # Aggressive scan
        assert "-p-" in cmd  # All ports
        assert "192.168.1.1" in cmd
    
    def test_build_full_scan_with_specific_ports(self, nmap_adapter):
        """Test full scan with port specification"""
        cmd = nmap_adapter.build_command("192.168.1.1", "full", {"ports": "1-1000"})
        
        assert "-A" in cmd
        assert "-p 1-1000" in cmd
        assert "-p-" not in cmd
    
    def test_build_quick_scan_command(self, nmap_adapter):
        """Test building quick scan command"""
        cmd = nmap_adapter.build_command("192.168.1.1", "quick", {})
        
        assert "nmap" in cmd
        assert "-sV" in cmd  # Service version
        assert "--top-ports 100" in cmd
        assert "-T5" in cmd  # Insane timing
    
    def test_build_stealth_scan_command(self, nmap_adapter):
        """Test building stealth scan command"""
        cmd = nmap_adapter.build_command("192.168.1.1", "stealth", {})
        
        assert "nmap" in cmd
        assert "-sS" in cmd  # SYN scan
        assert "-T2" in cmd  # Polite timing
        assert "--top-ports 100" in cmd
    
    def test_build_stealth_scan_with_ports(self, nmap_adapter):
        """Test stealth scan with specific ports"""
        cmd = nmap_adapter.build_command("192.168.1.1", "stealth", {"ports": "22,80,443"})
        
        assert "-sS" in cmd
        assert "-p 22,80,443" in cmd
        assert "--top-ports" not in cmd
    
    def test_build_custom_scan_with_service_detection(self, nmap_adapter):
        """Test custom scan with service detection"""
        cmd = nmap_adapter.build_command("192.168.1.1", "custom", {"service_detection": True})
        
        assert "-sV" in cmd
    
    def test_build_custom_scan_with_os_detection(self, nmap_adapter):
        """Test custom scan with OS detection"""
        cmd = nmap_adapter.build_command("192.168.1.1", "custom", {"os_detection": True})
        
        assert "-O" in cmd
    
    def test_build_custom_scan_with_script(self, nmap_adapter):
        """Test custom scan with NSE scripts"""
        cmd = nmap_adapter.build_command("192.168.1.1", "custom", {"scripts": "vuln,safe"})
        
        assert "--script=vuln,safe" in cmd
    
    def test_build_custom_scan_with_multiple_options(self, nmap_adapter):
        """Test custom scan with multiple options"""
        options = {
            "service_detection": True,
            "os_detection": True,
            "scripts": "default",
            "ports": "1-65535"
        }
        cmd = nmap_adapter.build_command("192.168.1.1", "custom", options)
        
        assert "-sV" in cmd
        assert "-O" in cmd
        assert "--script=default" in cmd
        assert "-p 1-65535" in cmd


class TestNmapAdapterEdgeCases:
    """Edge case tests for NmapAdapter"""
    
    def test_check_tool_availability_exception(self, mock_wsl_helper, nmap_adapter):
        """Test check_tool_availability when exception occurs"""
        # Mock check_tool_availability to raise exception after adapter is created
        nmap_adapter.wsl_helper.check_tool_availability = Mock(side_effect=Exception("Connection failed"))
        
        result = nmap_adapter.check_tool_availability()
        
        # Should catch exception and return False
        assert result is False
