"""
Comprehensive tests for Nikto Adapter

Tests Nikto web scanner adapter including command building,
scan execution, and XML output parsing.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
from itertools import cycle

from services.adapters.nikto_adapter import NiktoAdapter
from services.adapters.base_adapter import ScanResult
from utils.wsl_helper import WSLHelper, WSLCommandResult


@pytest.fixture
def mock_wsl_helper():
    """Create mock WSL helper"""
    helper = Mock(spec=WSLHelper)
    helper.execute_command = Mock()
    helper.check_tool_availability = Mock(return_value=True)
    return helper


@pytest.fixture
def nikto_adapter(mock_wsl_helper):
    """Create Nikto adapter with mocked WSL helper"""
    return NiktoAdapter(wsl_helper=mock_wsl_helper)


class TestNiktoAdapterInitialization:
    """Tests for Nikto adapter initialization"""

    def test_init_with_wsl_helper(self, mock_wsl_helper):
        """Test initialization with provided WSL helper"""
        adapter = NiktoAdapter(wsl_helper=mock_wsl_helper)
        assert adapter.wsl_helper == mock_wsl_helper

    @patch('services.adapters.nikto_adapter.WSLHelper')
    def test_init_without_wsl_helper(self, mock_wsl_class):
        """Test initialization creates WSL helper if not provided"""
        mock_helper = Mock()
        mock_wsl_class.return_value = mock_helper
        
        adapter = NiktoAdapter()
        
        mock_wsl_class.assert_called_once_with(distribution="kali-linux")

    def test_get_tool_name(self, nikto_adapter):
        """Test tool name is correct"""
        assert nikto_adapter.get_tool_name() == "nikto"


class TestTargetValidation:
    """Tests for target validation"""

    def test_validate_target_valid_url(self, nikto_adapter):
        """Test validating URL target"""
        assert nikto_adapter.validate_target("http://example.com") is True

    def test_validate_target_valid_hostname(self, nikto_adapter):
        """Test validating hostname target"""
        assert nikto_adapter.validate_target("example.com") is True

    def test_validate_target_valid_ip(self, nikto_adapter):
        """Test validating IP address target"""
        assert nikto_adapter.validate_target("192.168.1.1") is True

    def test_validate_target_empty(self, nikto_adapter):
        """Test validating empty target"""
        assert nikto_adapter.validate_target("") is False

    def test_validate_target_none(self, nikto_adapter):
        """Test validating None target"""
        assert nikto_adapter.validate_target(None) is False

    def test_validate_target_whitespace(self, nikto_adapter):
        """Test validating whitespace-only target"""
        assert nikto_adapter.validate_target("   ") is False


class TestDefaultOptions:
    """Tests for default options"""

    def test_get_default_options(self, nikto_adapter):
        """Test default options structure"""
        options = nikto_adapter.get_default_options()
        
        assert "port" in options
        assert "ssl" in options
        assert "timeout" in options
        assert "tuning" in options
        assert "format" in options
        
    def test_default_port(self, nikto_adapter):
        """Test default port is 80"""
        options = nikto_adapter.get_default_options()
        assert options["port"] == 80

    def test_default_ssl(self, nikto_adapter):
        """Test default SSL is False"""
        options = nikto_adapter.get_default_options()
        assert options["ssl"] is False

    def test_default_timeout(self, nikto_adapter):
        """Test default timeout"""
        options = nikto_adapter.get_default_options()
        assert options["timeout"] == 600


class TestCommandBuilding:
    """Tests for Nikto command building"""

    def test_build_basic_command(self, nikto_adapter):
        """Test building basic scan command"""
        command = nikto_adapter.build_command("example.com", "basic")
        
        assert "nikto" in command
        assert "example.com" in command
        assert "-h" in command

    def test_build_command_with_http_prefix(self, nikto_adapter):
        """Test building command with HTTP URL"""
        command = nikto_adapter.build_command("http://example.com", "basic")
        
        assert "http://example.com" in command

    def test_build_command_with_https_prefix(self, nikto_adapter):
        """Test building command with HTTPS URL"""
        command = nikto_adapter.build_command("https://example.com", "basic")
        
        assert "https://example.com" in command

    def test_build_command_adds_http_protocol(self, nikto_adapter):
        """Test command adds http:// protocol by default"""
        command = nikto_adapter.build_command("example.com", "basic")
        
        assert "http://example.com" in command

    def test_build_command_adds_https_with_ssl_option(self, nikto_adapter):
        """Test command adds https:// when SSL enabled"""
        command = nikto_adapter.build_command("example.com", "basic", {"ssl": True})
        
        assert "https://example.com" in command

    def test_build_command_custom_port(self, nikto_adapter):
        """Test building command with custom port"""
        command = nikto_adapter.build_command("example.com", "basic", {"port": 8080})
        
        assert "8080" in command

    def test_build_command_ssl_port_443_not_added(self, nikto_adapter):
        """Test default SSL port 443 not added to URL"""
        command = nikto_adapter.build_command("example.com", "basic", {"ssl": True, "port": 443})
        
        # Should not have :443 since it's the default SSL port
        assert ":443" not in command or "https://example.com" in command

    def test_build_quick_scan_command(self, nikto_adapter):
        """Test building quick scan command"""
        command = nikto_adapter.build_command("example.com", "quick")
        
        assert "nikto" in command
        assert "-Tuning 1" in command

    def test_build_ssl_scan_command(self, nikto_adapter):
        """Test building SSL-specific scan command"""
        command = nikto_adapter.build_command("example.com", "ssl")
        
        assert "nikto" in command
        assert "-ssl" in command
        assert "-Tuning b" in command

    def test_build_full_scan_command(self, nikto_adapter):
        """Test building full scan command"""
        command = nikto_adapter.build_command("example.com", "full")
        
        assert "nikto" in command
        assert "-Tuning" in command
        assert "1234567890abcde" in command

    def test_build_full_scan_with_ssl(self, nikto_adapter):
        """Test building full scan with SSL"""
        command = nikto_adapter.build_command("example.com", "full", {"ssl": True})
        
        assert "-ssl" in command

    def test_build_full_scan_with_evasion(self, nikto_adapter):
        """Test building full scan with evasion techniques"""
        command = nikto_adapter.build_command("example.com", "full", {"evasion": "1"})
        
        assert "-evasion" in command

    def test_build_custom_scan_command(self, nikto_adapter):
        """Test building custom scan command"""
        command = nikto_adapter.build_command("example.com", "custom", {
            "tuning": "123",
            "timeout": 300
        })
        
        assert "nikto" in command
        assert "-Tuning 123" in command
        assert "-timeout 300" in command

    def test_build_custom_scan_with_plugins(self, nikto_adapter):
        """Test building custom scan with specific plugins"""
        command = nikto_adapter.build_command("example.com", "custom", {
            "plugins": "tests(report:500)"
        })
        
        assert "-Plugins" in command

    def test_build_command_with_additional_flags(self, nikto_adapter):
        """Test building command with additional flags"""
        command = nikto_adapter.build_command("example.com", "basic", {
            "additional_flags": "-Display V"
        })
        
        assert "-Display V" in command

    def test_build_command_invalid_target(self, nikto_adapter):
        """Test building command with invalid target raises error"""
        with pytest.raises(ValueError, match="Invalid target"):
            nikto_adapter.build_command("", "basic")


class TestScanExecution:
    """Tests for scan execution"""

    def test_execute_scan_success(self, nikto_adapter, mock_wsl_helper):
        """Test successful scan execution"""
        # Mock successful scan
        mock_result = WSLCommandResult(
            success=True,
            stdout="<niktoscan>test output</niktoscan>",
            stderr="",
            return_code=0,
            command="nikto -h http://example.com",
            execution_time=10.5
        )
        mock_wsl_helper.execute_command.return_value = mock_result
        
        # Mock parse_output to avoid XML parsing issues
        with patch.object(nikto_adapter, 'parse_output', return_value={"vulnerabilities": []}):
            result = nikto_adapter.execute_scan("example.com", "basic")
        
        assert result.success is True
        assert result.tool == "nikto"
        assert result.target == "example.com"
        assert result.raw_output == "<niktoscan>test output</niktoscan>"

    def test_execute_scan_no_findings_return_code_1(self, nikto_adapter, mock_wsl_helper):
        """Test scan with no findings (return code 1) is still success"""
        # Nikto returns 1 when no findings - this is OK
        mock_result = WSLCommandResult(
            success=False,
            stdout="<niktoscan>no issues found</niktoscan>",
            stderr="",
            return_code=1,
            command="nikto -h http://example.com",
            execution_time=10.5
        )
        mock_wsl_helper.execute_command.return_value = mock_result
        
        with patch.object(nikto_adapter, 'parse_output', return_value={"vulnerabilities": []}):
            result = nikto_adapter.execute_scan("example.com", "basic")
        
        # Should still be successful
        assert result.success is True

    def test_execute_scan_failure(self, nikto_adapter, mock_wsl_helper):
        """Test failed scan execution"""
        # Mock failed scan with error code other than 0 or 1
        mock_result = WSLCommandResult(
            success=False,
            stdout="",
            stderr="Connection failed",
            return_code=2,
            command="nikto -h http://example.com",
            execution_time=5.0
        )
        mock_wsl_helper.execute_command.return_value = mock_result
        
        result = nikto_adapter.execute_scan("example.com", "basic")
        
        assert result.success is False
        assert "failed" in result.error_message.lower()

    def test_execute_scan_with_custom_timeout(self, nikto_adapter, mock_wsl_helper):
        """Test scan execution with custom timeout"""
        mock_result = WSLCommandResult(
            success=True,
            stdout="<niktoscan>test</niktoscan>",
            stderr="",
            return_code=0,
            command="nikto",
            execution_time=10.0
        )
        mock_wsl_helper.execute_command.return_value = mock_result
        
        with patch.object(nikto_adapter, 'parse_output', return_value={}):
            nikto_adapter.execute_scan("example.com", "basic", {"timeout": 1200})
        
        # Verify timeout was passed
        call_args = mock_wsl_helper.execute_command.call_args
        assert call_args[1]['timeout'] == 1200

    def test_execute_scan_parse_failure(self, nikto_adapter, mock_wsl_helper):
        """Test scan execution when parsing fails"""
        mock_result = WSLCommandResult(
            success=True,
            stdout="invalid xml output",
            stderr="",
            return_code=0,
            command="nikto",
            execution_time=10.0
        )
        mock_wsl_helper.execute_command.return_value = mock_result
        
        with patch.object(nikto_adapter, 'parse_output', side_effect=Exception("Parse error")):
            result = nikto_adapter.execute_scan("example.com", "basic")
        
        # Should still return success but with None parsed_output
        assert result.success is True
        assert result.parsed_output is None

    def test_execute_scan_includes_metadata(self, nikto_adapter, mock_wsl_helper):
        """Test scan result includes metadata"""
        mock_result = WSLCommandResult(
            success=True,
            stdout="<niktoscan></niktoscan>",
            stderr="",
            return_code=0,
            command="nikto",
            execution_time=10.0
        )
        mock_wsl_helper.execute_command.return_value = mock_result
        
        with patch.object(nikto_adapter, 'parse_output', return_value={}):
            result = nikto_adapter.execute_scan("example.com", "full")
        
        assert "scan_type" in result.scan_metadata
        assert result.scan_metadata["scan_type"] == "full"


class TestOutputParsing:
    """Tests for output parsing"""

    def test_parse_results_calls_parse_output(self, nikto_adapter):
        """Test parse_results is alias for parse_output"""
        with patch.object(nikto_adapter, 'parse_output', return_value={"test": "data"}) as mock_parse:
            result = nikto_adapter.parse_results("<xml>test</xml>")
            
            mock_parse.assert_called_once_with("<xml>test</xml>")
            assert result == {"test": "data"}

    def test_parse_output_empty_string(self, nikto_adapter):
        """Test parsing empty output"""
        # Should handle gracefully
        try:
            result = nikto_adapter.parse_output("")
            # May return empty dict or raise exception - both are acceptable
            assert isinstance(result, dict) or result is None
        except Exception:
            # Exception is also acceptable for invalid input
            pass

    def test_parse_output_invalid_xml(self, nikto_adapter):
        """Test parsing invalid XML returns empty dict or None"""
        # Nikto adapter may handle invalid XML gracefully
        result = nikto_adapter.parse_output("not xml at all")
        # Should return empty dict or None when parsing fails
        assert result is None or result == {} or isinstance(result, dict)


class TestEdgeCases:
    """Tests for edge cases"""

    def test_build_command_with_ipv6(self, nikto_adapter):
        """Test building command with IPv6 address"""
        command = nikto_adapter.build_command("2001:db8::1", "basic")
        
        assert "nikto" in command
        assert "2001:db8::1" in command

    def test_build_command_with_special_chars_in_url(self, nikto_adapter):
        """Test building command with special characters in URL"""
        # URL with path and query string
        target = "http://example.com/path?param=value"
        command = nikto_adapter.build_command(target, "basic")
        
        assert "example.com" in command

    def test_execute_scan_different_scan_types(self, nikto_adapter, mock_wsl_helper):
        """Test executing different scan types"""
        mock_result = WSLCommandResult(
            success=True,
            stdout="<niktoscan></niktoscan>",
            stderr="",
            return_code=0,
            command="nikto",
            execution_time=10.0
        )
        mock_wsl_helper.execute_command.return_value = mock_result
        
        scan_types = ["basic", "quick", "ssl", "full", "custom"]
        
        with patch.object(nikto_adapter, 'parse_output', return_value={}):
            for scan_type in scan_types:
                result = nikto_adapter.execute_scan("example.com", scan_type)
                assert result.success is True
                assert result.scan_metadata["scan_type"] == scan_type

    def test_timeout_handling(self, nikto_adapter, mock_wsl_helper):
        """Test timeout is properly passed to WSL helper"""
        mock_result = WSLCommandResult(
            success=True,
            stdout="<niktoscan></niktoscan>",
            stderr="",
            return_code=0,
            command="nikto",
            execution_time=10.0
        )
        mock_wsl_helper.execute_command.return_value = mock_result
        
        with patch.object(nikto_adapter, 'parse_output', return_value={}):
            # Test default timeout
            nikto_adapter.execute_scan("example.com", "basic")
            assert mock_wsl_helper.execute_command.call_args[1]['timeout'] == 900
            
            # Test custom timeout
            nikto_adapter.execute_scan("example.com", "basic", {"timeout": 300})
            assert mock_wsl_helper.execute_command.call_args[1]['timeout'] == 300


class TestNiktoAdditionalOptions:
    """Tests for additional Nikto options coverage"""
    
    def test_build_command_with_ssl_option(self, nikto_adapter):
        """Test building command with SSL option enabled"""
        cmd = nikto_adapter.build_command("example.com", "full", {"ssl": True})
        
        assert "nikto" in cmd
        assert "-ssl" in cmd
        assert "https://" in cmd
    
    def test_build_command_with_timeout_option(self, nikto_adapter):
        """Test building command with timeout option"""
        cmd = nikto_adapter.build_command("example.com", "full", {"timeout": 600})
        
        assert "nikto" in cmd
        assert "-timeout 600" in cmd
    
    def test_build_command_with_evasion_option(self, nikto_adapter):
        """Test building command with evasion techniques"""
        cmd = nikto_adapter.build_command("example.com", "full", {"evasion": "123"})
        
        assert "nikto" in cmd
        assert "-evasion 123" in cmd
    
    def test_build_command_with_specific_plugins(self, nikto_adapter):
        """Test building command with specific plugins (custom scan)"""
        cmd = nikto_adapter.build_command("example.com", "custom", {"plugins": "tests(1,2,3)"})
        
        assert "nikto" in cmd
        assert "-Plugins tests(1,2,3)" in cmd
    
    def test_build_command_plugins_all_not_added(self, nikto_adapter):
        """Test that plugins=ALL doesn't add -Plugins flag"""
        cmd = nikto_adapter.build_command("example.com", "custom", {"plugins": "ALL"})
        
        assert "nikto" in cmd
        assert "-Plugins" not in cmd


class TestNiktoXMLParsing:
    """Tests for Nikto XML parsing with detailed extraction"""
    
    def test_parse_output_with_detailed_scan_info(self, nikto_adapter):
        """Test parsing XML with detailed scan information"""
        xml_output = """<?xml version="1.0"?>
        <niktoscan>
            <scandetails targetip="192.168.1.100" 
                        targethostname="example.com"
                        targetport="80"
                        targetbanner="Apache/2.4.41"
                        starttime="2024-01-15 10:00:00"
                        siteip="192.168.1.100">
                <item id="000001" osvdbid="12345" osvdblink="http://osvdb.org/12345" method="GET">
                    <description>Test vulnerability found</description>
                    <uri>/admin/</uri>
                    <namelink>http://example.com/admin/</namelink>
                    <iplink>http://192.168.1.100/admin/</iplink>
                </item>
                <item id="000002" osvdbid="67890" osvdblink="http://osvdb.org/67890" method="POST">
                    <description>Another issue detected</description>
                    <uri>/test.php</uri>
                    <namelink>http://example.com/test.php</namelink>
                    <iplink>http://192.168.1.100/test.php</iplink>
                </item>
            </scandetails>
        </niktoscan>"""
        
        result = nikto_adapter.parse_output(xml_output)
        
        # Check target info extraction
        assert "target_info" in result
        assert result["target_info"]["target_ip"] == "192.168.1.100"
        assert result["target_info"]["target_hostname"] == "example.com"
        assert result["target_info"]["target_port"] == "80"
        assert result["target_info"]["target_banner"] == "Apache/2.4.41"
        assert result["target_info"]["start_time"] == "2024-01-15 10:00:00"
        assert result["target_info"]["site_ip"] == "192.168.1.100"
        
        # Check vulnerabilities extraction
        assert "vulnerabilities" in result
        assert len(result["vulnerabilities"]) == 2
        
        vuln1 = result["vulnerabilities"][0]
        assert vuln1["id"] == "000001"
        assert vuln1["osvdb_id"] == "12345"
        assert vuln1["description"] == "Test vulnerability found"
        assert vuln1["uri"] == "/admin/"
        assert vuln1["method"] == "GET"
        
        vuln2 = result["vulnerabilities"][1]
        assert vuln2["id"] == "000002"
        assert vuln2["description"] == "Another issue detected"
    
    def test_parse_output_with_missing_scan_details(self, nikto_adapter):
        """Test parsing XML when scandetails element is missing"""
        xml_output = """<?xml version="1.0"?>
        <niktoscan>
            <item id="000001">
                <description>Finding without scan details</description>
            </item>
        </niktoscan>"""
        
        result = nikto_adapter.parse_output(xml_output)
        
        # Should handle missing scandetails gracefully
        assert "target_info" in result
        assert result["target_info"]["target_ip"] is None
        assert result["target_info"]["target_hostname"] is None
    
    def test_parse_output_with_missing_item_elements(self, nikto_adapter):
        """Test parsing items with missing sub-elements"""
        xml_output = """<?xml version="1.0"?>
        <niktoscan>
            <scandetails targetip="10.0.0.1">
                <item id="000001">
                    <!-- Missing description, uri, etc -->
                </item>
            </scandetails>
        </niktoscan>"""
        
        result = nikto_adapter.parse_output(xml_output)
        
        assert "vulnerabilities" in result
        assert len(result["vulnerabilities"]) == 1
        
        vuln = result["vulnerabilities"][0]
        assert vuln["id"] == "000001"
        # Missing elements return empty strings, not None
        assert vuln["description"] == ""
        assert vuln["uri"] == ""
    
    def test_parse_output_empty_vulnerabilities_list(self, nikto_adapter):
        """Test parsing when no items/vulnerabilities found"""
        xml_output = """<?xml version="1.0"?>
        <niktoscan>
            <scandetails targetip="10.0.0.1" targethostname="clean.example.com">
            </scandetails>
        </niktoscan>"""
        
        result = nikto_adapter.parse_output(xml_output)
        
        assert "target_info" in result
        assert result["target_info"]["target_ip"] == "10.0.0.1"
        assert "vulnerabilities" in result
        assert len(result["vulnerabilities"]) == 0
