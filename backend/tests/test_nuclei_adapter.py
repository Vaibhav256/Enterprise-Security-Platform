"""
Comprehensive tests for Nuclei Adapter

Tests Nuclei template-based vulnerability scanner adapter including 
command building, scan execution, and JSON output parsing.
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime

from services.adapters.nuclei_adapter import NucleiAdapter
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
def nuclei_adapter(mock_wsl_helper):
    """Create Nuclei adapter with mocked WSL helper"""
    return NucleiAdapter(wsl_helper=mock_wsl_helper)


class TestNucleiAdapterInitialization:
    """Tests for Nuclei adapter initialization"""

    def test_init_with_wsl_helper(self, mock_wsl_helper):
        """Test initialization with provided WSL helper"""
        adapter = NucleiAdapter(wsl_helper=mock_wsl_helper)
        assert adapter.wsl_helper == mock_wsl_helper

    @patch('services.adapters.nuclei_adapter.WSLHelper')
    def test_init_without_wsl_helper(self, mock_wsl_class):
        """Test initialization creates WSL helper if not provided"""
        mock_helper = Mock()
        mock_wsl_class.return_value = mock_helper
        
        adapter = NucleiAdapter()
        
        mock_wsl_class.assert_called_once_with(distribution="kali-linux")

    def test_get_tool_name(self, nuclei_adapter):
        """Test tool name is correct"""
        assert nuclei_adapter.get_tool_name() == "nuclei"


class TestTargetValidation:
    """Tests for target validation"""

    def test_validate_target_valid_url(self, nuclei_adapter):
        """Test validating URL target"""
        assert nuclei_adapter.validate_target("http://example.com") is True

    def test_validate_target_valid_hostname(self, nuclei_adapter):
        """Test validating hostname target"""
        assert nuclei_adapter.validate_target("example.com") is True

    def test_validate_target_valid_ip(self, nuclei_adapter):
        """Test validating IP address target"""
        assert nuclei_adapter.validate_target("192.168.1.1") is True

    def test_validate_target_empty(self, nuclei_adapter):
        """Test validating empty target"""
        assert nuclei_adapter.validate_target("") is False

    def test_validate_target_none(self, nuclei_adapter):
        """Test validating None target"""
        assert nuclei_adapter.validate_target(None) is False

    def test_validate_target_whitespace(self, nuclei_adapter):
        """Test validating whitespace-only target"""
        assert nuclei_adapter.validate_target("   ") is False


class TestDefaultOptions:
    """Tests for default options"""

    def test_get_default_options(self, nuclei_adapter):
        """Test default options structure"""
        options = nuclei_adapter.get_default_options()
        
        assert "severity" in options
        assert "templates" in options
        assert "rate_limit" in options
        assert "concurrency" in options
        assert "timeout" in options

    def test_default_severity(self, nuclei_adapter):
        """Test default severity includes all levels"""
        options = nuclei_adapter.get_default_options()
        assert "critical" in options["severity"]
        assert "high" in options["severity"]
        assert "medium" in options["severity"]

    def test_default_rate_limit(self, nuclei_adapter):
        """Test default rate limit"""
        options = nuclei_adapter.get_default_options()
        assert options["rate_limit"] == 150

    def test_default_concurrency(self, nuclei_adapter):
        """Test default concurrency"""
        options = nuclei_adapter.get_default_options()
        assert options["concurrency"] == 25


class TestCommandBuilding:
    """Tests for Nuclei command building"""

    def test_build_basic_command(self, nuclei_adapter):
        """Test building basic scan command"""
        command = nuclei_adapter.build_command("example.com", "basic")
        
        assert "nuclei" in command
        assert "-u" in command or "example.com" in command

    def test_build_command_with_url(self, nuclei_adapter):
        """Test building command with full URL"""
        command = nuclei_adapter.build_command("http://example.com", "basic")
        
        assert "http://example.com" in command

    def test_build_quick_scan_command(self, nuclei_adapter):
        """Test building quick scan command"""
        command = nuclei_adapter.build_command("example.com", "quick")
        
        assert "nuclei" in command
        # Quick scan should include severity filtering
        assert "-s" in command or "-severity" in command

    def test_build_full_scan_command(self, nuclei_adapter):
        """Test building full scan command"""
        command = nuclei_adapter.build_command("example.com", "full")
        
        assert "nuclei" in command

    def test_build_cve_scan_command(self, nuclei_adapter):
        """Test building CVE-specific scan command"""
        command = nuclei_adapter.build_command("example.com", "cve")
        
        assert "nuclei" in command
        # CVE scan should include CVE tags
        assert "cve" in command.lower() or "-tags" in command

    def test_build_custom_scan_with_templates(self, nuclei_adapter):
        """Test building custom scan with specific templates"""
        command = nuclei_adapter.build_command("example.com", "custom", {
            "templates": "cves/,exposures/"
        })
        
        assert "nuclei" in command
        assert "-t" in command or "-templates" in command

    def test_build_custom_scan_with_tags(self, nuclei_adapter):
        """Test building custom scan with specific tags"""
        command = nuclei_adapter.build_command("example.com", "custom", {
            "tags": "xss,sqli"
        })
        
        assert "nuclei" in command

    def test_build_custom_scan_with_severity(self, nuclei_adapter):
        """Test building custom scan with severity filter"""
        command = nuclei_adapter.build_command("example.com", "custom", {
            "severity": "critical,high"
        })
        
        assert "nuclei" in command

    def test_build_command_with_rate_limit(self, nuclei_adapter):
        """Test building command with rate limit"""
        command = nuclei_adapter.build_command("example.com", "custom", {
            "rate_limit": 50
        })
        
        assert "nuclei" in command

    def test_build_command_with_concurrency(self, nuclei_adapter):
        """Test building command with concurrency"""
        command = nuclei_adapter.build_command("example.com", "custom", {
            "concurrency": 10
        })
        
        assert "nuclei" in command

    def test_build_command_invalid_target(self, nuclei_adapter):
        """Test building command with invalid target raises error"""
        with pytest.raises(ValueError, match="Invalid target"):
            nuclei_adapter.build_command("", "basic")


class TestScanExecution:
    """Tests for scan execution"""

    def test_execute_scan_success(self, nuclei_adapter, mock_wsl_helper):
        """Test successful scan execution"""
        mock_result = WSLCommandResult(
            success=True,
            stdout='[{"template":"test","severity":"high"}]',
            stderr="",
            return_code=0,
            command="nuclei -u http://example.com",
            execution_time=15.5
        )
        mock_wsl_helper.execute_command.return_value = mock_result
        
        with patch.object(nuclei_adapter, 'parse_output', return_value={"vulnerabilities": []}):
            result = nuclei_adapter.execute_scan("example.com", "basic")
        
        assert result.success is True
        assert result.tool == "nuclei"
        assert result.target == "example.com"

    def test_execute_scan_no_findings(self, nuclei_adapter, mock_wsl_helper):
        """Test scan with no findings"""
        mock_result = WSLCommandResult(
            success=True,
            stdout="[]",
            stderr="",
            return_code=0,
            command="nuclei -u http://example.com",
            execution_time=10.0
        )
        mock_wsl_helper.execute_command.return_value = mock_result
        
        with patch.object(nuclei_adapter, 'parse_output', return_value={"vulnerabilities": []}):
            result = nuclei_adapter.execute_scan("example.com", "basic")
        
        assert result.success is True

    def test_execute_scan_failure(self, nuclei_adapter, mock_wsl_helper):
        """Test failed scan execution"""
        mock_result = WSLCommandResult(
            success=False,
            stdout="",
            stderr="Connection timeout",
            return_code=1,
            command="nuclei -u http://example.com",
            execution_time=5.0
        )
        mock_wsl_helper.execute_command.return_value = mock_result
        
        result = nuclei_adapter.execute_scan("example.com", "basic")
        
        assert result.success is False
        assert "failed" in result.error_message.lower()

    def test_execute_scan_with_custom_timeout(self, nuclei_adapter, mock_wsl_helper):
        """Test scan execution with custom timeout"""
        mock_result = WSLCommandResult(
            success=True,
            stdout="[]",
            stderr="",
            return_code=0,
            command="nuclei",
            execution_time=10.0
        )
        mock_wsl_helper.execute_command.return_value = mock_result
        
        with patch.object(nuclei_adapter, 'parse_output', return_value={}):
            nuclei_adapter.execute_scan("example.com", "basic", {"timeout": 1800})
        
        # Verify scan was executed
        assert mock_wsl_helper.execute_command.called

    def test_execute_scan_parse_failure(self, nuclei_adapter, mock_wsl_helper):
        """Test scan execution when parsing fails"""
        mock_result = WSLCommandResult(
            success=True,
            stdout="invalid json",
            stderr="",
            return_code=0,
            command="nuclei",
            execution_time=10.0
        )
        mock_wsl_helper.execute_command.return_value = mock_result
        
        with patch.object(nuclei_adapter, 'parse_output', side_effect=Exception("Parse error")):
            result = nuclei_adapter.execute_scan("example.com", "basic")
        
        assert result.success is True
        assert result.parsed_output is None

    def test_execute_scan_includes_metadata(self, nuclei_adapter, mock_wsl_helper):
        """Test scan result includes metadata"""
        mock_result = WSLCommandResult(
            success=True,
            stdout="[]",
            stderr="",
            return_code=0,
            command="nuclei",
            execution_time=10.0
        )
        mock_wsl_helper.execute_command.return_value = mock_result
        
        with patch.object(nuclei_adapter, 'parse_output', return_value={}):
            result = nuclei_adapter.execute_scan("example.com", "cve")
        
        assert "scan_type" in result.scan_metadata
        assert result.scan_metadata["scan_type"] == "cve"


class TestOutputParsing:
    """Tests for output parsing"""

    def test_parse_results_calls_parse_output(self, nuclei_adapter):
        """Test parse_results is alias for parse_output"""
        with patch.object(nuclei_adapter, 'parse_output', return_value={"test": "data"}) as mock_parse:
            result = nuclei_adapter.parse_results('{"key": "value"}')
            
            mock_parse.assert_called_once_with('{"key": "value"}')
            assert result == {"test": "data"}

    def test_parse_output_valid_json(self, nuclei_adapter):
        """Test parsing valid JSON output"""
        json_output = '{"template-id":"test","info":{"name":"test","severity":"high"},"host":"http://example.com"}'
        
        result = nuclei_adapter.parse_output(json_output)
        
        # Should return a dictionary with findings
        assert isinstance(result, dict)
        assert "findings" in result
        assert "total_findings" in result

    def test_parse_output_empty_array(self, nuclei_adapter):
        """Test parsing empty output"""
        result = nuclei_adapter.parse_output("")
        
        # Should return dict with empty findings
        assert isinstance(result, dict)
        assert "findings" in result
        assert result["total_findings"] == 0

    def test_parse_output_invalid_json(self, nuclei_adapter):
        """Test parsing invalid JSON returns empty dict or None"""
        result = nuclei_adapter.parse_output("not json at all")
        
        # Should handle gracefully
        assert result is None or result == {} or isinstance(result, dict)

    def test_parse_output_empty_string(self, nuclei_adapter):
        """Test parsing empty output"""
        result = nuclei_adapter.parse_output("")
        
        # Should handle gracefully
        assert result is None or result == {} or isinstance(result, dict)


class TestEdgeCases:
    """Tests for edge cases"""

    def test_build_command_with_ipv6(self, nuclei_adapter):
        """Test building command with IPv6 address"""
        command = nuclei_adapter.build_command("2001:db8::1", "basic")
        
        assert "nuclei" in command
        assert "2001:db8::1" in command

    def test_build_command_with_port_in_url(self, nuclei_adapter):
        """Test building command with port in URL"""
        command = nuclei_adapter.build_command("http://example.com:8080", "basic")
        
        assert "example.com" in command
        assert "8080" in command

    def test_execute_scan_different_scan_types(self, nuclei_adapter, mock_wsl_helper):
        """Test executing different scan types"""
        mock_result = WSLCommandResult(
            success=True,
            stdout="[]",
            stderr="",
            return_code=0,
            command="nuclei",
            execution_time=10.0
        )
        mock_wsl_helper.execute_command.return_value = mock_result
        
        scan_types = ["basic", "quick", "full", "cve", "custom"]
        
        with patch.object(nuclei_adapter, 'parse_output', return_value={}):
            for scan_type in scan_types:
                result = nuclei_adapter.execute_scan("example.com", scan_type)
                assert result.success is True
                assert result.scan_metadata["scan_type"] == scan_type

    def test_build_command_with_multiple_tags(self, nuclei_adapter):
        """Test building command with multiple tags"""
        command = nuclei_adapter.build_command("example.com", "custom", {
            "tags": "xss,sqli,rce"
        })
        
        assert "nuclei" in command

    def test_build_command_with_verbose_flag(self, nuclei_adapter):
        """Test building command with verbose flag"""
        command = nuclei_adapter.build_command("example.com", "custom", {
            "verbose": True
        })
        
        assert "nuclei" in command

    def test_build_command_with_silent_flag(self, nuclei_adapter):
        """Test building command with silent flag"""
        command = nuclei_adapter.build_command("example.com", "custom", {
            "silent": True
        })
        
        assert "nuclei" in command


class TestNucleiAdditionalScanTypes:
    """Tests for additional Nuclei scan types"""
    
    def test_build_misconfig_scan_command(self, nuclei_adapter):
        """Test building misconfiguration scan command"""
        cmd = nuclei_adapter.build_command("example.com", "misconfig", {})
        
        assert "nuclei" in cmd
        assert "-tags" in cmd
        assert "misconfig" in cmd
        assert "exposure" in cmd
        assert "config" in cmd
        assert "-severity" in cmd
    
    def test_build_exposed_scan_command(self, nuclei_adapter):
        """Test building exposed panels scan command"""
        cmd = nuclei_adapter.build_command("example.com", "exposed", {})
        
        assert "nuclei" in cmd
        assert "-tags" in cmd
        assert "exposure" in cmd
        assert "panel" in cmd
        assert "login" in cmd
        assert "default-login" in cmd


class TestNucleiAdditionalOptions:
    """Tests for additional Nuclei options"""
    
    def test_build_command_with_follow_redirects(self, nuclei_adapter):
        """Test building command with follow redirects option"""
        cmd = nuclei_adapter.build_command("example.com", "custom", {
            "follow_host_redirects": True
        })
        
        assert "nuclei" in cmd
        assert "-follow-host-redirects" in cmd
    
    def test_build_command_with_max_redirects(self, nuclei_adapter):
        """Test building command with max redirects option"""
        cmd = nuclei_adapter.build_command("example.com", "custom", {
            "max_redirects": 5
        })
        
        assert "nuclei" in cmd
        assert "-max-redirects" in cmd
        assert "5" in cmd
    
    def test_build_command_with_silent_option(self, nuclei_adapter):
        """Test command building with silent mode"""
        cmd = nuclei_adapter.build_command("example.com", "custom", {
            "silent": True
        })
        
        assert "nuclei" in cmd
        assert "-silent" in cmd
    
    def test_build_command_with_verbose_option(self, nuclei_adapter):
        """Test command building with verbose mode"""
        cmd = nuclei_adapter.build_command("example.com", "custom", {
            "verbose": True
        })
        
        assert "nuclei" in cmd
        assert "-verbose" in cmd
    
    def test_build_command_with_debug_option(self, nuclei_adapter):
        """Test command building with debug mode"""
        cmd = nuclei_adapter.build_command("example.com", "custom", {
            "debug": True
        })
        
        assert "nuclei" in cmd
        assert "-debug" in cmd
    
    def test_build_command_with_additional_flags(self, nuclei_adapter):
        """Test command building with additional flags"""
        cmd = nuclei_adapter.build_command("example.com", "custom", {
            "additional_flags": "-no-color -stats"
        })
        
        assert "nuclei" in cmd
        assert "-no-color -stats" in cmd


class TestNucleiJSONParsingWithClassification:
    """Tests for Nuclei JSON parsing with CVE/CWE classification"""
    
    def test_parse_output_with_cve_classification(self, nuclei_adapter):
        """Test parsing output with CVE classification"""
        json_output = """{"template-id": "CVE-2021-12345", "info": {"name": "Test Vulnerability", "severity": "high", "tags": ["cve", "apache"], "classification": {"cve-id": ["CVE-2021-12345"]}}, "type": "http", "host": "http://example.com", "matched-at": "http://example.com/admin", "extracted-results": ["admin_panel"], "timestamp": "2024-01-15T10:00:00Z"}"""
        
        result = nuclei_adapter.parse_output(json_output)
        
        assert "findings" in result
        assert len(result["findings"]) == 1
        
        finding = result["findings"][0]
        assert finding["template_id"] == "CVE-2021-12345"
        assert finding["cve_id"] == ["CVE-2021-12345"]
    
    def test_parse_output_with_cwe_classification(self, nuclei_adapter):
        """Test parsing output with CWE classification"""
        json_output = """{"template-id": "sql-injection-test", "info": {"name": "SQL Injection", "severity": "critical", "tags": ["sqli", "injection"], "classification": {"cwe-id": ["CWE-89"]}}, "type": "http", "host": "http://example.com", "matched-at": "http://example.com/search?q=test", "timestamp": "2024-01-15T10:00:00Z"}"""
        
        result = nuclei_adapter.parse_output(json_output)
        
        assert "findings" in result
        finding = result["findings"][0]
        assert finding["cwe_id"] == ["CWE-89"]
    
    def test_parse_output_statistics_aggregation(self, nuclei_adapter):
        """Test statistics aggregation from findings"""
        # JSON Lines format - one JSON per line
        json_output = """{"template-id": "test-critical", "info": {"name": "Critical Issue", "severity": "critical", "tags": ["xss", "injection"]}, "type": "http", "host": "http://example.com", "matched-at": "http://example.com/page1"}
{"template-id": "test-high", "info": {"name": "High Issue", "severity": "high", "tags": ["xss", "rce"]}, "type": "http", "host": "http://example.com", "matched-at": "http://example.com/page2"}
{"template-id": "test-critical", "info": {"name": "Another Critical", "severity": "critical", "tags": ["sqli"]}, "type": "http", "host": "http://example.com", "matched-at": "http://example.com/page3"}"""
        
        result = nuclei_adapter.parse_output(json_output)
        
        # Check severity counts
        assert "severity_counts" in result
        assert result["severity_counts"]["critical"] == 2
        assert result["severity_counts"]["high"] == 1
        
        # Check template counts
        assert "template_counts" in result
        assert result["template_counts"]["test-critical"] == 2
        assert result["template_counts"]["test-high"] == 1
        
        # Check tag counts
        assert "tag_counts" in result
        assert result["tag_counts"]["xss"] == 2
        assert result["tag_counts"]["injection"] == 1
        assert result["tag_counts"]["rce"] == 1
        assert result["tag_counts"]["sqli"] == 1
