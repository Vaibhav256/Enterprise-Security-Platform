"""
Tests for base adapter and scan result data structures
"""
import pytest
from unittest.mock import Mock, MagicMock, patch
from services.adapters.base_adapter import BaseAdapter, ScanResult


class TestScanResult:
    """Test ScanResult dataclass"""
    
    def test_scan_result_success(self):
        """Test creating successful scan result"""
        result = ScanResult(
            success=True,
            tool="nmap",
            target="192.168.1.1",
            raw_output="<xml>test</xml>",
            execution_time=1.5
        )
        assert result.success is True
        assert result.tool == "nmap"
        assert result.target == "192.168.1.1"
        assert result.raw_output == "<xml>test</xml>"
        assert result.execution_time == 1.5
        assert result.parsed_output is None
        assert result.error_message is None
    
    def test_scan_result_failure(self):
        """Test creating failed scan result"""
        result = ScanResult(
            success=False,
            tool="nmap",
            target="192.168.1.1",
            raw_output="",
            error_message="Connection timeout",
            execution_time=30.0
        )
        assert result.success is False
        assert result.error_message == "Connection timeout"
        assert result.raw_output == ""
    
    def test_scan_result_with_parsed_output(self):
        """Test scan result with parsed data"""
        parsed_data = {
            "hosts": [{"ip": "192.168.1.1", "status": "up"}],
            "summary": {"total": 1}
        }
        result = ScanResult(
            success=True,
            tool="nmap",
            target="192.168.1.1",
            raw_output="<xml>...</xml>",
            parsed_output=parsed_data
        )
        assert result.parsed_output == parsed_data
        assert result.parsed_output["hosts"][0]["ip"] == "192.168.1.1"
    
    def test_scan_result_with_metadata(self):
        """Test scan result with scan metadata"""
        metadata = {
            "start_time": "2025-10-28T10:00:00",
            "scan_type": "full",
            "options": {"verbose": True}
        }
        result = ScanResult(
            success=True,
            tool="nmap",
            target="192.168.1.1",
            raw_output="output",
            scan_metadata=metadata
        )
        assert result.scan_metadata == metadata
        assert result.scan_metadata["scan_type"] == "full"


class MockAdapter(BaseAdapter):
    """Mock adapter for testing base adapter functionality"""
    
    def get_tool_name(self) -> str:
        return "mock_tool"
    
    def get_default_options(self) -> dict:
        return {"timeout": 300, "verbose": False}
    
    def build_command(self, target: str, scan_type: str, options: dict) -> str:
        return f"mock_tool -t {target} --type {scan_type}"
    
    def parse_results(self, raw_output: str) -> dict:
        return {"status": "parsed", "output": raw_output}
    
    def get_version_command(self) -> str:
        return "mock_tool --version"
    
    def validate_target(self, target: str) -> bool:
        """Validate target format"""
        return len(target) > 0


class TestBaseAdapter:
    """Test BaseAdapter abstract base class"""
    
    @patch('services.adapters.base_adapter.BaseAdapter._validate_tool')
    def test_adapter_initialization(self, mock_validate):
        """Test adapter initialization"""
        mock_wsl = Mock()
        mock_validate.return_value = True
        
        adapter = MockAdapter(mock_wsl)
        
        assert adapter.wsl_helper == mock_wsl
        assert adapter.tool_name == "mock_tool"
        assert adapter.logger is not None
        mock_validate.assert_called_once()
    
    @patch('services.adapters.base_adapter.BaseAdapter._validate_tool')
    def test_get_tool_name(self, mock_validate):
        """Test getting tool name"""
        mock_wsl = Mock()
        mock_validate.return_value = True
        
        adapter = MockAdapter(mock_wsl)
        assert adapter.get_tool_name() == "mock_tool"
    
    @patch('services.adapters.base_adapter.BaseAdapter._validate_tool')
    def test_get_default_options(self, mock_validate):
        """Test getting default options"""
        mock_wsl = Mock()
        mock_validate.return_value = True
        
        adapter = MockAdapter(mock_wsl)
        options = adapter.get_default_options()
        
        assert isinstance(options, dict)
        assert "timeout" in options
        assert options["timeout"] == 300
        assert "verbose" in options
    
    @patch('services.adapters.base_adapter.BaseAdapter._validate_tool')
    def test_build_command(self, mock_validate):
        """Test building scan command"""
        mock_wsl = Mock()
        mock_validate.return_value = True
        
        adapter = MockAdapter(mock_wsl)
        cmd = adapter.build_command(
            target="192.168.1.1",
            scan_type="basic",
            options={}
        )
        
        assert "mock_tool" in cmd
        assert "192.168.1.1" in cmd
        assert "basic" in cmd
    
    @patch('services.adapters.base_adapter.BaseAdapter._validate_tool')
    def test_parse_results(self, mock_validate):
        """Test parsing scan results"""
        mock_wsl = Mock()
        mock_validate.return_value = True
        
        adapter = MockAdapter(mock_wsl)
        raw_output = "test output data"
        parsed = adapter.parse_results(raw_output)
        
        assert isinstance(parsed, dict)
        assert parsed["status"] == "parsed"
        assert parsed["output"] == raw_output
    
    @patch('services.adapters.base_adapter.BaseAdapter._validate_tool')
    def test_get_version_command(self, mock_validate):
        """Test getting version command"""
        mock_wsl = Mock()
        mock_validate.return_value = True
        
        adapter = MockAdapter(mock_wsl)
        version_cmd = adapter.get_version_command()
        
        assert "mock_tool" in version_cmd
        assert "--version" in version_cmd


class TestBaseAdapterAbstract:
    """Test that BaseAdapter enforces abstract methods"""
    
    def test_cannot_instantiate_base_adapter(self):
        """Test that BaseAdapter cannot be instantiated directly"""
        mock_wsl = Mock()
        
        with pytest.raises(TypeError):
            # This should fail because BaseAdapter is abstract
            adapter = BaseAdapter(mock_wsl)
    
    def test_must_implement_get_tool_name(self):
        """Test that subclass must implement get_tool_name"""
        
        class IncompleteAdapter(BaseAdapter):
            def get_default_options(self):
                return {}
            def build_command(self, target, scan_type, options):
                return "cmd"
            def parse_results(self, raw_output):
                return {}
            def get_version_command(self):
                return "version"
            def validate_target(self, target):
                return True
        
        mock_wsl = Mock()
        
        with pytest.raises(TypeError):
            # Missing get_tool_name implementation
            adapter = IncompleteAdapter(mock_wsl)


class TestScanResultEdgeCases:
    """Test edge cases for ScanResult"""
    
    def test_empty_raw_output(self):
        """Test scan result with empty output"""
        result = ScanResult(
            success=True,
            tool="test",
            target="target",
            raw_output=""
        )
        assert result.raw_output == ""
        assert result.success is True
    
    def test_very_large_output(self):
        """Test scan result with large output"""
        large_output = "x" * 1000000  # 1MB of data
        result = ScanResult(
            success=True,
            tool="test",
            target="target",
            raw_output=large_output
        )
        assert len(result.raw_output) == 1000000
    
    def test_special_characters_in_output(self):
        """Test scan result with special characters"""
        special_output = "Test\n\t<xml>&nbsp;ü€ñ"
        result = ScanResult(
            success=True,
            tool="test",
            target="target",
            raw_output=special_output
        )
        assert result.raw_output == special_output
    
    def test_zero_execution_time(self):
        """Test scan result with zero execution time"""
        result = ScanResult(
            success=True,
            tool="test",
            target="target",
            raw_output="output",
            execution_time=0.0
        )
        assert result.execution_time == 0.0
    
    def test_negative_execution_time(self):
        """Test scan result with negative time (edge case)"""
        result = ScanResult(
            success=True,
            tool="test",
            target="target",
            raw_output="output",
            execution_time=-1.0
        )
        # Should still accept it, though it's invalid
        assert result.execution_time == -1.0
    
    def test_complex_nested_parsed_output(self):
        """Test deeply nested parsed output structure"""
        complex_data = {
            "level1": {
                "level2": {
                    "level3": {
                        "data": [1, 2, 3],
                        "nested_list": [
                            {"id": 1, "value": "a"},
                            {"id": 2, "value": "b"}
                        ]
                    }
                }
            }
        }
        result = ScanResult(
            success=True,
            tool="test",
            target="target",
            raw_output="output",
            parsed_output=complex_data
        )
        assert result.parsed_output["level1"]["level2"]["level3"]["data"] == [1, 2, 3]
        assert len(result.parsed_output["level1"]["level2"]["level3"]["nested_list"]) == 2


class TestBaseAdapterValidation:
    """Test base adapter validation methods"""
    
    def test_validate_tool_during_init_success(self):
        """Test tool validation happens during initialization"""
        mock_wsl = Mock()
        mock_wsl.check_tool_availability.return_value = True
        mock_wsl.get_tool_version.return_value = "v1.0.0"
        
        class TestAdapter(BaseAdapter):
            def get_tool_name(self):
                return "testtool"
            def validate_target(self, target):
                return True
            def build_command(self, target, scan_type, options):
                return "test"
            def parse_results(self, output):
                return {}
            def get_default_options(self):
                return {}
        
        # Tool validation happens in __init__
        adapter = TestAdapter(wsl_helper=mock_wsl)
        
        # Verify tool was validated
        assert adapter.tool_name == "testtool"
        mock_wsl.check_tool_availability.assert_called_with("testtool")
    
    def test_validate_tool_during_init_not_found(self):
        """Test tool validation fails during initialization when tool not found"""
        mock_wsl = Mock()
        mock_wsl.check_tool_availability.return_value = False
        
        class TestAdapter(BaseAdapter):
            def get_tool_name(self):
                return "missingtool"
            def validate_target(self, target):
                return True
            def build_command(self, target, scan_type, options):
                return "test"
            def parse_results(self, output):
                return {}
            def get_default_options(self):
                return {}
        
        # Should raise during __init__
        with pytest.raises(RuntimeError, match="not available in WSL"):
            adapter = TestAdapter(wsl_helper=mock_wsl)
    
    def test_get_version_flag_default(self):
        """Test get_version_flag returns default"""
        mock_wsl = Mock()
        mock_wsl.check_tool_availability.return_value = True
        mock_wsl.get_tool_version.return_value = "v1.0.0"
        
        class TestAdapter(BaseAdapter):
            def get_tool_name(self):
                return "testtool"
            def validate_target(self, target):
                return True
            def build_command(self, target, scan_type, options):
                return "test"
            def parse_results(self, output):
                return {}
            def get_default_options(self):
                return {}
        
        adapter = TestAdapter(wsl_helper=mock_wsl)
        
        flag = adapter.get_version_flag()
        
        assert flag == "--version"


class TestBaseAdapterExecuteScan:
    """Test base adapter execute_scan method"""
    
    def test_execute_scan_invalid_target(self):
        """Test execute_scan with invalid target"""
        mock_wsl = Mock()
        
        class TestAdapter(BaseAdapter):
            def get_tool_name(self):
                return "testtool"
            def validate_target(self, target):
                return False  # Always invalid
            def build_command(self, target, scan_type, options):
                return "test command"
            def parse_results(self, output):
                return {}
            def get_default_options(self):
                return {}
        
        adapter = TestAdapter(wsl_helper=mock_wsl)
        
        result = adapter.execute_scan("invalid-target")
        
        assert result.success is False
        assert "Invalid target format" in result.error_message
    
    def test_execute_scan_command_failure(self):
        """Test execute_scan when command execution fails"""
        mock_wsl = Mock()
        mock_result = Mock()
        mock_result.success = False
        mock_result.stdout = "partial output"
        mock_result.stderr = "error occurred"
        mock_wsl.execute_command.return_value = mock_result
        
        class TestAdapter(BaseAdapter):
            def get_tool_name(self):
                return "testtool"
            def validate_target(self, target):
                return True
            def build_command(self, target, scan_type, options):
                return "test command"
            def parse_results(self, output):
                return {}
            def get_default_options(self):
                return {}
        
        adapter = TestAdapter(wsl_helper=mock_wsl)
        
        result = adapter.execute_scan("192.168.1.1")
        
        assert result.success is False
        assert result.error_message == "error occurred"
        assert result.raw_output == "partial output"
    
    def test_execute_scan_parse_error(self):
        """Test execute_scan when parsing fails"""
        mock_wsl = Mock()
        mock_result = Mock()
        mock_result.success = True
        mock_result.stdout = "valid output"
        mock_result.stderr = ""
        mock_wsl.execute_command.return_value = mock_result
        
        class TestAdapter(BaseAdapter):
            def get_tool_name(self):
                return "testtool"
            def validate_target(self, target):
                return True
            def build_command(self, target, scan_type, options):
                return "test command"
            def parse_results(self, output):
                raise ValueError("Parse failed")
            def get_default_options(self):
                return {}
        
        adapter = TestAdapter(wsl_helper=mock_wsl)
        
        result = adapter.execute_scan("192.168.1.1")
        
        # Should succeed but with None parsed_output
        assert result.success is True
        assert result.parsed_output is None
        assert result.raw_output == "valid output"
    
    def test_execute_scan_exception_during_execution(self):
        """Test execute_scan when exception occurs during execution"""
        mock_wsl = Mock()
        mock_wsl.execute_command.side_effect = Exception("Execution failed")
        
        class TestAdapter(BaseAdapter):
            def get_tool_name(self):
                return "testtool"
            def validate_target(self, target):
                return True
            def build_command(self, target, scan_type, options):
                return "test command"
            def parse_results(self, output):
                return {}
            def get_default_options(self):
                return {}
        
        adapter = TestAdapter(wsl_helper=mock_wsl)
        
        result = adapter.execute_scan("192.168.1.1")
        
        assert result.success is False
        assert "Execution failed" in result.error_message
    
    def test_execute_scan_with_custom_timeout(self):
        """Test execute_scan with custom timeout"""
        mock_wsl = Mock()
        mock_result = Mock()
        mock_result.success = True
        mock_result.stdout = "output"
        mock_result.stderr = ""
        mock_wsl.execute_command.return_value = mock_result
        
        class TestAdapter(BaseAdapter):
            def get_tool_name(self):
                return "testtool"
            def validate_target(self, target):
                return True
            def build_command(self, target, scan_type, options):
                return "test command"
            def parse_results(self, output):
                return {"data": "parsed"}
            def get_default_options(self):
                return {}
            def get_default_timeout(self):
                return 300
        
        adapter = TestAdapter(wsl_helper=mock_wsl)
        
        result = adapter.execute_scan("192.168.1.1", timeout=600)
        
        assert result.success is True
        # Verify timeout was passed
        call_args = mock_wsl.execute_command.call_args
        assert call_args[1]['timeout'] == 600
    
    def test_execute_scan_uses_default_timeout(self):
        """Test execute_scan uses default timeout when not specified"""
        mock_wsl = Mock()
        mock_result = Mock()
        mock_result.success = True
        mock_result.stdout = "output"
        mock_result.stderr = ""
        mock_wsl.execute_command.return_value = mock_result
        
        class TestAdapter(BaseAdapter):
            def get_tool_name(self):
                return "testtool"
            def validate_target(self, target):
                return True
            def build_command(self, target, scan_type, options):
                return "test command"
            def parse_results(self, output):
                return {}
            def get_default_options(self):
                return {}
            def get_default_timeout(self):
                return 450
        
        adapter = TestAdapter(wsl_helper=mock_wsl)
        
        result = adapter.execute_scan("192.168.1.1")
        
        assert result.success is True
        # Verify default timeout was used
        call_args = mock_wsl.execute_command.call_args
        assert call_args[1]['timeout'] == 450
    
    def test_execute_scan_merges_options(self):
        """Test execute_scan merges custom options with defaults"""
        mock_wsl = Mock()
        mock_result = Mock()
        mock_result.success = True
        mock_result.stdout = "output"
        mock_result.stderr = ""
        mock_wsl.execute_command.return_value = mock_result
        
        class TestAdapter(BaseAdapter):
            def get_tool_name(self):
                return "testtool"
            def validate_target(self, target):
                return True
            def build_command(self, target, scan_type, options):
                self.captured_options = options
                return "test command"
            def parse_results(self, output):
                return {}
            def get_default_options(self):
                return {"port": 80, "ssl": False, "timeout": 300}
        
        adapter = TestAdapter(wsl_helper=mock_wsl)
        
        result = adapter.execute_scan("192.168.1.1", options={"ssl": True, "verbose": True})
        
        assert result.success is True
        # Check options were merged
        assert adapter.captured_options["port"] == 80  # default
        assert adapter.captured_options["ssl"] is True  # overridden
        assert adapter.captured_options["verbose"] is True  # added
        assert adapter.captured_options["timeout"] == 300  # default
    
    def test_execute_scan_includes_metadata(self):
        """Test execute_scan includes scan metadata in result"""
        mock_wsl = Mock()
        mock_result = Mock()
        mock_result.success = True
        mock_result.stdout = "output"
        mock_result.stderr = ""
        mock_wsl.execute_command.return_value = mock_result
        
        class TestAdapter(BaseAdapter):
            def get_tool_name(self):
                return "testtool"
            def validate_target(self, target):
                return True
            def build_command(self, target, scan_type, options):
                return "test command"
            def parse_results(self, output):
                return {}
            def get_default_options(self):
                return {}
        
        adapter = TestAdapter(wsl_helper=mock_wsl)
        
        result = adapter.execute_scan("192.168.1.1", scan_type="full", options={"fast": True})
        
        assert result.success is True
        assert result.scan_metadata is not None
        assert result.scan_metadata["scan_type"] == "full"
        assert result.scan_metadata["options"]["fast"] is True
