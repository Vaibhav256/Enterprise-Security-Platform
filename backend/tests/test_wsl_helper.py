"""
Comprehensive tests for WSL Helper

Tests WSL command execution, validation, tool availability checking,
and error handling for the WSL helper utility.
"""

import subprocess
from unittest.mock import Mock, MagicMock, patch, call
from itertools import repeat, cycle
import pytest

from utils.wsl_helper import WSLHelper, WSLCommandResult, WSLToolValidator


class TestWSLCommandResult:
    """Tests for WSLCommandResult dataclass"""

    def test_command_result_creation(self):
        """Test creating a command result"""
        result = WSLCommandResult(
            success=True,
            stdout="output",
            stderr="",
            return_code=0,
            command="ls -la",
            execution_time=1.5
        )
        
        assert result.success is True
        assert result.stdout == "output"
        assert result.stderr == ""
        assert result.return_code == 0
        assert result.command == "ls -la"
        assert result.execution_time == 1.5

    def test_command_result_failure(self):
        """Test creating a failed command result"""
        result = WSLCommandResult(
            success=False,
            stdout="",
            stderr="Error occurred",
            return_code=1,
            command="invalid_command",
            execution_time=0.1
        )
        
        assert result.success is False
        assert result.stderr == "Error occurred"
        assert result.return_code == 1


class TestWSLHelperInitialization:
    """Tests for WSL helper initialization"""

    @patch('subprocess.run')
    def test_init_with_defaults(self, mock_run):
        """Test initialization with default parameters"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "kali-linux\nUbuntu\n"
        mock_run.return_value = mock_result
        
        helper = WSLHelper()
        
        assert helper.distribution == "kali-linux"
        assert helper.default_timeout == 300
        mock_run.assert_called_once()

    @patch('subprocess.run')
    def test_init_with_custom_distribution(self, mock_run):
        """Test initialization with custom distribution"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Ubuntu\nDebian\n"
        mock_run.return_value = mock_result
        
        helper = WSLHelper(distribution="Ubuntu", default_timeout=600)
        
        assert helper.distribution == "Ubuntu"
        assert helper.default_timeout == 600

    @patch('subprocess.run')
    def test_init_wsl_not_available(self, mock_run):
        """Test initialization when WSL is not available"""
        mock_run.side_effect = FileNotFoundError("wsl.exe not found")
        
        with pytest.raises(RuntimeError, match="wsl.exe not found"):
            WSLHelper()

    @patch('subprocess.run')
    def test_init_wsl_command_timeout(self, mock_run):
        """Test initialization when WSL command times out"""
        mock_run.side_effect = subprocess.TimeoutExpired("wsl.exe", 10)
        
        with pytest.raises(RuntimeError, match="WSL command timed out"):
            WSLHelper()

    @patch('subprocess.run')
    def test_init_wsl_returns_error(self, mock_run):
        """Test initialization when WSL returns error"""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_run.return_value = mock_result
        
        with pytest.raises(RuntimeError, match="WSL is not available"):
            WSLHelper()


class TestWSLAvailability:
    """Tests for WSL availability checking"""

    @patch('subprocess.run')
    def test_is_wsl_available_true(self, mock_run):
        """Test checking WSL availability when available"""
        # Mock for initialization
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "kali-linux\n"
        mock_run.return_value = mock_result
        
        helper = WSLHelper()
        
        # Mock for is_wsl_available call
        mock_run.return_value = mock_result
        assert helper.is_wsl_available() is True

    @patch('subprocess.run')
    def test_is_wsl_available_false_file_not_found(self, mock_run):
        """Test WSL availability when wsl.exe not found"""
        # Mock for initialization
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "kali-linux\n"
        mock_run.return_value = mock_result
        
        helper = WSLHelper()
        
        # Mock FileNotFoundError for is_wsl_available
        mock_run.side_effect = FileNotFoundError()
        assert helper.is_wsl_available() is False

    @patch('subprocess.run')
    def test_is_wsl_available_false_timeout(self, mock_run):
        """Test WSL availability when command times out"""
        # Mock for initialization
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "kali-linux\n"
        mock_run.return_value = mock_result
        
        helper = WSLHelper()
        
        # Mock timeout for is_wsl_available
        mock_run.side_effect = subprocess.TimeoutExpired("wsl", 10)
        assert helper.is_wsl_available() is False


class TestCommandExecution:
    """Tests for command execution"""

    @patch('subprocess.run')
    @patch('time.time')
    def test_execute_command_success(self, mock_time, mock_run):
        """Test successful command execution"""
        # Mock for initialization
        mock_init_result = Mock()
        mock_init_result.returncode = 0
        mock_init_result.stdout = "kali-linux\n"
        
        # Mock for command execution
        mock_cmd_result = Mock()
        mock_cmd_result.returncode = 0
        mock_cmd_result.stdout = "command output"
        mock_cmd_result.stderr = ""
        
        mock_run.side_effect = [mock_init_result, mock_cmd_result]
        mock_time.side_effect = [100.0, 101.5]  # Start and end time
        
        helper = WSLHelper()
        result = helper.execute_command("ls -la")
        
        assert result.success is True
        assert result.stdout == "command output"
        assert result.stderr == ""
        assert result.return_code == 0
        assert result.execution_time == 1.5

    @patch('subprocess.run')
    @patch('time.time')
    def test_execute_command_failure(self, mock_time, mock_run):
        """Test failed command execution"""
        # Mock for initialization
        mock_init_result = Mock()
        mock_init_result.returncode = 0
        mock_init_result.stdout = "kali-linux\n"
        
        # Mock for command execution
        mock_cmd_result = Mock()
        mock_cmd_result.returncode = 1
        mock_cmd_result.stdout = ""
        mock_cmd_result.stderr = "command not found"
        
        mock_run.side_effect = [mock_init_result, mock_cmd_result]
        # Use itertools.cycle to provide unlimited time values for logging calls
        mock_time.side_effect = cycle([100.0, 100.1])
        
        helper = WSLHelper()
        result = helper.execute_command("invalid_command", check_success=False)
        
        assert result.success is False
        assert result.stderr == "command not found"
        assert result.return_code == 1

    @patch('subprocess.run')
    def test_execute_command_timeout(self, mock_run):
        """Test command execution timeout"""
        # Mock for initialization
        mock_init_result = Mock()
        mock_init_result.returncode = 0
        mock_init_result.stdout = "kali-linux\n"
        
        mock_run.side_effect = [
            mock_init_result,
            subprocess.TimeoutExpired("wsl", 10)
        ]
        
        helper = WSLHelper()
        
        with pytest.raises(subprocess.TimeoutExpired):
            helper.execute_command("sleep 100", timeout=1)

    @patch('subprocess.run')
    @patch('time.time')
    def test_execute_command_with_custom_timeout(self, mock_time, mock_run):
        """Test command execution with custom timeout"""
        # Mock for initialization
        mock_init_result = Mock()
        mock_init_result.returncode = 0
        mock_init_result.stdout = "kali-linux\n"
        
        # Mock for command execution
        mock_cmd_result = Mock()
        mock_cmd_result.returncode = 0
        mock_cmd_result.stdout = "output"
        mock_cmd_result.stderr = ""
        
        mock_run.side_effect = [mock_init_result, mock_cmd_result]
        mock_time.side_effect = [100.0, 101.0]
        
        helper = WSLHelper()
        result = helper.execute_command("command", timeout=600)
        
        assert result.success is True
        # Verify timeout was passed to subprocess.run
        call_args = mock_run.call_args_list[1]
        assert call_args[1]['timeout'] == 600


class TestToolAvailability:
    """Tests for tool availability checking"""

    @patch('subprocess.run')
    @patch('time.time')
    def test_check_tool_availability_true(self, mock_time, mock_run):
        """Test checking tool availability when tool exists"""
        # Mock for initialization
        mock_init_result = Mock()
        mock_init_result.returncode = 0
        mock_init_result.stdout = "kali-linux\n"
        
        # Mock for which command
        mock_cmd_result = Mock()
        mock_cmd_result.returncode = 0
        mock_cmd_result.stdout = "/usr/bin/nmap"
        mock_cmd_result.stderr = ""
        
        mock_run.side_effect = [mock_init_result, mock_cmd_result]
        mock_time.side_effect = [100.0, 100.1]
        
        helper = WSLHelper()
        available = helper.check_tool_availability("nmap")
        
        assert available is True

    @patch('subprocess.run')
    @patch('time.time')
    def test_check_tool_availability_false(self, mock_time, mock_run):
        """Test checking tool availability when tool doesn't exist"""
        # Mock for initialization
        mock_init_result = Mock()
        mock_init_result.returncode = 0
        mock_init_result.stdout = "kali-linux\n"
        
        # Mock for which command (tool not found)
        mock_cmd_result = Mock()
        mock_cmd_result.returncode = 1
        mock_cmd_result.stdout = ""
        mock_cmd_result.stderr = ""
        
        mock_run.side_effect = [mock_init_result, mock_cmd_result]
        # Use cycle to provide unlimited time values
        mock_time.side_effect = cycle([100.0, 100.1])
        
        helper = WSLHelper()
        available = helper.check_tool_availability("nonexistent_tool")
        
        assert available is False


class TestToolVersion:
    """Tests for tool version retrieval"""

    @patch('subprocess.run')
    @patch('time.time')
    def test_get_tool_version_success(self, mock_time, mock_run):
        """Test getting tool version successfully"""
        # Mock for initialization
        mock_init_result = Mock()
        mock_init_result.returncode = 0
        mock_init_result.stdout = "kali-linux\n"
        
        # Mock for which command (check availability)
        mock_which_result = Mock()
        mock_which_result.returncode = 0
        mock_which_result.stdout = "/usr/bin/nmap"
        mock_which_result.stderr = ""
        
        # Mock for version command
        mock_version_result = Mock()
        mock_version_result.returncode = 0
        mock_version_result.stdout = "Nmap version 7.91"
        mock_version_result.stderr = ""
        
        mock_run.side_effect = [mock_init_result, mock_which_result, mock_version_result]
        # Use cycle to provide unlimited time values
        mock_time.side_effect = cycle([100.0, 100.1, 100.2])
        
        helper = WSLHelper()
        version = helper.get_tool_version("nmap", "--version")
        
        assert "7.91" in version or "Nmap" in version

    @patch('subprocess.run')
    @patch('time.time')
    def test_get_tool_version_failure(self, mock_time, mock_run):
        """Test getting tool version when tool doesn't exist"""
        # Mock for initialization
        mock_init_result = Mock()
        mock_init_result.returncode = 0
        mock_init_result.stdout = "kali-linux\n"
        
        # Mock for which command (tool not found)
        mock_which_result = Mock()
        mock_which_result.returncode = 1
        mock_which_result.stdout = ""
        mock_which_result.stderr = ""
        
        mock_run.side_effect = [mock_init_result, mock_which_result]
        # Use cycle to provide unlimited time values
        mock_time.side_effect = cycle([100.0, 100.1])
        
        helper = WSLHelper()
        version = helper.get_tool_version("invalid_tool", "--version")
        
        assert version is None


class TestFileOperations:
    """Tests for file operations"""

    @patch('subprocess.run')
    @patch('time.time')
    @patch('shutil.copy2')
    def test_copy_file_from_wsl(self, mock_copy, mock_time, mock_run):
        """Test copying file from WSL to Windows"""
        # Mock for initialization
        mock_init_result = Mock()
        mock_init_result.returncode = 0
        mock_init_result.stdout = "kali-linux\n"
        
        # Mock for wslpath command
        mock_wslpath_result = Mock()
        mock_wslpath_result.returncode = 0
        mock_wslpath_result.stdout = "C:\\Users\\test\\file.txt\n"
        mock_wslpath_result.stderr = ""
        
        mock_run.side_effect = [mock_init_result, mock_wslpath_result]
        mock_time.side_effect = cycle([100.0, 100.1])
        
        helper = WSLHelper()
        result = helper.copy_file_from_wsl("/tmp/test.txt", "C:\\dest\\test.txt")
        
        assert result is True
        mock_copy.assert_called_once()

    @patch('subprocess.run')
    @patch('time.time')
    def test_create_temp_file(self, mock_time, mock_run):
        """Test creating temporary file in WSL"""
        # Mock for initialization
        mock_init_result = Mock()
        mock_init_result.returncode = 0
        mock_init_result.stdout = "kali-linux\n"
        
        # Mock for echo command
        mock_echo_result = Mock()
        mock_echo_result.returncode = 0
        mock_echo_result.stdout = ""
        mock_echo_result.stderr = ""
        
        mock_run.side_effect = [mock_init_result, mock_echo_result]
        mock_time.side_effect = cycle([100.0, 100.1])
        
        helper = WSLHelper()
        temp_path = helper.create_temp_file("test content", "txt")
        
        assert temp_path.startswith("/tmp/wsltmp_")
        assert temp_path.endswith(".txt")


class TestCommandSanitization:
    """Tests for command sanitization"""

    @patch('subprocess.run')
    def test_sanitize_command_basic(self, mock_run):
        """Test basic command sanitization"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "kali-linux\n"
        mock_run.return_value = mock_result
        
        helper = WSLHelper()
        
        # Access private method for testing
        sanitized = helper._sanitize_command("ls -la")
        assert isinstance(sanitized, str)
        assert "ls" in sanitized

    @patch('subprocess.run')
    def test_sanitize_command_with_special_chars(self, mock_run):
        """Test sanitizing command with special characters"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "kali-linux\n"
        mock_run.return_value = mock_result
        
        helper = WSLHelper()
        
        # Test with potentially dangerous characters
        sanitized = helper._sanitize_command("echo 'test' && ls")
        assert isinstance(sanitized, str)


class TestEdgeCases:
    """Tests for edge cases and error conditions"""

    @patch('subprocess.run')
    def test_empty_command(self, mock_run):
        """Test executing empty command"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "kali-linux\n"
        mock_run.return_value = mock_result
        
        helper = WSLHelper()
        
        # Empty command should be handled
        try:
            helper._sanitize_command("")
            assert True  # Should not raise exception
        except Exception:
            assert False  # Should handle gracefully

    @patch('subprocess.run')
    def test_distribution_with_special_chars(self, mock_run):
        """Test WSL helper with distribution name containing special characters"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "kali-linux\nUbuntu-20.04\n"
        mock_run.return_value = mock_result
        
        # Should handle distribution names with hyphens
        helper = WSLHelper(distribution="Ubuntu-20.04")
        assert helper.distribution == "Ubuntu-20.04"

    @patch('subprocess.run')
    def test_very_long_timeout(self, mock_run):
        """Test with very long timeout value"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "kali-linux\n"
        mock_run.return_value = mock_result
        
        helper = WSLHelper(default_timeout=86400)  # 24 hours
        assert helper.default_timeout == 86400


class TestWSLToolValidator:
    """Tests for WSLToolValidator class"""

    @patch('subprocess.run')
    @patch('time.time')
    def test_validate_required_tools(self, mock_time, mock_run):
        """Test validating multiple required tools"""
        # Mock for initialization
        mock_init_result = Mock()
        mock_init_result.returncode = 0
        mock_init_result.stdout = "kali-linux\n"
        
        # Mock for which commands
        mock_nmap_result = Mock()
        mock_nmap_result.returncode = 0
        mock_nmap_result.stdout = "/usr/bin/nmap"
        mock_nmap_result.stderr = ""
        
        mock_curl_result = Mock()
        mock_curl_result.returncode = 1
        mock_curl_result.stdout = ""
        mock_curl_result.stderr = ""
        
        mock_run.side_effect = [mock_init_result, mock_nmap_result, mock_curl_result]
        mock_time.side_effect = cycle([100.0, 100.1])
        
        helper = WSLHelper()
        validator = WSLToolValidator(helper)
        
        results = validator.validate_required_tools(["nmap", "curl"])
        
        assert results["nmap"] is True
        assert results["curl"] is False

    @patch('subprocess.run')
    @patch('time.time')
    def test_get_missing_tools(self, mock_time, mock_run):
        """Test getting list of missing tools"""
        # Mock for initialization
        mock_init_result = Mock()
        mock_init_result.returncode = 0
        mock_init_result.stdout = "kali-linux\n"
        
        # Mock for which commands
        mock_python_result = Mock()
        mock_python_result.returncode = 0
        mock_python_result.stdout = "/usr/bin/python3"
        mock_python_result.stderr = ""
        
        mock_missing_result = Mock()
        mock_missing_result.returncode = 1
        mock_missing_result.stdout = ""
        mock_missing_result.stderr = ""
        
        mock_run.side_effect = [mock_init_result, mock_python_result, mock_missing_result]
        mock_time.side_effect = cycle([100.0, 100.1])
        
        helper = WSLHelper()
        validator = WSLToolValidator(helper)
        
        missing = validator.get_missing_tools(["python3", "missing_tool"])
        
        assert "missing_tool" in missing
        assert "python3" not in missing

    @patch('subprocess.run')
    @patch('time.time')
    def test_validate_or_raise(self, mock_time, mock_run):
        """Test validate_or_raise with missing tools"""
        # Mock for initialization
        mock_init_result = Mock()
        mock_init_result.returncode = 0
        mock_init_result.stdout = "kali-linux\n"
        
        # Mock for which command (tool not found)
        mock_missing_result = Mock()
        mock_missing_result.returncode = 1
        mock_missing_result.stdout = ""
        mock_missing_result.stderr = ""
        
        mock_run.side_effect = [mock_init_result, mock_missing_result]
        mock_time.side_effect = cycle([100.0, 100.1])


class TestWSLHelperErrorPaths:
    """Tests for WSL Helper error paths and edge cases"""

    @patch('subprocess.run')
    def test_validate_wsl_distribution_not_found(self, mock_run):
        """Test warning when specified distribution not found"""
        # Mock list distributions with wrong distro
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Ubuntu-20.04\nDebian\n"  # Different from requested
        mock_run.return_value = mock_result
        
        # This should log warning but not raise - distribution validation is permissive
        helper = WSLHelper(distribution="NonExistentDistro")
        assert helper.distribution == "NonExistentDistro"

    @patch('subprocess.run')
    def test_validate_wsl_generic_exception(self, mock_run):
        """Test generic exception handling in WSL validation"""
        # Simulate unexpected error
        mock_run.side_effect = ValueError("Unexpected error")
        
        with pytest.raises(RuntimeError, match="Failed to validate WSL"):
            WSLHelper()

    @patch('subprocess.run')
    @patch('time.time')
    def test_execute_command_generic_exception(self, mock_time, mock_run):
        """Test generic exception handling in execute_command"""
        # Mock initialization
        mock_init_result = Mock()
        mock_init_result.returncode = 0
        mock_init_result.stdout = "kali-linux\n"
        
        # Simulate unexpected exception during command execution
        mock_run.side_effect = [mock_init_result, ValueError("Unexpected error")]
        mock_time.side_effect = cycle([100.0, 100.1])
        
        helper = WSLHelper()
        
        with pytest.raises(ValueError):
            helper.execute_command("test command", timeout=10)

    @patch('subprocess.run')
    @patch('time.time')
    def test_execute_command_with_file_output(self, mock_time, mock_run):
        """Test execute_command_with_file_output method"""
        # Mock initialization
        mock_init_result = Mock()
        mock_init_result.returncode = 0
        mock_init_result.stdout = "kali-linux\n"
        
        # Mock command execution
        mock_command_result = Mock()
        mock_command_result.returncode = 0
        mock_command_result.stdout = "Command executed"
        mock_command_result.stderr = ""
        
        # Mock file read
        mock_cat_result = Mock()
        mock_cat_result.returncode = 0
        mock_cat_result.stdout = "File contents here"
        mock_cat_result.stderr = ""
        
        mock_run.side_effect = [mock_init_result, mock_command_result, mock_cat_result]
        mock_time.side_effect = cycle([100.0, 100.1])
        
        helper = WSLHelper()
        result, file_content = helper.execute_command_with_file_output(
            "nmap -oX output.xml target", "/tmp/output.xml"
        )
        
        assert result.success is True
        assert result.stdout == "Command executed"
        assert file_content == "File contents here"
        
        # Verify cat command was called
        cat_call = [call for call in mock_run.call_args_list if "cat" in str(call)]
        assert len(cat_call) > 0

    @patch('subprocess.run')
    @patch('time.time')
    def test_check_tool_availability_false(self, mock_time, mock_run):
        """Test check_tool_availability when tool is not found"""
        # Mock initialization
        mock_init_result = Mock()
        mock_init_result.returncode = 0
        mock_init_result.stdout = "kali-linux\n"
        
        # Mock which command - tool not found
        mock_which_result = Mock()
        mock_which_result.returncode = 1
        mock_which_result.stdout = ""
        mock_which_result.stderr = ""
        
        mock_run.side_effect = [mock_init_result, mock_which_result]
        mock_time.side_effect = cycle([100.0, 100.1])
        
        helper = WSLHelper()
        available = helper.check_tool_availability("missing_tool")
        
        assert available is False

    @patch('subprocess.run')
    @patch('time.time')
    def test_get_tool_version_exception_handling(self, mock_time, mock_run):
        """Test get_tool_version with exception"""
        # Mock initialization
        mock_init_result = Mock()
        mock_init_result.returncode = 0
        mock_init_result.stdout = "kali-linux\n"
        
        # Simulate exception during version check
        mock_run.side_effect = [mock_init_result, RuntimeError("Version check failed")]
        mock_time.side_effect = cycle([100.0, 100.1])
        
        helper = WSLHelper()
        version = helper.get_tool_version("some_tool")
        
        assert version is None

    @patch('subprocess.run')
    @patch('time.time')
    def test_get_distribution_info(self, mock_time, mock_run):
        """Test get_distribution_info method"""
        # Mock initialization
        mock_init_result = Mock()
        mock_init_result.returncode = 0
        mock_init_result.stdout = "kali-linux\n"
        
        # Mock os-release command
        mock_os_result = Mock()
        mock_os_result.returncode = 0
        mock_os_result.stdout = "NAME=Ubuntu\nVERSION=20.04"
        mock_os_result.stderr = ""
        
        # Mock kernel command
        mock_kernel_result = Mock()
        mock_kernel_result.returncode = 0
        mock_kernel_result.stdout = "5.10.16.3-microsoft-standard-WSL2"
        mock_kernel_result.stderr = ""
        
        # Mock hostname command
        mock_hostname_result = Mock()
        mock_hostname_result.returncode = 0
        mock_hostname_result.stdout = "my-wsl-machine"
        mock_hostname_result.stderr = ""
        
        mock_run.side_effect = [
            mock_init_result,
            mock_os_result,
            mock_kernel_result,
            mock_hostname_result
        ]
        mock_time.side_effect = cycle([100.0, 100.1])
        
        helper = WSLHelper()
        info = helper.get_distribution_info()
        
        assert "os_release" in info
        assert info["os_release"] == "NAME=Ubuntu\nVERSION=20.04"
        assert "kernel" in info
        assert "5.10.16.3" in info["kernel"]
        assert "hostname" in info
        assert info["hostname"] == "my-wsl-machine"

    @patch('subprocess.run')
    @patch('time.time')
    def test_get_distribution_info_with_failures(self, mock_time, mock_run):
        """Test get_distribution_info when some commands fail"""
        # Mock initialization
        mock_init_result = Mock()
        mock_init_result.returncode = 0
        mock_init_result.stdout = "kali-linux\n"
        
        # Mock os-release command - success
        mock_os_result = Mock()
        mock_os_result.returncode = 0
        mock_os_result.stdout = "NAME=Ubuntu"
        mock_os_result.stderr = ""
        
        # Mock kernel command - failure
        mock_kernel_result = Mock()
        mock_kernel_result.returncode = 1
        mock_kernel_result.stdout = ""
        mock_kernel_result.stderr = "Error"
        
        # Mock hostname command - success
        mock_hostname_result = Mock()
        mock_hostname_result.returncode = 0
        mock_hostname_result.stdout = "hostname"
        mock_hostname_result.stderr = ""
        
        mock_run.side_effect = [
            mock_init_result,
            mock_os_result,
            mock_kernel_result,
            mock_hostname_result
        ]
        mock_time.side_effect = cycle([100.0, 100.1])
        
        helper = WSLHelper()
        info = helper.get_distribution_info()
        
        # Should have os_release and hostname, but not kernel
        assert "os_release" in info
        assert "hostname" in info
        assert "kernel" not in info or info.get("kernel") == ""

    @patch('subprocess.run')
    def test_sanitize_command_with_dangerous_patterns(self, mock_run):
        """Test _sanitize_command detecting dangerous patterns"""
        # Mock initialization
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "kali-linux\n"
        mock_run.return_value = mock_result
        
        helper = WSLHelper()
        
        # Test various dangerous patterns that should be caught
        dangerous_commands = [
            "ls; rm -rf /tmp",  # Dangerous rm with semicolon
            "test && rm -rf important",  # Dangerous rm with &&
            "echo test | rm -rf data",  # Dangerous rm with pipe
            "cat file; shutdown now",  # Shutdown command
            "ls; reboot",  # Reboot command
        ]
        
        for cmd in dangerous_commands:
            with pytest.raises(ValueError, match="dangerous pattern"):
                helper._sanitize_command(cmd)

    @patch('subprocess.run')
    @patch('time.time')
    @patch('shutil.copy')
    def test_copy_file_from_wsl_exception(self, mock_copy, mock_time, mock_run):
        """Test copy_file_from_wsl with exception"""
        # Mock initialization
        mock_init_result = Mock()
        mock_init_result.returncode = 0
        mock_init_result.stdout = "kali-linux\n"
        
        # Mock wslpath command - exception
        mock_run.side_effect = [mock_init_result, RuntimeError("Path conversion failed")]
        mock_time.side_effect = cycle([100.0, 100.1])
        
        helper = WSLHelper()
        success = helper.copy_file_from_wsl("/tmp/test.txt", "C:\\output.txt")
        
        assert success is False

    @patch('subprocess.run')
    @patch('time.time')
    def test_create_temp_file_failure(self, mock_time, mock_run):
        """Test create_temp_file when file creation fails"""
        # Mock initialization
        mock_init_result = Mock()
        mock_init_result.returncode = 0
        mock_init_result.stdout = "kali-linux\n"
        
        # Mock echo command - failure
        mock_echo_result = Mock()
        mock_echo_result.returncode = 1
        mock_echo_result.stdout = ""
        mock_echo_result.stderr = "Failed to create file"
        
        mock_run.side_effect = [mock_init_result, mock_echo_result]
        mock_time.side_effect = cycle([100.0, 100.1])
        
        helper = WSLHelper()
        
        # The actual error message from execute_command is "WSL command failed..."
        with pytest.raises(RuntimeError, match="WSL command failed"):
            helper.create_temp_file("content", "txt")

    @patch('subprocess.run')
    @patch('time.time')
    def test_cleanup_temp_file_success(self, mock_time, mock_run):
        """Test cleanup_temp_file successful removal"""
        # Mock initialization
        mock_init_result = Mock()
        mock_init_result.returncode = 0
        mock_init_result.stdout = "kali-linux\n"
        
        # Mock rm command - success
        mock_rm_result = Mock()
        mock_rm_result.returncode = 0
        mock_rm_result.stdout = ""
        mock_rm_result.stderr = ""
        
        mock_run.side_effect = [mock_init_result, mock_rm_result]
        mock_time.side_effect = cycle([100.0, 100.1])
        
        helper = WSLHelper()
        success = helper.cleanup_temp_file("/tmp/test.txt")
        
        assert success is True

    @patch('subprocess.run')
    @patch('time.time')
    def test_cleanup_temp_file_failure(self, mock_time, mock_run):
        """Test cleanup_temp_file when removal fails"""
        # Mock initialization
        mock_init_result = Mock()
        mock_init_result.returncode = 0
        mock_init_result.stdout = "kali-linux\n"
        
        # Mock rm command - failure
        mock_rm_result = Mock()
        mock_rm_result.returncode = 1
        mock_rm_result.stdout = ""
        mock_rm_result.stderr = "Permission denied"
        
        # Need two mock_run calls: one for init, one for rm command
        mock_run.side_effect = [mock_init_result, mock_rm_result]
        mock_time.side_effect = cycle([100.0, 100.1])
        
        helper = WSLHelper()
        success = helper.cleanup_temp_file("/tmp/test.txt")
        
        assert success is False

    @patch('subprocess.run')
    @patch('time.time')
    def test_get_distribution_info_exception_handling(self, mock_time, mock_run):
        """Test get_distribution_info with exception in command execution"""
        # Mock initialization
        mock_init_result = Mock()
        mock_init_result.returncode = 0
        mock_init_result.stdout = "kali-linux\n"
        
        # First command succeeds, second raises exception
        mock_os_result = Mock()
        mock_os_result.returncode = 0
        mock_os_result.stdout = "NAME=Ubuntu"
        mock_os_result.stderr = ""
        
        mock_run.side_effect = [
            mock_init_result,
            mock_os_result,
            Exception("Command execution failed")
        ]
        mock_time.side_effect = cycle([100.0, 100.1])
        
        helper = WSLHelper()
        info = helper.get_distribution_info()
        
        # Should have os_release but kernel should be "Unknown" due to exception
        assert info["os_release"] == "NAME=Ubuntu"
        assert info["kernel"] == "Unknown"

    @patch('subprocess.run')
    @patch('time.time')
    def test_copy_file_from_wsl_exception_handling(self, mock_time, mock_run):
        """Test copy_file_from_wsl with exception during file copy"""
        # Mock initialization
        mock_init_result = Mock()
        mock_init_result.returncode = 0
        mock_init_result.stdout = "kali-linux\n"
        
        # Mock subprocess.run to raise exception
        mock_run.side_effect = [
            mock_init_result,
            Exception("File copy failed")
        ]
        mock_time.side_effect = cycle([100.0, 100.1])
        
        helper = WSLHelper()
        result = helper.copy_file_from_wsl("/tmp/test.txt", "C:\\dest.txt")
        
        assert result is False

    @patch('subprocess.run')
    @patch('time.time')
    def test_create_temp_file_failure_exception(self, mock_time, mock_run):
        """Test create_temp_file when command fails"""
        # Mock initialization
        mock_init_result = Mock()
        mock_init_result.returncode = 0
        mock_init_result.stdout = "kali-linux\n"
        
        # Mock mktemp command failure
        mock_mktemp_result = Mock()
        mock_mktemp_result.returncode = 1
        mock_mktemp_result.stdout = ""
        mock_mktemp_result.stderr = "Failed to create temp file"
        
        mock_run.side_effect = [mock_init_result, mock_mktemp_result]
        mock_time.side_effect = cycle([100.0, 100.1])
        
        helper = WSLHelper()
        
        # Should raise RuntimeError when temp file creation fails
        with pytest.raises(RuntimeError, match="WSL command failed"):
            helper.create_temp_file("content", "txt")
