"""
Unit Tests for Input Validation Utilities

Tests for security-critical input validation functions.
Related to QA Test Cases: #4, #21-25, #107, #161-165
"""

import pytest
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.input_validation import (
    ValidationError,
    IPAddressValidator,
    PortValidator,
    CommandSanitizer,
    WSLCommandValidator,
    validate_scan_request,
    sanitize_user_input
)


class TestIPAddressValidator:
    """Tests for IP address validation (Test Case #21)."""
    
    def test_valid_ipv4(self):
        """Test valid IPv4 addresses."""
        valid_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "127.0.0.1",
            "8.8.8.8",
            "255.255.255.255"
        ]
        for ip in valid_ips:
            assert IPAddressValidator.validate_ip(ip) == ip
    
    def test_valid_ipv6(self):
        """Test valid IPv6 addresses."""
        valid_ips = [
            "::1",
            "fe80::1",
            "2001:db8::1",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        ]
        for ip in valid_ips:
            result = IPAddressValidator.validate_ip(ip)
            assert result  # IPv6 may be normalized
    
    def test_invalid_ipv4(self):
        """Test invalid IPv4 addresses."""
        invalid_ips = [
            "999.999.999.999",
            "192.168.1",
            "192.168.1.1.1",
            "abc.def.ghi.jkl",
            "192.168.-1.1"
        ]
        for ip in invalid_ips:
            with pytest.raises(ValidationError, match="Invalid IP address"):
                IPAddressValidator.validate_ip(ip)
    
    def test_valid_cidr(self):
        """Test valid CIDR notation."""
        valid_cidrs = [
            "192.168.1.0/24",
            "10.0.0.0/16",  # Changed from /8 which is too large
            "172.16.0.0/16"
        ]
        for cidr in valid_cidrs:
            result = IPAddressValidator.validate_cidr(cidr)
            assert "/" in result
    
    def test_cidr_too_large(self):
        """Test CIDR range that's too large."""
        with pytest.raises(ValidationError, match="too large"):
            IPAddressValidator.validate_cidr("10.0.0.0/8")  # 16M hosts
    
    def test_invalid_cidr(self):
        """Test invalid CIDR notation."""
        with pytest.raises(ValidationError):
            IPAddressValidator.validate_cidr("192.168.1.0/33")  # Invalid prefix
    
    def test_command_injection_in_target(self):
        """Test Case #4: Command injection prevention."""
        malicious_targets = [
            "192.168.1.1; rm -rf /",
            "192.168.1.1 | cat /etc/passwd",
            "192.168.1.1 && whoami",
            "192.168.1.1`id`",
            "192.168.1.1$(ls)",
            "192.168.1.1\nls"
        ]
        for target in malicious_targets:
            with pytest.raises(ValidationError, match="Invalid character"):
                IPAddressValidator.validate_target(target)
    
    def test_validate_target_single_ip(self):
        """Test target validation for single IP."""
        assert IPAddressValidator.validate_target("192.168.1.1") == "192.168.1.1"
    
    def test_validate_target_cidr(self):
        """Test target validation for CIDR."""
        result = IPAddressValidator.validate_target("192.168.1.0/24")
        assert "/" in result
    
    def test_validate_target_domain_name(self):
        """Test target validation for domain names."""
        valid_domains = [
            "scanme.nmap.org",
            "example.com",
            "localhost",
            "test.example.co.uk",
            "subdomain.test.example.com"
        ]
        for domain in valid_domains:
            result = IPAddressValidator.validate_target(domain)
            assert result == domain
    
    def test_validate_target_invalid_domain(self):
        """Test rejection of invalid domain names."""
        invalid_domains = [
            "-invalid.com",  # Starts with hyphen
            "invalid-.com",  # Ends with hyphen
            "invalid..com",  # Double dots
            "invalid .com",  # Space
            "@invalid.com",  # Special character
        ]
        for domain in invalid_domains:
            with pytest.raises(ValidationError, match="Invalid domain"):
                IPAddressValidator.validate_target(domain)
    
    def test_validate_domain_name_method(self):
        """Test domain name validation directly."""
        # Valid domains
        assert IPAddressValidator.validate_domain_name("scanme.nmap.org") == "scanme.nmap.org"
        assert IPAddressValidator.validate_domain_name("example.com") == "example.com"
        assert IPAddressValidator.validate_domain_name("localhost") == "localhost"
    
    def test_validate_domain_name_too_long(self):
        """Test domain name length limit (253 chars)."""
        # Create a valid-format domain that's too long
        # Each label is separated by dots and valid
        labels = ['a' * 63] * 5  # 5 labels of 63 chars = 315 chars + 4 dots = 319 chars total
        long_domain = '.'.join(labels)
        with pytest.raises(ValidationError, match="Domain name too long"):
            IPAddressValidator.validate_domain_name(long_domain)
    
    def test_validate_target_with_http_url(self):
        """Test URL with http protocol is stripped and validated."""
        # Should strip http:// and validate domain
        result = IPAddressValidator.validate_target("http://example.com")
        assert result == "example.com"
    
    def test_validate_target_with_https_url(self):
        """Test URL with https protocol is stripped and validated."""
        # Should strip https:// and validate domain
        result = IPAddressValidator.validate_target("https://scanme.nmap.org")
        assert result == "scanme.nmap.org"
    
    def test_validate_target_with_ftp_url(self):
        """Test URL with ftp protocol is stripped and validated."""
        result = IPAddressValidator.validate_target("ftp://files.example.com")
        assert result == "files.example.com"
    
    def test_validate_target_with_url_and_path(self):
        """Test URL with protocol and path extracts just the domain."""
        # http://testphp.vulnweb.com/path -> testphp.vulnweb.com
        result = IPAddressValidator.validate_target("http://testphp.vulnweb.com/")
        assert result == "testphp.vulnweb.com"
        
        result = IPAddressValidator.validate_target("https://testphp.vulnweb.com/path/to/resource")
        assert result == "testphp.vulnweb.com"
    
    def test_validate_target_with_url_and_trailing_slash(self):
        """Test URL with trailing slash is stripped."""
        result = IPAddressValidator.validate_target("http://example.com/")
        assert result == "example.com"
    
    def test_validate_target_url_case_insensitive(self):
        """Test URL protocol matching is case-insensitive."""
        result = IPAddressValidator.validate_target("HTTP://EXAMPLE.COM")
        assert result == "EXAMPLE.COM"
        
        result = IPAddressValidator.validate_target("HTTPS://example.com")
        assert result == "example.com"


class TestPortValidator:
    """Tests for port validation (Test Case #22)."""
    
    def test_valid_port_number(self):
        """Test valid port numbers."""
        valid_ports = [1, 80, 443, 8080, 65535]
        for port in valid_ports:
            assert PortValidator.validate_port_number(port) == port
    
    def test_invalid_port_number(self):
        """Test invalid port numbers."""
        invalid_ports = [0, -1, 65536, 100000, "invalid"]
        for port in invalid_ports:
            with pytest.raises(ValidationError):
                PortValidator.validate_port_number(port)
    
    def test_single_port_range(self):
        """Test single port specification."""
        assert PortValidator.validate_port_range("80") == "80"
    
    def test_port_range(self):
        """Test port range specification."""
        assert PortValidator.validate_port_range("1-1000") == "1-1000"
    
    def test_comma_separated_ports(self):
        """Test comma-separated ports."""
        assert PortValidator.validate_port_range("22,80,443") == "22,80,443"
    
    def test_mixed_port_specification(self):
        """Test mixed port specification."""
        assert PortValidator.validate_port_range("22,80-90,443") == "22,80-90,443"
    
    def test_invalid_port_format(self):
        """Test invalid port format."""
        invalid_formats = [
            "invalid",
            "80-",
            "-80",
            "80;90",
            "80|90",
            "eighty"
        ]
        for fmt in invalid_formats:
            with pytest.raises(ValidationError, match="Invalid port"):
                PortValidator.validate_port_range(fmt)
    
    def test_inverted_range(self):
        """Test port range with start > end."""
        with pytest.raises(ValidationError, match="start port must be"):
            PortValidator.validate_port_range("1000-1")
    
    def test_too_many_ports(self):
        """Test exceeding maximum port count."""
        # Try to scan all 65535 ports
        with pytest.raises(ValidationError, match="Too many ports"):
            PortValidator.validate_port_range("1-65535")


class TestCommandSanitizer:
    """Tests for command sanitization (Test Case #4, #107)."""
    
    def test_safe_alphanumeric(self):
        """Test sanitization of safe alphanumeric strings."""
        safe_strings = ["test", "test123", "test_file", "test-name", "file.txt"]
        for s in safe_strings:
            result = CommandSanitizer.sanitize_for_shell(s, allow_special=False)
            assert result  # Should not raise
    
    def test_reject_special_characters_strict(self):
        """Test rejection of special characters in strict mode."""
        dangerous_strings = [
            "test;rm",
            "test|cat",
            "test&whoami",
            "test$var",
            "test`id`"
        ]
        for s in dangerous_strings:
            with pytest.raises(ValidationError, match="Invalid characters"):
                CommandSanitizer.sanitize_for_shell(s, allow_special=False)
    
    def test_escape_special_characters_permissive(self):
        """Test escaping in permissive mode."""
        # In permissive mode, shlex.quote should escape
        result = CommandSanitizer.sanitize_for_shell("test value", allow_special=True)
        assert "'" in result or '"' in result  # Should be quoted
    
    def test_validate_scan_type_valid(self):
        """Test valid scan types."""
        valid_types = ['quick', 'full', 'stealth', 'version', 'vulnerability']
        for scan_type in valid_types:
            assert CommandSanitizer.validate_scan_type(scan_type) == scan_type
    
    def test_validate_scan_type_invalid(self):
        """Test invalid scan types."""
        with pytest.raises(ValidationError, match="Invalid scan type"):
            CommandSanitizer.validate_scan_type("malicious_type")
    
    def test_build_safe_command_array(self):
        """Test building safe command arrays."""
        result = CommandSanitizer.build_safe_command_array(
            'nmap',
            ['-p', '80', '192.168.1.1']
        )
        assert result == ['nmap', '-p', '80', '192.168.1.1']
        assert isinstance(result, list)  # Array, not string!
    
    def test_reject_null_bytes_in_command(self):
        """Test rejection of null bytes."""
        with pytest.raises(ValidationError, match="Null byte"):
            CommandSanitizer.build_safe_command_array(
                'nmap',
                ['test\x00malicious']
            )
    
    def test_reject_newlines_in_command(self):
        """Test rejection of newlines."""
        with pytest.raises(ValidationError, match="Newline"):
            CommandSanitizer.build_safe_command_array(
                'nmap',
                ['test\nmalicious']
            )


class TestWSLCommandValidator:
    """Tests for WSL command validation (Test Case #3, #107)."""
    
    def test_valid_distribution(self):
        """Test valid WSL distributions."""
        valid_distros = ['kali-linux', 'ubuntu', 'debian']
        for distro in valid_distros:
            assert WSLCommandValidator.validate_distribution(distro) == distro
    
    def test_invalid_distribution(self):
        """Test Case #3: Invalid WSL distribution."""
        with pytest.raises(ValidationError, match="Invalid WSL distribution"):
            WSLCommandValidator.validate_distribution("non-existent-distro")
    
    def test_valid_tool(self):
        """Test valid security tools."""
        valid_tools = ['nmap', 'nikto', 'nuclei', 'openvas']
        for tool in valid_tools:
            assert WSLCommandValidator.validate_tool(tool) == tool
    
    def test_invalid_tool(self):
        """Test invalid tool name."""
        with pytest.raises(ValidationError, match="Invalid tool"):
            WSLCommandValidator.validate_tool("malicious_tool")
    
    def test_build_wsl_command(self):
        """Test building safe WSL commands."""
        result = WSLCommandValidator.build_wsl_command(
            'kali-linux',
            'nmap',
            ['-p', '80', '192.168.1.1']
        )
        expected = ['wsl.exe', '-d', 'kali-linux', '--', 'nmap', '-p', '80', '192.168.1.1']
        assert result == expected
        assert isinstance(result, list)  # Must be array!
    
    def test_wsl_command_injection_prevention(self):
        """Test Case #107: Prevent command injection in WSL."""
        # Even if someone bypasses earlier validation, invalid distro/tool should fail
        with pytest.raises(ValidationError):
            WSLCommandValidator.build_wsl_command(
                'kali-linux; rm -rf /',
                'nmap',
                []
            )


class TestScanRequestValidation:
    """Tests for complete scan request validation (Test Case #24, #161)."""
    
    def test_valid_scan_request(self):
        """Test valid scan request."""
        result = validate_scan_request(
            target="192.168.1.1",
            scan_type="quick",
            ports="80,443"
        )
        assert result['target'] == "192.168.1.1"
        assert result['scan_type'] == "quick"
        assert result['ports'] == "80,443"
    
    def test_scan_request_without_ports(self):
        """Test scan request without port specification."""
        result = validate_scan_request(
            target="192.168.1.0/24",
            scan_type="full"
        )
        assert result['target']
        assert result['scan_type'] == "full"
        assert 'ports' not in result
    
    def test_scan_request_invalid_target(self):
        """Test Case #161: Invalid target in scan request."""
        with pytest.raises(ValidationError):
            validate_scan_request(
                target="invalid_ip",
                scan_type="quick"
            )
    
    def test_scan_request_invalid_type(self):
        """Test invalid scan type."""
        with pytest.raises(ValidationError):
            validate_scan_request(
                target="192.168.1.1",
                scan_type="malicious"
            )
    
    def test_scan_request_invalid_ports(self):
        """Test Case #163: Invalid ports."""
        with pytest.raises(ValidationError):
            validate_scan_request(
                target="192.168.1.1",
                scan_type="quick",
                ports="99999"  # Invalid port number
            )


class TestUserInputSanitization:
    """Tests for general user input sanitization (Test Case #165)."""
    
    def test_valid_user_input(self):
        """Test valid user input."""
        result = sanitize_user_input("  Test input with spaces  ")
        assert result == "Test input with spaces"
    
    def test_input_too_long(self):
        """Test input exceeding maximum length."""
        long_input = "a" * 1001
        with pytest.raises(ValidationError, match="too long"):
            sanitize_user_input(long_input, max_length=1000)
    
    def test_null_byte_rejection(self):
        """Test rejection of null bytes."""
        with pytest.raises(ValidationError, match="Null byte"):
            sanitize_user_input("test\x00malicious")
    
    def test_whitespace_trimming(self):
        """Test whitespace trimming."""
        result = sanitize_user_input("  \n\t test \t\n  ")
        assert result == "test"
    
    def test_empty_input(self):
        """Test Case #165: Empty input handling."""
        result = sanitize_user_input("   ")
        assert result == ""


class TestEdgeCases:
    """Edge case tests (Test Cases #176-180, #186-190)."""
    
    def test_minimum_ip_range(self):
        """Test Case #176: Single IP (minimum range)."""
        result = IPAddressValidator.validate_target("192.168.1.1")
        assert result == "192.168.1.1"
    
    def test_maximum_port(self):
        """Test Case #178: Maximum port number."""
        result = PortValidator.validate_port_number(65535)
        assert result == 65535
    
    def test_minimum_port(self):
        """Test minimum port number."""
        result = PortValidator.validate_port_number(1)
        assert result == 1
    
    def test_special_characters_in_input(self):
        """Test Case #188: Special characters in various inputs."""
        # Unicode should be allowed in user input
        result = sanitize_user_input("Test with émojis 🚀")
        assert "🚀" in result
    
    def test_case_insensitive_validation(self):
        """Test case-insensitive validation."""
        assert CommandSanitizer.validate_scan_type("QUICK") == "quick"
        assert WSLCommandValidator.validate_distribution("KALI-LINUX") == "kali-linux"
    
    def test_whitespace_handling(self):
        """Test whitespace trimming in various validators."""
        assert IPAddressValidator.validate_ip("  192.168.1.1  ") == "192.168.1.1"
        assert PortValidator.validate_port_range("  80,443  ") == "80,443"


# Integration tests combining multiple validators
class TestIntegration:
    """Integration tests for realistic scenarios."""
    
    def test_complete_nmap_scan_validation(self):
        """Test complete Nmap scan parameter validation."""
        # Validate all parameters for a typical Nmap scan
        target = IPAddressValidator.validate_target("192.168.1.0/24")
        ports = PortValidator.validate_port_range("1-1000")
        scan_type = CommandSanitizer.validate_scan_type("quick")
        
        # Build WSL command
        tool_args = ['-p', ports, target]
        command = WSLCommandValidator.build_wsl_command(
            'kali-linux',
            'nmap',
            tool_args
        )
        
        assert command[0] == 'wsl.exe'
        assert 'nmap' in command
        assert target in command
    
    def test_malicious_scan_request_rejected(self):
        """Test that malicious scan requests are rejected at multiple levels."""
        # This should fail at IP validation
        with pytest.raises(ValidationError):
            validate_scan_request(
                target="192.168.1.1; rm -rf /",
                scan_type="quick"
            )
        
        # This should fail at scan type validation
        with pytest.raises(ValidationError):
            validate_scan_request(
                target="192.168.1.1",
                scan_type="malicious; whoami"
            )
        
        # This should fail at port validation
        with pytest.raises(ValidationError):
            validate_scan_request(
                target="192.168.1.1",
                scan_type="quick",
                ports="80; cat /etc/passwd"
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
