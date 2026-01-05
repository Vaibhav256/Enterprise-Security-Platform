"""
Input Validation Utilities for Security

This module provides validation and sanitization functions to prevent
injection attacks and ensure data integrity across the application.

Related QA Issues:
- Issue #1: Command Injection via Unsanitized Scan Parameters (CRITICAL)
- Issue #107: Command Injection Security Test
"""

import re
import ipaddress
from typing import List, Union, Optional
from shlex import quote as shell_quote


class ValidationError(Exception):
    """Raised when input validation fails."""
    pass


class IPAddressValidator:
    """Validates IP addresses and CIDR ranges."""
    
    # Maximum CIDR range to prevent scanning entire internet
    MAX_CIDR_HOSTS = 65536  # /16 network
    
    @staticmethod
    def validate_ip(ip_string: str) -> str:
        """
        Validate a single IP address (IPv4 or IPv6).
        
        Args:
            ip_string: IP address string to validate
            
        Returns:
            Validated IP address string
            
        Raises:
            ValidationError: If IP is invalid
        """
        try:
            # This handles both IPv4 and IPv6
            ip_obj = ipaddress.ip_address(ip_string.strip())
            return str(ip_obj)
        except ValueError as e:
            raise ValidationError(f"Invalid IP address '{ip_string}': {str(e)}")
    
    @staticmethod
    def validate_cidr(cidr_string: str) -> str:
        """
        Validate CIDR notation (e.g., 192.168.1.0/24).
        
        Args:
            cidr_string: CIDR range string to validate
            
        Returns:
            Validated CIDR string
            
        Raises:
            ValidationError: If CIDR is invalid or too large
        """
        try:
            network = ipaddress.ip_network(cidr_string.strip(), strict=False)
            
            # Check if range is too large
            if network.num_addresses > IPAddressValidator.MAX_CIDR_HOSTS:
                raise ValidationError(
                    f"CIDR range too large: {network.num_addresses} hosts. "
                    f"Maximum allowed: {IPAddressValidator.MAX_CIDR_HOSTS}"
                )
            
            return str(network)
        except ValueError as e:
            raise ValidationError(f"Invalid CIDR notation '{cidr_string}': {str(e)}")
    
    @staticmethod
    def validate_domain_name(domain: str) -> str:
        """
        Validate domain name or hostname.
        
        Args:
            domain: Domain name to validate (e.g., scanme.nmap.org, localhost)
            
        Returns:
            Validated domain name string
            
        Raises:
            ValidationError: If domain name is invalid
        """
        domain = domain.strip()
        
        # Allow localhost and IP-like patterns
        if domain.lower() == 'localhost':
            return domain
        
        # Domain name pattern: labels separated by dots, alphanumeric and hyphens allowed
        # Labels can't start or end with hyphen, and can't be empty
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        
        if not re.match(domain_pattern, domain):
            raise ValidationError(
                f"Invalid domain name '{domain}': Must be valid hostname format "
                f"(e.g., scanme.nmap.org, example.com, localhost)"
            )
        
        # Additional check: domain must have at least one character
        if len(domain) == 0:
            raise ValidationError("Domain name cannot be empty")
        
        # Additional check: domain must not exceed 253 characters (DNS limit)
        if len(domain) > 253:
            raise ValidationError(
                f"Domain name too long: {len(domain)} characters. Maximum: 253"
            )
        
        return domain

    
    @staticmethod
    def validate_target(target: str) -> str:
        """
        Validate scan target (IP address, CIDR range, domain name, or URL).
        
        Args:
            target: Target IP, CIDR, domain, URL, or hostname to validate
            
        Returns:
            Validated target string (URL protocol stripped if present)
            
        Raises:
            ValidationError: If target is invalid
        """
        target = target.strip()
        
        # Check for shell metacharacters that could be used for injection
        dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '<', '>', '\n', '\r', '\\']
        for char in dangerous_chars:
            if char in target:
                raise ValidationError(
                    f"Invalid character '{char}' in target. "
                    f"Only IP addresses, domain names, and CIDR notation allowed."
                )
        
        # Strip URL protocols if present (http://, https://, etc.)
        # Common protocols: http, https, ftp, ftps, ssh, etc.
        url_protocol_pattern = r'^(https?|ftps?|ssh|telnet)://(.+)$'
        url_match = re.match(url_protocol_pattern, target, re.IGNORECASE)
        if url_match:
            protocol, target = url_match.groups()
            target = target.strip().rstrip('/')  # Remove trailing slash if present
        
        # Check for path in URL (e.g., domain.com/path) - keep only the host
        # But be careful: CIDR uses / so check for CIDR first
        if '/' in target and not re.match(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/\d+$', target):
            # If it looks like a URL path, extract just the host
            if '/' in target:
                target = target.split('/')[0]
        
        # Try as CIDR first (contains /)
        if '/' in target:
            return IPAddressValidator.validate_cidr(target)
        
        # Try as IP address
        try:
            return IPAddressValidator.validate_ip(target)
        except ValidationError:
            # If not an IP, try as domain name
            return IPAddressValidator.validate_domain_name(target)


class PortValidator:
    """Validates port numbers and port ranges."""
    
    MIN_PORT = 1
    MAX_PORT = 65535
    MAX_PORTS_PER_SCAN = 10000  # Reasonable limit for port scanning
    
    @staticmethod
    def validate_port_number(port: Union[int, str]) -> int:
        """
        Validate a single port number.
        
        Args:
            port: Port number to validate
            
        Returns:
            Validated port number as integer
            
        Raises:
            ValidationError: If port is invalid
        """
        try:
            port_num = int(port)
            if not (PortValidator.MIN_PORT <= port_num <= PortValidator.MAX_PORT):
                raise ValidationError(
                    f"Port {port_num} out of valid range "
                    f"({PortValidator.MIN_PORT}-{PortValidator.MAX_PORT})"
                )
            return port_num
        except ValueError:
            raise ValidationError(f"Invalid port number: {port}")
    
    @staticmethod
    def validate_port_range(port_range: str) -> str:
        """
        Validate port range specification.
        
        Accepts formats:
        - Single port: "80"
        - Range: "1-1000"
        - Comma-separated: "22,80,443"
        - Mixed: "22,80-90,443"
        
        Args:
            port_range: Port range string to validate
            
        Returns:
            Validated port range string
            
        Raises:
            ValidationError: If format is invalid or range too large
        """
        # Allow only digits, commas, and hyphens
        if not re.match(r'^[\d,\-]+$', port_range.strip()):
            raise ValidationError(
                f"Invalid port range format: {port_range}. "
                f"Use formats like: '80', '1-1000', '22,80,443'"
            )
        
        total_ports = 0
        parts = port_range.split(',')
        
        for part in parts:
            part = part.strip()
            if '-' in part:
                # Range like "80-90"
                try:
                    start, end = part.split('-')
                    start_port = PortValidator.validate_port_number(start)
                    end_port = PortValidator.validate_port_number(end)
                    
                    if start_port > end_port:
                        raise ValidationError(
                            f"Invalid range {part}: start port must be <= end port"
                        )
                    
                    total_ports += (end_port - start_port + 1)
                except ValueError:
                    raise ValidationError(f"Invalid port range: {part}")
            else:
                # Single port
                PortValidator.validate_port_number(part)
                total_ports += 1
        
        if total_ports > PortValidator.MAX_PORTS_PER_SCAN:
            raise ValidationError(
                f"Too many ports specified: {total_ports}. "
                f"Maximum allowed: {PortValidator.MAX_PORTS_PER_SCAN}"
            )
        
        return port_range.strip()


class CommandSanitizer:
    """Sanitizes inputs for use in shell commands."""
    
    # Regex for allowed characters in various contexts
    ALLOWED_ALPHANUMERIC = re.compile(r'^[a-zA-Z0-9_\-\.]+$')
    
    @staticmethod
    def sanitize_for_shell(value: str, allow_special: bool = False) -> str:
        """
        Sanitize a value for safe use in shell commands.
        
        Uses shlex.quote() to properly escape shell metacharacters.
        
        Args:
            value: Value to sanitize
            allow_special: If False, reject strings with special characters
            
        Returns:
            Sanitized value safe for shell execution
            
        Raises:
            ValidationError: If value contains dangerous characters and allow_special=False
        """
        if not allow_special:
            # For strict contexts, only allow alphanumeric, underscore, hyphen, dot
            if not CommandSanitizer.ALLOWED_ALPHANUMERIC.match(value):
                raise ValidationError(
                    f"Invalid characters in '{value}'. "
                    f"Only alphanumeric, underscore, hyphen, and dot allowed."
                )
        
        # Use shlex.quote for proper shell escaping
        return shell_quote(value)
    
    @staticmethod
    def validate_scan_type(scan_type: str) -> str:
        """
        Validate scan type against allowlist.
        
        Args:
            scan_type: Scan type identifier
            
        Returns:
            Validated scan type
            
        Raises:
            ValidationError: If scan type not in allowlist
        """
        ALLOWED_SCAN_TYPES = {
            'basic', 'quick', 'full', 'stealth', 'version', 
            'vulnerability', 'compliance', 'custom',
            'cve', 'misconfig', 'exposed', 'ssl'  # Nuclei and Nikto specific types
        }
        
        scan_type = scan_type.lower().strip()
        if scan_type not in ALLOWED_SCAN_TYPES:
            raise ValidationError(
                f"Invalid scan type: {scan_type}. "
                f"Allowed types: {', '.join(sorted(ALLOWED_SCAN_TYPES))}"
            )
        
        return scan_type
    
    @staticmethod
    def build_safe_command_array(
        base_command: str,
        args: List[str],
        validate_args: bool = True
    ) -> List[str]:
        """
        Build a command array for safe subprocess execution.
        
        This prevents shell injection by using array-based subprocess calls
        instead of string concatenation.
        
        Args:
            base_command: Base command (e.g., 'nmap')
            args: List of arguments
            validate_args: Whether to validate each argument
            
        Returns:
            List of command components safe for subprocess
            
        Raises:
            ValidationError: If any argument is invalid
        """
        command = [base_command]
        
        for arg in args:
            if validate_args:
                # Check for null bytes
                if '\x00' in arg:
                    raise ValidationError("Null byte detected in command argument")
                
                # Check for newlines (can break command parsing)
                if '\n' in arg or '\r' in arg:
                    raise ValidationError("Newline detected in command argument")
            
            command.append(arg)
        
        return command


class WSLCommandValidator:
    """Validates and sanitizes commands for WSL execution."""
    
    ALLOWED_WSL_DISTRIBUTIONS = {'kali-linux', 'ubuntu', 'debian'}
    ALLOWED_TOOLS = {
        'nmap', 'nikto', 'nuclei', 'openvas', 'gvm-cli',
        'python3',  # For OpenVAS GVM script execution
        'cat',      # For reading nmap output files
        'bash', 'sh'  # For shell commands
    }
    
    @staticmethod
    def validate_distribution(distro: str) -> str:
        """
        Validate WSL distribution name.
        
        Args:
            distro: WSL distribution name
            
        Returns:
            Validated distribution name
            
        Raises:
            ValidationError: If distribution not in allowlist
        """
        distro = distro.lower().strip()
        if distro not in WSLCommandValidator.ALLOWED_WSL_DISTRIBUTIONS:
            raise ValidationError(
                f"Invalid WSL distribution: {distro}. "
                f"Allowed: {', '.join(sorted(WSLCommandValidator.ALLOWED_WSL_DISTRIBUTIONS))}"
            )
        return distro
    
    @staticmethod
    def validate_tool(tool: str) -> str:
        """
        Validate security tool name.
        
        Args:
            tool: Tool name
            
        Returns:
            Validated tool name
            
        Raises:
            ValidationError: If tool not in allowlist
        """
        tool = tool.lower().strip()
        if tool not in WSLCommandValidator.ALLOWED_TOOLS:
            raise ValidationError(
                f"Invalid tool: {tool}. "
                f"Allowed: {', '.join(sorted(WSLCommandValidator.ALLOWED_TOOLS))}"
            )
        return tool
    
    @staticmethod
    def build_wsl_command(
        distro: str,
        tool: str,
        tool_args: List[str]
    ) -> List[str]:
        """
        Build a safe WSL command array.
        
        Args:
            distro: WSL distribution name
            tool: Security tool to run
            tool_args: Arguments for the tool
            
        Returns:
            Safe command array for subprocess execution
            
        Raises:
            ValidationError: If any parameter is invalid
        """
        # Validate inputs
        validated_distro = WSLCommandValidator.validate_distribution(distro)
        validated_tool = WSLCommandValidator.validate_tool(tool)
        
        # Build command array (NOT a shell string!)
        # Format: wsl.exe -d <distro> -- <tool> <args...>
        command = [
            'wsl.exe',
            '-d', validated_distro,
            '--', validated_tool
        ]
        
        # Add tool arguments (already validated by caller)
        command.extend(tool_args)
        
        return command


# Convenience functions for common validations

def validate_scan_request(
    target: str,
    scan_type: str,
    ports: Optional[str] = None
) -> dict:
    """
    Validate a complete scan request.
    
    Args:
        target: Target IP or CIDR
        scan_type: Type of scan
        ports: Port specification (optional)
        
    Returns:
        Dict with validated parameters
        
    Raises:
        ValidationError: If any parameter is invalid
    """
    validated = {
        'target': IPAddressValidator.validate_target(target),
        'scan_type': CommandSanitizer.validate_scan_type(scan_type)
    }
    
    if ports:
        validated['ports'] = PortValidator.validate_port_range(ports)
    
    return validated


def sanitize_user_input(user_input: str, max_length: int = 1000) -> str:
    """
    General sanitization for user text input.
    
    Args:
        user_input: Raw user input
        max_length: Maximum allowed length
        
    Returns:
        Sanitized input
        
    Raises:
        ValidationError: If input is too long or contains null bytes
    """
    if len(user_input) > max_length:
        raise ValidationError(
            f"Input too long: {len(user_input)} characters. "
            f"Maximum: {max_length}"
        )
    
    if '\x00' in user_input:
        raise ValidationError("Null byte detected in input")
    
    # Remove or replace potentially problematic characters
    # Keep this minimal - let specific validators handle their contexts
    sanitized = user_input.strip()
    
    return sanitized
