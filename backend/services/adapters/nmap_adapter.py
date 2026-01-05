"""
Nmap Adapter

This module provides the adapter for executing Nmap scans via WSL Kali Linux.
It handles command generation, execution, and XML output parsing.

Author: NTRO Security Team
Date: 2025-10-22
"""

import logging
import re
from typing import Any, Dict, Optional

from utils.parsers import NmapParser
from utils.target_parser import UniversalTargetParser

from .base_adapter import BaseAdapter, ScanResult

logger = logging.getLogger(__name__)


class NmapAdapter(BaseAdapter):
    """
    Adapter for Nmap network scanner

    Supports various scan types and parses XML output into structured format.
    """

    def __init__(self, wsl_helper: Optional[Any] = None):
        """
        Initialize Nmap adapter

        Args:
            wsl_helper: WSL helper instance (creates new if None)
        """
        if wsl_helper is None:
            from utils.wsl_helper import WSLHelper

            wsl_helper = WSLHelper(distribution="kali-linux")
        super().__init__(wsl_helper)

    def get_tool_name(self) -> str:
        return "nmap"

    def get_version_flag(self) -> str:
        return "-V"

    def get_default_options(self) -> Dict[str, Any]:
        """
        Get default Nmap options

        Returns:
            Dictionary of default options
        """
        return {
            "output_format": "xml",  # Use XML output for parsing
            "timing": "T4",  # Aggressive timing
            "ports": None,  # All ports by default
            "scripts": None,  # No scripts by default
            "os_detection": False,  # OS detection disabled by default
            "service_detection": True,  # Service detection enabled
            "verbose": True,  # Verbose output
        }

    def get_default_timeout(self) -> int:
        """Nmap scans can take longer"""
        return 600  # 10 minutes

    def validate_target(self, target: str) -> bool:
        """
        Validate target format using UniversalTargetParser
        
        Now supports ALL formats:
        - URLs: http://example.com (auto-converted to hostname)
        - IPv4: 192.168.1.1, 10.0.0.1-254
        - IPv6: 2001:db8::1, [2001:db8::1]:8080
        - Hostnames: scanme.nmap.org, localhost
        - CIDR: 192.168.1.0/24, 2001:db8::/32
        - Ports: example.com:8080 (port extracted for -p flag)

        Args:
            target: Target to validate (any format)

        Returns:
            True if valid
        """
        try:
            # Use universal parser - it handles all formats and security checks
            parsed = UniversalTargetParser.parse(target)
            return True
        except (ValueError, Exception) as e:
            logger.warning(f"Invalid target '{target}': {e}")
            return False

    def build_command(
        self, target: str, scan_type: str, options: Dict[str, Any]
    ) -> str:
        """
        Build Nmap command using safe array-based construction

        Args:
            target: Target to scan
            scan_type: Type of scan (basic, full, quick, custom)
            options: Additional options

        Returns:
            Nmap command string
            
        Raises:
            ValueError: If target is invalid
        """
        # 🔒 SECURITY: Validate target before processing
        if not self.validate_target(target):
            raise ValueError(f"Invalid or malicious target: {target}")
        
        # 🔒 SECURITY: Validate ports if provided in options
        if options.get("ports"):
            from utils.input_validation import PortValidator, ValidationError
            try:
                PortValidator.validate_port_range(str(options["ports"]))
            except ValidationError as e:
                raise ValueError(f"Invalid port specification: {str(e)}")
        
        # 🔒 SECURITY: Use WSLCommandValidator for safe command construction
        from utils.input_validation import WSLCommandValidator
        
        # 🌐 UNIVERSAL TARGET PARSING: Convert any target format to Nmap-compatible format
        try:
            parsed_target = UniversalTargetParser.parse(target)
            nmap_target = parsed_target.nmap_format
            
            # Extract port if present (for -p flag)
            target_port = parsed_target.port
            
            logger.info(f"Target conversion: '{target}' -> '{nmap_target}' (type: {parsed_target.target_type})")
            if target_port:
                logger.info(f"Extracted port: {target_port}")
        except Exception as e:
            logger.error(f"Failed to parse target '{target}': {e}")
            raise ValueError(f"Invalid target format: {target}")
        
        # Start with base command parts as array
        cmd_parts = ["nmap"]

        # Add scan type specific options
        if scan_type == "basic":
            # Basic port scan with service detection
            cmd_parts.append("-sV")  # Service version detection
            if options.get("ports"):
                cmd_parts.extend(["-p", str(options['ports'])])
            elif target_port:
                cmd_parts.extend(["-p", str(target_port)])
            else:
                cmd_parts.extend(["--top-ports", "1000"])

        elif scan_type == "full":
            # Comprehensive scan
            cmd_parts.append("-A")  # Aggressive scan
            if options.get("ports"):
                cmd_parts.extend(["-p", str(options['ports'])])
            elif target_port:
                cmd_parts.extend(["-p", str(target_port)])
            else:
                cmd_parts.append("-p-")  # All ports

        elif scan_type == "quick":
            # Quick scan of most common ports
            cmd_parts.append("-sV")
            cmd_parts.extend(["--top-ports", "100"])
            cmd_parts.append("-T5")  # Insane timing

        elif scan_type == "stealth":
            # Stealth SYN scan
            cmd_parts.append("-sS")  # SYN scan
            cmd_parts.append("-T2")  # Polite timing
            if options.get("ports"):
                cmd_parts.extend(["-p", str(options['ports'])])
            elif target_port:
                cmd_parts.extend(["-p", str(target_port)])
            else:
                cmd_parts.extend(["--top-ports", "100"])

        elif scan_type == "custom":
            # Custom scan based on options
            if options.get("service_detection"):
                cmd_parts.append("-sV")

            if options.get("os_detection"):
                cmd_parts.append("-O")

            if options.get("ports"):
                cmd_parts.extend(["-p", str(options['ports'])])
            elif target_port:
                cmd_parts.extend(["-p", str(target_port)])

            if options.get("scripts"):
                cmd_parts.append(f"--script={options['scripts']}")

        # Add timing template (if not already set by scan type)
        if not any("-T" in str(part) for part in cmd_parts):
            timing = options.get("timing", "T4")
            if timing:
                cmd_parts.append(f"-{timing}")

        # Add verbosity
        if options.get("verbose"):
            cmd_parts.append("-v")

        # Add XML output to temp file (safely constructed filename)
        safe_target = nmap_target.replace('/', '_').replace('\\', '_').replace(':', '_')
        output_file = f"/tmp/nmap_scan_{safe_target}.xml"
        cmd_parts.extend(["-oX", output_file])

        # Add target (now in Nmap-compatible format)
        cmd_parts.append(nmap_target)

        # 🔒 SECURITY: Build safe WSL command using validator
        # This prevents command injection by using array-based construction
        try:
            wsl_cmd = WSLCommandValidator.build_wsl_command(
                distro="kali-linux",
                tool="nmap",
                tool_args=cmd_parts[1:]  # Skip 'nmap' as it's added by build_wsl_command
            )
            # Append command to read output file
            read_wsl_cmd = WSLCommandValidator.build_wsl_command(
                distro="kali-linux",
                tool="cat",
                tool_args=[output_file]
            )
            # Convert arrays to shell command strings (safe because arrays are pre-validated)
            import shlex
            full_cmd = ' '.join(shlex.quote(arg) for arg in wsl_cmd) + ' && ' + ' '.join(shlex.quote(arg) for arg in read_wsl_cmd)
            return full_cmd
        except ValueError as e:
            self.logger.error("Command validation failed: %s", str(e))
            raise

    def parse_results(self, raw_output: str) -> Dict[str, Any]:
        """
        Parse scan results (alias for parse_output for BaseAdapter compatibility)

        Args:
            raw_output: Raw output from tool

        Returns:
            Parsed results dictionary
        """
        return self.parse_output(raw_output)

    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        """
        Parse Nmap XML output

        Args:
            raw_output: Raw XML output from Nmap

        Returns:
            Parsed output dictionary
        """
        try:
            # Extract XML content (in case there's extra output)
            xml_start = raw_output.find("<?xml")
            if xml_start == -1:
                xml_start = raw_output.find("<nmaprun")

            if xml_start != -1:
                xml_content = raw_output[xml_start:]

                # Try to find end of XML
                xml_end = xml_content.rfind("</nmaprun>")
                if xml_end != -1:
                    # Include closing tag
                    xml_content = xml_content[: xml_end + 10]

                return NmapParser.parse_xml(xml_content)
            else:
                raise ValueError("No XML content found in output")

        except Exception as e:
            logger.error("Failed to parse Nmap output: %s", str(e))
            raise

    def execute_port_scan(
        self, target: str, ports: str = "1-1000", timeout: Optional[int] = None
    ) -> ScanResult:
        """
        Convenience method for basic port scanning

        Args:
            target: Target to scan
            ports: Port specification (e.g., "1-1000", "80,443", "1-65535")
            timeout: Timeout in seconds

        Returns:
            ScanResult object
        """
        return self.execute_scan(
            target=target, scan_type="basic", options={"ports": ports}, timeout=timeout
        )

    def execute_service_scan(
        self, target: str, ports: Optional[str] = None, timeout: Optional[int] = None
    ) -> ScanResult:
        """
        Convenience method for service version detection

        Args:
            target: Target to scan
            ports: Port specification (None for top 1000)
            timeout: Timeout in seconds

        Returns:
            ScanResult object
        """
        options: Dict[str, Any] = {"service_detection": True}
        if ports:
            options["ports"] = ports

        return self.execute_scan(
            target=target, scan_type="custom", options=options, timeout=timeout
        )

    def execute_os_detection(
        self, target: str, timeout: Optional[int] = None
    ) -> ScanResult:
        """
        Convenience method for OS detection

        Args:
            target: Target to scan
            timeout: Timeout in seconds

        Returns:
            ScanResult object
        """
        return self.execute_scan(
            target=target,
            scan_type="custom",
            options={"os_detection": True, "service_detection": True},
            timeout=timeout,
        )

    def execute_script_scan(
        self,
        target: str,
        scripts: str,
        ports: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> ScanResult:
        """
        Convenience method for NSE script scanning

        Args:
            target: Target to scan
            scripts: NSE scripts to run (e.g., "default,vuln")
            ports: Port specification
            timeout: Timeout in seconds

        Returns:
            ScanResult object
        """
        options = {"scripts": scripts, "service_detection": True}
        if ports:
            options["ports"] = ports

        return self.execute_scan(
            target=target, scan_type="custom", options=options, timeout=timeout
        )

    def check_tool_availability(self) -> bool:
        """
        Check if the tool is available in WSL
        
        Returns:
            True if tool is available, False otherwise
        """
        try:
            return bool(self.wsl_helper.check_tool_availability(self.tool_name))
        except Exception as e:
            self.logger.warning(f"Failed to check tool availability: {e}")
            return False



if __name__ == "__main__":
    # Example usage
    import sys

    sys.path.append("../..")

    from utils.wsl_helper import WSLHelper

    logging.basicConfig(level=logging.INFO)

    print("=== Nmap Adapter Test ===\n")

    try:
        # Initialize WSL helper
        wsl = WSLHelper()

        # Initialize Nmap adapter
        nmap = NmapAdapter(wsl)

        print("Nmap adapter initialized successfully\n")

        # Test target validation
        test_targets = [
            ("192.168.1.1", True),
            ("192.168.1.0/24", True),
            ("example.com", True),
            ("999.999.999.999", False),
            ("invalid target", False),
        ]

        print("Testing target validation:")
        for target, expected in test_targets:
            result = nmap.validate_target(target)
            status = "✓" if result == expected else "✗"
            print(f"  {status} {target}: {result}")

        print("\n" + "=" * 50 + "\n")

        # Test command building
        print("Testing command building:")

        test_cases = [
            ("192.168.1.1", "basic", {}),
            ("192.168.1.0/24", "full", {}),
            ("example.com", "quick", {}),
            ("192.168.1.1", "custom", {"ports": "80,443", "scripts": "default"}),
        ]

        for target, scan_type, options in test_cases:
            cmd = nmap.build_command(
                target, scan_type, {**nmap.get_default_options(), **options}
            )
            print(f"  {scan_type} scan of {target}:")
            print(f"    {cmd}\n")

        print("=" * 50)
        print("\nNote: To run actual scans, execute a scan method like:")
        print("  result = nmap.execute_port_scan('192.168.1.1', ports='1-100')")

    except Exception as e:
        print(f"Error: {str(e)}")
