"""
OpenVAS Adapter

This module provides the adapter for executing OpenVAS/GVM vulnerability scans via WSL Kali Linux.
It interacts with the Greenbone Vulnerability Management (GVM) system using python-gvm library.

Author: NTRO Security Team
Date: 2025-10-26
"""

import logging
import re
from datetime import datetime
from typing import Any, Dict, Optional

from utils.parsers import OpenVASParser
from utils.target_parser import UniversalTargetParser

from .base_adapter import BaseAdapter, ScanResult

logger = logging.getLogger(__name__)


class OpenVASAdapter(BaseAdapter):
    """
    Adapter for OpenVAS/GVM vulnerability scanner

    This adapter uses gvm-cli to interact with OpenVAS through the GVM API.
    Requires OpenVAS to be properly configured and running in WSL.
    """

    def __init__(
        self, 
        wsl_helper: Optional[Any] = None, 
        gvm_socket: str = "/run/gvmd/gvmd.sock",
        gvm_username: Optional[str] = None,
        gvm_password: Optional[str] = None
    ):
        """
        Initialize OpenVAS adapter

        Args:
            wsl_helper: WSL helper instance for command execution
            gvm_socket: Path to GVM socket (default: /run/gvmd/gvmd.sock)
            gvm_username: GVM username for authentication (from GVM_USERNAME env var)
            gvm_password: GVM password for authentication (from GVM_PASSWORD env var)
        """
        import os
        
        if wsl_helper is None:
            from utils.wsl_helper import WSLHelper

            wsl_helper = WSLHelper(distribution="kali-linux")
        self.gvm_socket = gvm_socket
        self.gvm_username = gvm_username or os.getenv("GVM_USERNAME", "admin")
        self.gvm_password = gvm_password or os.getenv("GVM_PASSWORD", "admin")
        
        if not self.gvm_password:
            import logging
            logging.warning("GVM_PASSWORD not set - using default password 'admin'")
            self.gvm_password = "admin"
        
        super().__init__(wsl_helper)

    def get_tool_name(self) -> str:
        return "gvm-cli"  # We check for gvm-cli which is used to interact with OpenVAS

    def get_version_flag(self) -> str:
        return "--version"

    def get_default_options(self) -> Dict[str, Any]:
        """
        Get default OpenVAS scan options

        Returns:
            Dictionary of default options
        """
        return {
            "scan_config": "daba56c8-73ec-11df-a475-002264764cea",  # Full and fast
            # All TCP and Nmap top 100 UDP
            "port_list": "33d0cd82-57c6-11e1-8ed1-406186ea4fc5",
            "alive_test": "ICMP Ping",
            "max_checks": 4,
            "max_hosts": 20,
        }

    def get_default_timeout(self) -> int:
        """OpenVAS scans can take very long"""
        return 7200  # 2 hours (OpenVAS scans often exceed 1 hour)

    def validate_target(self, target: str) -> bool:
        """
        Validate target using UniversalTargetParser
        
        Now supports ALL formats:
        - URLs: http://example.com (auto-strips to hostname)
        - IPv4: 192.168.1.1, 10.0.0.0/24
        - IPv6: 2001:db8::1
        - Hostnames: scanme.nmap.org
        - CIDR: 192.168.1.0/24, 2001:db8::/32
        - Ranges: 192.168.1.1-254

        Args:
            target: Target in any format

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
        Build OpenVAS/GVM scan command using python-gvm library (safe construction)

        This creates a command that executes the gvm_scan_script.py which:
        1. Authenticates with GVM
        2. Creates a target
        3. Creates a task
        4. Starts the task
        5. Waits for completion (with polling)
        6. Retrieves the report

        Args:
            target: Target to scan
            scan_type: Type of scan (basic, full, quick, custom)
            options: Additional options (scan_config, port_list, alive_test, max_checks, max_hosts)

        Returns:
            Command string to execute the Python script
            
        Raises:
            ValueError: If target is invalid
        """
        # 🔒 SECURITY: Validate target before processing
        if not self.validate_target(target):
            raise ValueError(f"Invalid or malicious target: {target}")
        
        # 🌐 UNIVERSAL TARGET PARSING: Convert any target format to OpenVAS-compatible format
        try:
            parsed_target = UniversalTargetParser.parse(target)
            openvas_target = parsed_target.openvas_format  # Hostname/IP without URL
            
            logger.info(f"Target conversion for OpenVAS: '{target}' -> '{openvas_target}' (type: {parsed_target.target_type})")
        except Exception as e:
            logger.error(f"Failed to parse target '{target}': {e}")
            raise ValueError(f"Invalid target format: {target}")
        
        # Merge default options with user options
        merged_options = self.get_default_options()
        if options:
            merged_options.update(options)
        
        # Extract OpenVAS-specific options for passing to script
        openvas_options = {
            "scan_config": merged_options.get("scan_config"),
            "port_list": merged_options.get("port_list"),
            "alive_test": merged_options.get("alive_test"),
            "max_checks": merged_options.get("max_checks"),
            "max_hosts": merged_options.get("max_hosts"),
        }
        
        # Remove None values
        openvas_options = {k: v for k, v in openvas_options.items() if v is not None}
        
        logger.info(f"OpenVAS options: {openvas_options}")
        
        # 🔒 SECURITY: Use WSLCommandValidator for safe command construction
        from utils.input_validation import WSLCommandValidator
        
        # Get the path to the gvm_scan_script.py
        import os
        script_dir = os.path.dirname(os.path.abspath(__file__))
        script_path = os.path.join(script_dir, "gvm_scan_script.py")
        
        # Convert Windows path to WSL path if needed
        if script_path.startswith('D:\\'):
            script_path = script_path.replace('D:\\', '/mnt/d/').replace('\\', '/')
        
        # Build command using array-based construction (use parsed target)
        cmd_parts = [
            script_path,
            openvas_target,  # Use OpenVAS-formatted target
            scan_type,
            self.gvm_socket,
            self.gvm_username,
            self.gvm_password
        ]
        
        # Add options as JSON string if any options are provided
        if openvas_options:
            import json
            cmd_parts.append(json.dumps(openvas_options))
        
        # 🔒 SECURITY: Build safe WSL command using validator
        try:
            wsl_cmd = WSLCommandValidator.build_wsl_command(
                distro="kali-linux",
                tool="python3",
                tool_args=cmd_parts
            )
            # Convert array to shell command string (safe because array is pre-validated)
            import shlex
            command = ' '.join(shlex.quote(arg) for arg in wsl_cmd)
            logger.info("Built GVM scan command using python-gvm library (validated)")
            return command
        except ValueError as e:
            logger.error("Command validation failed: %s", str(e))
            raise

    def execute_scan(
        self,
        target: str,
        scan_type: str = "basic",
        options: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
    ) -> ScanResult:
        """
        Execute OpenVAS scan using python-gvm library

        Args:
            target: Target URL/hostname/IP
            scan_type: Type of scan (basic, full, quick, custom)
            options: Additional options
            timeout: Timeout in seconds

        Returns:
            ScanResult object
        """
        logger.info("Starting OpenVAS %s scan on %s", scan_type, target)

        if options is None:
            options = {}

        # 🔒 CRITICAL: Check if GVM socket exists before attempting scan
        start_time = datetime.now()
        if not self._check_and_handle_gvm_socket():
            error_msg = (
                f"GVM socket not found at {self.gvm_socket}. "
                f"OpenVAS/GVM service is not running in WSL. "
                f"Please ensure OpenVAS is installed and running in Kali Linux WSL environment. "
                f"Socket path: {self.gvm_socket}"
            )
            logger.error(error_msg)
            end_time = datetime.now()
            execution_time = (end_time - start_time).total_seconds()
            return ScanResult(
                success=False,
                tool="openvas",
                target=target,
                raw_output="",
                error_message=error_msg,
                execution_time=execution_time,
            )

        # Build command
        command = self.build_command(target, scan_type, options)

        # Execute scan
        exec_timeout = timeout if timeout is not None else options.get("timeout", 3600)
        result = self.wsl_helper.execute_command(
            command,
            timeout=exec_timeout,
            check_success=False
        )
        end_time = datetime.now()
        execution_time = (end_time - start_time).total_seconds()

        # Check for errors
        if not result.success:
            error_msg = f"OpenVAS scan failed: {result.stderr}"
            logger.error(error_msg)
            return ScanResult(
                success=False,
                tool="openvas",
                target=target,
                raw_output=result.stderr,
                error_message=error_msg,
                execution_time=execution_time,
            )

        # Parse output
        try:
            parsed_data = self.parse_output(result.stdout)
        except Exception as e:
            logger.error("Failed to parse OpenVAS output: %s", str(e))
            parsed_data = None

        logger.info(
            "OpenVAS scan completed in %.2fs",
            execution_time
        )

        return ScanResult(
            success=True,
            tool="openvas",
            target=target,
            raw_output=result.stdout,
            parsed_output=parsed_data,
            execution_time=execution_time,
            scan_metadata={"scan_type": scan_type},
        )

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
        Parse OpenVAS XML report

        Args:
            raw_output: Raw XML output from OpenVAS

        Returns:
            Parsed output dictionary
        """
        try:
            # Extract XML content from the output
            # Look for the <get_reports_response> tag
            xml_start = raw_output.find("<get_reports_response")

            if xml_start == -1:
                # Try alternative start tags
                xml_start = raw_output.find("<report ")

            if xml_start != -1:
                xml_content = raw_output[xml_start:]

                # Try to find end tag
                xml_end = xml_content.find("</get_reports_response>")
                if xml_end != -1:
                    xml_content = xml_content[: xml_end + 23]

                return OpenVASParser.parse_xml(xml_content)
            else:
                raise ValueError("No XML report found in output")

        except Exception as e:
            logger.error("Failed to parse OpenVAS output: %s", str(e))
            # Try to extract any error messages
            if "Error:" in raw_output:
                error_lines = [
                    line for line in raw_output.split("\n") if "Error:" in line
                ]
                raise ValueError(f"OpenVAS scan failed: {'; '.join(error_lines)}")
            raise

    def _check_and_handle_gvm_socket(self) -> bool:
        """
        Check if GVM socket exists and attempt recovery if not found

        Returns:
            True if socket exists, False otherwise
            
        Raises:
            No exceptions - logs all issues
        """
        try:
            # Check if gvmd socket exists using ls (simpler than test -S)
            check_cmd = f"ls -la {self.gvm_socket}"
            result = self.wsl_helper.execute_command(
                check_cmd, timeout=10, check_success=False
            )

            if result.success and self.gvm_socket in result.stdout:
                logger.info("✓ GVM socket found at %s", self.gvm_socket)
                return True
            
            # Socket doesn't exist - try to find alternative socket paths
            logger.warning("✗ GVM socket not found at %s - searching for alternative paths", self.gvm_socket)
            
            # Try common alternative socket paths
            alternative_sockets = [
                "/run/gvmd.sock",
                "/tmp/gvmd.sock",
                "/var/run/gvmd.sock",
                "/var/run/gvm/gvmd.sock",
            ]
            
            for alt_socket in alternative_sockets:
                check_alt_cmd = f"ls -la {alt_socket}"
                alt_result = self.wsl_helper.execute_command(
                    check_alt_cmd, timeout=10, check_success=False
                )
                
                if alt_result.success and alt_socket in alt_result.stdout:
                    logger.info("✓ Found alternative GVM socket at %s - updating path", alt_socket)
                    self.gvm_socket = alt_socket
                    return True
            
            # Check if GVM service is running using pgrep (simpler than ps | grep)
            ps_cmd = "pgrep -f gvmd"
            ps_result = self.wsl_helper.execute_command(
                ps_cmd, timeout=10, check_success=False
            )
            
            if not ps_result.success or not ps_result.stdout.strip():
                logger.error("✗ GVM/Greenbone services not running. Start with: sudo gvm-start")
            else:
                logger.warning("✗ GVM services appear to be running but socket not found at expected path")
            
            return False

        except Exception as e:
            logger.error("✗ Error checking GVM socket: %s", str(e))
            return False

    def check_gvm_service(self) -> bool:
        """
        Check if GVM service is running

        Returns:
            True if service is running
        """
        return self._check_and_handle_gvm_socket()

    def get_scan_configs(self) -> Dict[str, str]:
        """
        Get available scan configurations

        Returns:
            Dictionary of config names to IDs
        """
        try:
            cmd = (
                f'gvm-cli socket --socketpath {self.gvm_socket} --xml "<get_configs/>"'
            )
            result = self.wsl_helper.execute_command(cmd, timeout=30)

            # Parse XML to extract config IDs and names
            # This is a simplified version
            configs = {}

            # Extract using regex (simplified)
            import re

            pattern = r'<config id="([^"]+)">.*?<name>([^<]+)</name>'
            matches = re.findall(pattern, result.stdout, re.DOTALL)

            for config_id, name in matches:
                configs[name] = config_id

            logger.info("Found %s scan configurations", len(configs))
            return configs

        except Exception as e:
            logger.error("Failed to get scan configs: %s", str(e))
            return {}

    def execute_vulnerability_scan(
        self, target: str, config: str = "full", timeout: Optional[int] = None
    ) -> ScanResult:
        """
        Convenience method for vulnerability scanning

        Args:
            target: Target to scan
            config: Config type (basic, full, quick)
            timeout: Timeout in seconds

        Returns:
            ScanResult object
        """
        return self.execute_scan(target=target, scan_type=config, timeout=timeout)

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

    print("=== OpenVAS Adapter Test ===\n")

    try:
        # Initialize WSL helper
        wsl = WSLHelper()

        # Initialize OpenVAS adapter
        openvas = OpenVASAdapter(wsl)

        print("OpenVAS adapter initialized successfully\n")

        # Check GVM service
        print("Checking GVM service:")
        if openvas.check_gvm_service():
            print("  ✓ GVM service is running\n")
        else:
            print("  ✗ GVM service is not running")
            print("  Please start OpenVAS/GVM in your WSL environment\n")

        # Test target validation
        test_targets = [
            ("192.168.1.1", True),
            ("192.168.1.0/24", True),
            ("example.com", True),
            ("999.999.999.999", False),
        ]

        print("Testing target validation:")
        for target, expected in test_targets:
            result = openvas.validate_target(target)
            status = "✓" if result == expected else "✗"
            print(f"  {status} {target}: {result}")

        print("\n" + "=" * 50 + "\n")

        # Get available scan configs
        print("Available scan configurations:")
        try:
            configs = openvas.get_scan_configs()
            for name, config_id in list(configs.items())[:5]:  # Show first 5
                print(f"  - {name}: {config_id}")
            if len(configs) > 5:
                print(f"  ... and {len(configs) - 5} more")
        except Exception as e:
            print(f"  Could not retrieve configs: {str(e)}")

        print("\n" + "=" * 50)
        print("\nNote: To run actual scans, execute:")
        print("  result = openvas.execute_vulnerability_scan('192.168.1.1')")
        print("\nWarning: OpenVAS scans can take a very long time!")

    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback

        traceback.print_exc()
