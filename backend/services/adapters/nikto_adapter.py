"""
Nikto Scanner Adapter

Adapter for running Nikto web server scanner via WSL Kali Linux.
Nikto is a web server scanner that tests for dangerous files, outdated versions,
and server configuration issues.

Author: NTRO Security Team
Date: 2025-10-22
"""

import logging
import os
import sys
from defusedxml import ElementTree as ET
from datetime import datetime
from typing import Any, Dict, Optional

from services.adapters.base_adapter import BaseAdapter
from utils.wsl_helper import WSLHelper
from utils.target_parser import UniversalTargetParser

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)


logger = logging.getLogger(__name__)


class NiktoAdapter(BaseAdapter):
    """
    Adapter for Nikto web vulnerability scanner

    Nikto scans web servers for:
    - Dangerous files and CGIs
    - Outdated server software
    - Server configuration issues
    - Default files and programs
    - SSL/TLS issues
    """

    def __init__(self, wsl_helper: Optional[WSLHelper] = None):
        """
        Initialize Nikto adapter

        Args:
            wsl_helper: WSL helper instance (creates new if None)
        """
        if wsl_helper is None:
            wsl_helper = WSLHelper(distribution="kali-linux")
        super().__init__(wsl_helper)

    def get_tool_name(self) -> str:
        """Return tool name"""
        return "nikto"

    def validate_target(self, target: str) -> bool:
        """
        Validate target using UniversalTargetParser
        
        Now supports ALL formats:
        - URLs: http://example.com, https://192.168.1.1:8080
        - Hostnames: example.com, scanme.nmap.org (auto-adds http://)
        - IPv4/IPv6: 192.168.1.1, 2001:db8::1 (auto-adds http://)

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

    def get_default_options(self) -> Dict[str, Any]:
        """
        Get default Nikto scan options

        Returns:
            Default options dictionary
        """
        return {
            "port": 80,
            "ssl": False,
            "timeout": 600,
            "tuning": "1234567890ab",  # All tests
            "format": "xml",
            "evasion": None,
            "plugins": "ALL",
        }

    def build_command(
        self,
        target: str,
        scan_type: str = "basic",
        options: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Build Nikto command using safe array-based construction

        Args:
            target: Target URL/hostname
            scan_type: Type of scan (basic, full, quick, ssl, custom)
            options: Additional options

        Returns:
            Nikto command string
        """
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")

        # 🔒 SECURITY: Use WSLCommandValidator for safe command construction
        from utils.input_validation import WSLCommandValidator

        # 🌐 UNIVERSAL TARGET PARSING: Convert any target format to Nikto-compatible URL
        try:
            parsed_target = UniversalTargetParser.parse(target)
            nikto_target = parsed_target.nikto_format  # Always returns full URL
            
            logger.info(f"Target conversion for Nikto: '{target}' -> '{nikto_target}' (type: {parsed_target.target_type})")
        except Exception as e:
            logger.error(f"Failed to parse target '{target}': {e}")
            raise ValueError(f"Invalid target format: {target}")

        # Merge options
        opts = self.get_default_options()
        if options:
            opts.update(options)

        # Target is already formatted as full URL by parser
        target_url = nikto_target

        # Build command based on scan type (array-based)
        cmd_parts = ["nikto"]
        
        if scan_type == "quick":
            # Quick scan - reduced tuning (respect user override)
            cmd_parts.extend(["-h", target_url])
            tuning = opts.get("tuning", "1")  # Default: Only interesting files
            cmd_parts.extend(["-Tuning", str(tuning)])
            cmd_parts.extend(["-timeout", str(opts.get("timeout", 300))])
            cmd_parts.extend(["-Format", "xml"])  # Always use XML format for reliable parsing
            cmd_parts.extend(["-output", "-"])  # Output to stdout

        elif scan_type == "ssl":
            # SSL/TLS specific scan (respect user override)
            cmd_parts.extend(["-h", target_url])
            tuning = opts.get("tuning", "b")  # Default: SSL tests
            cmd_parts.extend(["-Tuning", str(tuning)])
            cmd_parts.append("-ssl")
            cmd_parts.extend(["-timeout", str(opts.get("timeout", 600))])
            cmd_parts.extend(["-Format", "xml"])  # Always use XML format for reliable parsing
            cmd_parts.extend(["-output", "-"])  # Output to stdout

        elif scan_type == "full":
            # Comprehensive scan (respect user override)
            cmd_parts.extend(["-h", target_url])
            tuning = opts.get("tuning", "1234567890abcde")  # Default: All tests
            cmd_parts.extend(["-Tuning", str(tuning)])
            cmd_parts.extend(["-timeout", str(opts.get("timeout", 900))])
            cmd_parts.extend(["-Format", "xml"])  # Always use XML format for reliable parsing
            cmd_parts.extend(["-output", "-"])  # Output to stdout

            if opts.get("ssl"):
                cmd_parts.append("-ssl")

            # Add evasion techniques if specified
            if opts.get("evasion"):
                cmd_parts.extend(["-evasion", str(opts["evasion"])])

        elif scan_type == "custom":
            # Custom scan with user options
            cmd_parts.extend(["-h", target_url])
            cmd_parts.extend(["-Format", "xml"])
            cmd_parts.extend(["-output", "-"])  # Output to stdout

            if "tuning" in opts:
                cmd_parts.extend(["-Tuning", str(opts["tuning"])])

            if opts.get("ssl"):
                cmd_parts.append("-ssl")

            if "timeout" in opts:
                cmd_parts.extend(["-timeout", str(opts["timeout"])])

            if "evasion" in opts:
                cmd_parts.extend(["-evasion", str(opts["evasion"])])

            if "plugins" in opts and opts["plugins"] != "ALL":
                cmd_parts.extend(["-Plugins", str(opts["plugins"])])

        else:  # basic
            # Basic scan (respect user override)
            cmd_parts.extend(["-h", target_url])
            tuning = opts.get("tuning", "123456")  # Default: Common tests
            cmd_parts.extend(["-Tuning", str(tuning)])
            cmd_parts.extend(["-timeout", str(opts.get("timeout", 600))])
            cmd_parts.extend(["-Format", "xml"])  # Always use XML format for reliable parsing
            cmd_parts.extend(["-output", "-"])  # Output to stdout

            if opts.get("ssl"):
                cmd_parts.append("-ssl")

        # 🔒 SECURITY: Build safe WSL command using validator
        try:
            wsl_cmd = WSLCommandValidator.build_wsl_command(
                distro="kali-linux",
                tool="nikto",
                tool_args=cmd_parts[1:]  # Skip 'nikto' as it's added by build_wsl_command
            )
            # Convert array to shell command string (safe because array is pre-validated)
            import shlex
            command = ' '.join(shlex.quote(arg) for arg in wsl_cmd)
            logger.info("Built Nikto command (validated)")
            return command
        except ValueError as e:
            logger.error("Command validation failed: %s", str(e))
            raise

    def execute_scan(  # type: ignore[override]
        self,
        target: str,
        scan_type: str = "basic",
        options: Optional[Dict[str, Any]] = None,
    ):
        """
        Execute Nikto scan

        Args:
            target: Target URL/hostname
            scan_type: Type of scan
            options: Additional options

        Returns:
            ScanResult object
        """
        from services.adapters.base_adapter import ScanResult
        
        logger.info("Starting Nikto %s scan on %s", scan_type, target)

        # Build command
        command = self.build_command(target, scan_type, options)

        # Execute scan
        start_time = datetime.now()
        result = self.wsl_helper.execute_command(
            command, timeout=options.get("timeout", 900) if options else 900,
            check_success=False  # Nikto may return non-zero on no findings
        )
        end_time = datetime.now()
        execution_time = (end_time - start_time).total_seconds()

        # Nikto returns 0 on success, 1 on no findings (which is still OK)
        # Only treat it as error if stderr has actual error messages
        if not result.success and result.return_code not in [0, 1]:
            error_msg = f"Nikto scan failed: {result.stderr}"
            logger.error(error_msg)
            return ScanResult(
                success=False,
                tool="nikto",
                target=target,
                raw_output=result.stderr,
                error_message=error_msg,
                execution_time=execution_time,
            )

        # Parse output
        try:
            parsed_data = self.parse_output(result.stdout)
        except Exception as e:
            logger.error("Failed to parse Nikto output: %s", str(e))
            parsed_data = None

        logger.info(
            "Nikto scan completed in %.2fs. Found %d issues",
            execution_time,
            len(parsed_data.get("vulnerabilities", [])) if parsed_data else 0,
        )

        return ScanResult(
            success=True,
            tool="nikto",
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
        Parse Nikto XML output

        Args:
            raw_output: Raw XML output from Nikto

        Returns:
            Parsed results dictionary
        """
        try:
            # Parse XML
            root = ET.fromstring(raw_output)

            # Extract scan information
            scan_details = root.find(".//scandetails")
            target_info = {
                "target_ip": (
                    scan_details.get("targetip") if scan_details is not None else None
                ),
                "target_hostname": (
                    scan_details.get("targethostname")
                    if scan_details is not None
                    else None
                ),
                "target_port": (
                    scan_details.get("targetport") if scan_details is not None else None
                ),
                "target_banner": (
                    scan_details.get("targetbanner")
                    if scan_details is not None
                    else None
                ),
                "start_time": (
                    scan_details.get("starttime") if scan_details is not None else None
                ),
                "site_ip": (
                    scan_details.get("siteip") if scan_details is not None else None
                ),
            }

            # Extract vulnerabilities/findings
            vulnerabilities = []
            for item in root.findall(".//item"):
                desc_elem = item.find("description")
                uri_elem = item.find("uri")
                namelink_elem = item.find("namelink")
                iplink_elem = item.find("iplink")
                
                # Get description text
                description = desc_elem.text if desc_elem is not None else ""
                
                # Determine severity based on OSVDB ID and description keywords
                severity = "info"  # Default
                osvdb_id = item.get("osvdbid", "")
                
                # High severity indicators
                if any(keyword in description.lower() for keyword in [
                    "sql injection", "command injection", "remote code execution",
                    "arbitrary code", "buffer overflow", "authentication bypass",
                    "directory traversal", "file inclusion", "xxe"
                ]):
                    severity = "high"
                # Medium severity indicators
                elif any(keyword in description.lower() for keyword in [
                    "cross-site scripting", "xss", "csrf", "session fixation",
                    "weak password", "default credentials", "information disclosure",
                    "clickjacking", "x-frame-options", "security header", "outdated",
                    "vulnerable", "missing patch", "wildcard"
                ]):
                    severity = "medium"
                # Low severity indicators
                elif any(keyword in description.lower() for keyword in [
                    "banner", "version disclosure", "x-powered-by",
                    "server info", "header", "cookie"
                ]):
                    severity = "low"

                vuln = {
                    "id": item.get("id"),
                    "osvdb_id": osvdb_id,
                    "osvdb_link": item.get("osvdblink"),
                    "method": item.get("method"),
                    "description": description,
                    "uri": uri_elem.text if uri_elem is not None else "",
                    "name_link": (
                        namelink_elem.text if namelink_elem is not None else ""
                    ),
                    "ip_link": iplink_elem.text if iplink_elem is not None else "",
                    "severity": severity,  # Add severity field
                    "title": description[:100] if description else f"Nikto Finding {item.get('id', 'unknown')}",  # Add title field
                }
                vulnerabilities.append(vuln)

            # Statistics
            statistics = root.find(".//statistics")
            stats = {}
            if statistics is not None:
                stats = {
                    "elapsed_time": statistics.get("elapsedtime"),
                    "items_found": statistics.get("itemsfound"),
                    "items_tested": statistics.get("itemstested"),
                }

            # Calculate severity counts
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "info").lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1

            return {
                "target_info": target_info,
                "vulnerabilities": vulnerabilities,
                "vulnerability_count": len(vulnerabilities),
                "severity_counts": severity_counts,
                "statistics": stats,
            }

        except ET.ParseError as e:
            logger.error("XML parsing error: %s", str(e))
            # Return text-based parsing as fallback with proper structure
            return {
                "raw_text": raw_output,
                "vulnerabilities": [],
                "vulnerability_count": 0,
                "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                "parse_error": str(e),
                "target_info": {},
                "statistics": {},
            }


# Test/Example usage
if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    print("=" * 60)
    print("Nikto Adapter Test")
    print("=" * 60)

    adapter = NiktoAdapter()

    # Test 1: Validate target
    print("\nTest 1: Target Validation")
    test_targets = ["http://example.com", "example.com", "192.168.1.1", ""]
    for target in test_targets:
        valid = adapter.validate_target(target)
        print(f"  {target:30s} -> {'Valid' if valid else 'Invalid'}")

    # Test 2: Build commands
    print("\nTest 2: Command Building")
    target = "http://localhost"
    for scan_type in ["quick", "basic", "full", "ssl"]:
        cmd = adapter.build_command(target, scan_type)
        print(f"  {scan_type:10s}: {cmd[:80]}...")

    # Test 3: Check tool availability
    print("\nTest 3: Tool Availability")
    available = adapter.wsl_helper.check_tool_availability("nikto")
    if available:
        version = adapter.wsl_helper.get_tool_version("nikto")
        print(f"  ✓ Nikto is available: {version}")
    else:
        print("  ✗ Nikto is not installed")
        print("\n  To install: sudo apt update && sudo apt install -y nikto")

    print("\n" + "=" * 60)
    print("Nikto adapter initialized successfully!")
    print("=" * 60)
    def check_tool_availability(self) -> bool:
        """
        Check if the tool is available in WSL
        
        Returns:
            True if tool is available, False otherwise
        """
        try:
            return bool(self.wsl_helper.check_tool_availability("nikto"))
        except Exception as e:
            self.logger.warning(f"Failed to check tool availability: {e}")
            return False


