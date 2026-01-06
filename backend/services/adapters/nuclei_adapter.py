"""
Nuclei Scanner Adapter

Adapter for running Nuclei vulnerability scanner via WSL Kali Linux.
Nuclei is a fast, template-based vulnerability scanner that uses YAML templates
to detect vulnerabilities across various protocols and technologies.

Author: NTRO Security Team
Date: 2025-10-22
"""

import json
import logging
import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

from services.adapters.base_adapter import BaseAdapter
from utils.wsl_helper import WSLHelper
from utils.target_parser import UniversalTargetParser

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)


logger = logging.getLogger(__name__)


class NucleiAdapter(BaseAdapter):
    """
    Adapter for Nuclei template-based vulnerability scanner

    Nuclei uses YAML templates to detect:
    - CVE vulnerabilities
    - Misconfigurations
    - Exposed panels and services
    - Vulnerable dependencies
    - Custom security issues
    """

    def __init__(self, wsl_helper: Optional[WSLHelper] = None):
        """
        Initialize Nuclei adapter

        Args:
            wsl_helper: WSL helper instance (creates new if None)
        """
        if wsl_helper is None:
            wsl_helper = WSLHelper(distribution="kali-linux")
        super().__init__(wsl_helper)

    def get_tool_name(self) -> str:
        """Return tool name"""
        return "nuclei"

    def validate_target(self, target: str) -> bool:
        """
        Validate target using UniversalTargetParser
        
        Now supports ALL formats:
        - URLs: http://example.com, https://192.168.1.1:8080
        - Hostnames: example.com (auto-adds http://)
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
        Get default Nuclei scan options

        Returns:
            Default options dictionary
        """
        return {
            "severity": "critical,high,medium,low,info",
            "templates": None,  # Use all templates by default
            "tags": None,
            "rate_limit": 150,  # Requests per second
            "concurrency": 25,  # Parallel templates
            "timeout": 5,  # Per-request timeout
            "retries": 1,
            "follow_redirects": True,
            "follow_host_redirects": False,
            "max_redirects": 10,
            "disable_redirects": False,
            "silent": False,
            "verbose": False,
            "debug": False,
        }

    def get_default_timeout(self) -> int:
        """
        Dynamic timeout for template-based scanning
        Scans run until natural completion (safety limit: 4 hours)
        """
        return 14400  # 4 hours - template scans can be extensive

    def build_command(
        self,
        target: str,
        scan_type: str = "basic",
        options: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """
        Build Nuclei command using safe array-based construction

        Args:
            target: Target URL/hostname/IP
            scan_type: Type of scan (basic, full, cve, misconfig, exposed, custom)
            options: Additional options

        Returns:
            WSL command array (e.g., ['wsl.exe', '-d', 'kali-linux', '--', 'nuclei', ...])
        """
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")

        # 🔒 SECURITY: Use WSLCommandValidator for safe command construction
        from utils.input_validation import WSLCommandValidator

        # 🌐 UNIVERSAL TARGET PARSING: Convert any target format to Nuclei-compatible URL
        try:
            parsed_target = UniversalTargetParser.parse(target)
            nuclei_target = parsed_target.nuclei_format  # Always returns full URL
            
            logger.info(f"Target conversion for Nuclei: '{target}' -> '{nuclei_target}' (type: {parsed_target.target_type})")
        except Exception as e:
            logger.error(f"Failed to parse target '{target}': {e}")
            raise ValueError(f"Invalid target format: {target}")

        # Merge options
        opts = self.get_default_options()
        if options:
            opts.update(options)

        # Target is already formatted as full URL by parser
        target_url = nuclei_target

        # Build command based on scan type (array-based)
        cmd_parts = ["nuclei", "-u", target_url, "-jsonl"]

        if scan_type == "cve":
            # CVE-focused scan - respect user severity or default to critical,high,medium
            severity = opts.get("severity", "critical,high,medium")
            cmd_parts.extend(["-tags", "cve", "-severity", severity])

        elif scan_type == "misconfig":
            # Misconfiguration scan - respect user severity or default to critical,high,medium,low
            severity = opts.get("severity", "critical,high,medium,low")
            cmd_parts.extend([
                "-tags", "misconfig,exposure,config",
                "-severity", severity
            ])

        elif scan_type == "exposed":
            # Exposed panels and services - respect user severity or default to critical,high,medium,low
            severity = opts.get("severity", "critical,high,medium,low")
            cmd_parts.extend([
                "-tags", "exposure,panel,login,default-login",
                "-severity", severity
            ])

        elif scan_type == "full":
            # Comprehensive scan with all templates - respect user severity or default to all
            severity = opts.get("severity", "critical,high,medium,low,info")
            cmd_parts.extend(["-severity", severity])

        elif scan_type == "custom":
            # Custom scan with user options
            if opts.get("severity"):
                cmd_parts.extend(["-severity", str(opts["severity"])])

            if opts.get("tags"):
                cmd_parts.extend(["-tags", str(opts["tags"])])

            if opts.get("templates"):
                cmd_parts.extend(["-t", str(opts["templates"])])

        else:  # basic
            # Basic scan - respect user severity or default to critical,high
            severity = opts.get("severity", "critical,high")
            cmd_parts.extend(["-severity", severity])

        # Add common options
        cmd_parts.extend([
            "-rate-limit", str(opts.get("rate_limit", 150)),
            "-concurrency", str(opts.get("concurrency", 25)),
            "-timeout", str(opts.get("timeout", 5)),
            "-retries", str(opts.get("retries", 1))
        ])

        # Redirect options
        if opts.get("follow_redirects", True):
            cmd_parts.append("-follow-redirects")

        if opts.get("follow_host_redirects", False):
            cmd_parts.append("-follow-host-redirects")

        if opts.get("max_redirects"):
            cmd_parts.extend(["-max-redirects", str(opts["max_redirects"])])

        # Verbosity
        if opts.get("silent"):
            cmd_parts.append("-silent")
        elif opts.get("verbose"):
            cmd_parts.append("-verbose")

        if opts.get("debug"):
            cmd_parts.append("-debug")

        # 🔒 SECURITY: Build safe WSL command using validator
        try:
            wsl_cmd = WSLCommandValidator.build_wsl_command(
                distro="kali-linux",
                tool="nuclei",
                tool_args=cmd_parts[1:]  # Skip 'nuclei' as it's added by build_wsl_command
            )
            logger.info("Built Nuclei WSL command array (validated)")
            return wsl_cmd
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
        Execute Nuclei scan

        Args:
            target: Target URL/hostname/IP
            scan_type: Type of scan
            options: Additional options

        Returns:
            ScanResult object
        """
        from services.adapters.base_adapter import ScanResult
        
        logger.info("Starting Nuclei %s scan on %s", scan_type, target)

        # Build command
        command = self.build_command(target, scan_type, options)

        # Determine timeout: use provided value or default to 30 minutes
        # Nuclei scans can vary: quick tests (30s) or full scans (30+ minutes)
        provided_timeout = options.get("timeout") if options else None
        if provided_timeout:
            timeout = provided_timeout  # Use whatever user specifies
        else:
            timeout = 1800  # Default: 30 minutes (1800 seconds)
        
        logger.info("Nuclei timeout set to %d seconds (%.1f minutes)", timeout, timeout / 60)

        # Execute scan
        start_time = datetime.now()
        result = self.wsl_helper.execute_command(
            command, timeout=timeout,
            check_success=False  # Nuclei may return non-zero on no findings
        )
        end_time = datetime.now()
        execution_time = (end_time - start_time).total_seconds()
        
        # Check if scan timed out (return_code=-1 indicates timeout)
        timed_out = (result.return_code == -1)
        if timed_out:
            logger.warning(f"⚠️ Nuclei scan timed out after {timeout}s - saving partial results")

        # Nuclei returns 0 on success, 2 on no findings (which is still OK)
        # Allow timeout (-1) to continue with partial results
        # Only treat it as error if stderr has actual error messages and no output
        if not result.success and result.return_code not in [0, 2, -1]:
            error_msg = f"Nuclei scan failed: {result.stderr}"
            logger.error(error_msg)
            return ScanResult(
                success=False,
                tool="nuclei",
                target=target,
                raw_output=result.stderr,
                error_message=error_msg,
                execution_time=execution_time,
            )

        # Parse output (works even for partial/timeout results)
        try:
            parsed_data = self.parse_output(result.stdout)
        except Exception as e:
            logger.error("Failed to parse Nuclei output: %s", str(e))
            parsed_data = None

        findings_count = len(parsed_data.get("findings", [])) if parsed_data else 0
        
        if timed_out:
            logger.warning(
                f"⚠️ Nuclei scan TIMED OUT after {timeout}s ({execution_time:.2f}s elapsed). "
                f"Saved {findings_count} partial findings"
            )
        else:
            logger.info(
                "Nuclei scan completed in %.2fs. Found %d findings",
                execution_time,
                findings_count,
            )

        return ScanResult(
            success=True,  # Consider timeout as "success with partial results"
            tool="nuclei",
            target=target,
            raw_output=result.stdout,
            parsed_output=parsed_data,
            execution_time=execution_time,
            scan_metadata={
                "scan_type": scan_type,
                "timed_out": timed_out,
                "timeout_seconds": timeout if timed_out else None
            },
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
        Parse Nuclei JSON output

        Args:
            raw_output: Raw JSON Lines output from Nuclei

        Returns:
            Parsed results dictionary
        """
        findings = []

        # Nuclei outputs JSON Lines (one JSON object per line)
        for line in raw_output.strip().split("\n"):
            if not line.strip():
                continue

            try:
                finding = json.loads(line)

                # Extract key information with safe navigation
                info = finding.get("info") or {}
                classification = info.get("classification") or {}
                
                parsed_finding = {
                    "template_id": finding.get("template-id"),
                    "template_name": info.get("name"),
                    "severity": str(info.get("severity") or "info").lower(),
                    "description": info.get("description"),
                    "tags": info.get("tags") or [],
                    "classification": classification,
                    "matched_at": finding.get("matched-at"),
                    "matcher_name": finding.get("matcher-name"),
                    "extracted_results": finding.get("extracted-results") or [],
                    "curl_command": finding.get("curl-command"),
                    "type": finding.get("type"),
                    "host": finding.get("host"),
                    "ip": finding.get("ip"),
                    "timestamp": finding.get("timestamp"),
                }

                # Add CVE information if present
                if "cve-id" in classification:
                    parsed_finding["cve_id"] = classification["cve-id"]

                # Add CWE information if present
                if "cwe-id" in classification:
                    parsed_finding["cwe_id"] = classification["cwe-id"]

                findings.append(parsed_finding)

            except json.JSONDecodeError as e:
                logger.warning("Failed to parse JSON line: %s", e)
                continue

        # Aggregate statistics
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        template_counts: Dict[str, int] = {}
        tag_counts: Dict[str, int] = {}

        for finding in findings:
            # Count by severity
            severity = str(finding.get("severity") or "info").lower()  # ✅ FIX: Ensure string
            if severity in severity_counts:
                severity_counts[severity] += 1

            # Count by template
            template_id = finding.get("template_id")
            if template_id:
                template_counts[template_id] = template_counts.get(template_id, 0) + 1

            # Count by tags
            for tag in finding.get("tags", []):
                tag_counts[tag] = tag_counts.get(tag, 0) + 1

        return {
            "findings": findings,
            "total_findings": len(findings),
            "vulnerability_count": len(findings),  # For consistency with task summary extraction
            "severity_counts": severity_counts,
            "template_counts": template_counts,
            "tag_counts": tag_counts,
            "unique_templates": len(template_counts),
            "unique_tags": len(tag_counts),
        }


# Test/Example usage
if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    print("=" * 60)
    print("Nuclei Adapter Test")
    print("=" * 60)

    adapter = NucleiAdapter()

    # Test 1: Validate target
    print("\nTest 1: Target Validation")
    test_targets = ["http://example.com", "example.com", "192.168.1.1", ""]
    for target in test_targets:
        valid = adapter.validate_target(target)
        print(f"  {target:30s} -> {'Valid' if valid else 'Invalid'}")

    # Test 2: Build commands
    print("\nTest 2: Command Building")
    target = "http://localhost"
    for scan_type in ["basic", "cve", "misconfig", "exposed", "full"]:
        cmd = adapter.build_command(target, scan_type)
        print(f"  {scan_type:10s}: {cmd[:80]}...")

    # Test 3: Check tool availability
    print("\nTest 3: Tool Availability")
    available = adapter.wsl_helper.check_tool_availability("nuclei")
    if available:
        version = adapter.wsl_helper.get_tool_version("nuclei")
        print(f"  ✓ Nuclei is available: {version}")
    else:
        print("  ✗ Nuclei is not installed")
        print("\n  To install:")
        print(
            "  1. Download: wget https://github.com/projectdiscovery/nuclei/releases/"
            "download/v3.1.0/nuclei_3.1.0_linux_amd64.zip"
        )
        print("  2. Extract: unzip nuclei_3.1.0_linux_amd64.zip")
        print("  3. Install: sudo mv nuclei /usr/local/bin/")
        print("  4. Update templates: nuclei -update-templates")

    print("\n" + "=" * 60)
    print("Nuclei adapter initialized successfully!")
    print("=" * 60)
    def check_tool_availability(self) -> bool:
        """
        Check if the tool is available in WSL
        
        Returns:
            True if tool is available, False otherwise
        """
        try:
            return bool(self.wsl_helper.check_tool_availability("nuclei"))
        except Exception as e:
            self.logger.warning(f"Failed to check tool availability: {e}")
            return False


