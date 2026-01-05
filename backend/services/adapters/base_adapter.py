"""
Base Adapter Class

This module provides the base adapter interface that all tool adapters must implement.
It defines the common methods and structure for tool integration.

Author: NTRO Security Team
Date: 2025-10-22
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Data class for scan results"""

    success: bool
    tool: str
    target: str
    raw_output: str
    parsed_output: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    execution_time: float = 0.0
    scan_metadata: Optional[Dict[str, Any]] = None


class BaseAdapter(ABC):
    """
    Base adapter class for security scanning tools

    All tool adapters must inherit from this class and implement
    the abstract methods.
    """

    def __init__(self, wsl_helper):
        """
        Initialize adapter

        Args:
            wsl_helper: WSLHelper instance for command execution
        """
        self.wsl_helper = wsl_helper
        self.tool_name = self.get_tool_name()
        self.logger = logging.getLogger(f"{__name__}.{self.tool_name}")

        # Validate tool availability
        self._validate_tool()

    @abstractmethod
    def get_tool_name(self) -> str:
        """
        Get the name of the tool

        Returns:
            Tool name as string
        """

    @abstractmethod
    def get_default_options(self) -> Dict[str, Any]:
        """
        Get default options for the tool

        Returns:
            Dictionary of default options
        """

    @abstractmethod
    def build_command(
        self, target: str, scan_type: str, options: Dict[str, Any]
    ) -> str:
        """
        Build the command to execute for the scan

        Args:
            target: Target to scan (IP, hostname, CIDR)
            scan_type: Type of scan (basic, full, quick, custom)
            options: Additional options for the scan

        Returns:
            Command string to execute
        """

    @abstractmethod
    def parse_results(self, raw_output: str) -> Dict[str, Any]:
        """
        Parse raw tool output into structured format

        Args:
            raw_output: Raw output from the tool

        Returns:
            Parsed output as dictionary
        """

    @abstractmethod
    def validate_target(self, target: str) -> bool:
        """
        Validate that the target is in correct format

        Args:
            target: Target to validate

        Returns:
            True if valid, False otherwise
        """

    def _validate_tool(self) -> None:
        """
        Validate that the tool is available in WSL

        Raises:
            RuntimeError: If tool is not available
        """
        if not self.wsl_helper.check_tool_availability(self.tool_name):
            raise RuntimeError(
                f"Tool '{self.tool_name}' is not available in WSL. "
                f"Please install it in your Kali Linux distribution."
            )

        version = self.wsl_helper.get_tool_version(
            self.tool_name, self.get_version_flag()
        )
        self.logger.info("Tool '%s' is available: %s", self.tool_name, version)

    def get_version_flag(self) -> str:
        """
        Get the version flag for the tool

        Returns:
            Version flag (default: --version)
        """
        return "--version"

    def execute_scan(
        self,
        target: str,
        scan_type: str = "basic",
        options: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
    ) -> ScanResult:
        """
        Execute a scan

        Args:
            target: Target to scan
            scan_type: Type of scan
            options: Additional options
            timeout: Timeout in seconds

        Returns:
            ScanResult object
        """
        self.logger.info(
            f"Starting {self.tool_name} scan of {target} (type: {scan_type})"
        )

        # Validate target
        if not self.validate_target(target):
            return ScanResult(
                success=False,
                tool=self.tool_name,
                target=target,
                raw_output="",
                error_message=f"Invalid target format: {target}",
            )

        # Merge options with defaults
        scan_options = self.get_default_options().copy()
        if options:
            scan_options.update(options)

        try:
            # Build command
            command = self.build_command(target, scan_type, scan_options)
            self.logger.debug("Executing command: %s", command)

            # Execute via WSL
            import time

            start_time = time.time()

            result = self.wsl_helper.execute_command(
                command,
                timeout=timeout or self.get_default_timeout(),
                check_success=False,
            )

            execution_time = time.time() - start_time

            # Check for errors
            if not result.success:
                self.logger.error("Scan failed: %s", result.stderr)
                return ScanResult(
                    success=False,
                    tool=self.tool_name,
                    target=target,
                    raw_output=result.stdout,
                    error_message=result.stderr[:500],
                    execution_time=execution_time,
                )

            # Parse output
            try:
                parsed_output = self.parse_results(result.stdout)
            except Exception as parse_error:
                self.logger.warning(f"Failed to parse output: {str(parse_error)}")
                parsed_output = None

            self.logger.info(f"Scan completed successfully in {execution_time:.2f}s")

            return ScanResult(
                success=True,
                tool=self.tool_name,
                target=target,
                raw_output=result.stdout,
                parsed_output=parsed_output,
                execution_time=execution_time,
                scan_metadata={"scan_type": scan_type, "options": scan_options},
            )

        except Exception as e:
            self.logger.error("Scan execution failed: %s", str(e))
            return ScanResult(
                success=False,
                tool=self.tool_name,
                target=target,
                raw_output="",
                error_message=str(e),
            )

    def get_default_timeout(self) -> int:
        """
        Get default timeout for scans

        Returns:
            Timeout in seconds (default: 300)
        """
        return 300

    def get_supported_scan_types(self) -> List[str]:
        """
        Get list of supported scan types

        Returns:
            List of scan type strings
        """
        return ["basic", "full", "quick", "custom"]
