"""
WSL Helper Module

This module provides utilities for executing commands in Windows Subsystem for Linux (WSL)
Kali Linux environment. It handles command execution, output capture, error handling,
and timeout management.

Author: NTRO Security Team
Date: 2025-10-22
"""

import logging
import re
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class WSLCommandResult:
    """Data class for WSL command execution results"""

    success: bool
    stdout: str
    stderr: str
    return_code: int
    command: str
    execution_time: float
    wsl_command: Optional[str] = None  # Full WSL command for debugging


class WSLHelper:
    """
    Helper class for executing commands in WSL Kali Linux environment.

    This class provides methods to:
    - Execute commands in WSL
    - Check tool availability
    - Validate WSL distribution
    - Handle timeouts and errors
    """

    def __init__(self, distribution: str = "kali-linux", default_timeout: int = 300):
        """
        Initialize WSL Helper

        Args:
            distribution: WSL distribution name (default: kali-linux)
            default_timeout: Default timeout for commands in seconds (default: 300)
        """
        self.distribution = distribution
        self.default_timeout = default_timeout
        self._validate_wsl_available()
        logger.info("WSL Helper initialized for distribution: %s", distribution)

    def _validate_wsl_available(self) -> None:
        """
        Validate that WSL is available on the system
        
        Enhanced validation addressing QA Issue #3:
        - Checks WSL installation
        - Verifies distribution exists
        - Confirms distribution is running
        - Provides detailed error messages

        Raises:
            RuntimeError: If WSL is not available or distribution not found
        """
        try:
            # Check WSL installation
            result = subprocess.run(
                ["wsl.exe", "--list", "--verbose"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                raise RuntimeError(
                    f"WSL is not available on this system. Error: {result.stderr}"
                )

            # Parse distributions and their states
            distributions = result.stdout.strip().split("\n")[1:]  # Skip header
            distributions = [
                d.strip().replace("\x00", "") for d in distributions if d.strip()
            ]

            logger.debug("Available WSL distributions: %s", distributions)

            # Check if specified distribution exists and get its state
            dist_found = False
            dist_running = False
            for dist_line in distributions:
                if self.distribution.lower() in dist_line.lower():
                    dist_found = True
                    dist_running = 'Running' in dist_line
                    logger.debug(f"Distribution state: {dist_line}")
                    break
            
            if not dist_found:
                available_list = [d.split()[0].strip('*') for d in distributions if d]
                raise RuntimeError(
                    f"WSL distribution '{self.distribution}' not found. "
                    f"Available distributions: {', '.join(available_list)}. "
                    f"Please install Kali Linux: 'wsl --install -d kali-linux'"
                )
            
            # Try to wake up distribution if not running
            if not dist_running:
                logger.warning(f"Distribution '{self.distribution}' not running, starting it...")
                wake_result = subprocess.run(
                    ["wsl.exe", "-d", self.distribution, "echo", "test"],
                    capture_output=True,
                    timeout=30
                )
                if wake_result.returncode != 0:
                    raise RuntimeError(
                        f"Failed to start distribution '{self.distribution}': "
                        f"{wake_result.stderr}"
                    )
                logger.info(f"✅ Distribution '{self.distribution}' started successfully")
            
            logger.info(f"✅ WSL distribution '{self.distribution}' is available and ready")

        except subprocess.TimeoutExpired:
            raise RuntimeError(
                "WSL validation timed out after 10 seconds. WSL may be unresponsive. "
                "Try restarting WSL: 'wsl --shutdown'"
            )
        except FileNotFoundError:
            raise RuntimeError(
                "wsl.exe not found. Windows Subsystem for Linux is not installed. "
                "Install WSL2: https://aka.ms/wsl2install"
            )

        except FileNotFoundError:
            raise RuntimeError("wsl.exe not found. WSL may not be installed.")
        except subprocess.TimeoutExpired:
            raise RuntimeError("WSL command timed out")
        except Exception as e:
            raise RuntimeError(f"Failed to validate WSL: {str(e)}")

    def is_wsl_available(self) -> bool:
        """
        Check if WSL is available on the system

        Returns:
            True if WSL is available, False otherwise
        """
        try:
            result = subprocess.run(
                ["wsl.exe", "--list", "--quiet"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            return False

    def execute_command(
        self,
        command: str,
        timeout: Optional[int] = None,
        check_success: bool = True,
        env: Optional[Dict[str, str]] = None,
    ) -> WSLCommandResult:
        """
        Execute a command in WSL

        Args:
            command: Command to execute in WSL
            timeout: Timeout in seconds (uses default_timeout if None)
            check_success: Whether to raise exception on non-zero return code
            env: Environment variables to set

        Returns:
            WSLCommandResult object containing execution details

        Raises:
            subprocess.TimeoutExpired: If command times out
            RuntimeError: If command fails and check_success is True
        """
        timeout = timeout or self.default_timeout

        # Sanitize command to prevent injection
        sanitized_command = self._sanitize_command(command)

        # Build WSL command
        wsl_command = [
            "wsl.exe",
            "-d",
            self.distribution,
            "--",
            "bash",
            "-c",
            sanitized_command,
        ]
        
        # Prepare full command string for logging and debugging
        wsl_command_str = " ".join(wsl_command)

        logger.info("Executing WSL command: %s", command)
        logger.debug("Full WSL command: %s", wsl_command_str)
        logger.debug("Distribution: %s, Timeout: %ss", self.distribution, timeout)

        import time

        start_time = time.time()
        process = None

        try:
            # Use Popen for better process control (QA Issue #2)
            process = subprocess.Popen(
                wsl_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env
            )
            
            # Wait with timeout and ensure cleanup
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                returncode = process.returncode
            except subprocess.TimeoutExpired:
                execution_time = time.time() - start_time
                logger.error("Command timed out after %ss (%.2fs elapsed)", timeout, execution_time)
                logger.error("  Original command: %s", command)
                logger.error("  Full WSL command: %s", wsl_command_str)
                logger.error("  Distribution: %s", self.distribution)
                
                # Graceful termination first
                process.terminate()
                try:
                    stdout, stderr = process.communicate(timeout=5)
                    logger.info("Process terminated gracefully, captured partial output")
                except subprocess.TimeoutExpired:
                    # Force kill if still running
                    logger.warning("Process did not terminate, killing forcefully")
                    process.kill()
                    try:
                        stdout, stderr = process.communicate(timeout=2)
                    except:
                        stdout, stderr = "", ""
                
                # Return partial results instead of raising exception
                logger.warning(f"Command timed out after {execution_time:.2f}s - returning partial output ({len(stdout)} bytes)")
                return WSLCommandResult(
                    success=False,
                    stdout=stdout,
                    stderr=f"TIMEOUT after {timeout}s: {stderr}",
                    return_code=-1,  # Indicate timeout
                    command=command,
                    execution_time=execution_time,
                    wsl_command=wsl_command_str,
                )

            execution_time = time.time() - start_time

            wsl_result = WSLCommandResult(
                success=(returncode == 0),
                stdout=stdout,
                stderr=stderr,
                return_code=returncode,
                command=command,
                execution_time=execution_time,
                wsl_command=wsl_command_str,
            )

            logger.info(
                f"Command completed in {execution_time:.2f}s "
                f"(return code: {returncode})"
            )

            if returncode != 0:
                # Enhanced error context (QA Issue #4)
                error_context = {
                    'command': command[:200],
                    'return_code': returncode,
                    'stderr': stderr[:500],
                    'execution_time': execution_time,
                    'distribution': self.distribution
                }
                logger.warning("Command failed: %s", error_context)
                if check_success:
                    raise RuntimeError(
                        f"WSL command failed with return code {returncode}: "
                        f"{stderr[:500]}\n"
                        f"Command: {command[:200]}\n"
                        f"Execution time: {execution_time:.2f}s"
                    )

            return wsl_result

        except Exception as e:
            logger.error("Command execution failed: %s (command: %s)", str(e), command[:200])
            raise
        finally:
            # Ensure process is cleaned up (QA Issue #2 - prevent zombie processes)
            if process and process.poll() is None:
                logger.warning("Cleaning up running process")
                try:
                    process.kill()
                    process.wait(timeout=5)
                except Exception as cleanup_error:
                    logger.error("Failed to cleanup process: %s", cleanup_error)

    def execute_wsl_command_array(
        self,
        wsl_command: List[str],
        timeout: Optional[int] = None,
        check_success: bool = True,
    ) -> WSLCommandResult:
        """
        Execute a pre-built WSL command array directly (no bash -c wrapping)
        
        Use this method when you've already built a complete WSL command using
        build_wsl_command() from input_validation module. This avoids double
        WSL nesting that would occur with execute_command().
        
        Args:
            wsl_command: Pre-built WSL command array (e.g., ['wsl.exe', '-d', 'kali-linux', '--', 'nikto', ...])
            timeout: Timeout in seconds (uses default_timeout if None)
            check_success: Whether to raise exception on non-zero return code
            
        Returns:
            WSLCommandResult object containing execution details
            
        Raises:
            subprocess.TimeoutExpired: If command times out
            RuntimeError: If command fails and check_success is True
        """
        timeout = timeout or self.default_timeout
        
        # Build command string for logging
        wsl_command_str = " ".join(wsl_command)
        
        logger.info("Executing pre-built WSL command array")
        logger.debug("Full WSL command: %s", wsl_command_str)
        logger.debug("Timeout: %ss", timeout)
        
        import time
        start_time = time.time()
        process = None
        
        try:
            # Execute the command array directly
            process = subprocess.Popen(
                wsl_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            
            # Wait with timeout and ensure cleanup
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                returncode = process.returncode
            except subprocess.TimeoutExpired:
                execution_time = time.time() - start_time
                logger.error("Command timed out after %ss (%.2fs elapsed)", timeout, execution_time)
                logger.error("  Full WSL command: %s", wsl_command_str)
                
                # Graceful termination first
                process.terminate()
                try:
                    stdout, stderr = process.communicate(timeout=5)
                    logger.info("Process terminated gracefully, captured partial output")
                except subprocess.TimeoutExpired:
                    # Force kill if still running
                    logger.warning("Process did not terminate, killing forcefully")
                    process.kill()
                    try:
                        stdout, stderr = process.communicate(timeout=2)
                    except:
                        stdout, stderr = "", ""
                
                # Return partial results instead of raising exception
                logger.warning(f"Command timed out after {execution_time:.2f}s - returning partial output ({len(stdout)} bytes)")
                return WSLCommandResult(
                    success=False,
                    stdout=stdout,
                    stderr=f"TIMEOUT after {timeout}s: {stderr}",
                    return_code=-1,  # Indicate timeout
                    command=" ".join(wsl_command[4:]) if len(wsl_command) > 4 else wsl_command_str,  # Extract actual tool command
                    execution_time=execution_time,
                    wsl_command=wsl_command_str,
                )
            
            execution_time = time.time() - start_time
            
            wsl_result = WSLCommandResult(
                success=(returncode == 0),
                stdout=stdout,
                stderr=stderr,
                return_code=returncode,
                command=" ".join(wsl_command[4:]) if len(wsl_command) > 4 else wsl_command_str,  # Extract actual tool command
                execution_time=execution_time,
                wsl_command=wsl_command_str,
            )
            
            logger.info(
                f"Command completed in {execution_time:.2f}s "
                f"(return code: {returncode})"
            )
            
            if returncode != 0:
                error_context = {
                    'command': wsl_command_str[:200],
                    'return_code': returncode,
                    'stderr': stderr[:500],
                    'execution_time': execution_time,
                }
                logger.warning("Command failed: %s", error_context)
                if check_success:
                    raise RuntimeError(
                        f"WSL command failed with return code {returncode}: "
                        f"{stderr[:500]}\n"
                        f"Command: {wsl_command_str[:200]}\n"
                        f"Execution time: {execution_time:.2f}s"
                    )
            
            return wsl_result
            
        except Exception as e:
            logger.error("Command execution failed: %s (command: %s)", str(e), wsl_command_str[:200])
            raise
        finally:
            # Ensure process is cleaned up
            if process and process.poll() is None:
                logger.warning("Cleaning up running process")
                try:
                    process.kill()
                    process.wait(timeout=5)
                except Exception as cleanup_error:
                    logger.error("Failed to cleanup process: %s", cleanup_error)

    def execute_command_with_file_output(
        self, command: str, output_file: str, timeout: Optional[int] = None
    ) -> Tuple[WSLCommandResult, str]:
        """
        Execute a command that produces file output and retrieve the file content

        Args:
            command: Command to execute
            output_file: Path to output file in WSL filesystem
            timeout: Timeout in seconds

        Returns:
            Tuple of (WSLCommandResult, file_content)
        """
        # Execute the command
        result = self.execute_command(command, timeout=timeout)

        # Read the output file
        read_command = f"cat {output_file}"
        file_result = self.execute_command(read_command, timeout=30)

        return result, file_result.stdout

    def check_tool_availability(self, tool: str) -> bool:
        """
        Check if a tool is available in WSL

        Args:
            tool: Name of the tool to check

        Returns:
            True if tool is available, False otherwise
        """
        command = f"which {tool}"

        try:
            result = self.execute_command(command, timeout=10, check_success=False)
            available = result.success and result.stdout.strip() != ""

            if available:
                logger.info(f"Tool '{tool}' is available at: {result.stdout.strip()}")
            else:
                logger.warning("Tool '%s' is not available", tool)

            return available

        except Exception as e:
            logger.error("Failed to check tool availability: %s", str(e))
            return False

    def get_tool_version(
        self, tool: str, version_flag: str = "--version"
    ) -> Optional[str]:
        """
        Get the version of a tool

        Args:
            tool: Name of the tool
            version_flag: Flag to get version (default: --version)

        Returns:
            Version string or None if unavailable
        """
        if not self.check_tool_availability(tool):
            return None

        command = f"{tool} {version_flag}"

        try:
            result = self.execute_command(command, timeout=10, check_success=False)

            # Extract version from output (first line typically)
            version = (
                result.stdout.split("\n")[0]
                if result.stdout
                else result.stderr.split("\n")[0]
            )

            logger.info("Tool '%s' version: %s", tool, version)
            return version.strip()

        except Exception as e:
            logger.error("Failed to get tool version: %s", str(e))
            return None

    def get_distribution_info(self) -> Dict[str, str]:
        """
        Get information about the WSL distribution

        Returns:
            Dictionary containing distribution information
        """
        commands = {
            "os_release": "cat /etc/os-release",
            "kernel": "uname -r",
            "hostname": "hostname",
        }

        info = {}

        for key, command in commands.items():
            try:
                result = self.execute_command(command, timeout=10, check_success=False)
                if result.success:
                    info[key] = result.stdout.strip()
            except Exception as e:
                logger.warning("Failed to get %s: %s", key, str(e))
                info[key] = "Unknown"

        return info

    def _sanitize_command(self, command: str) -> str:
        """
        Sanitize command to prevent injection attacks
        
        Enhanced security implementation addressing QA Issue #1.

        Args:
            command: Command to sanitize

        Returns:
            Sanitized command

        Raises:
            ValueError: If command contains dangerous patterns
        """
        # Dangerous command patterns (QA Issue #1 remediation)
        dangerous_patterns = [
            r";\s*rm\s+-rf",  # Dangerous rm commands
            r"&&\s*rm\s+-rf",
            r"\|\s*rm\s+-rf",
            r";\s*shutdown",  # Shutdown commands
            r";\s*reboot",
            r";\s*mkfs",  # Filesystem operations
            r";\s*dd\s+",  # Direct disk access (dd command)
            r";\s*wget.*\|\s*bash",  # Remote code execution
            r";\s*curl.*\|\s*bash",  # Remote code execution
            r"`.*`",  # Backtick command substitution
            r"\$\(",  # Command substitution
            r">\s*/dev/",  # Writing to device files (with space)
            r"of=/dev/",  # Writing to device files (dd style)
            r"<\s*<\s*EOF",  # Here documents (can hide commands)
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                logger.error(f"Potentially dangerous command detected: {command[:100]}")
                raise ValueError(f"Command contains dangerous pattern: {pattern}")
        
        # Check for shell metacharacters that could enable injection
        dangerous_chars = [';', '|', '&', '`', '$', '(', ')', '<', '>', '\n', '\r']
        for char in dangerous_chars:
            if char in command and not self._is_safe_context(command, char):
                logger.error(f"Dangerous character '{char}' in unsafe context: {command[:100]}")
                raise ValueError(f"Command contains dangerous character: {char}")

        return command
    
    def _is_safe_context(self, command: str, char: str) -> bool:
        """
        Check if a potentially dangerous character is in a safe context (e.g., quoted)
        
        Args:
            command: Full command string
            char: Character to check
            
        Returns:
            True if character is in safe context, False otherwise
        """
        # Allow certain characters in known safe contexts
        safe_patterns = {
            '|': r'nmap.*-oX\s*-',  # Nmap XML output to stdout
            '&': r'(-p\s+\d+-\d+|&&)',  # Port ranges OR command chaining with &&
        }
        
        if char in safe_patterns:
            return bool(re.search(safe_patterns[char], command))
        
        return False

    def copy_file_from_wsl(self, wsl_path: str, windows_path: str) -> bool:
        """
        Copy a file from WSL to Windows filesystem

        Args:
            wsl_path: Path in WSL filesystem
            windows_path: Destination path in Windows filesystem

        Returns:
            True if successful, False otherwise
        """
        try:
            # Convert WSL path to Windows path
            command = f"wslpath -w {wsl_path}"
            result = self.execute_command(command, timeout=10)

            if result.success:
                import shutil

                wsl_windows_path = result.stdout.strip()
                shutil.copy2(wsl_windows_path, windows_path)
                logger.info("File copied from %s to %s", wsl_path, windows_path)
                return True

            return False

        except Exception as e:
            logger.error("Failed to copy file: %s", str(e))
            return False

    def create_temp_file(self, content: str, extension: str = "txt") -> str:
        """
        Create a temporary file in WSL with given content

        Args:
            content: File content
            extension: File extension

        Returns:
            Path to the temporary file in WSL
        """
        import uuid

        temp_filename = f"/tmp/wsltmp_{uuid.uuid4().hex}.{extension}"

        # Escape single quotes in content
        escaped_content = content.replace("'", "'\\''")

        command = f"echo '{escaped_content}' > {temp_filename}"
        result = self.execute_command(command, timeout=30)

        if result.success:
            logger.info("Temporary file created: %s", temp_filename)
            return temp_filename
        else:
            raise RuntimeError("Failed to create temporary file")

    def cleanup_temp_file(self, filepath: str) -> bool:
        """
        Remove a temporary file from WSL

        Args:
            filepath: Path to file in WSL

        Returns:
            True if successful
        """
        command = f"rm -f {filepath}"
        result = self.execute_command(command, timeout=10, check_success=False)

        if result.success:
            logger.debug("Temporary file cleaned up: %s", filepath)
            return True

        logger.warning("Failed to cleanup temporary file: %s", filepath)
        return False


class WSLToolValidator:
    """Validator for checking required tools in WSL"""

    def __init__(self, wsl_helper: WSLHelper):
        self.wsl_helper = wsl_helper

    def validate_required_tools(self, tools: List[str]) -> Dict[str, bool]:
        """
        Validate that required tools are available

        Args:
            tools: List of tool names to check

        Returns:
            Dictionary mapping tool names to availability status
        """
        results = {}

        for tool in tools:
            results[tool] = self.wsl_helper.check_tool_availability(tool)

        return results

    def get_missing_tools(self, tools: List[str]) -> List[str]:
        """
        Get list of missing tools
        
        Args:
            tools: List of tool names to check

        Returns:
            List of missing tool names
        """
        validation = self.validate_required_tools(tools)
        return [tool for tool, available in validation.items() if not available]

    def validate_or_raise(self, tools: List[str]) -> None:
        """
        Validate tools and raise exception if any are missing

        Args:
            tools: List of tool names to check

        Raises:
            RuntimeError: If any tools are missing
        """
        missing = self.get_missing_tools(tools)

        if missing:
            raise RuntimeError(
                f"Required tools are missing in WSL: {', '.join(missing)}. "
                f"Please install them in your Kali Linux distribution."
            )


# Convenience function for quick WSL command execution
def quick_wsl_command(command: str, timeout: int = 60) -> str:
    """
    Execute a quick WSL command and return stdout

    Args:
        command: Command to execute
        timeout: Timeout in seconds

    Returns:
        Command stdout

    Raises:
        RuntimeError: If command fails
    """
    helper = WSLHelper()
    result = helper.execute_command(command, timeout=timeout)
    return result.stdout


if __name__ == "__main__":
    # Example usage and testing
    logging.basicConfig(level=logging.INFO)

    print("=== WSL Helper Test ===\n")

    try:
        # Initialize helper
        wsl = WSLHelper()

        # Get distribution info
        print("Distribution Info:")
        info = wsl.get_distribution_info()
        for key, value in info.items():
            print(f"  {key}: {value}")

        print("\n" + "=" * 50 + "\n")

        # Check tool availability
        tools = ["nmap", "openvas", "python3", "curl"]
        print("Tool Availability Check:")

        validator = WSLToolValidator(wsl)
        results = validator.validate_required_tools(tools)

        for tool, available in results.items():
            status = "✓ Available" if available else "✗ Not Found"
            print(f"  {tool}: {status}")

            if available:
                version = wsl.get_tool_version(tool)
                if version:
                    print(f"    Version: {version}")

        print("\n" + "=" * 50 + "\n")

        # Test command execution
        print("Testing basic command execution:")
        result = wsl.execute_command("echo 'Hello from WSL'", timeout=10)
        print(f"  Output: {result.stdout.strip()}")
        print(f"  Execution time: {result.execution_time:.3f}s")

    except Exception as e:
        print(f"Error: {str(e)}")
