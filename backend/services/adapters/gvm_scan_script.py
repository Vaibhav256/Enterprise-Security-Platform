#!/usr/bin/env python3
"""
GVM Scan Script using python-gvm library

This script performs OpenVAS scans using the python-gvm library
for proper authentication and API interaction.

Usage: python3 gvm_scan_script.py <target> <scan_type> <socket_path> <username> <password> [options_json]
"""

import sys
import time
import json
from lxml import etree

try:
    from gvm.connections import UnixSocketConnection
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeTransform
    from gvm.errors import GvmError
except ImportError:
    # Allow module to load without gvm library for testing
    UnixSocketConnection = None  # type: ignore
    Gmp = None  # type: ignore
    EtreeTransform = None  # type: ignore
    GvmError = Exception  # Use base Exception if gvm not available


def create_and_run_scan(target, scan_type, socket_path, username, password, options=None):
    """
    Create and run a GVM scan
    
    Args:
        target: Target IP/hostname to scan
        scan_type: Type of scan (basic, full, quick, custom)
        socket_path: Path to GVM Unix socket
        username: GVM username
        password: GVM password
        options: Optional dict with custom settings:
            - scan_config: Custom scan configuration ID
            - port_list: Custom port list ID
            - alive_test: Alive test method
            - max_checks: Max concurrent checks per host
            - max_hosts: Max concurrent hosts
    
    Returns:
        XML report as string
    """
    # Parse options if provided
    if options is None:
        options = {}
    
    # Debug logging
    print(f"DEBUG: GVM Scan Parameters:", file=sys.stderr)
    print(f"  Target: {target}", file=sys.stderr)
    print(f"  Type: {scan_type}", file=sys.stderr)
    print(f"  Socket: {socket_path}", file=sys.stderr)
    print(f"  Username: {username}", file=sys.stderr)
    print(f"  Password: {'*' * len(password) if password else 'EMPTY'}", file=sys.stderr)
    print(f"  Options: {options}", file=sys.stderr)
    
    # Validate credentials
    if not username:
        raise ValueError("GVM username cannot be empty")
    if not password:
        raise ValueError("GVM password cannot be empty")
    
    # Scan configuration IDs - use custom if provided, otherwise use defaults based on scan_type
    default_scan_configs = {
        "basic": "daba56c8-73ec-11df-a475-002264764cea",  # Full and fast
        "full": "698f691e-7489-11df-9d8c-002264764cea",   # Full and very deep
        "quick": "8715c877-47a0-438d-98a3-27c7a6ab2196",  # Discovery
        "custom": "daba56c8-73ec-11df-a475-002264764cea", # Default to full and fast
    }
    
    # Respect user's scan_config option or use default based on scan_type
    config_id = options.get("scan_config", default_scan_configs.get(scan_type, default_scan_configs["basic"]))
    print(f"  Using scan config: {config_id}", file=sys.stderr)
    
    # Port list ID - respect user option or use default (All TCP and Nmap top 100 UDP)
    port_list_id = options.get("port_list", "33d0cd82-57c6-11e1-8ed1-406186ea4fc5")
    print(f"  Using port list: {port_list_id}", file=sys.stderr)
    
    # OpenVAS Default Scanner ID
    scanner_id = "08b69003-5fc2-4037-a479-93b440211c73"
    
    try:
        # Connect to GVM
        connection = UnixSocketConnection(path=socket_path)
        transform = EtreeTransform()
        
        with Gmp(connection=connection, transform=transform) as gmp:
            # Authenticate
            print("Authenticating with GVM...", file=sys.stderr)
            gmp.authenticate(username, password)
            print("Authentication successful!", file=sys.stderr)
            
            # Create target
            target_name = f"scan_target_{int(time.time())}"
            print(f"Creating target: {target_name}", file=sys.stderr)
            
            target_response = gmp.create_target(
                name=target_name,
                hosts=[target],
                port_list_id=port_list_id
            )
            target_id = target_response.get('id')
            print(f"Target created: {target_id}", file=sys.stderr)
            
            # Create task
            task_name = f"scan_task_{int(time.time())}"
            print(f"Creating task: {task_name}", file=sys.stderr)
            
            task_response = gmp.create_task(
                name=task_name,
                config_id=config_id,
                target_id=target_id,
                scanner_id=scanner_id
            )
            task_id = task_response.get('id')
            print(f"Task created: {task_id}", file=sys.stderr)
            
            # Start task
            print("Starting scan...", file=sys.stderr)
            gmp.start_task(task_id)
            print("Scan started!", file=sys.stderr)
            
            # Wait for completion - poll status periodically
            # OpenVAS scans can take 30+ minutes for thorough vulnerability checks
            GVM_POLL_INTERVAL_SECONDS = 30  # Check scan status every 30 seconds
            max_wait = 7200  # 2 hour timeout (OpenVAS scans can be slow)
            wait_time = 0
            
            while wait_time < max_wait:
                time.sleep(GVM_POLL_INTERVAL_SECONDS)
                wait_time += GVM_POLL_INTERVAL_SECONDS
                
                # Get task status
                task_status = gmp.get_task(task_id)
                status = task_status.find('.//status').text
                
                print(f"Status: {status} (waited {wait_time}s)", file=sys.stderr)
                
                if status == 'Done':
                    print("Scan completed!", file=sys.stderr)
                    break
                elif status in ['Stopped', 'Interrupted']:
                    raise Exception(f"Scan stopped with status: {status}")
            
            if wait_time >= max_wait:
                raise Exception("Scan timeout - exceeded maximum wait time")
            
            # Get report
            print("Retrieving report...", file=sys.stderr)
            
            # Get the report ID from the task
            task_data = gmp.get_task(task_id)
            report_element = task_data.find('.//last_report/report')
            if report_element is None:
                raise Exception("No report found for completed task")
            
            report_id = report_element.get('id')
            print(f"Report ID: {report_id}", file=sys.stderr)
            
            # Get full report in XML format
            report = gmp.get_report(
                report_id=report_id,
                report_format_id='a994b278-1f62-11e1-96ac-406186ea4fc5',  # XML format
                details=True
            )
            
            # Convert to string
            report_xml = etree.tostring(report, encoding='unicode')
            
            print(f"Report retrieved successfully! Size: {len(report_xml)} bytes", file=sys.stderr)
            
            # Optional: Clean up (comment out to keep for review)
            # print(f"Cleaning up...", file=sys.stderr)
            # gmp.delete_task(task_id, ultimate=True)
            # gmp.delete_target(target_id, ultimate=True)
            
            return report_xml
            
    except GvmError as e:
        print(f"GVM Error: {e}", file=sys.stderr)
        raise
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        raise


if __name__ == "__main__":
    if len(sys.argv) < 6:
        print("Usage: python3 gvm_scan_script.py <target> <scan_type> <socket_path> <username> <password> [options_json]", file=sys.stderr)
        sys.exit(1)
    
    target = sys.argv[1]
    scan_type = sys.argv[2]
    socket_path = sys.argv[3]
    username = sys.argv[4]
    password = sys.argv[5]
    
    # Parse optional JSON options argument
    options = {}
    output_file = None  # Optional output file path
    if len(sys.argv) > 6:
        try:
            options = json.loads(sys.argv[6])
            print(f"Parsed options: {options}", file=sys.stderr)
        except json.JSONDecodeError as e:
            print(f"Warning: Failed to parse options JSON: {e}", file=sys.stderr)
            options = {}
    
    # Check for output file argument
    if len(sys.argv) > 7:
        output_file = sys.argv[7]
    
    try:
        report = create_and_run_scan(target, scan_type, socket_path, username, password, options)
        
        # Write to file if specified, otherwise stdout
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
            print(f"Report written to {output_file}", file=sys.stderr)
        else:
            print(report)  # Output the XML report to stdout (legacy mode)
        
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)
