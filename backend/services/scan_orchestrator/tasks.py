"""
Scan Tasks

This module contains the actual task functions that are executed by RQ workers.
These tasks handle the execution of scans using the appropriate adapters.

Author: NTRO Security Team
Date: 2025-10-22
Updated: 2025-10-23 - Added WebSocket real-time events (Phase 2, Day 2)
"""

import logging
import os
import sys
from datetime import datetime
from typing import Any, Dict, Optional

from services.adapters import NmapAdapter, OpenVASAdapter
from services.adapters.nikto_adapter import NiktoAdapter
from services.adapters.nuclei_adapter import NucleiAdapter
from services.data_ingestor.ingestor import DataIngestor
from utils.wsl_helper import WSLHelper

# Add backend directory to path for imports
backend_dir = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)


logger = logging.getLogger(__name__)

# Import WebSocket emission functions (Phase 2, Day 2)
try:
    from api_gateway.websocket import (emit_scan_completed, emit_scan_failed,
                                       emit_scan_progress, emit_scan_queued,
                                       emit_scan_started)

    WEBSOCKET_AVAILABLE = True
    logger.info("✅ WebSocket events enabled for real-time updates")
except ImportError as e:
    WEBSOCKET_AVAILABLE = False
    logger.warning("⚠️ WebSocket not available: %s", e)

    # Create no-op functions if WebSocket not available
    def emit_scan_queued(*args, **kwargs):  # type: ignore[misc]
        pass

    def emit_scan_started(*args, **kwargs):  # type: ignore[misc]
        pass

    def emit_scan_progress(*args, **kwargs):  # type: ignore[misc]
        pass

    def emit_scan_completed(*args, **kwargs):  # type: ignore[misc]
        pass

    def emit_scan_failed(*args, **kwargs):  # type: ignore[misc]
        pass


def get_adapter(tool: str, wsl_helper: Optional[WSLHelper] = None):
    """
    Get the appropriate adapter for a tool

    Args:
        tool: Tool name
        wsl_helper: WSLHelper instance (not required for Nessus)

    Returns:
        Adapter instance

    Raises:
        ValueError: If tool is not supported
    """
    tool = tool.lower()

    if tool == "nmap":
        return NmapAdapter(wsl_helper)
    elif tool == "openvas":
        return OpenVASAdapter(wsl_helper)
    elif tool == "nikto":
        return NiktoAdapter(wsl_helper)
    elif tool == "nuclei":
        return NucleiAdapter(wsl_helper)
    else:
        raise ValueError(f"Unsupported tool: {tool}")


def execute_scan(
    scan_id: str,
    target: str,
    tool: str,
    scan_type: str = "basic",
    options: Optional[Dict[str, Any]] = None,
    **kwargs,
) -> Dict[str, Any]:
    """
    Execute a scan task

    This function is called by RQ workers to execute scans.

    Args:
        scan_id: Unique scan identifier
        target: Target to scan
        tool: Tool to use
        scan_type: Type of scan
        options: Additional scan options

    Returns:
        Dictionary containing scan results
    """
    logger.info("Starting scan %s: %s scan of %s", scan_id, tool, target)
    
    # 🔒 SECURITY: Validate all inputs before processing (Issue #1 - CRITICAL)
    from utils.input_validation import (
        IPAddressValidator,
        CommandSanitizer,
        WSLCommandValidator,
        ValidationError
    )
    
    validation_errors = []
    
    try:
        # Validate target (IP/CIDR)
        IPAddressValidator.validate_target(target)
    except ValidationError as e:
        validation_errors.append(f"Invalid target: {str(e)}")
    
    try:
        # Validate tool
        WSLCommandValidator.validate_tool(tool)
    except ValidationError as e:
        validation_errors.append(f"Invalid tool: {str(e)}")
    
    try:
        # Validate scan type
        CommandSanitizer.validate_scan_type(scan_type)
    except ValidationError as e:
        validation_errors.append(f"Invalid scan_type: {str(e)}")
    
    # Validate options if provided
    if options:
        if 'ports' in options:
            try:
                from utils.input_validation import PortValidator
                PortValidator.validate_port_range(str(options['ports']))
            except ValidationError as e:
                validation_errors.append(f"Invalid ports: {str(e)}")
    
    if validation_errors:
        # In development mode, log warnings but continue execution
        # In production mode, fail the scan
        if os.getenv('FLASK_ENV', 'development') == 'production':
            error_msg = f"Input validation failed: {', '.join(validation_errors)}"
            logger.error("Scan %s validation failed: %s", scan_id, error_msg)
            
            # Update scan status to FAILED
            try:
                from config.config import get_config
                config = get_config()
                ingestor = DataIngestor(database_url=config.DATABASE_URL)
                from services.data_ingestor.models import ScanStatus
                ingestor.update_scan_status(
                    scan_id=scan_id, 
                    status=ScanStatus.FAILED,
                    error_message=error_msg
                )
            except Exception as update_err:
                logger.error("Failed to update scan status: %s", str(update_err))
            
            return {
                "scan_id": scan_id,
                "success": False,
                "error": error_msg,
                "validation_errors": validation_errors
            }
        else:
            # Development mode: warn but continue
            logger.warning("⚠️ Scan %s has validation warnings (continuing in dev mode): %s", 
                          scan_id, ', '.join(validation_errors))
    else:
        logger.info("✅ Scan %s passed input validation", scan_id)

    # Get current job (for progress updates)
    from rq import get_current_job

    job = get_current_job()

    try:
        # Get database URL from config
        from config.config import get_config

        config = get_config()

        # Initialize data ingestor
        ingestor = DataIngestor(database_url=config.DATABASE_URL)

        # Update scan status to RUNNING
        from services.data_ingestor.models import ScanStatus

        ingestor.update_scan_status(scan_id=scan_id, status=ScanStatus.RUNNING)
        logger.info("Scan %s status updated to RUNNING", scan_id)

        # 🔥 WebSocket: Emit scan started event (Phase 2, Day 2)
        emit_scan_started(scan_id, target, tool_name=tool)
        logger.debug("📡 WebSocket: Emitted scan_started for %s", scan_id)

        # Update job meta with initial status
        if job:
            job.meta["status"] = "initializing"
            job.meta["progress"] = 0
            job.save_meta()

        # 🔥 WebSocket: Emit progress 0% (Phase 2, Day 2)
        emit_scan_progress(scan_id, 0, "Initializing scan...")

        # Initialize WSL helper
        wsl_helper = WSLHelper()

        # Update progress
        if job:
            job.meta["status"] = "preparing"
            job.meta["progress"] = 10
            job.save_meta()

        # 🔥 WebSocket: Emit progress 10% (Phase 2, Day 2)
        emit_scan_progress(scan_id, 10, "Preparing scan environment...")

        # Get appropriate adapter
        adapter = get_adapter(tool, wsl_helper)

        # Update progress
        if job:
            job.meta["status"] = "scanning"
            job.meta["progress"] = 20
            job.save_meta()

        # 🔥 WebSocket: Emit progress 20% (Phase 2, Day 2)
        emit_scan_progress(scan_id, 20, f"Starting {tool} scan...")

        # 🔥 WebSocket: Emit progress 30% (Phase 2, Day 2)
        emit_scan_progress(scan_id, 30, f"Executing {tool} scan on {target}...")

        # Execute scan
        result = adapter.execute_scan(
            target=target, scan_type=scan_type, options=options
        )

        # 🔥 WebSocket: Emit progress 70% (Phase 2, Day 2)
        emit_scan_progress(scan_id, 70, "Scan completed, processing results...")

        # Update progress
        if job:
            job.meta["status"] = "processing"
            job.meta["progress"] = 80
            job.save_meta()

        # 🔥 WebSocket: Emit progress 80% (Phase 2, Day 2)
        emit_scan_progress(scan_id, 80, "Storing results in database...")

        # Store raw results in database (even if empty - indicates no findings)
        if result.success:
            try:
                # Store raw output even if empty string (0 findings is valid result)
                raw_output = result.raw_output if result.raw_output is not None else ""
                ingestor.store_raw_result(
                    scan_id=scan_id,
                    tool_name=tool,
                    raw_output=raw_output,
                    output_format=(
                        "xml" if tool in ["nmap", "openvas", "nikto"] else "json"
                    ),
                    parsed_output=result.parsed_output,
                )
                logger.info("Raw results stored for scan %s (length: %d bytes)", scan_id, len(raw_output))
            except Exception as e:
                logger.warning("Failed to store raw results: %s", str(e))

        # Store scan summary if vulnerability data available
        if result.success and result.parsed_output:
            try:
                parsed = result.parsed_output
                
                # ✅ DEFENSIVE: Ensure parsed output has required structure
                # This prevents the zero-vulnerability bug from ever happening again
                if not isinstance(parsed, dict):
                    logger.error(f"Invalid parsed output type: {type(parsed)}. Expected dict.")
                    parsed = {}
                
                # Ensure vulnerability_count and severity_counts exist
                if "vulnerability_count" not in parsed:
                    # Try to calculate from vulnerabilities array
                    vulns = parsed.get("vulnerabilities", [])
                    if isinstance(vulns, list):
                        parsed["vulnerability_count"] = len(vulns)
                        logger.warning(f"Added missing vulnerability_count: {len(vulns)}")
                
                if "severity_counts" not in parsed:
                    # Try to calculate from vulnerabilities array
                    vulns = parsed.get("vulnerabilities", [])
                    if isinstance(vulns, list):
                        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                        for vuln in vulns:
                            severity = str(vuln.get("severity", "info")).lower()
                            if severity in severity_counts:
                                severity_counts[severity] += 1
                        parsed["severity_counts"] = severity_counts
                        logger.warning(f"Added missing severity_counts: {severity_counts}")
                    else:
                        # No vulnerabilities array either - set to zeros
                        parsed["severity_counts"] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                        parsed["vulnerability_count"] = 0
                        logger.warning("No vulnerabilities found in parsed output")

                # Extract summary data from parsed output
                # Nmap parser structure: {'hosts': [...], 'summary': {...},
                # 'scan_info': {...}}
                _ = parsed.get("summary", {})
                hosts = parsed.get("hosts", [])

                # Count statistics from hosts
                hosts_scanned = len(hosts)
                hosts_up = sum(1 for h in hosts if h.get("state") == "up")

                # Count open ports
                open_ports = 0
                total_ports = 0
                for host in hosts:
                    for port in host.get("ports", []):
                        total_ports += 1
                        if port.get("state") == "open":
                            open_ports += 1

                # Extract vulnerability counts (for vulnerability scanners)
                vuln_count = parsed.get("vulnerability_count", 0)
                severity_counts = parsed.get("severity_counts", {})

                summary_dict = {
                    "hosts_scanned": hosts_scanned,
                    "hosts_up": hosts_up,
                    "total_ports": total_ports,
                    "open_ports": open_ports,
                    "vulnerabilities_found": vuln_count,
                    "critical_count": severity_counts.get("critical", 0),
                    "high_count": severity_counts.get("high", 0),
                    "medium_count": severity_counts.get("medium", 0),
                    "low_count": severity_counts.get("low", 0),
                    "info_count": severity_counts.get("info", 0),
                }

                logger.info("Summary stats: %s", summary_dict)

                ingestor.create_scan_summary(scan_id=scan_id, summary_data=summary_dict)
                logger.info("Scan summary stored for scan %s", scan_id)
            except Exception as e:
                logger.warning("Failed to store scan summary: %s", str(e))
        
        # 📦 Store vulnerabilities/findings in database
        if result.success and result.parsed_output:
            try:
                parsed = result.parsed_output
                
                # ✅ DEFENSIVE: Validate parsed output structure
                if not isinstance(parsed, dict):
                    logger.error(f"Cannot store vulnerabilities: parsed output is {type(parsed)}, not dict")
                    raise ValueError(f"Invalid parsed output type: {type(parsed)}")
                
                # Different tools have different structures for findings
                # Nuclei: findings array
                # OpenVAS/Nikto: vulnerabilities array  
                # Nmap: hosts → ports array (needs conversion)
                findings = (
                    parsed.get("findings", []) or 
                    parsed.get("vulnerabilities", [])
                )
                
                # ✅ DEFENSIVE: Ensure findings is a list
                if not isinstance(findings, list):
                    logger.warning(f"Findings is {type(findings)}, converting to list")
                    findings = []
                
                # Special handling for Nmap: convert hosts/ports to findings
                if not findings and parsed.get("hosts") and tool.lower() == "nmap":
                    findings = []
                    for host in parsed["hosts"]:
                        host_ip = host.get("ip_address", "unknown")
                        hostname = host.get("hostname")
                        
                        for port in host.get("ports", []):
                            # Get port number (field is 'port' not 'port_number')
                            port_num = port.get("port")
                            
                            # Determine severity based on port state and service
                            severity = "info"
                            if port.get("state") == "open":
                                # Common high-risk ports
                                risky_ports = [21, 23, 445, 3389, 5900, 1433, 3306, 5432, 6379, 27017]
                                if port_num in risky_ports:
                                    severity = "medium"
                                # Ports with known vulnerabilities
                                if port.get("service_name") in ["telnet", "ftp", "microsoft-ds", "ms-wbt-server"]:
                                    severity = "medium"
                            
                            # Create finding from port
                            finding = {
                                "title": f"{port.get('state', 'Unknown').capitalize()} Port: {port_num}/{port.get('protocol', 'tcp')}",
                                "severity": severity,
                                "host": hostname or host_ip,
                                "ip_address": host_ip,
                                "port": port_num,
                                "protocol": port.get("protocol", "tcp"),
                                "service": port.get("service_name"),
                                "service_version": port.get("service_version"),
                                "state": port.get("state"),
                                "description": f"Port {port_num} is {port.get('state')} on {host_ip}",
                            }
                            
                            # Add service details if available
                            if port.get("service_name"):
                                finding["description"] += f" - Service: {port.get('service_name')}"
                                if port.get("service_version"):
                                    finding["description"] += f" {port.get('service_version')}"
                            
                            findings.append(finding)
                    
                    logger.info(f"Converted {len(findings)} Nmap ports to findings")
                
                # Special handling for Nuclei: ensure proper field mapping
                if findings and tool.lower() == "nuclei":
                    converted_findings = []
                    for finding in findings:
                        # Extract port from matched_at URL if not directly available
                        port = None
                        matched_at = finding.get("matched_at", "")
                        if matched_at:
                            # Try to extract port from URL (e.g., "http://example.com:8080")
                            import re
                            port_match = re.search(r':(\d+)', matched_at)
                            if port_match:
                                port = int(port_match.group(1))
                            elif matched_at.startswith("https://"):
                                port = 443
                            elif matched_at.startswith("http://"):
                                port = 80
                        
                        # Convert Nuclei finding to standard vulnerability format
                        converted = {
                            "title": finding.get("template_name") or finding.get("template_id"),
                            "severity": finding.get("severity", "info").lower(),
                            "description": finding.get("description", ""),
                            "port": port,
                            "protocol": finding.get("type", "http"),  # type is usually http/dns/tcp
                            "service": finding.get("type"),
                            "cve_id": finding.get("cve_id"),
                            "cwe_id": finding.get("cwe_id"),
                            "references": finding.get("tags", []),
                            # Store all Nuclei-specific data in metadata
                            "nuclei_data": {
                                "template_id": finding.get("template_id"),
                                "matched_at": finding.get("matched_at"),
                                "matcher_name": finding.get("matcher_name"),
                                "extracted_results": finding.get("extracted_results", []),
                                "curl_command": finding.get("curl_command"),
                                "host": finding.get("host"),
                                "ip": finding.get("ip"),
                                "timestamp": finding.get("timestamp"),
                                "classification": finding.get("classification", {}),
                            }
                        }
                        converted_findings.append(converted)
                    
                    findings = converted_findings
                    logger.info(f"Converted {len(findings)} Nuclei findings to standard format")
                
                if findings:
                    emit_scan_progress(scan_id, 83, f"Storing {len(findings)} findings...")
                    logger.info(f"📦 Attempting to store {len(findings)} findings for scan {scan_id}")
                    logger.debug(f"First finding structure: {findings[0] if findings else 'N/A'}")
                    
                    stored_count = ingestor.store_vulnerabilities(
                        scan_id=scan_id,
                        vulnerabilities=findings
                    )
                    logger.info("✅ Successfully stored %d findings for scan %s", stored_count, scan_id)
                    
                    # ✅ DEFENSIVE: Verify storage succeeded
                    if stored_count == 0 and len(findings) > 0:
                        logger.error(f"❌ CRITICAL: Storage returned 0 but had {len(findings)} findings!")
                    elif stored_count != len(findings):
                        logger.warning(f"⚠️ Storage count mismatch: stored {stored_count}, expected {len(findings)}")
                else:
                    logger.info("ℹ️ No findings to store for scan %s (tool: %s, parsed_output keys: %s)", 
                               scan_id, tool, list(parsed.keys()) if parsed else [])
                    
            except Exception as e:
                logger.error(f"❌ CRITICAL: Failed to store findings for scan {scan_id}: {str(e)}", exc_info=True)
                logger.error(f"   Tool: {tool}, Parsed output keys: {list(parsed.keys()) if parsed else 'None'}")
                logger.error(f"   Findings count: {len(findings) if 'findings' in locals() else 'N/A'}")
        
        # �🔥 Enrich vulnerabilities with threat intelligence (Task 6)
        if result.success and result.parsed_output:
            try:
                emit_scan_progress(scan_id, 85, "Enriching vulnerabilities with threat intelligence...")
                
                from services.threat_feeds.feed_manager import ThreatFeedManager
                
                feed_manager = ThreatFeedManager()
                parsed = result.parsed_output
                
                # Extract vulnerabilities from parsed output
                vulnerabilities = parsed.get("vulnerabilities", [])
                enriched_count = 0
                
                for vuln in vulnerabilities:
                    cve_id = vuln.get("cve_id")
                    if cve_id:
                        try:
                            # Enrich with NVD and ExploitDB data
                            enriched = feed_manager.enrich_vulnerability(vuln)
                            
                            # Update vulnerability with enriched data
                            vuln.update(enriched)
                            enriched_count += 1
                            
                            logger.debug(f"Enriched {cve_id} with threat intelligence")
                        except Exception as e:
                            logger.warning(f"Failed to enrich {cve_id}: {e}")
                
                logger.info(f"Enriched {enriched_count}/{len(vulnerabilities)} vulnerabilities with threat intelligence")
                
                # Update parsed output with enriched vulnerabilities
                result.parsed_output["vulnerabilities"] = vulnerabilities
                
                # Re-store the enriched results
                if enriched_count > 0:
                    ingestor.store_raw_result(
                        scan_id=scan_id,
                        tool_name=tool,
                        raw_output=result.raw_output,
                        output_format=(
                            "xml" if tool in ["nmap", "openvas", "nikto"] else "json"
                        ),
                        parsed_output=result.parsed_output,
                    )
                    logger.info(f"Updated scan results with {enriched_count} enriched vulnerabilities")
                
            except Exception as e:
                logger.warning(f"Failed to enrich vulnerabilities: {e}")
        
        # 🤖 Automatically index vulnerabilities to ChromaDB for RAG/Intelligence layer
        if result.success:
            try:
                emit_scan_progress(scan_id, 90, "Indexing vulnerabilities to ChromaDB for AI analysis...")
                
                from intelligence_layer.rag.indexing import VulnerabilityIndexer
                
                # Initialize indexer
                indexer = VulnerabilityIndexer()
                
                # Get vulnerabilities from database for this scan
                from sqlalchemy import create_engine
                from sqlalchemy.orm import sessionmaker
                from config.models import Vulnerability
                
                engine = create_engine(config.DATABASE_URL)
                Session = sessionmaker(bind=engine)
                session = Session()
                
                try:
                    # Query vulnerabilities for this scan
                    vulnerabilities = session.query(Vulnerability).filter(
                        Vulnerability.scan_id == scan_id
                    ).all()
                    
                    indexed_count = 0
                    for vuln in vulnerabilities:
                        try:
                            # Extract host IP from metadata if available
                            metadata = vuln.vuln_data or {}
                            host_ip = metadata.get('ip_address') or metadata.get('host') or 'unknown'
                            exploit_available = metadata.get('exploit_available', False)
                            
                            # Index each vulnerability to ChromaDB
                            indexer.index_vulnerability(
                                cve_id=vuln.cve_id or f"VULN-{vuln.vuln_id}",
                                host_ip=host_ip,
                                port=vuln.port or 0,
                                service=vuln.service or 'unknown',
                                severity=vuln.severity,
                                cvss_score=float(vuln.cvss_score) if vuln.cvss_score else 0.0,
                                description=vuln.description or '',
                                exploit_available=exploit_available,
                                tool_name=tool,
                                scan_id=scan_id,
                                additional_metadata={
                                    'title': vuln.title,
                                    'solution': vuln.solution,
                                    'references': vuln.references,
                                    'protocol': vuln.protocol,
                                    'discovered_at': vuln.discovered_at.isoformat() if vuln.discovered_at else None,
                                    'vuln_data': metadata
                                },
                                skip_duplicates=True
                            )
                            indexed_count += 1
                        except Exception as idx_err:
                            logger.warning(f"Failed to index vulnerability {vuln.vuln_id}: {idx_err}")
                    
                    logger.info(f"✅ Auto-indexed {indexed_count}/{len(vulnerabilities)} vulnerabilities to ChromaDB for scan {scan_id}")
                    
                finally:
                    session.close()
                    
            except Exception as e:
                logger.warning(f"Failed to auto-index vulnerabilities to ChromaDB: {e}")
                # Don't fail the scan if indexing fails - it can be done manually later

        # Update scan status to completed
        from services.data_ingestor.models import ScanStatus

        ingestor.update_scan_status(
            scan_id=scan_id,
            status=ScanStatus.COMPLETED if result.success else ScanStatus.FAILED,
            error_message=result.error_message,
        )

        # Update progress
        if job:
            job.meta["status"] = "completed"
            job.meta["progress"] = 100
            job.save_meta()

        # 🔥 WebSocket: Emit progress 100% (Phase 2, Day 2)
        emit_scan_progress(scan_id, 100, "Scan completed successfully!")

        # 🔥 WebSocket: Emit scan completed event (Phase 2, Day 2)
        vuln_count = (
            result.parsed_output.get("vulnerability_count", 0)
            if result.parsed_output
            else 0
        )
        emit_scan_completed(
            scan_id=scan_id,
            results_count=vuln_count,
            execution_time=result.execution_time,
        )
        logger.debug("📡 WebSocket: Emitted scan_completed for %s", scan_id)

        logger.info(
            "Scan %s completed successfully (execution time: %.2fs)",
            scan_id,
            result.execution_time,
        )

        return {"scan_id": scan_id, "status": "completed"}

    except Exception as e:
        import traceback
        
        # Enhanced error logging for debugging
        error_type = type(e).__name__
        error_msg = str(e)
        tb = traceback.format_exc()
        
        logger.error("=" * 70)
        logger.error("SCAN EXECUTION FAILED: %s", scan_id)
        logger.error("=" * 70)
        logger.error("Error Type: %s", error_type)
        logger.error("Error Message: %s", error_msg)
        logger.error("Tool: %s | Target: %s | Scan Type: %s", tool, target, scan_type)
        logger.error("Traceback:\n%s", tb)
        logger.error("=" * 70)

        # 🔥 WebSocket: Emit scan failed event (Phase 2, Day 2)
        emit_scan_failed(scan_id, str(e))
        logger.debug("📡 WebSocket: Emitted scan_failed for %s", scan_id)

        # Update database status to failed
        try:
            from config.config import get_config

            config = get_config()
            ingestor = DataIngestor(database_url=config.DATABASE_URL)
            from services.data_ingestor.models import ScanStatus

            ingestor.update_scan_status(
                scan_id=scan_id, status=ScanStatus.FAILED, error_message=str(e)
            )
        except Exception as db_error:
            logger.error("Failed to update scan status: %s", str(db_error))

        # Update job meta with error
        if job:
            job.meta["status"] = "failed"
            job.meta["error"] = str(e)
            job.save_meta()

        # Return error result
        return {
            "scan_id": scan_id,
            "success": False,
            "tool": tool,
            "target": target,
            "error_message": str(e),
            "completed_at": datetime.utcnow().isoformat(),
        }


def test_wsl_connection() -> Dict[str, Any]:
    """
    Test task to verify WSL connectivity

    Returns:
        Dictionary with WSL connection test results
    """
    logger.info("Testing WSL connection")

    try:
        wsl_helper = WSLHelper()

        # Get distribution info
        info = wsl_helper.get_distribution_info()

        # Check for required tools
        from utils.wsl_helper import WSLToolValidator

        validator = WSLToolValidator(wsl_helper)

        required_tools = ["nmap", "gvm-cli", "python3"]
        tool_status = validator.validate_required_tools(required_tools)

        result = {
            "success": True,
            "distribution_info": info,
            "tool_availability": tool_status,
            "timestamp": datetime.utcnow().isoformat(),
        }

        logger.info("WSL connection test successful")
        return result

    except Exception as e:
        logger.error("WSL connection test failed: %s", str(e))
        return {
            "success": False,
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat(),
        }


if __name__ == "__main__":
    # Example: Test the execute_scan function directly
    logging.basicConfig(level=logging.INFO)

    print("=== Task Execution Test ===\n")

    # Test WSL connection
    print("Testing WSL connection...")
    wsl_result = test_wsl_connection()

    if wsl_result["success"]:
        print("✓ WSL connection successful")
        print(
            f"  Distribution: {wsl_result['distribution_info'].get('hostname', 'unknown')}"
        )
        print("  Tools available:")
        for tool, available in wsl_result["tool_availability"].items():
            status = "✓" if available else "✗"
            print(f"    {status} {tool}")
    else:
        print(f"✗ WSL connection failed: {wsl_result['error']}")

    print("\n" + "=" * 50)
    print("\nTo execute a scan task directly (for testing):")
    print("  result = execute_scan(")
    print("      scan_id=str(uuid.uuid4()),")
    print("      target='192.168.1.1',")
    print("      tool='nmap',")
    print("      scan_type='basic'")
    print("  )")
