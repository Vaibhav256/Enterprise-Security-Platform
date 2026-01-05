"""
Processing Tasks

RQ (Redis Queue) tasks for processing and analyzing scan data.

Author: NTRO Security Team
Date: 2025-10-26
"""

import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)


def parse_scan_output(scan_id: str, raw_output: str, tool_name: str):
    """
    Parse raw scan output

    Args:
        scan_id: Unique scan identifier
        raw_output: Raw tool output
        tool_name: Name of the tool that generated output

    Returns:
        Parsed results
    """
    try:
        logger.info(f"Parsing output for scan {scan_id} from {tool_name}")

        # Use appropriate parser
        if tool_name == "nmap":
            from utils.parsers import NmapParser
            return NmapParser.parse_xml(raw_output)
        elif tool_name == "openvas":
            from utils.parsers import OpenVASParser
            return OpenVASParser.parse_xml(raw_output)
        else:
            logger.warning(f"No parser available for {tool_name}")
            return {"raw": raw_output}

    except Exception as e:
        logger.error(f"Failed to parse output for scan {scan_id}: {str(e)}")
        raise


def extract_vulnerabilities(scan_id: str, parsed_results: Dict[str, Any]):
    """
    Extract vulnerabilities from parsed results

    Args:
        scan_id: Unique scan identifier
        parsed_results: Parsed scan results

    Returns:
        List of vulnerabilities
    """
    try:
        logger.info(f"Extracting vulnerabilities for scan {scan_id}")

        vulnerabilities = []

        # Extract from different result formats
        if "vulnerabilities" in parsed_results:
            vulnerabilities = parsed_results["vulnerabilities"]
        elif "findings" in parsed_results:
            vulnerabilities = parsed_results["findings"]
        elif "issues" in parsed_results:
            vulnerabilities = parsed_results["issues"]

        logger.info(
            f"Extracted {len(vulnerabilities)} vulnerabilities for scan {scan_id}"
        )
        return vulnerabilities

    except Exception as e:
        logger.error(f"Failed to extract vulnerabilities for scan {scan_id}: {str(e)}")
        raise
