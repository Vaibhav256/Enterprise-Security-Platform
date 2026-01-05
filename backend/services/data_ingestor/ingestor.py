"""
Data Ingestor

This module provides the data ingestion layer for storing scan results in the database.
It handles CRUD operations and data validation.

Author: NTRO Security Team
Date: 2025-10-22
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from .models import Base, RawScanResult, Scan, ScanStatus, ScanSummary
from config.models import Vulnerability
import uuid

logger = logging.getLogger(__name__)


class DataIngestor:
    """
    Data ingestor for managing scan data in the database

    Provides methods for creating, reading, updating, and deleting scan records.
    """

    def __init__(self, database_url: str):
        """
        Initialize data ingestor

        Args:
            database_url: SQLAlchemy database URL
                e.g., "postgresql://user:password@localhost:5432/dbname"
        """
        self.engine = create_engine(database_url, pool_pre_ping=True)
        self.SessionLocal = sessionmaker(
            autocommit=False, autoflush=False, bind=self.engine
        )

        # Create tables if they don't exist
        Base.metadata.create_all(self.engine)

        logger.info("Data ingestor initialized")

    def get_session(self) -> Session:
        """Get a new database session"""
        return self.SessionLocal()

    # ==================== Scan Operations ====================

    def create_scan(
        # Convert scan_id to proper UUID if needed
        
        self,
        scan_id: str,
        target: str,
        tool_name: str,
        scan_type: str,
        options: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        priority: str = "normal",
        job_id: Optional[str] = None,
    ) -> Scan:
        # Ensure scan_id is a valid UUID
        try:
            if isinstance(scan_id, str) and not scan_id.count('-') == 4:
                scan_id = str(uuid.uuid4())
        except (ValueError, AttributeError):
            # If validation fails, generate a new UUID
            scan_id = str(uuid.uuid4())

        """
        Create a new scan record

        Args:
            scan_id: Unique scan identifier
            target: Scan target
            tool_name: Tool to use
            scan_type: Type of scan
            options: Scan options
            tags: Tags for categorization
            priority: Scan priority
            job_id: Redis job ID

        Returns:
            Scan object
        """
        session = self.get_session()

        try:
            scan = Scan(
                id=scan_id,
                target=target,
                tool_name=tool_name,
                scan_type=scan_type,
                status=ScanStatus.PENDING,
                options=options,
                tags=tags,
                priority=priority,
                job_id=job_id,
            )

            session.add(scan)
            session.commit()
            session.refresh(scan)

            logger.info("Created scan record: %s", scan_id)
            return scan

        except SQLAlchemyError as e:
            session.rollback()
            logger.error("Failed to create scan: %s", str(e))
            raise
        finally:
            session.close()

    def get_scan(self, scan_id: str) -> Optional[Scan]:
        """
        Get a scan by ID

        Args:
            scan_id: Scan ID

        Returns:
            Scan object or None if not found
        """
        session = self.get_session()

        try:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            return scan
        finally:
            session.close()

    def update_scan_status(
        self,
        scan_id: str,
        status: ScanStatus,
        progress: Optional[int] = None,
        error_message: Optional[str] = None,
    ) -> bool:
        """
        Update scan status

        Args:
            scan_id: Scan ID
            status: New status
            progress: Progress percentage
            error_message: Error message if failed

        Returns:
            True if updated successfully
        """
        session = self.get_session()

        try:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()

            if not scan:
                logger.warning("Scan not found: %s", scan_id)
                return False

            scan.status = status

            if progress is not None:
                scan.progress = progress

            if error_message:
                scan.error_message = error_message

            # Update timestamps based on status
            if status == ScanStatus.RUNNING and not scan.started_at:
                scan.started_at = datetime.utcnow()
            elif status in [
                ScanStatus.COMPLETED,
                ScanStatus.FAILED,
                ScanStatus.CANCELLED,
            ]:
                scan.completed_at = datetime.utcnow()
                # execution_time is a @property, it auto-calculates

            session.commit()
            logger.info("Updated scan %s status to %s", scan_id, status.value)
            return True

        except SQLAlchemyError as e:
            session.rollback()
            logger.error("Failed to update scan status: %s", str(e))
            return False
        finally:
            session.close()

    def list_scans(
        self,
        status: Optional[ScanStatus] = None,
        tool: Optional[str] = None,
        limit: int = 20,
        offset: int = 0,
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> tuple[List[Scan], int]:
        """
        List scans with filtering and pagination

        Args:
            status: Filter by status
            tool: Filter by tool
            limit: Maximum number of results
            offset: Offset for pagination
            sort_by: Field to sort by
            sort_order: Sort order (asc or desc)

        Returns:
            Tuple of (scan list, total count)
        """
        session = self.get_session()

        try:
            query = session.query(Scan)

            # Apply filters
            if status:
                query = query.filter(Scan.status == status)

            if tool:
                query = query.filter(Scan.tool_name == tool)

            # Get total count
            total = query.count()

            # Apply sorting
            sort_column = getattr(Scan, sort_by, Scan.created_at)
            if sort_order == "desc":
                query = query.order_by(sort_column.desc())
            else:
                query = query.order_by(sort_column.asc())

            # Apply pagination
            scans = query.limit(limit).offset(offset).all()

            return scans, total

        finally:
            session.close()

    def delete_scan(self, scan_id: str) -> bool:
        """
        Delete a scan and all associated data

        Args:
            scan_id: Scan ID

        Returns:
            True if deleted successfully
        """
        session = self.get_session()

        try:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()

            if not scan:
                logger.warning("Scan not found: %s", scan_id)
                return False

            session.delete(scan)
            session.commit()

            logger.info("Deleted scan: %s", scan_id)
            return True

        except SQLAlchemyError as e:
            session.rollback()
            logger.error("Failed to delete scan: %s", str(e))
            return False
        finally:
            session.close()

    # ==================== Raw Result Operations ====================

    def store_raw_result(
        self,
        scan_id: str,
        tool_name: str,
        raw_output: str,
        output_format: str = "text",
        parsed_output: Optional[Dict[str, Any]] = None,
    ) -> RawScanResult:
        """
        Store raw scan result

        Args:
            scan_id: Scan ID
            tool_name: Tool name
            raw_output: Raw output string
            output_format: Output format (xml, json, text)
            parsed_output: Parsed output dictionary

        Returns:
            RawScanResult object
        """
        # Ensure scan_id is a valid UUID
        try:
            if isinstance(scan_id, str):
                uuid.UUID(scan_id)  # Validate format
        except ValueError:
            logger.warning(f"Invalid scan_id format: {scan_id}, generating new UUID")
            scan_id = str(uuid.uuid4())

        session = self.get_session()

        try:
            result = RawScanResult(
                scan_id=scan_id,
                tool_name=tool_name,
                raw_output=raw_output,
                output_format=output_format
            )

            session.add(result)
            session.commit()
            session.refresh(result)

            logger.info("Stored raw result for scan %s", scan_id)
            return result

        except SQLAlchemyError as e:
            session.rollback()
            logger.error("Failed to store raw result: %s", str(e))
            raise
        finally:
            session.close()

    def get_raw_results(self, scan_id: str) -> List[RawScanResult]:
        """
        Get raw results for a scan

        Args:
            scan_id: Scan ID

        Returns:
            List of RawScanResult objects
        """
        session = self.get_session()

        try:
            results = (
                session.query(RawScanResult)
                .filter(RawScanResult.scan_id == scan_id)
                .all()
            )

            return results
        finally:
            session.close()

    # ==================== Summary Operations ====================

    def create_scan_summary(
        self, scan_id: str, summary_data: Dict[str, Any]
    ) -> ScanSummary:
        """
        Create scan summary

        Args:
            scan_id: Scan ID
            summary_data: Summary statistics

        Returns:
            ScanSummary object
        """
        session = self.get_session()

        try:
            # Accept multiple possible summary key names coming from parsers/tasks
            # so older exporters or parsing code that uses `hosts_scanned` or
            # `vulnerabilities_found` still work.
            total_hosts = summary_data.get("total_hosts", summary_data.get("hosts_scanned", 0))
            total_ports = summary_data.get("total_ports", summary_data.get("open_ports", 0))
            total_vulnerabilities = summary_data.get(
                "total_vulnerabilities",
                summary_data.get("vulnerabilities_found", 0)
            )

            summary = ScanSummary(
                scan_id=scan_id,
                total_hosts=total_hosts,
                total_ports=total_ports,
                total_vulnerabilities=total_vulnerabilities,
                critical_count=summary_data.get("critical_count", 0),
                high_count=summary_data.get("high_count", 0),
                medium_count=summary_data.get("medium_count", 0),
                low_count=summary_data.get("low_count", 0),
                info_count=summary_data.get("info_count", 0)
            )

            session.add(summary)
            session.commit()
            session.refresh(summary)

            logger.info("Created summary for scan %s", scan_id)
            return summary

        except SQLAlchemyError as e:
            session.rollback()
            logger.error("Failed to create summary: %s", str(e))
            raise
        finally:
            session.close()

    def get_scan_summary(self, scan_id: str) -> Optional[ScanSummary]:
        """
        Get scan summary

        Args:
            scan_id: Scan ID

        Returns:
            ScanSummary object or None
        """
        session = self.get_session()

        try:
            summary = (
                session.query(ScanSummary)
                .filter(ScanSummary.scan_id == scan_id)
                .first()
            )

            return summary
        finally:
            session.close()

    def update_ai_summary(self, scan_id: str, ai_summary: Dict[str, Any]) -> bool:
        """
        Update AI summary in scan_summaries table

        Args:
            scan_id: Scan ID
            ai_summary: AI-generated summary dictionary

        Returns:
            True if updated, False if summary doesn't exist
        """
        session = self.get_session()

        try:
            summary = (
                session.query(ScanSummary)
                .filter(ScanSummary.scan_id == scan_id)
                .first()
            )

            if summary:
                summary.ai_summary = ai_summary
                summary.updated_at = datetime.utcnow()
                session.commit()
                logger.info("Updated AI summary for scan %s", scan_id)
                return True
            else:
                logger.warning("No summary found for scan %s, cannot update AI summary", scan_id)
                return False

        except SQLAlchemyError as e:
            session.rollback()
            logger.error("Failed to update AI summary: %s", str(e))
            raise
        finally:
            session.close()

    def store_vulnerabilities(
        self,
        scan_id: str,
        vulnerabilities: List[Dict[str, Any]],
    ) -> int:
        """
        Store vulnerabilities from scan findings

        Args:
            scan_id: Scan ID
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            Number of vulnerabilities stored
        """
        if not vulnerabilities:
            logger.warning("No vulnerabilities to store for scan %s", scan_id)
            return 0

        session = self.get_session()

        try:
            stored_count = 0

            for vuln in vulnerabilities:
                # Extract port and convert to integer if present
                port = vuln.get("port")
                if port is not None:
                    try:
                        port = int(port)
                    except (ValueError, TypeError):
                        port = None
                
                # Merge nuclei_data into main vulnerability data if present
                vuln_data_for_storage = vuln.copy()
                if "nuclei_data" in vuln:
                    nuclei_data = vuln.pop("nuclei_data")
                    vuln_data_for_storage.update(nuclei_data)
                
                # Create Vulnerability object (host stored in vuln_data JSON, not as separate field)
                vulnerability = Vulnerability(
                    scan_id=scan_id,
                    severity=vuln.get("severity", "unknown"),
                    title=vuln.get("title") or vuln.get("template_name") or vuln.get("name", "Unknown Vulnerability"),
                    description=vuln.get("description", ""),
                    cvss_score=vuln.get("cvss_score"),
                    cve_id=vuln.get("cve_id") or vuln.get("template_id"),
                    port=port,
                    protocol=vuln.get("protocol") or vuln.get("type"),  # Use 'type' as fallback
                    service=vuln.get("service"),
                    solution=vuln.get("solution") or vuln.get("remediation"),
                    references=vuln.get("references", []),
                    vuln_data=vuln_data_for_storage  # Store complete finding (mapped to 'metadata' column in database)
                )

                session.add(vulnerability)
                stored_count += 1

            session.commit()
            logger.info("Stored %d vulnerabilities for scan %s", stored_count, scan_id)
            return stored_count

        except SQLAlchemyError as e:
            session.rollback()
            logger.error("Failed to store vulnerabilities: %s", str(e))
            raise
        finally:
            session.close()

    def get_vulnerabilities(self, scan_id: str) -> List[Dict[str, Any]]:
        """
        Get vulnerabilities for a scan from database
        
        Args:
            scan_id: Scan ID
            
        Returns:
            List of vulnerability dictionaries
        """
        session = self.get_session()
        
        try:
            from config.models import Vulnerability
            
            vulnerabilities = session.query(Vulnerability).filter_by(scan_id=scan_id).all()
            
            result = []
            for vuln in vulnerabilities:
                vuln_dict = {
                    'id': str(vuln.vuln_id),
                    'scan_id': str(vuln.scan_id),
                    'severity': vuln.severity,
                    'title': vuln.title,
                    'description': vuln.description,
                    'cvss_score': float(vuln.cvss_score) if vuln.cvss_score else None,
                    'cve_id': vuln.cve_id,
                    'port': vuln.port,
                    'protocol': vuln.protocol,
                    'service': vuln.service,
                    'solution': vuln.solution,
                    'references': vuln.references,
                    'discovered_at': vuln.discovered_at.isoformat() if vuln.discovered_at else None,
                    'metadata': vuln.vuln_data  # Full metadata including nuclei_data
                }
                result.append(vuln_dict)
            
            logger.info("Retrieved %d vulnerabilities for scan %s", len(result), scan_id)
            return result
            
        except Exception as e:
            logger.error("Failed to get vulnerabilities: %s", str(e))
            return []
        finally:
            session.close()


def create_ingestor_from_config(config: Dict[str, Any]) -> DataIngestor:
    """
    Create data ingestor from configuration

    Args:
        config: Configuration dictionary

    Returns:
        DataIngestor instance
    """
    db_config = config.get("database", {})

    # Build database URL
    database_url = db_config.get("url")

    if not database_url:
        # Build from components
        db_type = db_config.get("type", "postgresql")
        username = db_config.get("username", "postgres")
        password = db_config.get("password", "")
        host = db_config.get("host", "localhost")
        port = db_config.get("port", 5432)
        database = db_config.get("database", "vulnerability_scanner")

        database_url = f"{db_type}://{username}:{password}@{host}:{port}/{database}"

    return DataIngestor(database_url)


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)

    print("=== Data Ingestor Test ===\n")

    # Example database URL (update with your actual credentials)
    database_url = "postgresql://postgres:password@localhost:5432/vulnerability_scanner"

    print(f"Database URL: {database_url}")
    print("\nTo use the data ingestor:")
    print("  ingestor = DataIngestor(database_url)")
    print("  scan = ingestor.create_scan(")
    print("      scan_id=str(uuid.uuid4()),")
    print("      target='192.168.1.1',")
    print("      tool_name='nmap',")
    print("      scan_type='basic'")
    print("  )")
