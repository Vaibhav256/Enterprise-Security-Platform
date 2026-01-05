"""
Cleanup Tasks

RQ (Redis Queue) tasks for cleanup and maintenance.

Author: NTRO Security Team
Date: 2025-10-26
"""

import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


def cleanup_old_scans(days_old: int = 30):
    """
    Clean up old scan records

    Args:
        days_old: Delete scans older than this many days

    Returns:
        Number of scans deleted
    """
    try:
        logger.info(f"Cleaning up scans older than {days_old} days")

        from config.config import get_config
        config = get_config()

        # Calculate cutoff date
        cutoff_date = datetime.now() - timedelta(days=days_old)

        # Get all scans older than cutoff date
        from services.data_ingestor.models import Scan
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        engine = create_engine(config.DATABASE_URL)
        Session = sessionmaker(bind=engine)
        session = Session()

        try:
            # Query old scans
            old_scans = (
                session.query(Scan)
                .filter(Scan.created_at < cutoff_date)
                .all()
            )

            deleted_count = len(old_scans)

            # Delete old scans (cascade will delete related records)
            for scan in old_scans:
                session.delete(scan)

            session.commit()
            logger.info(f"Cleaned up {deleted_count} old scans (before {cutoff_date.date()})")
            return deleted_count

        except Exception as e:
            session.rollback()
            logger.error(f"Database error during cleanup: {e}")
            raise
        finally:
            session.close()

    except Exception as e:
        logger.error(f"Failed to cleanup old scans: {str(e)}")
        raise


def cleanup_temp_files():
    """
    Clean up temporary files

    Returns:
        Number of files deleted
    """
    try:
        logger.info("Cleaning up temporary files")

        import glob
        import os

        # Look for temp files in common locations
        temp_patterns = ["/tmp/scan_*.xml", "/tmp/nmap_*.txt", "/tmp/nuclei_*.json"]

        deleted_count = 0
        for pattern in temp_patterns:
            for filepath in glob.glob(pattern):
                try:
                    # Only delete files older than 1 day
                    if (
                        os.path.getmtime(filepath)
                        < (datetime.now() - timedelta(days=1)).timestamp()
                    ):
                        os.remove(filepath)
                        deleted_count += 1
                except Exception as e:
                    logger.warning(f"Could not delete {filepath}: {e}")

        logger.info(f"Cleaned up {deleted_count} temporary files")
        return deleted_count

    except Exception as e:
        logger.error(f"Failed to cleanup temp files: {str(e)}")
        raise
