"""
Monitoring Tasks

RQ (Redis Queue) tasks for system monitoring and health checks.

Author: NTRO Security Team
Date: 2025-10-26
"""

import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


def check_scan_timeouts(timeout_minutes: int = 60):
    """
    Check for scans that have timed out

    Args:
        timeout_minutes: Consider scans timed out after this many minutes

    Returns:
        Number of timed out scans
    """
    try:
        logger.info(
            f"Checking for scans that exceeded {timeout_minutes} minute timeout"
        )

        from config.config import get_config
        from services.data_ingestor.ingestor import DataIngestor
        from services.data_ingestor.models import ScanStatus

        config = get_config()
        ingestor = DataIngestor(database_url=config.DATABASE_URL)

        # Get running scans
        all_scans, _ = ingestor.list_scans(limit=1000)

        timeout_cutoff = datetime.now() - timedelta(minutes=timeout_minutes)
        timed_out_count = 0

        for scan in all_scans:
            if scan.status == ScanStatus.RUNNING:
                if scan.started_at and scan.started_at < timeout_cutoff:
                    # Mark as failed due to timeout
                    ingestor.update_scan_status(
                        str(scan.id),
                        ScanStatus.FAILED,
                        error_message=f"Scan timed out after {timeout_minutes} minutes",
                    )
                    timed_out_count += 1
                    logger.warning(f"Scan {scan.id} timed out")

        logger.info(f"Found {timed_out_count} timed out scans")
        return timed_out_count

    except Exception as e:
        logger.error(f"Failed to check scan timeouts: {str(e)}")
        raise


def monitor_worker_health():
    """
    Monitor worker health and report issues

    Returns:
        Worker health status
    """
    try:
        logger.info("Checking RQ worker health")

        from redis import Redis
        from rq import Worker
        from config.config import get_config

        config = get_config()
        redis_conn = Redis(
            host=config.REDIS_HOST,
            port=config.REDIS_PORT,
            db=config.REDIS_DB,
        )

        # Get worker statistics
        stats = {
            "healthy": True,
            "workers": 0,
            "active_tasks": 0,
            "timestamp": datetime.now().isoformat(),
        }

        try:
            # Get active workers
            workers = Worker.all(connection=redis_conn)
            stats["workers"] = len(workers)
            
            # Count active jobs
            active_jobs = sum(1 for w in workers if w.get_current_job() is not None)
            stats["active_tasks"] = active_jobs
            
            if len(workers) == 0:
                stats["healthy"] = False
                logger.warning("No active workers found")
        except Exception as e:
            logger.error(f"Could not inspect workers: {e}")
            stats["healthy"] = False

        logger.info(
            f"Worker health check: {stats['workers']} workers, {stats['active_tasks']} active tasks"
        )
        return stats

    except Exception as e:
        logger.error(f"Failed to check worker health: {str(e)}")
        raise
