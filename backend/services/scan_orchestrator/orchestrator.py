"""
Scan Orchestrator

This module provides the orchestration layer for managing scan jobs.
It handles job queueing, task dispatching, and status tracking using Redis Queue (RQ).

Author: NTRO Security Team
Date: 2025-10-22
"""

import logging
from datetime import datetime
from typing import Any, Dict, Optional

from redis import Redis
from rq import Queue
from rq.job import Job

from services.scan_orchestrator.tasks import execute_scan

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """
    Orchestrator for managing scan jobs

    This class handles:
    - Job enqueueing
    - Adapter dispatching
    - Status tracking
    - Error handling
    """

    def __init__(
        self,
        redis_host: str = "localhost",
        redis_port: int = 6379,
        redis_db: int = 0,
        redis_password: Optional[str] = None,
    ):
        """
        Initialize scan orchestrator

        Args:
            redis_host: Redis server host
            redis_port: Redis server port
            redis_db: Redis database number
            redis_password: Redis password (if required)
        """
        self.redis_conn = Redis(
            host=redis_host,
            port=redis_port,
            db=redis_db,
            password=redis_password,
            decode_responses=False,  # RQ handles encoding/decoding internally
        )

        # Create queues with different priorities
        self.high_priority_queue = Queue("high", connection=self.redis_conn)
        self.normal_queue = Queue("normal", connection=self.redis_conn)
        self.low_priority_queue = Queue("low", connection=self.redis_conn)

        logger.info("Scan orchestrator initialized")

    def enqueue_scan(
        self,
        scan_id: str,
        target: str,
        tool: str,
        scan_type: str = "basic",
        options: Optional[Dict[str, Any]] = None,
        priority: str = "normal",
        timeout: Optional[int] = None,
    ) -> str:
        """
        Enqueue a new scan job

        Args:
            scan_id: Unique scan identifier
            target: Target to scan
            tool: Tool to use (nmap, openvas, etc.)
            scan_type: Type of scan
            options: Additional scan options
            priority: Job priority (low, normal, high)
            timeout: Job timeout in seconds

        Returns:
            Job ID

        Raises:
            ValueError: If tool is not supported
        """
        # Validate tool
        supported_tools = ["nmap", "openvas", "nikto", "nuclei"]
        if tool.lower() not in supported_tools:
            raise ValueError(f"Unsupported tool: {tool}")

        # Select queue based on priority
        if priority == "high":
            queue = self.high_priority_queue
        elif priority == "low":
            queue = self.low_priority_queue
        else:
            queue = self.normal_queue

        # Prepare job data
        job_data = {
            "scan_id": scan_id,
            "target": target,
            "tool": tool.lower(),
            "scan_type": scan_type,
            "options": options or {},
            "enqueued_at": datetime.utcnow().isoformat(),
        }

        # Enqueue job
        # On Windows, don't set timeout (SIGALRM not supported)
        import sys

        # Build enqueue arguments
        enqueue_kwargs = {
            "kwargs": job_data,
            "job_id": scan_id,
            "result_ttl": 86400,  # Keep results for 24 hours
            "failure_ttl": 86400,  # Keep failures for 24 hours
        }

        # Only set timeout on non-Windows platforms (SIGALRM not available on
        # Windows)
        if sys.platform != "win32":
            enqueue_kwargs["timeout"] = timeout or 3600

        # Enqueue the job (use the actual function reference, not a string)
        job = queue.enqueue(execute_scan, **enqueue_kwargs)

        logger.info(
            "Enqueued %s scan job %s for target %s (priority: %s, queue: %s)",
            tool,
            scan_id,
            target,
            priority,
            queue.name,
        )

        return str(job.id)

    def get_job_status(self, job_id: str) -> Dict[str, Any]:
        """
        Get status of a job

        Args:
            job_id: Job ID

        Returns:
            Dictionary containing job status information
        """
        try:
            job = Job.fetch(job_id, connection=self.redis_conn)

            status_info = {
                "job_id": job_id,
                "status": job.get_status(),
                "created_at": job.created_at.isoformat() if job.created_at else None,
                "started_at": job.started_at.isoformat() if job.started_at else None,
                "ended_at": job.ended_at.isoformat() if job.ended_at else None,
                "meta": job.meta,
            }

            # Add progress if available
            if "progress" in job.meta:
                status_info["progress"] = job.meta["progress"]

            # Add result if completed
            if job.is_finished:
                status_info["result"] = job.result

            # Add error if failed
            if job.is_failed:
                status_info["error"] = (
                    str(job.exc_info) if job.exc_info else "Unknown error"
                )

            return status_info

        except Exception as e:
            logger.error("Failed to get job status: %s", str(e))
            return {"job_id": job_id, "status": "unknown", "error": str(e)}

    def cancel_job(self, job_id: str) -> bool:
        """
        Cancel a pending or running job

        Args:
            job_id: Job ID

        Returns:
            True if cancelled successfully
        """
        try:
            job = Job.fetch(job_id, connection=self.redis_conn)

            if job.is_finished or job.is_failed:
                logger.warning("Cannot cancel job %s: already completed", job_id)
                return False

            job.cancel()
            logger.info("Cancelled job %s", job_id)
            return True

        except Exception as e:
            logger.error("Failed to cancel job: %s", str(e))
            return False

    def get_queue_stats(self) -> Dict[str, Any]:
        """
        Get statistics about job queues

        Returns:
            Dictionary containing queue statistics
        """
        stats = {
            "high_priority": {
                "queued": len(self.high_priority_queue),
                "started": self.high_priority_queue.started_job_registry.count,
                "finished": self.high_priority_queue.finished_job_registry.count,
                "failed": self.high_priority_queue.failed_job_registry.count,
            },
            "normal": {
                "queued": len(self.normal_queue),
                "started": self.normal_queue.started_job_registry.count,
                "finished": self.normal_queue.finished_job_registry.count,
                "failed": self.normal_queue.failed_job_registry.count,
            },
            "low_priority": {
                "queued": len(self.low_priority_queue),
                "started": self.low_priority_queue.started_job_registry.count,
                "finished": self.low_priority_queue.finished_job_registry.count,
                "failed": self.low_priority_queue.failed_job_registry.count,
            },
        }

        return stats

    def clear_failed_jobs(self) -> int:
        """
        Clear all failed jobs from queues

        Returns:
            Number of jobs cleared
        """
        count = 0

        for queue in [
            self.high_priority_queue,
            self.normal_queue,
            self.low_priority_queue,
        ]:
            failed_registry = queue.failed_job_registry
            job_ids = failed_registry.get_job_ids()

            for job_id in job_ids:
                try:
                    failed_registry.remove(job_id, delete_job=True)
                    count += 1
                except Exception as e:
                    logger.error("Failed to clear job %s: %s", job_id, str(e))

        logger.info("Cleared %s failed jobs", count)
        return count

    def get_all_jobs(self, status: Optional[str] = None) -> list[Dict[str, Any]]:
        """
        Get all jobs across all queues

        Args:
            status: Optional status filter (queued, started, finished, failed)

        Returns:
            List of job information dictionaries
        """
        jobs = []

        for queue in [
            self.high_priority_queue,
            self.normal_queue,
            self.low_priority_queue,
        ]:
            # Get queued jobs
            if status is None or status == "queued":
                for job in queue.jobs:
                    jobs.append({
                        "job_id": str(job.id),
                        "queue": queue.name,
                        "status": "queued",
                    })

            # Get jobs from registries
            registries = {
                "started": queue.started_job_registry,
                "finished": queue.finished_job_registry,
                "failed": queue.failed_job_registry,
            }

            for reg_status, registry in registries.items():
                if status is None or status == reg_status:
                    for job_id in registry.get_job_ids():
                        jobs.append({
                            "job_id": str(job_id),
                            "queue": queue.name,
                            "status": reg_status,
                        })

        return jobs

    def get_job_result(self, job_id: str) -> Optional[Any]:
        """
        Get result of a finished job

        Args:
            job_id: Job ID

        Returns:
            Job result if finished, None otherwise
        """
        try:
            job = Job.fetch(job_id, connection=self.redis_conn)

            if job.is_finished:
                return job.result
            
            return None

        except Exception as e:
            logger.error("Failed to get job result: %s", str(e))
            return None

    def requeue_failed_job(self, job_id: str) -> Optional[str]:
        """
        Requeue a failed job

        Args:
            job_id: Job ID to requeue

        Returns:
            Job ID if requeued successfully, None otherwise
        """
        try:
            job = Job.fetch(job_id, connection=self.redis_conn)

            if not job.is_failed:
                logger.warning("Job %s is not in failed state", job_id)
                return None

            job.requeue()
            logger.info("Requeued failed job %s", job_id)
            return job_id

        except Exception as e:
            logger.error("Failed to requeue job: %s", str(e))
            return None


def create_orchestrator_from_config(config: Dict[str, Any]) -> ScanOrchestrator:
    """
    Create orchestrator from configuration dictionary

    Args:
        config: Configuration dictionary

    Returns:
        ScanOrchestrator instance
    """
    redis_config = config.get("redis", {})

    return ScanOrchestrator(
        redis_host=redis_config.get("host", "localhost"),
        redis_port=redis_config.get("port", 6379),
        redis_db=redis_config.get("db", 0),
        redis_password=redis_config.get("password"),
    )


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)

    print("=== Scan Orchestrator Test ===\n")

    try:
        # Initialize orchestrator
        orchestrator = ScanOrchestrator()

        print("Orchestrator initialized successfully\n")

        # Get queue stats
        print("Queue Statistics:")
        stats = orchestrator.get_queue_stats()
        for queue_name, queue_stats in stats.items():
            print(f"\n  {queue_name}:")
            for stat_name, value in queue_stats.items():
                print(f"    {stat_name}: {value}")

        print("\n" + "=" * 50)
        print("\nTo enqueue a scan:")
        print("  scan_id = str(uuid.uuid4())")
        print("  job_id = orchestrator.enqueue_scan(")
        print("      scan_id=scan_id,")
        print("      target='192.168.1.1',")
        print("      tool='nmap',")
        print("      scan_type='basic'")
        print("  )")

        print("\nTo check job status:")
        print("  status = orchestrator.get_job_status(job_id)")

    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback

        traceback.print_exc()
