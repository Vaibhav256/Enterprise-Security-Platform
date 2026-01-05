#!/usr/bin/env python3
"""
RQ Worker Launcher

Starts Redis Queue workers to process scan jobs.

Usage:
    python start_worker.py [--queue QUEUE] [--workers NUM]

Author: NTRO Security Team
Date: 2025-10-22
"""

import argparse
import logging
import os
import sys

from redis import Redis
from rq import Connection, Queue, Worker
from rq.worker import SimpleWorker

from config.config import get_config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def start_worker(queue_names=None, burst=False):
    """
    Start RQ worker

    Args:
        queue_names: List of queue names to listen to
        burst: If True, worker will exit after all jobs are processed
    """
    if queue_names is None:
        queue_names = ["high", "normal", "low"]

    config = get_config("development")

    logger.info("=" * 60)
    logger.info("Starting RQ Worker")
    logger.info("=" * 60)
    logger.info("Redis: %s:%s", config.REDIS_HOST, config.REDIS_PORT)
    logger.info("Queues: %s", ', '.join(queue_names))
    logger.info("Burst mode: %s", 'Yes' if burst else 'No')
    logger.info("Worker is ready to process jobs...")
    logger.info("Press Ctrl+C to stop")
    logger.info("=" * 60)

    # Create Redis connection
    redis_conn = Redis(
        host=config.REDIS_HOST,
        port=config.REDIS_PORT,
        db=config.REDIS_DB,
        decode_responses=False,  # RQ handles encoding/decoding internally
    )

    # Create queues
    queues = [Queue(name, connection=redis_conn) for name in queue_names]

    # Start worker (use SimpleWorker on Windows since os.fork() is not
    # available)
    with Connection(redis_conn):
        if sys.platform == "win32":
            # On Windows, use SimpleWorker with disabled timeout (SIGALRM not
            # available)
            from rq.timeouts import BaseDeathPenalty

            # Create a no-op death penalty for Windows
            class NoOpDeathPenalty(BaseDeathPenalty):
                def setup_death_penalty(self):
                    pass

                def cancel_death_penalty(self):
                    pass

            worker = SimpleWorker(queues, connection=redis_conn)
            worker.death_penalty_class = NoOpDeathPenalty
            worker.disable_default_exception_handler = False
            worker.log_job_description = True
        else:
            worker = Worker(queues, connection=redis_conn)
        worker.work(burst=burst, with_scheduler=False)


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Start RQ Worker for scan processing")
    parser.add_argument(
        "--queue",
        "-q",
        action="append",
        help="Queue name to listen to (can specify multiple times)",
    )
    parser.add_argument(
        "--workers",
        "-w",
        type=int,
        default=1,
        help="Number of worker processes (default: 1)",
    )
    parser.add_argument(
        "--burst", "-b", action="store_true", help="Exit after all jobs are processed"
    )

    args = parser.parse_args()

    # Default queues if none specified
    queue_names = args.queue if args.queue else ["high", "normal", "low"]

    # Load environment
    from dotenv import load_dotenv

    load_dotenv()

    try:
        if args.workers == 1:
            # Single worker
            start_worker(queue_names, burst=args.burst)
        else:
            # Multiple workers (using multiprocessing)
            import multiprocessing

            logger.info("Starting %d workers...", args.workers)

            processes = []
            for i in range(args.workers):
                p = multiprocessing.Process(
                    target=start_worker, args=(queue_names, args.burst)
                )
                p.start()
                processes.append(p)
                logger.info("  Worker %d started (PID: %d)", i+1, p.pid)

            # Wait for all workers
            for p in processes:
                p.join()

    except KeyboardInterrupt:
        logger.info("\n\nShutting down worker(s)...")
        sys.exit(0)


if __name__ == "__main__":
    main()
