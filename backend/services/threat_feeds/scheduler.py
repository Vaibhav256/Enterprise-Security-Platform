"""
Threat Feed Scheduler

This module provides scheduled tasks for automatic threat intelligence feed updates.
Uses APScheduler for background scheduling.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger

from services.threat_feeds.feed_manager import ThreatFeedManager

logger = logging.getLogger(__name__)


class FeedScheduler:
    """
    Scheduler for automatic threat feed updates
    
    This class manages:
    - Scheduled feed refreshes
    - Background task execution
    - Update logging
    - Error handling
    """
    
    def __init__(self, feed_manager: Optional[ThreatFeedManager] = None):
        """
        Initialize scheduler
        
        Args:
            feed_manager: ThreatFeedManager instance (creates new if None)
        """
        self.feed_manager = feed_manager or ThreatFeedManager()
        self.scheduler = BackgroundScheduler()
        self._is_running = False
        
        logger.info("Feed scheduler initialized")
    
    def start(
        self,
        daily_refresh: bool = True,
        hourly_check: bool = False,
        custom_cron: Optional[str] = None
    ):
        """
        Start the scheduler with configured jobs
        
        Args:
            daily_refresh: Enable daily feed refresh (default: True)
            hourly_check: Enable hourly feed check (default: False)
            custom_cron: Custom cron expression for updates (e.g., "0 */6 * * *" for every 6 hours)
        """
        if self._is_running:
            logger.warning("Scheduler already running")
            return
        
        # Add daily refresh job (runs at 2 AM every day)
        if daily_refresh:
            self.scheduler.add_job(
                func=self._refresh_feeds_task,
                trigger=CronTrigger(hour=2, minute=0),
                id='daily_feed_refresh',
                name='Daily Feed Refresh',
                replace_existing=True
            )
            logger.info("Added daily feed refresh job (runs at 2:00 AM)")
        
        # Add hourly check job (checks if refresh needed)
        if hourly_check:
            self.scheduler.add_job(
                func=self._check_feeds_task,
                trigger=IntervalTrigger(hours=1),
                id='hourly_feed_check',
                name='Hourly Feed Check',
                replace_existing=True
            )
            logger.info("Added hourly feed check job")
        
        # Add custom cron job
        if custom_cron:
            try:
                # Parse cron expression (format: minute hour day month day_of_week)
                parts = custom_cron.split()
                if len(parts) == 5:
                    self.scheduler.add_job(
                        func=self._refresh_feeds_task,
                        trigger=CronTrigger(
                            minute=parts[0],
                            hour=parts[1],
                            day=parts[2],
                            month=parts[3],
                            day_of_week=parts[4]
                        ),
                        id='custom_feed_refresh',
                        name='Custom Feed Refresh',
                        replace_existing=True
                    )
                    logger.info(f"Added custom feed refresh job: {custom_cron}")
                else:
                    logger.error(f"Invalid cron expression: {custom_cron}")
            except Exception as e:
                logger.error(f"Failed to add custom cron job: {e}")
        
        # Start scheduler
        self.scheduler.start()
        self._is_running = True
        
        logger.info("Feed scheduler started")
    
    def stop(self):
        """Stop the scheduler"""
        if not self._is_running:
            logger.warning("Scheduler not running")
            return
        
        self.scheduler.shutdown(wait=True)
        self._is_running = False
        
        logger.info("Feed scheduler stopped")
    
    def trigger_refresh(self, force: bool = False):
        """
        Manually trigger feed refresh
        
        Args:
            force: Force refresh even if cache is valid
        """
        logger.info(f"Manually triggering feed refresh (force={force})")
        
        try:
            results = self.feed_manager.refresh_feeds(force=force)
            
            logger.info("Manual feed refresh completed")
            logger.info(f"Results: {results}")
            
            return results
        except Exception as e:
            logger.error(f"Manual feed refresh failed: {e}")
            raise
    
    def get_next_run_times(self):
        """
        Get next run times for all scheduled jobs
        
        Returns:
            Dictionary mapping job IDs to next run times
        """
        jobs = {}
        
        for job in self.scheduler.get_jobs():
            jobs[job.id] = {
                'name': job.name,
                'next_run': job.next_run_time.isoformat() if job.next_run_time else None
            }
        
        return jobs
    
    def _refresh_feeds_task(self):
        """
        Background task to refresh feeds
        
        This task:
        - Refreshes all feeds
        - Logs results
        - Handles errors gracefully
        """
        logger.info("Starting scheduled feed refresh")
        
        try:
            start_time = datetime.utcnow()
            
            # Refresh feeds (force=False respects cache TTL)
            results = self.feed_manager.refresh_feeds(force=False)
            
            # Calculate execution time
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            
            logger.info(f"Scheduled feed refresh completed in {execution_time:.2f}s")
            logger.info(f"Results: {results}")
            
            # Log detailed status
            status = self.feed_manager.get_feed_status()
            for feed_name, feed_info in status.items():
                if feed_info.get('cached'):
                    age = feed_info.get('cache_age', 'unknown')
                    logger.info(f"  {feed_name}: cached ({age} old)")
                else:
                    logger.info(f"  {feed_name}: not cached")
        
        except Exception as e:
            logger.error(f"Scheduled feed refresh failed: {e}")
            import traceback
            logger.error(traceback.format_exc())
    
    def _check_feeds_task(self):
        """
        Background task to check if feeds need refresh
        
        This task:
        - Checks cache status
        - Triggers refresh if needed
        - Logs status
        """
        logger.debug("Checking feed status")
        
        try:
            status = self.feed_manager.get_feed_status()
            
            # Check if any feed needs refresh
            needs_refresh = False
            
            for feed_name, feed_info in status.items():
                if not feed_info.get('cached'):
                    needs_refresh = True
                    logger.info(f"Feed {feed_name} not cached - refresh needed")
                    break
                
                # Check cache age (refresh if older than 24 hours)
                cache_age_str = feed_info.get('cache_age', '')
                if 'day' in cache_age_str or 'hour' in cache_age_str:
                    # Extract hours from string like "2 hours, 30 minutes ago"
                    try:
                        if 'day' in cache_age_str:
                            needs_refresh = True
                            logger.info(f"Feed {feed_name} cache expired - refresh needed")
                            break
                        elif 'hour' in cache_age_str:
                            hours = int(cache_age_str.split()[0])
                            if hours >= 24:
                                needs_refresh = True
                                logger.info(f"Feed {feed_name} cache expired ({hours}h old) - refresh needed")
                                break
                    except (KeyError, ValueError, TypeError) as e:
                        logger.debug(f"Failed to parse cache info: {e}")
                        pass
            
            # Trigger refresh if needed
            if needs_refresh:
                logger.info("Triggering feed refresh")
                self._refresh_feeds_task()
            else:
                logger.debug("All feeds up to date")
        
        except Exception as e:
            logger.error(f"Feed check task failed: {e}")
    
    @property
    def is_running(self) -> bool:
        """Check if scheduler is running"""
        return self._is_running


# Global scheduler instance
_scheduler_instance = None


def get_scheduler() -> FeedScheduler:
    """
    Get global scheduler instance
    
    Returns:
        FeedScheduler instance
    """
    global _scheduler_instance
    
    if _scheduler_instance is None:
        _scheduler_instance = FeedScheduler()
    
    return _scheduler_instance


def start_scheduler(
    daily_refresh: bool = True,
    hourly_check: bool = False,
    custom_cron: Optional[str] = None
):
    """
    Start global scheduler
    
    Args:
        daily_refresh: Enable daily feed refresh
        hourly_check: Enable hourly feed check
        custom_cron: Custom cron expression
    """
    scheduler = get_scheduler()
    scheduler.start(
        daily_refresh=daily_refresh,
        hourly_check=hourly_check,
        custom_cron=custom_cron
    )


def stop_scheduler():
    """Stop global scheduler"""
    global _scheduler_instance
    
    if _scheduler_instance:
        _scheduler_instance.stop()
        _scheduler_instance = None


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("=== Feed Scheduler Test ===\n")
    
    # Create scheduler
    scheduler = FeedScheduler()
    
    # Start with default settings
    print("Starting scheduler with daily refresh...")
    scheduler.start(daily_refresh=True, hourly_check=False)
    
    # Show next run times
    print("\nScheduled jobs:")
    jobs = scheduler.get_next_run_times()
    for job_id, job_info in jobs.items():
        print(f"  {job_info['name']}: {job_info['next_run']}")
    
    # Trigger manual refresh
    print("\nTriggering manual refresh...")
    try:
        results = scheduler.trigger_refresh(force=False)
        print(f"Refresh completed: {results}")
    except Exception as e:
        print(f"Refresh failed: {e}")
    
    # Stop scheduler
    print("\nStopping scheduler...")
    scheduler.stop()
    
    print("\n✓ Test completed")
