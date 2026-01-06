"""
Threat Feed Automatic Synchronization Scheduler

Runs scheduled jobs to automatically sync threat feeds every 6 hours
using APScheduler for background job execution.

Author: NTRO Security Team
Date: 2025-10-31
"""

import logging
import os
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from .feed_sync_service import FeedSyncService

logger = logging.getLogger(__name__)

# Configuration constants (Issue Q3 - Magic numbers extracted)
SYNC_INTERVAL_HOURS = 2  # Sync feeds every 2 hours
MISFIRE_GRACE_TIME_SECONDS = 300  # Allow 5 minute delay if scheduler is busy
STARTUP_MISFIRE_GRACE_TIME_SECONDS = 60  # Allow 1 minute delay for startup sync
MAX_CRITICAL_CVE_ALERTS = 5  # Limit critical alerts to avoid log spam
CRITICAL_ALERT_LOOKBACK_DAYS = 7  # Check for critical CVEs in last 7 days


class FeedScheduler:
    """Manages scheduled feed synchronization"""
    
    _instance = None  # Singleton instance
    
    def __new__(cls):
        """Implement singleton pattern"""
        if cls._instance is None:
            cls._instance = super(FeedScheduler, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        """Initialize scheduler (only once due to singleton)"""
        if self._initialized:
            return
        
        self.scheduler = BackgroundScheduler()
        self.sync_service = FeedSyncService()
        self._initialized = True
        self._job_id = None
        
        logger.info("✅ FeedScheduler initialized (singleton)")
    
    def start(self):
        """Start the background scheduler"""
        if self.scheduler.running:
            logger.warning("⚠️  Scheduler already running")
            return
        
        try:
            # Add job: sync threat feeds every N hours (configurable)
            self._job_id = self.scheduler.add_job(
                func=self._sync_feeds_job,
                trigger=IntervalTrigger(hours=SYNC_INTERVAL_HOURS),
                id='feed_sync_2h',
                name='Threat Feed Synchronization',
                misfire_grace_time=MISFIRE_GRACE_TIME_SECONDS,
                replace_existing=True
            )
            
            # Also add a startup sync (run immediately on first start)
            self.scheduler.add_job(
                func=self._sync_feeds_job,
                id='feed_sync_startup',
                name='Initial Feed Sync',
                misfire_grace_time=STARTUP_MISFIRE_GRACE_TIME_SECONDS,
                replace_existing=True
            )
            
            self.scheduler.start()
            
            logger.info("🚀 Feed scheduler started!")
            logger.info("📅 Scheduled jobs:")
            for job in self.scheduler.get_jobs():
                logger.info(f"   - {job.name} (ID: {job.id}, Next run: {job.next_run_time})")
            
        except Exception as e:
            logger.error(f"❌ Failed to start scheduler: {e}", exc_info=True)
    
    def stop(self):
        """Stop the background scheduler"""
        if not self.scheduler.running:
            logger.warning("⚠️  Scheduler not running")
            return
        
        try:
            self.scheduler.shutdown(wait=True)
            logger.info("⏹️  Feed scheduler stopped")
        except Exception as e:
            logger.error(f"❌ Error stopping scheduler: {e}")
    
    def get_status(self) -> dict:
        """Get scheduler status"""
        if not self.scheduler.running:
            return {
                'running': False,
                'jobs': []
            }
        
        jobs_info = []
        for job in self.scheduler.get_jobs():
            jobs_info.append({
                'id': job.id,
                'name': job.name,
                'next_run': job.next_run_time.isoformat() if job.next_run_time else None,
                'trigger': str(job.trigger)
            })
        
        return {
            'running': self.scheduler.running,
            'jobs': jobs_info
        }
    
    def _sync_feeds_job(self):
        """Background job: sync all threat feeds"""
        try:
            logger.info("=" * 60)
            logger.info("🔄 SCHEDULED FEED SYNC STARTED")
            logger.info(f"   Timestamp: {datetime.utcnow().isoformat()}")
            logger.info("=" * 60)
            
            # Perform full sync
            results = self.sync_service.sync_all()
            
            # Log results
            logger.info("=" * 60)
            logger.info("✅ SCHEDULED FEED SYNC COMPLETED")
            logger.info(f"   Total entries synced: {results['total_new'] + results['total_updated']}")
            logger.info(f"   NVD:      new={results['nvd'].get('new', 0)}, updated={results['nvd'].get('updated', 0)}")
            logger.info(f"   ExploitDB: new={results['exploitdb'].get('new', 0)}, updated={results['exploitdb'].get('updated', 0)}")
            logger.info(f"   Errors: {results['total_errors']}")
            logger.info(f"   Duration: {results.get('duration_seconds', 'N/A')}s")
            logger.info("=" * 60)
            
            # Log critical vulnerabilities with exploits
            self._log_critical_alerts()
            
        except Exception as e:
            logger.error(f"❌ Scheduled feed sync failed: {e}", exc_info=True)
    
    def _log_critical_alerts(self):
        """Log critical CVEs with available exploits"""
        try:
            from services.data_ingestor.ingestor import DataIngestor
            import os
            
            # Get database URL - use PostgreSQL
            database_url = os.getenv(
                "DATABASE_URL",
                "postgresql://postgres:postgres@localhost:5432/vulnerability_scanner"
            )
            ingestor = DataIngestor(database_url)
            session = ingestor.get_session()
            
            # Import models
            from services.data_ingestor.models import FeedEntry
            
            # Find critical CVEs with exploits
            # Show top N critical vulnerabilities from last N days (configurable)
            week_ago = datetime.utcnow() - timedelta(days=CRITICAL_ALERT_LOOKBACK_DAYS)
            critical_cves = session.query(FeedEntry).filter(
                FeedEntry.feed_source == 'nvd',
                FeedEntry.severity == 'CRITICAL',
                FeedEntry.published_date >= week_ago
            ).order_by(FeedEntry.cvss_score.desc()).limit(MAX_CRITICAL_CVE_ALERTS).all()
            
            if critical_cves:
                logger.warning("⚠️  CRITICAL VULNERABILITIES DETECTED:")
                for cve in critical_cves:
                    # Check for exploits
                    exploit_count = session.query(FeedEntry).filter(
                        FeedEntry.feed_source == 'exploitdb',
                        FeedEntry.entry_id.contains(cve.cve_id) if cve.cve_id else False
                    ).count()
                    
                    exploit_status = f"🔴 {exploit_count} public exploits" if exploit_count > 0 else "🟢 No known exploits"
                    logger.warning(f"   {cve.cve_id}: CVSS {cve.cvss_score} | {exploit_status}")
            
            session.close()
            session.close()
            
        except Exception as e:
            logger.error(f"Error logging critical alerts: {e}")


# Global scheduler instance
_scheduler = None


def get_scheduler() -> FeedScheduler:
    """Get or create the global scheduler instance"""
    global _scheduler
    if _scheduler is None:
        _scheduler = FeedScheduler()
    return _scheduler


def start_feed_scheduler():
    """Start the background feed scheduler"""
    scheduler = get_scheduler()
    scheduler.start()
    logger.info("✅ Feed scheduler initialized and started")


def stop_feed_scheduler():
    """Stop the background feed scheduler"""
    scheduler = get_scheduler()
    scheduler.stop()
    logger.info("✅ Feed scheduler stopped")
