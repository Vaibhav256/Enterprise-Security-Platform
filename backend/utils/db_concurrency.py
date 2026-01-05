"""
Database Concurrency Control Utilities

Implements optimistic locking and transaction management to address QA Issue #5.
Prevents race conditions in concurrent scan updates.

Author: QA Team
Date: 2025-10-30
"""

import logging
from typing import Optional, Any, Dict
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from services.data_ingestor.models import Scan, ScanStatus

logger = logging.getLogger(__name__)


class OptimisticLockError(Exception):
    """Raised when optimistic lock version mismatch occurs"""
    pass


class DatabaseConcurrencyManager:
    """
    Manages concurrent database operations with optimistic locking.
    
    QA Issue #5 Remediation:
    - Implements version-based optimistic locking
    - Provides retry logic for concurrent updates
    - Ensures atomic state transitions
    """
    
    def __init__(self, session: Session, max_retries: int = 3):
        """
        Initialize concurrency manager.
        
        Args:
            session: SQLAlchemy session
            max_retries: Maximum number of retry attempts for concurrent updates
        """
        self.session = session
        self.max_retries = max_retries
    
    def update_scan_with_lock(
        self,
        scan_id: str,
        updates: Dict[str, Any],
        expected_version: Optional[int] = None
    ) -> Scan:
        """
        Update scan with optimistic locking.
        
        QA Issue #5: Prevents lost updates in concurrent scenarios.
        
        Args:
            scan_id: Scan identifier
            updates: Dictionary of fields to update
            expected_version: Expected version number (for explicit locking)
            
        Returns:
            Updated scan object
            
        Raises:
            OptimisticLockError: If version mismatch detected
            ValueError: If scan not found
        """
        scan = self.session.query(Scan).filter_by(id=scan_id).first()
        
        if not scan:
            raise ValueError(f"Scan not found: {scan_id}")
        
        # Check version if provided
        if expected_version is not None and scan.version != expected_version:
            raise OptimisticLockError(
                f"Scan {scan_id} was modified by another process. "
                f"Expected version {expected_version}, found {scan.version}"
            )
        
        # Store current version
        current_version = scan.version
        
        # Apply updates
        for key, value in updates.items():
            if hasattr(scan, key):
                setattr(scan, key, value)
        
        # Increment version
        scan.version = current_version + 1
        
        try:
            self.session.commit()
            logger.info(
                f"Scan {scan_id} updated successfully "
                f"(version {current_version} → {scan.version})"
            )
            return scan
        except IntegrityError as e:
            self.session.rollback()
            logger.error(f"Concurrent update conflict for scan {scan_id}: {e}")
            raise OptimisticLockError(
                f"Scan {scan_id} was modified concurrently. Please retry."
            )
    
    def update_scan_status_atomic(
        self,
        scan_id: str,
        new_status: ScanStatus,
        allowed_transitions: Optional[Dict[ScanStatus, list]] = None
    ) -> Scan:
        """
        Update scan status with atomic state transition validation.
        
        QA Issue #5: Ensures valid state transitions even under concurrency.
        
        Args:
            scan_id: Scan identifier
            new_status: Target status
            allowed_transitions: Map of valid transitions (status -> list of allowed next states)
            
        Returns:
            Updated scan
            
        Raises:
            ValueError: If transition is invalid
        """
        # Define valid state transitions if not provided
        if allowed_transitions is None:
            allowed_transitions = {
                ScanStatus.PENDING: [ScanStatus.QUEUED, ScanStatus.CANCELLED],
                ScanStatus.QUEUED: [ScanStatus.RUNNING, ScanStatus.CANCELLED],
                ScanStatus.RUNNING: [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED],
                ScanStatus.COMPLETED: [],  # Terminal state
                ScanStatus.FAILED: [],  # Terminal state
                ScanStatus.CANCELLED: [],  # Terminal state
            }
        
        scan = self.session.query(Scan).filter_by(id=scan_id).with_for_update().first()
        
        if not scan:
            raise ValueError(f"Scan not found: {scan_id}")
        
        # Validate transition
        current_status = scan.status
        if current_status in allowed_transitions:
            if new_status not in allowed_transitions[current_status]:
                raise ValueError(
                    f"Invalid status transition: {current_status} → {new_status}. "
                    f"Allowed: {allowed_transitions[current_status]}"
                )
        
        # Update with version increment
        scan.status = new_status
        scan.version += 1
        
        try:
            self.session.commit()
            logger.info(f"Scan {scan_id} status: {current_status} → {new_status}")
            return scan
        except Exception as e:
            self.session.rollback()
            logger.error(f"Failed to update scan status: {e}")
            raise
    
    def retry_on_conflict(self, operation, *args, **kwargs):
        """
        Retry operation on optimistic lock conflict.
        
        QA Issue #5: Automatic retry for transient concurrency conflicts.
        
        Args:
            operation: Callable to execute
            *args, **kwargs: Arguments for operation
            
        Returns:
            Operation result
            
        Raises:
            OptimisticLockError: If max retries exceeded
        """
        last_error = None
        
        for attempt in range(self.max_retries):
            try:
                return operation(*args, **kwargs)
            except OptimisticLockError as e:
                last_error = e
                logger.warning(
                    f"Optimistic lock conflict on attempt {attempt + 1}/{self.max_retries}: {e}"
                )
                # Refresh session to get latest data
                self.session.rollback()
                
                if attempt < self.max_retries - 1:
                    import time
                    # Exponential backoff: 0.1s, 0.2s, 0.4s
                    time.sleep(0.1 * (2 ** attempt))
        
        raise OptimisticLockError(
            f"Max retries ({self.max_retries}) exceeded. Last error: {last_error}"
        )


class DataRetentionManager:
    """
    Manages data lifecycle and archival.
    
    QA Issue #6 Remediation:
    - Implements retention policies
    - Provides archival functionality
    - Prevents unbounded data growth
    """
    
    DEFAULT_RETENTION_DAYS = 90
    ARCHIVE_BATCH_SIZE = 100
    
    def __init__(self, session: Session):
        """
        Initialize retention manager.
        
        Args:
            session: SQLAlchemy session
        """
        self.session = session
    
    def mark_scans_for_archival(self, days: int = DEFAULT_RETENTION_DAYS) -> int:
        """
        Mark old scans for archival.
        
        QA Issue #6: Implement retention policy.
        
        Args:
            days: Age threshold in days
            
        Returns:
            Number of scans marked
        """
        from datetime import datetime, timedelta
        
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        # Find completed/failed scans older than threshold
        old_scans = self.session.query(Scan).filter(
            Scan.completed_at < cutoff_date,
            Scan.archived == False,
            Scan.status.in_([ScanStatus.COMPLETED, ScanStatus.FAILED])
        ).limit(self.ARCHIVE_BATCH_SIZE).all()
        
        count = 0
        for scan in old_scans:
            scan.archived = True
            scan.archived_at = datetime.utcnow()
            count += 1
        
        self.session.commit()
        logger.info(f"Marked {count} scans for archival (older than {days} days)")
        
        return count
    
    def delete_archived_scans(self, archive_age_days: int = 365) -> int:
        """
        Delete scans that have been archived for a long time.
        
        QA Issue #6: Permanent deletion after archive period.
        
        Args:
            archive_age_days: How long to keep archived scans
            
        Returns:
            Number of scans deleted
        """
        from datetime import datetime, timedelta
        
        cutoff_date = datetime.utcnow() - timedelta(days=archive_age_days)
        
        # Delete scans archived before cutoff
        result = self.session.query(Scan).filter(
            Scan.archived == True,
            Scan.archived_at < cutoff_date
        ).delete()
        
        self.session.commit()
        logger.info(f"Deleted {result} archived scans (older than {archive_age_days} days)")
        
        return result


# Export utilities
__all__ = [
    'OptimisticLockError',
    'DatabaseConcurrencyManager',
    'DataRetentionManager'
]
