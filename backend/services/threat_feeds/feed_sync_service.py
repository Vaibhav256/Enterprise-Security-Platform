"""
Real-Time Threat Feed Synchronization Service

Automatically fetches and syncs threat intelligence from:
- NVD (National Vulnerability Database) via API
- ExploitDB via web scraping
- Updates database continuously

Author: NTRO Security Team
Date: 2025-10-31
"""

import os
import sys
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from pathlib import Path
from contextlib import contextmanager

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from services.threat_feeds.nvd_client import NVDClient
from services.threat_feeds.exploitdb_client import ExploitDBClient
from config.database import get_db_connection, release_db_connection

logger = logging.getLogger(__name__)


@contextmanager
def get_db_cursor():
    """
    Context manager for database cursor with automatic cleanup.
    Ensures cursor and connection are properly closed in all code paths.
    """
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        yield cursor
        conn.commit()
    except Exception:
        if conn:
            conn.rollback()
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            release_db_connection(conn)


class FeedSyncService:
    """
    Real-time threat intelligence feed synchronization service.
    
    Continuously fetches latest CVEs from NVD API and exploits from ExploitDB,
    storing them in the database for intelligent querying and correlation.
    """
    
    def __init__(self, nvd_api_key: Optional[str] = None):
        """
        Initialize feed sync service.
        
        Args:
            nvd_api_key: NVD API key (defaults to env variable)
        """
        self.nvd_client = NVDClient(api_key=nvd_api_key)
        self.exploitdb_client = ExploitDBClient()
        
        logger.info("FeedSyncService initialized")
    
    def sync_nvd_recent(self, days: int = 30, batch_size: int = 300) -> Dict[str, int]:
        """
        Sync NVD CVEs from the API to database (both recent and older).
        
        Args:
            days: Number of days to look back (default 30 for more coverage)
            batch_size: Number of CVEs to fetch per request (default 300 for large batches)
            
        Returns:
            dict: Statistics (new, updated, errors)
        """
        logger.info(f"Starting NVD sync for last {days} days (batch size: {batch_size})...")
        
        stats = {
            'new': 0,
            'updated': 0,
            'skipped': 0,
            'errors': 0
        }
        
        try:
            # Fetch CVEs from NVD API (both recent and older entries)
            cves = self.nvd_client.get_recent_cves(days=days, max_results=batch_size)
            logger.info(f"Fetched {len(cves)} CVEs from NVD API")
            
            if not cves:
                logger.warning("No CVEs returned from NVD API")
                return stats
            
            # Store in database
            with get_db_cursor() as cursor:
                for cve_data in cves:
                    try:
                        result = self._upsert_nvd_cve(cursor, cve_data)
                        stats[result] += 1
                        
                        # Periodic logging for large batches
                        if (stats['new'] + stats['updated']) % 20 == 0:
                            logger.info(f"Progress: {stats['new']} new, {stats['updated']} updated")
                    
                    except Exception as e:
                        logger.error(f"Error processing CVE {cve_data.get('cve_id')}: {e}")
                        stats['errors'] += 1
                        continue
                
                logger.info(f"NVD sync complete: {stats}")
        
        except Exception as e:
            logger.error(f"Error during NVD sync: {e}")
            stats['errors'] += 1
        
        return stats
    
    def sync_exploitdb_recent(self, max_exploits: int = 50) -> Dict[str, int]:
        """
        Sync recent ExploitDB entries to database.
        
        Args:
            max_exploits: Maximum number of exploits to fetch
            
        Returns:
            dict: Statistics (new, updated, errors)
        """
        logger.info(f"Starting ExploitDB sync (max {max_exploits})...")
        
        stats = {
            'new': 0,
            'updated': 0,
            'skipped': 0,
            'errors': 0
        }
        
        try:
            # Fetch recent exploits
            exploits = self.exploitdb_client.get_recent_exploits(limit=max_exploits)
            logger.info(f"Fetched {len(exploits)} exploits from ExploitDB")
            
            if not exploits:
                logger.warning("No exploits returned from ExploitDB")
                return stats
            
            # Store in database
            with get_db_cursor() as cursor:
                for exploit in exploits:
                    try:
                        result = self._upsert_exploitdb_entry(cursor, exploit)
                        stats[result] += 1
                        
                        # Periodic logging
                        if (stats['new'] + stats['updated']) % 10 == 0:
                            logger.info(f"Progress: {stats['new']} new, {stats['updated']} updated")
                    
                    except Exception as e:
                        logger.error(f"Error processing exploit {exploit.get('edb_id')}: {e}")
                        stats['errors'] += 1
                        continue
                
                logger.info(f"ExploitDB sync complete: {stats}")
        
        except Exception as e:
            logger.error(f"Error during ExploitDB sync: {e}")
            stats['errors'] += 1
        
        return stats
    
    def _upsert_nvd_cve(self, cursor, cve_data: Dict[str, Any]) -> str:
        """
        Insert or update NVD CVE in database.
        
        Args:
            cursor: Database cursor
            cve_data: CVE data from NVD API
            
        Returns:
            str: 'new', 'updated', or 'skipped'
        """
        cve_id = cve_data.get('cve_id')
        
        # Check if exists
        cursor.execute(
            "SELECT id, modified_date FROM feed_entries WHERE entry_id = %s",
            (cve_id,)
        )
        existing = cursor.fetchone()
        
        # Parse dates
        published_date = self._parse_iso_date(cve_data.get('published'))
        modified_date = self._parse_iso_date(cve_data.get('last_modified'))
        
        # Extract CVSS data
        cvss_v3 = cve_data.get('cvss_v3', {})
        cvss_score = cvss_v3.get('baseScore') if cvss_v3 else None
        cvss_vector = cvss_v3.get('vectorString') if cvss_v3 else None
        severity = cve_data.get('severity', '').lower()
        
        # Extract weaknesses
        weaknesses = cve_data.get('weaknesses', [])
        
        # Extract references
        refs = cve_data.get('references', [])
        ref_urls = [r.get('url') for r in refs if r.get('url')]
        
        # Affected products
        products = cve_data.get('affected_products', [])
        product_strs = [f"{p.get('vendor')}:{p.get('product')}:{p.get('version')}" for p in products]
        
        if existing:
            # Check if update needed
            existing_id, existing_modified = existing
            
            if existing_modified and modified_date:
                if existing_modified >= modified_date:
                    return 'skipped'  # Already up to date
            
            # Update existing entry
            cursor.execute(
                """
                UPDATE feed_entries
                SET title = %s,
                    description = %s,
                    severity = %s,
                    cvss_score = %s,
                    cvss_vector = %s,
                    cwe_ids = %s,
                    ref_urls = %s,
                    affected_products = %s,
                    published_date = %s,
                    modified_date = %s,
                    metadata = %s,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
                """,
                (
                    cve_id,
                    cve_data.get('description'),
                    severity,
                    cvss_score,
                    cvss_vector,
                    weaknesses if weaknesses else None,
                    ref_urls if ref_urls else None,
                    product_strs if product_strs else None,
                    published_date,
                    modified_date,
                    self._to_json(cve_data),
                    existing_id
                )
            )
            return 'updated'
        
        else:
            # Insert new entry
            cursor.execute(
                """
                INSERT INTO feed_entries (
                    feed_source, feed_type, entry_id, title, description,
                    severity, cvss_score, cvss_vector,
                    cwe_ids, ref_urls, affected_products,
                    published_date, modified_date,
                    metadata
                ) VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s,
                    %s, %s,
                    %s
                )
                """,
                (
                    'nvd',
                    'cve',
                    cve_id,
                    cve_id,
                    cve_data.get('description'),
                    severity,
                    cvss_score,
                    cvss_vector,
                    weaknesses if weaknesses else None,
                    ref_urls if ref_urls else None,
                    product_strs if product_strs else None,
                    published_date,
                    modified_date,
                    self._to_json(cve_data)
                )
            )
            return 'new'
    
    def _upsert_exploitdb_entry(self, cursor, exploit_data: Dict[str, Any]) -> str:
        """
        Insert or update ExploitDB entry in database.
        
        Args:
            cursor: Database cursor
            exploit_data: Exploit data from ExploitDB
            
        Returns:
            str: 'new', 'updated', or 'skipped'
        """
        edb_id = exploit_data.get('edb_id', f"EDB-{exploit_data.get('id', 'UNKNOWN')}")
        
        # Check if exists
        cursor.execute(
            "SELECT id FROM feed_entries WHERE entry_id = %s",
            (edb_id,)
        )
        existing = cursor.fetchone()
        
        # Parse data
        title = exploit_data.get('title', 'Untitled Exploit')
        description = exploit_data.get('description', '')
        exploit_type = exploit_data.get('type', 'unknown')
        platform = exploit_data.get('platform', 'unknown')
        published_date = self._parse_iso_date(exploit_data.get('date'))
        
        # CVE references
        cve_refs = exploit_data.get('cve', [])
        if isinstance(cve_refs, str):
            cve_refs = [cve_refs] if cve_refs else []
        
        # References
        exploit_id = exploit_data.get('id', 'unknown')
        default_url = f'https://www.exploit-db.com/exploits/{exploit_id}'
        refs = [exploit_data.get('url', default_url)]
        
        if existing:
            return 'skipped'  # ExploitDB entries rarely update
        
        else:
            # Insert new entry
            cursor.execute(
                """
                INSERT INTO feed_entries (
                    feed_source, feed_type, entry_id, title, description,
                    exploit_available, exploit_type, exploit_platform,
                    ref_urls, published_date,
                    metadata
                ) VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s,
                    %s, %s,
                    %s
                )
                """,
                (
                    'exploitdb',
                    'exploit',
                    edb_id,
                    title,
                    description,
                    'yes',
                    exploit_type,
                    platform,
                    refs,
                    published_date,
                    self._to_json(exploit_data)
                )
            )
            return 'new'
    
    def _parse_iso_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse ISO 8601 date string"""
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except Exception:
            return None
    
    def _to_json(self, data: Any) -> Optional[str]:
        """Convert to JSON string"""
        import json
        try:
            return json.dumps(data)
        except Exception:
            return None
    
    def sync_all(self, nvd_days: int = 7, nvd_batch: int = 100, edb_max: int = 50) -> Dict[str, Any]:
        """
        Sync all threat feeds (NVD + ExploitDB).
        
        Args:
            nvd_days: Days of NVD CVEs to fetch
            nvd_batch: Batch size for NVD
            edb_max: Max ExploitDB exploits
            
        Returns:
            dict: Combined statistics
        """
        logger.info("=" * 60)
        logger.info("  Starting Full Threat Feed Sync")
        logger.info("=" * 60)
        
        results = {
            'nvd': {},
            'exploitdb': {},
            'total_new': 0,
            'total_updated': 0,
            'total_errors': 0,
            'sync_time': datetime.utcnow().isoformat()
        }
        
        # Sync NVD
        logger.info("\n📡 Syncing NVD CVEs from API...")
        nvd_stats = self.sync_nvd_recent(days=nvd_days, batch_size=nvd_batch)
        results['nvd'] = nvd_stats
        results['total_new'] += nvd_stats.get('new', 0)
        results['total_updated'] += nvd_stats.get('updated', 0)
        results['total_errors'] += nvd_stats.get('errors', 0)
        
        # Sync ExploitDB
        logger.info("\n📡 Syncing ExploitDB exploits...")
        edb_stats = self.sync_exploitdb_recent(max_exploits=edb_max)
        results['exploitdb'] = edb_stats
        results['total_new'] += edb_stats.get('new', 0)
        results['total_updated'] += edb_stats.get('updated', 0)
        results['total_errors'] += edb_stats.get('errors', 0)
        
        # Summary
        logger.info("\n" + "=" * 60)
        logger.info("  Sync Complete!")
        logger.info("=" * 60)
        logger.info(f"  NVD: {nvd_stats.get('new', 0)} new, {nvd_stats.get('updated', 0)} updated")
        logger.info(f"  ExploitDB: {edb_stats.get('new', 0)} new, {edb_stats.get('updated', 0)} updated")
        logger.info(f"  Total: {results['total_new']} new, {results['total_updated']} updated")
        logger.info(f"  Errors: {results['total_errors']}")
        logger.info("=" * 60)
        
        return results


def main():
    """CLI entry point for manual sync"""
    import argparse
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    parser = argparse.ArgumentParser(description='Sync threat intelligence feeds')
    parser.add_argument('--nvd-days', type=int, default=7, help='Days of NVD CVEs to fetch')
    parser.add_argument('--nvd-batch', type=int, default=100, help='NVD batch size')
    parser.add_argument('--edb-max', type=int, default=50, help='Max ExploitDB exploits')
    parser.add_argument('--api-key', type=str, help='NVD API key (overrides env)')
    
    args = parser.parse_args()
    
    # Run sync
    service = FeedSyncService(nvd_api_key=args.api_key)
    results = service.sync_all(
        nvd_days=args.nvd_days,
        nvd_batch=args.nvd_batch,
        edb_max=args.edb_max
    )
    
    print("\n✅ Sync completed successfully!")
    print(f"📊 Results: {results['total_new']} new, {results['total_updated']} updated")


if __name__ == '__main__':
    main()
