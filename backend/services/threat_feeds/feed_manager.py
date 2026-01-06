"""
Threat Feed Manager

Orchestrates threat intelligence feed updates and caching.
"""

import logging
import json
import os
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from pathlib import Path

from services.threat_feeds.nvd_client import NVDClient
from services.threat_feeds.exploitdb_client import ExploitDBClient

logger = logging.getLogger(__name__)


class ThreatFeedManager:
    """Manages threat intelligence feeds and caching."""
    
    def __init__(self, cache_dir: str = "data/threat_feeds"):
        """
        Initialize feed manager.
        
        Args:
            cache_dir: Directory to store cached feed data
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize clients
        nvd_api_key = os.getenv('NVD_API_KEY')
        self.nvd_client = NVDClient(api_key=nvd_api_key)
        self.exploitdb_client = ExploitDBClient()
        
        # Cache settings
        self.cache_ttl = timedelta(hours=24)  # Cache for 24 hours
    
    def get_feed_status(self) -> Dict[str, Any]:
        """
        Get status of all threat feeds.
        
        Returns:
            dict: Feed status information
        """
        status = {
            'nvd': self._get_cache_status('nvd'),
            'exploitdb': self._get_cache_status('exploitdb'),
            'last_update': self._get_last_update(),
            'cache_size': self._get_cache_size()
        }
        
        return status
    
    def refresh_feeds(self, force: bool = False) -> Dict[str, Any]:
        """
        Refresh threat intelligence feeds.
        
        Args:
            force: Force refresh even if cache is valid
            
        Returns:
            dict: Refresh results
        """
        results = {
            'timestamp': datetime.utcnow().isoformat(),
            'nvd_updated': False,
            'exploitdb_updated': False,
            'errors': []
        }
        
        try:
            # Check if refresh is needed
            if not force and not self._needs_refresh():
                logger.info("Cache is still valid, skipping refresh")
                return results
            
            # Refresh NVD data
            logger.info("Refreshing NVD feed...")
            nvd_result = self._refresh_nvd()
            results['nvd_updated'] = nvd_result['success']
            results['nvd_cve_count'] = nvd_result.get('cve_count', 0)
            
            if not nvd_result['success']:
                results['errors'].append(nvd_result.get('error'))
            
            # Update last refresh timestamp
            self._update_last_refresh()
            
            logger.info(f"Feed refresh completed: {results}")
            
        except Exception as e:
            logger.error(f"Error refreshing feeds: {e}")
            results['errors'].append(str(e))
        
        return results
    
    def enrich_vulnerability(self, vuln_data: Dict[str, Any], sources: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Enrich vulnerability data with threat intelligence.
        
        Args:
            vuln_data: Vulnerability data
            sources: List of sources to use ('nvd', 'exploitdb'), or None for all
            
        Returns:
            dict: Enriched vulnerability data
        """
        if sources is None:
            sources = ['nvd', 'exploitdb']
        
        enriched = vuln_data.copy()
        
        # Enrich with NVD data
        if 'nvd' in sources:
            try:
                enriched = self.nvd_client.enrich_vulnerability(enriched)
            except Exception as e:
                logger.error(f"Error enriching with NVD: {e}")
        
        # Enrich with ExploitDB data
        if 'exploitdb' in sources:
            try:
                enriched = self.exploitdb_client.enrich_vulnerability(enriched)
            except Exception as e:
                logger.error(f"Error enriching with ExploitDB: {e}")
        
        return enriched
    
    def search_vulnerabilities(
        self,
        keyword: Optional[str] = None,
        severity: Optional[str] = None,
        days: int = 7
    ) -> List[Dict[str, Any]]:
        """
        Search for vulnerabilities across feeds.
        
        Args:
            keyword: Search keyword
            severity: Filter by severity
            days: Look back N days
            
        Returns:
            list: Matching vulnerabilities
        """
        results = []
        
        # Search NVD
        if keyword:
            nvd_results = self.nvd_client.search_cves(
                keyword=keyword,
                cvss_severity=severity
            )
        else:
            nvd_results = self.nvd_client.get_recent_cves(days=days)
        
        results.extend(nvd_results)
        
        return results
    
    def _refresh_nvd(self) -> Dict[str, Any]:
        """Refresh NVD feed data."""
        try:
            # Fetch recent CVEs
            cves = self.nvd_client.get_recent_cves(days=7, max_results=100)
            
            # Cache data
            cache_file = self.cache_dir / 'nvd_recent.json'
            with open(cache_file, 'w') as f:
                json.dump({
                    'timestamp': datetime.utcnow().isoformat(),
                    'cves': cves
                }, f, indent=2)
            
            return {
                'success': True,
                'cve_count': len(cves)
            }
            
        except Exception as e:
            logger.error(f"Error refreshing NVD feed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _needs_refresh(self) -> bool:
        """Check if feeds need to be refreshed."""
        last_update = self._get_last_update()
        
        if not last_update:
            return True
        
        try:
            last_dt = datetime.fromisoformat(last_update)
            age = datetime.utcnow() - last_dt
            return age > self.cache_ttl
        except (ValueError, TypeError) as e:
            logger.warning(f"Failed to parse last_update timestamp: {e}")
            return True
    
    def _get_last_update(self) -> Optional[str]:
        """Get timestamp of last feed update."""
        status_file = self.cache_dir / 'status.json'
        
        if not status_file.exists():
            return None
        
        try:
            with open(status_file, 'r') as f:
                status = json.load(f)
                return status.get('last_update')
        except (IOError, json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Failed to read status file: {e}")
            return None
    
    def _update_last_refresh(self):
        """Update last refresh timestamp."""
        status_file = self.cache_dir / 'status.json'
        
        status = {
            'last_update': datetime.utcnow().isoformat()
        }
        
        with open(status_file, 'w') as f:
            json.dump(status, f, indent=2)
    
    def _get_cache_status(self, feed: str) -> Dict[str, Any]:
        """Get cache status for a specific feed."""
        cache_file = self.cache_dir / f'{feed}_recent.json'
        
        if not cache_file.exists():
            return {
                'cached': False,
                'age': None,
                'size': 0
            }
        
        try:
            stat = cache_file.stat()
            modified = datetime.fromtimestamp(stat.st_mtime)
            age = datetime.utcnow() - modified
            
            return {
                'cached': True,
                'age': str(age),
                'age_hours': age.total_seconds() / 3600,
                'size': stat.st_size,
                'valid': age < self.cache_ttl
            }
        except (OSError, IOError, ValueError) as e:
            logger.debug(f"Failed to get cache info: {e}")
            return {
                'cached': False,
                'age': None,
                'size': 0
            }
    
    def _get_cache_size(self) -> int:
        """Get total size of cache directory."""
        total = 0
        for file in self.cache_dir.glob('*'):
            if file.is_file():
                total += file.stat().st_size
        return total
