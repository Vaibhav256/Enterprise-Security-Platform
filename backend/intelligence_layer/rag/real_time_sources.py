"""
Real-Time Data Sources Integration
Provides access to live security data feeds (NVD, ExploitDB, CWE, etc.)
"""

import requests
import logging
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SimpleCache:
    """Simple in-memory cache with TTL"""
    
    def __init__(self, ttl_seconds=3600):
        self.cache = {}
        self.ttl = ttl_seconds
        self.timestamps = {}
    
    def get(self, key: str) -> Optional[Any]:
        if key not in self.cache:
            return None
        
        # Check if expired
        timestamp = self.timestamps.get(key)
        if timestamp and (datetime.utcnow() - timestamp).seconds > self.ttl:
            del self.cache[key]
            del self.timestamps[key]
            return None
        
        return self.cache[key]
    
    def set(self, key: str, value: Any):
        self.cache[key] = value
        self.timestamps[key] = datetime.utcnow()
    
    def clear(self):
        self.cache.clear()
        self.timestamps.clear()


class NVDClient:
    """
    Query NIST Vulnerability Database in real-time
    
    Free API with optional API key for higher rate limits
    Docs: https://nvd.nist.gov/developers
    """
    
    def __init__(self, api_key: Optional[str] = None, cache_ttl: int = 3600):
        """
        Initialize NVD client
        
        Args:
            api_key: Optional NVD API key (free registration)
            cache_ttl: Cache time-to-live in seconds
        """
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cache = SimpleCache(ttl_seconds=cache_ttl)
        self.session = requests.Session()
        
        logger.info("NVDClient initialized")
    
    def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a specific CVE
        
        Args:
            cve_id: CVE ID (e.g., "CVE-2023-44487")
        
        Returns:
            Dict with CVE details or None on error
        """
        # Check cache first
        cached = self.cache.get(cve_id)
        if cached:
            logger.info(f"Cache hit for {cve_id}")
            return cached
        
        try:
            # Query NVD API
            params = {
                'cveId': cve_id
            }
            
            # API key must be sent in header, not as query parameter
            headers = {}
            if self.api_key:
                headers['apiKey'] = self.api_key
            
            logger.info(f"Fetching {cve_id} from NVD API...")
            response = self.session.get(
                self.base_url,
                params=params,
                headers=headers,
                timeout=10
            )
            
            if response.status_code != 200:
                logger.error(f"NVD API error: HTTP {response.status_code}")
                return None
            
            data = response.json()
            
            # Check if vulnerabilities exist
            if not data.get('vulnerabilities'):
                logger.warning(f"No data found for {cve_id}")
                return None
            
            # Extract CVE data
            cve_data = data['vulnerabilities'][0]['cve']
            
            # Parse metrics
            cvss_score = 0.0
            severity = "UNKNOWN"
            
            try:
                metrics = cve_data.get('metrics', {})
                
                # Try CVSSv3.1 first (most common)
                if 'cvssMetricV31' in metrics:
                    cvss_data = metrics['cvssMetricV31']
                    if isinstance(cvss_data, list) and cvss_data:
                        cvss_score = cvss_data[0].get('cvssData', {}).get('baseScore', 0.0)
                        severity = cvss_data[0].get('cvssData', {}).get('baseSeverity', 'UNKNOWN')
                    elif isinstance(cvss_data, dict):
                        cvss_score = cvss_data.get('cvssData', {}).get('baseScore', 0.0)
                        severity = cvss_data.get('cvssData', {}).get('baseSeverity', 'UNKNOWN')
                
                # Fallback to CVSSv3.0
                elif 'cvssMetricV30' in metrics:
                    cvss_data = metrics['cvssMetricV30']
                    if isinstance(cvss_data, list) and cvss_data:
                        cvss_score = cvss_data[0].get('cvssData', {}).get('baseScore', 0.0)
                        severity = cvss_data[0].get('cvssData', {}).get('baseSeverity', 'UNKNOWN')
                    elif isinstance(cvss_data, dict):
                        cvss_score = cvss_data.get('cvssData', {}).get('baseScore', 0.0)
                        severity = cvss_data.get('cvssData', {}).get('baseSeverity', 'UNKNOWN')
                
                # Fallback to CVSSv2.0
                elif 'cvssMetricV2' in metrics:
                    cvss_data = metrics['cvssMetricV2']
                    if isinstance(cvss_data, list) and cvss_data:
                        cvss_score = cvss_data[0].get('cvssData', {}).get('baseScore', 0.0)
                        # CVSSv2 doesn't have baseSeverity, calculate it
                        if cvss_score >= 7.0:
                            severity = "HIGH"
                        elif cvss_score >= 4.0:
                            severity = "MEDIUM"
                        else:
                            severity = "LOW"
                    elif isinstance(cvss_data, dict):
                        cvss_score = cvss_data.get('cvssData', {}).get('baseScore', 0.0)
                        if cvss_score >= 7.0:
                            severity = "HIGH"
                        elif cvss_score >= 4.0:
                            severity = "MEDIUM"
                        else:
                            severity = "LOW"
                
                # Old NVD API format fallback
                elif 'cvssV3_1' in metrics:
                    cvss_score = metrics['cvssV3_1'].get('baseScore', 0.0)
                    severity = metrics['cvssV3_1'].get('baseSeverity', 'UNKNOWN')
                elif 'cvssV3_0' in metrics:
                    cvss_score = metrics['cvssV3_0'].get('baseScore', 0.0)
                    severity = metrics['cvssV3_0'].get('baseSeverity', 'UNKNOWN')
                elif 'cvssV2_0' in metrics:
                    cvss_score = metrics['cvssV2_0'].get('baseScore', 0.0)
                
                if cvss_score == 0.0:
                    logger.debug(f"⚠️  No CVSS score found for {cve_id}. Metrics structure: {list(metrics.keys())}")
                    
            except Exception as e:
                logger.warning(f"Could not parse CVSS metrics for {cve_id}: {e}")
            
            # Parse descriptions
            description = "No description available"
            try:
                descriptions = cve_data.get('descriptions', [])
                if descriptions:
                    description = descriptions[0].get('value', description)
            except Exception as e:
                logger.warning(f"Could not parse description: {e}")
            
            # Parse references
            references = []
            try:
                refs = cve_data.get('references', [])
                for ref in refs[:5]:  # Limit to 5 references
                    if 'url' in ref:
                        references.append(ref['url'])
            except Exception as e:
                logger.warning(f"Could not parse references: {e}")
            
            # Parse CWEs
            cwes = []
            try:
                weaknesses = cve_data.get('weaknesses', [])
                for weakness in weaknesses:
                    cwe_id = weakness.get('source', '').split('/')[-1] if 'source' in weakness else None
                    if cwe_id:
                        cwes.append(cwe_id)
            except Exception as e:
                logger.warning(f"Could not parse CWEs: {e}")
            
            # Assemble result
            result = {
                'id': cve_data['id'],
                'description': description,
                'cvss_score': cvss_score,
                'severity': severity,
                'published': cve_data.get('published', ''),
                'updated': cve_data.get('lastModified', ''),
                'cwes': cwes,
                'references': references,
                'source': 'NVD',
                'retrieved_at': datetime.utcnow().isoformat()
            }
            
            # Cache the result
            self.cache.set(cve_id, result)
            logger.info(f"Successfully retrieved {cve_id}: CVSS {cvss_score} ({severity})")
            
            return result
        
        except requests.exceptions.Timeout:
            logger.error(f"NVD API timeout for {cve_id}")
            return None
        
        except requests.exceptions.RequestException as e:
            logger.error(f"NVD API request error: {e}")
            return None
        
        except Exception as e:
            logger.error(f"Unexpected error fetching {cve_id}: {e}")
            return None
    
    def search_cves(
        self,
        keyword: str,
        max_results: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Search for CVEs by keyword using NVD API v2.0
        
        Args:
            keyword: Search keyword (product name, technology, etc.)
            max_results: Maximum number of results to return
        
        Returns:
            List of matching CVEs with basic info
        """
        try:
            logger.info(f"Searching NVD for keyword: {keyword}")
            
            # NVD API v2.0 supports keywordSearch parameter
            params = {
                'keywordSearch': keyword,
                'resultsPerPage': min(max_results, 100)  # API max is 2000, but keep it reasonable
            }
            
            # API key must be sent in header, not as query parameter
            headers = {}
            if self.api_key:
                headers['apiKey'] = self.api_key
            
            response = self.session.get(
                f"{self.base_url}",
                params=params,
                headers=headers,
                timeout=15
            )
            
            # Log the actual URL called for debugging
            logger.info(f"NVD API called: {response.url} - Status: {response.status_code}")
            
            # Rate limiting (0.6 seconds for free tier, 0.05 for API key)
            time.sleep(0.05 if self.api_key else 0.6)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                results = []
                for vuln in vulnerabilities[:max_results]:
                    cve_data = vuln.get('cve', {})
                    cve_id = cve_data.get('id', 'Unknown')
                    
                    # Get description
                    descriptions = cve_data.get('descriptions', [])
                    description = ''
                    for desc in descriptions:
                        if desc.get('lang') == 'en':
                            description = desc.get('value', '')
                            break
                    
                    # Get CVSS scores
                    metrics = cve_data.get('metrics', {})
                    cvss_v3 = metrics.get('cvssMetricV31', [{}])[0] if metrics.get('cvssMetricV31') else {}
                    cvss_v2 = metrics.get('cvssMetricV2', [{}])[0] if metrics.get('cvssMetricV2') else {}
                    
                    cvss_score = 0.0
                    severity = 'UNKNOWN'
                    
                    if cvss_v3:
                        cvss_data = cvss_v3.get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore', 0.0)
                        severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    elif cvss_v2:
                        cvss_data = cvss_v2.get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore', 0.0)
                        severity = cvss_v2.get('baseSeverity', 'UNKNOWN')
                    
                    # Get published date
                    published = cve_data.get('published', '')
                    
                    results.append({
                        'cve_id': cve_id,
                        'description': description,
                        'cvss_score': cvss_score,
                        'severity': severity,
                        'published_date': published,
                        'source': 'NVD',
                        'url': f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    })
                
                logger.info(f"Found {len(results)} CVEs for keyword: {keyword}")
                return results
            
            elif response.status_code == 403:
                logger.error("NVD API key required or rate limited")
                return []
            
            else:
                logger.error(f"NVD search failed: HTTP {response.status_code}")
                return []
        
        except requests.exceptions.Timeout:
            logger.error(f"NVD search timeout for keyword: {keyword}")
            return []
        
        except Exception as e:
            logger.error(f"Error searching CVEs: {e}", exc_info=True)
            return []
    
    def get_recent_cves(self, days: int = 7, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get recently published CVEs
        
        Args:
            days: Look back this many days
            limit: Maximum number of results
        
        Returns:
            List of recent CVEs
        """
        try:
            # Calculate date range
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)
            
            params = {
                'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S'),
                'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S'),
                'resultsPerPage': limit
            }
            
            if self.api_key:
                params['apiKey'] = self.api_key
            
            logger.info(f"Fetching recent CVEs from last {days} days...")
            response = self.session.get(
                self.base_url,
                params=params,
                timeout=10
            )
            
            if response.status_code != 200:
                logger.error(f"NVD API error: HTTP {response.status_code}")
                return []
            
            data = response.json()
            results = []
            
            for vuln in data.get('vulnerabilities', [])[:limit]:
                cve_data = vuln['cve']
                results.append({
                    'id': cve_data['id'],
                    'published': cve_data.get('published', '')
                })
            
            logger.info(f"Retrieved {len(results)} recent CVEs")
            return results
        
        except Exception as e:
            logger.error(f"Error fetching recent CVEs: {e}")
            return []


class ExploitDBClient:
    """
    Query Exploit Database for public exploits
    
    Note: ExploitDB requires registration for API access
    """
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.base_url = "https://exploit-db.com/api/v1"
        self.cache = SimpleCache(ttl_seconds=7200)
        
        logger.info("ExploitDBClient initialized")
    
    def search_by_cve(self, cve_id: str) -> List[Dict[str, Any]]:
        """
        Search for exploits by CVE ID
        
        Args:
            cve_id: CVE ID (e.g., "CVE-2023-44487")
        
        Returns:
            List of exploits for this CVE
        """
        if not self.api_key:
            logger.warning("ExploitDB API key not configured - skipping exploit search")
            return []
        
        try:
            # Check cache
            cached = self.cache.get(f"exploit_{cve_id}")
            if cached:
                return cached
            
            # Search ExploitDB
            # Note: This is a simplified example - actual implementation
            # would need to handle ExploitDB API rate limits and authentication
            
            logger.info(f"ExploitDB search not implemented yet (requires API key)")
            return []
        
        except Exception as e:
            logger.error(f"Error searching ExploitDB: {e}")
            return []


class CWEClient:
    """
    Query Common Weakness Enumeration database
    """
    
    def __init__(self):
        self.cache = SimpleCache(ttl_seconds=86400)
        logger.info("CWEClient initialized")
    
    def get_cwe_details(self, cwe_id: str) -> Optional[Dict[str, Any]]:
        """
        Get CWE details (e.g., CWE-79 for XSS)
        
        Args:
            cwe_id: CWE ID without prefix (e.g., "79" for CWE-79)
        
        Returns:
            CWE details or None
        """
        try:
            # Check cache
            cached = self.cache.get(f"cwe_{cwe_id}")
            if cached:
                return cached
            
            # In production, would fetch from:
            # https://cwe.mitre.org/data/csv/2000.csv or similar
            
            # For now, return basic info
            logger.warning("CWE lookup not fully implemented yet")
            return None
        
        except Exception as e:
            logger.error(f"Error fetching CWE details: {e}")
            return None


class RealTimeSourceManager:
    """
    Manager for all real-time data sources
    """
    
    def __init__(self, nvd_api_key: Optional[str] = None):
        self.nvd = NVDClient(api_key=nvd_api_key)
        self.exploitdb = ExploitDBClient(api_key=None)  # TODO: Add from config
        self.cwe = CWEClient()
    
    def enrich_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Enrich a CVE with all available real-time data
        
        Args:
            cve_id: CVE ID
        
        Returns:
            Enriched CVE data from multiple sources
        """
        try:
            result = {
                'id': cve_id,
                'sources': {},
                'confidence': 0.0
            }
            
            # Fetch from NVD
            nvd_data = self.nvd.get_cve_details(cve_id)
            if nvd_data:
                result['sources']['nvd'] = nvd_data
                result['confidence'] = 0.85  # High confidence for real-time data
            else:
                result['confidence'] = 0.3  # Lower confidence if NVD not available
            
            # Fetch from ExploitDB
            exploits = self.exploitdb.search_by_cve(cve_id)
            if exploits:
                result['sources']['exploits'] = exploits
                result['confidence'] += 0.05
            
            return result
        
        except Exception as e:
            logger.error(f"Error enriching {cve_id}: {e}")
            return None
    
    def clear_cache(self):
        """Clear all caches"""
        self.nvd.cache.clear()
        self.exploitdb.cache.clear()
        self.cwe.cache.clear()
        logger.info("All caches cleared")
