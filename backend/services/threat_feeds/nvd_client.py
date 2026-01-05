"""
NVD (National Vulnerability Database) API Client

Fetches CVE data from the NIST NVD API v2.0.
https://nvd.nist.gov/developers/vulnerabilities

Real-time integration with NVD API for continuous threat intelligence updates.
"""

import os
import requests
import time
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import logging
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


class NVDClient:
    """Client for interacting with the NVD API."""
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize NVD client.
        
        Args:
            api_key: Optional API key for higher rate limits
                    Without key: 5 requests per 30 seconds
                    With key: 50 requests per 30 seconds
        """
        # Use provided API key or get from environment
        self.api_key = api_key or os.getenv('NVD_API_KEY', 'cd0d6aed-069d-4584-b3b5-7f1580f746e8')
        self.session = requests.Session()
        
        if self.api_key:
            self.session.headers.update({'apiKey': self.api_key})
            logger.info("NVD client initialized with API key (50 req/30s)")
        else:
            logger.info("NVD client initialized without API key (5 req/30s)")
        
        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = 0.6 if self.api_key else 6  # seconds
    
    def _rate_limit(self):
        """Enforce rate limiting."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_request_interval:
            time.sleep(self.min_request_interval - elapsed)
        self.last_request_time = time.time()
    
    def get_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information for a specific CVE.
        
        Args:
            cve_id: CVE identifier (e.g., 'CVE-2024-1234')
            
        Returns:
            dict: CVE data or None if not found
        """
        try:
            self._rate_limit()
            
            params = {'cveId': cve_id}
            response = self.session.get(self.BASE_URL, params=params, timeout=30)
            
            if response.status_code == 404:
                logger.warning(f"CVE not found: {cve_id}")
                return None
            
            response.raise_for_status()
            data = response.json()
            
            if data.get('totalResults', 0) == 0:
                logger.warning(f"No results for CVE: {cve_id}")
                return None
            
            cve_item = data['vulnerabilities'][0]['cve']
            
            # Parse CVE data
            parsed = self._parse_cve(cve_item)
            
            logger.info(f"Retrieved CVE data: {cve_id}")
            return parsed
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching CVE {cve_id}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error parsing CVE {cve_id}: {e}")
            return None
    
    def get_recent_cves(self, days: int = 7, max_results: int = 100) -> List[Dict[str, Any]]:
        """
        Get CVEs published in the last N days.
        
        Args:
            days: Number of days to look back
            max_results: Maximum number of results
            
        Returns:
            list: List of CVE data dictionaries
        """
        try:
            self._rate_limit()
            
            # Calculate date range
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)
            
            params = {
                'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                'resultsPerPage': min(max_results, 2000)
            }
            
            response = self.session.get(self.BASE_URL, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            cves = []
            for vuln in data.get('vulnerabilities', []):
                cve_item = vuln.get('cve')
                if cve_item:
                    parsed = self._parse_cve(cve_item)
                    cves.append(parsed)
            
            logger.info(f"Retrieved {len(cves)} recent CVEs (last {days} days)")
            return cves
            
        except Exception as e:
            logger.error(f"Error fetching recent CVEs: {e}")
            return []
    
    def search_cves(
        self,
        keyword: Optional[str] = None,
        cvss_severity: Optional[str] = None,
        cwe_id: Optional[str] = None,
        max_results: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Search CVEs by criteria.
        
        Args:
            keyword: Keyword to search in descriptions
            cvss_severity: Severity level (LOW, MEDIUM, HIGH, CRITICAL)
            cwe_id: CWE identifier (e.g., 'CWE-79')
            max_results: Maximum number of results
            
        Returns:
            list: List of matching CVEs
        """
        try:
            self._rate_limit()
            
            params = {'resultsPerPage': min(max_results, 2000)}
            
            if keyword:
                params['keywordSearch'] = keyword
            
            if cvss_severity:
                params['cvssV3Severity'] = cvss_severity.upper()
            
            if cwe_id:
                params['cweId'] = cwe_id
            
            response = self.session.get(self.BASE_URL, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            cves = []
            for vuln in data.get('vulnerabilities', []):
                cve_item = vuln.get('cve')
                if cve_item:
                    parsed = self._parse_cve(cve_item)
                    cves.append(parsed)
            
            logger.info(f"Search returned {len(cves)} CVEs")
            return cves
            
        except Exception as e:
            logger.error(f"Error searching CVEs: {e}")
            return []
    
    def _parse_cve(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse raw CVE data into standardized format.
        
        Args:
            cve_data: Raw CVE data from NVD API
            
        Returns:
            dict: Parsed CVE data
        """
        cve_id = cve_data.get('id', 'UNKNOWN')
        
        # Description
        descriptions = cve_data.get('descriptions', [])
        description = next(
            (d['value'] for d in descriptions if d.get('lang') == 'en'),
            'No description available'
        )
        
        # CVSS scores
        metrics = cve_data.get('metrics', {})
        cvss_v3 = None
        cvss_v2 = None
        
        # Try CVSS v3.1 first, then v3.0
        for version in ['cvssMetricV31', 'cvssMetricV30']:
            if version in metrics and metrics[version]:
                cvss_data = metrics[version][0]['cvssData']
                cvss_v3 = {
                    'version': cvss_data.get('version'),
                    'vectorString': cvss_data.get('vectorString'),
                    'baseScore': cvss_data.get('baseScore'),
                    'baseSeverity': cvss_data.get('baseSeverity'),
                    'exploitabilityScore': metrics[version][0].get('exploitabilityScore'),
                    'impactScore': metrics[version][0].get('impactScore')
                }
                break
        
        # CVSS v2 (fallback)
        if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
            cvss_data = metrics['cvssMetricV2'][0]['cvssData']
            cvss_v2 = {
                'version': cvss_data.get('version'),
                'vectorString': cvss_data.get('vectorString'),
                'baseScore': cvss_data.get('baseScore'),
                'severity': metrics['cvssMetricV2'][0].get('baseSeverity')
            }
        
        # Weaknesses (CWE)
        weaknesses = []
        for weakness in cve_data.get('weaknesses', []):
            for desc in weakness.get('description', []):
                if desc.get('lang') == 'en':
                    weaknesses.append(desc.get('value'))
        
        # References
        references = []
        for ref in cve_data.get('references', []):
            references.append({
                'url': ref.get('url'),
                'source': ref.get('source'),
                'tags': ref.get('tags', [])
            })
        
        # Published and modified dates
        published = cve_data.get('published')
        last_modified = cve_data.get('lastModified')
        
        # Vendor and product info (from CPE)
        configurations = cve_data.get('configurations', [])
        affected_products = []
        
        for config in configurations:
            for node in config.get('nodes', []):
                for cpe_match in node.get('cpeMatch', []):
                    if cpe_match.get('vulnerable'):
                        cpe_uri = cpe_match.get('criteria', '')
                        # Parse CPE: cpe:2.3:a:vendor:product:version:...
                        parts = cpe_uri.split(':')
                        if len(parts) >= 5:
                            affected_products.append({
                                'vendor': parts[3],
                                'product': parts[4],
                                'version': parts[5] if len(parts) > 5 else '*'
                            })
        
        return {
            'cve_id': cve_id,
            'description': description,
            'published': published,
            'last_modified': last_modified,
            'cvss_v3': cvss_v3,
            'cvss_v2': cvss_v2,
            'severity': cvss_v3['baseSeverity'] if cvss_v3 else (cvss_v2['severity'] if cvss_v2 else 'UNKNOWN'),
            'weaknesses': weaknesses,
            'references': references,
            'affected_products': affected_products,
            'source': 'NVD',
            'source_url': f'https://nvd.nist.gov/vuln/detail/{cve_id}'
        }
    
    def enrich_vulnerability(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich vulnerability data with NVD information.
        
        Args:
            vuln_data: Vulnerability data with 'cve_id' field
            
        Returns:
            dict: Enriched vulnerability data
        """
        cve_id = vuln_data.get('cve_id') or vuln_data.get('cve')
        
        if not cve_id:
            logger.warning("No CVE ID found in vulnerability data")
            return vuln_data
        
        # Fetch NVD data
        nvd_data = self.get_cve(cve_id)
        
        if not nvd_data:
            return vuln_data
        
        # Merge data
        enriched = vuln_data.copy()
        enriched.update({
            'nvd_data': nvd_data,
            'cvss_v3': nvd_data.get('cvss_v3'),
            'cvss_v2': nvd_data.get('cvss_v2'),
            'severity': nvd_data.get('severity'),
            'weaknesses': nvd_data.get('weaknesses'),
            'references': nvd_data.get('references'),
            'affected_products': nvd_data.get('affected_products'),
            'nvd_url': nvd_data.get('source_url'),
            'last_updated': datetime.utcnow().isoformat()
        })
        
        return enriched
