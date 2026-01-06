"""
MCP Web Proxy Service
Secure proxy for LLM web access with SSRF protection and rate limiting.

Author: NTRO Security Team
Date: 2025-11-03
"""

import requests
import logging
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
from datetime import datetime, timedelta
from collections import defaultdict
import json
import threading

logger = logging.getLogger(__name__)


class MCPWebProxy:
    """
    Secure web proxy for LLM with safeguards:
    - Whitelisted domains only
    - Rate limiting per domain (thread-safe)
    - SSRF protection (no private IPs)
    - Response size limits
    - Timeout enforcement
    
    Thread Safety: All shared state access protected with locks
    """
    
    # Whitelisted domains (only these can be accessed)
    ALLOWED_DOMAINS = {
        'nvd.nist.gov',           # NVD CVE database
        'services.nvd.nist.gov',  # NVD API
        'cve.mitre.org',          # MITRE CVE
        'cve.org',                # CVE Program
        'exploit-db.com',         # ExploitDB
        'www.exploit-db.com',
        'cisa.gov',               # CISA advisories
        'www.cisa.gov',
        'github.com',             # GitHub security advisories
        'api.github.com',
        'cwe.mitre.org',          # CWE database
        'access.redhat.com',      # Red Hat security
        'ubuntu.com',             # Ubuntu security
        'debian.org',             # Debian security
        'security.microsoft.com', # Microsoft security
        'msrc.microsoft.com'      # MSRC
    }
    
    # Private IP ranges to block (SSRF protection)
    BLOCKED_IP_PATTERNS = [
        '127.',      # Loopback
        '10.',       # Private Class A
        '172.16.',   # Private Class B (172.16-31)
        '172.17.', '172.18.', '172.19.', '172.20.',
        '172.21.', '172.22.', '172.23.', '172.24.',
        '172.25.', '172.26.', '172.27.', '172.28.',
        '172.29.', '172.30.', '172.31.',
        '192.168.',  # Private Class C
        'localhost',
        '0.0.0.0'
    ]
    
    def __init__(
        self,
        max_requests_per_minute: int = 10,
        max_response_size: int = 500_000,  # 500 KB
        timeout: int = 10
    ):
        """
        Initialize MCP Web Proxy.
        
        Args:
            max_requests_per_minute: Rate limit per domain
            max_response_size: Max response size in bytes
            timeout: Request timeout in seconds
        """
        self.max_requests_per_minute = max_requests_per_minute
        self.max_response_size = max_response_size
        self.timeout = timeout
        
        # Rate limiting tracker: {domain: [(timestamp1, timestamp2, ...)]}
        self.request_history: Dict[str, List[datetime]] = defaultdict(list)
        # Thread-safe access to request_history
        self._history_lock = threading.Lock()
        
        logger.info("✅ MCP Web Proxy initialized (thread-safe)")
    
    def fetch(
        self,
        url: str,
        headers: Optional[Dict] = None,
        return_json: bool = True
    ) -> Dict[str, Any]:
        """
        Fetch URL with security checks.
        
        Args:
            url: URL to fetch
            headers: Optional HTTP headers
            return_json: Parse response as JSON
        
        Returns:
            {
                'success': bool,
                'data': response content or None,
                'error': error message or None,
                'status_code': HTTP status code,
                'url': final URL after redirects
            }
        """
        try:
            # 1. Validate URL
            validation = self._validate_url(url)
            if not validation['valid']:
                return {
                    'success': False,
                    'data': None,
                    'error': validation['error'],
                    'status_code': None,
                    'url': url
                }
            
            # 2. Check rate limits
            domain = urlparse(url).netloc
            if not self._check_rate_limit(domain):
                return {
                    'success': False,
                    'data': None,
                    'error': f'Rate limit exceeded for {domain} (max {self.max_requests_per_minute}/min)',
                    'status_code': 429,
                    'url': url
                }
            
            # 3. Make request
            headers = headers or {
                'User-Agent': 'NTRO-SecurityScanner/1.0',
                'Accept': 'application/json' if return_json else '*/*'
            }
            
            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True,
                stream=True  # Stream to check size
            )
            
            # 4. Check response size
            content = b''
            for chunk in response.iter_content(chunk_size=8192):
                content += chunk
                if len(content) > self.max_response_size:
                    return {
                        'success': False,
                        'data': None,
                        'error': f'Response too large (>{self.max_response_size} bytes)',
                        'status_code': response.status_code,
                        'url': response.url
                    }
            
            # 5. Update rate limit tracker
            self._record_request(domain)
            
            # 6. Parse response
            if return_json:
                try:
                    data = json.loads(content.decode('utf-8'))
                except json.JSONDecodeError as e:
                    return {
                        'success': False,
                        'data': None,
                        'error': f'Invalid JSON response: {e}',
                        'status_code': response.status_code,
                        'url': response.url
                    }
            else:
                data = content.decode('utf-8')
            
            return {
                'success': True,
                'data': data,
                'error': None,
                'status_code': response.status_code,
                'url': response.url
            }
            
        except requests.exceptions.Timeout:
            return {
                'success': False,
                'data': None,
                'error': f'Request timed out after {self.timeout}s',
                'status_code': None,
                'url': url
            }
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'data': None,
                'error': f'Request failed: {e}',
                'status_code': None,
                'url': url
            }
        except Exception as e:
            logger.error(f"Unexpected error in MCP fetch: {e}", exc_info=True)
            return {
                'success': False,
                'data': None,
                'error': f'Unexpected error: {e}',
                'status_code': None,
                'url': url
            }
    
    def _validate_url(self, url: str) -> Dict[str, Any]:
        """Validate URL against whitelist and SSRF checks"""
        try:
            parsed = urlparse(url)
            
            # Check scheme
            if parsed.scheme not in ('http', 'https'):
                return {
                    'valid': False,
                    'error': f'Invalid scheme: {parsed.scheme} (only http/https allowed)'
                }
            
            # Check domain whitelist
            domain = parsed.netloc.lower()
            if domain not in self.ALLOWED_DOMAINS:
                return {
                    'valid': False,
                    'error': f'Domain not whitelisted: {domain}'
                }
            
            # Check for private IPs (SSRF protection)
            for blocked_pattern in self.BLOCKED_IP_PATTERNS:
                if blocked_pattern in domain:
                    return {
                        'valid': False,
                        'error': f'Blocked IP pattern detected: {blocked_pattern}'
                    }
            
            return {'valid': True, 'error': None}
            
        except Exception as e:
            return {'valid': False, 'error': f'URL parsing error: {e}'}
    
    def _check_rate_limit(self, domain: str) -> bool:
        """
        Check if request is within rate limit (thread-safe)
        
        Thread Safety: Uses lock to safely access and modify request_history
        """
        now = datetime.now()
        one_minute_ago = now - timedelta(minutes=1)
        
        with self._history_lock:
            # Clean old requests
            self.request_history[domain] = [
                ts for ts in self.request_history[domain]
                if ts > one_minute_ago
            ]
            
            # Check if under limit
            if len(self.request_history[domain]) >= self.max_requests_per_minute:
                logger.warning(
                    f"Rate limit exceeded for {domain}: "
                    f"{len(self.request_history[domain])}/{self.max_requests_per_minute}"
                )
                return False
            
            return True
    
    def _record_request(self, domain: str):
        """
        Record request timestamp for rate limiting (thread-safe)
        
        Thread Safety: Uses lock to safely append to request_history
        """
        with self._history_lock:
            self.request_history[domain].append(datetime.now())
    
    def fetch_cve_details(self, cve_id: str) -> Dict[str, Any]:
        """
        Fetch CVE details from NVD API.
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234)
        
        Returns:
            CVE details from NVD
        """
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        result = self.fetch(url, return_json=True)
        
        if result['success'] and result['data']:
            # Extract relevant fields
            cves = result['data'].get('vulnerabilities', [])
            if cves:
                cve = cves[0].get('cve', {})
                
                # Extract CVSS v3 metrics
                cvss_v3 = {}
                metrics = cve.get('metrics', {})
                if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                    cvss_v3 = metrics['cvssMetricV31'][0].get('cvssData', {})
                elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                    cvss_v3 = metrics['cvssMetricV30'][0].get('cvssData', {})
                
                return {
                    'success': True,
                    'cve_id': cve_id,
                    'published': cve.get('published'),
                    'last_modified': cve.get('lastModified'),
                    'description': cve.get('descriptions', [{}])[0].get('value', 'No description available'),
                    'cvss_v3': cvss_v3,
                    'references': cve.get('references', []),
                    'source': 'nvd'
                }
        
        return result
    
    def search_exploits(self, cve_id: str) -> Dict[str, Any]:
        """
        Search ExploitDB for public exploits.
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            Exploit search results
        """
        # Note: ExploitDB doesn't have a public API, would need scraping
        # Alternative: Use local ExploitDB feed from threat_feeds service
        return {
            'success': False,
            'error': 'ExploitDB API not available, use local feed instead',
            'cve_id': cve_id
        }


# Singleton instance
_mcp_proxy = None


def get_mcp_proxy() -> MCPWebProxy:
    """Get or create MCP proxy singleton"""
    global _mcp_proxy
    if _mcp_proxy is None:
        _mcp_proxy = MCPWebProxy(
            max_requests_per_minute=10,
            max_response_size=500_000,
            timeout=10
        )
    return _mcp_proxy
