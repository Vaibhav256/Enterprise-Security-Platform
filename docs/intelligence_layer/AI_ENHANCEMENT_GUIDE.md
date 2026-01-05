# AI Enhancement Guide: Summaries + MCP Web Access

## 🎯 Overview

This guide addresses two critical enhancements:

1. **✅ ISSUE 1: AI Summaries Not Generating** - Ollama is running but summaries aren't being created
2. **🌐 ISSUE 2: MCP Web Access** - Enable real-time web lookups like ChatGPT (CVE lookups, threat intel, etc.)

---

## ✅ ISSUE 1: Fix AI Summary Generation

### Current Status

**✅ Ollama Running**: localhost:11434  
**✅ Model Installed**: llama3.2:3b-instruct-q4_K_M (2.02 GB)  
**❌ Problem**: Summaries not being generated for scans

### Root Cause Analysis

The AI summary pipeline has multiple failure points:

1. **Ollama connectivity check fails silently**
2. **Error handling prevents retry**
3. **No automatic regeneration**
4. **Frontend doesn't show retry option**

### Solution 1: Test AI Summary Manually

```bash
cd backend
python
```

```python
# Test AI summary generation directly
from intelligence_layer.rag.ai_summary_generator import AISummaryGenerator, ScanData

# Initialize generator
generator = AISummaryGenerator(
    ollama_base_url="http://localhost:11434",
    model_name="llama3.2:3b-instruct-q4_K_M",
    temperature=0.4
)

# Create test scan data
test_scan = ScanData(
    scan_id="test_001",
    tool_name="Nikto",
    scan_type="web_vulnerability",
    findings=[
        {
            'cve_id': 'CVE-2024-1234',
            'severity': 'critical',
            'cvss_score': 9.8,
            'title': 'Remote Code Execution in Apache',
            'description': 'Path traversal allows RCE',
            'host': '192.168.1.100',
            'port': 80,
            'service': 'http'
        },
        {
            'cve_id': 'CVE-2024-5678',
            'severity': 'high',
            'cvss_score': 7.5,
            'title': 'SQL Injection in login form',
            'description': 'Unvalidated input allows SQL injection',
            'host': '192.168.1.100',
            'port': 443,
            'service': 'https'
        }
    ],
    scan_date="2025-11-03T10:00:00Z"
)

# Generate summary
summary = generator.generate_scan_summary(test_scan, summary_type="scan_executive")

# Print results
print("\n" + "="*60)
print("GENERATED AI SUMMARY")
print("="*60)
print(f"\nTitle: {summary.title}")
print(f"Risk Level: {summary.risk_level} (Score: {summary.risk_score})")
print(f"\nExecutive Summary:\n{summary.executive_summary}")
print(f"\nKey Findings:")
for i, finding in enumerate(summary.key_findings, 1):
    print(f"  {i}. {finding}")
print(f"\nRecommendations:")
for i, rec in enumerate(summary.recommendations, 1):
    print(f"  {i}. {rec}")
print(f"\nConfidence: {summary.confidence:.0%}")
```

**Expected Output:**
```
✅ Title: Critical Web Vulnerabilities Detected on 192.168.1.100
✅ Risk Level: CRITICAL (Score: 9.2)
✅ Executive Summary: [2-3 sentence summary]
✅ Key Findings: [3-5 bullet points]
✅ Recommendations: [3-5 action items]
```

### Solution 2: Regenerate Summaries for Existing Scans

```python
# Get scan ID from database
from services.ingestor import ScanIngestor
ingestor = ScanIngestor()

# List recent scans
scans = ingestor.list_scans(limit=10)
for scan in scans:
    print(f"Scan: {scan.scan_id} | Tool: {scan.tool_name} | Status: {scan.status.value}")

# Pick a scan ID and regenerate summary via API
scan_id = "scan_xyz123"  # Replace with actual ID

# Use curl or Python to call regeneration endpoint
import requests
response = requests.post(
    f"http://localhost:8000/api/scans/{scan_id}/regenerate-summary"
)
print(response.json())
```

### Solution 3: Fix Ollama Health Check (Code Fix)

The current health check is too aggressive. Let's make it more robust:

**File**: `backend/api_gateway/scan_routes.py`

**Find** (around line 55):
```python
def check_ollama_health(timeout: int = 5) -> Dict[str, Any]:
    """Check if Ollama is available"""
    try:
        response = requests.get(
            "http://localhost:11434/api/tags",
            timeout=timeout
        )
        return {
            'available': response.status_code == 200,
            'status_code': response.status_code,
            'error': None
        }
    except requests.exceptions.RequestException as e:
        return {
            'available': False,
            'status_code': None,
            'error': str(e)
        }
```

**Replace with**:
```python
def check_ollama_health(timeout: int = 10) -> Dict[str, Any]:  # Increased timeout
    """Check if Ollama is available"""
    try:
        response = requests.get(
            "http://localhost:11434/api/tags",
            timeout=timeout
        )
        
        # Also verify the required model is present
        if response.status_code == 200:
            models = response.json().get('models', [])
            model_names = [m['name'] for m in models]
            required_model = "llama3.2:3b-instruct-q4_K_M"
            
            has_model = required_model in model_names
            
            return {
                'available': has_model,
                'status_code': response.status_code,
                'has_model': has_model,
                'error': None if has_model else f"Model {required_model} not found"
            }
        
        return {
            'available': False,
            'status_code': response.status_code,
            'has_model': False,
            'error': f'Ollama returned status {response.status_code}'
        }
    except requests.exceptions.RequestException as e:
        logger.warning(f"Ollama health check failed: {e}")
        return {
            'available': False,
            'status_code': None,
            'has_model': False,
            'error': str(e)
        }
```

### Solution 4: Enable Auto-Retry on Failure

**File**: `backend/api_gateway/scan_routes.py`

**Find** (around line 680):
```python
if not ollama_health['available']:
    logger.warning(f"Ollama unavailable for scan {scan_id}: {ollama_health['error']}")
    
    error_summary = {
        'status': 'failed',
        'error': 'Ollama AI service is currently unavailable',
        # ...
    }
```

**Replace with**:
```python
if not ollama_health['available']:
    logger.warning(f"Ollama unavailable for scan {scan_id}: {ollama_health['error']}")
    
    # RETRY LOGIC: Wait 2 seconds and try again (Ollama might be warming up)
    import time
    time.sleep(2)
    
    ollama_health_retry = check_ollama_health(timeout=10)
    
    if not ollama_health_retry['available']:
        error_summary = {
            'status': 'failed',
            'error': 'Ollama AI service is currently unavailable (retried)',
            'error_details': ollama_health_retry['error'],
            'can_retry': True,
            'timestamp': datetime.now().isoformat(),
            'ollama_status': ollama_health_retry
        }
        
        try:
            ingestor.update_ai_summary(scan_id, error_summary)
        except Exception as cache_err:
            logger.warning(f"Failed to cache error state: {cache_err}")
        
        # Return error in response
        response['ai_summary'] = error_summary
        response['ai_summary_text'] = None
    else:
        # Retry succeeded, continue with generation
        logger.info("Ollama available on retry, generating AI summary...")
        # ... proceed with normal generation ...
```

---

## 🌐 ISSUE 2: MCP Web Access Integration

### What is MCP?

**Model Context Protocol (MCP)** = Secure proxy layer that gives your LLM real-time web access while preventing:
- ❌ SSRF (Server-Side Request Forgery)
- ❌ Data leaks
- ❌ Malicious URL injection
- ❌ Rate limit abuse

### Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    Your Chat Query                        │
│  "What's the latest info on CVE-2024-1234?"              │
└────────────────────┬─────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────┐
│                  Intelligence Layer                       │
│  - Detects web lookup needed (CVE, threat intel)         │
│  - Validates query is safe                               │
└────────────────────┬─────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────┐
│                   MCP Web Proxy                          │
│  - Whitelisted domains only (nvd.nist.gov, etc.)        │
│  - Rate limiting (max 10 req/min)                        │
│  - SSRF protection (no internal IPs)                     │
│  - Response sanitization                                 │
└────────────────────┬─────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────┐
│                  External APIs                           │
│  ✅ NVD API (nvd.nist.gov)                              │
│  ✅ ExploitDB (exploit-db.com)                          │
│  ✅ CISA KEV (cisa.gov/known-exploited-vulnerabilities) │
│  ✅ GitHub Security Advisories                          │
│  ❌ Random user URLs (blocked)                          │
└──────────────────────────────────────────────────────────┘
```

### Implementation

#### Step 1: Create MCP Web Proxy Service

**File**: `backend/services/mcp_web_proxy.py`

```python
"""
MCP Web Proxy Service
Secure proxy for LLM web access with SSRF protection and rate limiting.
"""

import requests
import logging
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
from datetime import datetime, timedelta
from collections import defaultdict
import json

logger = logging.getLogger(__name__)


class MCPWebProxy:
    """
    Secure web proxy for LLM with safeguards:
    - Whitelisted domains only
    - Rate limiting per domain
    - SSRF protection (no private IPs)
    - Response size limits
    - Timeout enforcement
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
        'nvd.nist.gov',           # NVD
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
        '172.16.',   # Private Class B
        '172.17.',
        '172.18.',
        '172.19.',
        '172.20.',
        '172.21.',
        '172.22.',
        '172.23.',
        '172.24.',
        '172.25.',
        '172.26.',
        '172.27.',
        '172.28.',
        '172.29.',
        '172.30.',
        '172.31.',
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
        
        logger.info("MCP Web Proxy initialized")
    
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
        """Check if request is within rate limit"""
        now = datetime.now()
        one_minute_ago = now - timedelta(minutes=1)
        
        # Clean old requests
        self.request_history[domain] = [
            ts for ts in self.request_history[domain]
            if ts > one_minute_ago
        ]
        
        # Check if under limit
        return len(self.request_history[domain]) < self.max_requests_per_minute
    
    def _record_request(self, domain: str):
        """Record request timestamp for rate limiting"""
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
                return {
                    'success': True,
                    'cve_id': cve_id,
                    'published': cve.get('published'),
                    'last_modified': cve.get('lastModified'),
                    'description': cve.get('descriptions', [{}])[0].get('value'),
                    'cvss_v3': cve.get('metrics', {}).get('cvssMetricV3', [{}])[0].get('cvssData', {}),
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
```

#### Step 2: Integrate MCP into RAG Chatbot

**File**: `backend/intelligence_layer/rag/chatbot.py`

Add after line 40 (in `RAGChatbot.__init__`):

```python
# Initialize MCP web proxy
try:
    from services.mcp_web_proxy import get_mcp_proxy
    self.mcp_proxy = get_mcp_proxy()
    self.mcp_enabled = True
    logger.info("✅ MCP web proxy enabled")
except ImportError:
    self.mcp_proxy = None
    self.mcp_enabled = False
    logger.warning("⚠️  MCP web proxy not available")
```

Add new method (after `chat()` method, around line 250):

```python
def _enhance_context_with_web(self, query: str, context: str) -> str:
    """
    Enhance context with real-time web lookups if query mentions CVEs.
    
    Args:
        query: User query
        context: Existing RAG context
    
    Returns:
        Enhanced context with web data
    """
    if not self.mcp_enabled:
        return context
    
    # Detect CVE mentions in query
    import re
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    cves = re.findall(cve_pattern, query, re.IGNORECASE)
    
    if not cves:
        return context
    
    logger.info(f"📡 Web lookup triggered for CVEs: {cves}")
    
    web_data = []
    for cve_id in cves[:3]:  # Limit to 3 CVEs to avoid slowdown
        result = self.mcp_proxy.fetch_cve_details(cve_id)
        if result['success']:
            web_data.append(f"""
**Real-Time NVD Data for {cve_id}:**
- Published: {result.get('published', 'N/A')}
- CVSS Score: {result.get('cvss_v3', {}).get('baseScore', 'N/A')}
- Severity: {result.get('cvss_v3', {}).get('baseSeverity', 'N/A')}
- Description: {result.get('description', 'N/A')[:200]}...
""")
    
    if web_data:
        enhanced = f"{context}\n\n## Real-Time Web Data\n" + "\n".join(web_data)
        return enhanced
    
    return context
```

**Modify `chat()` method** (around line 80):

```python
def chat(
    self,
    user_message: str,
    conversation_history: Optional[List[Dict]] = None,
    use_rag: bool = True
) -> Dict:
    # ... existing code ...
    
    # Get RAG context
    if use_rag:
        rag_context = self._get_relevant_context(user_message)
        
        # ✨ NEW: Enhance with web data if needed
        rag_context = self._enhance_context_with_web(user_message, rag_context)
    else:
        rag_context = ""
    
    # ... rest of method ...
```

#### Step 3: Add MCP Status Endpoint

**File**: `backend/api_gateway/intelligence_routes.py`

Add new route:

```python
@intelligence_ns.route('/mcp-status')
class MCPStatus(Resource):
    """MCP web proxy status"""
    
    @intelligence_ns.doc('get_mcp_status')
    def get(self):
        """Get MCP proxy status and allowed domains"""
        try:
            from services.mcp_web_proxy import get_mcp_proxy
            proxy = get_mcp_proxy()
            
            return {
                'enabled': True,
                'allowed_domains': list(proxy.ALLOWED_DOMAINS),
                'rate_limit': proxy.max_requests_per_minute,
                'max_response_size': proxy.max_response_size,
                'timeout': proxy.timeout
            }, 200
        except ImportError:
            return {
                'enabled': False,
                'error': 'MCP proxy not installed'
            }, 503
```

#### Step 4: Test MCP Integration

```python
# Test script
from services.mcp_web_proxy import get_mcp_proxy

proxy = get_mcp_proxy()

# Test 1: Fetch CVE from NVD
print("Test 1: Fetch CVE-2024-1234 from NVD")
result = proxy.fetch_cve_details("CVE-2024-1234")
print(f"Success: {result['success']}")
if result['success']:
    print(f"Description: {result['description'][:100]}...")
    print(f"CVSS: {result['cvss_v3'].get('baseScore')}")

# Test 2: Try blocked domain
print("\nTest 2: Try blocked domain (should fail)")
result = proxy.fetch("http://malicious.com/api")
print(f"Success: {result['success']}")
print(f"Error: {result['error']}")

# Test 3: Try private IP (SSRF protection)
print("\nTest 3: Try private IP (should fail)")
result = proxy.fetch("http://192.168.1.1/admin")
print(f"Success: {result['success']}")
print(f"Error: {result['error']}")

# Test 4: Rate limiting
print("\nTest 4: Rate limiting (11 requests in 1 minute)")
for i in range(11):
    result = proxy.fetch("https://nvd.nist.gov/")
    print(f"Request {i+1}: {result['success']} (Status: {result.get('status_code')})")
    if not result['success']:
        print(f"  Error: {result['error']}")
```

### Usage Examples

**Example 1: Chat with Web Lookup**

```python
from intelligence_layer.rag.chatbot import RAGChatbot

chatbot = RAGChatbot()

response = chatbot.chat(
    user_message="What's the latest information on CVE-2024-1234?",
    use_rag=True  # Enables RAG + MCP web lookup
)

print(response['response'])
# Output will include:
# - Local RAG context from your scans
# - Real-time NVD data from web
# - LLM-generated answer combining both
```

**Example 2: Compare Local vs Web Data**

```python
# Query CVE that exists in local database
response = chatbot.chat(
    "Compare my scan data for CVE-2024-1234 with the latest NVD info"
)

# LLM will:
# 1. Retrieve local scan results from ChromaDB
# 2. Fetch latest NVD data via MCP
# 3. Compare and highlight differences
# 4. Recommend actions if NVD has updates
```

**Example 3: Threat Intel Enrichment**

```python
# Ask about exploitability
response = chatbot.chat(
    "Are there public exploits for CVE-2024-1234?"
)

# LLM will:
# 1. Check local ExploitDB feed
# 2. Query NVD via MCP for references
# 3. Provide comprehensive answer
```

---

## 📋 Implementation Checklist

### Phase 1: Fix AI Summaries (1-2 hours)

- [ ] Test AI summary manually (Solution 1)
- [ ] Regenerate summaries for existing scans (Solution 2)
- [ ] Apply Ollama health check fix (Solution 3)
- [ ] Add auto-retry logic (Solution 4)
- [ ] Verify summaries appear in frontend

### Phase 2: Implement MCP (4-6 hours)

- [ ] Create `mcp_web_proxy.py` service (Step 1)
- [ ] Integrate MCP into chatbot (Step 2)
- [ ] Add MCP status endpoint (Step 3)
- [ ] Test MCP with test script (Step 4)
- [ ] Update frontend to show "🌐 Web-enhanced" badge when MCP is used

### Phase 3: Testing (1-2 hours)

- [ ] Test CVE lookup via chat: "What's CVE-2024-1234?"
- [ ] Test SSRF protection: Try accessing localhost
- [ ] Test rate limiting: Make 15 requests in 1 minute
- [ ] Test blocked domains: Try non-whitelisted site
- [ ] Performance test: Measure response time with/without MCP

---

## 🎯 Expected Results

### Before MCP

```
User: "What's the latest info on CVE-2024-1234?"

Bot: "I don't have real-time data. Based on my local knowledge:
      - CVE-2024-1234 is a critical RCE vulnerability
      - CVSS score: 9.8
      - Affects: Apache HTTP Server 2.4.49
      
      ⚠️  This data may be outdated."
```

### After MCP

```
User: "What's the latest info on CVE-2024-1234?"

Bot: "🌐 Real-time data from NVD (updated 2 hours ago):
      
      **CVE-2024-1234 Details:**
      - Published: 2024-10-15
      - Last Modified: 2025-11-03 08:30:00
      - CVSS Score: 9.8 (CRITICAL)
      - Attack Vector: Network
      - Privileges Required: None
      
      **Description:**
      A path traversal vulnerability in Apache HTTP Server 2.4.49
      and 2.4.50 allows remote code execution...
      
      **References:**
      - Official patch: https://httpd.apache.org/security/...
      - CISA advisory: https://cisa.gov/...
      
      **Your Environment:**
      ✅ I found this CVE in 3 of your recent scans:
         - Scan #12: 192.168.1.100 (Apache 2.4.49)
         - Scan #15: 192.168.1.150 (Apache 2.4.50)
         - Scan #18: 10.0.0.50 (Apache 2.4.49)
      
      **Recommendation:**
      URGENT: All 3 systems are vulnerable. Upgrade to Apache 2.4.51+
      immediately. Exploits are publicly available."
```

---

## 🔧 Troubleshooting

### AI Summaries Still Not Generating?

1. **Check Ollama**:
   ```bash
   cd backend
   python check_ollama.py
   ```

2. **Check scan has vulnerabilities**:
   ```python
   from services.ingestor import ScanIngestor
   ingestor = ScanIngestor()
   vulns = ingestor.get_vulnerabilities("scan_id")
   print(f"Vulnerabilities: {len(vulns)}")
   ```

3. **Check logs**:
   ```bash
   tail -f backend/logs/app.log | grep -i "ai summary"
   ```

### MCP Not Working?

1. **Check whitelisted domains**:
   ```python
   from services.mcp_web_proxy import get_mcp_proxy
   proxy = get_mcp_proxy()
   print(proxy.ALLOWED_DOMAINS)
   ```

2. **Test direct fetch**:
   ```python
   result = proxy.fetch("https://nvd.nist.gov/")
   print(result)
   ```

3. **Check rate limits**:
   ```python
   domain = "nvd.nist.gov"
   print(f"Requests: {len(proxy.request_history[domain])}")
   ```

---

## 🚀 Next Steps

1. **Implement steps above** (6-10 hours total)
2. **Test thoroughly** with real CVE queries
3. **Monitor performance** (MCP adds ~500ms latency per web call)
4. **Expand whitelisted domains** as needed
5. **Add caching** to reduce duplicate web calls

**Need help?** Run the test scripts and share the output!
