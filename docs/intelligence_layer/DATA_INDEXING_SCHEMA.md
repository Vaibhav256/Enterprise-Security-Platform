# Data Indexing Strategy for RAG Retrieval

## Overview

This document defines the **data indexing schema** for the Intelligence Layer's RAG pipeline. The indexing strategy determines what vulnerability scan data and threat intelligence is vectorized and stored in ChromaDB for efficient semantic retrieval.

---

## Indexed Data Sources

### 1. Vulnerability Scan Results (Primary Source)

**Origin:** Backend's normalized scan database (from Nmap, OpenVAS, Nikto, Nuclei running in WSL).

**Data Points to Index:**

| Field | Description | Example Value | Indexing Priority |
|-------|-------------|---------------|-------------------|
| `vulnerability_id` | Unique identifier | `vuln_scan_12345` | High (for deduplication) |
| `cve_id` | CVE identifier | `CVE-2023-12345` | **Critical** (primary search key) |
| `host_ip` | Target IP address | `192.168.1.50` | **Critical** (filtering) |
| `port` | Affected port | `22` (SSH) | High |
| `service` | Running service | `OpenSSH 7.4` | High |
| `tool_name` | Scanning tool | `Nmap`, `OpenVAS` | Medium (provenance) |
| `scan_date` | Timestamp | `2024-01-15T14:30:00Z` | Medium (temporal filtering) |
| `severity` | CVSS category | `critical`, `high`, `medium`, `low` | **Critical** (prioritization) |
| `cvss_score` | Numeric score | `9.8` | High |
| `description` | Vulnerability summary | "Remote code execution via auth bypass in SSH..." | **Critical** (semantic search) |
| `remediation` | Fix guidance | "Upgrade to OpenSSH 9.0+" | **Critical** (actionable advice) |
| `exploit_available` | Known exploit exists | `true`/`false` | High (risk assessment) |
| `references` | External URLs | `["https://nvd.nist.gov/...", "https://exploitdb.com/..."]` | Medium |

**Composite Document Format (What Gets Vectorized):**
```text
CVE-2023-12345: Remote Code Execution in OpenSSH 7.4 (Port 22)
Severity: Critical (CVSS 9.8)
Host: 192.168.1.50
Tool: Nmap (Scanned 2024-01-15)
Description: An authentication bypass vulnerability in OpenSSH versions 7.x allows remote attackers to execute arbitrary code without credentials via a crafted SSH handshake.
Remediation: Upgrade to OpenSSH 9.0 or later. Apply security patches from vendor advisories.
Exploit: Public exploit available (ExploitDB-2024-001)
References: https://nvd.nist.gov/vuln/detail/CVE-2023-12345
```

**Why This Format?**
- **Natural Language:** Embeds well with sentence transformers (captures semantic meaning)
- **Structured:** Maintains key-value pairs for easy parsing in LLM responses
- **Complete:** All info needed to answer queries without re-fetching from DB

---

### 2. Threat Intelligence Feeds (Secondary Source)

**Origin:** External APIs (NVD, ExploitDB, Rapid7).

**Data Points to Index:**

| Field | Description | Example Value | Indexing Priority |
|-------|-------------|---------------|-------------------|
| `cve_id` | CVE identifier | `CVE-2023-12345` | **Critical** |
| `cwe_id` | Weakness type | `CWE-287` (Improper Authentication) | Medium |
| `description` | Detailed explanation | "The SSH daemon in OpenSSH 7.x contains a logic error..." | **Critical** |
| `cvss_vector` | Scoring details | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | Medium |
| `published_date` | CVE disclosure date | `2023-05-20` | Medium |
| `last_modified` | Latest update | `2024-01-10` | Low |
| `exploit_maturity` | Exploitation status | `Proof-of-Concept`, `Functional`, `High` | High |
| `affected_products` | Vendor/product list | `["OpenSSH 7.0-7.9"]` | High |
| `remediation_official` | Vendor fix | "Apply patch from OpenBSD advisory 2023-05" | **Critical** |

**Composite Document Format:**
```text
CVE-2023-12345: OpenSSH Authentication Bypass (CWE-287)
Published: 2023-05-20 | CVSS: 9.8 (Critical)
Affected Products: OpenSSH 7.0 through 7.9
Description: A logic error in the SSH daemon's authentication module allows remote attackers to bypass authentication checks by sending a specially crafted SSH_MSG_USERAUTH_REQUEST packet during the handshake phase, leading to unauthorized remote code execution.
Exploit Status: Functional exploit publicly available (Metasploit module ssh_auth_bypass)
Remediation: Upgrade to OpenSSH 9.0+. OpenBSD advisory 2023-05 provides patches for legacy versions.
References: https://nvd.nist.gov/vuln/detail/CVE-2023-12345, https://www.exploitdb.com/exploits/50001
```

---

### 3. Attack Path Annotations (Tertiary Source)

**Origin:** Attack path modeling engine (generated from graph analysis).

**Data Points to Index:**

| Field | Description | Example Value | Indexing Priority |
|-------|-------------|---------------|-------------------|
| `path_id` | Unique identifier | `attack_path_456` | High |
| `source_host` | Initial compromise | `192.168.1.100` (DMZ web server) | High |
| `target_host` | Final objective | `192.168.10.50` (Database server) | High |
| `path_description` | Attack narrative | "Attacker exploits CVE-2023-11111 on web server, pivots via weak SSH creds to internal network..." | **Critical** |
| `vulnerabilities_chained` | CVEs in sequence | `["CVE-2023-11111", "CVE-2023-22222"]` | **Critical** |
| `attack_complexity` | Ease of exploitation | `Low`, `Medium`, `High` | Medium |
| `mitigation_priority` | Recommended action order | "1. Patch web server (CVE-2023-11111), 2. Enforce SSH key auth" | **Critical** |

**Composite Document Format:**
```text
Attack Path: Web Server (192.168.1.100) → Internal Database (192.168.10.50)
Complexity: Low | Vulnerabilities: 2 chained
Step 1: Exploit CVE-2023-11111 (SQL injection) on web server to gain shell access
Step 2: Pivot via weak SSH credentials (CVE-2023-22222) to internal network
Step 3: Access database server with elevated privileges
Impact: Full database compromise, potential data exfiltration
Mitigation Priority:
1. Patch web server SQL injection (CVE-2023-11111) - CRITICAL
2. Enforce SSH public key authentication, disable password auth
3. Segment internal network (VLAN isolation)
```

---

## Vector Database Schema (ChromaDB Collections)

### Collection 1: `vulnerability_scans`

**Purpose:** Store all vulnerability findings from scanning tools.

**Metadata Fields (for filtering):**
```python
{
    "cve_id": "CVE-2023-12345",
    "host_ip": "192.168.1.50",
    "port": 22,
    "tool_name": "Nmap",
    "severity": "critical",  # critical, high, medium, low
    "cvss_score": 9.8,
    "scan_date": "2024-01-15",
    "exploit_available": true
}
```

**Document Text (vectorized):**
```
Full composite text from "Composite Document Format" section above
```

**Index Configuration:**
```python
import chromadb

client = chromadb.PersistentClient(path="./chroma_db")

vuln_collection = client.get_or_create_collection(
    name="vulnerability_scans",
    metadata={"description": "Indexed vulnerability scan results"},
    embedding_function=chromadb.utils.embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name="sentence-transformers/all-MiniLM-L6-v2"
    )
)
```

---

### Collection 2: `threat_intelligence`

**Purpose:** Store enriched CVE data from external threat feeds.

**Metadata Fields:**
```python
{
    "cve_id": "CVE-2023-12345",
    "cwe_id": "CWE-287",
    "cvss_score": 9.8,
    "published_date": "2023-05-20",
    "exploit_maturity": "Functional",  # PoC, Functional, High
    "affected_products": ["OpenSSH 7.0-7.9"]
}
```

**Document Text:** Composite format from "Threat Intelligence Feeds" section.

---

### Collection 3: `attack_paths`

**Purpose:** Store generated attack path scenarios for chained vulnerabilities.

**Metadata Fields:**
```python
{
    "path_id": "attack_path_456",
    "source_host": "192.168.1.100",
    "target_host": "192.168.10.50",
    "vulnerabilities_chained": ["CVE-2023-11111", "CVE-2023-22222"],
    "attack_complexity": "Low",  # Low, Medium, High
    "num_steps": 3
}
```

**Document Text:** Composite format from "Attack Path Annotations" section.

---

## Indexing Pipeline Workflow

```
┌──────────────────────────────────────────────────────────────┐
│ PHASE 1: Data Extraction                                      │
│ ─────────────────────────                                     │
│ • Query backend database for new scan results                 │
│ • Fetch CVE details from NVD/ExploitDB APIs                   │
│ • Generate attack paths from graph analysis engine            │
└──────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│ PHASE 2: Document Assembly                                    │
│ ────────────────────────────                                  │
│ • Combine fields into natural language composite text         │
│ • Extract metadata for filtering                              │
│ • Assign unique document ID                                   │
└──────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│ PHASE 3: Embedding Generation                                 │
│ ──────────────────────────────                                │
│ • Load sentence-transformers model                            │
│ • Generate 384-dim vector for each document                   │
│ • Batch processing (100 docs at a time for efficiency)        │
└──────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│ PHASE 4: Storage in ChromaDB                                  │
│ ───────────────────────────                                   │
│ • Insert into appropriate collection:                          │
│   - vulnerability_scans                                        │
│   - threat_intelligence                                        │
│   - attack_paths                                               │
│ • Store metadata for filtering                                │
│ • Persist to disk (SQLite backend)                            │
└──────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│ PHASE 5: Index Maintenance                                    │
│ ────────────────────────                                      │
│ • Incremental updates: Add new scans without reindexing all   │
│ • Deduplication: Check if CVE already indexed (update if yes) │
│ • Pruning: Remove outdated entries (e.g., scans >6 months old)│
└──────────────────────────────────────────────────────────────┘
```

---

## Example Indexing Code

```python
from sentence_transformers import SentenceTransformer
import chromadb
from datetime import datetime

# Initialize components
embedder = SentenceTransformer('all-MiniLM-L6-v2')
client = chromadb.PersistentClient(path="./backend/chroma_db")
vuln_collection = client.get_or_create_collection("vulnerability_scans")

def index_vulnerability(vuln_data: dict):
    """
    Index a single vulnerability from scan results.
    
    Args:
        vuln_data: Dict with keys: cve_id, host_ip, port, description, etc.
    """
    # Assemble composite document
    document_text = f"""
CVE-{vuln_data['cve_id']}: {vuln_data['title']} (Port {vuln_data['port']})
Severity: {vuln_data['severity'].capitalize()} (CVSS {vuln_data['cvss_score']})
Host: {vuln_data['host_ip']}
Tool: {vuln_data['tool_name']} (Scanned {vuln_data['scan_date']})
Description: {vuln_data['description']}
Remediation: {vuln_data['remediation']}
Exploit: {'Public exploit available' if vuln_data['exploit_available'] else 'No known exploit'}
References: {', '.join(vuln_data['references'])}
    """.strip()
    
    # Prepare metadata
    metadata = {
        "cve_id": vuln_data['cve_id'],
        "host_ip": vuln_data['host_ip'],
        "port": vuln_data['port'],
        "tool_name": vuln_data['tool_name'],
        "severity": vuln_data['severity'],
        "cvss_score": vuln_data['cvss_score'],
        "scan_date": vuln_data['scan_date'],
        "exploit_available": vuln_data['exploit_available']
    }
    
    # Add to ChromaDB
    vuln_collection.add(
        documents=[document_text],
        metadatas=[metadata],
        ids=[f"vuln_{vuln_data['vulnerability_id']}"]
    )
    
    print(f"✓ Indexed {vuln_data['cve_id']} for {vuln_data['host_ip']}")

# Example usage
sample_vuln = {
    'vulnerability_id': 12345,
    'cve_id': 'CVE-2023-12345',
    'title': 'Remote Code Execution in OpenSSH 7.4',
    'host_ip': '192.168.1.50',
    'port': 22,
    'tool_name': 'Nmap',
    'scan_date': '2024-01-15',
    'severity': 'critical',
    'cvss_score': 9.8,
    'description': 'An authentication bypass vulnerability allows remote attackers to execute arbitrary code.',
    'remediation': 'Upgrade to OpenSSH 9.0 or later.',
    'exploit_available': True,
    'references': ['https://nvd.nist.gov/vuln/detail/CVE-2023-12345']
}

index_vulnerability(sample_vuln)
```

---

## Batch Indexing Strategy

For initial population of the vector database (indexing all historical scans):

```python
def batch_index_scans(scan_results: list, batch_size: int = 100):
    """
    Efficiently index large numbers of scan results.
    
    Args:
        scan_results: List of vulnerability dicts
        batch_size: Number of docs to process at once
    """
    for i in range(0, len(scan_results), batch_size):
        batch = scan_results[i:i+batch_size]
        
        documents = []
        metadatas = []
        ids = []
        
        for vuln in batch:
            # Assemble document (same as above)
            doc_text = f"CVE-{vuln['cve_id']}: {vuln['description']}..."
            documents.append(doc_text)
            
            # Metadata
            metadatas.append({
                "cve_id": vuln['cve_id'],
                "host_ip": vuln['host_ip'],
                # ... other fields
            })
            
            ids.append(f"vuln_{vuln['vulnerability_id']}")
        
        # Batch insert
        vuln_collection.add(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )
        
        print(f"✓ Indexed batch {i//batch_size + 1} ({len(batch)} vulnerabilities)")

# Usage
all_scans = fetch_all_scans_from_database()  # Your DB query function
batch_index_scans(all_scans, batch_size=100)
```

**Performance:** ~1000 documents/minute on modern CPU.

---

## Incremental Updates (Live Scanning)

When new scans complete, add them to the index without rebuilding:

```python
def on_scan_complete(scan_id: int):
    """
    Triggered by backend when a scan finishes.
    Indexes new vulnerabilities in real-time.
    """
    new_vulns = fetch_vulnerabilities_for_scan(scan_id)
    
    for vuln in new_vulns:
        # Check if already indexed (by CVE + host combination)
        existing = vuln_collection.get(
            where={"cve_id": vuln['cve_id'], "host_ip": vuln['host_ip']}
        )
        
        if existing['ids']:
            # Update existing entry
            vuln_collection.update(
                ids=[existing['ids'][0]],
                documents=[assemble_document(vuln)],
                metadatas=[extract_metadata(vuln)]
            )
            print(f"↻ Updated {vuln['cve_id']} for {vuln['host_ip']}")
        else:
            # New entry
            index_vulnerability(vuln)
```

---

## Query Example (How RAG Retrieves Data)

```python
def retrieve_context(user_query: str, filter_params: dict = None):
    """
    Retrieve relevant vulnerability documents for RAG.
    
    Args:
        user_query: Natural language question
        filter_params: Optional metadata filters (e.g., {"severity": "critical"})
    
    Returns:
        List of retrieved documents with metadata
    """
    # Embed query
    query_embedding = embedder.encode(user_query)
    
    # Search ChromaDB
    results = vuln_collection.query(
        query_embeddings=[query_embedding],
        n_results=5,  # Top-5 retrieval
        where=filter_params  # E.g., {"host_ip": "192.168.1.50"}
    )
    
    return [
        {
            "text": doc,
            "metadata": meta,
            "similarity_score": score
        }
        for doc, meta, score in zip(
            results['documents'][0],
            results['metadatas'][0],
            results['distances'][0]
        )
    ]

# Example
context_docs = retrieve_context(
    user_query="What are the critical SSH vulnerabilities?",
    filter_params={"severity": "critical", "port": 22}
)

for doc in context_docs:
    print(f"Score: {doc['similarity_score']:.3f}")
    print(f"CVE: {doc['metadata']['cve_id']}")
    print(f"Text: {doc['text'][:200]}...\n")
```

---

## Index Maintenance Schedule

| Task | Frequency | Purpose |
|------|-----------|---------|
| **Incremental Updates** | Real-time (on scan completion) | Add new vulnerabilities immediately |
| **Deduplication Check** | Daily | Remove duplicate CVE entries for same host |
| **Stale Data Pruning** | Weekly | Archive scans older than 6 months |
| **Full Reindex** | Monthly | Rebuild index with latest embedding model |
| **Backup** | Daily | Save ChromaDB to backup storage |

---

## Storage Estimates

**Assumptions:**
- Average vulnerability document: 500 tokens → ~2KB text + 384 floats embedding = ~3.5KB total
- 1000 vulnerabilities per scan
- 10 scans retained

**Calculation:**
- 10,000 vulnerabilities × 3.5KB = **35MB disk space**
- ChromaDB overhead (SQLite): ~10MB
- **Total: ~50MB** for typical college project scale

**Scaling:** For production (1M vulnerabilities): ~3.5GB (easily fits on modern servers).

---

## Technology Stack Summary

| Component | Technology | Justification |
|-----------|------------|---------------|
| **Vector Database** | ChromaDB | Easy setup, metadata filtering, embedded DB |
| **Embedding Model** | sentence-transformers/all-MiniLM-L6-v2 | Lightweight, fast, good quality |
| **Persistence** | SQLite (via ChromaDB) | No external DB required |
| **Update Mechanism** | Real-time (event-driven) | Immediate indexing on scan completion |

---

## Next Steps

1. **Implement indexing module** (see example code above)
2. **Integrate with backend database** (query scan results)
3. **Set up automated indexing trigger** (on scan completion event)
4. **Test retrieval quality** (measure precision@5 on sample queries)
5. **Populate initial index** (batch process historical scans)
