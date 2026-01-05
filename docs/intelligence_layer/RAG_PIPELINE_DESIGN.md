# RAG Pipeline Architecture for Vulnerability Chatbot

## Overview

This document defines the **Retrieval-Augmented Generation (RAG) Pipeline** for the Intelligence Layer's chatbot component. The pipeline enables natural language queries about vulnerabilities, attack paths, and remediation guidance by combining semantic search over scan data with local LLM-powered response generation.

---

## High-Level Pipeline Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                         USER INTERACTION                              │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 1: Query Preprocessing                                          │
│  ─────────────────────────────                                        │
│  • Parse user query                                                   │
│  • Extract entities (CVE IDs, IP addresses, tool names)               │
│  • Detect query intent (vulnerability lookup, remediation,            │
│    attack path, general info)                                         │
│  • Query expansion (add synonyms: "exploit" → "vulnerability",        │
│    "fix" → "remediation")                                             │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 2: Embedding Generation                                         │
│  ──────────────────────────────                                       │
│  • Convert preprocessed query to vector embedding                     │
│  • Model: sentence-transformers/all-MiniLM-L6-v2 (lightweight)        │
│  • Output: 384-dimensional dense vector                               │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 3: Retrieval (Semantic Search)                                  │
│  ─────────────────────────────────                                    │
│  • Vector similarity search in indexed data:                          │
│    - Scan results (vulnerabilities, hosts, ports)                     │
│    - Threat intelligence (NVD, ExploitDB descriptions)                │
│    - Attack path annotations                                          │
│  • Ranking: Cosine similarity (top-k=5 by default)                    │
│  • Metadata filtering: tool name, severity, date range                │
│  • Output: List of relevant documents with scores                     │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 4: Context Assembly                                             │
│  ───────────────────────                                              │
│  • Rerank retrieved documents (optional: cross-encoder model)         │
│  • Format context:                                                    │
│    [Document 1]                                                       │
│    Source: Nmap scan (2024-01-15)                                     │
│    Host: 192.168.1.50                                                 │
│    Vulnerability: CVE-2023-12345 (CVSS 9.8)                           │
│    Description: Remote code execution in Apache 2.4.x...              │
│    ...                                                                │
│  • Truncate to fit LLM context window (Llama 3.2: 128K tokens)        │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 5: Prompt Augmentation                                          │
│  ──────────────────────────                                           │
│  • Build prompt template:                                             │
│                                                                       │
│    SYSTEM ROLE:                                                       │
│    You are a cybersecurity analyst assistant. Use ONLY the            │
│    provided vulnerability scan data to answer questions.              │
│    If information is not in the context, say "I don't have            │
│    data on that." Always cite sources (CVE IDs, tool names).          │
│                                                                       │
│    CONTEXT:                                                           │
│    {retrieved_documents}                                              │
│                                                                       │
│    CONVERSATION HISTORY:                                              │
│    {previous_turns}                                                   │
│                                                                       │
│    USER QUERY:                                                        │
│    {user_question}                                                    │
│                                                                       │
│    INSTRUCTIONS:                                                      │
│    - Prioritize critical vulnerabilities (CVSS ≥7.0)                  │
│    - Include remediation steps if available                           │
│    - Format response as: Summary → Details → Recommendations          │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 6: LLM Generation                                               │
│  ────────────────────                                                 │
│  • Send augmented prompt to local LLM:                                │
│    Model: Llama 3.2 3B Instruct (via Ollama)                          │
│    Endpoint: http://localhost:11434/v1/chat/completions               │
│    Temperature: 0.3 (low for factual accuracy)                        │
│    Max tokens: 512 (concise analyst-facing responses)                 │
│  • Streaming: Enable for real-time UI updates                         │
│  • Output: Generated text response                                    │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 7: Post-Processing                                              │
│  ──────────────────────                                               │
│  • Extract citations (CVE IDs, URLs) and format as clickable links    │
│  • Add confidence score (based on retrieval scores)                   │
│  • Filter hallucinations: Verify all CVE IDs exist in context         │
│  • Format markdown: **bold** for CVEs, `code` for commands            │
│  • Append "Sources Used" footer with document references              │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 8: Response Delivery                                            │
│  ────────────────────────                                             │
│  • Return JSON to frontend:                                           │
│    {                                                                  │
│      "response": "Formatted LLM response...",                         │
│      "sources": [                                                     │
│        {"cve": "CVE-2023-12345", "url": "https://nvd.nist.gov/..."}  │
│      ],                                                               │
│      "confidence": 0.92,                                              │
│      "conversation_id": "uuid-1234"                                   │
│    }                                                                  │
│  • Store conversation in session for multi-turn dialogue              │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Component Details

### 1. Query Preprocessing Module

**Purpose:** Normalize and enrich user queries before embedding.

**Operations:**
- **Entity Extraction:** Regex/NER to identify CVE-2023-XXXXX, IP addresses (192.168.x.x), port numbers (e.g., 22, 443)
- **Intent Classification:** 
  - `vulnerability_lookup`: "Tell me about CVE-2023-12345"
  - `remediation`: "How do I fix this SQL injection?"
  - `attack_path`: "Show me exploitation routes for host X"
  - `general_info`: "What is a buffer overflow?"
- **Query Expansion:** Add technical synonyms (e.g., "RCE" → "Remote Code Execution")

**Tech Stack:**
- spaCy for NER (named entity recognition)
- Regex for CVE/IP extraction

---

### 2. Embedding Model

**Selected Model:** `sentence-transformers/all-MiniLM-L6-v2`

**Rationale:**
- **Lightweight:** 22M parameters, <100MB disk space
- **Fast:** ~0.01 sec per query on CPU
- **Quality:** Decent semantic understanding for technical text
- **Domain:** Pre-trained on general text, fine-tunable on vulnerability descriptions

**Alternative (Higher Quality):** `sentence-transformers/all-mpnet-base-v2` (109M params, slower but better accuracy)

**Usage:**
```python
from sentence_transformers import SentenceTransformer

embedder = SentenceTransformer('all-MiniLM-L6-v2')
query_embedding = embedder.encode("What vulnerabilities affect port 22?")
# Output: numpy array, shape (384,)
```

---

### 3. Vector Database for Retrieval

**Selected Solution:** **ChromaDB** (Recommended for PoC/College Project)

**Rationale:**
| Feature | ChromaDB | FAISS | Pinecone (Cloud) |
|---------|----------|-------|------------------|
| **Setup Complexity** | ✅ Minimal (pip install) | ⚠️ Moderate | ❌ Requires API key |
| **Metadata Filtering** | ✅ Native SQL-like queries | ⚠️ Manual post-processing | ✅ Native |
| **Persistence** | ✅ Embedded DB (SQLite) | ⚠️ Manual save/load | ✅ Cloud-hosted |
| **Cost** | ✅ Free | ✅ Free | ❌ Paid ($70/mo+) |
| **Local-First** | ✅ Yes | ✅ Yes | ❌ Cloud-only |
| **Scalability** | ⚠️ Good (<1M docs) | ✅ Excellent (billions) | ✅ Excellent |

**Winner for College Project:** ChromaDB (easiest setup, good metadata filtering, free).

**Fallback for Production:** FAISS (if >100K vulnerabilities need indexing).

**Example ChromaDB Usage:**
```python
import chromadb

# Initialize client
client = chromadb.PersistentClient(path="./chroma_db")

# Create collection
collection = client.get_or_create_collection(
    name="vulnerability_scans",
    metadata={"description": "Indexed scan results and threat intel"}
)

# Add documents
collection.add(
    documents=["CVE-2023-12345: Remote code execution in Apache 2.4.x..."],
    metadatas=[{"cve": "CVE-2023-12345", "tool": "Nmap", "severity": "critical"}],
    ids=["vuln_001"]
)

# Query
results = collection.query(
    query_embeddings=[query_embedding],
    n_results=5,
    where={"severity": "critical"}  # Metadata filter
)
```

---

### 4. Context Assembly Strategy

**Challenge:** LLM context windows are limited (Llama 3.2: 128K tokens ≈ 90K words).

**Strategy:**
1. **Retrieve Top-K Documents:** Start with k=10 from vector search
2. **Rerank (Optional):** Use cross-encoder model (`cross-encoder/ms-marco-MiniLM-L-6-v2`) to reorder by relevance
3. **Truncate:** Keep top 5 after reranking
4. **Format:** Structure as markdown for LLM readability:
   ```
   ## Document 1: Nmap Scan (192.168.1.50)
   - **CVE:** CVE-2023-12345
   - **Severity:** Critical (CVSS 9.8)
   - **Description:** RCE in Apache HTTP Server...
   - **Remediation:** Upgrade to Apache 2.4.59+
   ```

---

### 5. Prompt Engineering Best Practices

**System Prompt Template:**
```
You are a cybersecurity analyst assistant for the NTRO vulnerability detection platform.

CAPABILITIES:
- Answer questions about vulnerabilities found in scans
- Explain attack paths and exploitation techniques
- Provide remediation guidance with authoritative sources

CONSTRAINTS:
- ONLY use information from the provided scan data (CONTEXT section below)
- If information is unavailable, respond: "I don't have data on that in the current scans."
- Always cite sources: CVE IDs, tool names, scan dates
- Prioritize critical/high severity findings (CVSS ≥7.0)

OUTPUT FORMAT:
1. **Summary:** 1-2 sentence answer
2. **Details:** Specific vulnerability data
3. **Remediation:** Actionable steps (if available)
4. **Sources:** List CVE IDs and reference URLs

CONTEXT:
{retrieved_documents}

CONVERSATION HISTORY:
{previous_turns}

USER QUERY:
{user_question}
```

**Why This Works:**
- **Role Definition:** Sets expectation for technical, analyst-facing tone
- **Constraints:** Prevents hallucination (LLM can't invent CVE data)
- **Structure:** Ensures consistent, actionable responses

---

### 6. LLM Integration (Ollama + Llama 3.2)

**API Call Example:**
```python
import requests

def query_llm(prompt: str, model: str = "llama3.2:3b-instruct-q4_K_M"):
    response = requests.post(
        "http://localhost:11434/v1/chat/completions",
        json={
            "model": model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3,  # Low for factual accuracy
            "max_tokens": 512,
            "stream": False  # Set True for streaming
        }
    )
    return response.json()["choices"][0]["message"]["content"]
```

**Parameters Explained:**
- `temperature=0.3`: Reduces randomness (0=deterministic, 1=creative)
- `max_tokens=512`: Limits response length (prevents rambling)
- `stream=False`: Return full response at once (set `True` for real-time UI updates)

---

### 7. Post-Processing & Hallucination Detection

**Verification Steps:**
1. **CVE Validation:** Extract all CVE-XXXX-XXXXX patterns from response, verify they exist in retrieved context
2. **IP Validation:** Ensure mentioned IP addresses match scanned hosts
3. **Confidence Scoring:**
   ```python
   confidence = min(retrieval_scores) * 0.5 + (1 - hallucination_rate) * 0.5
   # retrieval_scores: Vector similarity scores from ChromaDB
   # hallucination_rate: % of CVEs in response not in context
   ```
4. **Citation Formatting:** Convert plain CVE IDs to clickable links:
   ```
   CVE-2023-12345 → [CVE-2023-12345](https://nvd.nist.gov/vuln/detail/CVE-2023-12345)
   ```

---

## Data Flow Example: End-to-End Query

**User Query:** "What are the critical vulnerabilities on host 192.168.1.50?"

**Step-by-Step:**
1. **Preprocessing:** Extract IP `192.168.1.50`, intent = `vulnerability_lookup`, filter = `critical`
2. **Embedding:** Convert to vector [0.12, -0.34, ...]
3. **Retrieval:** ChromaDB query with metadata filter `{"host": "192.168.1.50", "severity": "critical"}` → Returns 3 documents:
   - Nmap scan: SSH on port 22, CVE-2023-11111 (CVSS 9.8)
   - OpenVAS: Outdated kernel, CVE-2023-22222 (CVSS 8.5)
   - Nikto: SQL injection in web app, CVE-2023-33333 (CVSS 9.2)
4. **Context Assembly:**
   ```
   ## Scan 1: Nmap (2024-01-15)
   - Host: 192.168.1.50
   - Port 22: SSH, CVE-2023-11111 (RCE via auth bypass)
   ...
   ```
5. **Prompt:** System prompt + context + user query
6. **LLM Response:**
   ```
   **Summary:** Host 192.168.1.50 has 3 critical vulnerabilities (CVSS ≥8.5).

   **Details:**
   - CVE-2023-11111 (Port 22/SSH): Remote code execution via authentication bypass
   - CVE-2023-22222 (Kernel): Privilege escalation in Linux kernel 5.x
   - CVE-2023-33333 (Web App): SQL injection in login form

   **Remediation:**
   - Update SSH to version 9.0+ (CVE-2023-11111)
   - Apply kernel patch 5.15.89+ (CVE-2023-22222)
   - Sanitize SQL inputs, use parameterized queries (CVE-2023-33333)

   **Sources:** [CVE-2023-11111](nvd link), [CVE-2023-22222](nvd link), ...
   ```
7. **Post-Processing:** Verify all CVE IDs exist in context ✓, add confidence score (0.94)
8. **Delivery:** Return JSON to frontend with formatted markdown

---

## Performance Metrics

| Metric | Target | Measurement Method |
|--------|--------|-------------------|
| **Query Latency** | <2 sec (end-to-end) | Time from API call to response |
| **Retrieval Precision@5** | >80% | % of top-5 results relevant to query |
| **Response Factuality** | >90% | % of claims verifiable in context |
| **Hallucination Rate** | <5% | % of CVE IDs not in retrieved docs |

---

## Technology Stack Summary

| Component | Technology | Justification |
|-----------|------------|---------------|
| **Embedding Model** | sentence-transformers/all-MiniLM-L6-v2 | Fast, lightweight, good quality |
| **Vector Database** | ChromaDB | Easy setup, metadata filtering, free |
| **Local LLM** | Llama 3.2 3B (Ollama) | Best balance for college project |
| **NER/Entity Extraction** | spaCy + Regex | Mature, accurate |
| **API Framework** | FastAPI (Python) | Async support, auto-docs |

---

## Next Steps

1. **Implement data indexing pipeline** (see `DATA_INDEXING_SCHEMA.md`)
2. **Build PoC chatbot** (see `poc_local_llm.py`)
3. **Integrate with backend** (expose REST API for frontend)
4. **Evaluate on test queries** (measure latency, factuality)
