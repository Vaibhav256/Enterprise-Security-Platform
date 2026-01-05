# RAG Pipeline Visual Architecture

This document provides ASCII diagrams and visual representations of the Intelligence Layer's RAG pipeline architecture.

---

## High-Level System Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    NTRO VULNERABILITY DETECTION PLATFORM                  │
└──────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    │                               │
                    ▼                               ▼
        ┌─────────────────────┐         ┌─────────────────────┐
        │   SCANNING LAYER    │         │   FRONTEND (UI)     │
        │  (Nmap, OpenVAS,    │         │  - Chatbot Widget   │
        │   Nikto, Nuclei)    │         │  - Attack Graph Viz │
        └─────────────────────┘         └─────────────────────┘
                    │                               │
                    │ Scan Results                  │ User Queries
                    ▼                               ▼
        ┌───────────────────────────────────────────────────────┐
        │           INTELLIGENCE LAYER (Phase 2/3)              │
        │                                                       │
        │  ┌─────────────────────────────────────────────┐     │
        │  │        RAG CHATBOT (Phase 3)                │     │
        │  │  ┌──────────────┐  ┌──────────────┐        │     │
        │  │  │  ChromaDB    │  │ Ollama LLM   │        │     │
        │  │  │ (Vector DB)  │  │ Llama 3.2 3B │        │     │
        │  │  └──────────────┘  └──────────────┘        │     │
        │  └─────────────────────────────────────────────┘     │
        │                                                       │
        │  ┌─────────────────────────────────────────────┐     │
        │  │  ATTACK PATH ENGINE (Phase 2)               │     │
        │  │  ┌──────────────┐  ┌──────────────┐        │     │
        │  │  │  NetworkX    │  │ Path Finder  │        │     │
        │  │  │  (Graph DB)  │  │ (Algorithms) │        │     │
        │  │  └──────────────┘  └──────────────┘        │     │
        │  └─────────────────────────────────────────────┘     │
        └───────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
        ┌─────────────────────┐         ┌─────────────────────┐
        │  THREAT INTEL FEEDS │         │   BACKEND DATABASE  │
        │  (NVD, ExploitDB)   │         │  (Scan Results)     │
        └─────────────────────┘         └─────────────────────┘
```

---

## RAG Pipeline Detailed Flow

```
┌────────────────────────────────────────────────────────────────────────┐
│                          USER QUERY INPUT                               │
│  "What are the critical SSH vulnerabilities on host 192.168.1.50?"     │
└────────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────────────┐
│ STEP 1: PREPROCESSING                                                   │
│ ─────────────────────                                                   │
│ • Extract entities: IP="192.168.1.50", Service="SSH"                   │
│ • Detect intent: vulnerability_lookup                                   │
│ • Filter constraint: severity="critical"                                │
│ • Query expansion: "SSH" → ["SSH", "OpenSSH", "Secure Shell"]          │
└────────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────────────┐
│ STEP 2: EMBEDDING GENERATION                                            │
│ ─────────────────────────────                                           │
│ Model: sentence-transformers/all-MiniLM-L6-v2                          │
│ Input: "critical SSH vulnerabilities 192.168.1.50"                     │
│ Output: [0.12, -0.34, 0.56, ...] (384-dim vector)                      │
│ Latency: ~0.01 seconds                                                  │
└────────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────────────┐
│ STEP 3: SEMANTIC RETRIEVAL (ChromaDB)                                   │
│ ────────────────────────────────────                                    │
│ Collection: vulnerability_scans                                         │
│ Query: vector=[...], where={"host_ip": "192.168.1.50", "port": 22,     │
│                              "severity": "critical"}                    │
│ Top-K: 5 documents                                                       │
│ Ranking: Cosine similarity                                               │
│                                                                          │
│ Retrieved Documents:                                                     │
│ ┌──────────────────────────────────────────────────────────────┐       │
│ │ Doc 1 (score: 0.92)                                           │       │
│ │ CVE-2023-12345: OpenSSH Auth Bypass RCE (Port 22)            │       │
│ │ Severity: Critical (CVSS 9.8)                                 │       │
│ │ Host: 192.168.1.50                                            │       │
│ │ ...                                                           │       │
│ └──────────────────────────────────────────────────────────────┘       │
│ ┌──────────────────────────────────────────────────────────────┐       │
│ │ Doc 2 (score: 0.87)                                           │       │
│ │ CVE-2023-22222: SSH Key Mgmt Vuln (Port 22)                  │       │
│ │ ...                                                           │       │
│ └──────────────────────────────────────────────────────────────┘       │
└────────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────────────┐
│ STEP 4: CONTEXT ASSEMBLY                                                │
│ ─────────────────────────                                               │
│ • Rerank (optional): Cross-encoder model                                │
│ • Format for LLM readability:                                           │
│                                                                          │
│   ## Document 1: Nmap Scan (192.168.1.50)                              │
│   - **CVE:** CVE-2023-12345                                             │
│   - **Severity:** Critical (CVSS 9.8)                                   │
│   - **Description:** RCE in Apache HTTP Server...                       │
│   - **Remediation:** Upgrade to OpenSSH 9.0+                            │
│                                                                          │
│   ## Document 2: ...                                                    │
│                                                                          │
│ • Truncate to fit LLM context (128K tokens for Llama 3.2)               │
└────────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────────────┐
│ STEP 5: PROMPT AUGMENTATION                                             │
│ ────────────────────────────                                            │
│ SYSTEM ROLE:                                                             │
│ You are a cybersecurity analyst assistant. Use ONLY the provided        │
│ vulnerability scan data to answer questions. If information is not in   │
│ the context, say "I don't have data on that." Always cite sources.      │
│                                                                          │
│ CONTEXT:                                                                 │
│ {retrieved_documents_from_step_4}                                       │
│                                                                          │
│ USER QUERY:                                                              │
│ What are the critical SSH vulnerabilities on host 192.168.1.50?         │
│                                                                          │
│ INSTRUCTIONS:                                                            │
│ - Prioritize critical vulnerabilities (CVSS ≥7.0)                       │
│ - Include remediation steps if available                                │
│ - Format: Summary → Details → Recommendations                           │
└────────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────────────┐
│ STEP 6: LLM GENERATION (Ollama + Llama 3.2 3B)                          │
│ ─────────────────────────────────────────────────────                   │
│ Endpoint: http://localhost:11434/v1/chat/completions                    │
│ Parameters:                                                              │
│   - temperature: 0.3 (low for factual accuracy)                         │
│   - max_tokens: 512                                                      │
│   - stream: false                                                        │
│                                                                          │
│ Processing Time: ~1.5 seconds                                            │
│ Tokens Generated: ~180 tokens                                            │
│ Speed: ~15 tokens/sec (CPU) | ~60 tokens/sec (GPU)                      │
│                                                                          │
│ Generated Response:                                                      │
│ ┌──────────────────────────────────────────────────────────────┐       │
│ │ **Summary:** Host 192.168.1.50 has 2 critical SSH           │       │
│ │ vulnerabilities (CVSS ≥9.0).                                 │       │
│ │                                                               │       │
│ │ **Details:**                                                  │       │
│ │ - CVE-2023-12345 (Port 22/SSH): Remote code execution via    │       │
│ │   authentication bypass                                       │       │
│ │ - CVE-2023-22222 (Port 22/SSH): SSH key management flaw      │       │
│ │                                                               │       │
│ │ **Remediation:**                                              │       │
│ │ - Update SSH to version 9.0+ (CVE-2023-12345)                │       │
│ │ - Apply key rotation patch (CVE-2023-22222)                  │       │
│ │                                                               │       │
│ │ **Sources:** CVE-2023-12345, CVE-2023-22222                  │       │
│ └──────────────────────────────────────────────────────────────┘       │
└────────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────────────┐
│ STEP 7: POST-PROCESSING                                                 │
│ ─────────────────────────                                               │
│ • Hallucination Detection:                                               │
│   - Extract CVE IDs from response: [CVE-2023-12345, CVE-2023-22222]    │
│   - Verify all exist in retrieved context ✓                             │
│   - Hallucination rate: 0% ✓                                            │
│                                                                          │
│ • Citation Formatting:                                                   │
│   CVE-2023-12345 → [CVE-2023-12345](https://nvd.nist.gov/...)           │
│                                                                          │
│ • Confidence Score:                                                      │
│   retrieval_avg_score (0.89) * 0.5 + (1 - hallucination_rate) * 0.5    │
│   = 0.945 (High Confidence)                                              │
│                                                                          │
│ • Markdown Formatting:                                                   │
│   **CVE-2023-12345** (bold), `ssh` (code), [link](url)                  │
└────────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────────────┐
│ STEP 8: RESPONSE DELIVERY (JSON to Frontend)                            │
│ ─────────────────────────────────────────────────────                   │
│ {                                                                        │
│   "response": "**Summary:** Host 192.168.1.50 has 2 critical...",       │
│   "sources": [                                                           │
│     {                                                                    │
│       "cve": "CVE-2023-12345",                                           │
│       "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-12345",         │
│       "cvss_score": 9.8                                                  │
│     },                                                                   │
│     {                                                                    │
│       "cve": "CVE-2023-22222",                                           │
│       "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-22222",         │
│       "cvss_score": 9.0                                                  │
│     }                                                                    │
│   ],                                                                     │
│   "confidence": 0.945,                                                   │
│   "conversation_id": "uuid-1234-5678",                                   │
│   "latency_ms": 1547,                                                    │
│   "tokens_generated": 182                                                │
│ }                                                                        │
└────────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │  FRONTEND DISPLAYS    │
                    │  CHATBOT RESPONSE     │
                    └───────────────────────┘
```

---

## Attack Path Graph Structure

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ATTACK PATH GRAPH MODEL                          │
└────────────────────────────────────────────────────────────────────────┘

NODE TYPES:

  🖥️  HOST NODE                      ⚠️  VULNERABILITY NODE
  ┌─────────────────────┐           ┌─────────────────────┐
  │ ID: host_192.168.1.50│           │ ID: vuln_CVE-2023-* │
  │ IP: 192.168.1.50     │           │ CVE: CVE-2023-12345 │
  │ OS: Ubuntu 20.04     │           │ CVSS: 9.8 (Critical)│
  │ Segment: DMZ         │           │ Exploit: Available  │
  │ Ports: [22,80,443]   │           │ Impact: RCE         │
  └─────────────────────┘           └─────────────────────┘

  🔑  CREDENTIAL NODE
  ┌─────────────────────┐
  │ ID: cred_ssh_weak   │
  │ Service: SSH        │
  │ Type: weak_password │
  │ Strength: weak      │
  └─────────────────────┘

EDGE TYPES:

  HAS_VULNERABILITY (Host → Vuln)
  ────────────────────────────────
  Host: 192.168.1.50  ──[detected_by: Nmap]──▶  Vuln: CVE-2023-12345

  EXPLOITS (Vuln → Host)
  ──────────────────────
  Vuln: CVE-2023-12345  ──[impact: RCE, priv: root]──▶  Host: 192.168.1.50

  LEADS_TO (Host → Host - Lateral Movement)
  ──────────────────────────────────────────
  Host: 192.168.1.50 (DMZ)  ──[method: SSH pivot]──▶  Host: 192.168.10.20 (Internal)

EXAMPLE GRAPH:

                    External Attacker
                            │
                            ▼
    ┌───────────────────────────────────────────────────────────┐
    │                    DMZ Network                             │
    │                                                            │
    │   🖥️ Web Server (192.168.1.50)                            │
    │      │                                                     │
    │      │ HAS_VULNERABILITY                                  │
    │      ▼                                                     │
    │   ⚠️ CVE-2023-11111 (SQL Injection, CVSS 9.2)            │
    │      │                                                     │
    │      │ EXPLOITS (Impact: RCE, Priv: www-data)            │
    │      ▼                                                     │
    │   🖥️ Web Server (192.168.1.50) [COMPROMISED]             │
    └───────────────────────────┬───────────────────────────────┘
                                │
                                │ LEADS_TO (Method: SSH weak creds)
                                ▼
    ┌───────────────────────────────────────────────────────────┐
    │                  Internal Network                          │
    │                                                            │
    │   🖥️ App Server (192.168.10.20)                           │
    │      │                                                     │
    │      │ HAS_VULNERABILITY                                  │
    │      ▼                                                     │
    │   ⚠️ CVE-2023-22222 (Privilege Escalation, CVSS 8.5)     │
    │      │                                                     │
    │      │ EXPLOITS (Impact: Priv Esc, Priv: root)           │
    │      ▼                                                     │
    │   🖥️ App Server (192.168.10.20) [ROOT ACCESS]            │
    │      │                                                     │
    │      │ LEADS_TO (Method: Network access)                 │
    │      ▼                                                     │
    │   🖥️ Database Server (192.168.10.50) [DATA BREACH]       │
    └───────────────────────────────────────────────────────────┘

ATTACK PATH NARRATIVE:

Step 1: Attacker exploits CVE-2023-11111 (SQL injection) on web server
        → Gains www-data shell access

Step 2: Pivots to internal network via weak SSH credentials (lateral movement)
        → Accesses app server 192.168.10.20

Step 3: Exploits CVE-2023-22222 (privilege escalation) on app server
        → Gains root access

Step 4: Uses root privileges to access database server
        → Full data breach achieved

MITIGATION PRIORITY:
1. 🔴 Patch CVE-2023-11111 (SQL injection) - CRITICAL (Blocks initial entry)
2. 🟠 Enforce SSH key authentication (Breaks lateral movement chain)
3. 🟡 Patch CVE-2023-22222 (Privilege escalation)
4. 🟢 Segment network (VLAN isolation between DMZ and Internal)
```

---

## Component Interaction Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         DATA FLOW ARCHITECTURE                       │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   SCANNER   │    │   THREAT    │    │   BACKEND   │
│   LAYER     │───▶│    INTEL    │───▶│   DATABASE  │
│ (Nmap, etc) │    │ (NVD, etc)  │    │  (Postgres) │
└─────────────┘    └─────────────┘    └─────────────┘
                                              │
                                              ▼
                                    ┌─────────────────┐
                                    │  INTELLIGENCE   │
                                    │     LAYER       │
                                    │                 │
                                    │  ┌───────────┐  │
                                    │  │ INDEXER   │  │
                                    │  └─────┬─────┘  │
                                    │        │        │
                                    │        ▼        │
                        ┌───────────┤  ┌───────────┐ │
                        │           │  │ ChromaDB  │ │
                        │           │  │ (Vectors) │ │
                        │           │  └───────────┘ │
                        │           │                 │
                        │           │  ┌───────────┐ │
                        │           │  │ NetworkX  │ │
                        │           │  │ (Graphs)  │ │
                        │           │  └───────────┘ │
                        │           └─────────────────┘
                        │                     │
                        │                     ▼
                        │           ┌─────────────────┐
                        │           │  RAG PIPELINE   │
                        │           │                 │
                        │           │  ┌───────────┐  │
                        │           │  │ Embedder  │  │
                        │           │  └─────┬─────┘  │
                        │           │        │        │
                        │           │        ▼        │
                        │           │  ┌───────────┐  │
                        │           │  │ Retriever │  │
                        │           │  └─────┬─────┘  │
                        │           │        │        │
                        │           │        ▼        │
                        │           │  ┌───────────┐  │
                        └───────────┼─▶│  Ollama   │  │
   User Query                       │  │  Llama 3.2│  │
        │                           │  └─────┬─────┘  │
        │                           │        │        │
        └───────────────────────────┤        ▼        │
                                    │  ┌───────────┐  │
                                    │  │Post-Proc  │  │
                                    │  └─────┬─────┘  │
                                    └────────┼────────┘
                                             │
                                             ▼
                                      ┌─────────────┐
                                      │  FRONTEND   │
                                      │   (React)   │
                                      └─────────────┘
```

---

## Performance Timeline (Typical Query)

```
Time (ms) │ Component                    │ Action
──────────┼──────────────────────────────┼─────────────────────────────
    0     │ Frontend                     │ User submits query
   10     │ API Gateway                  │ Receives request
   20     │ RAG Pipeline - Preprocessing │ Extract entities, intent
   30     │ Embedding Service            │ Generate 384-dim vector
   35     │ ChromaDB                     │ Vector similarity search
   50     │ Retrieval Engine             │ Fetch top-5 documents
   60     │ Context Assembly             │ Format for LLM
   80     │ Prompt Builder               │ Inject context, system prompt
  100     │ Ollama API Call              │ Send to Llama 3.2
 1600     │ LLM Inference                │ Generate response (1.5s)
 1620     │ Post-Processing              │ Hallucination check, citations
 1640     │ API Gateway                  │ Return JSON response
 1650     │ Frontend                     │ Display chatbot message
──────────┴──────────────────────────────┴─────────────────────────────

TOTAL LATENCY: ~1.65 seconds (end-to-end)
- Embedding: 5ms
- Retrieval: 15ms
- LLM Inference: 1.5s (dominates latency)
- Other: 100ms
```

**Optimization Opportunities:**
- Use GPU: Reduce LLM time to ~400ms (60% latency reduction)
- Cache common queries: Skip LLM for repeated questions
- Streaming: Show partial response in real-time (<100ms to first token)

---

**Document Version:** 1.0  
**Last Updated:** 2025-01-30  
**Purpose:** Visual reference for RAG pipeline architecture
