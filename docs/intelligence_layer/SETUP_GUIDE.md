# Intelligence Layer Setup Guide

## Quick Installation (5 Steps, ~20 Minutes)

This guide walks you through setting up the Intelligence Layer foundation for the NTRO Vulnerability Detection Platform.

---

## Prerequisites Check

Before starting, verify you have:

- [ ] **Windows 10/11** (PowerShell available)
- [ ] **Python 3.9 or higher** installed (`python --version`)
- [ ] **8GB RAM minimum** (16GB recommended)
- [ ] **5GB free disk space** (for Ollama + model + dependencies)
- [ ] **Internet connection** (for initial downloads only - fully offline afterwards)

---

## Step 1: Install Ollama (5 minutes)

Ollama is the inference engine for running Llama 3.2 locally.

### Option A: Using Windows Package Manager (Recommended)

```powershell
# Open PowerShell as Administrator
winget install Ollama.Ollama
```

### Option B: Manual Download

1. Visit: https://ollama.com/download
2. Download **Ollama for Windows**
3. Run installer (`OllamaSetup.exe`)
4. Accept defaults

### Verify Installation

```powershell
ollama --version
# Expected: ollama version 0.x.x
```

**Troubleshooting:** If `ollama` command not found, restart PowerShell or add to PATH manually.

---

## Step 2: Pull Llama 3.2 Model (5 minutes)

Download the recommended model (2GB download).

```powershell
ollama pull llama3.2:3b-instruct-q4_K_M
```

**Progress indicator:**
```
pulling manifest
pulling 6e8a2c4... 100% ▕████████████▏ 2.0 GB
pulling 966de95... 100% ▕████████████▏ 1.4 KB
pulling fcc5a6b... 100% ▕████████████▏   12 KB
pulling a70ff74... 100% ▕████████████▏  487 B
verifying sha256 digest
success
```

### Verify Model

```powershell
ollama list
# Expected output includes: llama3.2:3b-instruct-q4_K_M
```

---

## Step 3: Start Ollama Server (1 minute)

The server must run continuously for the chatbot to work.

```powershell
# Open a NEW PowerShell window (keep it open)
ollama serve
```

**Expected output:**
```
Listening on 127.0.0.1:11434 (version 0.x.x)
time=2025-01-30T14:30:00.000+00:00 level=INFO source=images.go:806 msg="total blobs: 4"
```

**Important:** Keep this terminal window open. Minimize it if needed.

### Verify Server is Running

```powershell
# In a SEPARATE PowerShell window
curl http://localhost:11434/api/tags

# Expected: JSON response with "models" array
```

---

## Step 4: Install Python Dependencies (5 minutes)

Navigate to the intelligence layer directory and install required packages.

```powershell
cd "d:\New folder (2)\backend\intelligence_layer"
pip install -r requirements.txt
```

**Expected packages installed:**
- sentence-transformers (embedding model)
- chromadb (vector database)
- networkx (graph database)
- spacy (NLP/entity extraction)
- matplotlib, plotly (visualization)
- requests (HTTP client for Ollama)

### Install spaCy English Model

```powershell
python -m spacy download en_core_web_sm
```

**Progress:**
```
✔ Download and installation successful
You can now load the package via spacy.load('en_core_web_sm')
```

---

## Step 5: Validate Setup with PoC Script (5 minutes)

Run the Proof-of-Concept script to verify everything works.

```powershell
python poc_local_llm.py
```

### Expected Output (Successful Setup)

```
╔════════════════════════════════════════════════════════════════════╗
║   Local LLM Proof-of-Concept for Intelligence Layer (Phase 3)     ║
║   Model: Llama 3.2 3B Instruct (via Ollama)                       ║
╚════════════════════════════════════════════════════════════════════╝

Step 1: Verifying Ollama Server
✓ Ollama server is running

Step 2: Verifying Model Availability
✓ Model 'llama3.2:3b-instruct-q4_K_M' is available

Step 3: Running Automated Test Queries
======================================================================

Test 1/4: Basic Vulnerability Explanation
Prompt: What is CVE-2023-12345? Explain in 2-3 sentences.
Querying LLM...
Response (1.2s, 15.3 tok/sec):
CVE-2023-12345 refers to an authentication bypass vulnerability in OpenSSH 7.x 
that allows remote attackers to execute arbitrary code without credentials. 
The flaw enables attackers to bypass authentication checks via a crafted SSH handshake.

----------------------------------------------------------------------

Test 2/4: Remediation Guidance
...

✓ PoC completed successfully!
Local LLM setup validated. Ready for RAG pipeline integration.
```

### Interactive Mode Test

When prompted:
```
Do you want to enter interactive chatbot mode? (y/n): y
```

Type `y` and test a query:
```
You: What is a buffer overflow?
Assistant: A buffer overflow is a vulnerability where a program writes more data 
to a buffer than it can hold, potentially allowing attackers to execute arbitrary 
code or crash the system. Common in C/C++ due to lack of bounds checking...

You: exit
```

---

## Troubleshooting Common Issues

### ❌ Issue: "Cannot connect to Ollama server"

**Symptom:**
```
✗ Cannot connect to Ollama server at http://localhost:11434
  Please start Ollama: 'ollama serve'
```

**Fix:**
```powershell
# In a separate terminal, run:
ollama serve
```

**Root cause:** Ollama server not running.

---

### ❌ Issue: "Model 'llama3.2:3b-instruct-q4_K_M' not found"

**Symptom:**
```
✗ Model 'llama3.2:3b-instruct-q4_K_M' not found
  Pull model: 'ollama pull llama3.2:3b-instruct-q4_K_M'
```

**Fix:**
```powershell
ollama pull llama3.2:3b-instruct-q4_K_M
# Wait for download (~2GB, 5 minutes)
```

**Root cause:** Model not downloaded yet.

---

### ❌ Issue: "ModuleNotFoundError: No module named 'sentence_transformers'"

**Symptom:**
```python
ModuleNotFoundError: No module named 'sentence_transformers'
```

**Fix:**
```powershell
pip install -r requirements.txt
# Ensure you're in: backend/intelligence_layer/
```

**Root cause:** Dependencies not installed.

---

### ❌ Issue: Slow inference (<5 tokens/sec)

**Symptom:**
```
Response (8.5s, 4.2 tok/sec)
```

**Fixes (in order of effectiveness):**

1. **Use GPU (if available):**
   - Ollama auto-detects NVIDIA GPUs
   - Verify: `ollama run llama3.2:3b-instruct-q4_K_M --verbose`
   - Expected: "GPU layers: 32/32"

2. **Close other applications:**
   - Free up RAM (browsers, IDEs)

3. **Switch to faster model:**
   ```powershell
   ollama pull phi3.5:3.8b
   # Update MODEL_NAME in poc_local_llm.py
   ```

4. **Reduce max_tokens:**
   - Edit `poc_local_llm.py`: `max_tokens=512` → `max_tokens=256`

---

### ❌ Issue: High memory usage (>8GB RAM)

**Symptoms:**
- Computer slows down during LLM queries
- "Out of memory" errors

**Fixes:**

1. **Use smaller model:**
   ```powershell
   ollama pull llama3.2:1b
   # Update MODEL_NAME in poc_local_llm.py
   ```

2. **Reduce batch size (when indexing data later):**
   - ChromaDB batch processing: 100 → 50 documents at a time

3. **Close other apps** (browsers, Slack, etc.)

---

## Next Steps After Setup

### Immediate (Testing)

1. ✅ Run PoC script successfully
2. ✅ Test interactive chatbot mode
3. ✅ Verify <2 sec query latency

### Phase 2 Implementation (Attack Path Modeling)

1. **Implement Graph Builder** (`attack_path/graph_builder.py`)
   - Reference: `docs/intelligence_layer/ATTACK_PATH_GRAPH_MODEL.md`
   - Build NetworkX graphs from scan results

2. **Develop Path Discovery** (`attack_path/path_discovery.py`)
   - Simple paths (single-step exploits)
   - Chained paths (multi-hop attacks)

3. **Create Visualization** (Matplotlib/Plotly)

### Phase 3 Implementation (RAG Chatbot)

4. **Build Indexing Pipeline** (`rag/indexing.py`)
   - Populate ChromaDB with scan data
   - Reference: `docs/intelligence_layer/DATA_INDEXING_SCHEMA.md`

5. **Implement Retrieval Engine** (`rag/retrieval_engine.py`)
   - Semantic search over ChromaDB
   - Reference: `docs/intelligence_layer/RAG_PIPELINE_DESIGN.md`

6. **Develop Chatbot** (`rag/chatbot.py`)
   - Prompt engineering, LLM integration
   - Post-processing (hallucination detection)

7. **Expose API** (FastAPI endpoints)
   - `/api/v1/chat` - Chatbot queries
   - `/api/v1/attack-paths` - Attack path discovery

---

## Verification Checklist

Before proceeding to implementation, ensure all these are ✅:

- [ ] Ollama server runs without errors
- [ ] Model `llama3.2:3b-instruct-q4_K_M` is pulled
- [ ] PoC script shows "✓ Ollama server is running"
- [ ] PoC script shows "✓ Model available"
- [ ] All 4 automated tests complete successfully
- [ ] Interactive mode responds to queries
- [ ] Query latency is <3 seconds (ideally <2s)
- [ ] No Python import errors

---

## Resource Usage Summary

After successful setup, your system should have:

| Resource | Usage | Normal? |
|----------|-------|---------|
| **Disk Space** | ~3GB | ✅ Yes (2GB model + 1GB deps) |
| **RAM (idle)** | ~500MB | ✅ Yes (Ollama server) |
| **RAM (querying)** | ~4GB | ✅ Yes (model loaded) |
| **CPU (querying)** | 60-80% | ✅ Yes (during inference) |
| **Network** | 0 KB/s | ✅ Yes (fully offline) |

---

## Getting Help

### Documentation

1. **Quick Start:** `backend/intelligence_layer/README.md`
2. **Full Report:** `docs/intelligence_layer/IMPLEMENTATION_SUMMARY.md`
3. **LLM Details:** `docs/intelligence_layer/LLM_SELECTION_REPORT.md`
4. **RAG Architecture:** `docs/intelligence_layer/RAG_PIPELINE_DESIGN.md`

### Common Commands Reference

```powershell
# Start Ollama server
ollama serve

# List installed models
ollama list

# Pull a model
ollama pull llama3.2:3b-instruct-q4_K_M

# Test model interactively
ollama run llama3.2:3b-instruct-q4_K_M

# Verify server
curl http://localhost:11434/api/tags

# Run PoC script
python poc_local_llm.py
```

---

**Setup Complete!** 🎉

You now have a fully functional local LLM infrastructure for the Intelligence Layer. Proceed to Phase 2/3 implementation as outlined in `IMPLEMENTATION_SUMMARY.md`.

---

**Document Version:** 1.0  
**Last Updated:** 2025-01-30  
**Estimated Setup Time:** 20 minutes  
**Difficulty:** Easy 🟢
