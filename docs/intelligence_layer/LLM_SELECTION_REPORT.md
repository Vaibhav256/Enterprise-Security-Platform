# Local LLM Selection Report for Intelligence Layer

## Executive Summary

This report evaluates open-source, locally runnable Large Language Models (LLMs) for the RAG-based chatbot component of the Centralized Vulnerability Detection and Intelligent Query Interface. The selection prioritizes **cost-effectiveness** (no paid models), **data privacy** (local deployment), and **performance** suitable for cybersecurity question-answering tasks.

---

## LLM Candidates Evaluated

### 1. **Llama 3.2 (3B Instruct) - RECOMMENDED**

**Model Characteristics:**
- **Parameters:** 3 billion
- **Context Window:** 128K tokens (extremely large for local models)
- **Quantization:** Available in 4-bit, 8-bit (GGUF format)
- **Memory Requirements:** ~2-4GB RAM (4-bit quantized)
- **License:** Llama 3 Community License (permissive for research/education)

**Rationale for Suitability:**
- **Best balance for college project:** Small enough to run on laptops (8-16GB RAM) while maintaining strong instruction-following capabilities
- **Cybersecurity applicability:** Trained on diverse datasets including technical documentation; excels at structured Q&A
- **RAG optimization:** Large context window (128K) allows extensive vulnerability data injection without truncation
- **Active community:** Extensive GGUF quantizations available, well-documented Ollama integration
- **Inference speed:** ~10-20 tokens/sec on CPU, ~50-100 tokens/sec on mid-range GPU (RTX 3060)

**Recommended Inference Framework:** **Ollama**
- **Why Ollama:** 
  - One-command model installation (`ollama pull llama3.2:3b`)
  - Built-in API server (OpenAI-compatible endpoints)
  - Automatic quantization selection based on hardware
  - GPU acceleration with automatic fallback to CPU
  - Minimal configuration required

---

### 2. **Mistral 7B Instruct v0.3**

**Model Characteristics:**
- **Parameters:** 7 billion
- **Context Window:** 32K tokens
- **Quantization:** 4-bit, 5-bit, 8-bit (GGUF)
- **Memory Requirements:** ~4-6GB RAM (4-bit quantized)
- **License:** Apache 2.0 (fully open)

**Rationale for Suitability:**
- **Strong reasoning:** Excellent at multi-step logical reasoning, critical for attack path explanations
- **Concise responses:** Trained to avoid verbosity, ideal for analyst-facing chatbot
- **JSON mode:** Native structured output support (useful for extracting CVE data, remediation steps)
- **Performance:** Slightly slower than Llama 3.2 3B but higher quality for complex queries
- **Context limitation:** 32K context window may require more aggressive chunking for large scan reports

**Recommended Inference Framework:** **Ollama** or **llama.cpp**
- Ollama: `ollama pull mistral:7b-instruct`
- llama.cpp: More control over quantization and sampling parameters

---

### 3. **Phi-3.5 Mini Instruct (3.8B)**

**Model Characteristics:**
- **Parameters:** 3.8 billion
- **Context Window:** 128K tokens
- **Quantization:** 4-bit optimized (GGUF)
- **Memory Requirements:** ~2-3GB RAM (4-bit)
- **License:** MIT (most permissive)

**Rationale for Suitability:**
- **Microsoft pedigree:** Trained on high-quality filtered datasets, strong on technical Q&A
- **Efficiency:** Optimized for edge deployment, fastest inference among candidates
- **Long context:** 128K context window matches Llama 3.2
- **Trade-off:** Slightly lower reasoning quality than Mistral 7B, but sufficient for factual retrieval tasks

**Recommended Inference Framework:** **Ollama**
- Installation: `ollama pull phi3.5:3.8b`

---

## Final Recommendation: **Llama 3.2 3B Instruct with Ollama**

### Justification for College Project Context

| Criterion | Llama 3.2 3B | Mistral 7B | Phi-3.5 Mini |
|-----------|--------------|------------|---------------|
| **Hardware Accessibility** | ✅ Excellent (runs on 8GB RAM laptops) | ⚠️ Good (requires 12GB+ for comfort) | ✅ Excellent |
| **Context Window** | ✅ 128K (ideal for RAG) | ⚠️ 32K (requires chunking) | ✅ 128K |
| **Inference Speed** | ✅ Fast (~15 tok/sec CPU) | ⚠️ Moderate (~8 tok/sec CPU) | ✅ Very fast (~20 tok/sec CPU) |
| **Cybersecurity Q&A Quality** | ✅ Very good | ✅ Excellent | ⚠️ Good |
| **Setup Complexity** | ✅ Minimal (Ollama 1-liner) | ✅ Minimal | ✅ Minimal |
| **Community Support** | ✅ Extensive | ✅ Extensive | ⚠️ Growing |
| **License for Academic Use** | ✅ Permissive | ✅ Apache 2.0 | ✅ MIT |

**Winner:** Llama 3.2 3B strikes the best balance between **accessibility** (runs on any student laptop), **performance** (large context for RAG), and **ease of deployment** (Ollama).

---

## Implementation Path with Ollama

### Step 1: Install Ollama
```bash
# Windows (PowerShell as Admin)
winget install Ollama.Ollama

# Alternative: Download from https://ollama.com/download
```

### Step 2: Pull Llama 3.2 Model
```bash
ollama pull llama3.2:3b-instruct-q4_K_M
```
- `3b-instruct`: Instruction-tuned variant (required for chatbot)
- `q4_K_M`: 4-bit quantization, balanced quality/speed

### Step 3: Verify Installation
```bash
ollama run llama3.2:3b-instruct-q4_K_M
# Interactive prompt appears - type a test question
```

### Step 4: Start API Server (for Python integration)
```bash
ollama serve
# Starts OpenAI-compatible API on http://localhost:11434
```

---

## Alternative Configuration: GPU Acceleration

For students with NVIDIA GPUs (RTX 2060+):
```bash
# Ollama automatically detects GPU
# Verify GPU usage:
ollama run llama3.2:3b-instruct-q4_K_M --verbose

# Expected output: "GPU layers: 32/32" (full offload)
```

**Expected speedup:** 3-5x faster inference (50-80 tokens/sec on RTX 3060).

---

## Fallback Plan: Mistral 7B for Advanced Use Cases

If query complexity exceeds Llama 3.2's capabilities (e.g., multi-hop reasoning for complex attack paths):
```bash
ollama pull mistral:7b-instruct-v0.3-q4_K_M
```

**Switching models in code:** Change one line in `rag_engine.py`:
```python
model_name = "llama3.2:3b-instruct-q4_K_M"  # or "mistral:7b-instruct-v0.3-q4_K_M"
```

---

## Resource Benchmarks

| Hardware Profile | Recommended Model | Expected Performance |
|------------------|-------------------|----------------------|
| **Laptop (8GB RAM, no GPU)** | Llama 3.2 3B (4-bit) | 10-15 tok/sec, 2-3 sec latency |
| **Desktop (16GB RAM, RTX 3060)** | Llama 3.2 3B (4-bit) | 50-80 tok/sec, <1 sec latency |
| **High-end (32GB RAM, RTX 4080)** | Mistral 7B (5-bit) | 100+ tok/sec, <0.5 sec latency |

---

## Cost Analysis

| Component | Cloud-based (e.g., GPT-4) | Local LLM (Llama 3.2) |
|-----------|---------------------------|------------------------|
| **Per Query** | $0.01-0.03 (API fees) | $0.00 (electricity ~$0.0001) |
| **1000 Queries** | $10-30 | $0.00 |
| **Privacy** | ❌ Data sent to third party | ✅ All data stays local |
| **Internet Dependency** | ❌ Required | ✅ Fully offline capable |
| **Setup Time** | 5 min (API key) | 10 min (install Ollama) |

**Conclusion:** Local LLM is **100x cheaper** and **fully private**, critical for handling sensitive vulnerability data in NTRO's operational context.

---

## Next Steps

1. **Install Ollama and pull Llama 3.2** (see commands above)
2. **Implement Python RAG pipeline** (see `RAG_PIPELINE_DESIGN.md`)
3. **Create PoC script** to validate local LLM responses (see `poc_local_llm.py`)
4. **Benchmark performance** on sample vulnerability queries
5. **Iterate to Mistral 7B** if quality issues arise

---

## References

- **Ollama Documentation:** https://ollama.com/docs
- **Llama 3.2 Model Card:** https://ollama.com/library/llama3.2
- **Mistral Models:** https://ollama.com/library/mistral
- **Quantization Guide:** https://github.com/ggerganov/llama.cpp/blob/master/examples/quantize/README.md
