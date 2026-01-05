# AI Evaluation Module 🎯

Comprehensive evaluation framework for NTRO's AI components, measuring performance against targets defined in `ai.md`.

## 📊 Evaluated Components

### 1. RAG Chatbot
- **BLEU Score** (target: >40) - N-gram overlap with reference answers
- **ROUGE-L Score** (target: >0.6) - Longest common subsequence similarity
- **Hallucination Rate** (target: <5%) - Incorrect CVE citations
- **Precision@5** (target: >80%) - Retrieval accuracy

### 2. Attack Path Modeling
- **Graph Build Time** (target: <5s for 100 hosts) - Performance benchmark
- **F1 Score** (target: >0.85) - Path discovery accuracy
- **Spearman Correlation** (target: >0.7) - Mitigation ranking quality

---

## 🚀 Quick Start

### Step 1: Install Dependencies

```powershell
cd backend
.\setup_evaluation.ps1
```

This installs:
- `nltk` - BLEU score calculation
- `rouge-score` - ROUGE metrics
- `scipy` - Statistical correlations
- `numpy`, `pandas` - Data processing

### Step 2: Ensure Services Running

```bash
# Start Ollama (required for RAG chatbot)
ollama serve

# Verify model is available
ollama list | grep llama3.2
```

### Step 3: Run Evaluation

```powershell
cd backend
python -m evaluation.run_all_evals
```

**Expected Output:**
```
======================================================================
  NTRO AI COMPONENTS COMPREHENSIVE EVALUATION
======================================================================

Starting RAG chatbot evaluation...
Loaded 5 Q&A pairs for evaluation
Evaluating query 1/5: What is CVE-2023-12345?...
  BLEU: 45.23, ROUGE-L: 0.678, Hallucination: False
...

╔══════════════════════════════════════════════════════════════╗
║           RAG CHATBOT EVALUATION REPORT                      ║
╚══════════════════════════════════════════════════════════════╝

📊 METRICS SUMMARY
  Total Queries Evaluated: 5
  Average Response Time:   1.82 seconds

🎯 QUALITY METRICS (vs. Targets)
  BLEU Score:             45.23 / 100
    Target: > 40          ✅ PASS
    
  ROUGE-L Score:          0.678
    Target: > 0.6         ✅ PASS
    
  Hallucination Rate:     0.0%
    Target: < 5%          ✅ PASS
    
  Precision@5:            0.85
    Target: > 80%         ✅ PASS

🏆 OVERALL STATUS: ✅ ALL TARGETS MET

======================================================================
  OVERALL EVALUATION STATUS: ALL TARGETS MET ✅
======================================================================

✅ Results saved to: evaluation/results/evaluation_report_20251030_143022.json
```

---

## 📁 Module Structure

```
evaluation/
├── __init__.py                 # Module exports
├── README.md                   # This file
├── requirements.txt            # Python dependencies
│
├── dataset_loader.py           # Test dataset management
├── rag_evaluator.py            # RAG chatbot evaluation
├── attack_path_evaluator.py   # Attack path evaluation
├── run_all_evals.py            # Main evaluation runner
│
├── datasets/                   # Test datasets (auto-generated)
│   ├── rag_qa_pairs.json       # 50 Q&A pairs for RAG testing
│   └── attack_scenarios.json  # 20 attack scenarios
│
└── results/                    # Evaluation results
    ├── evaluation_report_latest.json
    └── evaluation_report_20251030_143022.json
```

---

## 📝 Test Datasets

### RAG Q&A Pairs (`datasets/rag_qa_pairs.json`)

**Default Dataset**: 5 gold-standard Q&A pairs
- Vulnerability lookup questions
- Remediation guidance queries
- Attack path reasoning
- CVSS interpretation

**Adding Custom Q&A Pairs**:
```python
from evaluation.dataset_loader import DatasetLoader, QAPair

loader = DatasetLoader()
qa_pairs = loader.load_rag_qa_pairs()

# Add new pair
qa_pairs.append(QAPair(
    question="What are the critical vulnerabilities on 192.168.1.100?",
    reference_answer="Host 192.168.1.100 has 2 critical vulnerabilities: CVE-2024-1111 (CVSS 9.8), CVE-2024-2222 (CVSS 9.1)",
    expected_cves=["CVE-2024-1111", "CVE-2024-2222"],
    category="vulnerability_lookup"
))

loader.save_qa_pairs(qa_pairs)
```

### Attack Scenarios (`datasets/attack_scenarios.json`)

**Default Dataset**: 2 synthetic scenarios
- Web server RCE → Database access
- Multi-hop lateral movement via SSH

**Adding Custom Scenarios**:
```python
from evaluation.dataset_loader import AttackScenario

scenario = AttackScenario(
    scenario_id="custom_001",
    description="Phishing → Lateral movement → Domain Admin",
    hosts=[
        {"ip": "192.168.1.10", "role": "workstation", "os": "Windows"},
        {"ip": "192.168.10.5", "role": "domain_controller", "os": "Windows"}
    ],
    vulnerabilities=[
        {"cve": "CVE-2024-XXXX", "host": "192.168.1.10", "cvss": 7.8, "type": "privilege_escalation"}
    ],
    expected_paths=[
        ["192.168.1.10", "CVE-2024-XXXX", "192.168.10.5"]
    ],
    criticality="critical"
)
```

---

## 📊 Interpreting Results

### BLEU Score (0-100)
- **> 60**: Excellent (near-human quality)
- **40-60**: Good (acceptable for technical Q&A) ✅ TARGET
- **< 40**: Needs improvement

### ROUGE-L Score (0-1)
- **> 0.8**: Excellent semantic similarity
- **0.6-0.8**: Good (acceptable) ✅ TARGET
- **< 0.6**: Poor fidelity

### Hallucination Rate (%)
- **< 5%**: Acceptable ✅ TARGET
- **5-10%**: Moderate risk
- **> 10%**: Unacceptable

### F1 Score (0-1)
- **> 0.9**: Excellent
- **0.85-0.9**: Good ✅ TARGET
- **< 0.85**: Needs improvement

---

## 🛠️ Advanced Usage

### Run Individual Evaluations

```python
# RAG only
from evaluation.rag_evaluator import RAGEvaluator
from evaluation.dataset_loader import DatasetLoader
from intelligence_layer.rag.chatbot import RAGChatbot

loader = DatasetLoader()
chatbot = RAGChatbot(...)  # Initialize
evaluator = RAGEvaluator(chatbot, loader)
metrics = evaluator.evaluate()
print(evaluator.generate_report(metrics))
```

```python
# Attack Path only
from evaluation.attack_path_evaluator import AttackPathEvaluator

evaluator = AttackPathEvaluator(loader)
metrics = evaluator.evaluate()
print(evaluator.generate_report(metrics))
```

### Export Results to CSV

```python
import json
import pandas as pd

with open('evaluation/results/evaluation_report_latest.json') as f:
    results = json.load(f)

df = pd.DataFrame([results['rag_chatbot']])
df.to_csv('rag_metrics.csv', index=False)
```

---

## 🐛 Troubleshooting

### Error: "NLTK data not found"
```bash
python -c "import nltk; nltk.download('punkt'); nltk.download('stopwords')"
```

### Error: "Cannot connect to Ollama"
```bash
# Start Ollama server
ollama serve

# Verify running
curl http://localhost:11434/api/tags
```

### Error: "ChromaDB collection not found"
```python
# Index sample data first
from intelligence_layer.rag.indexing import VulnerabilityIndexer

indexer = VulnerabilityIndexer()
indexer.index_vulnerability({
    "cve_id": "CVE-2023-12345",
    "description": "Remote code execution in OpenSSH 7.4",
    "cvss_score": 9.8,
    "host_ip": "192.168.1.50"
})
```

---

## 📚 References

- **ai.md** - Target metrics and evaluation requirements
- **Intelligence Layer README** - RAG and Attack Path documentation
- **NLTK BLEU** - https://www.nltk.org/api/nltk.translate.bleu_score.html
- **ROUGE Metrics** - https://pypi.org/project/rouge-score/

---

## 🎯 Next Steps

1. ✅ Run initial evaluation with default datasets
2. 📝 Expand `rag_qa_pairs.json` to 50 questions (target from verification.md)
3. 📝 Add 20 attack scenarios covering diverse attack vectors
4. 📊 Conduct user satisfaction survey (10 beta testers)
5. 📈 Generate PDF reports with Matplotlib charts
6. 🔄 Integrate into CI/CD pipeline (automated evaluation on every commit)

---

**Status**: ✅ Evaluation module complete - Ready for testing  
**Last Updated**: 2025-10-30  
**Maintainer**: NTRO Intelligence Layer Team
