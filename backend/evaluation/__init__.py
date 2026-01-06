"""
AI Evaluation Module

Provides comprehensive evaluation metrics for AI components:
1. RAG Chatbot (BLEU, ROUGE, Hallucination Rate, Precision@5)
2. Attack Path Modeling (Graph Build Time, F1 Score, Mitigation Ranking)
3. Vulnerability Detection (F1 Score, False Positive Rate)

Author: NTRO Intelligence Layer Team
Date: 2025-10-30
"""

from .rag_evaluator import RAGEvaluator
from .dataset_loader import DatasetLoader

# Attack path evaluator is optional in this workspace (may be implemented separately).
# Import it only if present to avoid breaking test collection when the module is missing.
try:
    from .attack_path_evaluator import AttackPathEvaluator  # type: ignore
except Exception:
    AttackPathEvaluator = None

# Public API
__all__ = ['RAGEvaluator', 'DatasetLoader']
if AttackPathEvaluator is not None:
    __all__.insert(1, 'AttackPathEvaluator')
