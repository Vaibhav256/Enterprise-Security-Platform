"""
RAG Chatbot Evaluator

Evaluates RAG chatbot performance using:
- BLEU Score (n-gram overlap with reference answers)
- ROUGE-L Score (longest common subsequence)
- Hallucination Rate (incorrect CVE citations)
- Retrieval Precision@5 (relevance of retrieved documents)

Target Metrics (from ai.md):
- BLEU > 40 (acceptable for technical Q&A)
- ROUGE-L > 0.6 (good semantic fidelity)
- Hallucination Rate < 5%
- Precision@5 > 80%

Author: NTRO Intelligence Layer Team
Date: 2025-10-30
"""

import re
import logging
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
import statistics

try:
    from nltk.translate.bleu_score import sentence_bleu, SmoothingFunction
    from rouge_score import rouge_scorer
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False
    logging.warning("NLTK or rouge-score not installed. Install with: pip install nltk rouge-score")

from intelligence_layer.rag.chatbot import RAGChatbot
from .dataset_loader import DatasetLoader, QAPair

logger = logging.getLogger(__name__)


@dataclass
class RAGMetrics:
    """RAG evaluation metrics"""
    bleu_score: float
    rouge_l_score: float
    hallucination_rate: float
    precision_at_5: float
    avg_response_time: float
    total_queries: int
    
    def passes_targets(self) -> bool:
        """Check if all metrics meet target thresholds"""
        return (
            self.bleu_score > 40 and
            self.rouge_l_score > 0.6 and
            self.hallucination_rate < 0.05 and
            self.precision_at_5 > 0.8
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'bleu_score': round(self.bleu_score, 2),
            'rouge_l_score': round(self.rouge_l_score, 3),
            'hallucination_rate': round(self.hallucination_rate, 3),
            'precision_at_5': round(self.precision_at_5, 3),
            'avg_response_time_sec': round(self.avg_response_time, 2),
            'total_queries': self.total_queries,
            'passes_targets': self.passes_targets()
        }


class RAGEvaluator:
    """Evaluates RAG chatbot performance"""
    
    def __init__(self, chatbot: RAGChatbot, dataset_loader: DatasetLoader):
        """
        Initialize RAG evaluator
        
        Args:
            chatbot: RAGChatbot instance to evaluate
            dataset_loader: DatasetLoader for test datasets
        """
        self.chatbot = chatbot
        self.dataset_loader = dataset_loader
        
        if not METRICS_AVAILABLE:
            raise ImportError("NLTK and rouge-score required. Install with: pip install nltk rouge-score")
        
        # Initialize ROUGE scorer
        self.rouge_scorer = rouge_scorer.RougeScorer(['rougeL'], use_stemmer=True)
        self.smoothing = SmoothingFunction()
    
    def evaluate(self) -> RAGMetrics:
        """
        Run comprehensive RAG evaluation
        
        Returns:
            RAGMetrics with all evaluation scores
        """
        logger.info("Starting RAG chatbot evaluation...")
        
        # Load test dataset
        qa_pairs = self.dataset_loader.load_rag_qa_pairs()
        logger.info(f"Loaded {len(qa_pairs)} Q&A pairs for evaluation")
        
        bleu_scores = []
        rouge_scores = []
        hallucinations = []
        precision_scores = []
        response_times = []
        
        for i, qa_pair in enumerate(qa_pairs, 1):
            logger.info(f"Evaluating query {i}/{len(qa_pairs)}: {qa_pair.question[:50]}...")
            
            # Get chatbot response
            import time
            start_time = time.time()
            try:
                response = self.chatbot.query(qa_pair.question)
                response_time = time.time() - start_time
                response_times.append(response_time)
                
                # Calculate BLEU score
                bleu = self._calculate_bleu(response['response'], qa_pair.reference_answer)
                bleu_scores.append(bleu)
                
                # Calculate ROUGE-L score
                rouge = self._calculate_rouge_l(response['response'], qa_pair.reference_answer)
                rouge_scores.append(rouge)
                
                # Check for hallucinations
                has_hallucination = self._check_hallucination(response, qa_pair.expected_cves)
                hallucinations.append(1 if has_hallucination else 0)
                
                # Calculate retrieval precision (if sources available)
                if 'sources' in response and response['sources']:
                    precision = self._calculate_precision_at_k(
                        response['sources'], qa_pair.expected_cves, k=5
                    )
                    precision_scores.append(precision)
                
                logger.info(f"  BLEU: {bleu:.2f}, ROUGE-L: {rouge:.3f}, Hallucination: {has_hallucination}")
            
            except Exception as e:
                logger.error(f"Error evaluating query: {e}")
                continue
        
        # Aggregate metrics
        metrics = RAGMetrics(
            bleu_score=statistics.mean(bleu_scores) if bleu_scores else 0.0,
            rouge_l_score=statistics.mean(rouge_scores) if rouge_scores else 0.0,
            hallucination_rate=statistics.mean(hallucinations) if hallucinations else 0.0,
            precision_at_5=statistics.mean(precision_scores) if precision_scores else 0.0,
            avg_response_time=statistics.mean(response_times) if response_times else 0.0,
            total_queries=len(qa_pairs)
        )
        
        logger.info(f"Evaluation complete: {metrics.to_dict()}")
        return metrics
    
    def _calculate_bleu(self, candidate: str, reference: str) -> float:
        """
        Calculate BLEU score (0-100 scale)
        
        Args:
            candidate: Chatbot-generated response
            reference: Gold-standard reference answer
        
        Returns:
            BLEU score (0-100)
        """
        # Tokenize (simple whitespace split)
        candidate_tokens = candidate.lower().split()
        reference_tokens = [reference.lower().split()]  # BLEU expects list of references
        
        # Calculate BLEU with smoothing (handles short sentences)
        bleu = sentence_bleu(
            reference_tokens,
            candidate_tokens,
            smoothing_function=self.smoothing.method1
        )
        
        return bleu * 100  # Convert to 0-100 scale
    
    def _calculate_rouge_l(self, candidate: str, reference: str) -> float:
        """
        Calculate ROUGE-L score (longest common subsequence)
        
        Args:
            candidate: Chatbot-generated response
            reference: Gold-standard reference answer
        
        Returns:
            ROUGE-L F1 score (0-1)
        """
        scores = self.rouge_scorer.score(reference, candidate)
        return scores['rougeL'].fmeasure
    
    def _check_hallucination(self, response: Dict[str, Any], expected_cves: List[str]) -> bool:
        """
        Check if response contains hallucinated CVE references
        
        Args:
            response: Chatbot response dict
            expected_cves: List of expected CVE IDs
        
        Returns:
            True if hallucination detected
        """
        # Extract CVEs mentioned in response
        response_text = response.get('response', '')
        mentioned_cves = re.findall(r'CVE-\d{4}-\d{4,7}', response_text)
        
        # Check if mentioned CVEs are in expected list or sources
        source_cves = []
        if 'sources' in response:
            for source in response['sources']:
                if 'cve_id' in source:
                    source_cves.append(source['cve_id'])
        
        valid_cves = set(expected_cves + source_cves)
        
        for cve in mentioned_cves:
            if cve not in valid_cves:
                logger.warning(f"Hallucination detected: {cve} not in sources")
                return True
        
        # Check if hallucination was detected by chatbot itself
        if response.get('hallucination_detected', False):
            return True
        
        return False
    
    def _calculate_precision_at_k(
        self, sources: List[Dict[str, Any]], expected_cves: List[str], k: int = 5
    ) -> float:
        """
        Calculate Precision@K for retrieval
        
        Args:
            sources: Retrieved source documents
            expected_cves: Expected CVE IDs for this query
            k: Number of top results to consider
        
        Returns:
            Precision@K (0-1)
        """
        if not sources or not expected_cves:
            return 0.0
        
        top_k_sources = sources[:k]
        relevant_count = 0
        
        for source in top_k_sources:
            if 'cve_id' in source and source['cve_id'] in expected_cves:
                relevant_count += 1
        
        return relevant_count / min(k, len(top_k_sources))
    
    def generate_report(self, metrics: RAGMetrics) -> str:
        """
        Generate human-readable evaluation report
        
        Args:
            metrics: RAGMetrics to report
        
        Returns:
            Formatted report string
        """
        report = f"""
╔══════════════════════════════════════════════════════════════╗
║           RAG CHATBOT EVALUATION REPORT                      ║
╚══════════════════════════════════════════════════════════════╝

📊 METRICS SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Total Queries Evaluated: {metrics.total_queries}
  Average Response Time:   {metrics.avg_response_time:.2f} seconds

🎯 QUALITY METRICS (vs. Targets)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  BLEU Score:             {metrics.bleu_score:.2f} / 100
    Target: > 40          {'✅ PASS' if metrics.bleu_score > 40 else '❌ FAIL'}
    
  ROUGE-L Score:          {metrics.rouge_l_score:.3f}
    Target: > 0.6         {'✅ PASS' if metrics.rouge_l_score > 0.6 else '❌ FAIL'}
    
  Hallucination Rate:     {metrics.hallucination_rate:.1%}
    Target: < 5%          {'✅ PASS' if metrics.hallucination_rate < 0.05 else '❌ FAIL'}
    
  Precision@5:            {metrics.precision_at_5:.1%}
    Target: > 80%         {'✅ PASS' if metrics.precision_at_5 > 0.8 else '❌ FAIL'}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🏆 OVERALL STATUS: {'✅ ALL TARGETS MET' if metrics.passes_targets() else '⚠️ NEEDS IMPROVEMENT'}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        return report
