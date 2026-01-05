"""
Run All AI Evaluations

Executes comprehensive evaluation of all AI components:
1. RAG Chatbot (BLEU, ROUGE, Hallucination, Precision@5)
2. Attack Path Modeling (Graph Build Time, F1 Score, Mitigation Ranking)

Usage:
    python -m evaluation.run_all_evals
    
Output:
    - Console report with metrics
    - JSON results saved to evaluation/results/evaluation_report.json
    - Optional PDF report

Author: NTRO Intelligence Layer Team
Date: 2025-10-30
"""

import os
import sys
import json
import logging
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from evaluation.rag_evaluator import RAGEvaluator
from evaluation.attack_path_evaluator import AttackPathEvaluator
from evaluation.dataset_loader import DatasetLoader
from intelligence_layer.rag.chatbot import RAGChatbot
from intelligence_layer.rag.retrieval_engine import RAGRetrievalEngine
from intelligence_layer.rag.indexing import VulnerabilityIndexer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def check_dependencies():
    """Check if required packages are installed"""
    missing_packages = []
    
    try:
        import nltk
    except ImportError:
        missing_packages.append('nltk')
    
    try:
        import rouge_score
    except ImportError:
        missing_packages.append('rouge-score')
    
    try:
        import scipy
    except ImportError:
        missing_packages.append('scipy')
    
    if missing_packages:
        logger.error(f"Missing required packages: {', '.join(missing_packages)}")
        logger.error(f"Install with: pip install {' '.join(missing_packages)}")
        return False
    
    return True


def initialize_rag_components():
    """Initialize RAG chatbot for evaluation"""
    logger.info("Initializing RAG components...")
    
    try:
        # Initialize components
        persist_dir = os.getenv('CHROMA_PERSIST_DIR', './chroma_db')
        indexer = VulnerabilityIndexer(persist_directory=persist_dir)
        
        retrieval_engine = RAGRetrievalEngine(indexer)
        
        ollama_url = os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')
        model_name = os.getenv('OLLAMA_MODEL', 'llama3.2:3b-instruct-q4_K_M')
        
        chatbot = RAGChatbot(
            retrieval_engine=retrieval_engine,
            ollama_base_url=ollama_url,
            model_name=model_name
        )
        
        logger.info("RAG components initialized successfully")
        return chatbot
    
    except Exception as e:
        logger.error(f"Failed to initialize RAG components: {e}")
        logger.error("Make sure Ollama is running: ollama serve")
        return None


def run_rag_evaluation(chatbot, dataset_loader):
    """Run RAG chatbot evaluation"""
    logger.info("\n" + "="*70)
    logger.info("STARTING RAG CHATBOT EVALUATION")
    logger.info("="*70 + "\n")
    
    try:
        evaluator = RAGEvaluator(chatbot, dataset_loader)
        metrics = evaluator.evaluate()
        report = evaluator.generate_report(metrics)
        
        print(report)
        return metrics.to_dict()
    
    except Exception as e:
        logger.error(f"RAG evaluation failed: {e}", exc_info=True)
        return None


def run_attack_path_evaluation(dataset_loader):
    """Run attack path modeling evaluation"""
    logger.info("\n" + "="*70)
    logger.info("STARTING ATTACK PATH MODELING EVALUATION")
    logger.info("="*70 + "\n")
    
    try:
        evaluator = AttackPathEvaluator(dataset_loader)
        metrics = evaluator.evaluate()
        report = evaluator.generate_report(metrics)
        
        print(report)
        return metrics.to_dict()
    
    except Exception as e:
        logger.error(f"Attack path evaluation failed: {e}", exc_info=True)
        return None


def save_results(results: dict, output_dir: str = "./evaluation/results"):
    """Save evaluation results to JSON file"""
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"evaluation_report_{timestamp}.json")
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    logger.info(f"\n✅ Results saved to: {output_file}")
    
    # Also save as latest
    latest_file = os.path.join(output_dir, "evaluation_report_latest.json")
    with open(latest_file, 'w') as f:
        json.dump(results, f, indent=2)


def main():
    """Main evaluation runner"""
    print("\n" + "="*70)
    print("  NTRO AI COMPONENTS COMPREHENSIVE EVALUATION")
    print("="*70 + "\n")
    
    # Check dependencies
    if not check_dependencies():
        logger.error("Please install missing dependencies and try again")
        return 1
    
    # Initialize dataset loader
    dataset_loader = DatasetLoader()
    
    results = {
        'evaluation_date': datetime.now().isoformat(),
        'rag_chatbot': None,
        'attack_path_modeling': None,
        'overall_status': 'INCOMPLETE'
    }
    
    # Run RAG evaluation
    chatbot = initialize_rag_components()
    if chatbot:
        rag_results = run_rag_evaluation(chatbot, dataset_loader)
        results['rag_chatbot'] = rag_results
    else:
        logger.warning("Skipping RAG evaluation (initialization failed)")
    
    # Run Attack Path evaluation
    attack_path_results = run_attack_path_evaluation(dataset_loader)
    results['attack_path_modeling'] = attack_path_results
    
    # Determine overall status
    all_passed = True
    if results['rag_chatbot']:
        all_passed = all_passed and results['rag_chatbot'].get('passes_targets', False)
    else:
        all_passed = False
    
    if results['attack_path_modeling']:
        all_passed = all_passed and results['attack_path_modeling'].get('passes_targets', False)
    else:
        all_passed = False
    
    results['overall_status'] = 'ALL TARGETS MET ✅' if all_passed else 'NEEDS IMPROVEMENT ⚠️'
    
    # Save results
    save_results(results)
    
    # Print summary
    print("\n" + "="*70)
    print(f"  OVERALL EVALUATION STATUS: {results['overall_status']}")
    print("="*70 + "\n")
    
    return 0 if all_passed else 1


if __name__ == '__main__':
    sys.exit(main())
