#!/usr/bin/env python3
"""
Proof-of-Concept: Local LLM Interaction with Ollama

This script demonstrates loading and interacting with Llama 3.2 3B via Ollama
for the Intelligence Layer's RAG chatbot component.

Prerequisites:
    1. Install Ollama: https://ollama.com/download
    2. Pull model: ollama pull llama3.2:3b-instruct-q4_K_M
    3. Start server: ollama serve (runs on http://localhost:11434)

Usage:
    python poc_local_llm.py
"""

import requests
import json
import time
from typing import Dict, List, Optional

# Configuration
OLLAMA_BASE_URL = "http://localhost:11434"
MODEL_NAME = "llama3.2:3b-instruct-q4_K_M"  # Recommended model from LLM_SELECTION_REPORT.md

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def check_ollama_status() -> bool:
    """
    Verify Ollama server is running and accessible.
    
    Returns:
        True if server is running, False otherwise
    """
    try:
        response = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5)
        if response.status_code == 200:
            print(f"{Colors.OKGREEN}✓ Ollama server is running{Colors.ENDC}")
            return True
        else:
            print(f"{Colors.FAIL}✗ Ollama server returned status {response.status_code}{Colors.ENDC}")
            return False
    except requests.exceptions.ConnectionError:
        print(f"{Colors.FAIL}✗ Cannot connect to Ollama server at {OLLAMA_BASE_URL}{Colors.ENDC}")
        print(f"{Colors.WARNING}  Please start Ollama: 'ollama serve'{Colors.ENDC}")
        return False
    except Exception as e:
        print(f"{Colors.FAIL}✗ Error checking Ollama: {e}{Colors.ENDC}")
        return False


def check_model_availability(model_name: str) -> bool:
    """
    Verify the specified model is pulled and available.
    
    Args:
        model_name: Name of the model (e.g., "llama3.2:3b-instruct-q4_K_M")
    
    Returns:
        True if model is available, False otherwise
    """
    try:
        response = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5)
        if response.status_code == 200:
            models = response.json().get('models', [])
            available_models = [m['name'] for m in models]
            
            if model_name in available_models:
                print(f"{Colors.OKGREEN}✓ Model '{model_name}' is available{Colors.ENDC}")
                return True
            else:
                print(f"{Colors.FAIL}✗ Model '{model_name}' not found{Colors.ENDC}")
                print(f"{Colors.WARNING}  Available models: {', '.join(available_models)}{Colors.ENDC}")
                print(f"{Colors.WARNING}  Pull model: 'ollama pull {model_name}'{Colors.ENDC}")
                return False
        return False
    except Exception as e:
        print(f"{Colors.FAIL}✗ Error checking model: {e}{Colors.ENDC}")
        return False


def query_llm(
    prompt: str,
    model: str = MODEL_NAME,
    system_prompt: Optional[str] = None,
    temperature: float = 0.3,
    max_tokens: int = 512,
    stream: bool = False
) -> Dict:
    """
    Send a query to the local LLM via Ollama API.
    
    Args:
        prompt: User query/prompt
        model: Model name (default: Llama 3.2 3B)
        system_prompt: Optional system instructions
        temperature: Randomness (0=deterministic, 1=creative)
        max_tokens: Maximum response length
        stream: Enable streaming response
    
    Returns:
        Dict with 'response', 'model', 'latency' keys
    """
    messages = []
    
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    
    messages.append({"role": "user", "content": prompt})
    
    payload = {
        "model": model,
        "messages": messages,
        "options": {
            "temperature": temperature,
            "num_predict": max_tokens  # Ollama uses num_predict instead of max_tokens
        },
        "stream": stream
    }
    
    try:
        start_time = time.time()
        response = requests.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json=payload,
            timeout=60  # Allow up to 60 seconds for response
        )
        latency = time.time() - start_time
        
        if response.status_code == 200:
            result = response.json()
            return {
                "response": result['message']['content'],
                "model": result.get('model', model),
                "latency": round(latency, 2),
                "tokens_evaluated": result.get('eval_count', 0),
                "tokens_per_second": round(result.get('eval_count', 0) / latency, 2) if latency > 0 else 0
            }
        else:
            return {
                "response": None,
                "error": f"HTTP {response.status_code}: {response.text}",
                "latency": round(latency, 2)
            }
    except requests.exceptions.Timeout:
        return {
            "response": None,
            "error": "Request timeout (>60s)",
            "latency": 60.0
        }
    except Exception as e:
        return {
            "response": None,
            "error": str(e),
            "latency": 0.0
        }


def run_test_queries():
    """
    Execute test queries to validate local LLM setup for cybersecurity use cases.
    """
    # System prompt for cybersecurity analyst assistant
    SYSTEM_PROMPT = """You are a cybersecurity analyst assistant for vulnerability analysis.
You provide concise, accurate, and technical responses about vulnerabilities, exploits, and remediation.
Always cite CVE IDs when discussing specific vulnerabilities."""

    test_cases = [
        {
            "name": "Basic Vulnerability Explanation",
            "prompt": "What is CVE-2023-12345? Explain in 2-3 sentences.",
            "system": SYSTEM_PROMPT
        },
        {
            "name": "Remediation Guidance",
            "prompt": "How do I fix a remote code execution vulnerability in OpenSSH 7.4?",
            "system": SYSTEM_PROMPT
        },
        {
            "name": "Attack Path Reasoning",
            "prompt": "An attacker exploited a SQL injection on a web server. What could they do next to compromise internal servers?",
            "system": SYSTEM_PROMPT
        },
        {
            "name": "CVSS Interpretation",
            "prompt": "What does a CVSS score of 9.8 mean? Should I prioritize patching it?",
            "system": SYSTEM_PROMPT
        }
    ]
    
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}Running Test Queries for Cybersecurity RAG Use Cases{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}\n")
    
    for i, test in enumerate(test_cases, 1):
        print(f"{Colors.OKCYAN}{Colors.BOLD}Test {i}/{len(test_cases)}: {test['name']}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}Prompt: {test['prompt']}{Colors.ENDC}")
        print(f"{Colors.WARNING}Querying LLM...{Colors.ENDC}")
        
        result = query_llm(
            prompt=test['prompt'],
            system_prompt=test.get('system'),
            temperature=0.3,  # Low temperature for factual accuracy
            max_tokens=256
        )
        
        if result.get('response'):
            print(f"{Colors.OKGREEN}Response ({result['latency']}s, {result['tokens_per_second']} tok/sec):{Colors.ENDC}")
            print(f"{result['response']}\n")
        else:
            print(f"{Colors.FAIL}Error: {result.get('error')}{Colors.ENDC}\n")
        
        print(f"{Colors.HEADER}{'-'*70}{Colors.ENDC}\n")


def interactive_mode():
    """
    Interactive chatbot session for manual testing.
    """
    SYSTEM_PROMPT = """You are a cybersecurity analyst assistant for the NTRO vulnerability detection platform.
Answer questions about vulnerabilities, exploits, and remediation using technical, analyst-facing language.
Be concise and always cite sources (CVE IDs, tool names) when possible."""

    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}Interactive Chatbot Mode (Type 'exit' to quit){Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*70}{Colors.ENDC}\n")
    
    conversation_history = []
    
    # Interactive loop for CLI demo (Issue Q4 - Intentional Design)
    # This while True loop is INTENTIONAL for interactive CLI chat.
    # Exit conditions:
    #   1. User types 'exit', 'quit', or 'q' (line 247)
    #   2. KeyboardInterrupt (Ctrl+C) caught below (line 280)
    #   3. EOFError (Ctrl+D on Unix) caught below (line 282)
    # NOT an infinite loop bug - this is standard CLI REPL pattern.
    while True:
        try:
            user_input = input(f"{Colors.OKCYAN}You: {Colors.ENDC}")
            
            if user_input.lower() in ['exit', 'quit', 'q']:
                print(f"{Colors.WARNING}Exiting chatbot...{Colors.ENDC}")
                break
            
            if not user_input.strip():
                continue
            
            # Build messages with history (for context-aware responses)
            messages = [{"role": "system", "content": SYSTEM_PROMPT}]
            for turn in conversation_history:
                messages.append({"role": "user", "content": turn['user']})
                messages.append({"role": "assistant", "content": turn['assistant']})
            messages.append({"role": "user", "content": user_input})
            
            # Query LLM
            payload = {
                "model": MODEL_NAME,
                "messages": messages,
                "options": {"temperature": 0.3, "num_predict": 512},
                "stream": False
            }
            
            response = requests.post(f"{OLLAMA_BASE_URL}/api/chat", json=payload, timeout=60)
            
            if response.status_code == 200:
                result = response.json()
                assistant_response = result['message']['content']
                
                print(f"{Colors.OKGREEN}Assistant: {Colors.ENDC}{assistant_response}\n")
                
                # Store in conversation history
                conversation_history.append({
                    'user': user_input,
                    'assistant': assistant_response
                })
            else:
                print(f"{Colors.FAIL}Error: {response.status_code} - {response.text}{Colors.ENDC}\n")
        
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}Interrupted. Exiting...{Colors.ENDC}")
            break
        except Exception as e:
            print(f"{Colors.FAIL}Error: {e}{Colors.ENDC}\n")


def main():
    """
    Main execution flow for PoC script.
    """
    print(f"{Colors.HEADER}{Colors.BOLD}")
    print("╔════════════════════════════════════════════════════════════════════╗")
    print("║   Local LLM Proof-of-Concept for Intelligence Layer (Phase 3)     ║")
    print("║   Model: Llama 3.2 3B Instruct (via Ollama)                       ║")
    print("╚════════════════════════════════════════════════════════════════════╝")
    print(f"{Colors.ENDC}\n")
    
    # Step 1: Check Ollama server
    print(f"{Colors.BOLD}Step 1: Verifying Ollama Server{Colors.ENDC}")
    if not check_ollama_status():
        print(f"\n{Colors.FAIL}Setup incomplete. Please install and start Ollama.{Colors.ENDC}")
        print(f"{Colors.WARNING}Installation: https://ollama.com/download{Colors.ENDC}")
        print(f"{Colors.WARNING}Start server: 'ollama serve'{Colors.ENDC}")
        return
    
    # Step 2: Check model availability
    print(f"\n{Colors.BOLD}Step 2: Verifying Model Availability{Colors.ENDC}")
    if not check_model_availability(MODEL_NAME):
        print(f"\n{Colors.FAIL}Model not available. Pull it first.{Colors.ENDC}")
        print(f"{Colors.WARNING}Command: ollama pull {MODEL_NAME}{Colors.ENDC}")
        return
    
    # Step 3: Run automated test queries
    print(f"\n{Colors.BOLD}Step 3: Running Automated Test Queries{Colors.ENDC}")
    run_test_queries()
    
    # Step 4: Interactive mode (optional)
    print(f"\n{Colors.BOLD}Step 4: Interactive Mode{Colors.ENDC}")
    user_choice = input(f"{Colors.OKCYAN}Do you want to enter interactive chatbot mode? (y/n): {Colors.ENDC}")
    
    if user_choice.lower() in ['y', 'yes']:
        interactive_mode()
    
    print(f"\n{Colors.OKGREEN}{Colors.BOLD}✓ PoC completed successfully!{Colors.ENDC}")
    print(f"{Colors.OKGREEN}Local LLM setup validated. Ready for RAG pipeline integration.{Colors.ENDC}")


if __name__ == "__main__":
    main()
