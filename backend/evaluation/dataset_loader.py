"""
Dataset Loader for AI Evaluation

Loads and manages evaluation datasets:
- Gold-standard Q&A pairs for RAG chatbot
- Synthetic attack scenarios for path discovery
- Known vulnerabilities from OWASP test systems

Author: NTRO Intelligence Layer Team
Date: 2025-10-30
"""

import json
import os
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass


@dataclass
class QAPair:
    """Question-Answer pair for RAG evaluation"""
    question: str
    reference_answer: str
    expected_cves: List[str]
    category: str  # vulnerability_lookup, remediation, attack_path, general


@dataclass
class AttackScenario:
    """Attack scenario for path discovery evaluation"""
    scenario_id: str
    description: str
    hosts: List[Dict[str, Any]]
    vulnerabilities: List[Dict[str, Any]]
    expected_paths: List[List[str]]  # List of expected attack paths
    criticality: str  # low, medium, high, critical


class DatasetLoader:
    """Loads evaluation datasets from JSON files"""
    
    def __init__(self, dataset_dir: str = "./evaluation/datasets"):
        """
        Initialize dataset loader
        
        Args:
            dataset_dir: Directory containing dataset JSON files
        """
        self.dataset_dir = dataset_dir
        os.makedirs(dataset_dir, exist_ok=True)
    
    def load_rag_qa_pairs(self) -> List[QAPair]:
        """
        Load gold-standard Q&A pairs for RAG evaluation
        
        Returns:
            List of QAPair objects
        """
        filepath = os.path.join(self.dataset_dir, "rag_qa_pairs.json")
        
        # Create default dataset if not exists
        if not os.path.exists(filepath):
            default_pairs = self._create_default_qa_pairs()
            with open(filepath, 'w') as f:
                json.dump([vars(pair) for pair in default_pairs], f, indent=2)
            return default_pairs
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        return [QAPair(**item) for item in data]
    
    def load_attack_scenarios(self) -> List[AttackScenario]:
        """
        Load synthetic attack scenarios
        
        Returns:
            List of AttackScenario objects
        """
        filepath = os.path.join(self.dataset_dir, "attack_scenarios.json")
        
        # Create default dataset if not exists
        if not os.path.exists(filepath):
            default_scenarios = self._create_default_attack_scenarios()
            with open(filepath, 'w') as f:
                json.dump([vars(s) for s in default_scenarios], f, indent=2)
            return default_scenarios
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        return [AttackScenario(**item) for item in data]
    
    def _create_default_qa_pairs(self) -> List[QAPair]:
        """Create default Q&A pairs for initial testing"""
        return [
            QAPair(
                question="What is CVE-2023-12345?",
                reference_answer="CVE-2023-12345 is a remote code execution vulnerability in OpenSSH 7.4 with CVSS score 9.8. It allows unauthenticated attackers to execute arbitrary code via a crafted authentication request.",
                expected_cves=["CVE-2023-12345"],
                category="vulnerability_lookup"
            ),
            QAPair(
                question="How do I fix a remote code execution vulnerability in OpenSSH 7.4?",
                reference_answer="To fix RCE in OpenSSH 7.4: 1) Update to OpenSSH 9.0 or later, 2) Apply vendor security patches, 3) Configure firewall rules to restrict SSH access, 4) Enable key-based authentication only.",
                expected_cves=[],
                category="remediation"
            ),
            QAPair(
                question="Show me critical SSH vulnerabilities on host 192.168.1.50",
                reference_answer="Host 192.168.1.50 has 1 critical SSH vulnerability: CVE-2023-12345 (Port 22/SSH, CVSS 9.8) - Remote code execution via authentication bypass. Remediation: Update SSH to version 9.0+.",
                expected_cves=["CVE-2023-12345"],
                category="vulnerability_lookup"
            ),
            QAPair(
                question="What could an attacker do after exploiting SQL injection on a web server?",
                reference_answer="After SQL injection, an attacker could: 1) Extract database credentials, 2) Pivot to internal network via stored credentials, 3) Escalate privileges by exploiting database server vulnerabilities, 4) Access sensitive data or deploy ransomware.",
                expected_cves=[],
                category="attack_path"
            ),
            QAPair(
                question="What does a CVSS score of 9.8 mean?",
                reference_answer="CVSS 9.8 is a CRITICAL severity vulnerability. It indicates high exploitability, significant impact on confidentiality/integrity/availability, and should be patched immediately. Attackers can likely exploit remotely without authentication.",
                expected_cves=[],
                category="general"
            ),
        ]
    
    def _create_default_attack_scenarios(self) -> List[AttackScenario]:
        """Create default attack scenarios for testing"""
        return [
            AttackScenario(
                scenario_id="scenario_001",
                description="Web server RCE leading to database access",
                hosts=[
                    {"ip": "192.168.1.50", "role": "web_server", "os": "Linux"},
                    {"ip": "192.168.10.20", "role": "database", "os": "Linux"}
                ],
                vulnerabilities=[
                    {"cve": "CVE-2023-11111", "host": "192.168.1.50", "cvss": 9.8, "type": "RCE"},
                    {"cve": "CVE-2023-22222", "host": "192.168.10.20", "cvss": 7.5, "type": "weak_credentials"}
                ],
                expected_paths=[
                    ["192.168.1.50", "CVE-2023-11111", "192.168.10.20"]
                ],
                criticality="critical"
            ),
            AttackScenario(
                scenario_id="scenario_002",
                description="Multi-hop lateral movement via SSH",
                hosts=[
                    {"ip": "192.168.1.10", "role": "dmz_server", "os": "Linux"},
                    {"ip": "192.168.5.50", "role": "internal_app", "os": "Linux"},
                    {"ip": "192.168.10.100", "role": "domain_controller", "os": "Windows"}
                ],
                vulnerabilities=[
                    {"cve": "CVE-2023-33333", "host": "192.168.1.10", "cvss": 8.1, "type": "SSH_vuln"},
                    {"cve": "CVE-2023-44444", "host": "192.168.5.50", "cvss": 7.2, "type": "privilege_escalation"},
                    {"cve": "CVE-2023-55555", "host": "192.168.10.100", "cvss": 9.1, "type": "AD_exploit"}
                ],
                expected_paths=[
                    ["192.168.1.10", "CVE-2023-33333", "192.168.5.50", "CVE-2023-44444", "192.168.10.100"]
                ],
                criticality="high"
            ),
        ]
    
    def save_qa_pairs(self, qa_pairs: List[QAPair]):
        """Save Q&A pairs to JSON file"""
        filepath = os.path.join(self.dataset_dir, "rag_qa_pairs.json")
        with open(filepath, 'w') as f:
            json.dump([vars(pair) for pair in qa_pairs], f, indent=2)
    
    def save_attack_scenarios(self, scenarios: List[AttackScenario]):
        """Save attack scenarios to JSON file"""
        filepath = os.path.join(self.dataset_dir, "attack_scenarios.json")
        with open(filepath, 'w') as f:
            json.dump([vars(s) for s in scenarios], f, indent=2)
