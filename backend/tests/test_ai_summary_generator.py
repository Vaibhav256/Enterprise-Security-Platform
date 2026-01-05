"""
Test AI Summary Generator
Tests AI-powered summary generation for scans and findings.
"""

import pytest
import json
from datetime import datetime

from intelligence_layer.rag.ai_summary_generator import (
    AISummaryGenerator,
    ScanData,
    AISummary,
    SummaryType
)


# Test data
SAMPLE_SCAN_FINDINGS = [
    {
        'id': '1',
        'cve': 'CVE-2023-44487',
        'title': 'HTTP/2 Rapid Reset Attack',
        'severity': 'critical',
        'cvss_score': 8.6,
        'description': 'HTTP/2 can be exploited for rapid reset attack',
        'host': '192.168.1.100',
        'affected_component': 'nginx',
        'cwe': 'CWE-400'
    },
    {
        'id': '2',
        'cve': 'CVE-2023-21839',
        'title': 'OpenSSL Vulnerability',
        'severity': 'high',
        'cvss_score': 7.5,
        'description': 'Remote code execution in OpenSSL',
        'host': '192.168.1.100',
        'affected_component': 'OpenSSL',
        'cwe': 'CWE-190'
    },
    {
        'id': '3',
        'title': 'SQL Injection on Login Form',
        'severity': 'critical',
        'cvss_score': 9.8,
        'description': 'Unvalidated input in login endpoint',
        'host': '192.168.1.101',
        'affected_component': 'web_app',
        'cwe': 'CWE-89'
    }
]


class TestAISummaryGenerator:
    """Test AISummaryGenerator class"""
    
    def test_generator_initialization(self):
        """Test generator initialization"""
        generator = AISummaryGenerator()
        assert generator.ollama_base_url == "http://localhost:11434"
        assert generator.model_name == "llama3.2:3b-instruct-q4_K_M"
        assert generator.temperature == 0.4
        assert generator.max_tokens == 1024
    
    def test_scan_data_creation(self):
        """Test ScanData object creation"""
        scan_data = ScanData(
            scan_id="test_scan_001",
            tool_name="nessus",
            scan_type="vulnerability",
            findings=SAMPLE_SCAN_FINDINGS,
            scan_date="2024-01-01T00:00:00",
            target="192.168.1.100"
        )
        
        assert scan_data.scan_id == "test_scan_001"
        assert scan_data.tool_name == "nessus"
        assert len(scan_data.findings) == 3
        assert scan_data.target == "192.168.1.100"
    
    def test_ai_summary_creation(self):
        """Test AISummary object creation"""
        summary = AISummary(
            summary_id="summary_001",
            type=SummaryType.SCAN_EXECUTIVE.value,
            title="Security Assessment Summary",
            executive_summary="Multiple critical vulnerabilities detected.",
            key_findings=["HTTP/2 Rapid Reset", "OpenSSL RCE", "SQL Injection"],
            risk_score=0.85,
            risk_level="CRITICAL",
            recommendations=["Patch HTTP/2", "Update OpenSSL", "Sanitize inputs"],
            source_tool="nessus",
            confidence=0.9
        )
        
        assert summary.summary_id == "summary_001"
        assert summary.risk_level == "CRITICAL"
        assert len(summary.key_findings) == 3
        assert summary.confidence == 0.9
    
    def test_ai_summary_to_dict(self):
        """Test AISummary.to_dict()"""
        summary = AISummary(
            summary_id="summary_001",
            type=SummaryType.SCAN_EXECUTIVE.value,
            title="Test Summary",
            executive_summary="Test executive summary",
            key_findings=["Finding 1", "Finding 2"],
            risk_score=0.7,
            risk_level="HIGH",
            recommendations=["Action 1", "Action 2"]
        )
        
        summary_dict = summary.to_dict()
        assert summary_dict['summary_id'] == "summary_001"
        assert summary_dict['type'] == SummaryType.SCAN_EXECUTIVE.value
        assert summary_dict['risk_level'] == "HIGH"
    
    def test_ai_summary_to_markdown(self):
        """Test AISummary.to_markdown()"""
        summary = AISummary(
            summary_id="summary_001",
            type=SummaryType.SCAN_EXECUTIVE.value,
            title="Test Summary",
            executive_summary="Executive summary text",
            key_findings=["Finding 1", "Finding 2"],
            risk_score=0.8,
            risk_level="HIGH",
            recommendations=["Action 1", "Action 2"],
            confidence=0.85
        )
        
        markdown = summary.to_markdown()
        assert "# Test Summary" in markdown
        assert "HIGH" in markdown
        assert "Finding 1" in markdown
        assert "Action 1" in markdown
        assert "85%" in markdown
    
    def test_extract_json_from_text(self):
        """Test JSON extraction from LLM response"""
        generator = AISummaryGenerator()
        
        text_with_json = """
        Some explanation text...
        {
            "title": "Test",
            "risk_score": 0.5
        }
        More explanation...
        """
        
        extracted = generator._extract_json(text_with_json)
        assert extracted
        parsed = json.loads(extracted)
        assert parsed['title'] == "Test"
        assert parsed['risk_score'] == 0.5
    
    def test_summarize_findings(self):
        """Test finding summary generation"""
        generator = AISummaryGenerator()
        summary = generator._summarize_findings(SAMPLE_SCAN_FINDINGS)
        
        assert "HTTP/2 Rapid Reset Attack" in summary
        assert "OpenSSL Vulnerability" in summary
        assert "SQL Injection" in summary
        assert "CRITICAL" in summary or "critical" in summary.lower()
    
    def test_group_findings_by_severity(self):
        """Test severity grouping"""
        generator = AISummaryGenerator()
        grouped = generator._group_findings_by_severity(SAMPLE_SCAN_FINDINGS)
        
        assert "CRITICAL" in grouped
        assert "HIGH" in grouped
        assert grouped.count("2 issues") > 0  # 2 critical findings
    
    def test_prepare_scan_context(self):
        """Test scan context preparation"""
        generator = AISummaryGenerator()
        scan_data = ScanData(
            scan_id="test_scan",
            tool_name="nessus",
            scan_type="vulnerability",
            findings=SAMPLE_SCAN_FINDINGS,
            scan_date="2024-01-01"
        )
        
        context = generator._prepare_scan_context(scan_data)
        assert "nessus" in context
        assert "3" in context  # Total findings
        assert "HTTP/2" in context
    
    def test_prepare_finding_context(self):
        """Test finding context preparation"""
        generator = AISummaryGenerator()
        finding = SAMPLE_SCAN_FINDINGS[0]
        
        context = generator._prepare_finding_context(finding, "nessus")
        assert "CVE-2023-44487" in context
        assert "HTTP/2" in context
        assert "nessus" in context
    
    def test_prepare_risk_context(self):
        """Test risk assessment context"""
        generator = AISummaryGenerator()
        scan_data = ScanData(
            scan_id="test_scan",
            tool_name="openvas",
            scan_type="vulnerability",
            findings=SAMPLE_SCAN_FINDINGS
        )
        
        context = generator._prepare_risk_context(scan_data)
        assert "CRITICAL" in context
        assert "HIGH" in context
        assert "risk assessment" in context.lower()
    
    def test_prepare_remediation_context(self):
        """Test remediation planning context"""
        generator = AISummaryGenerator()
        scan_data = ScanData(
            scan_id="test_scan",
            tool_name="qualys",
            scan_type="vulnerability",
            findings=SAMPLE_SCAN_FINDINGS
        )
        
        context = generator._prepare_remediation_context(scan_data)
        assert "remediation" in context.lower()
        assert "priority" in context.lower()
        assert "3" in context  # 3 findings


class TestScanAISummarizer:
    """Test ScanAISummarizer integration"""
    
    def test_summarizer_initialization(self):
        """Test ScanAISummarizer initialization"""
        from intelligence_layer.rag.scan_processor import ScanAISummarizer
        
        summarizer = ScanAISummarizer()
        assert summarizer.summary_generator is None  # Lazy-loaded
    
    def test_format_summary_as_markdown(self):
        """Test markdown formatting"""
        from intelligence_layer.rag.scan_processor import ScanAISummarizer
        
        summary = {
            'title': 'Security Assessment',
            'risk_level': 'CRITICAL',
            'risk_score': 0.9,
            'executive_summary': 'Critical vulnerabilities found',
            'key_findings': ['Finding 1', 'Finding 2'],
            'recommendations': ['Action 1', 'Action 2'],
            'confidence': 0.85
        }
        
        markdown = ScanAISummarizer._format_summary_as_markdown(summary)
        assert "# Security Assessment" in markdown
        assert "CRITICAL" in markdown
        assert "Finding 1" in markdown
        assert "85%" in markdown


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
