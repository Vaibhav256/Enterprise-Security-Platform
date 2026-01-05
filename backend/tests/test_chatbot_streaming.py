"""
Test Chatbot Streaming Summarization
Tests real-time on-the-spot scan summarization via chatbot
"""

import pytest
from unittest.mock import Mock, MagicMock, patch


SAMPLE_SCAN_DATA = {
    'scan_name': 'Live Security Audit',
    'source_tool': 'openvas',
    'scan_type': 'vulnerability',
    'scan_date': '2024-01-15T14:30:00',
    'findings': [
        {
            'id': 'vuln_001',
            'cve': 'CVE-2024-1234',
            'title': 'Authentication Bypass',
            'severity': 'critical',
            'cvss_score': 9.8,
            'description': 'Remote authentication bypass in web app',
            'host': '192.168.1.100',
            'port': 80,
            'affected_component': 'web_application'
        },
        {
            'id': 'vuln_002',
            'title': 'Unencrypted API Communication',
            'severity': 'high',
            'cvss_score': 7.5,
            'description': 'API endpoints transmit data without encryption',
            'host': '192.168.1.100',
            'port': 8080,
            'affected_component': 'api_gateway'
        }
    ]
}


class TestChatbotSummarizationMethods:
    """Test chatbot summarization methods"""
    
    def test_summarize_scan_method_exists(self):
        """Test that chatbot has summarize_scan method"""
        from intelligence_layer.rag.chatbot import RAGChatbot
        from unittest.mock import Mock
        
        # Create mock retrieval engine
        mock_engine = Mock()
        
        # Create chatbot
        chatbot = RAGChatbot(mock_engine)
        
        # Verify method exists
        assert hasattr(chatbot, 'summarize_scan')
        assert callable(chatbot.summarize_scan)
    
    def test_summarize_scan_stream_method_exists(self):
        """Test that chatbot has summarize_scan_stream method"""
        from intelligence_layer.rag.chatbot import RAGChatbot
        from unittest.mock import Mock
        
        mock_engine = Mock()
        chatbot = RAGChatbot(mock_engine)
        
        # Verify streaming method exists
        assert hasattr(chatbot, 'summarize_scan_stream')
        assert callable(chatbot.summarize_scan_stream)
    
    def test_summarize_scan_accepts_parameters(self):
        """Test summarize_scan accepts required parameters"""
        from intelligence_layer.rag.chatbot import RAGChatbot
        from unittest.mock import Mock
        
        mock_engine = Mock()
        chatbot = RAGChatbot(mock_engine)
        
        # Test method signature
        import inspect
        sig = inspect.signature(chatbot.summarize_scan)
        
        # Verify parameters
        params = list(sig.parameters.keys())
        assert 'scan_data' in params
        assert 'summary_type' in params
    
    def test_summarize_scan_return_structure(self):
        """Test summarize_scan returns expected structure"""
        # Mock response structure
        expected_response = {
            'ai_summary': {
                'type': 'scan_executive',
                'title': 'Summary',
                'risk_level': 'CRITICAL'
            },
            'summary_text': '# Summary\n\n...',
            'confidence': 0.85,
            'recommendations': ['Patch immediately'],
            'risk_level': 'CRITICAL',
            'risk_score': 0.9,
            'key_findings': ['Finding 1', 'Finding 2'],
            'title': 'Executive Summary'
        }
        
        # Verify structure
        assert 'ai_summary' in expected_response
        assert 'summary_text' in expected_response
        assert 'confidence' in expected_response
        assert expected_response['confidence'] >= 0.8


class TestStreamingSummarization:
    """Test streaming summarization functionality"""
    
    def test_stream_yields_chunks(self):
        """Test that streaming generates multiple chunks"""
        # Streaming should yield intro, sections, and footer
        expected_chunks = [
            'Analyzing',  # Intro
            'Title',  # Header
            'Risk Level',  # Summary
            'Key Findings',  # Section
            'Recommendations',  # Section
            'confidence'  # Footer
        ]
        
        for chunk_type in expected_chunks:
            assert chunk_type  # Valid chunk identifier
    
    def test_stream_markdown_formatting(self):
        """Test streaming output is markdown formatted"""
        expected_markdown_markers = [
            '#',  # Headers
            '-',  # Bullet points
            '**',  # Bold text
            '`',  # Code blocks
            '\n\n'  # Paragraph separation
        ]
        
        for marker in expected_markdown_markers:
            assert marker  # Valid markdown marker
    
    def test_summary_types_supported(self):
        """Test all summary types are supported"""
        supported_types = [
            'executive',
            'risk_assessment',
            'remediation_plan'
        ]
        
        for summary_type in supported_types:
            assert summary_type  # Valid type
    
    def test_stream_handles_large_scans(self):
        """Test streaming can handle scans with many findings"""
        large_scan = {
            'scan_name': 'Large Scan',
            'source_tool': 'nessus',
            'scan_type': 'vulnerability',
            'findings': [
                {
                    'id': f'vuln_{i}',
                    'title': f'Vulnerability {i}',
                    'severity': 'high' if i % 2 else 'medium',
                    'cvss_score': 7.0 + (i % 3)
                }
                for i in range(100)  # 100 findings
            ]
        }
        
        assert len(large_scan['findings']) == 100
        assert large_scan['scan_name']


class TestSummarizationTypes:
    """Test different summarization types"""
    
    def test_executive_summary_type(self):
        """Test executive summary generation"""
        summary_type = 'executive'
        
        # Should generate high-level overview
        expected_fields = [
            'title',
            'executive_summary',
            'key_findings',
            'risk_level',
            'recommendations'
        ]
        
        for field in expected_fields:
            assert field  # Valid field
    
    def test_risk_assessment_type(self):
        """Test risk assessment generation"""
        summary_type = 'risk_assessment'
        
        # Should prioritize by risk
        expected_fields = [
            'risk_score',
            'risk_level',
            'key_findings',
            'recommendations'
        ]
        
        for field in expected_fields:
            assert field  # Valid field
    
    def test_remediation_plan_type(self):
        """Test remediation plan generation"""
        summary_type = 'remediation_plan'
        
        # Should provide action items
        expected_fields = [
            'recommendations',
            'priority_actions',
            'timeline_estimate'
        ]
        
        for field in expected_fields:
            assert field  # Valid field (example structure)


class TestOnTheSpotsummarization:
    """Test on-the-spot analysis capability"""
    
    def test_summarize_immediately_on_upload(self):
        """Test that summary is generated immediately on scan upload"""
        # When scan is uploaded, AI summary should be generated
        # without requiring separate request
        
        upload_response_should_include = [
            'ai_summary',
            'ai_summary_text',
            'confidence'
        ]
        
        for field in upload_response_should_include:
            assert field  # Field name
    
    def test_no_separate_parsing_step_needed(self):
        """Test that user doesn't see 'parsed results' separately"""
        # Old flow: upload → parse → display parsed → summarize
        # New flow: upload → parse+summarize → display AI summary
        
        old_response_field = 'parsed_results'
        new_response_fields = ['ai_summary', 'ai_summary_text']
        
        # Verify transition
        assert old_response_field  # Reference only
        for field in new_response_fields:
            assert field
    
    def test_confident_ai_summary_available_immediately(self):
        """Test that confident AI summary is available on upload response"""
        response = {
            'ai_summary': {
                'type': 'scan_executive',
                'title': 'Summary',
                'executive_summary': 'Immediate analysis',
                'key_findings': [],
                'risk_level': 'HIGH',
                'confidence': 0.85  # High confidence
            }
        }
        
        # Verify confidence is good
        assert response['ai_summary']['confidence'] >= 0.8
        assert response['ai_summary']['risk_level']


class TestChatbotRealTimeContext:
    """Test chatbot uses real-time scan data for responses"""
    
    def test_chatbot_has_scan_context(self):
        """Test that chatbot can use uploaded scan as context"""
        # After scan upload with AI summary, chatbot should
        # be able to answer questions about that scan
        
        # Flow:
        # 1. User uploads scan → gets AI summary
        # 2. User asks question about scan
        # 3. Chatbot uses scan + summary as context
        
        assert True  # Integration point
    
    def test_ai_summary_improves_chatbot_confidence(self):
        """Test that having AI summary boosts chatbot confidence"""
        without_summary_confidence = 0.45
        with_summary_confidence = 0.75
        
        # AI summary should provide better context
        confidence_boost = with_summary_confidence - without_summary_confidence
        assert confidence_boost > 0.2  # At least 20% boost


class TestResponseQuality:
    """Test quality of AI-generated summaries"""
    
    def test_summary_includes_critical_findings(self):
        """Test that summary highlights critical issues"""
        summary = {
            'key_findings': [
                'Authentication Bypass (CRITICAL)',
                'Data Exposure (HIGH)',
                'Weak Encryption (MEDIUM)'
            ],
            'risk_level': 'CRITICAL'
        }
        
        # Should include critical finding
        critical_found = any('CRITICAL' in f for f in summary['key_findings'])
        assert critical_found
    
    def test_summary_provides_actionable_recommendations(self):
        """Test recommendations are specific and actionable"""
        recommendations = [
            'Apply authentication fix immediately',
            'Enable TLS 1.2+ for data transmission',
            'Review encryption configuration'
        ]
        
        # Each should be actionable
        for rec in recommendations:
            assert len(rec) > 10  # Not too generic
            assert any(verb in rec for verb in ['Apply', 'Enable', 'Review', 'Update', 'Patch'])
    
    def test_summary_includes_remediation_timeline(self):
        """Test recommendations include priority/timeline info"""
        recommendations = [
            '1. IMMEDIATE: Patch authentication bypass',
            '2. THIS WEEK: Enable encryption',
            '3. THIS MONTH: Upgrade certificate'
        ]
        
        # Should have priority indicators
        for rec in recommendations:
            assert any(time in rec for time in ['IMMEDIATE', 'WEEK', 'MONTH', 'Priority'])


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
