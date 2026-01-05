#!/usr/bin/env python3
"""
Test AI Summary Generation
Verifies that the updated Ollama health check and retry logic work correctly.
"""

import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from intelligence_layer.rag.ai_summary_generator import AISummaryGenerator, ScanData
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_ai_summary():
    """Test AI summary generation with sample data"""
    
    print("="*70)
    print("TEST 1: AI Summary Generation")
    print("="*70)
    
    try:
        # Initialize generator
        print("\n1. Initializing AI Summary Generator...")
        generator = AISummaryGenerator(
            ollama_base_url="http://localhost:11434",
            model_name="llama3.2:3b-instruct-q4_K_M",
            temperature=0.4
        )
        print("   ✅ Generator initialized")
        
        # Create test scan data
        print("\n2. Creating test scan data...")
        test_scan = ScanData(
            scan_id="test_001",
            tool_name="Nikto",
            scan_type="web_vulnerability",
            findings=[
                {
                    'cve_id': 'CVE-2024-1234',
                    'severity': 'critical',
                    'cvss_score': 9.8,
                    'title': 'Remote Code Execution in Apache HTTP Server',
                    'description': 'Path traversal vulnerability allows remote code execution',
                    'host': '192.168.1.100',
                    'port': 80,
                    'service': 'http'
                },
                {
                    'cve_id': 'CVE-2024-5678',
                    'severity': 'high',
                    'cvss_score': 7.5,
                    'title': 'SQL Injection in login form',
                    'description': 'Unvalidated input in authentication endpoint',
                    'host': '192.168.1.100',
                    'port': 443,
                    'service': 'https'
                },
                {
                    'cve_id': 'CVE-2024-9012',
                    'severity': 'medium',
                    'cvss_score': 5.3,
                    'title': 'Outdated jQuery library detected',
                    'description': 'jQuery 1.8.3 has known XSS vulnerabilities',
                    'host': '192.168.1.100',
                    'port': 443,
                    'service': 'https'
                }
            ],
            scan_date="2025-11-03T10:00:00Z"
        )
        print(f"   ✅ Created scan with {len(test_scan.findings)} findings")
        
        # Generate summary
        print("\n3. Generating AI summary (this may take 10-30 seconds)...")
        summary = generator.generate_scan_summary(test_scan, summary_type="scan_executive")
        print("   ✅ Summary generated successfully!")
        
        # Display results
        print("\n" + "="*70)
        print("GENERATED AI SUMMARY")
        print("="*70)
        
        print(f"\n📋 Title: {summary.title}")
        print(f"⚠️  Risk Level: {summary.risk_level} (Score: {summary.risk_score:.2f}/10)")
        print(f"🎯 Confidence: {summary.confidence:.0%}")
        
        print(f"\n📝 Executive Summary:")
        print(f"   {summary.executive_summary}")
        
        print(f"\n🔍 Key Findings:")
        for i, finding in enumerate(summary.key_findings, 1):
            print(f"   {i}. {finding}")
        
        print(f"\n💡 Recommendations:")
        for i, rec in enumerate(summary.recommendations, 1):
            print(f"   {i}. {rec}")
        
        if summary.related_cves:
            print(f"\n🔗 Related CVEs:")
            for cve in summary.related_cves:
                print(f"   - {cve}")
        
        print("\n" + "="*70)
        print("✅ TEST PASSED: AI summary generation works correctly!")
        print("="*70)
        
        return True
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_ollama_health():
    """Test Ollama health check function"""
    
    print("\n" + "="*70)
    print("TEST 2: Ollama Health Check")
    print("="*70)
    
    try:
        from api_gateway.scan_routes import check_ollama_health
        
        print("\n1. Checking Ollama health (10s timeout)...")
        health = check_ollama_health(timeout=10)
        
        print(f"\n   Available: {health['available']}")
        print(f"   Response Time: {health.get('response_time', 0):.2f}s")
        print(f"   Has Model: {health.get('has_model', False)}")
        print(f"   Models: {health.get('models', [])}")
        
        if health.get('error'):
            print(f"   Error: {health['error']}")
        
        if health['available']:
            print("\n✅ TEST PASSED: Ollama is healthy!")
            return True
        else:
            print("\n❌ TEST FAILED: Ollama not available")
            print(f"   Error: {health['error']}")
            return False
            
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    print("\n" + "🧪"*35)
    print("AI SUMMARY GENERATION TEST SUITE")
    print("🧪"*35)
    
    # Test 1: Ollama health
    test1_passed = test_ollama_health()
    
    # Test 2: AI summary generation
    test2_passed = test_ai_summary()
    
    # Final report
    print("\n" + "="*70)
    print("FINAL REPORT")
    print("="*70)
    print(f"Test 1 (Ollama Health): {'✅ PASSED' if test1_passed else '❌ FAILED'}")
    print(f"Test 2 (AI Summary):    {'✅ PASSED' if test2_passed else '❌ FAILED'}")
    print("="*70)
    
    if test1_passed and test2_passed:
        print("\n🎉 ALL TESTS PASSED! AI summary generation is working correctly.")
        print("\nNext steps:")
        print("  1. Run a scan to generate real vulnerabilities")
        print("  2. Check scan results for AI summary")
        print("  3. If summary is missing, use regenerate endpoint:")
        print("     POST http://localhost:8000/api/scans/{scan_id}/regenerate-summary")
        sys.exit(0)
    else:
        print("\n⚠️  SOME TESTS FAILED. Check errors above.")
        sys.exit(1)
