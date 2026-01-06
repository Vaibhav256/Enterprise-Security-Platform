"""Check scan data and generate missing results/summaries"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sqlalchemy import create_engine, text
from config.config import Config

scan_id = "d088073e-97b7-4c69-8f67-6c7643996948"

engine = create_engine(Config.DATABASE_URL)

with engine.connect() as conn:
    # Check scan details
    scan = conn.execute(text(
        "SELECT id, target, tool_name, scan_type, status, created_at, started_at, completed_at "
        "FROM scans WHERE id = :scan_id"
    ), {"scan_id": scan_id}).fetchone()
    
    if not scan:
        print(f"❌ Scan {scan_id} not found!")
        sys.exit(1)
    
    print("=" * 100)
    print(f"📊 Scan Details:")
    print(f"ID: {scan.id}")
    print(f"Target: {scan.target}")
    print(f"Tool: {scan.tool_name}")
    print(f"Type: {scan.scan_type}")
    print(f"Status: {scan.status}")
    print(f"Created: {scan.created_at}")
    print(f"Started: {scan.started_at}")
    print(f"Completed: {scan.completed_at}")
    print("=" * 100)
    
    # Check raw results
    raw_results = conn.execute(text(
        "SELECT id, scan_id, tool_name, raw_output, created_at "
        "FROM raw_scan_results WHERE scan_id = :scan_id"
    ), {"scan_id": scan_id}).fetchone()
    
    print(f"\n📄 Raw Results:")
    if raw_results:
        output_preview = raw_results.raw_output[:500] if raw_results.raw_output else "Empty"
        print(f"✅ Exists (ID: {raw_results.id})")
        print(f"   Created: {raw_results.created_at}")
        print(f"   Output length: {len(raw_results.raw_output) if raw_results.raw_output else 0} bytes")
        print(f"   Preview: {output_preview}...")
    else:
        print("❌ No raw results found")
    
    # Check AI summary
    summary = conn.execute(text(
        "SELECT id, scan_id, ai_summary, created_at "
        "FROM scan_summaries WHERE scan_id = :scan_id"
    ), {"scan_id": scan_id}).fetchone()
    
    print(f"\n🤖 AI Summary:")
    if summary:
        print(f"✅ Exists (ID: {summary.id})")
        print(f"   Created: {summary.created_at}")
        if summary.ai_summary:
            print(f"   Summary preview: {str(summary.ai_summary)[:200]}...")
        else:
            print("   ⚠️ Summary is NULL/empty")
    else:
        print("❌ No summary record found")
    
    # Check findings count
    findings_count = conn.execute(text(
        "SELECT COUNT(*) as count FROM raw_scan_results "
        "WHERE scan_id = :scan_id AND raw_output IS NOT NULL AND raw_output != ''"
    ), {"scan_id": scan_id}).fetchone()
    
    print(f"\n📈 Findings: {findings_count.count if findings_count else 0}")
    
    print("\n" + "=" * 100)
    print("🔧 Recommendations:")
    
    if not raw_results or not raw_results.raw_output:
        print("❌ Raw results are missing - scan may have failed or timed out without capturing output")
        print("   Solution: Re-run the scan or check logs for errors")
    
    if scan.status != "COMPLETED":
        print(f"❌ Scan status is {scan.status} instead of COMPLETED")
        print("   Solution: Check why scan didn't complete successfully")
    
    if raw_results and raw_results.raw_output and not summary:
        print("✅ Raw results exist but summary is missing")
        print("   Solution: Run AI summary generation task manually")
        print(f"   Command: python -c \"from services.scan_orchestrator.tasks import generate_ai_summary; generate_ai_summary('{scan_id}')\"")
    
    if not raw_results and scan.status == "COMPLETED":
        print("⚠️ Scan marked as COMPLETED but no raw results stored")
        print("   This might be a data ingestion issue")
