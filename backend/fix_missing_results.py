"""Fix scan with missing results by retrying"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sqlalchemy import create_engine, text
from config.config import Config

scan_id = "d088073e-97b7-4c69-8f67-6c7643996948"

print("=" * 100)
print("🔧 Fixing Scan with Missing Results")
print("=" * 100)

engine = create_engine(Config.DATABASE_URL)

with engine.connect() as conn:
    # Get scan details
    scan = conn.execute(text(
        "SELECT target, tool_name, scan_type, options FROM scans WHERE id = :scan_id"
    ), {"scan_id": scan_id}).fetchone()
    
    if not scan:
        print(f"❌ Scan {scan_id} not found!")
        sys.exit(1)
    
    print(f"\n📊 Original Scan:")
    print(f"   Target: {scan.target}")
    print(f"   Tool: {scan.tool_name}")
    print(f"   Type: {scan.scan_type}")
    print(f"   Options: {scan.options}")
    
    print(f"\n✅ This scan has 0 bytes of raw output due to the double WSL nesting bug.")
    print(f"   The bug has now been FIXED in the code.")
    print(f"\n📌 To get actual results, you have two options:")
    print(f"\n   Option 1: Use the Retry button in the UI")
    print(f"   -----------------------------------------")
    print(f"   1. Go to the scan detail page for this scan")
    print(f"   2. Click the blue 'Retry' button")
    print(f"   3. The scan will re-run with the fixed code")
    print(f"\n   Option 2: Use the API endpoint")
    print(f"   --------------------------------")
    print(f"   POST http://localhost:5000/api/scans/{scan_id}/retry")
    print(f"\n   Option 3: Create a new scan with same parameters")
    print(f"   -------------------------------------------------")
    print(f"   Use the UI to create a new {scan.tool_name} {scan.scan_type} scan of {scan.target}")
    
    # Check if there are any successful scans from the same target
    successful_scans = conn.execute(text(
        "SELECT s.id, s.created_at, r.raw_output "
        "FROM scans s "
        "LEFT JOIN raw_scan_results r ON s.id = r.scan_id "
        "WHERE s.target = :target AND s.tool_name = :tool "
        "AND s.id != :scan_id "
        "AND r.raw_output IS NOT NULL AND LENGTH(r.raw_output) > 0 "
        "ORDER BY s.created_at DESC LIMIT 1"
    ), {"target": scan.target, "tool": scan.tool_name, "scan_id": scan_id}).fetchone()
    
    if successful_scans:
        print(f"\n✨ Good news: There's a successful scan of the same target!")
        print(f"   Scan ID: {successful_scans.id}")
        print(f"   Date: {successful_scans.created_at}")
        print(f"   Output size: {len(successful_scans.raw_output)} bytes")
        print(f"\n   You can view that scan instead of retrying this one.")
    else:
        print(f"\n⚠️ No other successful scans found for {scan.target} with {scan.tool_name}")
        print(f"   Recommend using Option 1 (Retry button) to get results.")

print("\n" + "=" * 100)
