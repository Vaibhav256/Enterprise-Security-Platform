"""
Check if AI summaries are still in database
"""
import sys
sys.path.insert(0, 'D:\\ESP\\backend')

from config.database import DATABASE_URL
from sqlalchemy import create_engine, text

engine = create_engine(DATABASE_URL)

with engine.connect() as conn:
    # Check for AI summaries in scan_summaries table
    result = conn.execute(text("""
        SELECT COUNT(*) as total_scans,
               COUNT(CASE WHEN ai_summary IS NOT NULL THEN 1 END) as scans_with_ai_summary
        FROM scan_summaries
    """))
    
    summary = result.fetchone()
    
    print(f"\n📊 AI Summary Status:")
    print("=" * 60)
    print(f"Total scans: {summary[0]}")
    print(f"Scans with AI summaries: {summary[1]}")
    
    # Show recent AI summaries
    result2 = conn.execute(text("""
        SELECT s.target, s.tool_name, 
               ss.ai_summary::text as summary_text,
               s.completed_at
        FROM scans s
        JOIN scan_summaries ss ON s.id = ss.scan_id
        WHERE ss.ai_summary IS NOT NULL
        ORDER BY s.completed_at DESC
        LIMIT 5
    """))
    
    recent = result2.fetchall()
    
    if recent:
        print(f"\n✅ Recent scans with AI summaries:")
        print("=" * 60)
        for scan in recent:
            summary_preview = scan[2][:200] + "..." if len(scan[2]) > 200 else scan[2]
            print(f"Target: {scan[0]}")
            print(f"Tool: {scan[1]}")
            print(f"AI Summary preview: {summary_preview}")
            print(f"Completed: {scan[3]}")
            print("-" * 60)
    else:
        print("\n⚠️ No AI summaries found in database")
