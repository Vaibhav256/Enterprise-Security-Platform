"""
Check if progress is being updated in database
"""
import sys
sys.path.insert(0, 'D:\\ESP\\backend')

from config.database import DATABASE_URL
from sqlalchemy import create_engine, text

engine = create_engine(DATABASE_URL)

with engine.connect() as conn:
    # Check ALL recent scans
    result = conn.execute(text("""
        SELECT id, target, status, progress_percent, completed_at, created_at
        FROM scans 
        ORDER BY created_at DESC
        LIMIT 10
    """))
    
    scans = result.fetchall()
    
    print(f"\n📊 Recent Scans ({len(scans)}):")
    print("=" * 120)
    for scan in scans:
        print(f"ID: {scan[0][:8]}...")
        print(f"Target: {scan[1]}")
        print(f"Status: {scan[2]}")
        print(f"Progress in DB: {scan[3]}%")
        print(f"Completed: {scan[4]}")
        print(f"Created: {scan[5]}")
        print("-" * 120)
