"""
Update all completed scans to have 100% progress
"""
import sys
sys.path.insert(0, 'D:\\ESP\\backend')

from config.database import DATABASE_URL
from sqlalchemy import create_engine, text

engine = create_engine(DATABASE_URL)

with engine.connect() as conn:
    result = conn.execute(text("""
        UPDATE scans 
        SET progress_percent = 100, progress_message = 'Completed'
        WHERE status = 'COMPLETED' AND (progress_percent IS NULL OR progress_percent = 0)
    """))
    conn.commit()
    
    print(f"✅ Updated {result.rowcount} completed scans to 100% progress")
