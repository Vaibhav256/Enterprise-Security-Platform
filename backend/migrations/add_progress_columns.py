"""
Add progress tracking columns to scans table
"""
import sys
sys.path.insert(0, 'D:\\ESP\\backend')

from config.database import DATABASE_URL
from sqlalchemy import create_engine, text

def run_migration():
    engine = create_engine(DATABASE_URL)
    
    with engine.connect() as conn:
        # Add progress_percent column
        try:
            conn.execute(text("""
                ALTER TABLE scans ADD COLUMN IF NOT EXISTS progress_percent INTEGER DEFAULT 0
            """))
            conn.commit()
            print("✅ Added progress_percent column")
        except Exception as e:
            print(f"progress_percent column may already exist: {e}")
        
        # Add progress_message column
        try:
            conn.execute(text("""
                ALTER TABLE scans ADD COLUMN IF NOT EXISTS progress_message VARCHAR(500)
            """))
            conn.commit()
            print("✅ Added progress_message column")
        except Exception as e:
            print(f"progress_message column may already exist: {e}")
        
        # Update existing running scans
        try:
            conn.execute(text("""
                UPDATE scans SET progress_percent = 0 
                WHERE status = 'running' AND progress_percent IS NULL
            """))
            conn.commit()
            print("✅ Updated existing running scans")
        except Exception as e:
            print(f"Update failed: {e}")
    
    print("\n✅ Migration completed successfully!")

if __name__ == "__main__":
    run_migration()
