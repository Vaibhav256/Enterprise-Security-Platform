"""Check scan timestamps"""
import sys
import os
from sqlalchemy import create_engine, text
import datetime

# Add backend to path to import config
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from config.config import Config
    database_url = Config.DATABASE_URL
except Exception as e:
    print(f"Warning: Could not load config, using default: {e}")
    database_url = 'postgresql://postgres:postgres@localhost:5432/vulnerability_scanner'

try:
    engine = create_engine(database_url)

    with engine.connect() as conn:
        result = conn.execute(text(
            'SELECT id, target, created_at, started_at, completed_at '
            'FROM scans ORDER BY created_at DESC LIMIT 5'
        ))
        
        print('Recent scans:')
        print('=' * 100)
        for row in result:
            print(f'Scan ID: {row.id[:8]}...')
            print(f'Target: {row.target}')
            print(f'Created: {row.created_at}')
            print(f'Started: {row.started_at}')
            print(f'Completed: {row.completed_at}')
            
            # Calculate time difference
            if row.created_at:
                now = datetime.datetime.now()
                # Handle timezone-aware datetimes
                if row.created_at.tzinfo is not None:
                    # Make now timezone-aware
                    import datetime as dt
                    now = datetime.datetime.now(row.created_at.tzinfo)
                
                diff = now - row.created_at
                hours = diff.total_seconds() / 3600
                minutes = diff.total_seconds() / 60
                print(f'Time since creation: {diff} ({hours:.1f} hours, {minutes:.1f} minutes)')
            
            print('-' * 100)
            
except Exception as e:
    print(f"❌ Error: {e}")
    print("\nMake sure:")
    print("1. PostgreSQL service is running")
    print("2. Database 'vulnerability_scanner' exists")
    print("3. Connection details are correct in config")
    sys.exit(1)
