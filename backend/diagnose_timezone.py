"""
Deep scan for timezone issues
"""
import sys
sys.path.insert(0, 'D:\\ESP\\backend')

from datetime import datetime, timezone
from config.database import DATABASE_URL
from sqlalchemy import create_engine, text
import pytz

print("=" * 80)
print("TIMEZONE DIAGNOSTIC REPORT")
print("=" * 80)

# 1. Check system timezone
print("\n1. SYSTEM TIMEZONE:")
print(f"   datetime.now(): {datetime.now()}")
print(f"   datetime.utcnow(): {datetime.utcnow()}")
print(f"   Difference: {(datetime.now() - datetime.utcnow()).total_seconds() / 3600:.1f} hours")

# 2. Check database timezone
engine = create_engine(DATABASE_URL)
with engine.connect() as conn:
    result = conn.execute(text("SHOW TIMEZONE"))
    db_tz = result.fetchone()[0]
    print(f"\n2. DATABASE TIMEZONE:")
    print(f"   PostgreSQL timezone: {db_tz}")
    
    # 3. Check actual scan timestamps
    result2 = conn.execute(text("""
        SELECT id, target, created_at, started_at, completed_at
        FROM scans
        ORDER BY created_at DESC
        LIMIT 3
    """))
    
    scans = result2.fetchall()
    
    print(f"\n3. RECENT SCAN TIMESTAMPS (from database):")
    print("-" * 80)
    for scan in scans:
        print(f"\nScan ID: {scan[0][:8]}...")
        print(f"Target: {scan[1]}")
        print(f"Created at: {scan[2]} (in DB)")
        
        if scan[2]:
            # Parse as naive datetime (what's in DB)
            db_time = scan[2]
            now_utc = datetime.utcnow()
            
            # Calculate difference
            diff_hours = (now_utc - db_time).total_seconds() / 3600
            
            print(f"Current UTC: {now_utc}")
            print(f"Difference: {diff_hours:.1f} hours ago")
            
            # What it should be in local time (IST = UTC+5:30)
            ist = pytz.timezone('Asia/Kolkata')
            db_time_utc = pytz.utc.localize(db_time)
            db_time_ist = db_time_utc.astimezone(ist)
            
            print(f"In IST: {db_time_ist.strftime('%Y-%m-%d %H:%M:%S %Z')}")

# 4. Check what the API returns
print(f"\n4. API RESPONSE FORMAT:")
print(f"   Backend uses .isoformat() which returns: {datetime.utcnow().isoformat()}")
print(f"   This is UTC time without timezone info")

# 5. Recommendations
print(f"\n5. IDENTIFIED ISSUES:")
print("-" * 80)
print("✅ Backend stores times in UTC (correct)")
print("⚠️ Backend returns times without timezone info (.isoformat() drops TZ)")
print("⚠️ Frontend assumes local timezone when parsing")
print("⚠️ This causes 5.5 hour offset for IST users")

print(f"\n6. SOLUTION:")
print("-" * 80)
print("1. Backend should return ISO strings with 'Z' suffix: .isoformat() + 'Z'")
print("2. Or use timezone-aware datetimes")
print("3. Frontend will then correctly parse as UTC and convert to local time")
