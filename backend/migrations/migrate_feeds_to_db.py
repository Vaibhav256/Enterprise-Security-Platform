#!/usr/bin/env python3
"""
Migrate Threat Feeds from JSON to Database

This script migrates existing threat intelligence data from JSON files
to the PostgreSQL database using the new feed_entries table.

Author: NTRO Security Team
Date: 2025-10-31

Usage:
    python migrate_feeds_to_db.py
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.database import get_db_connection, release_db_connection


def parse_nvd_date(date_str):
    """Parse NVD date format to datetime"""
    if not date_str:
        return None
    try:
        # NVD uses ISO 8601 format
        return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
    except Exception as e:
        print(f"Warning: Could not parse date '{date_str}': {e}")
        return None


def get_severity_from_cvss(cvss_score):
    """Calculate severity from CVSS score"""
    if cvss_score is None:
        return 'unknown'
    score = float(cvss_score)
    if score >= 9.0:
        return 'critical'
    elif score >= 7.0:
        return 'high'
    elif score >= 4.0:
        return 'medium'
    elif score >= 0.1:
        return 'low'
    else:
        return 'info'


def migrate_nvd_feeds():
    """Migrate NVD feeds from JSON to database"""
    print("\n📦 Migrating NVD feeds...")
    
    json_file = Path(__file__).parent.parent / 'data' / 'threat_feeds' / 'nvd_recent.json'
    
    if not json_file.exists():
        print(f"⚠️  NVD feed file not found: {json_file}")
        return 0
    
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"❌ Error reading NVD feed: {e}")
        return 0
    
    conn = None
    migrated_count = 0
    skipped_count = 0
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cves = data.get('cves', [])
        print(f"Found {len(cves)} NVD entries to migrate")
        
        for cve_data in cves:
            try:
                cve_id = cve_data.get('cve_id', 'UNKNOWN')
                description = cve_data.get('description')
                
                # Extract CVSS data
                cvss_v3 = cve_data.get('cvss_v3', {})
                cvss_score = cvss_v3.get('baseScore') if cvss_v3 else None
                cvss_vector = cvss_v3.get('vectorString') if cvss_v3 else None
                
                # Get severity
                severity_str = cve_data.get('severity', '').lower()
                if not severity_str and cvss_score:
                    severity_str = get_severity_from_cvss(cvss_score)
                
                # Extract references
                refs = cve_data.get('references', [])
                references = [ref.get('url') for ref in refs if ref.get('url')]
                
                # Extract CWE IDs
                weaknesses = cve_data.get('weaknesses', [])
                cwe_ids = [f"CWE-{w}" if not w.startswith('CWE-') else w for w in weaknesses]
                
                # Extract dates
                published_date = parse_nvd_date(cve_data.get('published'))
                modified_date = parse_nvd_date(cve_data.get('last_modified'))
                
                # Check if entry already exists
                cursor.execute(
                    "SELECT id FROM feed_entries WHERE entry_id = %s",
                    (cve_id,)
                )
                existing = cursor.fetchone()
                
                if existing:
                    skipped_count += 1
                    continue
                
                # Insert into database
                cursor.execute(
                    """
                    INSERT INTO feed_entries (
                        feed_source, feed_type, entry_id, title, description,
                        severity, cvss_score, cvss_vector,
                        cwe_ids, ref_urls,
                        published_date, modified_date,
                        metadata
                    ) VALUES (
                        %s, %s, %s, %s, %s,
                        %s, %s, %s,
                        %s, %s,
                        %s, %s,
                        %s
                    )
                    """,
                    (
                        'nvd',                    # feed_source
                        'cve',                    # feed_type
                        cve_id,                   # entry_id
                        cve_id,                   # title (use CVE ID)
                        description,              # description
                        severity_str,             # severity
                        cvss_score,              # cvss_score
                        cvss_vector,             # cvss_vector
                        cwe_ids if cwe_ids else None,  # cwe_ids
                        references if references else None,  # ref_urls
                        published_date,          # published_date
                        modified_date,           # modified_date
                        json.dumps(cve_data)     # metadata (store full entry)
                    )
                )
                
                migrated_count += 1
                
                if migrated_count % 100 == 0:
                    print(f"  Migrated {migrated_count} entries...")
                    conn.commit()
                
            except Exception as e:
                print(f"⚠️  Error migrating {cve_id}: {e}")
                continue
        
        conn.commit()
        print(f"✅ Migrated {migrated_count} NVD entries")
        if skipped_count > 0:
            print(f"⏭️  Skipped {skipped_count} existing entries")
        
        return migrated_count
        
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"❌ Error during migration: {e}")
        return 0
    finally:
        if cursor:
            cursor.close()
        if conn:
            release_db_connection(conn)


def verify_migration():
    """Verify migration results"""
    print("\n🔍 Verifying migration...")
    
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Count total entries
        cursor.execute("SELECT COUNT(*) FROM feed_entries")
        total = cursor.fetchone()[0]
        print(f"  Total feed entries: {total}")
        
        # Count by source
        cursor.execute("SELECT feed_source, COUNT(*) FROM feed_entries GROUP BY feed_source")
        for source, count in cursor.fetchall():
            print(f"    - {source}: {count} entries")
        
        # Count by severity
        cursor.execute("SELECT severity, COUNT(*) FROM feed_entries GROUP BY severity ORDER BY COUNT(*) DESC")
        print("\n  By severity:")
        for severity, count in cursor.fetchall():
            print(f"    - {severity or 'unknown'}: {count} entries")
        
        # Recent entries
        cursor.execute(
            """
            SELECT entry_id, severity, cvss_score, published_date 
            FROM feed_entries 
            ORDER BY published_date DESC 
            LIMIT 5
            """
        )
        print("\n  Recent entries:")
        for entry_id, severity, cvss_score, pub_date in cursor.fetchall():
            print(f"    - {entry_id} | {severity} | CVSS: {cvss_score} | {pub_date}")
        
        cursor.close()
        
    except Exception as e:
        print(f"❌ Error during verification: {e}")
    finally:
        if conn:
            release_db_connection(conn)


def main():
    """Main migration process"""
    print("=" * 60)
    print("  Threat Feeds Migration: JSON → Database")
    print("=" * 60)
    
    # Run SQL migration first
    print("\n📋 Step 1: Creating feed_entries table...")
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Read and execute SQL migration
        sql_file = Path(__file__).parent / 'add_feed_entries_table.sql'
        if sql_file.exists():
            with open(sql_file, 'r') as f:
                sql = f.read()
            cursor.execute(sql)
            conn.commit()
            print("✅ Table created successfully")
        else:
            print("⚠️  SQL migration file not found, assuming table exists")
        
        cursor.close()
    except Exception as e:
        print(f"❌ Error creating table: {e}")
        if conn:
            conn.rollback()
        return
    finally:
        if conn:
            release_db_connection(conn)
    
    # Migrate NVD feeds
    print("\n📋 Step 2: Migrating feed data...")
    nvd_count = migrate_nvd_feeds()
    
    # Verify migration
    verify_migration()
    
    # Summary
    print("\n" + "=" * 60)
    print("  Migration Complete!")
    print("=" * 60)
    print(f"  Total migrated: {nvd_count} entries")
    print("\n💡 Next steps:")
    print("  1. Update feed manager to use database instead of JSON")
    print("  2. Test feed API endpoints")
    print("  3. Consider removing old JSON files (backup first!)")
    print("=" * 60)


if __name__ == '__main__':
    main()
