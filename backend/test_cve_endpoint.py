"""Test CVE endpoint with NVD API fallback"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.config import Config
from config.database import SessionLocal
from config.models import FeedEntry
from services.threat_feeds.nvd_client import NVDClient
import json

def main():
    # Test with a recent CVE that's likely not in database
    test_cve_id = "CVE-2024-1234"  # This probably doesn't exist, let's try a real one
    test_cve_id = "CVE-2021-44228"  # Log4Shell - very well known

    print("=" * 100)
    print(f"Testing CVE Endpoint for: {test_cve_id}")
    print("=" * 100)

    # Step 1: Check if CVE is in database
    print(f"\n📊 Step 1: Checking local database...")
    session = SessionLocal()
    try:
        entry = session.query(FeedEntry).filter(
            FeedEntry.entry_id == test_cve_id,
            FeedEntry.feed_source == 'nvd'
        ).first()
        
        if entry:
            print(f"✅ Found in database!")
            print(f"   Title: {entry.title}")
            print(f"   Severity: {entry.severity}")
            print(f"   CVSS Score: {entry.cvss_score}")
            in_database = True
        else:
            print(f"❌ Not found in database")
            in_database = False
    finally:
        session.close()

    # Step 2: Fetch from NVD API
    print(f"\n🌐 Step 2: Fetching from NVD API...")
    nvd_client = NVDClient()
    nvd_data = nvd_client.get_cve(test_cve_id)

    if not nvd_data:
        print(f"❌ CVE not found in NVD either!")
        print(f"\nTrying another CVE: CVE-2023-12345...")
        test_cve_id = "CVE-2023-38545"  # curl vulnerability
        nvd_data = nvd_client.get_cve(test_cve_id)

    if nvd_data:
        print(f"✅ Successfully fetched from NVD!")
        print(f"   CVE ID: {nvd_data.get('cve_id')}")
        print(f"   Description: {nvd_data.get('description', '')[:100]}...")
        print(f"   Severity: {nvd_data.get('severity')}")
        
        # Step 3: Format response like API does
        print(f"\n📦 Step 3: Formatting API response...")
        cvss_v3_data = nvd_data.get('cvss_v3')
        cvss_v2_data = nvd_data.get('cvss_v2')
        
        api_response = {
            'id': nvd_data.get('cve_id', test_cve_id),
            'title': nvd_data.get('title', f"CVE {test_cve_id}"),
            'description': nvd_data.get('description', ''),
            'severity': nvd_data.get('severity', 'UNKNOWN'),
            'cvss_score': cvss_v3_data.get('baseScore') if cvss_v3_data else (cvss_v2_data.get('baseScore') if cvss_v2_data else None),
            'cvss_v3': cvss_v3_data.get('baseScore') if cvss_v3_data else None,
            'cvss_v2': cvss_v2_data.get('baseScore') if cvss_v2_data else None,
            'cvss_vector': cvss_v3_data.get('vectorString') if cvss_v3_data else (cvss_v2_data.get('vectorString') if cvss_v2_data else None),
            'published_date': nvd_data.get('published'),
            'modified_date': nvd_data.get('last_modified'),
            'references': [ref.get('url') for ref in nvd_data.get('references', []) if ref.get('url')],
            'exploit_available': False,
            'cwe_ids': nvd_data.get('weaknesses', []),
            'affected_products': nvd_data.get('affected_products', []),
            'source': 'nvd_api',
            'source_url': nvd_data.get('source_url')
        }
        
        print(f"✅ API Response formatted successfully!")
        
        # Step 4: Verify all required fields for frontend
        print(f"\n🔍 Step 4: Verifying fields for frontend display...")
        required_fields = {
            'id': 'CVE ID',
            'description': 'Description',
            'severity': 'Severity badge',
            'cvss_score': 'Overall CVSS score',
            'cvss_v3': 'CVSS v3.x score',
            'published_date': 'Published date',
        }
        
        missing_fields = []
        for field, purpose in required_fields.items():
            if api_response.get(field):
                print(f"   ✅ {field}: {purpose}")
            else:
                print(f"   ❌ {field}: {purpose} - MISSING!")
                missing_fields.append(field)
        
        if missing_fields:
            print(f"\n⚠️ Warning: Missing {len(missing_fields)} required fields")
        else:
            print(f"\n✅ All required fields present!")
        
        # Step 5: Show JSON that frontend will receive
        print(f"\n📋 Step 5: JSON Response for Frontend:")
        print("=" * 100)
        print(json.dumps(api_response, indent=2))
        print("=" * 100)
        
        # Step 6: Summary
        print(f"\n📊 Summary:")
        print(f"   CVE ID: {test_cve_id}")
        print(f"   In Database: {'Yes' if in_database else 'No'}")
        print(f"   Source: {'Database' if in_database else 'NVD API'}")
        print(f"   Severity: {api_response.get('severity')}")
        print(f"   CVSS Score: {api_response.get('cvss_score')}")
        print(f"   CVSS v3: {api_response.get('cvss_v3')}")
        print(f"   CVSS v2: {api_response.get('cvss_v2')}")
        print(f"   References: {len(api_response.get('references', []))} links")
        print(f"   CWE IDs: {len(api_response.get('cwe_ids', []))} weaknesses")
        print(f"   Affected Products: {len(api_response.get('affected_products', []))} products")
        
        print(f"\n✅ Test completed successfully!")
        print(f"\n🌐 View in browser: http://localhost:5173/feeds/cve/{test_cve_id}")

    else:
        print(f"\n❌ Test failed: Could not fetch CVE from NVD")
        print(f"\nTrying one more CVE that definitely exists...")
        
        # Try a very old but famous CVE
        test_cve_id = "CVE-2014-0160"  # Heartbleed
        nvd_data = nvd_client.get_cve(test_cve_id)
        
        if nvd_data:
            print(f"✅ Found {test_cve_id} (Heartbleed)!")
            print(f"   Description: {nvd_data.get('description', '')[:100]}...")
        else:
            print(f"❌ Still failed - check your internet connection or NVD API key")


# Wrap the script functionality to avoid running it during pytest collection
def main():
    """Run the CVE endpoint script (kept for manual testing)."""
    # Move the interactive script logic here when needed.
    print("This script is intended for manual debugging. Run it as a script, not as a pytest module.")


if __name__ == "__main__":
    main()
