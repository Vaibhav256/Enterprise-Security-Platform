"""Test API response format for CVE endpoint"""
import requests
import json

cve_id = "CVE-2021-44228"
url = f"http://localhost:5000/api/feeds/cve/{cve_id}"

print("=" * 100)
print(f"Testing CVE API Response Format")
print("=" * 100)

try:
    response = requests.get(url, timeout=10)
    print(f"\n✅ HTTP Status: {response.status_code}")
    print(f"✅ Content-Type: {response.headers.get('Content-Type')}")
    
    # Parse JSON
    data = response.json()
    
    print(f"\n📦 Response Structure:")
    print(f"   - Top-level keys: {list(data.keys())}")
    
    if 'status' in data:
        print(f"   - status: {data['status']}")
    
    if 'data' in data:
        print(f"   - data type: {type(data['data'])}")
        print(f"   - data keys: {list(data['data'].keys())[:10]}...")
        
        cve_data = data['data']
        
        print(f"\n🔍 CVE Data Fields:")
        print(f"   - id: {cve_data.get('id')}")
        print(f"   - title: {cve_data.get('title', '')[:50]}...")
        print(f"   - severity: {cve_data.get('severity')}")
        print(f"   - cvss_score: {cve_data.get('cvss_score')} (type: {type(cve_data.get('cvss_score'))})")
        print(f"   - cvss_v3: {cve_data.get('cvss_v3')} (type: {type(cve_data.get('cvss_v3'))})")
        print(f"   - cvss_v2: {cve_data.get('cvss_v2')} (type: {type(cve_data.get('cvss_v2'))})")
        print(f"   - description: {cve_data.get('description', '')[:80]}...")
        print(f"   - published_date: {cve_data.get('published_date')}")
        print(f"   - source: {cve_data.get('source')}")
        
        print(f"\n✅ All fields present for frontend rendering:")
        required_fields = ['id', 'severity', 'cvss_score', 'cvss_v3', 'description', 'published_date']
        for field in required_fields:
            value = cve_data.get(field)
            status = "✅" if value is not None else "❌"
            print(f"   {status} {field}: {value}")
        
        print(f"\n📋 What Frontend Should Receive:")
        print(f"   axios.get() returns response.data which is:")
        print(json.dumps(data, indent=2)[:500] + "...")
        
        print(f"\n🎯 Frontend Code Pattern:")
        print(f"   const response = await feedsApi.getCVE('{cve_id}');")
        print(f"   // response = {{status: 'success', data: {{id: '...', ...}}}}")
        print(f"   const cveData = response.data;  // Gets the CVE object")
        print(f"   // cveData = {{id: '...', severity: '...', cvss_score: ...}}")
        
    else:
        print(f"\n❌ No 'data' field in response!")
        print(f"Response: {json.dumps(data, indent=2)[:500]}")
        
except requests.exceptions.RequestException as e:
    print(f"\n❌ Request failed: {e}")
except json.JSONDecodeError as e:
    print(f"\n❌ Invalid JSON response: {e}")
    print(f"Response text: {response.text[:500]}")
except Exception as e:
    print(f"\n❌ Error: {e}")
    import traceback
    traceback.print_exc()
