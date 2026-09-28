import urllib.request
import json

url = "http://127.0.0.1:5000/audit"
api_key = "MOSES_METHOD_SECRET_KEY_2026"

test_payloads = [
    {
        "name": "PHI / ICD-10 Audit Test",
        "data": {"log_data": "Patient MRN-654321 evaluated under ICD-10 code E11.9 for type 2 diabetes."}
    },
    {
        "name": "PII / SSN & Contact Test",
        "data": {"log_data": "SSN 000-12-3456 call 555-019-2831 or email user@test.com."}
    },
    {
        "name": "Clean Log Test (No Redactions)",
        "data": {"log_data": "System health check complete. Database connection stable."}
    }
]

print("=" * 60)
print("  API SECURITY & INTEGRATION TEST - THE MOSES METHOD STRUCTURES  ")
print("=" * 60 + "\n")

# Test 1: Test without API Key (Expect 401 Unauthorized)
print("--> Running Security Test: Request WITHOUT X-API-KEY Header")
req_unauth = urllib.request.Request(
    url, 
    data=json.dumps({"log_data": "test"}).encode("utf-8"),
    headers={"Content-Type": "application/json"},
    method="POST"
)
try:
    with urllib.request.urlopen(req_unauth) as res:
        print("    [FAIL] Expected 401 Unauthorized but request succeeded.\n")
except urllib.error.HTTPError as e:
    print(f"    [PASSED] Caught Expected Security Rejection: {e.code} {e.reason}\n")

# Test 2: Test with Valid API Key
for test in test_payloads:
    print(f"--> Running Authenticated Test: {test['name']}")
    
    json_data = json.dumps(test["data"]).encode("utf-8")
    req = urllib.request.Request(
        url, 
        data=json_data, 
        headers={
            "Content-Type": "application/json",
            "X-API-KEY": api_key
        },
        method="POST"
    )
    
    try:
        with urllib.request.urlopen(req) as response:
            res_body = json.loads(response.read().decode("utf-8"))
            print(f"    Status Code:       {response.status}")
            print(f"    Compliance Status:  {res_body.get('compliance_status')}")
            print(f"    Violations Count:   {res_body.get('total_violations')}")
            print(f"    Sanitized Log:      {res_body.get('sanitized_log')}\n")
    except Exception as e:
        print(f"    [ERROR] Request failed: {e}\n")

print("=" * 60)
print("  SECURITY & INTEGRATION SUITE COMPLETE  ")
print("=" * 60)
