# Testing Phase 2 Improvements

## After Restarting the Application

Run these tests to verify all Phase 2 improvements are working:

### 1. Test Request ID Tracing

```powershell
# Make a request and check for X-Request-ID header
(Invoke-WebRequest http://localhost:5000/).Headers

# Should see:
# X-Request-ID: 550e8400-e29b-41d4-a716-446655440000 (or similar UUID)
```

### 2. Test API Version Endpoints

```powershell
# Get API version info
curl http://localhost:5000/api | ConvertFrom-Json

# Expected response:
# {
#   "current_version": "v1",
#   "supported_versions": ["v1"],
#   "deprecated_versions": [],
#   "endpoints": {...}
# }
```

### 3. Test Error Handling

```powershell
# Test 404 error (should return JSON)
curl http://localhost:5000/nonexistent | ConvertFrom-Json

# Expected response:
# {
#   "error": {
#     "code": "NOT_FOUND",
#     "message": "The requested URL /nonexistent was not found"
#   }
# }
```

### 4. Test Updated Root Endpoint

```powershell
# Check root endpoint has new fields
curl http://localhost:5000/ | ConvertFrom-Json

# Expected response:
# {
#   "message": "Vulnerability Scanner API",
#   "version": "1.0",
#   "api_version": "v1",
#   "docs": "/api/v1/docs",
#   "health": "/health/ready"
# }
```

### 5. Test Health Checks Still Working

```powershell
# Readiness check
curl http://localhost:5000/health/ready | ConvertFrom-Json | Select-Object status

# Expected: status = "ready"
```

### 6. Verify Logs Include Request IDs

```powershell
# Check application logs for request ID format
# Should see: [request_id=UUID] in log entries
```

## If Tests Fail

If any tests fail after restart:

1. **Check logs**:
   ```powershell
   # Look for errors in startup
   Get-Content backend/logs/app.log -Tail 50
   ```

2. **Verify imports**:
   ```powershell
   cd backend
   python -c "from utils.exceptions import *; from utils.error_handlers import *; from utils.request_id import *; from utils.versioning import *; print('✅ All imports OK')"
   ```

3. **Check app initialization**:
   - Error handlers registered
   - Request ID middleware initialized
   - API versioning endpoints registered

## Expected Console Output on Startup

When you run `python run_api.py`, you should see:

```
✅ Config validation passed
✅ Database connection pool created successfully
✅ Registered health check endpoints (/health, /health/ready, /health/live)
✅ Global error handlers registered
✅ Request ID middleware initialized (header: X-Request-ID)
✅ Registered API versioning endpoints (/api, /api/version)
Starting API Gateway on 0.0.0.0:5000
```

## Quick Validation Script

```powershell
# Run all tests at once
$tests = @(
    @{Name="Request ID"; Cmd={((Invoke-WebRequest http://localhost:5000/).Headers)['X-Request-ID']}},
    @{Name="API Info"; Cmd={(curl http://localhost:5000/api | ConvertFrom-Json).current_version}},
    @{Name="Root Endpoint"; Cmd={(curl http://localhost:5000/ | ConvertFrom-Json).api_version}},
    @{Name="Health Check"; Cmd={(curl http://localhost:5000/health/ready | ConvertFrom-Json).status}}
)

foreach ($test in $tests) {
    try {
        $result = & $test.Cmd
        Write-Host "✅ $($test.Name): $result" -ForegroundColor Green
    } catch {
        Write-Host "❌ $($test.Name): FAILED" -ForegroundColor Red
    }
}
```

## Success Criteria

All tests should pass with:
- ✅ X-Request-ID header present on all responses
- ✅ `/api` endpoint returns version info
- ✅ Error responses in consistent JSON format
- ✅ Root endpoint includes `api_version` field
- ✅ Health checks still functional

---

*Note: These tests validate that Phase 2 improvements are properly integrated and working.*
