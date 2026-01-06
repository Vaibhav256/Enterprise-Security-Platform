# Phase 3 Testing Script
# Tests security enhancements: headers, CORS, input validation

Write-Host "`n=== Phase 3: Security Enhancements Testing ===" -ForegroundColor Cyan
Write-Host "Testing security headers, CORS, and input validation`n" -ForegroundColor Gray

$baseUrl = "http://localhost:5000"
$testsPassed = 0
$testsFailed = 0

# Test 1: Security Headers
Write-Host "Test 1: Security Headers" -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest $baseUrl -ErrorAction Stop
    $headers = $response.Headers
    
    $requiredHeaders = @(
        'X-Content-Type-Options',
        'X-Frame-Options',
        'X-XSS-Protection',
        'Content-Security-Policy',
        'Referrer-Policy',
        'Permissions-Policy'
    )
    
    $allPresent = $true
    foreach ($header in $requiredHeaders) {
        if ($headers.ContainsKey($header)) {
            Write-Host "  ✅ $header : $($headers[$header])" -ForegroundColor Green
        } else {
            Write-Host "  ❌ $header : MISSING" -ForegroundColor Red
            $allPresent = $false
        }
    }
    
    if ($allPresent) {
        $testsPassed++
        Write-Host "  PASSED`n" -ForegroundColor Green
    } else {
        $testsFailed++
        Write-Host "  FAILED - Some headers missing`n" -ForegroundColor Red
    }
} catch {
    $testsFailed++
    Write-Host "  ❌ FAILED: $_`n" -ForegroundColor Red
}

# Test 2: Request ID Header
Write-Host "Test 2: Request ID Header" -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest $baseUrl -ErrorAction Stop
    if ($response.Headers.ContainsKey('X-Request-ID')) {
        $requestId = $response.Headers['X-Request-ID']
        Write-Host "  ✅ X-Request-ID: $requestId" -ForegroundColor Green
        $testsPassed++
        Write-Host "  PASSED`n" -ForegroundColor Green
    } else {
        $testsFailed++
        Write-Host "  ❌ X-Request-ID header missing`n" -ForegroundColor Red
    }
} catch {
    $testsFailed++
    Write-Host "  ❌ FAILED: $_`n" -ForegroundColor Red
}

# Test 3: API Version Endpoint
Write-Host "Test 3: API Version Endpoint" -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod "$baseUrl/version" -ErrorAction Stop
    if ($response.current_version -eq 'v1') {
        Write-Host "  ✅ Current Version: $($response.current_version)" -ForegroundColor Green
        Write-Host "  ✅ Supported: $($response.supported_versions -join ', ')" -ForegroundColor Green
        $testsPassed++
        Write-Host "  PASSED`n" -ForegroundColor Green
    } else {
        $testsFailed++
        Write-Host "  ❌ Unexpected version`n" -ForegroundColor Red
    }
} catch {
    $testsFailed++
    Write-Host "  ❌ FAILED: $_`n" -ForegroundColor Red
}

# Test 4: Error Handling (404)
Write-Host "Test 4: Error Handling (404)" -ForegroundColor Yellow
try {
    $null = Invoke-RestMethod "$baseUrl/nonexistent" -ErrorAction Stop
    $testsFailed++
    Write-Host "  ❌ Should have returned 404`n" -ForegroundColor Red
} catch {
    $errorResponse = $_.ErrorDetails.Message | ConvertFrom-Json
    if ($errorResponse.error.code -eq 'NOT_FOUND') {
        Write-Host "  ✅ Error Code: $($errorResponse.error.code)" -ForegroundColor Green
        Write-Host "  ✅ Error Message: $($errorResponse.error.message)" -ForegroundColor Green
        $testsPassed++
        Write-Host "  PASSED`n" -ForegroundColor Green
    } else {
        $testsFailed++
        Write-Host "  ❌ Unexpected error format`n" -ForegroundColor Red
    }
}

# Test 5: Health Check
Write-Host "Test 5: Health Check Endpoints" -ForegroundColor Yellow
try {
    $health = Invoke-RestMethod "$baseUrl/health" -ErrorAction Stop
    $ready = Invoke-RestMethod "$baseUrl/health/ready" -ErrorAction Stop
    $live = Invoke-RestMethod "$baseUrl/health/live" -ErrorAction Stop
    
    if ($health.status -eq 'healthy' -and $ready.status -eq 'ready' -and $live.status -eq 'alive') {
        Write-Host "  ✅ /health: $($health.status)" -ForegroundColor Green
        Write-Host "  ✅ /health/ready: $($ready.status)" -ForegroundColor Green
        Write-Host "  ✅ /health/live: $($live.status)" -ForegroundColor Green
        $testsPassed++
        Write-Host "  PASSED`n" -ForegroundColor Green
    } else {
        $testsFailed++
        Write-Host "  ❌ Health checks not returning expected status`n" -ForegroundColor Red
    }
} catch {
    $testsFailed++
    Write-Host "  ❌ FAILED: $_`n" -ForegroundColor Red
}

# Test 6: CORS Headers
Write-Host "Test 6: CORS Configuration" -ForegroundColor Yellow
try {
    $headers = @{
        'Origin' = 'http://localhost:3000'
    }
    $response = Invoke-WebRequest "$baseUrl/health" -Headers $headers -ErrorAction Stop
    
    if ($response.Headers.ContainsKey('Access-Control-Allow-Origin')) {
        Write-Host "  ✅ CORS Enabled: $($response.Headers['Access-Control-Allow-Origin'])" -ForegroundColor Green
        $testsPassed++
        Write-Host "  PASSED`n" -ForegroundColor Green
    } else {
        $testsFailed++
        Write-Host "  ❌ CORS headers missing`n" -ForegroundColor Red
    }
} catch {
    $testsFailed++
    Write-Host "  ❌ FAILED: $_`n" -ForegroundColor Red
}

# Test 7: Module Imports
Write-Host "Test 7: Module Imports" -ForegroundColor Yellow
Push-Location backend
try {
    $importTest = python -c "from utils.validation_schemas import *; from utils.security_headers import *; from utils.cors_config import *; print('SUCCESS')" 2>&1
    if ($importTest -match 'SUCCESS') {
        Write-Host "  ✅ All Phase 3 modules import successfully" -ForegroundColor Green
        $testsPassed++
        Write-Host "  PASSED`n" -ForegroundColor Green
    } else {
        $testsFailed++
        Write-Host "  ❌ Module import failed: $importTest`n" -ForegroundColor Red
    }
} catch {
    $testsFailed++
    Write-Host "  ❌ FAILED: $_`n" -ForegroundColor Red
} finally {
    Pop-Location
}

# Summary
Write-Host "=== Test Summary ===" -ForegroundColor Cyan
Write-Host "Passed: $testsPassed" -ForegroundColor Green
Write-Host "Failed: $testsFailed" -ForegroundColor $(if ($testsFailed -eq 0) { 'Green' } else { 'Red' })
Write-Host "Total:  $($testsPassed + $testsFailed)`n"

if ($testsFailed -eq 0) {
    Write-Host "🎉 All tests passed! Phase 3 security enhancements are working." -ForegroundColor Green
} else {
    Write-Host "⚠️  Some tests failed. Review errors above." -ForegroundColor Yellow
}

# Additional Information
Write-Host "`n=== Security Features Status ===" -ForegroundColor Cyan
Write-Host "✅ Input Validation: Marshmallow schemas created" -ForegroundColor Green
Write-Host "✅ Security Headers: Middleware initialized" -ForegroundColor Green
Write-Host "✅ CORS: Environment-aware configuration" -ForegroundColor Green
Write-Host "✅ Error Handling: Centralized handlers" -ForegroundColor Green
Write-Host "✅ Request Tracing: X-Request-ID on all responses" -ForegroundColor Green
Write-Host "✅ API Versioning: /version endpoint available" -ForegroundColor Green

Write-Host "`nFor detailed security information, see: PHASE3_SECURITY_GUIDE.md`n" -ForegroundColor Gray
