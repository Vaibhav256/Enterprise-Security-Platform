# Error Handling Guide

## Overview

ESP now has comprehensive centralized error handling with:
- **Custom exception classes** for all error types
- **Global error handlers** for consistent responses
- **Request ID tracing** for debugging

## Using Custom Exceptions

### Basic Usage

```python
from utils.exceptions import ValidationError, ScanNotFoundError

# Raise validation error
if not is_valid_ip(target):
    raise ValidationError(
        message=f"Invalid IP address: {target}",
        details={'target': target}
    )

# Raise not found error
scan = get_scan(scan_id)
if not scan:
    raise ScanNotFoundError(
        message=f"Scan {scan_id} not found",
        details={'scan_id': scan_id}
    )
```

### Available Exception Classes

#### Validation Errors (400)
- `ValidationError` - Generic validation failure
- `InvalidTargetError` - Invalid scan target
- `InvalidOptionsError` - Invalid scan options
- `MissingParameterError` - Required parameter missing

#### Authentication & Authorization (401, 403)
- `AuthenticationError` - Authentication failed
- `AuthorizationError` - Not authorized

#### Not Found (404)
- `NotFoundError` - Generic not found
- `ScanNotFoundError` - Scan not found
- `ReportNotFoundError` - Report not found

#### Conflict (409)
- `ConflictError` - Generic conflict
- `DuplicateScanError` - Duplicate scan exists

#### Rate Limiting (429)
- `RateLimitError` - Rate limit exceeded

#### Service Errors (500+)
- `ServiceError` - Generic service error
- `DatabaseError` - Database operation failed
- `QueueError` - Queue operation failed
- `ScannerError` - Scanner execution failed
- `ToolNotAvailableError` - Tool not available (503)
- `ExternalAPIError` - External API failed (502)
- `ConfigurationError` - Configuration error

#### Timeout (504)
- `TimeoutError` - Generic timeout
- `ScanTimeoutError` - Scan timeout

## Error Response Format

All errors return a consistent JSON structure:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid IP address: 999.999.999.999",
    "details": {
      "target": "999.999.999.999"
    }
  }
}
```

## Request ID Tracing

Every request gets a unique `X-Request-ID` header:

```bash
curl -i http://localhost:5000/api/scans
# Response includes:
# X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
```

Use request IDs to:
- **Track requests** across services
- **Correlate logs** for debugging
- **Report issues** with specific request IDs

### In Logs

Logs automatically include request IDs:

```
2025-11-27 15:10:23 [INFO] [request_id=550e8400-e29b-41d4-a716-446655440000] Scan created successfully
```

### Getting Request ID in Code

```python
from utils.request_id import get_request_id

def my_endpoint():
    request_id = get_request_id()
    logger.info(f"Processing request {request_id}")
```

## Updating Existing Code

### Before:
```python
@app.route('/api/scans/<scan_id>')
def get_scan(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        return {'error': 'Not found'}, 404
    return scan
```

### After:
```python
from utils.exceptions import ScanNotFoundError

@app.route('/api/scans/<scan_id>')
def get_scan(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        raise ScanNotFoundError(
            message=f"Scan {scan_id} not found",
            details={'scan_id': scan_id}
        )
    return scan
```

## Global Error Handlers

Error handlers are automatically registered when the app starts. They handle:

- ✅ Custom `ESPException` classes
- ✅ Werkzeug `HTTPException` classes
- ✅ Standard Python exceptions
- ✅ 404, 405, 500 errors

### Development vs Production

**Development:**
- Includes traceback in error responses
- Detailed error messages

**Production:**
- No traceback (security)
- Generic error messages
- Logs full details for debugging

## Best Practices

### 1. Use Specific Exceptions
```python
# ❌ Generic
raise Exception("Invalid target")

# ✅ Specific
raise InvalidTargetError(
    message=f"Target {target} is not reachable",
    details={'target': target, 'reason': 'timeout'}
)
```

### 2. Include Details
```python
raise ValidationError(
    message="Invalid scan parameters",
    details={
        'provided_options': options,
        'required_fields': ['target', 'scan_type'],
        'missing_fields': ['target']
    }
)
```

### 3. Log Before Raising (Optional)
```python
logger.warning(f"Scan not found: {scan_id}")
raise ScanNotFoundError(message=f"Scan {scan_id} not found")
```

### 4. Use Request IDs in Logs
```python
from utils.request_id import get_request_id

logger.info(
    f"Scan completed: {scan_id}",
    extra={'request_id': get_request_id()}
)
```

## Testing Error Responses

```bash
# Test validation error
curl -X POST http://localhost:5000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"invalid": "data"}'

# Response:
{
  "error": {
    "code": "MISSING_PARAMETER",
    "message": "Required parameter 'target' is missing",
    "details": {"required": ["target", "tool_name", "scan_type"]}
  }
}

# Note the X-Request-ID header for debugging
```

## Migration Path

1. **Phase 1** (Current): Error handlers registered, ready to use
2. **Phase 2**: Update route handlers to use custom exceptions
3. **Phase 3**: Update service layers to use custom exceptions
4. **Phase 4**: Update adapters to use custom exceptions

Start with critical paths (scan creation, scan retrieval) and gradually update all endpoints.
