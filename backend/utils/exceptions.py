"""
Custom Exception Classes for ESP Application

Provides structured exception hierarchy for better error handling
and consistent error responses across the API.

Author: NTRO Security Team
Date: 2025-11-27
"""

from typing import Optional, Dict, Any


class ESPException(Exception):
    """Base exception for all ESP application errors"""
    
    status_code = 500
    error_code = 'INTERNAL_ERROR'
    message = 'An internal error occurred'
    
    def __init__(
        self, 
        message: Optional[str] = None,
        error_code: Optional[str] = None,
        status_code: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message or self.message)
        self.message = message or self.message
        self.error_code = error_code or self.error_code
        self.status_code = status_code or self.status_code
        self.details = details or {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for JSON response"""
        response = {
            'error': {
                'code': self.error_code,
                'message': self.message,
            }
        }
        if self.details:
            response['error']['details'] = self.details
        return response


# ==========================================
# Validation Errors (400)
# ==========================================

class ValidationError(ESPException):
    """Validation error for invalid input"""
    status_code = 400
    error_code = 'VALIDATION_ERROR'
    message = 'Validation failed'


class InvalidTargetError(ValidationError):
    """Invalid scan target"""
    error_code = 'INVALID_TARGET'
    message = 'Invalid target format or unreachable target'


class InvalidOptionsError(ValidationError):
    """Invalid scan options"""
    error_code = 'INVALID_OPTIONS'
    message = 'Invalid scan options provided'


class MissingParameterError(ValidationError):
    """Required parameter missing"""
    error_code = 'MISSING_PARAMETER'
    message = 'Required parameter is missing'


# ==========================================
# Authentication & Authorization (401, 403)
# ==========================================

class AuthenticationError(ESPException):
    """Authentication failed"""
    status_code = 401
    error_code = 'AUTHENTICATION_FAILED'
    message = 'Authentication failed'


class AuthorizationError(ESPException):
    """User not authorized"""
    status_code = 403
    error_code = 'FORBIDDEN'
    message = 'You do not have permission to access this resource'


# ==========================================
# Not Found Errors (404)
# ==========================================

class NotFoundError(ESPException):
    """Resource not found"""
    status_code = 404
    error_code = 'NOT_FOUND'
    message = 'Resource not found'


class ScanNotFoundError(NotFoundError):
    """Scan not found"""
    error_code = 'SCAN_NOT_FOUND'
    message = 'Scan not found'


class ReportNotFoundError(NotFoundError):
    """Report not found"""
    error_code = 'REPORT_NOT_FOUND'
    message = 'Report not found'


# ==========================================
# Conflict Errors (409)
# ==========================================

class ConflictError(ESPException):
    """Resource conflict"""
    status_code = 409
    error_code = 'CONFLICT'
    message = 'Resource conflict'


class DuplicateScanError(ConflictError):
    """Duplicate scan already exists"""
    error_code = 'DUPLICATE_SCAN'
    message = 'A scan with these parameters is already running'


# ==========================================
# Rate Limiting (429)
# ==========================================

class RateLimitError(ESPException):
    """Rate limit exceeded"""
    status_code = 429
    error_code = 'RATE_LIMIT_EXCEEDED'
    message = 'Rate limit exceeded'


# ==========================================
# Service Errors (500+)
# ==========================================

class ServiceError(ESPException):
    """Internal service error"""
    status_code = 500
    error_code = 'SERVICE_ERROR'
    message = 'Internal service error occurred'


class DatabaseError(ServiceError):
    """Database operation failed"""
    error_code = 'DATABASE_ERROR'
    message = 'Database operation failed'


class QueueError(ServiceError):
    """Queue operation failed"""
    error_code = 'QUEUE_ERROR'
    message = 'Failed to queue job'


class ScannerError(ServiceError):
    """Scanner tool error"""
    error_code = 'SCANNER_ERROR'
    message = 'Scanner execution failed'


class ToolNotAvailableError(ServiceError):
    """Scanning tool not available"""
    status_code = 503
    error_code = 'TOOL_NOT_AVAILABLE'
    message = 'Scanning tool is not available'


class ExternalAPIError(ServiceError):
    """External API call failed"""
    status_code = 502
    error_code = 'EXTERNAL_API_ERROR'
    message = 'External API request failed'


class ConfigurationError(ServiceError):
    """Configuration error"""
    error_code = 'CONFIGURATION_ERROR'
    message = 'System configuration error'


# ==========================================
# Timeout Errors (504)
# ==========================================

class TimeoutError(ESPException):
    """Operation timeout"""
    status_code = 504
    error_code = 'TIMEOUT'
    message = 'Operation timed out'


class ScanTimeoutError(TimeoutError):
    """Scan execution timeout"""
    error_code = 'SCAN_TIMEOUT'
    message = 'Scan execution timed out'


# ==========================================
# Helper Functions
# ==========================================

def create_error_response(
    exception: Exception,
    include_traceback: bool = False
) -> Dict[str, Any]:
    """
    Create standardized error response from any exception
    
    Args:
        exception: The exception to convert
        include_traceback: Include traceback in response (dev only)
    
    Returns:
        Dictionary suitable for JSON response
    """
    if isinstance(exception, ESPException):
        response = exception.to_dict()
        status_code = exception.status_code
    else:
        # Handle unexpected exceptions
        response = {
            'error': {
                'code': 'INTERNAL_ERROR',
                'message': 'An unexpected error occurred',
            }
        }
        status_code = 500
    
    if include_traceback:
        import traceback
        response['error']['traceback'] = traceback.format_exc()
    
    return response, status_code
