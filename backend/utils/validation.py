"""
Input validation utilities for ESP API endpoints.

Provides validation functions for:
- Pagination parameters (limit, offset, page, per_page)
- Search queries (XSS, SQL injection prevention)
- File paths (path traversal prevention)
- Numeric ranges (bounds checking)
- String inputs (length, pattern validation)
"""

import re
from typing import Optional, Any
from flask import abort
import html


# Validation constants
MAX_PER_PAGE = 100
MAX_LIMIT = 1000
MAX_OFFSET = 1000000
MAX_SEARCH_LENGTH = 500
MAX_DAYS = 365

# File upload validation constants (Issue S2)
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
ALLOWED_MIME_TYPES = {
    'application/pdf',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',  # .xlsx
    'application/vnd.ms-excel',  # .xls
    'text/csv',
    'text/plain',
    'application/json',
    'application/xml',
    'text/xml'
}
ALLOWED_FILE_EXTENSIONS = {'.pdf', '.xlsx', '.xls', '.csv', '.txt', '.json', '.xml'}

# Safe patterns
SAFE_SCAN_ID_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{1,64}$')
SAFE_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9_.-]{1,255}$')
CVE_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)


def validate_pagination(page: int = 1, per_page: int = 20) -> tuple[int, int]:
    """
    Validate and sanitize pagination parameters.
    
    Args:
        page: Page number (1-indexed)
        per_page: Items per page
        
    Returns:
        tuple: (validated_page, validated_per_page)
        
    Raises:
        ValueError: If parameters are invalid
    """
    if page < 1:
        raise ValueError("page must be at least 1")
    if per_page < 1:
        raise ValueError("per_page must be at least 1")
    if per_page > MAX_PER_PAGE:
        raise ValueError(f"per_page cannot exceed {MAX_PER_PAGE}")
    
    return page, per_page


def validate_limit_offset(limit: int = 50, offset: int = 0) -> tuple[int, int]:
    """
    Validate and sanitize limit/offset parameters.
    
    Args:
        limit: Maximum number of results
        offset: Number of results to skip
        
    Returns:
        tuple: (validated_limit, validated_offset)
        
    Raises:
        ValueError: If parameters are invalid
    """
    if limit < 1:
        raise ValueError("limit must be at least 1")
    if limit > MAX_LIMIT:
        raise ValueError(f"limit cannot exceed {MAX_LIMIT}")
    if offset < 0:
        raise ValueError("offset cannot be negative")
    if offset > MAX_OFFSET:
        raise ValueError(f"offset cannot exceed {MAX_OFFSET}")
    
    return limit, offset


def validate_days(days: int, max_days: int = MAX_DAYS) -> int:
    """
    Validate days parameter.
    
    Args:
        days: Number of days
        max_days: Maximum allowed days
        
    Returns:
        int: Validated days
        
    Raises:
        ValueError: If days is invalid
    """
    if days < 1:
        raise ValueError("days must be at least 1")
    if days > max_days:
        raise ValueError(f"days cannot exceed {max_days}")
    
    return days


def sanitize_search_query(query: str) -> str:
    """
    Sanitize search query to prevent XSS and SQL injection.
    
    Args:
        query: Raw search query
        
    Returns:
        str: Sanitized query
        
    Raises:
        ValueError: If query is too long or contains dangerous patterns
    """
    if not query:
        return ""
    
    # Length check
    if len(query) > MAX_SEARCH_LENGTH:
        raise ValueError(f"search query cannot exceed {MAX_SEARCH_LENGTH} characters")
    
    # Remove HTML/JS (XSS prevention) using html.escape instead of bleach
    sanitized = html.escape(query, quote=True)
    
    # Check for SQL injection patterns
    dangerous_patterns = [
        r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE)\b)',
        r'(--|;|\/\*|\*\/)',
        r'(\bOR\b.*\b=\b)',
        r'(\bAND\b.*\b=\b)',
        r'(\'.*\'.*=.*\')',
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, sanitized, re.IGNORECASE):
            raise ValueError("search query contains potentially dangerous patterns")
    
    return sanitized.strip()


def validate_scan_id(scan_id: str) -> str:
    """
    Validate scan ID format.
    
    Args:
        scan_id: Scan identifier
        
    Returns:
        str: Validated scan ID
        
    Raises:
        ValueError: If scan ID format is invalid
    """
    if not scan_id:
        raise ValueError("scan_id is required")
    
    if not SAFE_SCAN_ID_PATTERN.match(scan_id):
        raise ValueError("scan_id contains invalid characters")
    
    return scan_id


def validate_filename(filename: str) -> str:
    """
    Validate filename to prevent path traversal.
    
    Args:
        filename: File name
        
    Returns:
        str: Validated filename
        
    Raises:
        ValueError: If filename is unsafe
    """
    if not filename:
        raise ValueError("filename is required")
    
    # Check for path traversal
    if '..' in filename or '/' in filename or '\\' in filename:
        raise ValueError("filename contains path traversal patterns")
    
    if not SAFE_FILENAME_PATTERN.match(filename):
        raise ValueError("filename contains invalid characters")
    
    return filename


def validate_cve_id(cve_id: str) -> str:
    """
    Validate CVE ID format.
    
    Args:
        cve_id: CVE identifier
        
    Returns:
        str: Validated CVE ID
        
    Raises:
        ValueError: If CVE ID format is invalid
    """
    if not cve_id:
        raise ValueError("cve_id is required")
    
    if not CVE_PATTERN.match(cve_id):
        raise ValueError("Invalid CVE ID format (expected: CVE-YYYY-NNNN)")
    
    return cve_id.upper()


def validate_severity(severity: Optional[str]) -> Optional[str]:
    """
    Validate severity level.
    
    Args:
        severity: Severity level
        
    Returns:
        str or None: Validated severity level
        
    Raises:
        ValueError: If severity is invalid
    """
    if not severity:
        return None
    
    valid_severities = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'}
    severity_upper = severity.upper()
    
    if severity_upper not in valid_severities:
        raise ValueError(f"severity must be one of: {', '.join(valid_severities)}")
    
    return severity_upper


def validate_status(status: Optional[str]) -> Optional[str]:
    """
    Validate scan status.
    
    Args:
        status: Status value
        
    Returns:
        str or None: Validated status
        
    Raises:
        ValueError: If status is invalid
    """
    if not status:
        return None
    
    valid_statuses = {'PENDING', 'QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED'}
    status_upper = status.upper()
    
    if status_upper not in valid_statuses:
        raise ValueError(f"status must be one of: {', '.join(valid_statuses)}")
    
    return status_upper


def validate_positive_integer(value: int, param_name: str = "parameter", min_value: int = 1, max_value: Optional[int] = None) -> int:
    """
    Validate that an integer is positive and within bounds.
    
    Args:
        value: Integer value to validate
        param_name: Parameter name for error messages
        min_value: Minimum allowed value (default: 1)
        max_value: Maximum allowed value (optional)
        
    Returns:
        int: Validated integer value
        
    Raises:
        ValueError: If value is invalid
    """
    if value < min_value:
        raise ValueError(f"{param_name} must be at least {min_value}")
    
    if max_value is not None and value > max_value:
        raise ValueError(f"{param_name} cannot exceed {max_value}")
    
    return value


def validate_boolean_param(value: str, param_name: str = "parameter") -> bool:
    """
    Validate and convert boolean query parameter.
    
    Args:
        value: String value ('true', 'false', '1', '0', 'yes', 'no')
        param_name: Parameter name for error messages
        
    Returns:
        bool: Validated boolean value
        
    Raises:
        ValueError: If value is not a valid boolean
    """
    if not value:
        return False
    
    value_lower = value.lower()
    
    if value_lower in {'true', '1', 'yes'}:
        return True
    elif value_lower in {'false', '0', 'no'}:
        return False
    else:
        raise ValueError(f"{param_name} must be a boolean (true/false)")


def safe_int(value: Any, default: int = 0, min_val: Optional[int] = None, max_val: Optional[int] = None) -> int:
    """
    Safely convert value to integer with bounds checking.
    
    Args:
        value: Value to convert
        default: Default value if conversion fails
        min_val: Minimum allowed value
        max_val: Maximum allowed value
        
    Returns:
        int: Validated integer
        
    Raises:
        ValueError: If value is out of bounds
    """
    try:
        result = int(value)
    except (ValueError, TypeError):
        result = default
    
    if min_val is not None and result < min_val:
        raise ValueError(f"value must be at least {min_val}")
    if max_val is not None and result > max_val:
        raise ValueError(f"value cannot exceed {max_val}")
    
    return result


def validate_report_organization(organization: Optional[str]) -> str:
    """
    Validate and sanitize organization name for reports.
    
    Args:
        organization: Organization name
        
    Returns:
        str: Validated organization name
        
    Raises:
        ValueError: If organization name is invalid
    """
    if not organization:
        return "NTRO"  # Default value
    
    # Length check
    if len(organization) > 100:
        raise ValueError("organization name cannot exceed 100 characters")
    
    # Sanitize HTML/XSS
    sanitized = html.escape(organization, quote=True)
    
    # Allow only alphanumeric, spaces, and basic punctuation
    if not re.match(r'^[a-zA-Z0-9\s\-_.,&()]+$', sanitized):
        raise ValueError("organization name contains invalid characters")
    
    return sanitized.strip()


def validate_report_classification(classification: Optional[str]) -> str:
    """
    Validate classification level for reports.
    
    Args:
        classification: Classification level
        
    Returns:
        str: Validated classification level
        
    Raises:
        ValueError: If classification is invalid
    """
    if not classification:
        return "CONFIDENTIAL"  # Default value
    
    valid_classifications = {
        'UNCLASSIFIED',
        'CONFIDENTIAL',
        'SECRET',
        'TOP SECRET',
        'INTERNAL',
        'PUBLIC'
    }
    
    classification_upper = classification.upper()
    
    if classification_upper not in valid_classifications:
        raise ValueError(f"classification must be one of: {', '.join(valid_classifications)}")
    
    return classification_upper


def validate_report_options(options: dict) -> dict:
    """
    Validate report generation options.
    
    Args:
        options: Report options dictionary
        
    Returns:
        dict: Validated options
        
    Raises:
        ValueError: If options are invalid
    """
    # Limit options dict size to prevent DoS
    max_options_size = 10 * 1024  # 10KB
    import json
    options_json = json.dumps(options)
    if len(options_json) > max_options_size:
        raise ValueError(f"options dictionary too large (max {max_options_size} bytes)")
    
    validated = {}
    
    # Validate boolean options
    for bool_key in ['include_attack_paths', 'include_charts', 'include_mitigations']:
        if bool_key in options:
            validated[bool_key] = bool(options[bool_key])
    
    # Validate string options
    if 'organization' in options:
        validated['organization'] = validate_report_organization(options['organization'])
    
    if 'classification' in options:
        validated['classification'] = validate_report_classification(options['classification'])
    
    return validated


def validate_file_upload(file_size: int, mime_type: str, filename: str) -> None:
    """
    Validate file upload parameters (Issue S2).
    
    Validates:
    - File size within limits
    - MIME type is allowed
    - File extension is whitelisted
    
    Args:
        file_size: File size in bytes
        mime_type: MIME type of uploaded file
        filename: Name of uploaded file
        
    Raises:
        ValueError: If file upload validation fails
    """
    # Size check
    if file_size < 1:
        raise ValueError("file cannot be empty")
    
    if file_size > MAX_FILE_SIZE:
        raise ValueError(f"file size exceeds maximum allowed size ({MAX_FILE_SIZE / (1024 * 1024):.1f} MB)")
    
    # MIME type check
    if mime_type not in ALLOWED_MIME_TYPES:
        raise ValueError(f"file type '{mime_type}' not allowed. Allowed types: {', '.join(ALLOWED_MIME_TYPES)}")
    
    # Extension check
    import os
    file_ext = os.path.splitext(filename)[1].lower()
    
    if file_ext not in ALLOWED_FILE_EXTENSIONS:
        raise ValueError(f"file extension '{file_ext}' not allowed. Allowed extensions: {', '.join(ALLOWED_FILE_EXTENSIONS)}")
    
    # Filename safety check (prevent path traversal)
    validate_filename(filename)


def get_mime_type_from_file(file_content: bytes) -> str:
    """
    Detect MIME type from file content (Issue S2).
    
    Uses file magic bytes to detect actual MIME type,
    preventing MIME type spoofing attacks.
    
    Args:
        file_content: File content bytes
        
    Returns:
        str: Detected MIME type
        
    Raises:
        ValueError: If MIME type cannot be detected
    """
    # Simple magic byte detection
    # For production, consider using 'python-magic' library
    
    if file_content.startswith(b'%PDF'):
        return 'application/pdf'
    elif file_content.startswith(b'PK\x03\x04'):  # ZIP-based formats (XLSX)
        return 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    elif file_content.startswith(b'\xd0\xcf\x11\xe0'):  # XLS (MS Office)
        return 'application/vnd.ms-excel'
    elif file_content.startswith(b'{') or file_content.startswith(b'['):  # JSON
        return 'application/json'
    elif file_content.startswith(b'<?xml') or file_content.startswith(b'<'):  # XML
        return 'application/xml'
    else:
        # Assume text/plain for other formats
        try:
            file_content.decode('utf-8')
            return 'text/plain'
        except UnicodeDecodeError:
            raise ValueError("unsupported file format (unable to detect MIME type)")

