"""
Input Validation and Sanitization Schemas

Provides marshmallow schemas and sanitization utilities for API inputs.

Author: NTRO Security Team
Date: 2025-11-27
"""

from marshmallow import Schema, fields, validate, validates, ValidationError, EXCLUDE
import re
from typing import Any, Dict
import html
import logging

logger = logging.getLogger(__name__)

# Constants
MAX_STRING_LENGTH = 1000
ALLOWED_SCAN_TYPES = ['nmap', 'openvas', 'nikto', 'nuclei', 'all']
ALLOWED_SEVERITIES = ['info', 'low', 'medium', 'high', 'critical']
ALLOWED_STATUSES = ['pending', 'running', 'completed', 'failed', 'cancelled']


class SanitizationMixin:
    """Mixin for field sanitization"""
    
    @staticmethod
    def sanitize_string(value: str) -> str:
        """Sanitize string input to prevent XSS"""
        if not value:
            return value
        
        # Escape HTML entities and normalize whitespace
        clean = html.escape(value)
        clean = ' '.join(clean.split())
        
        return clean
    
    @staticmethod
    def validate_no_sql_injection(value: str) -> bool:
        """Check for common SQL injection patterns"""
        if not value:
            return True
        
        # Patterns that might indicate SQL injection
        sql_patterns = [
            r"('\s*(OR|AND)\s*'?\d)",
            r"(;\s*DROP\s+TABLE)",
            r"(UNION\s+SELECT)",
            r"(--\s*$)",
            r"(/\*.*\*/)",
            r"(xp_cmdshell)",
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                raise ValidationError(f"Input contains suspicious pattern")
        
        return True


# Scan Schemas

class CreateScanSchema(Schema):
    """Schema for creating a new scan"""
    
    class Meta:
        unknown = EXCLUDE
    
    target = fields.Str(
        required=True,
        validate=[
            validate.Length(min=1, max=255),
            validate.Regexp(
                r'^[a-zA-Z0-9\.\-\_\:\/]+$',
                error="Target must be a valid hostname, IP, or CIDR"
            )
        ]
    )
    scan_type = fields.Str(
        required=True,
        validate=validate.OneOf(ALLOWED_SCAN_TYPES)
    )
    description = fields.Str(
        required=False,
        validate=validate.Length(max=500)
    )
    options = fields.Dict(
        required=False,
        keys=fields.Str(validate=validate.Length(max=50)),
        values=fields.Str(validate=validate.Length(max=500))
    )
    
    @validates('target')
    def validate_target(self, value):
        """Validate target field"""
        SanitizationMixin.validate_no_sql_injection(value)
    
    @validates('description')
    def validate_description(self, value):
        """Validate and sanitize description"""
        if value:
            SanitizationMixin.validate_no_sql_injection(value)


class UpdateScanSchema(Schema):
    """Schema for updating a scan"""
    
    class Meta:
        unknown = EXCLUDE
    
    status = fields.Str(
        required=False,
        validate=validate.OneOf(ALLOWED_STATUSES)
    )
    description = fields.Str(
        required=False,
        validate=validate.Length(max=500)
    )
    
    @validates('description')
    def validate_description(self, value):
        """Validate and sanitize description"""
        if value:
            SanitizationMixin.validate_no_sql_injection(value)


class ScanQuerySchema(Schema):
    """Schema for scan query parameters"""
    
    class Meta:
        unknown = EXCLUDE
    
    status = fields.Str(
        required=False,
        validate=validate.OneOf(ALLOWED_STATUSES)
    )
    scan_type = fields.Str(
        required=False,
        validate=validate.OneOf(ALLOWED_SCAN_TYPES)
    )
    target = fields.Str(
        required=False,
        validate=validate.Length(max=255)
    )
    limit = fields.Int(
        required=False,
        validate=validate.Range(min=1, max=100)
    )
    offset = fields.Int(
        required=False,
        validate=validate.Range(min=0)
    )
    
    @validates('target')
    def validate_target(self, value):
        """Validate target field"""
        if value:
            SanitizationMixin.validate_no_sql_injection(value)


# Vulnerability Schemas

class VulnerabilityQuerySchema(Schema):
    """Schema for vulnerability query parameters"""
    
    class Meta:
        unknown = EXCLUDE
    
    scan_id = fields.Int(required=False)
    severity = fields.Str(
        required=False,
        validate=validate.OneOf(ALLOWED_SEVERITIES)
    )
    limit = fields.Int(
        required=False,
        validate=validate.Range(min=1, max=100)
    )
    offset = fields.Int(
        required=False,
        validate=validate.Range(min=0)
    )
    search = fields.Str(
        required=False,
        validate=validate.Length(max=255)
    )
    
    @validates('search')
    def validate_search(self, value):
        """Validate search field"""
        if value:
            SanitizationMixin.validate_no_sql_injection(value)


# Chatbot Schemas

class ChatMessageSchema(Schema):
    """Schema for chatbot messages"""
    
    class Meta:
        unknown = EXCLUDE
    
    message = fields.Str(
        required=True,
        validate=validate.Length(min=1, max=2000)
    )
    session_id = fields.Str(
        required=False,
        validate=[
            validate.Length(max=100),
            validate.Regexp(
                r'^[a-zA-Z0-9\-]+$',
                error="Session ID must contain only alphanumeric characters and hyphens"
            )
        ]
    )
    
    @validates('message')
    def validate_message(self, value):
        """Validate and sanitize message"""
        SanitizationMixin.validate_no_sql_injection(value)


# Helper Functions

def validate_request_data(schema: Schema, data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and sanitize request data"""
    try:
        result = schema.load(data)
        logger.debug(f"Request data validated successfully")
        return result
    except ValidationError as e:
        logger.warning(f"Validation error: {e.messages}")
        raise


def validate_id(id_value: Any, field_name: str = "id") -> int:
    """Validate ID parameter"""
    try:
        id_int = int(id_value)
        if id_int <= 0:
            raise ValueError("ID must be positive")
        return id_int
    except (TypeError, ValueError) as e:
        raise ValidationError({field_name: [f"Invalid ID: {str(e)}"]})


# Schema instances
create_scan_schema = CreateScanSchema()
update_scan_schema = UpdateScanSchema()
scan_query_schema = ScanQuerySchema()
vulnerability_query_schema = VulnerabilityQuerySchema()
chat_message_schema = ChatMessageSchema()
