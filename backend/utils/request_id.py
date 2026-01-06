"""
Request ID Middleware

Adds unique request IDs to all requests for tracing and debugging.

Author: NTRO Security Team  
Date: 2025-11-27
"""

import uuid
import logging
from flask import Flask, request, g
from typing import Optional

logger = logging.getLogger(__name__)


class RequestIDMiddleware:
    """
    Middleware to add request IDs to all incoming requests
    
    Generates a unique UUID for each request and adds it to:
    - Flask's g object for access within request context
    - Response headers (X-Request-ID)
    - Log records for correlation
    """
    
    def __init__(self, app: Optional[Flask] = None, header_name: str = 'X-Request-ID'):
        """
        Initialize middleware
        
        Args:
            app: Flask application (optional, can use init_app later)
            header_name: Header name for request ID
        """
        self.header_name = header_name
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask) -> None:
        """
        Initialize middleware with Flask app
        
        Args:
            app: Flask application instance
        """
        app.before_request(self._before_request)
        app.after_request(self._after_request)
        
        # Add custom log filter
        self._setup_logging()
        
        logger.info(f"✅ Request ID middleware initialized (header: {self.header_name})")
    
    def _before_request(self) -> None:
        """Generate and store request ID before request processing"""
        # Check if request ID already exists in headers (forwarded from proxy)
        request_id = request.headers.get(self.header_name)
        
        if not request_id:
            # Generate new request ID
            request_id = str(uuid.uuid4())
        
        # Store in Flask's g object for access during request
        g.request_id = request_id
    
    def _after_request(self, response):
        """Add request ID to response headers"""
        if hasattr(g, 'request_id'):
            response.headers[self.header_name] = g.request_id
        return response
    
    def _setup_logging(self) -> None:
        """Setup logging filter to include request ID in all logs"""
        
        class RequestIDFilter(logging.Filter):
            """Log filter that adds request ID to log records"""
            
            def filter(self, record):
                # Add request ID to log record if available
                record.request_id = getattr(g, 'request_id', '-')
                return True
        
        # Add filter to root logger
        logging.getLogger().addFilter(RequestIDFilter())


def get_request_id() -> Optional[str]:
    """
    Get current request ID
    
    Returns:
        Request ID string or None if not in request context
    """
    return getattr(g, 'request_id', None)
