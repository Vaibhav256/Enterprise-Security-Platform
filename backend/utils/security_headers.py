"""
Security Headers Middleware

Adds security headers to all HTTP responses.

Author: NTRO Security Team
Date: 2025-11-27
"""

from flask import Flask, Response, request
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class SecurityHeadersMiddleware:
    """
    Middleware to add security headers to all responses
    
    Headers added:
    - X-Content-Type-Options: nosniff
    - X-Frame-Options: DENY
    - X-XSS-Protection: 1; mode=block
    - Strict-Transport-Security: max-age=31536000; includeSubDomains
    - Content-Security-Policy: default-src 'self'
    - Referrer-Policy: strict-origin-when-cross-origin
    - Permissions-Policy: geolocation=(), microphone=(), camera=()
    """
    
    def __init__(self, app: Flask, environment: str = 'development'):
        """
        Initialize security headers middleware
        
        Args:
            app: Flask application
            environment: Application environment (development/production)
        """
        self.app = app
        self.environment = environment
        
        # Register after_request handler
        app.after_request(self.add_security_headers)
        
        logger.info(f"✅ Security headers middleware initialized (env={environment})")
    
    def add_security_headers(self, response: Response) -> Response:
        """
        Add security headers to response
        
        Args:
            response: Flask response object
            
        Returns:
            Response with security headers added
        """
        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
        # Prevent clickjacking
        response.headers['X-Frame-Options'] = 'DENY'
        
        # Enable XSS protection (legacy, but still useful)
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Strict Transport Security (HTTPS only, add in production)
        if self.environment == 'production':
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        
        # Content Security Policy
        csp = self._build_csp_policy()
        response.headers['Content-Security-Policy'] = csp
        
        # Referrer Policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Permissions Policy (formerly Feature-Policy)
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        
        # Remove server header
        response.headers.pop('Server', None)
        
        return response
    
    def _build_csp_policy(self) -> str:
        """
        Build Content Security Policy based on environment
        
        Returns:
            CSP policy string
        """
        if self.environment == 'development':
            # Relaxed policy for development (allows localhost, inline scripts for debugging)
            csp_directives = [
                "default-src 'self'",
                "script-src 'self' 'unsafe-inline' 'unsafe-eval' localhost:* 127.0.0.1:*",
                "style-src 'self' 'unsafe-inline'",
                "img-src 'self' data: https:",
                "font-src 'self' data:",
                "connect-src 'self' ws://localhost:* ws://127.0.0.1:* http://localhost:* http://127.0.0.1:*",
                "frame-ancestors 'none'",
            ]
        else:
            # Strict policy for production
            csp_directives = [
                "default-src 'self'",
                "script-src 'self'",
                "style-src 'self'",
                "img-src 'self' data: https:",
                "font-src 'self'",
                "connect-src 'self' wss:",
                "frame-ancestors 'none'",
                "base-uri 'self'",
                "form-action 'self'",
            ]
        
        return '; '.join(csp_directives)


def init_security_headers(app: Flask, environment: Optional[str] = None) -> None:
    """
    Initialize security headers middleware
    
    Args:
        app: Flask application
        environment: Environment name (defaults to app.config['ENV'])
    """
    env = environment or app.config.get('ENV', 'development')
    SecurityHeadersMiddleware(app, environment=env)
