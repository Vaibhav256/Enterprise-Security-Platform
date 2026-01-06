"""
CORS Configuration

Environment-specific CORS policies with proper origin validation.

Author: NTRO Security Team
Date: 2025-11-27
"""

import os
import re
from flask import Flask
from flask_cors import CORS
from typing import List, Optional
import logging

logger = logging.getLogger(__name__)


class CORSConfig:
    """CORS configuration with environment-aware policies"""
    
    # Development allowed origins
    DEV_ORIGINS = [
        'http://localhost:3000',
        'http://localhost:5173',  # Vite default
        'http://127.0.0.1:3000',
        'http://127.0.0.1:5173',
    ]
    
    # Production origins (loaded from environment)
    PROD_ORIGINS_ENV = 'ALLOWED_ORIGINS'
    
    @classmethod
    def get_allowed_origins(cls, environment: str) -> List[str]:
        """
        Get allowed origins based on environment
        
        Args:
            environment: Application environment
            
        Returns:
            List of allowed origin patterns
        """
        if environment == 'production':
            # Load from environment variable
            origins_str = os.getenv(cls.PROD_ORIGINS_ENV, '')
            
            if not origins_str:
                logger.warning("⚠️ No ALLOWED_ORIGINS set in production! CORS will block all origins.")
                return []
            
            # Parse comma-separated origins
            origins = [origin.strip() for origin in origins_str.split(',')]
            logger.info(f"✅ Production CORS origins: {', '.join(origins)}")
            return origins
        
        else:
            # Development - allow localhost on common ports
            logger.info(f"✅ Development CORS origins: {', '.join(cls.DEV_ORIGINS)}")
            return cls.DEV_ORIGINS
    
    @classmethod
    def validate_origin(cls, origin: str, allowed_origins: List[str]) -> bool:
        """
        Validate if origin is allowed
        
        Args:
            origin: Origin to validate
            allowed_origins: List of allowed origin patterns
            
        Returns:
            True if origin is allowed
        """
        if not origin:
            return False
        
        # Check exact match first
        if origin in allowed_origins:
            return True
        
        # Check regex patterns (if origin starts with regex:)
        for allowed in allowed_origins:
            if allowed.startswith('regex:'):
                pattern = allowed[6:]  # Remove 'regex:' prefix
                if re.match(pattern, origin):
                    return True
        
        return False


def init_cors(app: Flask, environment: Optional[str] = None) -> None:
    """
    Initialize CORS with environment-specific configuration
    
    Args:
        app: Flask application
        environment: Environment name (defaults to app.config['ENV'])
    """
    env = environment or app.config.get('ENV', 'development')
    allowed_origins = CORSConfig.get_allowed_origins(env)
    
    if env == 'production':
        # Strict CORS for production
        cors_config = {
            'origins': allowed_origins,
            'methods': ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
            'allow_headers': ['Content-Type', 'Authorization', 'X-Request-ID'],
            'expose_headers': ['X-Request-ID', 'X-Total-Count'],
            'supports_credentials': False,  # Don't allow credentials unless needed
            'max_age': 3600,  # Cache preflight for 1 hour
        }
    else:
        # Relaxed CORS for development
        cors_config = {
            'origins': allowed_origins,
            'methods': ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
            'allow_headers': '*',
            'expose_headers': ['X-Request-ID', 'X-Total-Count'],
            'supports_credentials': True,  # Allow credentials in development
            'max_age': 600,  # Cache preflight for 10 minutes
        }
    
    # Apply CORS to API routes only
    CORS(app, resources={r"/api/*": cors_config, r"/health/*": cors_config})
    
    logger.info(f"✅ CORS configured for {env} environment")
