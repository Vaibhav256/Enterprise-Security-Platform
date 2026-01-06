"""
Configuration Module

This module handles application configuration from environment variables and config files.

Author: NTRO Security Team
Date: 2025-10-22
"""

import os
import sys
from typing import Any, Dict, Optional

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


import logging

logger = logging.getLogger(__name__)


class ConfigValidator:
    """Configuration validation utilities"""
    
    @staticmethod
    def validate_database_url(url: str) -> None:
        """Validate DATABASE_URL format"""
        if not url:
            raise ValueError("DATABASE_URL is required")
        
        if not url.startswith(('postgresql://', 'postgres://')):
            raise ValueError("DATABASE_URL must use PostgreSQL (postgresql:// or postgres://)")
        
        # Parse URL to check components
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            if not parsed.hostname:
                raise ValueError("DATABASE_URL missing hostname")
            if not parsed.username:
                raise ValueError("DATABASE_URL missing username")
        except Exception as e:
            raise ValueError(f"Invalid DATABASE_URL format: {e}")
    
    @staticmethod
    def validate_redis_config() -> None:
        """Validate Redis configuration"""
        host = os.getenv('REDIS_HOST')
        port = os.getenv('REDIS_PORT', '6379')
        
        if not host:
            raise ValueError("REDIS_HOST is required")
        
        try:
            port_int = int(port)
            if not (1 <= port_int <= 65535):
                raise ValueError(f"REDIS_PORT out of range (1-65535): {port_int}")
        except ValueError as e:
            raise ValueError(f"Invalid REDIS_PORT: {e}")
    
    @staticmethod
    def validate_secret_key(key: str, env: str) -> None:
        """Validate SECRET_KEY strength"""
        if env != 'production':
            return  # Relaxed validation in non-production
        
        if not key:
            raise ValueError("SECRET_KEY is required in production")
        
        if key == 'dev-secret-key-change-in-production':
            raise ValueError(
                "Production requires secure SECRET_KEY. "
                "Generate with: python -c 'import secrets; print(secrets.token_hex(32))'"
            )
        
        if len(key) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters in production")
    
    @staticmethod
    def validate_production_config() -> None:
        """Validate production-specific requirements"""
        env = os.getenv('FLASK_ENV', 'development')
        
        if env != 'production':
            return
        
        required_vars = ['SECRET_KEY', 'DATABASE_URL', 'REDIS_HOST']
        missing = [var for var in required_vars if not os.getenv(var)]
        
        if missing:
            raise ValueError(f"Missing required production variables: {', '.join(missing)}")
        
        # Validate individual components
        try:
            ConfigValidator.validate_secret_key(os.getenv('SECRET_KEY', ''), env)
            ConfigValidator.validate_database_url(os.getenv('DATABASE_URL', ''))
            ConfigValidator.validate_redis_config()
        except ValueError as e:
            raise ValueError(f"Production configuration validation failed: {e}")


def validate_required_env_vars():
    """Validate that required environment variables are set"""
    env = os.getenv("FLASK_ENV", "development")
    
    try:
        # Always validate basic configuration
        if os.getenv("DATABASE_URL"):
            ConfigValidator.validate_database_url(os.getenv("DATABASE_URL"))
        
        if os.getenv("REDIS_HOST"):
            ConfigValidator.validate_redis_config()
        
        # Production-specific validation
        if env == "production":
            ConfigValidator.validate_production_config()
            logger.info("✅ Production configuration validated successfully")
        else:
            logger.info(f"✅ Configuration validated for {env} environment")
            
    except ValueError as e:
        logger.error(f"❌ Configuration validation failed: {e}")
        if env == "production":
            sys.exit(1)  # Fail fast in production
        else:
            logger.warning("⚠️  Continuing in development mode with validation errors...")


# Validate on import
validate_required_env_vars()


class Config:
    """Base configuration"""

    # Application
    APP_NAME = "Vulnerability Scanner"
    VERSION = "1.0.0"
    DEBUG = os.getenv("FLASK_DEBUG", "0") == "1"
    
    # Authentication disabled - system operates without JWT tokens
    ENV = os.getenv("FLASK_ENV", "development")

    # API
    API_PORT = int(os.getenv("API_PORT", "5000"))
    API_HOST = os.getenv("API_HOST", "127.0.0.1")  # default to localhost to avoid binding all interfaces
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
    API_KEY = os.getenv("API_KEY", "")

    # Database
    DATABASE_URL = os.getenv(
        "DATABASE_URL",
        "postgresql://postgres:postgres@localhost:5432/vulnerability_scanner",
    )
    SQLALCHEMY_DATABASE_URI = DATABASE_URL  # SQLAlchemy compatibility
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = DEBUG

    # Redis
    REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
    REDIS_DB = int(os.getenv("REDIS_DB", "0"))
    REDIS_PASSWORD: Optional[str] = os.getenv("REDIS_PASSWORD", None)
    REDIS_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"

    # WSL Configuration
    WSL_DISTRIBUTION = os.getenv("WSL_DISTRIBUTION", "kali-linux")
    GVM_SOCKET_PATH = os.getenv("GVM_SOCKET_PATH", "/var/run/gvmd.sock")

    # Job Queue
    RQ_QUEUES = ["high", "default", "low"]
    DEFAULT_JOB_TIMEOUT = int(os.getenv("DEFAULT_JOB_TIMEOUT", "3600"))
    MAX_WORKER_JOBS = int(os.getenv("MAX_WORKER_JOBS", "10"))

    # Intelligence Layer Timeouts (for RAG chatbot operations)
    INTELLIGENCE_TIMEOUT = int(os.getenv("INTELLIGENCE_TIMEOUT", "120"))  # 120 seconds for RAG operations (retrieval + LLM inference + real-time enrichment)
    LLM_INFERENCE_TIMEOUT = int(os.getenv("LLM_INFERENCE_TIMEOUT", "60"))  # 60 seconds for Llama 3.2 inference
    RETRIEVAL_TIMEOUT = int(os.getenv("RETRIEVAL_TIMEOUT", "30"))  # 30 seconds for ChromaDB retrieval
    REALTIME_ENRICHMENT_TIMEOUT = int(os.getenv("REALTIME_ENRICHMENT_TIMEOUT", "20"))  # 20 seconds for NVD/CISA KEV lookups

    # Scan Configuration
    MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "5"))
    DEFAULT_SCAN_TIMEOUT = int(os.getenv("DEFAULT_SCAN_TIMEOUT", "3600"))
    SUPPORTED_TOOLS = ["nmap", "openvas", "nessus", "nikto", "nuclei"]
    # Bulk operations
    # Maximum number of scans allowed in a single bulk delete/export request.
    # Configure via environment variable MAX_BULK_DELETE; default is 100.
    MAX_BULK_DELETE = int(os.getenv("MAX_BULK_DELETE", "1000"))

    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FORMAT = os.getenv("LOG_FORMAT", "text")  # text or json

    # CORS
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")

    # SMTP Configuration
    SMTP_HOST = os.getenv("SMTP_HOST", "localhost")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "1") == "1"
    SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM = os.getenv("SMTP_FROM", "noreply@localhost")

    # Application URL
    APP_URL = os.getenv("APP_URL", "http://localhost:5000")

    # Webhook Configuration
    WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")

    # Alert Configuration
    ALERT_EMAIL = os.getenv("ALERT_EMAIL", "")
    ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL", "")

    @classmethod
    def to_dict(cls) -> Dict[str, Any]:
        """Convert config to dictionary"""
        return {
            key: value
            for key, value in cls.__dict__.items()
            if not key.startswith("_") and key.isupper()
        }


class DevelopmentConfig(Config):
    """Development configuration"""

    DEBUG = True
    ENV = "development"


class ProductionConfig(Config):
    """Production configuration"""

    DEBUG = False
    ENV = "production"
    SQLALCHEMY_ECHO = False


class TestingConfig(Config):
    """Testing configuration - Uses WSL PostgreSQL database"""

    TESTING = True
    DEBUG = True
    # Use the same PostgreSQL database as development (in WSL)
    # Tests will use transactions that rollback to avoid polluting data
    DATABASE_URL = os.getenv(
        "TEST_DATABASE_URL",
        "postgresql://postgres:postgres@localhost:5432/vulnerability_scanner"
    )
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    # Disable DB echo in tests to reduce noise
    SQLALCHEMY_ECHO = False


# Configuration dictionary
config_by_name = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}


def get_config(config_name: Optional[str] = None) -> type[Config]:
    """
    Get configuration by name

    Args:
        config_name: Configuration name (development, production, testing)

    Returns:
        Configuration class
    """
    if config_name is None:
        config_name = os.getenv("FLASK_ENV", "development")

    return config_by_name.get(config_name, DevelopmentConfig)
