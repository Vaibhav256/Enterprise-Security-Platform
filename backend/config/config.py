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


def validate_required_env_vars():
    """Validate that required environment variables are set for production"""
    if os.getenv("FLASK_ENV") == "production":
        required_vars = [
            "SECRET_KEY",
            "DATABASE_URL",
            "REDIS_HOST",
        ]
        
        missing_vars = [var for var in required_vars if not os.getenv(var)]
        
        if missing_vars:
            print(f"ERROR: Missing required environment variables: {', '.join(missing_vars)}", file=sys.stderr)
            print("Please set these variables before starting in production mode.", file=sys.stderr)
            sys.exit(1)
        
        # Warn about default SECRET_KEY
        if os.getenv("SECRET_KEY") == "dev-secret-key-change-in-production":
            print("WARNING: Using default SECRET_KEY in production! This is insecure.", file=sys.stderr)


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
    API_HOST = os.getenv("API_HOST", "0.0.0.0")
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
