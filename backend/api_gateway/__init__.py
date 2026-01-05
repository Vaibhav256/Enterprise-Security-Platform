"""
API Gateway Package

Flask REST API for the Centralized Vulnerability Detection Platform.
Provides endpoints for scan management, execution, and results retrieval.

Author: NTRO Security Team
Date: 2025-10-22
"""

from .app import create_app

__all__ = ["create_app"]
