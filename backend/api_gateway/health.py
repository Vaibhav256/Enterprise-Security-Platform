"""
Enhanced Health Check Endpoints

Provides comprehensive health monitoring for load balancers,
Kubernetes, Docker health checks, and monitoring systems.

Endpoints:
    /health          - Basic liveness check (always returns 200)
    /health/live     - Liveness probe (is app running?)
    /health/ready    - Readiness probe (can app serve traffic?)
    /health/startup  - Startup probe (has app initialized?)

Author: NTRO Security Team
Date: 2025-11-27
"""

import logging
import os
import time
from typing import Dict, Any

from flask import Blueprint, jsonify, current_app

logger = logging.getLogger(__name__)

health_bp = Blueprint('health', __name__)


def check_database() -> Dict[str, Any]:
    """
    Check database connectivity and responsiveness
    
    Fixed: Proper connection cleanup to prevent connection pool exhaustion
    """
    try:
        from config.database import SessionLocal
        start_time = time.time()
        
        # Use context manager to ensure connection is properly closed
        session = SessionLocal()
        try:
            # Test connection with simple query
            session.execute("SELECT 1")
            session.commit()
            
            response_time = (time.time() - start_time) * 1000  # Convert to ms
            return {
                'status': 'healthy',
                'message': 'Connected',
                'response_time_ms': round(response_time, 2)
            }
        finally:
            # CRITICAL: Always close the session
            session.close()
            
    except Exception as e:
        logger.error(f"Database health check failed: {e}", exc_info=True)
        return {
            'status': 'unhealthy',
            'message': str(e)
        }


def check_redis() -> Dict[str, Any]:
    """
    Check Redis connectivity and responsiveness
    
    Fixed: Proper connection cleanup with timeout
    """
    try:
        import redis
        redis_url = os.getenv('REDIS_URL', f"redis://{os.getenv('REDIS_HOST', 'localhost')}:{os.getenv('REDIS_PORT', 6379)}/{os.getenv('REDIS_DB', 0)}")
        
        start_time = time.time()
        # Add socket_timeout and socket_connect_timeout
        client = redis.from_url(
            redis_url,
            socket_timeout=5,
            socket_connect_timeout=5,
            decode_responses=True
        )
        
        try:
            # Test connection
            client.ping()
            response_time = (time.time() - start_time) * 1000
            
            return {
                'status': 'healthy',
                'message': 'Connected',
                'response_time_ms': round(response_time, 2)
            }
        finally:
            # CRITICAL: Close connection
            client.close()
            
    except redis.ConnectionError as e:
        logger.error(f"Redis connection failed: {e}")
        return {
            'status': 'unhealthy',
            'message': 'Connection failed'
        }
    except redis.TimeoutError as e:
        logger.error(f"Redis timeout: {e}")
        return {
            'status': 'unhealthy',
            'message': 'Connection timeout'
        }
    except Exception as e:
        logger.error(f"Redis health check failed: {e}", exc_info=True)
        return {
            'status': 'unhealthy',
            'message': str(e)
        }


def check_disk_space() -> Dict[str, Any]:
    """Check available disk space"""
    try:
        import shutil
        total, used, free = shutil.disk_usage('/')
        free_percent = (free / total) * 100
        free_gb = free / (1024 ** 3)
        
        status = 'healthy'
        if free_percent < 10:
            status = 'critical'
        elif free_percent < 20:
            status = 'warning'
        
        return {
            'status': status,
            'free_percent': round(free_percent, 2),
            'free_gb': round(free_gb, 2),
            'message': f'{round(free_gb, 1)}GB free ({round(free_percent, 1)}%)'
        }
    except Exception as e:
        logger.error(f"Disk space check failed: {e}")
        return {
            'status': 'unknown',
            'message': str(e)
        }


def check_chromadb() -> Dict[str, Any]:
    """Check ChromaDB (vector database) connectivity"""
    try:
        # Only check if intelligence layer is enabled
        if not os.getenv('ENABLE_RAG_CHATBOT', 'True').lower() == 'true':
            return {
                'status': 'disabled',
                'message': 'RAG chatbot feature disabled'
            }
        
        # Basic check - just verify the directory exists
        chroma_dir = os.getenv('CHROMA_PERSIST_DIR', './chroma_db')
        if os.path.exists(chroma_dir):
            return {
                'status': 'healthy',
                'message': 'ChromaDB directory accessible'
            }
        else:
            return {
                'status': 'warning',
                'message': 'ChromaDB directory not found (will be created on first use)'
            }
    except Exception as e:
        logger.error(f"ChromaDB health check failed: {e}")
        return {
            'status': 'unknown',
            'message': str(e)
        }


@health_bp.route('/health', methods=['GET'])
def health():
    """
    Basic health check endpoint
    
    Returns 200 OK if the application is running.
    Use this for basic liveness checks.
    """
    return jsonify({
        'status': 'healthy',
        'service': 'esp-api-gateway',
        'version': '1.0.0',
        'timestamp': time.time()
    }), 200


@health_bp.route('/health/live', methods=['GET'])
def liveness():
    """
    Liveness probe for Kubernetes/Docker
    
    Returns 200 if the application process is running.
    Kubernetes will restart the pod if this fails.
    """
    return jsonify({
        'status': 'alive',
        'timestamp': time.time()
    }), 200


@health_bp.route('/health/ready', methods=['GET'])
def readiness():
    """
    Readiness probe for Kubernetes/Docker
    
    Returns 200 only if the application can serve traffic.
    Checks all critical dependencies (database, Redis, etc.).
    Load balancers will remove the instance from rotation if this fails.
    """
    checks = {
        'database': check_database(),
        'redis': check_redis(),
        'disk_space': check_disk_space(),
        'chromadb': check_chromadb(),
    }
    
    # Determine overall health
    critical_checks = ['database', 'redis']
    all_critical_healthy = all(
        checks[name]['status'] in ['healthy', 'disabled'] 
        for name in critical_checks
    )
    
    # Check for any critical failures
    has_critical_failure = any(
        checks[name]['status'] == 'critical'
        for name in checks
    )
    
    if all_critical_healthy and not has_critical_failure:
        status = 'ready'
        status_code = 200
    else:
        status = 'not_ready'
        status_code = 503
    
    return jsonify({
        'status': status,
        'checks': checks,
        'timestamp': time.time(),
        'environment': os.getenv('FLASK_ENV', 'unknown')
    }), status_code


@health_bp.route('/health/startup', methods=['GET'])
def startup():
    """
    Startup probe for Kubernetes
    
    Returns 200 when the application has finished initializing.
    Kubernetes will wait for this before checking liveness/readiness.
    """
    # Check if critical components are initialized
    checks = {
        'database': check_database(),
        'redis': check_redis(),
    }
    
    all_initialized = all(
        check['status'] == 'healthy'
        for check in checks.values()
    )
    
    if all_initialized:
        return jsonify({
            'status': 'started',
            'checks': checks,
            'timestamp': time.time()
        }), 200
    else:
        return jsonify({
            'status': 'starting',
            'checks': checks,
            'timestamp': time.time()
        }), 503


@health_bp.route('/health/detailed', methods=['GET'])
def detailed():
    """
    Detailed health information for monitoring dashboards
    
    Returns comprehensive system health information.
    Should be protected in production (add authentication).
    """
    import sys
    import platform
    
    checks = {
        'database': check_database(),
        'redis': check_redis(),
        'disk_space': check_disk_space(),
        'chromadb': check_chromadb(),
    }
    
    system_info = {
        'python_version': sys.version,
        'platform': platform.platform(),
        'environment': os.getenv('FLASK_ENV', 'unknown'),
        'hostname': platform.node(),
    }
    
    return jsonify({
        'status': 'healthy',
        'checks': checks,
        'system': system_info,
        'timestamp': time.time()
    }), 200
