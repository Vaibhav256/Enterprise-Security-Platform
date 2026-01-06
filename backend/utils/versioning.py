"""
API Versioning Blueprint

Provides API versioning support with /api/v1/ prefix and version negotiation.

Author: NTRO Security Team
Date: 2025-11-27
"""

from flask import Blueprint, jsonify, request
from functools import wraps
import logging

logger = logging.getLogger(__name__)

# API version constants
CURRENT_VERSION = 'v1'
SUPPORTED_VERSIONS = ['v1']
DEPRECATED_VERSIONS = []


def create_versioned_blueprint(name: str, version: str = 'v1', **kwargs):
    """
    Create a Flask blueprint with API versioning
    
    Args:
        name: Blueprint name
        version: API version (e.g., 'v1')
        **kwargs: Additional blueprint arguments
    
    Returns:
        Versioned blueprint with /api/v{version} prefix
    """
    url_prefix = f'/api/{version}'
    return Blueprint(name, __name__, url_prefix=url_prefix, **kwargs)


def require_api_version(*versions):
    """
    Decorator to require specific API versions
    
    Args:
        *versions: Accepted versions (e.g., 'v1', 'v2')
    
    Example:
        @require_api_version('v1', 'v2')
        def my_endpoint():
            return {'data': 'value'}
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Extract version from URL path
            path_version = None
            if request.path.startswith('/api/'):
                parts = request.path.split('/')
                if len(parts) > 2 and parts[2].startswith('v'):
                    path_version = parts[2]
            
            # Check if version is accepted
            if path_version not in versions:
                return jsonify({
                    'error': {
                        'code': 'UNSUPPORTED_VERSION',
                        'message': f'API version {path_version} is not supported for this endpoint',
                        'supported_versions': list(versions)
                    }
                }), 400
            
            return f(*args, **kwargs)
        return wrapped
    return decorator


def deprecated(deprecated_in: str, removed_in: str = None, alternative: str = None):
    """
    Decorator to mark endpoint as deprecated
    
    Args:
        deprecated_in: Version when deprecated (e.g., 'v2')
        removed_in: Version when it will be removed (optional)
        alternative: Alternative endpoint to use (optional)
    
    Example:
        @deprecated(deprecated_in='v2', removed_in='v3', alternative='/api/v2/scans')
        def old_endpoint():
            return {'data': 'value'}
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Add deprecation warning header
            response = f(*args, **kwargs)
            
            if isinstance(response, tuple):
                data, status_code = response[0], response[1]
            else:
                data, status_code = response, 200
            
            # Build deprecation message
            warning = f'299 - "Endpoint deprecated in {deprecated_in}'
            if removed_in:
                warning += f', will be removed in {removed_in}'
            if alternative:
                warning += f'. Use {alternative} instead'
            warning += '"'
            
            # Return response with warning header
            if isinstance(data, dict):
                data = jsonify(data)
            
            if hasattr(data, 'headers'):
                data.headers['Warning'] = warning
                data.headers['Sunset'] = removed_in or 'TBD'
                if alternative:
                    data.headers['Link'] = f'<{alternative}>; rel="alternate"'
            
            return data, status_code
        return wrapped
    return decorator


# Version info endpoint
api_info_bp = Blueprint('api_info', __name__)


@api_info_bp.route('/version')
def api_version_info():
    """
    API version information endpoint
    
    Returns information about available API versions
    """
    return jsonify({
        'current_version': CURRENT_VERSION,
        'supported_versions': SUPPORTED_VERSIONS,
        'deprecated_versions': DEPRECATED_VERSIONS,
        'endpoints': {
            'v1': {
                'base_url': '/api/v1',
                'docs': '/api/docs',
                'health': '/health',
            }
        },
        'message': f'Use /api/ for current API version'
    }), 200
