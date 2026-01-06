"""
Global Error Handlers for Flask Application

Registers error handlers for consistent error responses across the API.

Author: NTRO Security Team
Date: 2025-11-27
"""

import logging
import os
from typing import Tuple, Dict, Any
from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

from utils.exceptions import ESPException, create_error_response

logger = logging.getLogger(__name__)


def register_error_handlers(app: Flask) -> None:
    """
    Register global error handlers for the Flask application
    
    Args:
        app: Flask application instance
    """
    
    include_traceback = os.getenv('FLASK_ENV', 'production') == 'development'
    
    @app.errorhandler(ESPException)
    def handle_esp_exception(error: ESPException) -> Tuple[Dict[str, Any], int]:
        """Handle custom ESP exceptions"""
        logger.error(
            f"ESP Exception: {error.error_code} - {error.message}",
            extra={
                'error_code': error.error_code,
                'status_code': error.status_code,
                'details': error.details,
                'path': request.path,
                'method': request.method,
            }
        )
        
        response, status_code = create_error_response(error, include_traceback)
        return jsonify(response), status_code
    
    @app.errorhandler(HTTPException)
    def handle_http_exception(error: HTTPException) -> Tuple[Dict[str, Any], int]:
        """Handle Werkzeug HTTP exceptions"""
        logger.warning(
            f"HTTP Exception: {error.code} - {error.name}",
            extra={
                'status_code': error.code,
                'path': request.path,
                'method': request.method,
            }
        )
        
        response = {
            'error': {
                'code': error.name.upper().replace(' ', '_'),
                'message': error.description or str(error),
            }
        }
        
        return jsonify(response), error.code
    
    @app.errorhandler(404)
    def handle_not_found(error) -> Tuple[Dict[str, Any], int]:
        """Handle 404 Not Found"""
        return jsonify({
            'error': {
                'code': 'NOT_FOUND',
                'message': f'The requested URL {request.path} was not found',
            }
        }), 404
    
    @app.errorhandler(405)
    def handle_method_not_allowed(error) -> Tuple[Dict[str, Any], int]:
        """Handle 405 Method Not Allowed"""
        return jsonify({
            'error': {
                'code': 'METHOD_NOT_ALLOWED',
                'message': f'Method {request.method} not allowed for {request.path}',
            }
        }), 405
    
    @app.errorhandler(500)
    def handle_internal_error(error: Exception) -> Tuple[Dict[str, Any], int]:
        """Handle 500 Internal Server Error"""
        logger.exception(
            "Internal server error",
            extra={
                'path': request.path,
                'method': request.method,
            }
        )
        
        response = {
            'error': {
                'code': 'INTERNAL_ERROR',
                'message': 'An internal server error occurred',
            }
        }
        
        if include_traceback:
            import traceback
            response['error']['traceback'] = traceback.format_exc()
        
        return jsonify(response), 500
    
    @app.errorhandler(Exception)
    def handle_unexpected_exception(error: Exception) -> Tuple[Dict[str, Any], int]:
        """Handle any unhandled exceptions"""
        logger.exception(
            "Unhandled exception",
            extra={
                'error_type': type(error).__name__,
                'path': request.path,
                'method': request.method,
            }
        )
        
        response, status_code = create_error_response(error, include_traceback)
        return jsonify(response), status_code
    
    logger.info("✅ Global error handlers registered")
