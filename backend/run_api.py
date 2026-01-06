#!/usr/bin/env python
"""
API Gateway Entry Point

Runs the Flask application with Socket.IO support for real-time updates.
"""

import os
import sys
import logging
from pathlib import Path

# Add backend directory to Python path
backend_dir = Path(__file__).parent
sys.path.insert(0, str(backend_dir))

from api_gateway.app import create_app
from api_gateway.websocket import init_socketio

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s [%(name)s]: %(message)s'
)
logger = logging.getLogger(__name__)


def validate_port(port_value: str, env: str) -> int:
    """
    Validate and return port number with proper error handling
    
    Args:
        port_value: Port value from environment
        env: Environment name (development/production)
        
    Returns:
        int: Validated port number
        
    Raises:
        ValueError: If port is invalid
    """
    try:
        port = int(port_value)
    except (ValueError, TypeError):
        logger.error(f"Invalid API_PORT value: {port_value}. Must be an integer.")
        raise ValueError(f"API_PORT must be an integer, got: {port_value}")
    
    # Validate port range (allow privileged ports for containerized deployments)
    if not (1 <= port <= 65535):
        logger.error(f"Port {port} out of valid range (1-65535)")
        raise ValueError(f"Port must be between 1-65535, got: {port}")
    
    # Warn about privileged ports outside containers
    if port < 1024 and env == 'development':
        logger.warning(f"Using privileged port {port}. May require elevated permissions.")
    
    return port


def get_port_config(env: str) -> int:
    """
    Get validated port configuration with environment-specific defaults
    
    Args:
        env: Environment name (development/production)
        
    Returns:
        int: Port number to use
    """
    default_port = 5000 if env == 'development' else 8000
    
    # Check if API_PORT is explicitly set
    port_env = os.getenv('API_PORT')
    
    if port_env:
        port = validate_port(port_env, env)
        logger.info(f"Using configured port {port} for {env} environment")
    else:
        port = default_port
        logger.info(f"Using default port {port} for {env} environment (set API_PORT to override)")
    
    return port


def main():
    """Start the API Gateway with Socket.IO"""
    
    # Get configuration
    env = os.getenv('FLASK_ENV', 'development')
    host = os.getenv('API_HOST', '127.0.0.1')  # default to localhost for safety
    
    # Get validated port
    try:
        port = get_port_config(env)
    except ValueError as e:
        logger.error(f"Port configuration error: {e}")
        sys.exit(1)
    
    debug = env == 'development'
    
    # Validate environment-specific settings
    if env == 'production' and debug:
        logger.error("Debug mode cannot be enabled in production!")
        sys.exit(1)
    
    # Create Flask app
    logger.info(f"Starting API Gateway on {host}:{port} (env={env})")
    app = create_app(config_name=env)
    
    # Initialize Socket.IO with the app
    socketio = init_socketio(app)
    
    # Security: Only allow unsafe werkzeug in development
    allow_unsafe = env == 'development'
    
    if not allow_unsafe:
        logger.info("Running in production mode with security restrictions")
    else:
        logger.warning("Running in development mode with relaxed security (unsafe werkzeug enabled)")
    
    # Run with Socket.IO
    try:
        socketio.run(
            app,
            host=host,
            port=port,
            debug=debug,
            use_reloader=debug,
            allow_unsafe_werkzeug=allow_unsafe
        )
    except KeyboardInterrupt:
        logger.info("Shutting down gracefully...")
    except Exception as e:
        logger.error(f"Failed to start application: {e}", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    main()
