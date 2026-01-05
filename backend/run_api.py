#!/usr/bin/env python
"""
API Gateway Entry Point

Runs the Flask application with Socket.IO support for real-time updates.
"""

import os
import sys
from pathlib import Path

# Add backend directory to Python path
backend_dir = Path(__file__).parent
sys.path.insert(0, str(backend_dir))

from api_gateway.app import create_app
from api_gateway.websocket import init_socketio

def main():
    """Start the API Gateway with Socket.IO"""
    
    # Get configuration
    env = os.getenv('FLASK_ENV', 'development')
    host = os.getenv('API_HOST', '0.0.0.0')
    # Ensure backend uses the canonical development port 5000 unless explicitly
    # overridden for production. Some developer environments may have set
    # API_PORT to 8000 previously; force 5000 in development to match the
    # frontend Vite proxy and project defaults.
    if env == 'development':
        # Force development API port to 5000 to match frontend dev proxy and
        # project conventions. This overrides any local API_PORT setting when
        # running in development mode.
        os.environ['API_PORT'] = '5000'
    port = int(os.getenv('API_PORT', 5000))
    debug = env == 'development'
    
    # Create Flask app
    app = create_app(config_name=env)
    
    # Initialize Socket.IO with the app
    socketio = init_socketio(app)
    
    print(f"Starting API Gateway on {host}:{port} (env={env})")
    
    # Run with Socket.IO
    socketio.run(
        app,
        host=host,
        port=port,
        debug=debug,
        use_reloader=debug,
        allow_unsafe_werkzeug=True  # For development
    )

if __name__ == '__main__':
    main()
