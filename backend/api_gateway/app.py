"""
Flask Application Factory

Creates and configures the Flask application for the API Gateway.

Author: NTRO Security Team
Date: 2025-10-22
"""

import logging
import os

from flask import Flask, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_restx import Api

logger = logging.getLogger(__name__)

# Initialize rate limiter (will be configured in create_app)
# 🔓 DEVELOPMENT: Rate limiting disabled for testing
# TODO: Re-enable for production deployment
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],  # Disabled for development
    storage_uri="memory://",  # Use Redis in production
    strategy="fixed-window",
    enabled=False  # Disable rate limiting
)


def create_app(config_name: str = None):
    """
    Application factory for creating Flask app
    
    Args:
        config_name: Configuration name (development, production, testing)
        
    Returns:
        Configured Flask application
    """
    # Create Flask app
    app = Flask(__name__)
    
    # Load configuration
    if config_name is None:
        config_name = os.getenv('FLASK_ENV', 'development')
    
    # Configure app
    app.config['ENV'] = config_name
    app.config['DEBUG'] = config_name == 'development'
    app.config['TESTING'] = config_name == 'testing'
    
    # Configure rate limiter
    redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    if config_name == 'production':
        # Use Redis for distributed rate limiting in production
        limiter.storage_uri = redis_url
        logger.info(f"✅ Rate limiter configured with Redis: {redis_url}")
    else:
        # Use in-memory storage for development/testing
        limiter.storage_uri = "memory://"
        logger.info("✅ Rate limiter configured with in-memory storage")
    
    # Initialize rate limiter with app
    limiter.init_app(app)
    
    # Enable CORS
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    
    # Create API
    api = Api(
        app,
        version='1.0',
        title='Vulnerability Scanner API',
        description='REST API for centralized vulnerability scanning platform',
        doc='/api/docs',
        prefix='/api'
    )
    
    # Authentication removed - system now operates without JWT authentication
    
    # Register scan/tools/stats namespaces
    try:
        from .routes import scans_ns, tools_ns, stats_ns
        api.add_namespace(scans_ns, path='/scans')
        api.add_namespace(tools_ns, path='/tools')
        api.add_namespace(stats_ns, path='/stats')
        logger.info("✅ Registered scans, tools, and stats namespaces")
    except ImportError as e:
        logger.warning(f"⚠️ Could not import routes: {e}")
    except AttributeError as e:
        logger.warning(f"⚠️ Could not find namespace in routes: {e}")
    
    # Register Intelligence Layer namespace
    try:
        from .intelligence_routes import intelligence_ns
        api.add_namespace(intelligence_ns, path='/intelligence')
        logger.info("✅ Registered intelligence namespace (RAG chatbot & attack paths)")
    except ImportError as e:
        logger.warning(f"⚠️ Could not import intelligence routes: {e}")
    
    # Register Threat Feeds namespace
    try:
        from api_gateway.routes.feeds import feeds_ns
        api.add_namespace(feeds_ns, path='/feeds')
        logger.info("✅ Registered threat feeds namespace")
    except ImportError as e:
        logger.warning(f"⚠️ Could not import feeds routes: {e}")
    
    # Register Reports blueprint
    try:
        from api_gateway.routes.reports import reports_bp
        app.register_blueprint(reports_bp)
        logger.info("✅ Registered reports blueprint")
    except ImportError as e:
        logger.warning(f"⚠️ Could not import reports routes: {e}")
    
    # Initialize background scheduler for threat feed synchronization
    try:
        from services.threat_feeds.feed_scheduler import start_feed_scheduler
        start_feed_scheduler()
        logger.info("✅ Background feed scheduler started (every 6 hours)")
    except Exception as e:
        logger.warning(f"⚠️ Could not start feed scheduler: {e}")
    
    # Health check endpoint (exempt from rate limiting)
    @app.route('/health')
    @limiter.exempt
    def health():
        """Health check endpoint (no rate limit)"""
        return {'status': 'healthy', 'service': 'vulnerability-scanner-api'}, 200
    
    # Root endpoint
    @app.route('/')
    def index():
        """Root endpoint"""
        return {
            'message': 'Vulnerability Scanner API',
            'version': '1.0',
            'docs': '/api/docs'
        }, 200
    
    logger.info(f"✅ Flask app created (env={config_name})")
    
    return app


if __name__ == '__main__':
    # For development only
    app = create_app('development')
    app.run(host='0.0.0.0', port=5000, debug=True)
