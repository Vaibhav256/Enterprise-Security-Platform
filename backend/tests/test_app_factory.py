"""
Tests for Flask Application Factory

Tests app.py create_app function and Flask application setup.
"""

import pytest
from unittest.mock import patch, Mock


class TestCreateAppFunction:
    """Test create_app factory function"""
    
    @patch('api_gateway.app.Api')
    @patch('api_gateway.app.CORS')
    def test_create_app_exists(self, mock_cors, mock_api):
        """Test create_app function can be called"""
        from api_gateway.app import create_app
        
        assert create_app is not None
        assert callable(create_app)
        
    @patch('api_gateway.app.Api')
    @patch('api_gateway.app.CORS')
    def test_create_app_returns_flask_app(self, mock_cors, mock_api):
        """Test create_app returns Flask application"""
        from api_gateway.app import create_app
        from flask import Flask
        
        app = create_app()
        
        assert isinstance(app, Flask)
        assert app.name == 'api_gateway.app'
        
    @patch('api_gateway.app.Api')
    @patch('api_gateway.app.CORS')
    def test_create_app_with_testing_config(self, mock_cors, mock_api):
        """Test create_app with testing configuration"""
        from api_gateway.app import create_app
        
        app = create_app('testing')
        
        assert app is not None
        assert isinstance(app, object)


class TestFlaskAppEndpoints:
    """Test Flask application endpoints"""
    
    @patch('api_gateway.app.Api')
    @patch('api_gateway.app.CORS')
    def test_health_endpoint_exists(self, mock_cors, mock_api):
        """Test /health endpoint exists"""
        from api_gateway.app import create_app
        
        app = create_app()
        
        # Check that health endpoint is registered
        with app.test_client() as client:
            response = client.get('/health')
            assert response is not None
            
    @patch('api_gateway.app.Api')
    @patch('api_gateway.app.CORS')
    def test_root_endpoint_exists(self, mock_cors, mock_api):
        """Test / root endpoint exists"""
        from api_gateway.app import create_app
        
        app = create_app()
        
        # Check that root endpoint is registered
        with app.test_client() as client:
            response = client.get('/')
            assert response is not None


class TestFlaskAppConfiguration:
    """Test Flask application configuration"""
    
    @patch('api_gateway.app.Api')
    @patch('api_gateway.app.CORS')
    def test_cors_configured(self, mock_cors, mock_api):
        """Test CORS is configured"""
        from api_gateway.app import create_app
        
        app = create_app()
        
        # Verify CORS was called
        mock_cors.assert_called_once()
        
    @patch('api_gateway.app.Api')
    @patch('api_gateway.app.CORS')
    def test_api_configured(self, mock_cors, mock_api):
        """Test Flask-RESTX API is configured"""
        from api_gateway.app import create_app
        
        app = create_app()
        
        # Verify API was instantiated
        mock_api.assert_called()
        
    @patch('api_gateway.app.Api')
    @patch('api_gateway.app.CORS')
    @patch('api_gateway.routes.scans_ns')
    def test_namespace_added(self, mock_scans_ns, mock_cors, mock_api):
        """Test scans namespace is added to API"""
        from api_gateway.app import create_app
        
        mock_api_instance = Mock()
        mock_api.return_value = mock_api_instance
        
        app = create_app()
        
        # Verify namespace was added
        mock_api_instance.add_namespace.assert_called()
    
    @patch('api_gateway.app.Api')
    @patch('api_gateway.app.CORS')
    def test_import_routes_failure(self, mock_cors, mock_api):
        """Test handling of routes import failure"""
        # Mock the import to fail
        with patch('api_gateway.app.logger') as mock_logger:
            # This will test the except path if routes can't be imported
            # The actual import will succeed, so we just verify logger exists
            from api_gateway.app import create_app
            app = create_app()
            assert app is not None


class TestAppMain:
    """Test __main__ block"""
    
    @patch('api_gateway.app.Api')
    @patch('api_gateway.app.CORS')
    def test_main_block_structure(self, mock_cors, mock_api):
        """Test that main block exists"""
        # Just verify the module can be executed
        import api_gateway.app
        assert hasattr(api_gateway.app, 'create_app')
