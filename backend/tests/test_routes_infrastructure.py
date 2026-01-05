"""
Tests for API Routes Infrastructure

Tests route registration, namespace creation, and basic route functionality.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from flask import Flask
from flask_restx import Api


class TestRoutesModuleImport:
    """Test routes module can be imported with mocked dependencies"""
    
    @patch('api_gateway.routes.get_config')
    @patch('api_gateway.routes.ScanOrchestrator')
    @patch('api_gateway.routes.DataIngestor')
    def test_routes_imports_successfully(self, mock_ingestor_class, mock_orch_class, mock_config):
        """Test that routes module can be imported"""
        # Mock config
        mock_cfg = Mock()
        mock_cfg.REDIS_HOST = 'localhost'
        mock_cfg.REDIS_PORT = 6379
        mock_cfg.DATABASE_URL = 'postgresql://test'
        mock_config.return_value = mock_cfg
        
        # Mock orchestrator instance
        mock_orch = Mock()
        mock_orch_class.return_value = mock_orch
        
        # Mock ingestor instance
        mock_ing = Mock()
        mock_ingestor_class.return_value = mock_ing
        
        # Import should work
        import api_gateway.routes as routes
        
        assert routes is not None
        assert hasattr(routes, 'scans_ns')


class TestNamespaceDefinitions:
    """Test API namespace definitions"""
    
    @patch('api_gateway.routes.get_config')
    @patch('api_gateway.routes.ScanOrchestrator')
    @patch('api_gateway.routes.DataIngestor')
    def test_scans_namespace_created(self, mock_ing, mock_orch, mock_config):
        """Test scans namespace exists"""
        mock_cfg = Mock()
        mock_cfg.REDIS_HOST = 'localhost'
        mock_cfg.REDIS_PORT = 6379
        mock_cfg.DATABASE_URL = 'postgresql://test'
        mock_config.return_value = mock_cfg
        
        import api_gateway.routes as routes
        
        assert routes.scans_ns is not None
        assert routes.scans_ns.name == 'scans'
        assert routes.scans_ns.description == 'Scan management operations'


class TestAPIModels:
    """Test API model definitions"""
    
    @patch('api_gateway.routes.get_config')
    @patch('api_gateway.routes.ScanOrchestrator')
    @patch('api_gateway.routes.DataIngestor')
    def test_scan_request_model_defined(self, mock_ing, mock_orch, mock_config):
        """Test scan request model is defined"""
        mock_cfg = Mock()
        mock_cfg.REDIS_HOST = 'localhost'
        mock_cfg.REDIS_PORT = 6379
        mock_cfg.DATABASE_URL = 'postgresql://test'
        mock_config.return_value = mock_cfg
        
        import api_gateway.routes as routes
        
        assert routes.scan_request_model is not None
        # Model should have required fields
        assert 'target' in routes.scan_request_model
        assert 'tool_name' in routes.scan_request_model
        assert 'scan_type' in routes.scan_request_model
