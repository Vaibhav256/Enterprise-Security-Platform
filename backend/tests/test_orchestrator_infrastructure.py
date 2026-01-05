"""
Tests for Scan Orchestrator

Tests orchestrator initialization and queue management.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock


class TestOrchestratorInit:
    """Test orchestrator initialization"""
    
    @patch('services.scan_orchestrator.orchestrator.Redis')
    @patch('services.scan_orchestrator.orchestrator.Queue')
    def test_init_with_defaults(self, mock_queue_class, mock_redis_class):
        """Test initialization with default parameters"""
        from services.scan_orchestrator.orchestrator import ScanOrchestrator
        
        mock_redis = Mock()
        mock_redis_class.return_value = mock_redis
        
        orch = ScanOrchestrator()
        
        # Verify Redis connection created
        mock_redis_class.assert_called_once_with(
            host='localhost',
            port=6379,
            db=0,
            password=None,
            decode_responses=False
        )
        
        # Verify redis_conn attribute set
        assert orch.redis_conn == mock_redis
        
    @patch('services.scan_orchestrator.orchestrator.Redis')
    @patch('services.scan_orchestrator.orchestrator.Queue')
    def test_init_with_custom_params(self, mock_queue_class, mock_redis_class):
        """Test initialization with custom parameters"""
        from services.scan_orchestrator.orchestrator import ScanOrchestrator
        
        mock_redis = Mock()
        mock_redis_class.return_value = mock_redis
        
        orch = ScanOrchestrator(
            redis_host='redis.example.com',
            redis_port=6380,
            redis_db=2,
            redis_password='secret123'
        )
        
        # Verify Redis called with custom params
        mock_redis_class.assert_called_once_with(
            host='redis.example.com',
            port=6380,
            db=2,
            password='secret123',
            decode_responses=False
        )
        
    @patch('services.scan_orchestrator.orchestrator.Redis')
    @patch('services.scan_orchestrator.orchestrator.Queue')
    def test_creates_priority_queues(self, mock_queue_class, mock_redis_class):
        """Test that orchestrator creates priority queues"""
        from services.scan_orchestrator.orchestrator import ScanOrchestrator
        
        mock_redis = Mock()
        mock_redis_class.return_value = mock_redis
        
        mock_high_queue = Mock()
        mock_normal_queue = Mock()
        mock_low_queue = Mock()
        mock_queue_class.side_effect = [mock_high_queue, mock_normal_queue, mock_low_queue]
        
        orch = ScanOrchestrator()
        
        # Verify 3 queues created
        assert mock_queue_class.call_count == 3
        
        # Verify queue names
        calls = mock_queue_class.call_args_list
        assert calls[0][0][0] == 'high'
        assert calls[1][0][0] == 'normal'
        assert calls[2][0][0] == 'low'
        
        # Verify queues assigned to attributes
        assert orch.high_priority_queue == mock_high_queue
        assert orch.normal_queue == mock_normal_queue
        assert orch.low_priority_queue == mock_low_queue
