"""
Tests for services/scan_orchestrator/tasks.py

This module tests the RQ task execution functions for scanning operations.

Author: NTRO Security Team
Date: 2025-10-28
"""

import logging
from datetime import datetime
from typing import Any, Dict
from unittest.mock import MagicMock, Mock, patch

import pytest

from services.data_ingestor.models import ScanStatus
from services.scan_orchestrator.tasks import (
    execute_scan,
    get_adapter,
    test_wsl_connection,
)


class TestGetAdapter:
    """Test adapter selection logic"""

    def test_get_adapter_nmap(self):
        """Test getting Nmap adapter"""
        mock_wsl = Mock()
        
        with patch('services.scan_orchestrator.tasks.NmapAdapter') as mock_adapter:
            result = get_adapter('nmap', mock_wsl)
            
            mock_adapter.assert_called_once_with(mock_wsl)
            assert result == mock_adapter.return_value

    def test_get_adapter_openvas(self):
        """Test getting OpenVAS adapter"""
        mock_wsl = Mock()
        
        with patch('services.scan_orchestrator.tasks.OpenVASAdapter') as mock_adapter:
            result = get_adapter('openvas', mock_wsl)
            
            mock_adapter.assert_called_once_with(mock_wsl)
            assert result == mock_adapter.return_value

    def test_get_adapter_nikto(self):
        """Test getting Nikto adapter"""
        mock_wsl = Mock()
        
        with patch('services.scan_orchestrator.tasks.NiktoAdapter') as mock_adapter:
            result = get_adapter('nikto', mock_wsl)
            
            mock_adapter.assert_called_once_with(mock_wsl)
            assert result == mock_adapter.return_value

    def test_get_adapter_nuclei(self):
        """Test getting Nuclei adapter"""
        mock_wsl = Mock()
        
        with patch('services.scan_orchestrator.tasks.NucleiAdapter') as mock_adapter:
            result = get_adapter('nuclei', mock_wsl)
            
            mock_adapter.assert_called_once_with(mock_wsl)
            assert result == mock_adapter.return_value

    def test_get_adapter_case_insensitive(self):
        """Test that adapter selection is case-insensitive"""
        mock_wsl = Mock()
        
        with patch('services.scan_orchestrator.tasks.NmapAdapter') as mock_adapter:
            result = get_adapter('NMAP', mock_wsl)
            mock_adapter.assert_called_once_with(mock_wsl)
            
            result = get_adapter('NmAp', mock_wsl)
            assert mock_adapter.call_count == 2

    def test_get_adapter_unsupported_tool(self):
        """Test error for unsupported tool"""
        mock_wsl = Mock()
        
        with pytest.raises(ValueError, match="Unsupported tool: invalid"):
            get_adapter('invalid', mock_wsl)


class TestExecuteScanSuccess:
    """Test successful scan execution"""

    @pytest.fixture
    def mock_dependencies(self):
        """Setup common mocks for execute_scan tests"""
        with patch('rq.get_current_job') as mock_job_func, \
             patch('config.config.get_config') as mock_config, \
             patch('services.scan_orchestrator.tasks.DataIngestor') as mock_ingestor_class, \
             patch('services.scan_orchestrator.tasks.WSLHelper') as mock_wsl_class, \
             patch('services.scan_orchestrator.tasks.get_adapter') as mock_get_adapter, \
             patch('services.scan_orchestrator.tasks.emit_scan_started') as mock_emit_started, \
             patch('services.scan_orchestrator.tasks.emit_scan_progress') as mock_emit_progress, \
             patch('services.scan_orchestrator.tasks.emit_scan_completed') as mock_emit_completed, \
             patch('services.scan_orchestrator.tasks.emit_scan_failed') as mock_emit_failed:
            
            # Configure mock job
            mock_job = Mock()
            mock_job.meta = {}
            mock_job.save_meta = Mock()
            mock_job_func.return_value = mock_job
            
            # Configure mock config
            mock_cfg = Mock()
            mock_cfg.DATABASE_URL = 'postgresql://test:test@localhost/test'
            mock_config.return_value = mock_cfg
            
            # Configure mock ingestor
            mock_ingestor = Mock()
            mock_ingestor_class.return_value = mock_ingestor
            
            # Configure mock WSL helper
            mock_wsl = Mock()
            mock_wsl_class.return_value = mock_wsl
            
            # Configure mock adapter with successful result
            mock_adapter = Mock()
            mock_result = Mock()
            mock_result.success = True
            mock_result.raw_output = '<xml>scan output</xml>'
            mock_result.parsed_output = {
                'hosts': [
                    {'state': 'up', 'ports': [{'state': 'open'}]}
                ],
                'summary': {},
                'vulnerability_count': 5,
                'severity_counts': {
                    'critical': 1,
                    'high': 2,
                    'medium': 1,
                    'low': 1,
                    'info': 0
                }
            }
            mock_result.execution_time = 45.5
            mock_result.error_message = None
            mock_adapter.execute_scan.return_value = mock_result
            mock_get_adapter.return_value = mock_adapter
            
            yield {
                'job_func': mock_job_func,
                'job': mock_job,
                'config': mock_config,
                'cfg': mock_cfg,
                'ingestor_class': mock_ingestor_class,
                'ingestor': mock_ingestor,
                'wsl_class': mock_wsl_class,
                'wsl': mock_wsl,
                'get_adapter': mock_get_adapter,
                'adapter': mock_adapter,
                'result': mock_result,
                'emit_started': mock_emit_started,
                'emit_progress': mock_emit_progress,
                'emit_completed': mock_emit_completed,
                'emit_failed': mock_emit_failed,
            }

    def test_execute_scan_success_nmap(self, mock_dependencies):
        """Test successful nmap scan execution"""
        result = execute_scan(
            scan_id='scan-123',
            target='192.168.1.1',
            tool='nmap',
            scan_type='basic'
        )
        
        # Verify result
        assert result['scan_id'] == 'scan-123'
        assert result['status'] == 'completed'
        
        # Verify ingestor calls
        ingestor = mock_dependencies['ingestor']
        assert ingestor.update_scan_status.call_count == 2  # RUNNING and COMPLETED
        ingestor.update_scan_status.assert_any_call(
            scan_id='scan-123',
            status=ScanStatus.RUNNING
        )
        ingestor.update_scan_status.assert_called_with(
            scan_id='scan-123',
            status=ScanStatus.COMPLETED,
            error_message=None
        )
        
        # Verify raw results stored
        ingestor.store_raw_result.assert_called_once_with(
            scan_id='scan-123',
            tool_name='nmap',
            raw_output='<xml>scan output</xml>',
            output_format='xml',
            parsed_output=mock_dependencies['result'].parsed_output
        )
        
        # Verify scan summary stored
        ingestor.create_scan_summary.assert_called_once()
        
        # Verify WebSocket events
        mock_dependencies['emit_started'].assert_called_once_with(
            'scan-123', '192.168.1.1', tool_name='nmap'
        )
        assert mock_dependencies['emit_progress'].call_count >= 5
        mock_dependencies['emit_completed'].assert_called_once_with(
            scan_id='scan-123',
            results_count=5,
            execution_time=45.5
        )

    def test_execute_scan_success_nuclei(self, mock_dependencies):
        """Test successful nuclei scan (JSON output format)"""
        result = execute_scan(
            scan_id='scan-456',
            target='https://example.com',
            tool='nuclei',
            scan_type='full',
            options={'template': 'cves'}
        )
        
        # Verify result
        assert result['scan_id'] == 'scan-456'
        assert result['status'] == 'completed'
        
        # Verify adapter called with correct parameters
        adapter = mock_dependencies['adapter']
        adapter.execute_scan.assert_called_once_with(
            target='https://example.com',
            scan_type='full',
            options={'template': 'cves'}
        )
        
        # Verify JSON format for nuclei
        ingestor = mock_dependencies['ingestor']
        ingestor.store_raw_result.assert_called_once()
        call_args = ingestor.store_raw_result.call_args
        assert call_args.kwargs['output_format'] == 'json'

    def test_execute_scan_job_meta_updates(self, mock_dependencies):
        """Test that job metadata is updated correctly"""
        execute_scan(
            scan_id='scan-789',
            target='10.0.0.1',
            tool='openvas'
        )
        
        job = mock_dependencies['job']
        
        # Verify meta updates happened
        assert job.save_meta.call_count >= 4
        
        # Verify final status
        assert job.meta['status'] == 'completed'
        assert job.meta['progress'] == 100

    def test_execute_scan_websocket_progress_tracking(self, mock_dependencies):
        """Test WebSocket progress updates"""
        execute_scan(
            scan_id='scan-ws',
            target='192.168.1.100',
            tool='nmap'
        )
        
        emit_progress = mock_dependencies['emit_progress']
        
        # Verify progress checkpoints
        progress_calls = [call.args for call in emit_progress.call_args_list]
        progress_values = [call[1] for call in progress_calls]
        
        assert 0 in progress_values  # Initialization
        assert 10 in progress_values  # Preparing
        assert 20 in progress_values  # Starting scan
        assert 30 in progress_values  # Executing
        assert 70 in progress_values  # Completed
        assert 80 in progress_values  # Storing results
        assert 100 in progress_values  # Finished


class TestExecuteScanFailure:
    """Test scan execution failure scenarios"""

    def test_execute_scan_adapter_failure(self):
        """Test scan when adapter execution fails"""
        with patch('rq.get_current_job') as mock_job_func, \
             patch('config.config.get_config') as mock_config, \
             patch('services.scan_orchestrator.tasks.DataIngestor') as mock_ingestor_class, \
             patch('services.scan_orchestrator.tasks.WSLHelper'), \
             patch('services.scan_orchestrator.tasks.get_adapter') as mock_get_adapter, \
             patch('services.scan_orchestrator.tasks.emit_scan_started'), \
             patch('services.scan_orchestrator.tasks.emit_scan_progress'), \
             patch('services.scan_orchestrator.tasks.emit_scan_failed') as mock_emit_failed:
            
            # Configure mocks
            mock_job = Mock()
            mock_job.meta = {}
            mock_job_func.return_value = mock_job
            
            mock_cfg = Mock()
            mock_cfg.DATABASE_URL = 'postgresql://test:test@localhost/test'
            mock_config.return_value = mock_cfg
            
            mock_ingestor = Mock()
            mock_ingestor_class.return_value = mock_ingestor
            
            # Configure adapter to return failure
            mock_adapter = Mock()
            mock_result = Mock()
            mock_result.success = False
            mock_result.raw_output = None
            mock_result.parsed_output = None
            mock_result.execution_time = 10.0
            mock_result.error_message = 'Connection timeout'
            mock_adapter.execute_scan.return_value = mock_result
            mock_get_adapter.return_value = mock_adapter
            
            result = execute_scan(
                scan_id='scan-fail',
                target='invalid-target',
                tool='nmap'
            )
            
            # Verify result
            assert result['scan_id'] == 'scan-fail'
            assert result['status'] == 'completed'  # Function completes even if scan fails
            
            # Verify status updated to FAILED
            mock_ingestor.update_scan_status.assert_called_with(
                scan_id='scan-fail',
                status=ScanStatus.FAILED,
                error_message='Connection timeout'
            )
            
            # Verify no results stored (raw_output is None)
            assert mock_ingestor.store_raw_result.call_count == 0

    def test_execute_scan_exception_handling(self):
        """Test scan when exception occurs"""
        with patch('rq.get_current_job') as mock_job_func, \
             patch('config.config.get_config') as mock_config, \
             patch('services.scan_orchestrator.tasks.DataIngestor') as mock_ingestor_class, \
             patch('services.scan_orchestrator.tasks.WSLHelper') as mock_wsl_class, \
             patch('services.scan_orchestrator.tasks.emit_scan_started'), \
             patch('services.scan_orchestrator.tasks.emit_scan_failed') as mock_emit_failed:
            
            # Configure mocks
            mock_job = Mock()
            mock_job.meta = {}
            mock_job_func.return_value = mock_job
            
            mock_cfg = Mock()
            mock_cfg.DATABASE_URL = 'postgresql://test:test@localhost/test'
            mock_config.return_value = mock_cfg
            
            mock_ingestor = Mock()
            mock_ingestor_class.return_value = mock_ingestor
            
            # Make WSLHelper raise exception
            mock_wsl_class.side_effect = RuntimeError('WSL not available')
            
            result = execute_scan(
                scan_id='scan-error',
                target='192.168.1.1',
                tool='nmap'
            )
            
            # Verify error result returned
            assert result['scan_id'] == 'scan-error'
            assert result['success'] is False
            assert 'WSL not available' in result['error_message']
            assert 'completed_at' in result
            
            # Verify WebSocket error event
            mock_emit_failed.assert_called_once()
            
            # Verify job meta updated with error
            assert mock_job.meta['status'] == 'failed'
            assert 'WSL not available' in mock_job.meta['error']

    def test_execute_scan_db_update_failure(self):
        """Test when database status update fails during exception"""
        with patch('rq.get_current_job') as mock_job_func, \
             patch('config.config.get_config') as mock_config, \
             patch('services.scan_orchestrator.tasks.DataIngestor') as mock_ingestor_class, \
             patch('services.scan_orchestrator.tasks.WSLHelper') as mock_wsl_class, \
             patch('services.scan_orchestrator.tasks.emit_scan_started'), \
             patch('services.scan_orchestrator.tasks.emit_scan_failed'):
            
            # Configure mocks
            mock_job = Mock()
            mock_job.meta = {}
            mock_job_func.return_value = mock_job
            
            mock_cfg = Mock()
            mock_cfg.DATABASE_URL = 'postgresql://test:test@localhost/test'
            mock_config.return_value = mock_cfg
            
            # First ingestor call raises error, second also raises error
            mock_ingestor = Mock()
            mock_ingestor.update_scan_status.side_effect = Exception('DB connection lost')
            mock_ingestor_class.return_value = mock_ingestor
            
            # WSL helper succeeds (we want DB error to be the failure)
            mock_wsl = Mock()
            mock_wsl_class.return_value = mock_wsl
            
            # Should not raise exception even if DB update fails
            result = execute_scan(
                scan_id='scan-db-error',
                target='192.168.1.1',
                tool='nmap'
            )
            
            # Verify error result still returned
            assert result['success'] is False
            assert 'DB connection lost' in result['error_message']

    def test_execute_scan_no_parsed_output(self):
        """Test scan with raw output but no parsed output"""
        with patch('rq.get_current_job') as mock_job_func, \
             patch('config.config.get_config') as mock_config, \
             patch('services.scan_orchestrator.tasks.DataIngestor') as mock_ingestor_class, \
             patch('services.scan_orchestrator.tasks.WSLHelper'), \
             patch('services.scan_orchestrator.tasks.get_adapter') as mock_get_adapter, \
             patch('services.scan_orchestrator.tasks.emit_scan_started'), \
             patch('services.scan_orchestrator.tasks.emit_scan_progress'), \
             patch('services.scan_orchestrator.tasks.emit_scan_completed'):
            
            # Configure mocks
            mock_job = Mock()
            mock_job.meta = {}
            mock_job_func.return_value = mock_job
            
            mock_cfg = Mock()
            mock_cfg.DATABASE_URL = 'postgresql://test:test@localhost/test'
            mock_config.return_value = mock_cfg
            
            mock_ingestor = Mock()
            mock_ingestor_class.return_value = mock_ingestor
            
            # Configure adapter with raw output but no parsed output
            mock_adapter = Mock()
            mock_result = Mock()
            mock_result.success = True
            mock_result.raw_output = '<xml>raw data</xml>'
            mock_result.parsed_output = None  # No parsed output
            mock_result.execution_time = 30.0
            mock_result.error_message = None
            mock_adapter.execute_scan.return_value = mock_result
            mock_get_adapter.return_value = mock_adapter
            
            result = execute_scan(
                scan_id='scan-no-parse',
                target='192.168.1.1',
                tool='nmap'
            )
            
            # Verify result
            assert result['status'] == 'completed'
            
            # Verify raw result stored
            mock_ingestor.store_raw_result.assert_called_once()
            
            # Verify scan summary NOT created (no parsed output)
            assert mock_ingestor.create_scan_summary.call_count == 0


class TestTestWSLConnection:
    """Test WSL connection testing function"""

    def test_wsl_connection_success(self):
        """Test successful WSL connection check"""
        with patch('services.scan_orchestrator.tasks.WSLHelper') as mock_wsl_class, \
             patch('utils.wsl_helper.WSLToolValidator') as mock_validator_class:
            
            # Configure mock WSL helper
            mock_wsl = Mock()
            mock_wsl.get_distribution_info.return_value = {
                'hostname': 'ubuntu',
                'version': '22.04'
            }
            mock_wsl_class.return_value = mock_wsl
            
            # Configure mock validator
            mock_validator = Mock()
            mock_validator.validate_required_tools.return_value = {
                'nmap': True,
                'gvm-cli': True,
                'python3': True
            }
            mock_validator_class.return_value = mock_validator
            
            result = test_wsl_connection()
            
            # Verify result
            assert result['success'] is True
            assert result['distribution_info']['hostname'] == 'ubuntu'
            assert result['tool_availability']['nmap'] is True
            assert 'timestamp' in result

    def test_wsl_connection_failure(self):
        """Test WSL connection failure"""
        with patch('services.scan_orchestrator.tasks.WSLHelper') as mock_wsl_class:
            
            # Make WSL helper raise exception
            mock_wsl_class.side_effect = RuntimeError('WSL not installed')
            
            result = test_wsl_connection()
            
            # Verify error result
            assert result['success'] is False
            assert 'WSL not installed' in result['error']
            assert 'timestamp' in result

    def test_wsl_connection_partial_tools(self):
        """Test WSL connection with some tools missing"""
        with patch('services.scan_orchestrator.tasks.WSLHelper') as mock_wsl_class, \
             patch('utils.wsl_helper.WSLToolValidator') as mock_validator_class:
            
            # Configure mocks
            mock_wsl = Mock()
            mock_wsl.get_distribution_info.return_value = {'hostname': 'debian'}
            mock_wsl_class.return_value = mock_wsl
            
            # Some tools available, some not
            mock_validator = Mock()
            mock_validator.validate_required_tools.return_value = {
                'nmap': True,
                'gvm-cli': False,  # Missing
                'python3': True
            }
            mock_validator_class.return_value = mock_validator
            
            result = test_wsl_connection()
            
            # Verify result still successful but shows missing tools
            assert result['success'] is True
            assert result['tool_availability']['nmap'] is True
            assert result['tool_availability']['gvm-cli'] is False


class TestWebSocketFallback:
    """Test WebSocket emission fallback when unavailable"""

    def test_websocket_not_available_no_crash(self):
        """Test that scan works even if WebSocket is unavailable"""
        # This test verifies the no-op functions work correctly
        # Import should have already handled WebSocket availability
        
        from services.scan_orchestrator.tasks import (
            emit_scan_completed,
            emit_scan_failed,
            emit_scan_progress,
            emit_scan_queued,
            emit_scan_started,
        )
        
        # These should not raise any errors (no-op functions)
        emit_scan_queued('scan-1', '192.168.1.1', tool_name='nmap')
        emit_scan_started('scan-1', '192.168.1.1', tool_name='nmap')
        emit_scan_progress('scan-1', 50, 'Running...')
        emit_scan_completed('scan-1', results_count=10, execution_time=30.0)
        emit_scan_failed('scan-1', 'Error message')
        
        # If we get here without exceptions, test passes
        assert True
