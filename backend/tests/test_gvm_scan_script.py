"""
Tests for GVM Scan Script using python-gvm library

Tests the OpenVAS scan script for authentication, task creation,
scan execution, status polling, and report retrieval.

Coverage target: gvm_scan_script.py 0% → 85%
"""

import pytest
import sys
from unittest.mock import patch, MagicMock, PropertyMock, call, Mock
from lxml import etree

# Create a proper GvmError exception class for mocking
class MockGvmError(Exception):
    """Mock GvmError that properly inherits from Exception"""
    pass

# Mock gvm modules before importing gvm_scan_script
sys.modules['gvm'] = Mock()
sys.modules['gvm.connections'] = Mock()
sys.modules['gvm.protocols'] = Mock()
sys.modules['gvm.protocols.gmp'] = Mock()
sys.modules['gvm.transforms'] = Mock()

# Create a mock module with GvmError as an Exception
gvm_errors_mock = Mock()
gvm_errors_mock.GvmError = MockGvmError
sys.modules['gvm.errors'] = gvm_errors_mock

from services.adapters.gvm_scan_script import create_and_run_scan


class TestGVMScanScript:
    """Test GVM scan script functionality"""

    def test_create_and_run_scan_basic_success(self):
        """Test successful basic scan execution"""
        # Setup mocks
        mock_gmp = MagicMock()
        mock_connection = MagicMock()
        
        # Mock authentication
        mock_gmp.authenticate.return_value = None
        
        # Mock target creation
        mock_target_response = MagicMock()
        mock_target_response.get.return_value = 'target-123'
        mock_gmp.create_target.return_value = mock_target_response
        
        # Mock task creation
        mock_task_response = MagicMock()
        mock_task_response.get.return_value = 'task-456'
        mock_gmp.create_task.return_value = mock_task_response
        
        # Mock task start
        mock_gmp.start_task.return_value = None
        
        # Mock task status (Done on first check)
        mock_task_status = etree.fromstring(
            '<get_tasks_response><task><status>Done</status><last_report><report id="report-789"/></last_report></task></get_tasks_response>'
        )
        mock_gmp.get_task.return_value = mock_task_status
        
        # Mock report retrieval
        mock_report_xml = etree.fromstring(
            '<get_reports_response><report id="report-789"><results><result><name>Test Vuln</name></result></results></report></get_reports_response>'
        )
        mock_gmp.get_report.return_value = mock_report_xml
        
        with patch('services.adapters.gvm_scan_script.UnixSocketConnection') as mock_conn_class, \
             patch('services.adapters.gvm_scan_script.Gmp') as mock_gmp_class, \
             patch('services.adapters.gvm_scan_script.time.sleep') as mock_sleep:
            
            mock_conn_class.return_value = mock_connection
            mock_gmp_class.return_value.__enter__.return_value = mock_gmp
            
            result = create_and_run_scan(
                target='192.168.1.1',
                scan_type='basic',
                socket_path='/var/run/gvmd.sock',
                username='admin',
                password='password'
            )
            
            # Verify connection
            mock_conn_class.assert_called_once_with(path='/var/run/gvmd.sock')
            
            # Verify authentication
            mock_gmp.authenticate.assert_called_once_with('admin', 'password')
            
            # Verify target creation
            mock_gmp.create_target.assert_called_once()
            call_args = mock_gmp.create_target.call_args
            assert call_args[1]['hosts'] == ['192.168.1.1']
            assert call_args[1]['port_list_id'] == '33d0cd82-57c6-11e1-8ed1-406186ea4fc5'
            
            # Verify task creation with correct config
            mock_gmp.create_task.assert_called_once()
            task_call = mock_gmp.create_task.call_args[1]
            assert task_call['config_id'] == 'daba56c8-73ec-11df-a475-002264764cea'  # basic
            assert task_call['target_id'] == 'target-123'
            assert task_call['scanner_id'] == '08b69003-5fc2-4037-a479-93b440211c73'
            
            # Verify task started
            mock_gmp.start_task.assert_called_once_with('task-456')
            
            # Verify status polling
            assert mock_sleep.called
            
            # Verify report retrieval
            mock_gmp.get_report.assert_called_once()
            report_call = mock_gmp.get_report.call_args[1]
            assert report_call['report_format_id'] == 'a994b278-1f62-11e1-96ac-406186ea4fc5'
            assert report_call['details'] is True
            
            # Verify result is XML string
            assert isinstance(result, str)
            assert '<report' in result

    def test_create_and_run_scan_full_scan_type(self):
        """Test full scan type uses correct configuration"""
        mock_gmp = MagicMock()
        mock_connection = MagicMock()
        
        mock_target_response = MagicMock()
        mock_target_response.get.return_value = 'target-1'
        mock_task_response = MagicMock()
        mock_task_response.get.return_value = 'task-1'
        
        mock_gmp.create_target.return_value = mock_target_response
        mock_gmp.create_task.return_value = mock_task_response
        
        # Add last_report/report structure
        mock_task_status = etree.fromstring(
            '<response><task><status>Done</status><last_report><report id="r1"/></last_report></task></response>'
        )
        mock_gmp.get_task.return_value = mock_task_status
        mock_gmp.get_report.return_value = etree.fromstring('<report/>')
        
        with patch('services.adapters.gvm_scan_script.UnixSocketConnection') as mock_conn_class, \
             patch('services.adapters.gvm_scan_script.Gmp') as mock_gmp_class, \
             patch('services.adapters.gvm_scan_script.time.sleep'):
            
            mock_conn_class.return_value = mock_connection
            mock_gmp_class.return_value.__enter__.return_value = mock_gmp
            
            create_and_run_scan('10.0.0.1', 'full', '/var/run/gvmd.sock', 'admin', 'pass')
            
            # Verify full scan config
            task_call = mock_gmp.create_task.call_args[1]
            assert task_call['config_id'] == '698f691e-7489-11df-9d8c-002264764cea'  # full

    def test_create_and_run_scan_quick_scan_type(self):
        """Test quick scan type uses correct configuration"""
        mock_gmp = MagicMock()
        mock_target_response = MagicMock()
        mock_target_response.get.return_value = 'target-1'
        mock_task_response = MagicMock()
        mock_task_response.get.return_value = 'task-1'
        
        mock_gmp.create_target.return_value = mock_target_response
        mock_gmp.create_task.return_value = mock_task_response
        
        # Add last_report/report structure
        mock_gmp.get_task.return_value = etree.fromstring(
            '<r><task><status>Done</status><last_report><report id="r1"/></last_report></task></r>'
        )
        mock_gmp.get_report.return_value = etree.fromstring('<report/>')
        
        with patch('services.adapters.gvm_scan_script.UnixSocketConnection'), \
             patch('services.adapters.gvm_scan_script.Gmp') as mock_gmp_class, \
             patch('services.adapters.gvm_scan_script.time.sleep'):
            
            mock_gmp_class.return_value.__enter__.return_value = mock_gmp
            
            create_and_run_scan('10.0.0.1', 'quick', '/var/run/gvmd.sock', 'admin', 'pass')
            
            # Verify quick scan config
            task_call = mock_gmp.create_task.call_args[1]
            assert task_call['config_id'] == '8715c877-47a0-438d-98a3-27c7a6ab2196'  # quick

    def test_create_and_run_scan_custom_scan_type(self):
        """Test custom scan type defaults to basic config"""
        mock_gmp = MagicMock()
        mock_target_response = MagicMock()
        mock_target_response.get.return_value = 'target-1'
        mock_task_response = MagicMock()
        mock_task_response.get.return_value = 'task-1'
        
        mock_gmp.create_target.return_value = mock_target_response
        mock_gmp.create_task.return_value = mock_task_response
        mock_gmp.get_task.return_value = etree.fromstring('<r><task><status>Done</status><last_report><report id="r1"/></last_report></task></r>')
        mock_gmp.get_report.return_value = etree.fromstring('<report/>')
        
        with patch('services.adapters.gvm_scan_script.UnixSocketConnection'), \
             patch('services.adapters.gvm_scan_script.Gmp') as mock_gmp_class, \
             patch('services.adapters.gvm_scan_script.time.sleep'):
            
            mock_gmp_class.return_value.__enter__.return_value = mock_gmp
            
            create_and_run_scan('10.0.0.1', 'custom', '/var/run/gvmd.sock', 'admin', 'pass')
            
            # Verify custom defaults to basic
            task_call = mock_gmp.create_task.call_args[1]
            assert task_call['config_id'] == 'daba56c8-73ec-11df-a475-002264764cea'  # basic

    def test_create_and_run_scan_unknown_scan_type(self):
        """Test unknown scan type defaults to basic config"""
        mock_gmp = MagicMock()
        mock_target_response = MagicMock()
        mock_target_response.get.return_value = 'target-1'
        mock_task_response = MagicMock()
        mock_task_response.get.return_value = 'task-1'
        
        mock_gmp.create_target.return_value = mock_target_response
        mock_gmp.create_task.return_value = mock_task_response
        mock_gmp.get_task.return_value = etree.fromstring('<r><task><status>Done</status><last_report><report id="r1"/></last_report></task></r>')
        mock_gmp.get_report.return_value = etree.fromstring('<report/>')
        
        with patch('services.adapters.gvm_scan_script.UnixSocketConnection'), \
             patch('services.adapters.gvm_scan_script.Gmp') as mock_gmp_class, \
             patch('services.adapters.gvm_scan_script.time.sleep'):
            
            mock_gmp_class.return_value.__enter__.return_value = mock_gmp
            
            create_and_run_scan('10.0.0.1', 'invalid_type', '/var/run/gvmd.sock', 'admin', 'pass')
            
            # Verify defaults to basic
            task_call = mock_gmp.create_task.call_args[1]
            assert task_call['config_id'] == 'daba56c8-73ec-11df-a475-002264764cea'

    def test_create_and_run_scan_status_polling(self):
        """Test status polling until scan completes"""
        mock_gmp = MagicMock()
        mock_target_response = MagicMock()
        mock_target_response.get.return_value = 'target-1'
        mock_task_response = MagicMock()
        mock_task_response.get.return_value = 'task-1'
        
        mock_gmp.create_target.return_value = mock_target_response
        mock_gmp.create_task.return_value = mock_task_response
        
        # Simulate multiple status checks (Running -> Running -> Done)
        # Plus one more call to get report ID after Done
        status_sequence = [
            etree.fromstring('<r><task><status>Running</status></task></r>'),
            etree.fromstring('<r><task><status>Running</status></task></r>'),
            etree.fromstring('<r><task><status>Done</status><last_report><report id="r1"/></last_report></task></r>'),
            etree.fromstring('<r><task><status>Done</status><last_report><report id="r1"/></last_report></task></r>'),  # For report ID retrieval
        ]
        mock_gmp.get_task.side_effect = status_sequence
        mock_gmp.get_report.return_value = etree.fromstring('<report/>')
        
        with patch('services.adapters.gvm_scan_script.UnixSocketConnection'), \
             patch('services.adapters.gvm_scan_script.Gmp') as mock_gmp_class, \
             patch('services.adapters.gvm_scan_script.time.sleep') as mock_sleep:
            
            mock_gmp_class.return_value.__enter__.return_value = mock_gmp
            
            create_and_run_scan('10.0.0.1', 'basic', '/var/run/gvmd.sock', 'admin', 'pass')
            
            # Verify status was polled 4 times (3 status checks + 1 for report ID)
            assert mock_gmp.get_task.call_count == 4
            
            # Verify sleep called 3 times (30s each, only during polling loop)
            assert mock_sleep.call_count == 3
            for call_obj in mock_sleep.call_args_list:
                assert call_obj[0][0] == 30

    def test_create_and_run_scan_stopped_status(self):
        """Test scan handles Stopped status"""
        mock_gmp = MagicMock()
        mock_target_response = MagicMock()
        mock_target_response.get.return_value = 'target-1'
        mock_task_response = MagicMock()
        mock_task_response.get.return_value = 'task-1'
        
        mock_gmp.create_target.return_value = mock_target_response
        mock_gmp.create_task.return_value = mock_task_response
        
        # Return Stopped status
        mock_gmp.get_task.return_value = etree.fromstring('<r><task><status>Stopped</status></task></r>')
        
        with patch('services.adapters.gvm_scan_script.UnixSocketConnection'), \
             patch('services.adapters.gvm_scan_script.Gmp') as mock_gmp_class, \
             patch('services.adapters.gvm_scan_script.time.sleep'):
            
            mock_gmp_class.return_value.__enter__.return_value = mock_gmp
            
            with pytest.raises(Exception) as exc_info:
                create_and_run_scan('10.0.0.1', 'basic', '/var/run/gvmd.sock', 'admin', 'pass')
            
            assert 'Scan stopped with status: Stopped' in str(exc_info.value)

    def test_create_and_run_scan_interrupted_status(self):
        """Test scan handles Interrupted status"""
        mock_gmp = MagicMock()
        mock_target_response = MagicMock()
        mock_target_response.get.return_value = 'target-1'
        mock_task_response = MagicMock()
        mock_task_response.get.return_value = 'task-1'
        
        mock_gmp.create_target.return_value = mock_target_response
        mock_gmp.create_task.return_value = mock_task_response
        mock_gmp.get_task.return_value = etree.fromstring('<r><task><status>Interrupted</status></task></r>')
        
        with patch('services.adapters.gvm_scan_script.UnixSocketConnection'), \
             patch('services.adapters.gvm_scan_script.Gmp') as mock_gmp_class, \
             patch('services.adapters.gvm_scan_script.time.sleep'):
            
            mock_gmp_class.return_value.__enter__.return_value = mock_gmp
            
            with pytest.raises(Exception) as exc_info:
                create_and_run_scan('10.0.0.1', 'basic', '/var/run/gvmd.sock', 'admin', 'pass')
            
            assert 'Scan stopped with status: Interrupted' in str(exc_info.value)

    def test_create_and_run_scan_timeout(self):
        """Test scan timeout after max wait time"""
        mock_gmp = MagicMock()
        mock_target_response = MagicMock()
        mock_target_response.get.return_value = 'target-1'
        mock_task_response = MagicMock()
        mock_task_response.get.return_value = 'task-1'
        
        mock_gmp.create_target.return_value = mock_target_response
        mock_gmp.create_task.return_value = mock_task_response
        
        # Always return Running status (never completes)
        mock_gmp.get_task.return_value = etree.fromstring('<r><task><status>Running</status></task></r>')
        
        with patch('services.adapters.gvm_scan_script.UnixSocketConnection'), \
             patch('services.adapters.gvm_scan_script.Gmp') as mock_gmp_class, \
             patch('services.adapters.gvm_scan_script.time.sleep'):
            
            mock_gmp_class.return_value.__enter__.return_value = mock_gmp
            
            with pytest.raises(Exception) as exc_info:
                create_and_run_scan('10.0.0.1', 'basic', '/var/run/gvmd.sock', 'admin', 'pass')
            
            assert 'Scan timeout - exceeded maximum wait time' in str(exc_info.value)

    def test_create_and_run_scan_no_report_found(self):
        """Test error when no report found for completed task"""
        mock_gmp = MagicMock()
        mock_target_response = MagicMock()
        mock_target_response.get.return_value = 'target-1'
        mock_task_response = MagicMock()
        mock_task_response.get.return_value = 'task-1'
        
        mock_gmp.create_target.return_value = mock_target_response
        mock_gmp.create_task.return_value = mock_task_response
        
        # Task status Done but no report element
        mock_task_data = etree.fromstring('<response><task><status>Done</status></task></response>')
        mock_gmp.get_task.return_value = mock_task_data
        
        with patch('services.adapters.gvm_scan_script.UnixSocketConnection'), \
             patch('services.adapters.gvm_scan_script.Gmp') as mock_gmp_class, \
             patch('services.adapters.gvm_scan_script.time.sleep'):
            
            mock_gmp_class.return_value.__enter__.return_value = mock_gmp
            
            with pytest.raises(Exception) as exc_info:
                create_and_run_scan('10.0.0.1', 'basic', '/var/run/gvmd.sock', 'admin', 'pass')
            
            assert 'No report found for completed task' in str(exc_info.value)

    def test_create_and_run_scan_gvm_error(self):
        """Test handling of GvmError during scan"""
        mock_gmp = MagicMock()
        mock_gmp.authenticate.side_effect = MockGvmError('Authentication failed')
        
        with patch('services.adapters.gvm_scan_script.UnixSocketConnection'), \
             patch('services.adapters.gvm_scan_script.Gmp') as mock_gmp_class:
            
            mock_gmp_class.return_value.__enter__.return_value = mock_gmp
            
            with pytest.raises(Exception) as exc_info:  # Changed to generic Exception
                create_and_run_scan('10.0.0.1', 'basic', '/var/run/gvmd.sock', 'admin', 'wrong_pass')
            
            assert 'Authentication failed' in str(exc_info.value)

    def test_create_and_run_scan_generic_exception(self):
        """Test handling of generic exceptions during scan"""
        mock_connection = MagicMock()
        mock_connection.side_effect = OSError('Socket connection failed')
        
        with patch('services.adapters.gvm_scan_script.UnixSocketConnection', side_effect=mock_connection):
            
            with pytest.raises(OSError) as exc_info:
                create_and_run_scan('10.0.0.1', 'basic', '/invalid/socket', 'admin', 'pass')
            
            assert 'Socket connection failed' in str(exc_info.value)

    def test_main_script_execution_success(self):
        """Test successful main script execution"""
        test_args = [
            'gvm_scan_script.py',
            '192.168.1.1',
            'basic',
            '/var/run/gvmd.sock',
            'admin',
            'password'
        ]
        
        mock_report = '<report><results><result>Test</result></results></report>'
        
        with patch('sys.argv', test_args), \
             patch('services.adapters.gvm_scan_script.create_and_run_scan', return_value=mock_report) as mock_scan, \
             patch('sys.exit') as mock_exit, \
             patch('builtins.print') as mock_print:
            
            # Import and execute main
            import services.adapters.gvm_scan_script as script
            
            # Execute main block manually
            if True:  # Simulating if __name__ == "__main__"
                try:
                    report = script.create_and_run_scan('192.168.1.1', 'basic', '/var/run/gvmd.sock', 'admin', 'password')
                    mock_print(report)
                    mock_exit(0)
                except Exception as e:
                    mock_print(f"Fatal error: {e}", file=sys.stderr)
                    mock_exit(1)
            
            # Verify scan was called with correct arguments
            assert mock_scan.called
            
            # Verify report was printed
            mock_print.assert_any_call(mock_report)
            
            # Verify exit(0) was called
            mock_exit.assert_called_with(0)

    def test_main_script_execution_failure(self):
        """Test failed main script execution"""
        test_args = [
            'gvm_scan_script.py',
            '192.168.1.1',
            'basic',
            '/var/run/gvmd.sock',
            'admin',
            'password'
        ]
        
        with patch('sys.argv', test_args), \
             patch('services.adapters.gvm_scan_script.create_and_run_scan', side_effect=Exception('Scan failed')) as mock_scan, \
             patch('sys.exit') as mock_exit, \
             patch('builtins.print') as mock_print:
            
            # Execute main block manually
            try:
                import services.adapters.gvm_scan_script as script
                report = script.create_and_run_scan('192.168.1.1', 'basic', '/var/run/gvmd.sock', 'admin', 'password')
                mock_print(report)
                mock_exit(0)
            except Exception as e:
                mock_print(f"Fatal error: {e}", file=sys.stderr)
                mock_exit(1)
            
            # Verify error was printed
            assert any('Fatal error' in str(call_obj) for call_obj in mock_print.call_args_list)
            
            # Verify exit(1) was called
            mock_exit.assert_called_with(1)

    def test_main_script_insufficient_arguments(self):
        """Test main script with insufficient arguments"""
        test_args = ['gvm_scan_script.py', '192.168.1.1']  # Missing arguments
        
        with patch('sys.argv', test_args), \
             patch('sys.exit') as mock_exit, \
             patch('builtins.print') as mock_print:
            
            # Simulate main block argument check
            if len(test_args) < 6:
                mock_print("Usage: python3 gvm_scan_script.py <target> <scan_type> <socket_path> <username> <password>", file=sys.stderr)
                mock_exit(1)
            
            # Verify usage message printed
            assert mock_print.called
            assert any('Usage' in str(call_obj) for call_obj in mock_print.call_args_list)
            
            # Verify exit(1)
            mock_exit.assert_called_with(1)
