"""
Tests for services/tasks/* Celery task modules

This module tests all Celery/RQ task functions for cleanup, monitoring,
processing, and notifications.

Author: NTRO Security Team
Date: 2025-10-28
"""

import logging
from datetime import datetime, timedelta
from unittest.mock import MagicMock, Mock, mock_open, patch

import pytest

# Import all tasks to test
from services.tasks.cleanup_tasks import cleanup_old_scans, cleanup_temp_files
from services.tasks.monitoring_tasks import (
    check_scan_timeouts,
    monitor_worker_health,
)
from services.tasks.notification_tasks import send_alert, send_scan_notification
from services.tasks.processing_tasks import (
    extract_vulnerabilities,
    parse_scan_output,
)


class TestCleanupTasks:
    """Test cleanup task functions"""

    def test_cleanup_old_scans_success(self):
        """Test successful cleanup of old scans"""
        with patch('config.config.get_config') as mock_config, \
             patch('sqlalchemy.create_engine') as mock_engine, \
             patch('sqlalchemy.orm.sessionmaker') as mock_sessionmaker:
            
            # Configure mock config
            mock_cfg = Mock()
            mock_cfg.DATABASE_URL = 'postgresql://test:test@localhost/test'
            mock_config.return_value = mock_cfg
            
            # Configure mock session
            mock_session = Mock()
            mock_sessionmaker.return_value = Mock(return_value=mock_session)
            
            # Create mock old scans
            cutoff_date = datetime.now() - timedelta(days=30)
            old_scan1 = Mock()
            old_scan1.created_at = cutoff_date - timedelta(days=10)
            old_scan2 = Mock()
            old_scan2.created_at = cutoff_date - timedelta(days=5)
            
            mock_query = Mock()
            mock_query.filter.return_value.all.return_value = [old_scan1, old_scan2]
            mock_session.query.return_value = mock_query
            
            # Execute cleanup
            result = cleanup_old_scans(days_old=30)
            
            # Verify result
            assert result == 2
            
            # Verify database operations
            assert mock_session.delete.call_count == 2
            mock_session.commit.assert_called_once()
            mock_session.close.assert_called_once()

    def test_cleanup_old_scans_with_custom_days(self):
        """Test cleanup with custom days parameter"""
        with patch('config.config.get_config') as mock_config, \
             patch('sqlalchemy.create_engine'), \
             patch('sqlalchemy.orm.sessionmaker') as mock_sessionmaker:
            
            mock_cfg = Mock()
            mock_cfg.DATABASE_URL = 'postgresql://test:test@localhost/test'
            mock_config.return_value = mock_cfg
            
            mock_session = Mock()
            mock_sessionmaker.return_value = Mock(return_value=mock_session)
            
            # No old scans found
            mock_query = Mock()
            mock_query.filter.return_value.all.return_value = []
            mock_session.query.return_value = mock_query
            
            result = cleanup_old_scans(days_old=90)
            
            assert result == 0
            mock_session.commit.assert_called_once()

    def test_cleanup_old_scans_database_error(self):
        """Test cleanup handles database errors"""
        with patch('config.config.get_config') as mock_config, \
             patch('sqlalchemy.create_engine'), \
             patch('sqlalchemy.orm.sessionmaker') as mock_sessionmaker:
            
            mock_cfg = Mock()
            mock_cfg.DATABASE_URL = 'postgresql://test:test@localhost/test'
            mock_config.return_value = mock_cfg
            
            mock_session = Mock()
            mock_sessionmaker.return_value = Mock(return_value=mock_session)
            
            # Make query raise exception
            mock_session.query.side_effect = Exception('Database connection lost')
            
            with pytest.raises(Exception, match='Database connection lost'):
                cleanup_old_scans(days_old=30)
            
            # Verify rollback and close were called
            mock_session.rollback.assert_called_once()
            mock_session.close.assert_called_once()

    def test_cleanup_temp_files_success(self):
        """Test successful cleanup of temporary files"""
        with patch('glob.glob') as mock_glob, \
             patch('os.path.getmtime') as mock_mtime, \
             patch('os.remove') as mock_remove:
            
            # Mock finding 3 temp files across all patterns
            def mock_glob_return(pattern):
                if '/tmp/scan_*.xml' in pattern:
                    return ['/tmp/scan_old1.xml']
                elif '/tmp/nmap_*.txt' in pattern:
                    return ['/tmp/nmap_old2.txt']
                elif '/tmp/nuclei_*.json' in pattern:
                    return ['/tmp/nuclei_old3.json']
                return []
            
            mock_glob.side_effect = mock_glob_return
            old_timestamp = (datetime.now() - timedelta(days=2)).timestamp()
            mock_mtime.return_value = old_timestamp
            
            result = cleanup_temp_files()
            
            # Verify 3 files deleted
            assert result == 3
            assert mock_remove.call_count == 3

    def test_cleanup_temp_files_skip_recent(self):
        """Test that recent files are not deleted"""
        with patch('glob.glob') as mock_glob, \
             patch('os.path.getmtime') as mock_mtime, \
             patch('os.remove') as mock_remove:
            
            # Mock finding files, but they're recent
            mock_glob.side_effect = lambda p: ['/tmp/scan_recent.xml'] if '/tmp/scan_*.xml' in p else []
            recent_timestamp = (datetime.now() - timedelta(hours=12)).timestamp()
            mock_mtime.return_value = recent_timestamp
            
            result = cleanup_temp_files()
            
            # Verify no files deleted
            assert result == 0
            mock_remove.assert_not_called()

    def test_cleanup_temp_files_handles_errors(self):
        """Test cleanup continues even if some files can't be deleted"""
        with patch('glob.glob') as mock_glob, \
             patch('os.path.getmtime') as mock_mtime, \
             patch('os.remove') as mock_remove:
            
            old_timestamp = (datetime.now() - timedelta(days=2)).timestamp()
            
            # Return files for first pattern only
            def mock_glob_return(pattern):
                if '/tmp/scan_*.xml' in pattern:
                    return ['/tmp/file1.xml', '/tmp/file2.xml']
                return []
            
            mock_glob.side_effect = mock_glob_return
            mock_mtime.return_value = old_timestamp
            
            # First delete succeeds, second fails
            mock_remove.side_effect = [None, PermissionError('Access denied')]
            
            result = cleanup_temp_files()
            
            # Should still report 1 file deleted
            assert result == 1


class TestMonitoringTasks:
    """Test monitoring task functions"""

    def test_check_scan_timeouts_finds_timed_out_scans(self):
        """Test detecting and marking timed out scans"""
        with patch('config.config.get_config') as mock_config, \
             patch('services.data_ingestor.ingestor.DataIngestor') as mock_ingestor_class:
            
            mock_cfg = Mock()
            mock_cfg.DATABASE_URL = 'postgresql://test:test@localhost/test'
            mock_config.return_value = mock_cfg
            
            mock_ingestor = Mock()
            mock_ingestor_class.return_value = mock_ingestor
            
            # Create mock scans - one timed out, one still OK
            from services.data_ingestor.models import ScanStatus
            
            timed_out_scan = Mock()
            timed_out_scan.status = ScanStatus.RUNNING
            timed_out_scan.started_at = datetime.now() - timedelta(minutes=90)
            timed_out_scan.id = 'scan-timeout'
            
            ok_scan = Mock()
            ok_scan.status = ScanStatus.RUNNING
            ok_scan.started_at = datetime.now() - timedelta(minutes=30)
            ok_scan.id = 'scan-ok'
            
            completed_scan = Mock()
            completed_scan.status = ScanStatus.COMPLETED
            completed_scan.id = 'scan-done'
            
            mock_ingestor.list_scans.return_value = (
                [timed_out_scan, ok_scan, completed_scan],
                3
            )
            
            result = check_scan_timeouts(timeout_minutes=60)
            
            # Should find 1 timed out scan
            assert result == 1
            
            # Verify it was marked as failed
            mock_ingestor.update_scan_status.assert_called_once_with(
                'scan-timeout',
                ScanStatus.FAILED,
                error_message='Scan timed out after 60 minutes'
            )

    def test_check_scan_timeouts_no_timeouts(self):
        """Test when all scans are within timeout"""
        with patch('config.config.get_config') as mock_config, \
             patch('services.data_ingestor.ingestor.DataIngestor') as mock_ingestor_class:
            
            mock_cfg = Mock()
            mock_cfg.DATABASE_URL = 'postgresql://test:test@localhost/test'
            mock_config.return_value = mock_cfg
            
            mock_ingestor = Mock()
            mock_ingestor_class.return_value = mock_ingestor
            
            from services.data_ingestor.models import ScanStatus
            
            # All scans are recent or completed
            recent_scan = Mock()
            recent_scan.status = ScanStatus.RUNNING
            recent_scan.started_at = datetime.now() - timedelta(minutes=10)
            
            mock_ingestor.list_scans.return_value = ([recent_scan], 1)
            
            result = check_scan_timeouts(timeout_minutes=60)
            
            assert result == 0
            mock_ingestor.update_scan_status.assert_not_called()

    def test_check_scan_timeouts_handles_errors(self):
        """Test timeout check handles database errors"""
        with patch('config.config.get_config') as mock_config, \
             patch('services.data_ingestor.ingestor.DataIngestor') as mock_ingestor_class:
            
            mock_cfg = Mock()
            mock_cfg.DATABASE_URL = 'postgresql://test:test@localhost/test'
            mock_config.return_value = mock_cfg
            
            mock_ingestor = Mock()
            mock_ingestor_class.return_value = mock_ingestor
            mock_ingestor.list_scans.side_effect = Exception('DB error')
            
            with pytest.raises(Exception, match='DB error'):
                check_scan_timeouts()

    def test_monitor_worker_health_healthy_workers(self):
        """Test monitoring healthy workers"""
        with patch('config.config.get_config') as mock_config, \
             patch('redis.Redis') as mock_redis_class, \
             patch('rq.Worker') as mock_worker_class:
            
            mock_cfg = Mock()
            mock_cfg.REDIS_HOST = 'localhost'
            mock_cfg.REDIS_PORT = 6379
            mock_cfg.REDIS_DB = 0
            mock_config.return_value = mock_cfg
            
            mock_redis = Mock()
            mock_redis_class.return_value = mock_redis
            
            # Create mock workers
            worker1 = Mock()
            worker1.get_current_job.return_value = Mock()  # Has active job
            worker2 = Mock()
            worker2.get_current_job.return_value = None  # Idle
            
            mock_worker_class.all.return_value = [worker1, worker2]
            
            result = monitor_worker_health()
            
            assert result['healthy'] is True
            assert result['workers'] == 2
            assert result['active_tasks'] == 1
            assert 'timestamp' in result

    def test_monitor_worker_health_no_workers(self):
        """Test monitoring when no workers are available"""
        with patch('config.config.get_config') as mock_config, \
             patch('redis.Redis') as mock_redis_class, \
             patch('rq.Worker') as mock_worker_class:
            
            mock_cfg = Mock()
            mock_cfg.REDIS_HOST = 'localhost'
            mock_cfg.REDIS_PORT = 6379
            mock_cfg.REDIS_DB = 0
            mock_config.return_value = mock_cfg
            
            mock_redis = Mock()
            mock_redis_class.return_value = mock_redis
            
            # No workers available
            mock_worker_class.all.return_value = []
            
            result = monitor_worker_health()
            
            assert result['healthy'] is False
            assert result['workers'] == 0
            assert result['active_tasks'] == 0

    def test_monitor_worker_health_connection_error(self):
        """Test monitoring handles connection errors"""
        with patch('config.config.get_config') as mock_config, \
             patch('redis.Redis') as mock_redis_class, \
             patch('rq.Worker') as mock_worker_class:
            
            mock_cfg = Mock()
            mock_cfg.REDIS_HOST = 'localhost'
            mock_cfg.REDIS_PORT = 6379
            mock_cfg.REDIS_DB = 0
            mock_config.return_value = mock_cfg
            
            mock_redis = Mock()
            mock_redis_class.return_value = mock_redis
            
            # Worker inspection fails
            mock_worker_class.all.side_effect = Exception('Redis connection failed')
            
            result = monitor_worker_health()
            
            # Should still return result but mark as unhealthy
            assert result['healthy'] is False


class TestProcessingTasks:
    """Test processing task functions"""

    def test_parse_scan_output_nmap(self):
        """Test parsing Nmap output"""
        with patch('utils.parsers.NmapParser') as mock_parser:
            
            mock_parser.parse_xml.return_value = {'hosts': [], 'summary': {}}
            
            result = parse_scan_output(
                scan_id='scan-123',
                raw_output='<xml>nmap output</xml>',
                tool_name='nmap'
            )
            
            assert result == {'hosts': [], 'summary': {}}
            mock_parser.parse_xml.assert_called_once_with('<xml>nmap output</xml>')

    def test_parse_scan_output_openvas(self):
        """Test parsing OpenVAS output"""
        with patch('utils.parsers.OpenVASParser') as mock_parser:
            
            mock_parser.parse_xml.return_value = {'vulnerabilities': []}
            
            result = parse_scan_output(
                scan_id='scan-456',
                raw_output='<report>openvas</report>',
                tool_name='openvas'
            )
            
            assert result == {'vulnerabilities': []}
            mock_parser.parse_xml.assert_called_once()

    def test_parse_scan_output_unknown_tool(self):
        """Test parsing unknown tool returns raw output"""
        result = parse_scan_output(
            scan_id='scan-789',
            raw_output='some output',
            tool_name='unknown_tool'
        )
        
        assert result == {'raw': 'some output'}

    def test_parse_scan_output_error(self):
        """Test parse handles errors"""
        with patch('utils.parsers.NmapParser') as mock_parser:
            
            mock_parser.parse_xml.side_effect = Exception('Parse error')
            
            with pytest.raises(Exception, match='Parse error'):
                parse_scan_output(
                    scan_id='scan-error',
                    raw_output='<invalid>xml</invalid>',
                    tool_name='nmap'
                )

    def test_extract_vulnerabilities_from_vulnerabilities_key(self):
        """Test extracting from 'vulnerabilities' key"""
        parsed_results = {
            'vulnerabilities': [
                {'id': 'CVE-2021-1234', 'severity': 'high'},
                {'id': 'CVE-2021-5678', 'severity': 'medium'}
            ]
        }
        
        result = extract_vulnerabilities('scan-123', parsed_results)
        
        assert len(result) == 2
        assert result[0]['id'] == 'CVE-2021-1234'

    def test_extract_vulnerabilities_from_findings_key(self):
        """Test extracting from 'findings' key"""
        parsed_results = {
            'findings': [
                {'title': 'SQL Injection', 'severity': 'critical'}
            ]
        }
        
        result = extract_vulnerabilities('scan-456', parsed_results)
        
        assert len(result) == 1
        assert result[0]['title'] == 'SQL Injection'

    def test_extract_vulnerabilities_from_issues_key(self):
        """Test extracting from 'issues' key"""
        parsed_results = {
            'issues': [
                {'type': 'XSS', 'risk': 'high'}
            ]
        }
        
        result = extract_vulnerabilities('scan-789', parsed_results)
        
        assert len(result) == 1

    def test_extract_vulnerabilities_no_vulns(self):
        """Test extraction with no vulnerabilities found"""
        parsed_results = {'summary': 'No issues found'}
        
        result = extract_vulnerabilities('scan-clean', parsed_results)
        
        assert result == []

    def test_extract_vulnerabilities_error(self):
        """Test extraction handles errors"""
        # Invalid parsed_results
        with pytest.raises(Exception):
            extract_vulnerabilities('scan-error', None)


class TestNotificationTasks:
    """Test notification task functions"""

    def test_send_scan_notification_email_configured(self):
        """Test sending notification via email"""
        with patch('config.config.get_config') as mock_config, \
             patch('smtplib.SMTP') as mock_smtp:
            
            mock_cfg = Mock()
            mock_cfg.SMTP_HOST = 'smtp.example.com'
            mock_cfg.SMTP_PORT = 587
            mock_cfg.SMTP_FROM = 'scanner@example.com'
            mock_cfg.SMTP_USE_TLS = True
            mock_cfg.SMTP_USERNAME = 'user'
            mock_cfg.SMTP_PASSWORD = 'pass'
            mock_cfg.APP_URL = 'http://localhost:5000'
            mock_cfg.WEBHOOK_URL = None
            mock_config.return_value = mock_cfg
            
            mock_server = Mock()
            mock_smtp.return_value.__enter__.return_value = mock_server
            
            result = send_scan_notification(
                scan_id='scan-123',
                status='completed',
                recipients=['user@example.com']
            )
            
            assert result['sent'] is True
            assert 'email' in result['methods']
            mock_server.send_message.assert_called_once()

    def test_send_scan_notification_webhook_configured(self):
        """Test sending notification via webhook"""
        with patch('config.config.get_config') as mock_config, \
             patch('requests.post') as mock_post:
            
            mock_cfg = Mock()
            mock_cfg.SMTP_HOST = None
            mock_cfg.WEBHOOK_URL = 'https://webhook.example.com/notify'
            mock_config.return_value = mock_cfg
            
            mock_response = Mock()
            mock_response.status_code = 200
            mock_post.return_value = mock_response
            
            result = send_scan_notification(
                scan_id='scan-456',
                status='failed'
            )
            
            assert result['sent'] is True
            assert 'webhook' in result['methods']
            mock_post.assert_called_once()

    def test_send_scan_notification_no_config(self):
        """Test notification with no methods configured"""
        with patch('config.config.get_config') as mock_config:
            
            mock_cfg = Mock()
            mock_cfg.SMTP_HOST = None
            mock_cfg.WEBHOOK_URL = None
            mock_config.return_value = mock_cfg
            
            result = send_scan_notification(
                scan_id='scan-789',
                status='completed'
            )
            
            assert result['sent'] is True
            assert 'log_only' in result['methods']

    def test_send_scan_notification_email_error(self):
        """Test notification continues on email error"""
        with patch('config.config.get_config') as mock_config, \
             patch('smtplib.SMTP') as mock_smtp:
            
            mock_cfg = Mock()
            mock_cfg.SMTP_HOST = 'smtp.example.com'
            mock_cfg.SMTP_PORT = 587
            mock_cfg.SMTP_FROM = 'scanner@example.com'
            mock_cfg.SMTP_USE_TLS = False
            mock_cfg.APP_URL = 'http://localhost'
            mock_cfg.WEBHOOK_URL = None
            mock_config.return_value = mock_cfg
            
            # Email fails
            mock_smtp.side_effect = Exception('SMTP error')
            
            result = send_scan_notification(
                scan_id='scan-error',
                status='completed',
                recipients=['user@example.com']
            )
            
            # Should still complete but sent=False
            assert result['sent'] is False

    def test_send_alert_email(self):
        """Test sending alert via email"""
        with patch('config.config.get_config') as mock_config, \
             patch('smtplib.SMTP') as mock_smtp:
            
            mock_cfg = Mock()
            mock_cfg.SMTP_HOST = 'smtp.example.com'
            mock_cfg.SMTP_PORT = 587
            mock_cfg.SMTP_FROM = 'alerts@example.com'
            mock_cfg.SMTP_USE_TLS = True
            mock_cfg.SMTP_USERNAME = 'alerts'
            mock_cfg.SMTP_PASSWORD = 'pass'
            mock_cfg.ALERT_EMAIL = 'admin@example.com'
            mock_cfg.ALERT_WEBHOOK_URL = None
            mock_config.return_value = mock_cfg
            
            mock_server = Mock()
            mock_smtp.return_value.__enter__.return_value = mock_server
            
            result = send_alert(
                alert_type='vulnerability',
                message='Critical vulnerability found',
                severity='critical',
                data={'cve': 'CVE-2021-1234'}
            )
            
            assert result['sent'] is True
            assert 'email' in result['methods']
            assert result['severity'] == 'critical'

    def test_send_alert_webhook(self):
        """Test sending alert via webhook"""
        with patch('config.config.get_config') as mock_config, \
             patch('requests.post') as mock_post:
            
            mock_cfg = Mock()
            mock_cfg.SMTP_HOST = None
            mock_cfg.ALERT_EMAIL = None
            mock_cfg.ALERT_WEBHOOK_URL = 'https://alerts.example.com'
            mock_config.return_value = mock_cfg
            
            mock_response = Mock()
            mock_response.status_code = 200
            mock_post.return_value = mock_response
            
            result = send_alert(
                alert_type='system',
                message='Worker offline',
                severity='warning'
            )
            
            assert result['sent'] is True
            assert 'webhook' in result['methods']

    def test_send_alert_no_config(self):
        """Test alert with no methods configured"""
        with patch('config.config.get_config') as mock_config:
            
            mock_cfg = Mock()
            mock_cfg.SMTP_HOST = None
            mock_cfg.ALERT_EMAIL = None
            mock_cfg.ALERT_WEBHOOK_URL = None
            mock_config.return_value = mock_cfg
            
            result = send_alert(
                alert_type='test',
                message='Test alert',
                severity='info'
            )
            
            assert result['sent'] is True
            assert 'log_only' in result['methods']

    def test_send_alert_webhook_failure(self):
        """Test alert handles webhook failures"""
        with patch('config.config.get_config') as mock_config, \
             patch('requests.post') as mock_post:
            
            mock_cfg = Mock()
            mock_cfg.SMTP_HOST = None
            mock_cfg.ALERT_EMAIL = None
            mock_cfg.ALERT_WEBHOOK_URL = 'https://alerts.example.com'
            mock_config.return_value = mock_cfg
            
            mock_response = Mock()
            mock_response.status_code = 500
            mock_post.return_value = mock_response
            
            result = send_alert(
                alert_type='test',
                message='Test',
                severity='info'
            )
            
            # Webhook failed (500), so should fall back to log_only
            assert result['sent'] is False  # Webhook didn't succeed
            assert result['methods'] == []  # No successful methods
