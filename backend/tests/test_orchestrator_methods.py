"""
Comprehensive tests for ScanOrchestrator methods
Tests job orchestration, status tracking, queue management

Focus on API-verified methods:
- enqueue_scan, get_job_status, cancel_job
- get_queue_stats, clear_failed_jobs
- get_job_result, requeue_failed_job
"""

import pytest
from unittest.mock import Mock, patch, PropertyMock
from datetime import datetime
from services.scan_orchestrator.orchestrator import ScanOrchestrator


class TestOrchestratorEnqueue:
    """Test job enqueue operations"""

    @patch('services.scan_orchestrator.orchestrator.Queue')
    @patch('services.scan_orchestrator.orchestrator.Redis')
    def test_enqueue_scan_high_priority(self, mock_redis, mock_queue):
        """Test enqueue with high priority"""
        orchestrator = ScanOrchestrator()
        mock_job = Mock(id='job-123')
        orchestrator.high_priority_queue.enqueue.return_value = mock_job
        
        result = orchestrator.enqueue_scan(
            scan_id='scan-123',
            target='192.168.1.1',
            tool='nmap',
            scan_type='basic',
            priority='high'
        )
        
        assert result == 'job-123'
        orchestrator.high_priority_queue.enqueue.assert_called_once()

    @patch('services.scan_orchestrator.orchestrator.Queue')
    @patch('services.scan_orchestrator.orchestrator.Redis')
    def test_enqueue_scan_low_priority(self, mock_redis, mock_queue):
        """Test enqueue with low priority"""
        orchestrator = ScanOrchestrator()
        mock_job = Mock(id='job-456')
        orchestrator.low_priority_queue.enqueue.return_value = mock_job
        
        result = orchestrator.enqueue_scan(
            scan_id='scan-456',
            target='example.com',
            tool='nikto',
            scan_type='full',
            priority='low'
        )
        
        assert result == 'job-456'
        orchestrator.low_priority_queue.enqueue.assert_called_once()
    
    @patch('services.scan_orchestrator.orchestrator.Queue')
    @patch('services.scan_orchestrator.orchestrator.Redis')
    def test_enqueue_scan_unsupported_tool(self, mock_redis, mock_queue):
        """Test enqueue with unsupported tool raises ValueError"""
        orchestrator = ScanOrchestrator()
        
        with pytest.raises(ValueError, match="Unsupported tool"):
            orchestrator.enqueue_scan(
                scan_id='scan-999',
                target='192.168.1.1',
                tool='invalid-tool',
                scan_type='basic'
            )


class TestOrchestratorJobStatus:
    """Test job status operations"""

    @patch('services.scan_orchestrator.orchestrator.Job')
    @patch('services.scan_orchestrator.orchestrator.Queue')
    @patch('services.scan_orchestrator.orchestrator.Redis')
    def test_get_job_status_queued(self, mock_redis, mock_queue, mock_job_class):
        """Test getting status of queued job"""
        orchestrator = ScanOrchestrator()
        
        mock_job = Mock()
        mock_job.get_status.return_value = 'queued'
        mock_job.created_at = datetime(2024, 1, 1, 12, 0, 0)
        mock_job.started_at = None
        mock_job.ended_at = None
        mock_job.meta = {}
        mock_job.is_finished = False
        mock_job.is_failed = False
        mock_job_class.fetch.return_value = mock_job
        
        status = orchestrator.get_job_status('job-123')
        
        assert status['job_id'] == 'job-123'
        assert status['status'] == 'queued'

    @patch('services.scan_orchestrator.orchestrator.Job')
    @patch('services.scan_orchestrator.orchestrator.Queue')
    @patch('services.scan_orchestrator.orchestrator.Redis')
    def test_get_job_status_not_found(self, mock_redis, mock_queue, mock_job_class):
        """Test getting status of non-existent job returns unknown"""
        orchestrator = ScanOrchestrator()
        mock_job_class.fetch.side_effect = Exception("Job not found")
        
        status = orchestrator.get_job_status('nonexistent')
        
        assert status['job_id'] == 'nonexistent'
        assert status['status'] == 'unknown'
        assert 'error' in status


class TestOrchestratorJobControl:
    """Test job control operations"""

    @patch('services.scan_orchestrator.orchestrator.Job')
    @patch('services.scan_orchestrator.orchestrator.Queue')
    @patch('services.scan_orchestrator.orchestrator.Redis')
    def test_cancel_job_success(self, mock_redis, mock_queue, mock_job_class):
        """Test successfully cancelling a job"""
        orchestrator = ScanOrchestrator()
        
        mock_job = Mock()
        mock_job.is_finished = False
        mock_job.is_failed = False
        mock_job_class.fetch.return_value = mock_job
        
        result = orchestrator.cancel_job('job-123')
        
        assert result is True
        mock_job.cancel.assert_called_once()

    @patch('services.scan_orchestrator.orchestrator.Job')
    @patch('services.scan_orchestrator.orchestrator.Queue')
    @patch('services.scan_orchestrator.orchestrator.Redis')
    def test_cancel_job_already_finished(self, mock_redis, mock_queue, mock_job_class):
        """Test cancelling an already finished job"""
        orchestrator = ScanOrchestrator()
        
        mock_job = Mock()
        mock_job.is_finished = True
        mock_job.is_failed = False
        mock_job_class.fetch.return_value = mock_job
        
        result = orchestrator.cancel_job('job-456')
        
        assert result is False
        mock_job.cancel.assert_not_called()


class TestOrchestratorQueueInfo:
    """Test queue information operations"""

    @patch('services.scan_orchestrator.orchestrator.Queue')
    @patch('services.scan_orchestrator.orchestrator.Redis')
    def test_get_queue_stats(self, mock_redis, mock_queue):
        """Test getting queue statistics"""
        orchestrator = ScanOrchestrator()
        
        # Mock registries
        for queue in [orchestrator.high_priority_queue, orchestrator.normal_queue, orchestrator.low_priority_queue]:
            queue.started_job_registry = Mock(count=2)
            queue.finished_job_registry = Mock(count=100)
            queue.failed_job_registry = Mock(count=5)
        
        stats = orchestrator.get_queue_stats()
        
        assert 'high_priority' in stats
        assert 'normal' in stats
        assert 'low_priority' in stats
        assert stats['high_priority']['started'] == 2


class TestOrchestratorCleanup:
    """Test cleanup operations"""

    @patch('services.scan_orchestrator.orchestrator.Queue')
    @patch('services.scan_orchestrator.orchestrator.Redis')
    def test_clear_failed_jobs(self, mock_redis, mock_queue):
        """Test clearing failed jobs from all queues"""
        orchestrator = ScanOrchestrator()
        
        # Mock failed job registries
        for queue in [orchestrator.high_priority_queue, orchestrator.normal_queue, orchestrator.low_priority_queue]:
            failed_reg = Mock()
            failed_reg.get_job_ids.return_value = ['failed-1', 'failed-2']
            failed_reg.remove = Mock()
            queue.failed_job_registry = failed_reg
        
        count = orchestrator.clear_failed_jobs()
        
        # 3 queues * 2 jobs each = 6 total
        assert count == 6


class TestOrchestratorErrorHandling:
    """Test error handling in orchestrator operations"""
    
    @patch('services.scan_orchestrator.orchestrator.Queue')
    @patch('services.scan_orchestrator.orchestrator.Redis')
    def test_get_job_status_not_found(self, mock_redis, mock_queue):
        """Test getting status of non-existent job"""
        orchestrator = ScanOrchestrator()
        
        # Mock Job.fetch to raise NoSuchJobError
        with patch('services.scan_orchestrator.orchestrator.Job') as mock_job_class:
            from rq.exceptions import NoSuchJobError
            mock_job_class.fetch.side_effect = NoSuchJobError()
            
            status = orchestrator.get_job_status('nonexistent-job-id')
            
            assert status['status'] == 'unknown'  # Returns 'unknown' on error
            assert 'error' in status
    
    @patch('services.scan_orchestrator.orchestrator.Queue')
    @patch('services.scan_orchestrator.orchestrator.Redis')
    def test_cancel_job_not_found(self, mock_redis, mock_queue):
        """Test canceling non-existent job"""
        orchestrator = ScanOrchestrator()
        
        # Mock Job.fetch to raise NoSuchJobError
        with patch('services.scan_orchestrator.orchestrator.Job') as mock_job_class:
            from rq.exceptions import NoSuchJobError
            mock_job_class.fetch.side_effect = NoSuchJobError()
            
            result = orchestrator.cancel_job('nonexistent-job-id')
            
            assert result is False
    
    @patch('services.scan_orchestrator.orchestrator.Queue')
    @patch('services.scan_orchestrator.orchestrator.Redis')
    def test_get_all_jobs_with_empty_queues(self, mock_redis, mock_queue):
        """Test getting all jobs when queues are empty"""
        orchestrator = ScanOrchestrator()
        
        # Mock empty queues
        for queue in [orchestrator.high_priority_queue, orchestrator.normal_queue, orchestrator.low_priority_queue]:
            queue.get_jobs.return_value = []
            queue.started_job_registry.get_job_ids.return_value = []
            queue.finished_job_registry.get_job_ids.return_value = []
            queue.failed_job_registry.get_job_ids.return_value = []
        
        jobs = orchestrator.get_all_jobs()
        
        assert isinstance(jobs, list)  # Returns list, not dict
        assert len(jobs) == 0


class TestOrchestratorAdvanced:
    """Test advanced orchestrator operations"""

    @patch('services.scan_orchestrator.orchestrator.Job')
    @patch('services.scan_orchestrator.orchestrator.Queue')
    @patch('services.scan_orchestrator.orchestrator.Redis')
    def test_get_job_result_success(self, mock_redis, mock_queue, mock_job_class):
        """Test getting successful job result"""
        orchestrator = ScanOrchestrator()
        
        mock_job = Mock()
        mock_job.result = {'scanned': True, 'findings': 10}
        mock_job.is_finished = True
        mock_job_class.fetch.return_value = mock_job
        
        result = orchestrator.get_job_result('job-123')
        
        assert result == {'scanned': True, 'findings': 10}

    @patch('services.scan_orchestrator.orchestrator.Job')
    @patch('services.scan_orchestrator.orchestrator.Queue')
    @patch('services.scan_orchestrator.orchestrator.Redis')
    def test_get_job_result_not_found(self, mock_redis, mock_queue, mock_job_class):
        """Test getting result of non-existent job"""
        orchestrator = ScanOrchestrator()
        mock_job_class.fetch.side_effect = Exception("Job not found")
        
        result = orchestrator.get_job_result('nonexistent')
        
        assert result is None

    @patch('services.scan_orchestrator.orchestrator.Job')
    @patch('services.scan_orchestrator.orchestrator.Queue')
    @patch('services.scan_orchestrator.orchestrator.Redis')
    def test_requeue_failed_job_success(self, mock_redis, mock_queue, mock_job_class):
        """Test requeuing a failed job"""
        orchestrator = ScanOrchestrator()
        
        # Mock failed job
        old_job = Mock()
        old_job.is_failed = True
        old_job.requeue = Mock()
        mock_job_class.fetch.return_value = old_job
        
        result = orchestrator.requeue_failed_job('job-failed')
        
        # requeue() is called on the job, returns same job ID
        assert result == 'job-failed'
        old_job.requeue.assert_called_once()

    @patch('services.scan_orchestrator.orchestrator.Job')
    @patch('services.scan_orchestrator.orchestrator.Queue')
    @patch('services.scan_orchestrator.orchestrator.Redis')
    def test_requeue_failed_job_not_failed(self, mock_redis, mock_queue, mock_job_class):
        """Test requeuing a job that hasn't failed"""
        orchestrator = ScanOrchestrator()
        
        mock_job = Mock()
        mock_job.is_failed = False
        mock_job_class.fetch.return_value = mock_job
        
        result = orchestrator.requeue_failed_job('job-123')
        
        assert result is None
    
    @patch('services.scan_orchestrator.orchestrator.Queue')
    @patch('services.scan_orchestrator.orchestrator.Redis')
    def test_list_jobs_all(self, mock_redis, mock_queue_class):
        """Test listing all jobs across all queues and statuses"""
        # Create mock jobs
        high_job = Mock()
        high_job.id = 'high-job-1'
        normal_job = Mock()
        normal_job.id = 'normal-job-1'
        
        # Create pre-configured queue mocks with jobs
        high_queue_mock = Mock()
        high_queue_mock.jobs = [high_job]  # Make it a real list
        high_queue_mock.name = 'high'
        high_queue_mock.started_job_registry.get_job_ids.return_value = []
        high_queue_mock.finished_job_registry.get_job_ids.return_value = []
        high_queue_mock.failed_job_registry.get_job_ids.return_value = []
        
        normal_queue_mock = Mock()
        normal_queue_mock.jobs = [normal_job]  # Make it a real list
        normal_queue_mock.name = 'normal'
        normal_queue_mock.started_job_registry.get_job_ids.return_value = []
        normal_queue_mock.finished_job_registry.get_job_ids.return_value = []
        normal_queue_mock.failed_job_registry.get_job_ids.return_value = []
        
        low_queue_mock = Mock()
        low_queue_mock.jobs = []  # Empty list
        low_queue_mock.name = 'low'
        low_queue_mock.started_job_registry.get_job_ids.return_value = []
        low_queue_mock.finished_job_registry.get_job_ids.return_value = []
        low_queue_mock.failed_job_registry.get_job_ids.return_value = []
        
        # Make Queue constructor return appropriate queue based on name
        def create_queue(name, connection=None):
            if name == 'high':
                return high_queue_mock
            elif name == 'normal':
                return normal_queue_mock
            else:  # low
                return low_queue_mock
        
        mock_queue_class.side_effect = create_queue
        
        # NOW create the orchestrator - it will use our pre-configured mocks
        orchestrator = ScanOrchestrator()
        
        jobs = orchestrator.get_all_jobs()
        
        assert len(jobs) >= 2, f"Expected >= 2 jobs, got {len(jobs)}: {jobs}"
        job_ids = [job['job_id'] for job in jobs]
        assert 'high-job-1' in job_ids
        assert 'normal-job-1' in job_ids
    
    @patch('services.scan_orchestrator.orchestrator.Queue')
    @patch('services.scan_orchestrator.orchestrator.Redis')
    def test_list_jobs_with_status_filter(self, mock_redis, mock_queue):
        """Test listing jobs filtered by status"""
        orchestrator = ScanOrchestrator()
        
        # Mock finished jobs in registry
        for queue in [orchestrator.high_priority_queue, orchestrator.normal_queue, orchestrator.low_priority_queue]:
            queue.jobs = []
            queue.started_job_registry.get_job_ids.return_value = []
            queue.finished_job_registry.get_job_ids.return_value = ['finished-job-1', 'finished-job-2']
            queue.failed_job_registry.get_job_ids.return_value = []
        
        jobs = orchestrator.get_all_jobs(status='finished')
        
        assert len(jobs) >= 2
        for job in jobs:
            assert job['status'] == 'finished'
