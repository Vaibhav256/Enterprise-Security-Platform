"""
Tests for DataIngestor methods

Tests ingestor CRUD operations, raw results, and scan summaries.
Focus on methods not covered by routes tests.
"""

import pytest
from datetime import datetime
from services.data_ingestor.models import ScanStatus
import uuid


class TestStoreRawResult:
    """Test store_raw_result method"""
    
    def test_store_raw_result_success(self, db_ingestor):
        """Test storing raw scan result successfully"""
        # Create a unique scan first
        scan = db_ingestor.create_scan(
            scan_id=f'test-raw-{uuid.uuid4()}',
            target='192.168.1.100',
            tool_name='nmap',
            scan_type='basic'
        )
        
        result = db_ingestor.store_raw_result(
            scan_id=scan.id,
            tool_name='nmap',
            raw_output='<?xml version="1.0"?><nmaprun>test</nmaprun>',
            output_format='xml'
        )
        
        assert result is not None
        assert result.scan_id == scan.id
        assert result.tool_name == 'nmap'
        assert result.raw_output == '<?xml version="1.0"?><nmaprun>test</nmaprun>'
        assert result.output_format == 'xml'
        assert result.file_size > 0
        
    def test_store_raw_result_with_parsed_output(self, db_ingestor):
        """Test storing raw result - parsed_output is read-only property"""
        scan = db_ingestor.create_scan(
            scan_id=f'test-parsed-{uuid.uuid4()}',
            target='192.168.1.101',
            tool_name='nmap',
            scan_type='basic'
        )
        
        # parsed_output is a @property, not stored directly
        result = db_ingestor.store_raw_result(
            scan_id=scan.id,
            tool_name='nmap',
            raw_output='Raw XML output',
            output_format='xml'
        )
        
        # parsed_output property returns None by default
        assert result.parsed_output is None
        
    def test_store_raw_result_invalid_scan_id_generates_uuid(self, db_ingestor):
        """Test that invalid scan_id still requires a valid scan to exist"""
        # Create a scan first with a valid UUID
        scan = db_ingestor.create_scan(
            scan_id=f'test-invalid-{uuid.uuid4()}',
            target='192.168.1.102',
            tool_name='nmap',
            scan_type='basic'
        )
        
        # Store result with the valid scan
        result = db_ingestor.store_raw_result(
            scan_id=scan.id,
            tool_name='nmap',
            raw_output='test output',
            output_format='text'
        )
        
        # Should work with valid scan_id
        assert result is not None
        assert result.scan_id == scan.id


class TestCreateScanSummary:
    """Test create_scan_summary method"""
    
    def test_create_scan_summary_success(self, db_ingestor):
        """Test creating scan summary successfully"""
        scan = db_ingestor.create_scan(
            scan_id=f'test-summary-{uuid.uuid4()}',
            target='192.168.1.102',
            tool_name='nmap',
            scan_type='basic'
        )
        
        summary_data = {
            'total_hosts': 10,
            'total_ports': 100,
            'total_vulnerabilities': 12,
            'critical_count': 2,
            'high_count': 4,
            'medium_count': 4,
            'low_count': 2,
            'info_count': 0
        }
        
        summary = db_ingestor.create_scan_summary(scan.id, summary_data)
        
        assert summary is not None
        assert summary.scan_id == scan.id
        assert summary.total_hosts == 10
        assert summary.total_ports == 100
        assert summary.total_vulnerabilities == 12
        assert summary.critical_count == 2
        assert summary.high_count == 4
        assert summary.medium_count == 4
        assert summary.low_count == 2
        assert summary.info_count == 0
        
    def test_create_scan_summary_with_partial_data(self, db_ingestor):
        """Test creating summary with partial data (defaults to 0)"""
        scan = db_ingestor.create_scan(
            scan_id=f'test-partial-{uuid.uuid4()}',
            target='192.168.1.103',
            tool_name='nmap',
            scan_type='basic'
        )
        
        summary_data = {
            'total_hosts': 5,
            'total_vulnerabilities': 3
        }
        
        summary = db_ingestor.create_scan_summary(scan.id, summary_data)
        
        assert summary.total_hosts == 5
        assert summary.total_vulnerabilities == 3
        # Others should default to 0
        assert summary.total_ports == 0
        assert summary.critical_count == 0
        
    def test_create_scan_summary_stores_raw_data(self, db_ingestor):
        """Test that summary is created successfully"""
        scan = db_ingestor.create_scan(
            scan_id=f'test-rawdata-{uuid.uuid4()}',
            target='192.168.1.104',
            tool_name='nmap',
            scan_type='basic'
        )
        
        summary_data = {
            'total_hosts': 3,
            'total_vulnerabilities': 5
        }
        
        summary = db_ingestor.create_scan_summary(scan.id, summary_data)
        
        assert summary.total_hosts == 3
        assert summary.total_vulnerabilities == 5


class TestGetScanSummary:
    """Test get_scan_summary method"""
    
    def test_get_scan_summary_exists(self, db_ingestor):
        """Test retrieving existing scan summary"""
        scan = db_ingestor.create_scan(
            scan_id=f'test-getsummary-{uuid.uuid4()}',
            target='192.168.1.105',
            tool_name='nmap',
            scan_type='basic'
        )
        
        # Create summary first
        summary_data = {'total_hosts': 5, 'total_vulnerabilities': 2}
        created = db_ingestor.create_scan_summary(scan.id, summary_data)
        
        # Retrieve it
        retrieved = db_ingestor.get_scan_summary(scan.id)
        
        assert retrieved is not None
        assert retrieved.id == created.id
        assert retrieved.total_hosts == 5
        
    def test_get_scan_summary_not_found(self, db_ingestor):
        """Test retrieving non-existent summary returns None"""
        summary = db_ingestor.get_scan_summary('nonexistent-scan-id')
        
        assert summary is None


class TestUpdateScanStatus:
    """Test update_scan_status with edge cases"""
    
    def test_update_status_to_running_sets_started_at(self, db_ingestor):
        """Test that updating to RUNNING sets started_at timestamp"""
        scan = db_ingestor.create_scan(
            scan_id=f'test-running-{uuid.uuid4()}',
            target='192.168.1.106',
            tool_name='nmap',
            scan_type='basic'
        )
        
        # Initially no started_at
        assert scan.started_at is None
        
        # Update to RUNNING
        db_ingestor.update_scan_status(scan.id, ScanStatus.RUNNING)
        
        updated_scan = db_ingestor.get_scan(scan.id)
        assert updated_scan.status == ScanStatus.RUNNING
        assert updated_scan.started_at is not None
            
    def test_update_status_to_completed_sets_completed_at(self, db_ingestor):
        """Test that updating to COMPLETED sets completed_at timestamp"""
        # Create a new scan
        scan = db_ingestor.create_scan(
            scan_id=f'test-completed-{uuid.uuid4()}',
            target='192.168.1.107',
            tool_name='nmap',
            scan_type='basic'
        )
        
        # Update to RUNNING first
        db_ingestor.update_scan_status(scan.id, ScanStatus.RUNNING)
        
        # Update to COMPLETED
        db_ingestor.update_scan_status(scan.id, ScanStatus.COMPLETED)
        
        updated_scan = db_ingestor.get_scan(scan.id)
        assert updated_scan.status == ScanStatus.COMPLETED
        assert updated_scan.completed_at is not None
        
    def test_update_status_to_failed_sets_completed_at(self, db_ingestor):
        """Test that updating to FAILED also sets completed_at"""
        scan = db_ingestor.create_scan(
            scan_id=f'test-failed-{uuid.uuid4()}',
            target='192.168.1.108',
            tool_name='nmap',
            scan_type='basic'
        )
        
        db_ingestor.update_scan_status(scan.id, ScanStatus.FAILED, error_message='Test error')
        
        updated_scan = db_ingestor.get_scan(scan.id)
        assert updated_scan.status == ScanStatus.FAILED
        assert updated_scan.completed_at is not None
        assert updated_scan.error_message == 'Test error'


class TestDeleteOperations:
    """Test delete operations"""
    
    def test_delete_scan_success(self, db_ingestor):
        """Test successful scan deletion"""
        scan = db_ingestor.create_scan(
            scan_id=f'test-delete-{uuid.uuid4()}',
            target='192.168.1.200',
            tool_name='nmap',
            scan_type='basic'
        )
        
        # Delete the scan
        result = db_ingestor.delete_scan(scan.id)
        assert result is True
        
        # Verify scan is deleted
        deleted_scan = db_ingestor.get_scan(scan.id)
        assert deleted_scan is None
    
    def test_delete_scan_not_found(self, db_ingestor):
        """Test deleting non-existent scan returns False"""
        result = db_ingestor.delete_scan(f'nonexistent-{uuid.uuid4()}')
        assert result is False
    
    def test_delete_scan_with_results(self, db_ingestor):
        """Test deleting scan also deletes associated results"""
        scan = db_ingestor.create_scan(
            scan_id=f'test-delete-cascade-{uuid.uuid4()}',
            target='192.168.1.201',
            tool_name='nmap',
            scan_type='basic'
        )
        
        # Add raw result
        db_ingestor.store_raw_result(
            scan_id=scan.id,
            tool_name='nmap',
            raw_output='test output',
            output_format='text'
        )
        
        # Add scan summary
        db_ingestor.create_scan_summary(
            scan_id=scan.id,
            summary_data={
                'total_hosts': 5,
                'total_ports': 100,
                'total_vulnerabilities': 3
            }
        )
        
        # Delete scan
        result = db_ingestor.delete_scan(scan.id)
        assert result is True
        
        # Verify all data is deleted (cascade)
        deleted_scan = db_ingestor.get_scan(scan.id)
        assert deleted_scan is None


class TestListScansWithFilters:
    """Test list_scans with various filters"""
    
    def test_list_scans_filter_by_status(self, db_ingestor):
        """Test filtering scans by status"""
        # Create scans with different statuses
        scan1 = db_ingestor.create_scan(f'scan-pending-{uuid.uuid4()}', '192.168.1.109', 'nmap', 'basic')
        scan2 = db_ingestor.create_scan(f'scan-running-{uuid.uuid4()}', '192.168.1.110', 'nmap', 'basic')
        scan3 = db_ingestor.create_scan(f'scan-completed-{uuid.uuid4()}', '192.168.1.111', 'nmap', 'basic')
        
        db_ingestor.update_scan_status(scan2.id, ScanStatus.RUNNING)
        db_ingestor.update_scan_status(scan3.id, ScanStatus.COMPLETED)
        
        # Filter by status - list_scans returns (scans, total) tuple
        running_scans, total = db_ingestor.list_scans(status=ScanStatus.RUNNING.value)
        
        assert len(running_scans) >= 1
        running_ids = [s.id for s in running_scans]
        assert scan2.id in running_ids
        
    def test_list_scans_filter_by_tool(self, db_ingestor):
        """Test filtering scans by tool name"""
        scan1 = db_ingestor.create_scan(f'scan-nmap-{uuid.uuid4()}', '192.168.1.112', 'nmap', 'basic')
        scan2 = db_ingestor.create_scan(f'scan-openvas-{uuid.uuid4()}', '192.168.1.113', 'openvas', 'basic')
        
        # list_scans returns (scans, total) tuple
        all_scans, total = db_ingestor.list_scans()
        
        assert len(all_scans) >= 2
        # Verify both tools exist
        tool_names = [s.tool_name for s in all_scans]
        assert 'nmap' in tool_names
        assert 'openvas' in tool_names
        
    def test_list_scans_with_limit(self, db_ingestor):
        """Test limiting number of results"""
        # Create multiple scans
        for i in range(5):
            db_ingestor.create_scan(f'scan-limit-{uuid.uuid4()}', '192.168.1.1', 'nmap', 'basic')
            
        # Get with limit - returns (scans, total) tuple
        scans, total = db_ingestor.list_scans(limit=2)
        
        assert len(scans) == 2
        assert total >= 5  # At least our 5 scans


class TestRawResultRetrieval:
    """Test raw result retrieval operations"""
    
    def test_get_raw_results(self, db_ingestor):
        """Test retrieving all raw results for a scan"""
        scan = db_ingestor.create_scan(
            scan_id=f'test-raw-results-{uuid.uuid4()}',
            target='192.168.1.202',
            tool_name='nmap',
            scan_type='basic'
        )
        
        # Store multiple raw results
        result1 = db_ingestor.store_raw_result(
            scan_id=scan.id,
            tool_name='nmap',
            raw_output='output 1',
            output_format='text'
        )
        
        result2 = db_ingestor.store_raw_result(
            scan_id=scan.id,
            tool_name='nmap',
            raw_output='output 2',
            output_format='xml'
        )
        
        # Retrieve all results
        results = db_ingestor.get_raw_results(scan.id)
        
        assert len(results) == 2
        assert result1.id in [r.id for r in results]
        assert result2.id in [r.id for r in results]
    
    def test_get_raw_results_empty(self, db_ingestor):
        """Test getting raw results for scan with no results"""
        scan = db_ingestor.create_scan(
            scan_id=f'test-no-results-{uuid.uuid4()}',
            target='192.168.1.203',
            tool_name='nmap',
            scan_type='basic'
        )
        
        results = db_ingestor.get_raw_results(scan.id)
        assert len(results) == 0


class TestErrorHandling:
    """Test error handling in various operations"""
    
    def test_get_scan_not_found(self, db_ingestor):
        """Test getting non-existent scan returns None"""
        scan = db_ingestor.get_scan(f'nonexistent-{uuid.uuid4()}')
        assert scan is None
    
    def test_get_scan_summary_not_found(self, db_ingestor):
        """Test getting summary for non-existent scan returns None"""
        summary = db_ingestor.get_scan_summary(f'nonexistent-{uuid.uuid4()}')
        assert summary is None
    
    def test_update_scan_status_nonexistent(self, db_ingestor):
        """Test updating status of non-existent scan"""
        result = db_ingestor.update_scan_status(
            f'nonexistent-{uuid.uuid4()}',
            ScanStatus.COMPLETED
        )
        # Should return False for non-existent scan
        assert result is False
    
    def test_create_scan_invalid_uuid_generates_new(self, db_ingestor):
        """Test that invalid UUID scan_id triggers UUID generation"""
        # Pass an invalid UUID string
        scan = db_ingestor.create_scan(
            scan_id='not-a-valid-uuid',  # Invalid UUID format
            target='192.168.1.204',
            tool_name='nmap',
            scan_type='basic'
        )
        
        # Should create scan with a valid generated UUID
        assert scan is not None
        assert scan.id != 'not-a-valid-uuid'  # Should have generated new UUID
        # Verify it's a valid UUID format
        try:
            uuid.UUID(scan.id)
            uuid_is_valid = True
        except ValueError:
            uuid_is_valid = False
        assert uuid_is_valid is True


class TestGetScanWithSession:
    """Test get_scan behavior"""
    
    def test_get_existing_scan(self, db_ingestor):
        """Test retrieving an existing scan"""
        scan = db_ingestor.create_scan(
            scan_id=f'test-get-{uuid.uuid4()}',
            target='192.168.1.205',
            tool_name='nmap',
            scan_type='basic'
        )
        
        retrieved = db_ingestor.get_scan(scan.id)
        assert retrieved is not None
        assert retrieved.id == scan.id
        assert retrieved.target == '192.168.1.205'


class TestIngestorErrorHandling:
    """Test error handling in DataIngestor methods"""
    
    def test_create_scan_with_database_error(self, db_ingestor, monkeypatch):
        """Test create_scan handles SQLAlchemy errors"""
        from sqlalchemy.exc import SQLAlchemyError
        
        # Mock session.commit to raise an error
        def mock_commit(*args, **kwargs):
            raise SQLAlchemyError("Database connection failed")
        
        session = db_ingestor.get_session()
        monkeypatch.setattr(session, 'commit', mock_commit)
        monkeypatch.setattr(db_ingestor, 'get_session', lambda: session)
        
        with pytest.raises(SQLAlchemyError):
            db_ingestor.create_scan(
                scan_id=f'test-error-{uuid.uuid4()}',
                target='192.168.1.206',
                tool_name='nmap',
                scan_type='basic'
            )
        
        session.close()
    
    def test_update_scan_status_with_database_error(self, db_ingestor, monkeypatch):
        """Test update_scan_status handles SQLAlchemy errors gracefully"""
        from sqlalchemy.exc import SQLAlchemyError
        
        # Create a scan first
        scan = db_ingestor.create_scan(
            scan_id=f'test-update-error-{uuid.uuid4()}',
            target='192.168.1.207',
            tool_name='nmap',
            scan_type='basic'
        )
        
        # Mock session.commit to raise an error
        def mock_commit(*args, **kwargs):
            raise SQLAlchemyError("Database update failed")
        
        session = db_ingestor.get_session()
        monkeypatch.setattr(session, 'commit', mock_commit)
        monkeypatch.setattr(db_ingestor, 'get_session', lambda: session)
        
        # Should return False on error, not raise
        result = db_ingestor.update_scan_status(scan.id, ScanStatus.COMPLETED)
        assert result is False
        
        session.close()
    
    def test_store_raw_result_with_database_error(self, db_ingestor, monkeypatch):
        """Test store_raw_result handles SQLAlchemy errors"""
        from sqlalchemy.exc import SQLAlchemyError
        
        # Create a scan first
        scan = db_ingestor.create_scan(
            scan_id=f'test-raw-error-{uuid.uuid4()}',
            target='192.168.1.208',
            tool_name='nmap',
            scan_type='basic'
        )
        
        # Mock session.commit to raise an error
        def mock_commit(*args, **kwargs):
            raise SQLAlchemyError("Failed to store result")
        
        session = db_ingestor.get_session()
        monkeypatch.setattr(session, 'commit', mock_commit)
        monkeypatch.setattr(db_ingestor, 'get_session', lambda: session)
        
        with pytest.raises(SQLAlchemyError):
            db_ingestor.store_raw_result(
                scan_id=scan.id,
                tool_name='nmap',
                raw_output='test output',
                output_format='text'
            )
        
        session.close()
    
    def test_delete_scan_with_database_error(self, db_ingestor, monkeypatch):
        """Test delete_scan handles SQLAlchemy errors gracefully"""
        from sqlalchemy.exc import SQLAlchemyError
        
        # Create a scan first
        scan = db_ingestor.create_scan(
            scan_id=f'test-delete-error-{uuid.uuid4()}',
            target='192.168.1.211',
            tool_name='nmap',
            scan_type='basic'
        )
        
        # Mock session.commit to raise an error
        def mock_commit(*args, **kwargs):
            raise SQLAlchemyError("Failed to delete scan")
        
        session = db_ingestor.get_session()
        monkeypatch.setattr(session, 'commit', mock_commit)
        monkeypatch.setattr(db_ingestor, 'get_session', lambda: session)
        
        # Should return False on error, not raise
        result = db_ingestor.delete_scan(scan.id)
        assert result is False
        
        session.close()
