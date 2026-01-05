"""
Database integration tests verifying data integrity and relationships.

Similar to TestNG's @Test(groups = {"integration", "database"})
"""
import pytest
from datetime import datetime, timedelta


@pytest.mark.integration
@pytest.mark.database
class TestDatabaseRelationships:
    """Integration tests for database relationships and cascades."""
    
    def test_scan_to_results_relationship(self, integration_ingestor):
        """Test one-to-many relationship between scans and results."""
        # Create scan
        scan_id = integration_ingestor.create_scan(
            target="192.168.1.100",
            tool_name="nmap",
            scan_type="quick",
            priority="normal"
        )
        
        # Add multiple raw results
        for i in range(3):
            integration_ingestor.save_raw_result(
                scan_id=scan_id,
                tool_name="nmap",
                raw_output=f"output_{i}",
                output_format="text"
            )
        
        # Verify relationship
        scan = integration_ingestor.get_scan(scan_id)
        assert scan is not None
        
        # Get results
        from services.data_ingestor.models import RawScanResult
        session = integration_ingestor.session
        results = session.query(RawScanResult).filter_by(scan_id=scan_id).all()
        assert len(results) == 3
        
        # Verify all results belong to same scan
        for result in results:
            assert result.scan_id == scan_id
    
    def test_cascade_delete_scan_and_results(self, integration_ingestor):
        """Test that deleting scan cascades to all related data."""
        # Create scan with results and summary
        scan_id = integration_ingestor.create_scan(
            target="cascade-test.com",
            tool_name="nmap",
            scan_type="quick",
            priority="normal"
        )
        
        # Add raw result
        integration_ingestor.save_raw_result(
            scan_id=scan_id,
            tool_name="nmap",
            raw_output="test output",
            output_format="text"
        )
        
        # Add parsed result
        integration_ingestor.save_parsed_result(
            scan_id=scan_id,
            tool_name="nmap",
            parsed_data={"hosts": []}
        )
        
        # Add summary
        from services.data_ingestor.models import ScanSummary
        session = integration_ingestor.session
        summary = ScanSummary(
            scan_id=scan_id,
            total_hosts=1,
            total_ports=10
        )
        session.add(summary)
        session.commit()
        
        # Count related records before delete
        from services.data_ingestor.models import RawScanResult, ParsedScanResult
        raw_count_before = session.query(RawScanResult).filter_by(scan_id=scan_id).count()
        parsed_count_before = session.query(ParsedScanResult).filter_by(scan_id=scan_id).count()
        summary_count_before = session.query(ScanSummary).filter_by(scan_id=scan_id).count()
        
        assert raw_count_before > 0
        assert parsed_count_before > 0
        assert summary_count_before > 0
        
        # Delete scan
        integration_ingestor.delete_scan(scan_id)
        
        # Verify cascaded deletes
        raw_count_after = session.query(RawScanResult).filter_by(scan_id=scan_id).count()
        parsed_count_after = session.query(ParsedScanResult).filter_by(scan_id=scan_id).count()
        summary_count_after = session.query(ScanSummary).filter_by(scan_id=scan_id).count()
        
        assert raw_count_after == 0
        assert parsed_count_after == 0
        assert summary_count_after == 0


@pytest.mark.integration
@pytest.mark.database
class TestDatabaseTransactions:
    """Integration tests for database transaction handling."""
    
    def test_transaction_rollback_on_error(self, integration_ingestor):
        """Test that database transactions rollback on errors."""
        from services.data_ingestor.models import Scan
        session = integration_ingestor.session
        
        # Start transaction
        try:
            # Create valid scan
            scan = Scan(
                scan_id="test-rollback",
                target="rollback-test.com",
                tool_name="nmap",
                scan_type="quick",
                priority="normal",
                status="pending"
            )
            session.add(scan)
            session.flush()
            
            # Try to create duplicate (should fail)
            duplicate = Scan(
                scan_id="test-rollback",  # Same ID
                target="duplicate.com",
                tool_name="nikto",
                scan_type="quick",
                priority="normal",
                status="pending"
            )
            session.add(duplicate)
            session.commit()
            
        except Exception:
            session.rollback()
        
        # Verify original scan was not committed
        scan = session.query(Scan).filter_by(scan_id="test-rollback").first()
        assert scan is None
    
    def test_transaction_isolation(self, integration_ingestor):
        """Test transaction isolation between operations."""
        # Create scan
        scan_id = integration_ingestor.create_scan(
            target="isolation-test.com",
            tool_name="nmap",
            scan_type="quick",
            priority="normal"
        )
        
        # Get initial status
        scan1 = integration_ingestor.get_scan(scan_id)
        initial_status = scan1.status
        
        # Update status
        integration_ingestor.update_scan_status(scan_id, "running")
        
        # Refresh and verify
        scan2 = integration_ingestor.get_scan(scan_id)
        assert scan2.status == "running"
        assert scan2.status != initial_status


@pytest.mark.integration
@pytest.mark.database
class TestDatabaseQueries:
    """Integration tests for complex database queries."""
    
    def test_filter_scans_by_multiple_criteria(self, integration_ingestor):
        """Test filtering scans by multiple fields."""
        # Create diverse set of scans
        integration_ingestor.create_scan("192.168.1.1", "nmap", "quick", "high")
        integration_ingestor.create_scan("192.168.1.2", "nmap", "comprehensive", "normal")
        integration_ingestor.create_scan("192.168.1.3", "nikto", "quick", "high")
        integration_ingestor.create_scan("192.168.1.4", "nuclei", "quick", "low")
        
        # Query by tool
        scans = integration_ingestor.list_scans(filters={"tool_name": "nmap"})
        assert len([s for s in scans if s.tool_name == "nmap"]) >= 2
        
        # Query by priority
        scans = integration_ingestor.list_scans(filters={"priority": "high"})
        assert len([s for s in scans if s.priority == "high"]) >= 2
        
        # Query by tool and priority
        from services.data_ingestor.models import Scan
        session = integration_ingestor.session
        scans = session.query(Scan).filter(
            Scan.tool_name == "nmap",
            Scan.priority == "high"
        ).all()
        assert len(scans) >= 1
    
    def test_query_scans_by_date_range(self, integration_ingestor):
        """Test querying scans within a date range."""
        # Create scans
        scan_id_1 = integration_ingestor.create_scan("10.0.0.1", "nmap", "quick", "normal")
        
        # Get scan with timestamp
        from services.data_ingestor.models import Scan
        session = integration_ingestor.session
        scan = session.query(Scan).filter_by(scan_id=scan_id_1).first()
        created_at = scan.created_at
        
        # Query scans created in last hour
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        recent_scans = session.query(Scan).filter(
            Scan.created_at >= one_hour_ago
        ).all()
        
        assert len(recent_scans) >= 1
        assert any(s.scan_id == scan_id_1 for s in recent_scans)
    
    def test_aggregate_queries(self, integration_ingestor):
        """Test database aggregation queries."""
        from services.data_ingestor.models import Scan
        from sqlalchemy import func
        session = integration_ingestor.session
        
        # Create scans with different statuses
        for status in ['pending', 'running', 'completed', 'failed']:
            for i in range(2):
                scan_id = integration_ingestor.create_scan(
                    f"{status}-{i}.com", 
                    "nmap", 
                    "quick", 
                    "normal"
                )
                integration_ingestor.update_scan_status(scan_id, status)
        
        # Count by status
        status_counts = session.query(
            Scan.status,
            func.count(Scan.scan_id)
        ).group_by(Scan.status).all()
        
        status_dict = dict(status_counts)
        assert status_dict.get('pending', 0) >= 2
        assert status_dict.get('running', 0) >= 2
        assert status_dict.get('completed', 0) >= 2
        assert status_dict.get('failed', 0) >= 2


@pytest.mark.integration
@pytest.mark.database
class TestDatabaseConstraints:
    """Integration tests for database constraints and validation."""
    
    def test_unique_scan_id_constraint(self, integration_ingestor):
        """Test that scan_id uniqueness is enforced."""
        from services.data_ingestor.models import Scan
        session = integration_ingestor.session
        
        # Create first scan
        scan1 = Scan(
            scan_id="duplicate-test",
            target="test1.com",
            tool_name="nmap",
            scan_type="quick",
            priority="normal",
            status="pending"
        )
        session.add(scan1)
        session.commit()
        
        # Try to create duplicate
        scan2 = Scan(
            scan_id="duplicate-test",  # Same ID
            target="test2.com",
            tool_name="nikto",
            scan_type="quick",
            priority="normal",
            status="pending"
        )
        session.add(scan2)
        
        with pytest.raises(Exception):  # Should raise integrity error
            session.commit()
        
        session.rollback()
    
    def test_foreign_key_constraint(self, integration_ingestor):
        """Test foreign key constraints are enforced."""
        from services.data_ingestor.models import RawScanResult
        session = integration_ingestor.session
        
        # Try to create result for non-existent scan
        result = RawScanResult(
            scan_id="non-existent-scan",
            tool_name="nmap",
            raw_output="test",
            output_format="text"
        )
        session.add(result)
        
        with pytest.raises(Exception):  # Should raise foreign key error
            session.commit()
        
        session.rollback()


@pytest.mark.integration
@pytest.mark.database
@pytest.mark.slow
class TestDatabasePerformance:
    """Integration tests for database performance with large datasets."""
    
    def test_bulk_insert_performance(self, integration_ingestor):
        """Test performance of bulk inserts."""
        import time
        
        start_time = time.time()
        
        # Bulk insert 100 scans
        scan_ids = []
        for i in range(100):
            scan_id = integration_ingestor.create_scan(
                f"bulk-{i}.example.com",
                "nmap",
                "quick",
                "normal"
            )
            scan_ids.append(scan_id)
        
        elapsed = time.time() - start_time
        
        # Should complete in reasonable time (< 5 seconds for 100 inserts)
        assert elapsed < 5.0
        assert len(scan_ids) == 100
    
    def test_query_performance_with_large_dataset(self, integration_ingestor):
        """Test query performance with many records."""
        import time
        
        # Create 200 scans if not already created
        for i in range(200):
            integration_ingestor.create_scan(
                f"perf-{i}.example.com",
                "nmap",
                "quick",
                "normal"
            )
        
        # Test query performance
        start_time = time.time()
        scans = integration_ingestor.list_scans(limit=50)
        elapsed = time.time() - start_time
        
        # Query should be fast (< 1 second)
        assert elapsed < 1.0
        assert len(scans) <= 50
