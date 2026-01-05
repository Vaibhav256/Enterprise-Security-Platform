"""
Tests for Database Models

Tests SQLAlchemy models and enumerations.
"""

import pytest
from datetime import datetime


class TestScanStatusEnum:
    """Test ScanStatus enumeration"""
    
    def test_scan_status_values(self):
        """Test ScanStatus enum values"""
        from services.data_ingestor.models import ScanStatus
        
        assert ScanStatus.PENDING.value == 'pending'
        assert ScanStatus.QUEUED.value == 'queued'
        assert ScanStatus.RUNNING.value == 'running'
        assert ScanStatus.COMPLETED.value == 'completed'
        assert ScanStatus.FAILED.value == 'failed'
        assert ScanStatus.CANCELLED.value == 'cancelled'


class TestScanModel:
    """Test Scan model"""
    
    def test_scan_model_exists(self):
        """Test Scan model can be imported"""
        from services.data_ingestor.models import Scan
        
        assert Scan is not None
        assert Scan.__tablename__ == 'scans'
        
    def test_scan_model_columns(self):
        """Test Scan model has required columns"""
        from services.data_ingestor.models import Scan
        
        # Check column names
        columns = [c.name for c in Scan.__table__.columns]
        
        assert 'id' in columns
        assert 'target' in columns
        assert 'tool_name' in columns
        assert 'scan_type' in columns
        assert 'status' in columns
        assert 'priority' in columns
        assert 'created_at' in columns
        
    def test_scan_repr(self):
        """Test Scan model __repr__"""
        from services.data_ingestor.models import Scan, ScanStatus
        
        scan = Scan(
            id='test-123',
            target='192.168.1.1',
            tool_name='nmap',
            scan_type='basic',
            status=ScanStatus.PENDING
        )
        
        repr_str = repr(scan)
        assert 'test-123' in repr_str
        assert '192.168.1.1' in repr_str
        assert 'nmap' in repr_str


class TestRawScanResultModel:
    """Test RawScanResult model"""
    
    def test_raw_scan_result_model_exists(self):
        """Test RawScanResult model exists"""
        from services.data_ingestor.models import RawScanResult
        
        assert RawScanResult is not None
        assert RawScanResult.__tablename__ == 'raw_scan_results'
        
    def test_raw_scan_result_columns(self):
        """Test RawScanResult has required columns"""
        from services.data_ingestor.models import RawScanResult
        
        columns = [c.name for c in RawScanResult.__table__.columns]
        
        assert 'id' in columns
        assert 'scan_id' in columns
        assert 'tool_name' in columns
        assert 'raw_output' in columns
        assert 'output_format' in columns
        assert 'created_at' in columns
    
    def test_raw_scan_result_repr(self):
        """Test RawScanResult model __repr__"""
        from services.data_ingestor.models import RawScanResult
        
        result = RawScanResult(
            id=1,
            scan_id='scan-123',
            tool_name='nmap',
            raw_output='output data'
        )
        
        repr_str = repr(result)
        assert 'RawScanResult' in repr_str
        assert 'scan-123' in repr_str


class TestScanSummaryModel:
    """Test ScanSummary model"""
    
    def test_scan_summary_model_exists(self):
        """Test ScanSummary model exists"""
        from services.data_ingestor.models import ScanSummary
        
        assert ScanSummary is not None
        assert ScanSummary.__tablename__ == 'scan_summaries'
        
    def test_scan_summary_columns(self):
        """Test ScanSummary has required columns"""
        from services.data_ingestor.models import ScanSummary
        
        columns = [c.name for c in ScanSummary.__table__.columns]
        
        assert 'id' in columns
        assert 'scan_id' in columns
        assert 'total_hosts' in columns
        assert 'total_ports' in columns
        assert 'total_vulnerabilities' in columns
        assert 'critical_count' in columns
        assert 'high_count' in columns
        assert 'medium_count' in columns
        assert 'low_count' in columns
        assert 'info_count' in columns
    
    def test_scan_summary_repr(self):
        """Test ScanSummary model __repr__"""
        from services.data_ingestor.models import ScanSummary
        
        summary = ScanSummary(
            id=1,
            scan_id='scan-123',
            total_hosts=5,
            total_vulnerabilities=10
        )
        
        repr_str = repr(summary)
        assert 'ScanSummary' in repr_str
        assert 'scan-123' in repr_str


class TestModelUtilityFunctions:
    """Test utility functions"""
    
    def test_create_tables_function_exists(self):
        """Test create_tables function exists"""
        from services.data_ingestor.models import create_tables
        
        assert create_tables is not None
        assert callable(create_tables)
        
    def test_drop_tables_function_exists(self):
        """Test drop_tables function exists"""
        from services.data_ingestor.models import drop_tables
        
        assert drop_tables is not None
        assert callable(drop_tables)
        
    def test_base_exists(self):
        """Test Base declarative base exists"""
        from services.data_ingestor.models import Base
        
        assert Base is not None
        assert hasattr(Base, 'metadata')
