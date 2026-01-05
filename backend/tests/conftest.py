"""
Pytest configuration and fixtures for tests
"""
import os
import sys
import pytest

# Add backend directory to path for imports
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Import after path setup
from services.data_ingestor.models import ScanStatus, Scan, RawScanResult
from services.data_ingestor.ingestor import DataIngestor


@pytest.fixture
def db_ingestor():
    """Create a real database ingestor for test data setup"""
    from config.config import get_config
    config = get_config()
    ingestor = DataIngestor(database_url=config.DATABASE_URL)
    return ingestor


@pytest.fixture
def test_scans(db_ingestor):
    """Create test scans in the database - unique per test invocation"""
    import uuid
    scan_ids = {}
    
    # Create first test scan with unique UUID
    test_uuid_1 = f'scan-123-{uuid.uuid4()}'
    scan_obj_1 = db_ingestor.create_scan(
        scan_id=test_uuid_1,
        target='192.168.1.1',
        tool_name='nmap',
        scan_type='basic',
        priority='high'
    )
    scan_id_1 = scan_obj_1.id
    scan_ids[test_uuid_1] = scan_id_1
    
    # Update status to completed
    db_ingestor.update_scan_status(scan_id_1, ScanStatus.COMPLETED)
    
    # Add raw results for first scan
    session = db_ingestor.get_session()
    try:
        raw_result = RawScanResult(
            scan_id=scan_id_1,
            tool_name='nmap',
            raw_output='Test scan output',
            output_format='text'
        )
        session.add(raw_result)
        session.commit()
    finally:
        session.close()
    
    # Create second test scan with unique UUID
    test_uuid_2 = f'scan-456-{uuid.uuid4()}'
    scan_obj_2 = db_ingestor.create_scan(
        scan_id=test_uuid_2,
        target='192.168.1.2',
        tool_name='openvas',
        scan_type='full',
        priority='normal'
    )
    scan_id_2 = scan_obj_2.id
    scan_ids[test_uuid_2] = scan_id_2
    
    yield scan_ids
