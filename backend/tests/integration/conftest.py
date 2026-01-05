"""
Pytest configuration for integration tests.

Provides fixtures and configuration similar to TestNG's setup/teardown and groups.
"""
import os
import pytest
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

# Import app components
import sys
backend_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(backend_dir))

from api_gateway.app import create_app
from services.data_ingestor.ingestor import DataIngestor
from services.scan_orchestrator.orchestrator import ScanOrchestrator


# Pytest markers (similar to TestNG groups)
def pytest_configure(config):
    """Register custom markers for test organization."""
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "api: marks tests for API endpoints integration"
    )
    config.addinivalue_line(
        "markers", "database: marks tests requiring database"
    )
    config.addinivalue_line(
        "markers", "queue: marks tests requiring task queue"
    )
    config.addinivalue_line(
        "markers", "e2e: marks end-to-end workflow tests"
    )
    config.addinivalue_line(
        "markers", "slow: marks slow-running tests"
    )


@pytest.fixture(scope="session")
def integration_app():
    """Create Flask app for integration testing (session scope)."""
    os.environ['TESTING'] = 'true'
    os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
    
    app = create_app(config_name='testing')
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with app.app_context():
        # Initialize database
        from services.data_ingestor.models import Base, engine
        Base.metadata.create_all(engine)
        
        yield app
        
        # Cleanup
        Base.metadata.drop_all(engine)


@pytest.fixture(scope="function")
def integration_client(integration_app):
    """Create test client for each test function."""
    return integration_app.test_client()


@pytest.fixture(scope="function")
def integration_db(integration_app):
    """Provide database session for integration tests."""
    with integration_app.app_context():
        from services.data_ingestor.models import get_session
        session = get_session()
        yield session
        session.rollback()
        session.close()


@pytest.fixture(scope="function")
def integration_ingestor(integration_app):
    """Provide DataIngestor instance for integration tests."""
    with integration_app.app_context():
        database_url = 'sqlite:///:memory:'
        ingestor = DataIngestor(database_url=database_url)
        yield ingestor


@pytest.fixture(scope="function")
def integration_orchestrator(integration_app):
    """Provide ScanOrchestrator instance for integration tests."""
    with integration_app.app_context():
        orchestrator = ScanOrchestrator()
        yield orchestrator


@pytest.fixture(scope="function")
def temp_output_dir():
    """Create temporary directory for test outputs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture(scope="function")
def mock_redis():
    """Mock Redis connection for queue tests."""
    mock = MagicMock()
    mock.ping.return_value = True
    mock.get.return_value = None
    mock.set.return_value = True
    return mock


@pytest.fixture(scope="function")
def sample_scan_data():
    """Provide sample scan data for tests."""
    return {
        "target": "192.168.1.1",
        "tool_name": "nmap",
        "scan_type": "quick",
        "priority": "normal",
        "options": {
            "ports": "1-1000",
            "scan_technique": "syn"
        }
    }


@pytest.fixture(scope="function")
def sample_nmap_output():
    """Provide sample nmap output for parsing tests."""
    return """
Starting Nmap 7.94 ( https://nmap.org ) at 2025-10-29 14:00 UTC
Nmap scan report for 192.168.1.1
Host is up (0.0010s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 2.50 seconds
"""


@pytest.fixture(scope="function")
def sample_parsed_results():
    """Provide sample parsed scan results."""
    return {
        "hosts": [
            {
                "ip": "192.168.1.1",
                "hostname": "example.com",
                "state": "up",
                "ports": [
                    {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
                    {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
                    {"port": 443, "protocol": "tcp", "state": "open", "service": "https"}
                ]
            }
        ],
        "scan_stats": {
            "total_hosts": 1,
            "hosts_up": 1,
            "ports_scanned": 1000
        }
    }
