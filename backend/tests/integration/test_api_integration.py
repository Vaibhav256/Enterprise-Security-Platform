"""
Integration tests for API endpoints with database and business logic.

Similar to TestNG's integration test suite with @Test(groups = {"integration", "api"})
"""
import pytest
import json
from datetime import datetime


@pytest.mark.integration
@pytest.mark.api
class TestScanAPIIntegration:
    """Integration tests for scan creation and retrieval workflows."""
    
    def test_create_and_retrieve_scan(self, integration_client, integration_ingestor):
        """Test complete workflow: create scan -> retrieve scan -> verify data."""
        # Create scan via API
        response = integration_client.post('/api/scans/', 
            json={
                "target": "192.168.1.100",
                "tool_name": "nmap",
                "scan_type": "comprehensive",
                "priority": "high"
            },
            content_type='application/json'
        )
        
        assert response.status_code == 201
        data = json.loads(response.data)
        scan_id = data['scan_id']
        
        # Verify scan exists in database
        scan = integration_ingestor.get_scan(scan_id)
        assert scan is not None
        assert scan.target == "192.168.1.100"
        assert scan.tool_name == "nmap"
        assert scan.priority == "high"
        
        # Retrieve via API
        response = integration_client.get(f'/api/scans/{scan_id}')
        assert response.status_code == 200
        retrieved = json.loads(response.data)
        assert retrieved['scan_id'] == scan_id
        assert retrieved['target'] == "192.168.1.100"
    
    def test_create_multiple_scans_and_list(self, integration_client, integration_ingestor):
        """Test creating multiple scans and listing them with filters."""
        # Create 5 scans
        scan_ids = []
        for i in range(5):
            response = integration_client.post('/api/scans/',
                json={
                    "target": f"192.168.1.{i+1}",
                    "tool_name": "nmap" if i % 2 == 0 else "nikto",
                    "scan_type": "quick",
                    "priority": "normal"
                },
                content_type='application/json'
            )
            assert response.status_code == 201
            data = json.loads(response.data)
            scan_ids.append(data['scan_id'])
        
        # List all scans
        response = integration_client.get('/api/scans/?per_page=100')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['total'] >= 5
        assert len(data['scans']) >= 5
        
        # Filter by tool
        response = integration_client.get('/api/scans/?tool_name=nmap')
        assert response.status_code == 200
        data = json.loads(response.data)
        for scan in data['scans']:
            assert scan['tool_name'] == 'nmap'
    
    def test_scan_status_updates(self, integration_client, integration_ingestor):
        """Test scan status progression through workflow."""
        # Create scan
        response = integration_client.post('/api/scans/',
            json={
                "target": "10.0.0.1",
                "tool_name": "nmap",
                "scan_type": "quick",
                "priority": "normal"
            },
            content_type='application/json'
        )
        scan_id = json.loads(response.data)['scan_id']
        
        # Initial status should be pending
        scan = integration_ingestor.get_scan(scan_id)
        assert scan.status == "pending"
        
        # Update to running
        integration_ingestor.update_scan_status(scan_id, "running")
        response = integration_client.get(f'/api/scans/{scan_id}/status')
        assert response.status_code == 200
        assert json.loads(response.data)['status'] == "running"
        
        # Update to completed
        integration_ingestor.update_scan_status(scan_id, "completed")
        response = integration_client.get(f'/api/scans/{scan_id}/status')
        assert response.status_code == 200
        assert json.loads(response.data)['status'] == "completed"


@pytest.mark.integration
@pytest.mark.api
@pytest.mark.database
class TestScanResultsIntegration:
    """Integration tests for scan results storage and retrieval."""
    
    def test_complete_scan_workflow_with_results(self, integration_client, integration_ingestor):
        """Test end-to-end: create scan -> add results -> retrieve results."""
        # Create scan
        response = integration_client.post('/api/scans/',
            json={
                "target": "192.168.1.50",
                "tool_name": "nmap",
                "scan_type": "quick",
                "priority": "normal"
            },
            content_type='application/json'
        )
        scan_id = json.loads(response.data)['scan_id']
        
        # Add raw results
        raw_output = "Nmap scan report for 192.168.1.50\nPORT STATE SERVICE\n22/tcp open ssh"
        integration_ingestor.save_raw_result(
            scan_id=scan_id,
            tool_name="nmap",
            raw_output=raw_output,
            output_format="text"
        )
        
        # Retrieve raw results via API
        response = integration_client.get(f'/api/scans/{scan_id}/results/raw')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data['results']) > 0
        assert data['results'][0]['tool_name'] == 'nmap'
        
        # Add parsed results
        parsed_data = {
            "hosts": [{
                "ip": "192.168.1.50",
                "ports": [{"port": 22, "service": "ssh", "state": "open"}]
            }]
        }
        integration_ingestor.save_parsed_result(
            scan_id=scan_id,
            tool_name="nmap",
            parsed_data=parsed_data
        )
        
        # Retrieve parsed results via API
        response = integration_client.get(f'/api/scans/{scan_id}/results/parsed')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data['results']) > 0
        assert 'hosts' in data['results'][0]['parsed_data']
    
    def test_scan_summary_generation(self, integration_client, integration_ingestor):
        """Test scan summary creation and retrieval."""
        # Create scan
        response = integration_client.post('/api/scans/',
            json={
                "target": "192.168.1.75",
                "tool_name": "nmap",
                "scan_type": "comprehensive",
                "priority": "high"
            },
            content_type='application/json'
        )
        scan_id = json.loads(response.data)['scan_id']
        
        # Create summary
        from services.data_ingestor.models import ScanSummary
        summary = ScanSummary(
            scan_id=scan_id,
            total_hosts=1,
            total_ports=10,
            total_vulnerabilities=5,
            critical_count=1,
            high_count=2,
            medium_count=2,
            low_count=0,
            info_count=0
        )
        session = integration_ingestor.session
        session.add(summary)
        session.commit()
        
        # Retrieve summary via API
        response = integration_client.get(f'/api/scans/{scan_id}/summary')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['total_hosts'] == 1
        assert data['total_vulnerabilities'] == 5
        assert data['critical_count'] == 1


@pytest.mark.integration
@pytest.mark.api
class TestScanDeletionIntegration:
    """Integration tests for scan deletion and cascade behavior."""
    
    def test_delete_scan_cascades_results(self, integration_client, integration_ingestor):
        """Test that deleting a scan removes all associated data."""
        # Create scan with results
        response = integration_client.post('/api/scans/',
            json={
                "target": "192.168.1.99",
                "tool_name": "nmap",
                "scan_type": "quick",
                "priority": "normal"
            },
            content_type='application/json'
        )
        scan_id = json.loads(response.data)['scan_id']
        
        # Add results
        integration_ingestor.save_raw_result(
            scan_id=scan_id,
            tool_name="nmap",
            raw_output="test output",
            output_format="text"
        )
        
        # Verify scan exists
        response = integration_client.get(f'/api/scans/{scan_id}')
        assert response.status_code == 200
        
        # Delete scan
        response = integration_client.delete(f'/api/scans/{scan_id}')
        assert response.status_code in [200, 204]
        
        # Verify scan is gone
        response = integration_client.get(f'/api/scans/{scan_id}')
        assert response.status_code == 404
        
        # Verify results are gone
        response = integration_client.get(f'/api/scans/{scan_id}/results/raw')
        assert response.status_code == 404


@pytest.mark.integration
@pytest.mark.api
class TestStatsAPIIntegration:
    """Integration tests for statistics endpoints."""
    
    def test_stats_with_multiple_scans(self, integration_client, integration_ingestor):
        """Test statistics calculation across multiple scans."""
        # Create scans with different statuses
        for i, status in enumerate(['pending', 'running', 'completed', 'failed']):
            response = integration_client.post('/api/scans/',
                json={
                    "target": f"10.0.0.{i+1}",
                    "tool_name": "nmap",
                    "scan_type": "quick",
                    "priority": "normal"
                },
                content_type='application/json'
            )
            scan_id = json.loads(response.data)['scan_id']
            integration_ingestor.update_scan_status(scan_id, status)
        
        # Get stats
        response = integration_client.get('/api/stats/')
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['total_scans'] >= 4
        assert 'status_breakdown' in data
        assert data['status_breakdown']['pending'] >= 1
        assert data['status_breakdown']['completed'] >= 1


@pytest.mark.integration
@pytest.mark.slow
class TestPaginationIntegration:
    """Integration tests for pagination across large datasets."""
    
    def test_pagination_with_large_dataset(self, integration_client, integration_ingestor):
        """Test pagination handles large number of scans correctly."""
        # Create 50 scans
        for i in range(50):
            integration_client.post('/api/scans/',
                json={
                    "target": f"10.0.{i//255}.{i%255}",
                    "tool_name": "nmap",
                    "scan_type": "quick",
                    "priority": "normal"
                },
                content_type='application/json'
            )
        
        # Test first page
        response = integration_client.get('/api/scans/?page=1&per_page=10')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data['scans']) == 10
        assert data['page'] == 1
        assert data['total'] >= 50
        
        # Test second page
        response = integration_client.get('/api/scans/?page=2&per_page=10')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data['scans']) == 10
        assert data['page'] == 2
        
        # Test last page
        last_page = (data['total'] + 9) // 10
        response = integration_client.get(f'/api/scans/?page={last_page}&per_page=10')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['page'] == last_page
