"""
End-to-end integration tests simulating complete scan workflows.

Similar to TestNG's @Test(groups = {"e2e", "integration"})
"""
import pytest
import json
from unittest.mock import patch, MagicMock


@pytest.mark.integration
@pytest.mark.e2e
class TestNmapScanWorkflow:
    """End-to-end tests for complete Nmap scan workflows."""
    
    @patch('services.adapters.nmap_adapter.subprocess.run')
    def test_complete_nmap_scan_workflow(
        self, 
        mock_subprocess,
        integration_client, 
        integration_ingestor,
        sample_nmap_output
    ):
        """Test complete workflow: create -> execute -> parse -> store -> retrieve."""
        # Mock nmap execution
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = sample_nmap_output
        mock_result.stderr = ""
        mock_subprocess.return_value = mock_result
        
        # Step 1: Create scan via API
        response = integration_client.post('/api/scans/',
            json={
                "target": "192.168.1.1",
                "tool_name": "nmap",
                "scan_type": "quick",
                "priority": "normal",
                "options": {"ports": "1-1000"}
            },
            content_type='application/json'
        )
        assert response.status_code == 201
        data = json.loads(response.data)
        scan_id = data['scan_id']
        
        # Step 2: Simulate scan execution
        from services.adapters.nmap_adapter import NmapAdapter
        adapter = NmapAdapter()
        
        # Update scan to running
        integration_ingestor.update_scan_status(scan_id, "running")
        
        # Execute scan (mocked)
        result = adapter.execute_scan(
            target="192.168.1.1",
            scan_type="quick",
            options={"ports": "1-1000"}
        )
        
        assert result['status'] == 'success'
        assert 'raw_output' in result
        
        # Step 3: Store raw results
        integration_ingestor.save_raw_result(
            scan_id=scan_id,
            tool_name="nmap",
            raw_output=result['raw_output'],
            output_format="text"
        )
        
        # Step 4: Parse results
        parsed = adapter.parse_results(result['raw_output'])
        assert 'hosts' in parsed
        
        # Step 5: Store parsed results
        integration_ingestor.save_parsed_result(
            scan_id=scan_id,
            tool_name="nmap",
            parsed_data=parsed
        )
        
        # Step 6: Update scan to completed
        integration_ingestor.update_scan_status(scan_id, "completed")
        
        # Step 7: Verify via API
        response = integration_client.get(f'/api/scans/{scan_id}')
        assert response.status_code == 200
        scan_data = json.loads(response.data)
        assert scan_data['status'] == 'completed'
        
        # Step 8: Retrieve results via API
        response = integration_client.get(f'/api/scans/{scan_id}/results/raw')
        assert response.status_code == 200
        
        response = integration_client.get(f'/api/scans/{scan_id}/results/parsed')
        assert response.status_code == 200
        parsed_results = json.loads(response.data)
        assert len(parsed_results['results']) > 0


@pytest.mark.integration
@pytest.mark.e2e
class TestMultiToolWorkflow:
    """End-to-end tests for workflows involving multiple scanning tools."""
    
    def test_sequential_scans_different_tools(
        self, 
        integration_client, 
        integration_ingestor
    ):
        """Test running multiple scans with different tools sequentially."""
        tools = ['nmap', 'nikto', 'nuclei']
        scan_ids = []
        
        # Create scans for each tool
        for tool in tools:
            response = integration_client.post('/api/scans/',
                json={
                    "target": "example.com",
                    "tool_name": tool,
                    "scan_type": "quick",
                    "priority": "normal"
                },
                content_type='application/json'
            )
            assert response.status_code == 201
            data = json.loads(response.data)
            scan_ids.append(data['scan_id'])
        
        # Simulate completion of all scans
        for scan_id, tool in zip(scan_ids, tools):
            integration_ingestor.update_scan_status(scan_id, "running")
            integration_ingestor.save_raw_result(
                scan_id=scan_id,
                tool_name=tool,
                raw_output=f"{tool} scan output for example.com",
                output_format="text"
            )
            integration_ingestor.update_scan_status(scan_id, "completed")
        
        # Verify all scans completed
        for scan_id in scan_ids:
            response = integration_client.get(f'/api/scans/{scan_id}')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['status'] == 'completed'
        
        # List all scans for target
        response = integration_client.get('/api/scans/?target=example.com')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data['scans']) >= 3


@pytest.mark.integration
@pytest.mark.e2e
class TestErrorHandlingWorkflow:
    """End-to-end tests for error scenarios and recovery."""
    
    @patch('services.adapters.nmap_adapter.subprocess.run')
    def test_scan_failure_workflow(
        self, 
        mock_subprocess,
        integration_client, 
        integration_ingestor
    ):
        """Test workflow when scan execution fails."""
        # Mock failed execution
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Error: target not found"
        mock_subprocess.return_value = mock_result
        
        # Create scan
        response = integration_client.post('/api/scans/',
            json={
                "target": "invalid-target",
                "tool_name": "nmap",
                "scan_type": "quick",
                "priority": "normal"
            },
            content_type='application/json'
        )
        scan_id = json.loads(response.data)['scan_id']
        
        # Simulate scan execution failure
        from services.adapters.nmap_adapter import NmapAdapter
        adapter = NmapAdapter()
        
        integration_ingestor.update_scan_status(scan_id, "running")
        
        result = adapter.execute_scan(
            target="invalid-target",
            scan_type="quick",
            options={}
        )
        
        # Verify failure handling
        assert result['status'] == 'error'
        
        # Update scan status to failed
        integration_ingestor.update_scan_status(
            scan_id, 
            "failed",
            error_message=result.get('error', 'Unknown error')
        )
        
        # Verify via API
        response = integration_client.get(f'/api/scans/{scan_id}')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'failed'
        assert 'error_message' in data
    
    def test_retry_failed_scan(self, integration_client, integration_ingestor):
        """Test retrying a failed scan."""
        # Create and fail a scan
        response = integration_client.post('/api/scans/',
            json={
                "target": "192.168.1.50",
                "tool_name": "nmap",
                "scan_type": "quick",
                "priority": "normal"
            },
            content_type='application/json'
        )
        original_scan_id = json.loads(response.data)['scan_id']
        
        # Mark as failed
        integration_ingestor.update_scan_status(
            original_scan_id, 
            "failed",
            error_message="Timeout"
        )
        
        # Get original scan details
        original_scan = integration_ingestor.get_scan(original_scan_id)
        
        # Create retry scan with same parameters
        response = integration_client.post('/api/scans/',
            json={
                "target": original_scan.target,
                "tool_name": original_scan.tool_name,
                "scan_type": original_scan.scan_type,
                "priority": original_scan.priority
            },
            content_type='application/json'
        )
        assert response.status_code == 201
        retry_scan_id = json.loads(response.data)['scan_id']
        
        # Verify retry scan is different
        assert retry_scan_id != original_scan_id
        
        # Verify retry scan has same parameters
        retry_scan = integration_ingestor.get_scan(retry_scan_id)
        assert retry_scan.target == original_scan.target
        assert retry_scan.tool_name == original_scan.tool_name


@pytest.mark.integration
@pytest.mark.e2e
@pytest.mark.database
class TestDataPersistenceWorkflow:
    """End-to-end tests for data persistence and consistency."""
    
    def test_scan_data_persistence_across_sessions(
        self, 
        integration_client, 
        integration_ingestor
    ):
        """Test that scan data persists correctly in database."""
        # Create scan
        response = integration_client.post('/api/scans/',
            json={
                "target": "persistence-test.com",
                "tool_name": "nmap",
                "scan_type": "comprehensive",
                "priority": "high",
                "options": {"ports": "1-65535"},
                "tags": ["test", "persistence"]
            },
            content_type='application/json'
        )
        scan_id = json.loads(response.data)['scan_id']
        
        # Add comprehensive data
        integration_ingestor.update_scan_status(scan_id, "running")
        integration_ingestor.save_raw_result(
            scan_id=scan_id,
            tool_name="nmap",
            raw_output="detailed scan output...",
            output_format="text"
        )
        integration_ingestor.save_parsed_result(
            scan_id=scan_id,
            tool_name="nmap",
            parsed_data={"hosts": [{"ip": "persistence-test.com"}]}
        )
        integration_ingestor.update_scan_status(scan_id, "completed")
        
        # Clear session to simulate new session
        integration_ingestor.session.expire_all()
        
        # Retrieve all data in "new session"
        scan = integration_ingestor.get_scan(scan_id)
        assert scan is not None
        assert scan.target == "persistence-test.com"
        assert scan.status == "completed"
        assert scan.tool_name == "nmap"
        assert scan.options == {"ports": "1-65535"}
        assert "test" in scan.tags
        
        # Verify results persisted
        response = integration_client.get(f'/api/scans/{scan_id}/results/raw')
        assert response.status_code == 200
        
        response = integration_client.get(f'/api/scans/{scan_id}/results/parsed')
        assert response.status_code == 200


@pytest.mark.integration
@pytest.mark.e2e
class TestConcurrentScansWorkflow:
    """End-to-end tests for concurrent scan execution."""
    
    def test_multiple_concurrent_scans(
        self, 
        integration_client, 
        integration_ingestor
    ):
        """Test system handles multiple concurrent scans correctly."""
        # Create 10 scans simultaneously
        scan_ids = []
        for i in range(10):
            response = integration_client.post('/api/scans/',
                json={
                    "target": f"concurrent-{i}.example.com",
                    "tool_name": "nmap",
                    "scan_type": "quick",
                    "priority": "normal" if i % 2 == 0 else "high"
                },
                content_type='application/json'
            )
            assert response.status_code == 201
            scan_ids.append(json.loads(response.data)['scan_id'])
        
        # Verify all scans created
        assert len(scan_ids) == 10
        assert len(set(scan_ids)) == 10  # All unique
        
        # Simulate concurrent execution
        for i, scan_id in enumerate(scan_ids):
            integration_ingestor.update_scan_status(scan_id, "running")
            integration_ingestor.save_raw_result(
                scan_id=scan_id,
                tool_name="nmap",
                raw_output=f"scan output {i}",
                output_format="text"
            )
            integration_ingestor.update_scan_status(scan_id, "completed")
        
        # Verify all completed
        for scan_id in scan_ids:
            scan = integration_ingestor.get_scan(scan_id)
            assert scan.status == "completed"
        
        # Verify listing shows all
        response = integration_client.get('/api/scans/?per_page=20')
        data = json.loads(response.data)
        assert data['total'] >= 10
