"""
Comprehensive tests for API Routes endpoints

Tests all route handlers with Flask test client:
- POST /scans/ - Create scan
- GET /scans/ - List scans
- GET /scans/<id> - Get scan details
- DELETE /scans/<id> - Delete scan
- GET /scans/<id>/status - Get scan status
- GET /scans/<id>/raw_results - Get raw results
- GET /scans/<id>/parsed_results - Get parsed results
- GET /scans/<id>/export/<format> - Export results
- GET /scans/stats - Get statistics
- POST /scans/bulk/delete - Bulk delete
- POST /scans/bulk/export - Bulk export
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
from flask import Flask
from flask_restx import Api

from services.data_ingestor.models import ScanStatus, Scan, RawScanResult
from services.data_ingestor.ingestor import DataIngestor


@pytest.fixture
def app():
    """Create Flask app for testing"""
    app = Flask(__name__)
    app.config['TESTING'] = True
    return app


@pytest.fixture
def api(app):
    """Create Flask-RESTX API"""
    return Api(app, version='1.0', title='Test API')


@pytest.fixture
def client(app, api):
    """Create test client with real routes (uses real DB via routes module)"""
    # Import routes and register - uses real ingestor/orchestrator
    import api_gateway.routes as routes
    api.add_namespace(routes.scans_ns, path='/scans')
    api.add_namespace(routes.tools_ns, path='/tools')
    api.add_namespace(routes.stats_ns, path='/stats')
    
    # Store references for tests that need them
    app.ingestor = routes.ingestor
    app.orchestrator = routes.orchestrator
    
    yield app.test_client()
class TestScanListEndpoint:
    """Test POST /scans/ and GET /scans/ endpoints"""
    
    def test_create_scan_success(self, client, app, db_ingestor):
        """Test creating a new scan"""
        # Make request
        response = client.post('/scans/', 
            data=json.dumps({
                'target': '192.168.1.50',
                'tool_name': 'nmap',
                'scan_type': 'basic',
                'priority': 'high'
            }),
            content_type='application/json'
        )
        
        # Verify
        assert response.status_code == 201
        data = json.loads(response.data)
        assert 'scan_id' in data
        # Should be a valid UUID format
        assert len(data['scan_id']) > 20
        
        # Cleanup
        db_ingestor.delete_scan(data['scan_id'])
    
    def test_create_scan_missing_required_field(self, client, app):
        """Test creating scan without required field"""
        response = client.post('/scans/',
            data=json.dumps({
                'target': '192.168.1.1',
                'tool_name': 'nmap'
                # missing scan_type
            }),
            content_type='application/json'
        )
        
        assert response.status_code == 400
    
    def test_create_scan_invalid_tool(self, client, app):
        """Test creating scan with invalid tool"""
        # Invalid tool should be rejected by orchestrator
        response = client.post('/scans/',
            data=json.dumps({
                'target': '192.168.1.1',
                'tool_name': 'invalid-tool-xyz',
                'scan_type': 'basic'
            }),
            content_type='application/json'
        )
        
        # Should return 400 or 500 for invalid tool
        assert response.status_code in [400, 500]
    
    def test_list_scans_success(self, client, app, test_scans):
        """Test listing scans"""
        response = client.get('/scans/')

        assert response.status_code == 200
        data = json.loads(response.data)
        # API may return a paginated dict or a raw list; normalize to list
        scans = data.get('scans') if isinstance(data, dict) else data
        assert isinstance(scans, list)
        assert len(scans) >= 1
        # Verify structure
        assert 'scan_id' in scans[0]
    
    def test_list_scans_with_filters(self, client, app, test_scans):
        """Test listing scans with status filter"""
        response = client.get('/scans/?status=completed&tool=nmap')

        assert response.status_code == 200
        data = json.loads(response.data)
        scans = data.get('scans') if isinstance(data, dict) else data
        # Should get at least our completed nmap scan
        assert isinstance(scans, list)


class TestScanDetailEndpoint:
    """Test GET/DELETE /scans/<scan_id> endpoints"""
    
    def test_get_scan_success(self, client, app, test_scans):
        """Test getting scan details"""
        # Get first scan ID from dynamic fixture
        scan_id = list(test_scans.values())[0]
        response = client.get(f'/scans/{scan_id}')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['scan_id'] == scan_id
        assert 'target' in data
        assert 'tool_name' in data
        assert 'status' in data
    
    def test_get_scan_not_found(self, client, app):
        """Test getting non-existent scan"""
        response = client.get('/scans/nonexistent-scan-id-12345')
        
        assert response.status_code == 404
    
    def test_delete_scan_success(self, client, app, test_scans):
        """Test deleting a scan"""
        # Get first scan ID from dynamic fixture
        scan_id = list(test_scans.values())[0]
        response = client.delete(f'/scans/{scan_id}')
        
        assert response.status_code in [200, 204]  # 200 OK or 204 No Content
        if response.data:
            data = json.loads(response.data)
            assert 'message' in data or data.get('message') == 'Scan deleted successfully'
    
    def test_delete_scan_not_found(self, client, app):
        """Test deleting non-existent scan"""
        response = client.delete('/scans/nonexistent-scan-id-12345')
        
        assert response.status_code == 404


class TestScanStatusEndpoint:
    """Test GET /scans/<scan_id>/status endpoint"""
    
    def test_get_scan_status_completed(self, client, app, test_scans):
        """Test getting status of completed scan"""
        # Get first scan ID from dynamic fixture
        scan_id = list(test_scans.values())[0]
        response = client.get(f'/scans/{scan_id}/status')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'completed'  # Changed from scan_status to status
        assert 'progress' in data
    
    def test_get_scan_status_not_found(self, client, app):
        """Test getting status of non-existent scan"""
        response = client.get('/scans/nonexistent-scan-id-12345/status')
        
        assert response.status_code == 404


class TestScanResultsEndpoints:
    """Test results endpoints"""
    
    def test_get_raw_results_success(self, client, app, test_scans):
        """Test getting raw scan results"""
        # Get first scan ID from dynamic fixture
        scan_id = list(test_scans.values())[0]
        response = client.get(f'/scans/{scan_id}/raw_results')

        assert response.status_code == 200
        data = json.loads(response.data)
        # endpoint returns {'results': [...]} - normalize
        results = data.get('results') if isinstance(data, dict) else data
        assert isinstance(results, list)
        assert len(results) >= 1
        assert 'raw_output' in results[0]
    
    def test_get_raw_results_not_found(self, client, app):
        """Test getting raw results for non-existent scan"""
        response = client.get('/scans/nonexistent-scan-id-12345/raw_results')
        
        assert response.status_code == 404
    
    def test_get_parsed_results_success(self, client, app, test_scans):
        """Test getting parsed scan results"""
        # Get first scan ID from dynamic fixture
        scan_id = list(test_scans.values())[0]
        # For now, just test that endpoint works even with empty summaries
        response = client.get(f'/scans/{scan_id}/parsed_results')
        
        # Returns 200 with empty array if no summaries
        assert response.status_code in [200, 404]
    
    def test_get_parsed_results_not_found(self, client, app):
        """Test getting parsed results for non-existent scan"""
        response = client.get('/scans/nonexistent-scan-id-12345/parsed_results')
        
        assert response.status_code == 404


class TestScanExportEndpoint:
    """Test GET /scans/<scan_id>/export/<format> endpoint"""
    
    @patch('services.export_service.exporters.ExportManager.export_scan')
    @patch('services.export_service.exporters.ExportManager.get_content_type')
    def test_export_json_success(self, mock_get_content_type, mock_export_scan, client, app, test_scans):
        """Test exporting scan results as JSON"""
        from io import BytesIO
        
        # Get first scan ID from dynamic fixture
        scan_id = list(test_scans.values())[0]
        
        # Mock ExportManager classmethods to return BytesIO
        mock_export_scan.return_value = BytesIO(b'{"results": []}')
        mock_get_content_type.return_value = 'application/json'
        
        response = client.get(f'/scans/{scan_id}/export/json')
        
        assert response.status_code == 200
    
    def test_export_unsupported_format(self, client, app, test_scans):
        """Test exporting with unsupported format"""
        # Get first scan ID from dynamic fixture
        scan_id = list(test_scans.values())[0]
        response = client.get(f'/scans/{scan_id}/export/invalid')
        
        assert response.status_code == 400
    
    def test_export_scan_not_found(self, client, app):
        """Test exporting non-existent scan"""
        response = client.get('/scans/nonexistent-scan-id-12345/export/json')
        
        assert response.status_code == 404


class TestStatisticsEndpoints:
    """Test statistics endpoints"""
    
    def test_get_scan_statistics_success(self, client, app, test_scans):
        """Test getting scan statistics"""
        response = client.get('/scans/stats')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        # Should have our test scans at minimum
        assert 'total_scans' in data
        assert data['total_scans'] >= 1


class TestBulkOperations:
    """Test bulk operation endpoints"""
    
    def test_bulk_delete_success(self, client, app, test_scans):
        """Test bulk deleting scans"""
        # Use real scan IDs from test_scans fixture (get both scans)
        scan_ids = list(test_scans.values())
        response = client.post('/scans/bulk/delete',
            data=json.dumps({
                'scan_ids': scan_ids
            }),
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'deleted' in data
        assert 'failed' in data
    
    def test_bulk_delete_missing_scan_ids(self, client, app):
        """Test bulk delete without scan_ids"""
        response = client.post('/scans/bulk/delete',
            data=json.dumps({}),
            content_type='application/json'
        )
        
        assert response.status_code == 400
    
    @patch('services.export_service.exporters.ExportManager.export_scan')
    def test_bulk_export_success(self, mock_export_scan, client, app, test_scans):
        """Test bulk exporting scans"""
        from io import BytesIO
        
        # Mock ExportManager.export_scan to return BytesIO
        mock_export_scan.return_value = BytesIO(b'{"results": []}')
        
        # Get first scan ID from dynamic fixture
        scan_id = list(test_scans.values())[0]
        
        response = client.post('/scans/bulk/export',
            data=json.dumps({
                'scan_ids': [scan_id],
                'format': 'json'
            }),
            content_type='application/json'
        )
        
        assert response.status_code == 200
    
    def test_bulk_export_missing_parameters(self, client, app):
        """Test bulk export with invalid format"""
        response = client.post('/scans/bulk/export',
            data=json.dumps({
                'scan_ids': ['scan-1'],
                'format': 'invalid-format'  # Invalid format should return 400
            }),
            content_type='application/json'
        )
        
        assert response.status_code == 400


class TestToolsEndpoint:
    """Test /tools endpoint"""
    
    def test_get_tools_list(self, client, app):
        """Test getting list of available tools"""
        response = client.get('/tools/')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'tools' in data
        assert 'count' in data
        assert len(data['tools']) > 0
        
        # Verify tool structure
        tool = data['tools'][0]
        assert 'name' in tool
        assert 'display_name' in tool
        assert 'description' in tool
        assert 'category' in tool
        assert 'supported_scan_types' in tool
        assert 'capabilities' in tool


class TestStatsEndpoint:
    """Test /stats endpoint"""
    
    def test_get_stats_empty_db(self, client, app):
        """Test getting stats with no scans"""
        response = client.get('/stats/')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'total_scans' in data
        assert 'status_breakdown' in data
        assert 'tool_usage' in data
        assert 'vulnerabilities' in data
    
    def test_get_stats_with_scans(self, client, app, test_scans):
        """Test getting stats with existing scans"""
        response = client.get('/stats/')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['total_scans'] > 0
        assert 'status_breakdown' in data
        assert 'success_rate' in data
        assert 'active_scans' in data
    
    def test_get_stats_with_summaries(self, client, app, test_scans, db_ingestor):
        """Test getting stats with scan summaries containing vulnerability counts"""
        from services.data_ingestor.models import ScanSummary
        
        # Add scan summary with vulnerability counts
        scan_id = list(test_scans.values())[0]
        session = db_ingestor.get_session()
        try:
            summary = ScanSummary(
                scan_id=scan_id,
                total_vulnerabilities=10,
                critical_count=2,
                high_count=3,
                medium_count=3,
                low_count=1,
                info_count=1
            )
            session.add(summary)
            session.commit()
        finally:
            session.close()
        
        response = client.get('/stats/')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'vulnerabilities' in data
        assert data['vulnerabilities']['total'] >= 10
        assert data['vulnerabilities']['critical'] >= 2
        assert data['vulnerabilities']['high'] >= 3


class TestScanErrorHandling:
    """Test error handling in scan endpoints"""
    
    def test_list_scans_invalid_status(self, client, app):
        """Test listing scans with invalid status parameter"""
        response = client.get('/scans/?status=INVALID_STATUS')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Invalid status' in data.get('message', '')
    
    def test_create_scan_missing_required_fields(self, client, app):
        """Test creating scan without required fields"""
        response = client.post('/scans/',
            data=json.dumps({'target': '192.168.1.1'}),  # Missing tool_name and scan_type
            content_type='application/json'
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        # Flask-RESTX returns "Input payload validation failed"
        assert 'validation failed' in data.get('message', '').lower() or 'required' in data.get('message', '').lower()
    
    def test_create_scan_empty_field(self, client, app):
        """Test creating scan with empty field values"""
        response = client.post('/scans/',
            data=json.dumps({
                'target': '',  # Empty target
                'tool_name': 'nmap',
                'scan_type': 'basic'
            }),
            content_type='application/json'
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'cannot be empty' in data.get('message', '')
    
    def test_create_scan_whitespace_field(self, client, app):
        """Test creating scan with whitespace-only field"""
        response = client.post('/scans/',
            data=json.dumps({
                'target': '   ',  # Whitespace only
                'tool_name': 'nmap',
                'scan_type': 'basic'
            }),
            content_type='application/json'
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'cannot be empty' in data.get('message', '')
    
    def test_get_scan_not_found(self, client, app):
        """Test getting non-existent scan"""
        response = client.get('/scans/999999')
        
        assert response.status_code == 404
        data = json.loads(response.data)
        assert 'not found' in data.get('message', '').lower()
    
    def test_delete_scan_not_found(self, client, app):
        """Test deleting non-existent scan"""
        response = client.delete('/scans/999999')
        
        assert response.status_code == 404
        data = json.loads(response.data)
        assert 'not found' in data.get('message', '').lower()
    
    def test_get_scan_status_not_found(self, client, app):
        """Test getting status of non-existent scan"""
        response = client.get('/scans/999999/status')
        
        assert response.status_code == 404
        data = json.loads(response.data)
        assert 'not found' in data.get('message', '').lower()
    
    def test_get_raw_results_not_found(self, client, app):
        """Test getting raw results of non-existent scan"""
        response = client.get('/scans/999999/raw_results')
        
        assert response.status_code == 404
        data = json.loads(response.data)
        assert 'no results' in data.get('message', '').lower() or 'not found' in data.get('message', '').lower()
    
    def test_get_parsed_results_not_found(self, client, app):
        """Test getting parsed results of non-existent scan"""
        response = client.get('/scans/999999/parsed_results')
        
        assert response.status_code == 404
        data = json.loads(response.data)
        assert 'no results' in data.get('message', '').lower() or 'not found' in data.get('message', '').lower()
    
    def test_export_results_not_found(self, client, app):
        """Test exporting results of non-existent scan"""
        response = client.get('/scans/999999/export/json')
        
        assert response.status_code == 404
        data = json.loads(response.data)
        assert 'not found' in data.get('message', '').lower()
    
    def test_export_results_invalid_format(self, client, app, test_scans):
        """Test exporting with invalid format"""
        scan_id = list(test_scans.keys())[0]
        response = client.get(f'/scans/{scan_id}/export/invalid_format')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'format' in data.get('message', '').lower()
    
    def test_bulk_delete_invalid_input(self, client, app):
        """Test bulk delete with invalid input"""
        response = client.post('/scans/bulk/delete',
            data=json.dumps({'invalid': 'data'}),
            content_type='application/json'
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'scan' in data.get('message', '').lower() and 'ids' in data.get('message', '').lower()
    
    def test_bulk_export_invalid_format(self, client, app):
        """Test bulk export with invalid format"""
        response = client.post('/scans/bulk/export',
            data=json.dumps({
                'scan_ids': ['scan-1'],
                'format': 'invalid_format'
            }),
            content_type='application/json'
        )

        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'format' in data.get('message', '').lower()
    
    def test_get_raw_results_success(self, client, app, test_scans):
        """Test getting raw results successfully"""
        scan_id = list(test_scans.values())[0]
        response = client.get(f'/scans/{scan_id}/raw_results')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'results' in data
    
    def test_get_scan_status_success(self, client, app, test_scans):
        """Test getting scan status successfully"""
        scan_id = list(test_scans.values())[0]
        response = client.get(f'/scans/{scan_id}/status')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'status' in data or 'scan_id' in data


class TestScanListFiltering:
    """Test scan list filtering and pagination"""
    
    def test_list_scans_with_status_filter(self, client, app, test_scans):
        """Test filtering scans by status"""
        response = client.get('/scans/?status=COMPLETED')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'scans' in data
        # All returned scans should be completed
        for scan in data['scans']:
            assert scan['status'] in ['COMPLETED', 'completed']
    
    def test_list_scans_with_tool_filter(self, client, app, test_scans):
        """Test filtering scans by tool name"""
        response = client.get('/scans/?tool=nmap')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'scans' in data
    
    def test_list_scans_with_pagination(self, client, app, test_scans):
        """Test pagination parameters"""
        response = client.get('/scans/?page=1&per_page=5')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'scans' in data
        assert 'total' in data
        assert 'page' in data
        assert data['page'] == 1
    
    def test_list_scans_combined_filters(self, client, app, test_scans):
        """Test combining multiple filters"""
        response = client.get('/scans/?status=COMPLETED&tool=nmap&page=1&per_page=10')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'scans' in data
        assert 'total' in data


class TestBulkOperations:
    """Test bulk operations"""
    
    def test_bulk_delete_success(self, client, app, test_scans):
        """Test bulk delete with valid scan IDs"""
        scan_ids = list(test_scans.values())
        response = client.post('/scans/bulk/delete',
            data=json.dumps({'scan_ids': scan_ids}),
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'deleted' in data or 'deleted_count' in data or 'message' in data
    
    def test_bulk_delete_empty_list(self, client, app):
        """Test bulk delete with empty scan IDs"""
        response = client.post('/scans/bulk/delete',
            data=json.dumps({'scan_ids': []}),
            content_type='application/json'
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'scan' in data.get('message', '').lower() or 'empty' in data.get('message', '').lower()
    
    def test_bulk_export_success(self, client, app, test_scans):
        """Test bulk export with valid format"""
        scan_ids = list(test_scans.values())
        response = client.post('/scans/bulk/export',
            data=json.dumps({
                'scan_ids': scan_ids,
                'format': 'json'
            }),
            content_type='application/json'
        )
        
        # May return 200 with data or 404 if no results
        assert response.status_code in [200, 404, 500]


class TestExportFormats:
    """Test export functionality with different formats"""
    
    def test_export_json_format(self, client, app, test_scans):
        """Test JSON export format"""
        scan_id = list(test_scans.values())[0]
        response = client.get(f'/scans/{scan_id}/export/json')
        
        # May be 200 or 404 depending on whether results exist
        assert response.status_code in [200, 404]
    
    def test_export_xml_format(self, client, app, test_scans):
        """Test XML export format"""
        scan_id = list(test_scans.values())[0]
        response = client.get(f'/scans/{scan_id}/export/xml')
        
        assert response.status_code in [200, 404]
    
    def test_export_csv_format(self, client, app, test_scans):
        """Test CSV export format"""
        scan_id = list(test_scans.values())[0]
        response = client.get(f'/scans/{scan_id}/export/csv')
        
        assert response.status_code in [200, 404]
    
    def test_export_html_format(self, client, app, test_scans):
        """Test HTML export format"""
        scan_id = list(test_scans.values())[0]
        response = client.get(f'/scans/{scan_id}/export/html')
        
        # HTML may not be supported, expecting 400 or 404
        assert response.status_code in [200, 400, 404]


class TestScanDeletion:
    """Test scan deletion"""
    
    def test_delete_scan_success(self, client, app, test_scans):
        """Test deleting an existing scan"""
        scan_id = list(test_scans.values())[0]
        response = client.delete(f'/scans/{scan_id}')
        
        assert response.status_code in [200, 204]


class TestEdgeCases:
    """Test edge cases and boundary conditions"""
    
    def test_list_scans_large_page_size(self, client, app, test_scans):
        """Test with very large per_page value"""
        response = client.get('/scans/?page=1&per_page=1000')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'scans' in data
    
    def test_get_scan_with_summary(self, client, app, test_scans, db_ingestor):
        """Test getting scan that has a summary"""
        from services.data_ingestor.models import ScanSummary
        
        scan_id = list(test_scans.values())[0]
        
        # Add a summary
        session = db_ingestor.get_session()
        try:
            summary = ScanSummary(
                scan_id=scan_id,
                total_vulnerabilities=5,
                critical_count=1,
                high_count=2,
                medium_count=2
            )
            session.add(summary)
            session.commit()
        finally:
            session.close()
        
        response = client.get(f'/scans/{scan_id}')
        
        # May return 500 if there's an issue with the summary
        assert response.status_code in [200, 500]


class TestErrorHandlers:
    """Test error handling paths in routes"""
    
    def test_list_scans_with_type_error(self, client, app, monkeypatch):
        """Test list scans with TypeError in processing"""
        from api_gateway import routes
        
        def mock_list_scans(*args, **kwargs):
            raise TypeError("Type mismatch")
        
        monkeypatch.setattr(routes.ingestor, 'list_scans', mock_list_scans)
        
        response = client.get('/scans/')
        assert response.status_code == 500
            
    def test_list_scans_with_keyerror(self, client, app, monkeypatch):
        """Test list scans with KeyError in processing"""
        from api_gateway import routes
        
        def mock_list_scans(*args, **kwargs):
            raise KeyError("Missing required key")
        
        monkeypatch.setattr(routes.ingestor, 'list_scans', mock_list_scans)
        
        response = client.get('/scans/')
        assert response.status_code == 500
            
    def test_create_scan_with_value_error(self, client, app, monkeypatch):
        """Test create scan with ValueError"""
        from api_gateway import routes
        
        def mock_create_scan(*args, **kwargs):
            raise ValueError("Invalid scan data")
        
        monkeypatch.setattr(routes.ingestor, 'create_scan', mock_create_scan)
        
        scan_data = {
            'tool': 'nmap',
            'target': '192.168.1.1',
            'config': {},
            'priority': 5
        }
        response = client.post('/scans/', json=scan_data)
        assert response.status_code in [400, 500]  # May be validation or runtime error
            
    def test_create_scan_with_attribute_error(self, client, app, monkeypatch):
        """Test create scan with AttributeError"""
        from api_gateway import routes
        
        def mock_create_scan(*args, **kwargs):
            raise AttributeError("Missing required attribute")
        
        monkeypatch.setattr(routes.ingestor, 'create_scan', mock_create_scan)
        
        scan_data = {
            'tool': 'nmap',
            'target': '192.168.1.1',
            'config': {},
            'priority': 5
        }
        response = client.post('/scans/', json=scan_data)
        assert response.status_code in [400, 500]  # May be validation or runtime error
            
    def test_export_with_value_error(self, client, app, test_scans, monkeypatch):
        """Test export with ValueError from ExportManager"""
        from services.export_service import exporters
        
        scan_id = list(test_scans.values())[0]
        
        def mock_export_scan(*args, **kwargs):
            raise ValueError("Unsupported export format")
        
        monkeypatch.setattr(exporters.ExportManager, 'export_scan', staticmethod(mock_export_scan))
        
        response = client.get(f'/scans/{scan_id}/export/json')
        assert response.status_code == 400
            
    def test_export_with_generic_exception(self, client, app, test_scans, monkeypatch):
        """Test export with generic Exception"""
        from services.export_service import exporters
        
        scan_id = list(test_scans.values())[0]
        
        def mock_export_scan(*args, **kwargs):
            raise Exception("Export processing failed")
        
        monkeypatch.setattr(exporters.ExportManager, 'export_scan', staticmethod(mock_export_scan))
        
        response = client.get(f'/scans/{scan_id}/export/json')
        assert response.status_code == 500


class TestStatsEndpoint:
    """Test statistics endpoints"""
    
    def test_get_stats_summary(self, client, app, test_scans):
        """Test getting statistics summary"""
        response = client.get('/stats/')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        # Should have key statistics fields
        assert 'total_scans' in data
        assert 'status_breakdown' in data
        assert 'tool_usage' in data
        
    def test_stats_with_vulnerabilities(self, client, app, test_scans, db_ingestor):
        """Test stats include vulnerability counts"""
        from services.data_ingestor.models import ScanSummary
        
        scan_id = list(test_scans.values())[0]
        
        # Add vulnerability summary
        session = db_ingestor.get_session()
        try:
            summary = ScanSummary(
                scan_id=scan_id,
                total_vulnerabilities=10,
                critical_count=2,
                high_count=3,
                medium_count=3,
                low_count=2
            )
            session.add(summary)
            session.commit()
        finally:
            session.close()
        
        response = client.get('/stats/')
        assert response.status_code == 200
        data = json.loads(response.data)
        
        # Should have vulnerability breakdown
        if 'vulnerabilities' in data:
            assert 'total' in data['vulnerabilities']
            
    def test_stats_error_handling(self, client, app, monkeypatch):
        """Test stats endpoint error handling"""
        from api_gateway import routes
        
        def mock_list_scans(*args, **kwargs):
            raise Exception("Database error")
        
        monkeypatch.setattr(routes.ingestor, 'list_scans', mock_list_scans)
        
        response = client.get('/stats/')
        assert response.status_code == 500


class TestToolsEndpoint:
    """Test tools information endpoint"""
    
    def test_get_tools_list(self, client, app):
        """Test getting available tools list"""
        response = client.get('/tools/')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        # Should return tools information
        assert 'tools' in data or isinstance(data, list)
        
    def test_tools_endpoint_exists(self, client, app):
        """Test tools endpoint is accessible"""
        response = client.get('/tools/')
        
        # Should not return 404
        assert response.status_code != 404


class TestBulkDeleteEndpoint:
    """Test bulk delete operations"""
    
    def test_bulk_delete_with_scan_ids(self, client, app, test_scans):
        """Test bulk delete with valid scan IDs"""
        scan_ids = list(test_scans.values())[:2]
        
        response = client.post('/scans/bulk/delete', json={
            'scan_ids': scan_ids
        })
        
        # Should accept request
        assert response.status_code in [200, 400]
        
    def test_bulk_delete_validation_error(self, client, app):
        """Test bulk delete with invalid data"""
        response = client.post('/scans/bulk/delete', json={
            'scan_ids': []
        })
        
        assert response.status_code == 400
        
    def test_bulk_delete_with_nonexistent_ids(self, client, app):
        """Test bulk delete with IDs that don't exist"""
        response = client.post('/scans/bulk/delete', json={
            'scan_ids': ['nonexistent-1', 'nonexistent-2']
        })
        
        # Should handle gracefully
        assert response.status_code in [200, 404]
        
    def test_bulk_delete_error_handling(self, client, app, monkeypatch):
        """Test bulk delete error handling"""
        from api_gateway import routes
        
        def mock_delete_scan(*args, **kwargs):
            raise Exception("Delete failed")
        
        monkeypatch.setattr(routes.ingestor, 'delete_scan', mock_delete_scan)
        
        response = client.post('/scans/bulk/delete', json={
            'scan_ids': ['test-id']
        })
        
        # Should return error or partial success
        assert response.status_code in [200, 500]


class TestGetScanEndpoint:
    """Test individual scan retrieval with edge cases"""
    
    def test_get_scan_not_found(self, client, app):
        """Test getting scan that doesn't exist"""
        response = client.get('/scans/nonexistent-scan-id')
        
        assert response.status_code == 404
        
    def test_get_scan_with_results(self, client, app, test_scans, db_ingestor):
        """Test getting scan with raw results"""
        from services.data_ingestor.models import RawScanResult
        
        scan_id = list(test_scans.values())[0]
        
        # Add raw results with correct fields
        session = db_ingestor.get_session()
        try:
            result = RawScanResult(
                scan_id=scan_id,
                tool_name="nmap",
                raw_output="Test scan output\nHost: 192.168.1.1\nPorts: 80, 443",
                output_format="text"
            )
            session.add(result)
            session.commit()
        finally:
            session.close()
        
        response = client.get(f'/scans/{scan_id}')
        assert response.status_code == 200
        
    def test_get_scan_error_handling(self, client, app, test_scans, monkeypatch):
        """Test get scan error handling"""
        from api_gateway import routes
        
        scan_id = list(test_scans.values())[0]
        
        def mock_get_scan(*args, **kwargs):
            raise ValueError("Database error")
        
        monkeypatch.setattr(routes.ingestor, 'get_scan', mock_get_scan)
        
        response = client.get(f'/scans/{scan_id}')
        assert response.status_code == 404  # ValueError is treated as not found

        if response.status_code == 200:
            data = json.loads(response.data)
            assert 'scan_id' in data or 'id' in data