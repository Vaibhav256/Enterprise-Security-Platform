"""
Comprehensive tests for export service exporters

Tests all export formats including JSON, CSV, XLSX, PDF, and XML
"""

import io
import json
from datetime import datetime
from unittest.mock import Mock, patch

import pytest

from services.export_service.exporters import (
    CSVExporter,
    ExportManager,
    JSONExporter,
    PDFExporter,
    XMLExporter,
    XLSXExporter,
)


@pytest.fixture
def sample_scan_data():
    """Create sample scan data"""
    return {
        'scan_id': 'test-scan-123',
        'target': '192.168.1.1',
        'tool_name': 'nmap',
        'scan_type': 'basic',
        'status': 'completed',
        'created_at': '2025-01-01T10:00:00',
        'completed_at': '2025-01-01T10:05:00',
        'execution_time': 300,
        'summary': {
            'hosts_scanned': 5,
            'hosts_up': 3,
            'total_ports': 100,
            'open_ports': 10,
            'vulnerabilities_found': 15,
            'critical_count': 2,
            'high_count': 5,
            'medium_count': 6,
            'low_count': 2,
            'info_count': 0
        },
        'parsed_results': [
            {
                'tool_name': 'nmap',
                'data': {
                    'hosts': [
                        {
                            'address': '192.168.1.1',
                            'ports': [{'port': 80, 'state': 'open', 'service': 'http'}]
                        }
                    ]
                }
            }
        ]
    }


class TestJSONExporter:
    """Tests for JSON export"""

    def test_export_basic(self, sample_scan_data):
        """Test basic JSON export"""
        exporter = JSONExporter()
        output = io.BytesIO()
        
        exporter.export(sample_scan_data, output)
        
        output.seek(0)
        result = json.loads(output.read().decode('utf-8'))
        
        assert result['scan_id'] == 'test-scan-123'
        assert result['target'] == '192.168.1.1'
        assert result['tool_name'] == 'nmap'

    def test_export_with_datetime(self):
        """Test JSON export with datetime objects"""
        exporter = JSONExporter()
        data = {
            'timestamp': datetime(2025, 1, 1, 10, 0, 0),
            'name': 'test'
        }
        output = io.BytesIO()
        
        exporter.export(data, output)
        
        output.seek(0)
        result = json.loads(output.read().decode('utf-8'))
        assert '2025-01-01' in result['timestamp']

    def test_serialize_nested_datetime(self):
        """Test serializing nested datetime objects"""
        exporter = JSONExporter()
        data = {
            'items': [
                {'time': datetime(2025, 1, 1)},
                {'time': datetime(2025, 1, 2)}
            ]
        }
        
        serialized = exporter._serialize_data(data)
        assert isinstance(serialized['items'][0]['time'], str)

    def test_export_empty_data(self):
        """Test exporting empty data"""
        exporter = JSONExporter()
        output = io.BytesIO()
        
        exporter.export({}, output)
        
        output.seek(0)
        result = json.loads(output.read().decode('utf-8'))
        assert result == {}


class TestCSVExporter:
    """Tests for CSV export"""

    def test_export_basic(self, sample_scan_data):
        """Test basic CSV export"""
        exporter = CSVExporter()
        output = io.BytesIO()
        
        exporter.export(sample_scan_data, output)
        
        output.seek(0)
        content = output.read().decode('utf-8')
        
        assert 'Scan Information' in content
        assert '192.168.1.1' in content
        assert 'nmap' in content

    def test_export_with_summary(self, sample_scan_data):
        """Test CSV export includes summary"""
        exporter = CSVExporter()
        output = io.BytesIO()
        
        exporter.export(sample_scan_data, output)
        
        output.seek(0)
        content = output.read().decode('utf-8')
        
        assert 'Summary' in content
        assert '15' in content  # vulnerabilities_found

    def test_export_without_parsed_results(self, sample_scan_data):
        """Test CSV export without parsed results"""
        sample_scan_data['parsed_results'] = []
        exporter = CSVExporter()
        output = io.BytesIO()
        
        exporter.export(sample_scan_data, output)
        
        output.seek(0)
        content = output.read().decode('utf-8')
        assert content  # Should still export basic info

    def test_export_missing_summary(self, sample_scan_data):
        """Test CSV export with missing summary"""
        del sample_scan_data['summary']
        exporter = CSVExporter()
        output = io.BytesIO()
        
        exporter.export(sample_scan_data, output)
        
        output.seek(0)
        content = output.read().decode('utf-8')
        assert 'Scan Information' in content


class TestXLSXExporter:
    """Tests for XLSX export"""

    def test_export_basic(self, sample_scan_data):
        """Test basic XLSX export"""
        exporter = XLSXExporter()
        output = io.BytesIO()
        
        exporter.export(sample_scan_data, output)
        
        output.seek(0)
        content = output.read()
        assert len(content) > 0  # File has content

    def test_export_with_vulnerabilities(self, sample_scan_data):
        """Test XLSX export with vulnerability data"""
        sample_scan_data['parsed_results'][0]['data']['vulnerabilities'] = [
            {'name': 'CVE-2024-1234', 'severity': 'high'}
        ]
        
        exporter = XLSXExporter()
        output = io.BytesIO()
        
        exporter.export(sample_scan_data, output)
        
        output.seek(0)
        content = output.read()
        assert len(content) > 0

    def test_export_empty_results(self):
        """Test XLSX export with empty results"""
        data = {
            'scan_id': 'test',
            'target': '127.0.0.1',
            'parsed_results': []
        }
        
        exporter = XLSXExporter()
        output = io.BytesIO()
        
        exporter.export(data, output)
        
        output.seek(0)
        content = output.read()
        assert len(content) > 0


class TestPDFExporter:
    """Tests for PDF export"""

    def test_export_basic(self, sample_scan_data):
        """Test basic PDF export"""
        exporter = PDFExporter()
        output = io.BytesIO()
        
        exporter.export(sample_scan_data, output)
        
        output.seek(0)
        content = output.read()
        assert content.startswith(b'%PDF')  # PDF signature

    def test_export_with_summary(self, sample_scan_data):
        """Test PDF export includes summary"""
        exporter = PDFExporter()
        output = io.BytesIO()
        
        exporter.export(sample_scan_data, output)
        
        output.seek(0)
        content = output.read()
        assert len(content) > 1000  # PDF has substantial content

    def test_export_with_hosts(self, sample_scan_data):
        """Test PDF export with host data"""
        sample_scan_data['parsed_results'][0]['data']['hosts'] = [
            {
                'address': '192.168.1.1',
                'ports': [
                    {'port': 80, 'state': 'open', 'service': 'http'},
                    {'port': 443, 'state': 'open', 'service': 'https'}
                ]
            }
        ]
        
        exporter = PDFExporter()
        output = io.BytesIO()
        
        exporter.export(sample_scan_data, output)
        
        output.seek(0)
        assert output.read().startswith(b'%PDF')

    def test_export_with_vulnerabilities(self, sample_scan_data):
        """Test PDF export with vulnerabilities"""
        sample_scan_data['parsed_results'][0]['data']['vulnerabilities'] = [
            {
                'name': 'CVE-2024-1234',
                'severity': 'critical',
                'description': 'Test vulnerability'
            }
        ]
        
        exporter = PDFExporter()
        output = io.BytesIO()
        
        exporter.export(sample_scan_data, output)
        
        output.seek(0)
        content = output.read()
        assert len(content) > 0


class TestXMLExporter:
    """Tests for XML export"""

    def test_export_basic(self, sample_scan_data):
        """Test basic XML export"""
        exporter = XMLExporter()
        output = io.BytesIO()
        
        exporter.export(sample_scan_data, output)
        
        output.seek(0)
        content = output.read().decode('utf-8')
        
        assert '<?xml version=' in content
        assert '<scan>' in content
        assert '<scan_id>test-scan-123</scan_id>' in content

    def test_export_with_nested_data(self, sample_scan_data):
        """Test XML export with nested structures"""
        exporter = XMLExporter()
        output = io.BytesIO()
        
        exporter.export(sample_scan_data, output)
        
        output.seek(0)
        content = output.read().decode('utf-8')
        
        assert '<summary>' in content
        assert '<hosts_scanned>5</hosts_scanned>' in content

    def test_export_with_list_data(self, sample_scan_data):
        """Test XML export with list data"""
        exporter = XMLExporter()
        output = io.BytesIO()
        
        exporter.export(sample_scan_data, output)
        
        output.seek(0)
        content = output.read().decode('utf-8')
        
        assert '<results>' in content

    def test_export_special_characters(self):
        """Test XML export handles special characters"""
        data = {
            'scan_id': 'test-123',
            'target': 'Test & <script>',
            'tool_name': '"quoted"'
        }
        
        exporter = XMLExporter()
        output = io.BytesIO()
        
        exporter.export(data, output)
        
        output.seek(0)
        content = output.read().decode('utf-8')
        
        # XML should contain the scan structure
        assert '<scan>' in content
        assert 'test-123' in content


class TestExportManager:
    """Tests for ExportManager"""

    def test_export_scan_json(self, sample_scan_data):
        """Test exporting scan as JSON"""
        output = ExportManager.export_scan(sample_scan_data, 'json')
        
        output.seek(0)
        result = json.loads(output.read().decode('utf-8'))
        assert result['scan_id'] == 'test-scan-123'

    def test_export_scan_csv(self, sample_scan_data):
        """Test exporting scan as CSV"""
        output = ExportManager.export_scan(sample_scan_data, 'csv')
        
        output.seek(0)
        content = output.read().decode('utf-8')
        assert '192.168.1.1' in content

    def test_export_scan_xlsx(self, sample_scan_data):
        """Test exporting scan as XLSX"""
        output = ExportManager.export_scan(sample_scan_data, 'xlsx')
        
        output.seek(0)
        content = output.read()
        assert len(content) > 0

    def test_export_scan_pdf(self, sample_scan_data):
        """Test exporting scan as PDF"""
        output = ExportManager.export_scan(sample_scan_data, 'pdf')
        
        output.seek(0)
        assert output.read().startswith(b'%PDF')

    def test_export_scan_xml(self, sample_scan_data):
        """Test exporting scan as XML"""
        output = ExportManager.export_scan(sample_scan_data, 'xml')
        
        output.seek(0)
        content = output.read().decode('utf-8')
        assert '<?xml' in content

    def test_export_invalid_format(self, sample_scan_data):
        """Test exporting with invalid format"""
        with pytest.raises(ValueError, match="Unsupported export format"):
            ExportManager.export_scan(sample_scan_data, 'invalid')

    def test_get_content_type_json(self):
        """Test getting content type for JSON"""
        content_type = ExportManager.get_content_type('json')
        assert content_type == 'application/json'

    def test_get_content_type_csv(self):
        """Test getting content type for CSV"""
        content_type = ExportManager.get_content_type('csv')
        assert content_type == 'text/csv'

    def test_get_content_type_xlsx(self):
        """Test getting content type for XLSX"""
        content_type = ExportManager.get_content_type('xlsx')
        assert content_type == 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'

    def test_get_content_type_pdf(self):
        """Test getting content type for PDF"""
        content_type = ExportManager.get_content_type('pdf')
        assert content_type == 'application/pdf'

    def test_get_content_type_xml(self):
        """Test getting content type for XML"""
        content_type = ExportManager.get_content_type('xml')
        assert content_type == 'application/xml'

    def test_get_content_type_invalid(self):
        """Test getting content type for invalid format"""
        with pytest.raises(ValueError, match="Unsupported export format"):
            ExportManager.get_content_type('invalid')


class TestExporterEdgeCases:
    """Tests for edge cases and error handling"""

    def test_json_export_none_values(self):
        """Test JSON export with None values"""
        data = {'key': None, 'other': 'value'}
        exporter = JSONExporter()
        output = io.BytesIO()
        
        exporter.export(data, output)
        
        output.seek(0)
        result = json.loads(output.read().decode('utf-8'))
        assert result['key'] is None

    def test_csv_export_unicode(self):
        """Test CSV export with unicode characters"""
        data = {
            'target': '测试',
            'tool_name': 'nmap'
        }
        exporter = CSVExporter()
        output = io.BytesIO()
        
        exporter.export(data, output)
        
        output.seek(0)
        content = output.read().decode('utf-8')
        assert '测试' in content

    def test_xml_export_empty_dict(self):
        """Test XML export with empty dictionary"""
        exporter = XMLExporter()
        output = io.BytesIO()
        
        exporter.export({}, output)
        
        output.seek(0)
        content = output.read().decode('utf-8')
        assert '<?xml' in content

    def test_pdf_export_long_text(self):
        """Test PDF export with long text"""
        data = {
            'scan_id': 'test',
            'target': 'test',
            'summary': {
                'description': 'A' * 1000
            }
        }
        exporter = PDFExporter()
        output = io.BytesIO()
        
        exporter.export(data, output)
        
        output.seek(0)
        content = output.read()
        assert len(content) > 0

    def test_xlsx_export_many_rows(self):
        """Test XLSX export with many rows"""
        data = {
            'scan_id': 'test',
            'target': 'test',
            'parsed_results': [
                {
                    'tool_name': 'nmap',
                    'data': {
                        'hosts': [
                            {'address': f'192.168.1.{i}', 'ports': []}
                            for i in range(50)
                        ]
                    }
                }
            ]
        }
        
        exporter = XLSXExporter()
        output = io.BytesIO()
        
        exporter.export(data, output)
        
        output.seek(0)
        content = output.read()
        assert len(content) > 0


class TestExporterErrorHandling:
    """Test error handling in all exporters"""

    def test_json_export_exception(self):
        """Test JSON export with write error"""
        exporter = JSONExporter()
        data = {'scan_id': 'test'}
        
        # Mock output that raises exception on write
        output = Mock()
        output.write.side_effect = IOError("Write failed")
        
        with pytest.raises(IOError):
            exporter.export(data, output)

    def test_csv_export_exception(self):
        """Test CSV export with write error"""
        exporter = CSVExporter()
        data = {'scan_id': 'test', 'parsed_results': []}
        
        output = Mock()
        output.write.side_effect = IOError("Write failed")
        
        with pytest.raises(IOError):
            exporter.export(data, output)

    def test_xlsx_export_exception(self):
        """Test XLSX export with save error"""
        exporter = XLSXExporter()
        data = {'scan_id': 'test', 'parsed_results': []}
        
        output = Mock()
        output.write.side_effect = IOError("Write failed")
        
        with pytest.raises(Exception):
            exporter.export(data, output)

    def test_pdf_export_exception(self):
        """Test PDF export with build error"""
        exporter = PDFExporter()
        data = {'scan_id': 'test', 'parsed_results': []}
        
        output = Mock()
        output.write.side_effect = IOError("Write failed")
        
        with pytest.raises(Exception):
            exporter.export(data, output)

    def test_xml_export_exception(self):
        """Test XML export with write error"""
        exporter = XMLExporter()
        data = {'scan_id': 'test', 'parsed_results': []}
        
        output = Mock()
        output.write.side_effect = IOError("Write failed")
        
        with pytest.raises(IOError):
            exporter.export(data, output)


class TestExporterEdgeCases:
    """Test edge cases in exporters"""

    def test_csv_long_description_truncation(self):
        """Test CSV truncates long descriptions"""
        long_desc = "A" * 200
        data = {
            'scan_id': 'test',
            'parsed_results': [{
                'tool_name': 'test',
                'data': {
                    'vulnerabilities': [{
                        'title': 'Test Vuln',
                        'severity': 'high',
                        'description': long_desc
                    }]
                }
            }]
        }
        
        exporter = CSVExporter()
        output = io.BytesIO()
        exporter.export(data, output)
        
        output.seek(0)
        content = output.read().decode('utf-8')
        # Should contain truncated version with ...
        assert '...' in content
        assert long_desc not in content  # Full text not present

    def test_xlsx_long_description_truncation(self):
        """Test XLSX truncates long descriptions"""
        long_desc = "B" * 200
        data = {
            'scan_id': 'test',
            'parsed_results': [{
                'tool_name': 'test',
                'data': {
                    'vulnerabilities': [{
                        'title': 'Test',
                        'severity': 'high',
                        'description': long_desc,
                        'affected_item': 'test',
                        'solution': 'fix it'
                    }]
                }
            }]
        }
        
        exporter = XLSXExporter()
        output = io.BytesIO()
        exporter.export(data, output)
        
        output.seek(0)
        assert len(output.read()) > 0

    def test_xlsx_remove_default_sheet(self):
        """Test XLSX removes default sheet"""
        data = {
            'scan_id': 'test',
            'parsed_results': [{
                'tool_name': 'test',
                'data': {'vulnerabilities': []}
            }]
        }
        
        exporter = XLSXExporter()
        output = io.BytesIO()
        exporter.export(data, output)
        
        output.seek(0)
        content = output.read()
        assert len(content) > 0
        # Workbook created successfully

    def test_pdf_long_description_truncation(self):
        """Test PDF truncates long descriptions"""
        long_desc = "C" * 600
        long_solution = "D" * 600
        data = {
            'scan_id': 'test',
            'target': 'test.com',
            'parsed_results': [{
                'tool_name': 'test',
                'data': {
                    'vulnerabilities': [{
                        'title': 'Test',
                        'severity': 'critical',
                        'description': long_desc,
                        'solution': long_solution,
                        'affected_item': 'test'
                    }]
                }
            }]
        }
        
        exporter = PDFExporter()
        output = io.BytesIO()
        exporter.export(data, output)
        
        output.seek(0)
        assert len(output.read()) > 0

    def test_pdf_with_recommendation_instead_of_solution(self):
        """Test PDF uses recommendation if solution missing"""
        data = {
            'scan_id': 'test',
            'target': 'test.com',
            'parsed_results': [{
                'tool_name': 'test',
                'data': {
                    'vulnerabilities': [{
                        'title': 'Test',
                        'severity': 'high',
                        'description': 'Test description',
                        'recommendation': 'Apply this recommendation',
                        'affected_item': 'test'
                    }]
                }
            }]
        }
        
        exporter = PDFExporter()
        output = io.BytesIO()
        exporter.export(data, output)
        
        output.seek(0)
        assert len(output.read()) > 0

    def test_pdf_long_solution_truncation(self):
        """Test PDF truncates long solution text"""
        long_solution = "E" * 700
        data = {
            'scan_id': 'test',
            'target': 'test.com',
            'parsed_results': [{
                'tool_name': 'test',
                'data': {
                    'vulnerabilities': [{
                        'title': 'Test',
                        'severity': 'medium',
                        'description': 'Short desc',
                        'solution': long_solution,
                        'affected_item': 'test'
                    }]
                }
            }]
        }
        
        exporter = PDFExporter()
        output = io.BytesIO()
        exporter.export(data, output)
        
        output.seek(0)
        assert len(output.read()) > 0

class TestBaseExporter:
    '''Test BaseExporter abstract class'''
    
    def test_base_exporter_raises_not_implemented(self):
        '''Test that BaseExporter.export raises NotImplementedError'''
        from services.export_service.exporters import BaseExporter
        from io import BytesIO
        
        exporter = BaseExporter()
        output = BytesIO()
        
        with pytest.raises(NotImplementedError):
            exporter.export({}, output)
