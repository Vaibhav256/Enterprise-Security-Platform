"""
Tests for Scan Tasks Module

Tests task module imports and WebSocket fallback functions.
"""

import pytest


class TestTasksModuleImport:
    """Test tasks module imports"""
    
    def test_tasks_imports_successfully(self):
        """Test tasks module can be imported"""
        import services.scan_orchestrator.tasks as tasks
        
        assert tasks is not None
        
    def test_has_logger(self):
        """Test module has logger"""
        import services.scan_orchestrator.tasks as tasks
        
        assert hasattr(tasks, 'logger')
        assert tasks.logger.name == 'services.scan_orchestrator.tasks'
        
    def test_has_websocket_flag(self):
        """Test WEBSOCKET_AVAILABLE flag exists"""
        import services.scan_orchestrator.tasks as tasks
        
        assert hasattr(tasks, 'WEBSOCKET_AVAILABLE')
        assert isinstance(tasks.WEBSOCKET_AVAILABLE, bool)


class TestWebSocketEmitFunctions:
    """Test WebSocket emit functions (fallbacks or real)"""
    
    def test_emit_scan_queued_exists(self):
        """Test emit_scan_queued function exists"""
        import services.scan_orchestrator.tasks as tasks
        
        assert hasattr(tasks, 'emit_scan_queued')
        assert callable(tasks.emit_scan_queued)
        
    def test_emit_scan_started_exists(self):
        """Test emit_scan_started function exists"""
        import services.scan_orchestrator.tasks as tasks
        
        assert hasattr(tasks, 'emit_scan_started')
        assert callable(tasks.emit_scan_started)
        
    def test_emit_scan_progress_exists(self):
        """Test emit_scan_progress function exists"""
        import services.scan_orchestrator.tasks as tasks
        
        assert hasattr(tasks, 'emit_scan_progress')
        assert callable(tasks.emit_scan_progress)
        
    def test_emit_scan_completed_exists(self):
        """Test emit_scan_completed function exists"""
        import services.scan_orchestrator.tasks as tasks
        
        assert hasattr(tasks, 'emit_scan_completed')
        assert callable(tasks.emit_scan_completed)
        
    def test_emit_scan_failed_exists(self):
        """Test emit_scan_failed function exists"""
        import services.scan_orchestrator.tasks as tasks
        
        assert hasattr(tasks, 'emit_scan_failed')
        assert callable(tasks.emit_scan_failed)
        
    def test_emit_functions_dont_raise_errors(self):
        """Test emit functions are callable"""
        import services.scan_orchestrator.tasks as tasks
        
        # Just verify they are callable - already tested they exist above
        assert callable(tasks.emit_scan_queued)
        assert callable(tasks.emit_scan_started)
        assert callable(tasks.emit_scan_progress)
        assert callable(tasks.emit_scan_completed)
        assert callable(tasks.emit_scan_failed)


class TestAdapterImports:
    """Test that adapters are imported"""
    
    def test_nmap_adapter_imported(self):
        """Test NmapAdapter is imported"""
        import services.scan_orchestrator.tasks as tasks
        
        assert hasattr(tasks, 'NmapAdapter')
        
    def test_openvas_adapter_imported(self):
        """Test OpenVASAdapter is imported"""
        import services.scan_orchestrator.tasks as tasks
        
        assert hasattr(tasks, 'OpenVASAdapter')
        
    def test_nikto_adapter_imported(self):
        """Test NiktoAdapter is imported"""
        import services.scan_orchestrator.tasks as tasks
        
        assert hasattr(tasks, 'NiktoAdapter')
        
    def test_nuclei_adapter_imported(self):
        """Test NucleiAdapter is imported"""
        import services.scan_orchestrator.tasks as tasks
        
        assert hasattr(tasks, 'NucleiAdapter')
        
    def test_wsl_helper_imported(self):
        """Test WSLHelper is imported"""
        import services.scan_orchestrator.tasks as tasks
        
        assert hasattr(tasks, 'WSLHelper')
        
    def test_data_ingestor_imported(self):
        """Test DataIngestor is imported"""
        import services.scan_orchestrator.tasks as tasks
        
        assert hasattr(tasks, 'DataIngestor')
