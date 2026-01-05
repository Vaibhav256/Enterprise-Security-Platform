"""
Tests for WebSocket Real-Time Scan Updates

Tests the Socket.IO server for real-time scan status broadcasting.
Covers connection handling, room subscriptions, event emissions, and error cases.

Coverage target: websocket.py 43% → 95%
"""

import pytest
from datetime import datetime
from unittest.mock import patch, MagicMock, PropertyMock
from flask import Flask

from api_gateway.websocket import (
    socketio,
    init_socketio,
    emit_scan_event,
    emit_scan_queued,
    emit_scan_started,
    emit_scan_progress,
    emit_scan_completed,
    emit_scan_failed,
    get_room_stats,
    scan_rooms,
)


@pytest.fixture
def app():
    """Create Flask app for testing"""
    app = Flask(__name__)
    app.config['TESTING'] = True
    return app


class TestWebSocketInit:
    """Test WebSocket initialization"""

    def test_init_socketio(self, app):
        """Test Socket.IO initialization with Flask app"""
        with patch.object(socketio, 'init_app') as mock_init, \
             patch.object(socketio, 'async_mode', 'eventlet', create=True):
            result = init_socketio(app)
            
            assert result == socketio
            mock_init.assert_called_once_with(app)


class TestConnectionHandlers:
    """Test WebSocket connection/disconnection handlers"""

    def test_handle_connect(self, app):
        """Test client connection handler"""
        from api_gateway.websocket import handle_connect
        
        with app.test_request_context():
            with patch('api_gateway.websocket.request') as mock_request, \
                 patch('api_gateway.websocket.emit') as mock_emit:
                
                mock_request.sid = 'client-123'
                
                handle_connect()
                
                # Should emit connection_established
                mock_emit.assert_called_once()
                args = mock_emit.call_args[0]
                assert args[0] == 'connection_established'
                assert args[1]['status'] == 'connected'
                assert args[1]['client_id'] == 'client-123'
                assert 'timestamp' in args[1]

    def test_handle_disconnect_single_room(self, app):
        """Test client disconnection from single room"""
        from api_gateway.websocket import handle_disconnect
        
        # Setup: client in one scan room
        scan_rooms.clear()
        scan_rooms['scan-123'] = {'client-abc'}
        
        with app.test_request_context():
            with patch('api_gateway.websocket.request') as mock_request:
                mock_request.sid = 'client-abc'
                
                handle_disconnect()
                
                # Should remove client and clean up empty room
                assert 'scan-123' not in scan_rooms

    def test_handle_disconnect_multiple_rooms(self, app):
        """Test client disconnection from multiple rooms"""
        from api_gateway.websocket import handle_disconnect
        
        # Setup: client in multiple scan rooms
        scan_rooms.clear()
        scan_rooms['scan-1'] = {'client-abc', 'client-xyz'}
        scan_rooms['scan-2'] = {'client-abc'}
        
        with app.test_request_context():
            with patch('api_gateway.websocket.request') as mock_request:
                mock_request.sid = 'client-abc'
                
                handle_disconnect()
                
                # Should remove client from both rooms
                assert 'client-abc' not in scan_rooms.get('scan-1', set())
                assert 'scan-2' not in scan_rooms  # Empty room cleaned up
                assert scan_rooms['scan-1'] == {'client-xyz'}  # Other client remains

    def test_handle_disconnect_no_rooms(self, app):
        """Test client disconnection when not in any rooms"""
        from api_gateway.websocket import handle_disconnect
        
        scan_rooms.clear()
        
        with app.test_request_context():
            with patch('api_gateway.websocket.request') as mock_request:
                mock_request.sid = 'client-unknown'
                
                # Should not raise error
                handle_disconnect()
                
                assert len(scan_rooms) == 0


class TestRoomSubscriptions:
    """Test scan room subscription/unsubscription"""

    def test_subscribe_scan_success(self, app):
        """Test successful scan subscription"""
        from api_gateway.websocket import handle_subscribe_scan
        
        scan_rooms.clear()
        
        with app.test_request_context():
            with patch('api_gateway.websocket.request') as mock_request, \
                 patch('api_gateway.websocket.join_room') as mock_join, \
                 patch('api_gateway.websocket.emit') as mock_emit:
                
                mock_request.sid = 'client-123'
                data = {'scan_id': 'scan-abc'}
                
                handle_subscribe_scan(data)
                
                # Should join room
                mock_join.assert_called_once_with('scan-abc')
                
                # Should track subscription
                assert 'scan-abc' in scan_rooms
                assert 'client-123' in scan_rooms['scan-abc']
                
                # Should emit confirmation
                mock_emit.assert_called_once()
                args = mock_emit.call_args[0]
                assert args[0] == 'subscription_confirmed'
                assert args[1]['scan_id'] == 'scan-abc'
                assert args[1]['room_size'] == 1

    def test_subscribe_scan_multiple_clients(self, app):
        """Test multiple clients subscribing to same scan"""
        from api_gateway.websocket import handle_subscribe_scan
        
        scan_rooms.clear()
        
        with app.test_request_context():
            with patch('api_gateway.websocket.request') as mock_request, \
                 patch('api_gateway.websocket.join_room'), \
                 patch('api_gateway.websocket.emit') as mock_emit:
                
                # First client subscribes
                mock_request.sid = 'client-1'
                handle_subscribe_scan({'scan_id': 'scan-abc'})
                
                # Second client subscribes
                mock_request.sid = 'client-2'
                handle_subscribe_scan({'scan_id': 'scan-abc'})
                
                # Should have 2 subscribers
                assert len(scan_rooms['scan-abc']) == 2
                assert 'client-1' in scan_rooms['scan-abc']
                assert 'client-2' in scan_rooms['scan-abc']
                
                # Last emit should show room_size=2
                last_call = mock_emit.call_args[0]
                assert last_call[1]['room_size'] == 2

    def test_subscribe_scan_missing_scan_id(self, app):
        """Test subscription without scan_id"""
        from api_gateway.websocket import handle_subscribe_scan
        
        scan_rooms.clear()
        
        with app.test_request_context():
            with patch('api_gateway.websocket.request') as mock_request, \
                 patch('api_gateway.websocket.join_room') as mock_join, \
                 patch('api_gateway.websocket.emit') as mock_emit:
                
                mock_request.sid = 'client-123'
                data = {}  # Missing scan_id
                
                handle_subscribe_scan(data)
                
                # Should NOT join room
                mock_join.assert_not_called()
                
                # Should emit error
                mock_emit.assert_called_once()
                args = mock_emit.call_args[0]
                assert args[0] == 'subscription_error'
                assert 'error' in args[1]

    def test_unsubscribe_scan_success(self, app):
        """Test successful scan unsubscription"""
        from api_gateway.websocket import handle_unsubscribe_scan
        
        # Setup: client already subscribed
        scan_rooms.clear()
        scan_rooms['scan-abc'] = {'client-123'}
        
        with app.test_request_context():
            with patch('api_gateway.websocket.request') as mock_request, \
                 patch('api_gateway.websocket.leave_room') as mock_leave, \
                 patch('api_gateway.websocket.emit') as mock_emit:
                
                mock_request.sid = 'client-123'
                data = {'scan_id': 'scan-abc'}
                
                handle_unsubscribe_scan(data)
                
                # Should leave room
                mock_leave.assert_called_once_with('scan-abc')
                
                # Should remove tracking
                assert 'scan-abc' not in scan_rooms  # Room deleted when empty
                
                # Should emit confirmation
                mock_emit.assert_called_once()
                args = mock_emit.call_args[0]
                assert args[0] == 'unsubscription_confirmed'
                assert args[1]['scan_id'] == 'scan-abc'

    def test_unsubscribe_scan_keep_room_with_other_clients(self, app):
        """Test unsubscription keeps room with remaining clients"""
        from api_gateway.websocket import handle_unsubscribe_scan
        
        # Setup: multiple clients in room
        scan_rooms.clear()
        scan_rooms['scan-abc'] = {'client-1', 'client-2'}
        
        with app.test_request_context():
            with patch('api_gateway.websocket.request') as mock_request, \
                 patch('api_gateway.websocket.leave_room'), \
                 patch('api_gateway.websocket.emit'):
                
                mock_request.sid = 'client-1'
                
                handle_unsubscribe_scan({'scan_id': 'scan-abc'})
                
                # Should keep room with remaining client
                assert 'scan-abc' in scan_rooms
                assert scan_rooms['scan-abc'] == {'client-2'}

    def test_unsubscribe_scan_missing_scan_id(self, app):
        """Test unsubscription without scan_id"""
        from api_gateway.websocket import handle_unsubscribe_scan
        
        scan_rooms.clear()
        
        with app.test_request_context():
            with patch('api_gateway.websocket.request') as mock_request, \
                 patch('api_gateway.websocket.leave_room') as mock_leave:
                
                mock_request.sid = 'client-123'
                data = {}  # Missing scan_id
                
                handle_unsubscribe_scan(data)
                
                # Should not leave any room
                mock_leave.assert_not_called()

    def test_unsubscribe_scan_not_in_room(self, app):
        """Test unsubscription when client not in room"""
        from api_gateway.websocket import handle_unsubscribe_scan
        
        scan_rooms.clear()
        scan_rooms['scan-abc'] = {'client-other'}
        
        with app.test_request_context():
            with patch('api_gateway.websocket.request') as mock_request, \
                 patch('api_gateway.websocket.leave_room'), \
                 patch('api_gateway.websocket.emit'):
                
                mock_request.sid = 'client-123'  # Not in room
                
                # Should not raise error
                handle_unsubscribe_scan({'scan_id': 'scan-abc'})
                
                # Room should be unchanged
                assert scan_rooms['scan-abc'] == {'client-other'}


class TestPingHandler:
    """Test WebSocket ping/pong keepalive"""

    def test_handle_ping(self):
        """Test ping handler responds with pong"""
        from api_gateway.websocket import handle_ping
        
        with patch('api_gateway.websocket.emit') as mock_emit:
            handle_ping()
            
            # Should emit pong with timestamp
            mock_emit.assert_called_once()
            args = mock_emit.call_args[0]
            assert args[0] == 'pong'
            assert 'timestamp' in args[1]


class TestEventEmission:
    """Test scan event emission functions"""

    def test_emit_scan_event_success(self):
        """Test successful event emission to room"""
        scan_rooms.clear()
        scan_rooms['scan-123'] = {'client-1', 'client-2'}
        
        with patch('api_gateway.websocket.socketio') as mock_socketio:
            emit_scan_event('scan-123', 'test_event', {'data': 'value'})
            
            # Should emit to room
            mock_socketio.emit.assert_called_once()
            call_args = mock_socketio.emit.call_args
            
            assert call_args[0][0] == 'test_event'  # Event type
            assert call_args[1]['room'] == 'scan-123'
            
            # Check payload
            payload = call_args[0][1]
            assert payload['data'] == 'value'
            assert payload['scan_id'] == 'scan-123'
            assert payload['event_type'] == 'test_event'
            assert 'timestamp' in payload

    def test_emit_scan_event_no_subscribers(self):
        """Test event emission with no subscribers"""
        scan_rooms.clear()
        
        with patch('api_gateway.websocket.socketio') as mock_socketio:
            # Should not raise error
            emit_scan_event('scan-999', 'test_event', {})
            
            # Should still emit (room might exist without tracking)
            mock_socketio.emit.assert_called_once()

    def test_emit_scan_event_exception_handling(self):
        """Test event emission handles exceptions gracefully"""
        scan_rooms.clear()
        
        with patch('api_gateway.websocket.socketio') as mock_socketio:
            mock_socketio.emit.side_effect = Exception("Connection lost")
            
            # Should not raise exception
            emit_scan_event('scan-123', 'test_event', {})
            
            # Should have attempted emission
            mock_socketio.emit.assert_called_once()

    def test_emit_scan_queued(self):
        """Test emit_scan_queued helper"""
        with patch('api_gateway.websocket.emit_scan_event') as mock_emit:
            emit_scan_queued('scan-123', '192.168.1.1', 'nmap')
            
            mock_emit.assert_called_once_with(
                'scan-123',
                'scan_queued',
                {'status': 'queued', 'target': '192.168.1.1', 'tool_name': 'nmap'}
            )

    def test_emit_scan_started(self):
        """Test emit_scan_started helper"""
        with patch('api_gateway.websocket.emit_scan_event') as mock_emit:
            emit_scan_started('scan-456', 'example.com', 'nuclei')
            
            mock_emit.assert_called_once_with(
                'scan-456',
                'scan_started',
                {
                    'status': 'running',
                    'target': 'example.com',
                    'tool_name': 'nuclei',
                    'progress': 0
                }
            )

    def test_emit_scan_progress(self):
        """Test emit_scan_progress helper"""
        with patch('api_gateway.websocket.emit_scan_event') as mock_emit:
            emit_scan_progress('scan-789', 50, 'Scanning ports...')
            
            mock_emit.assert_called_once_with(
                'scan-789',
                'scan_progress',
                {
                    'status': 'running',
                    'progress': 50,
                    'message': 'Scanning ports...'
                }
            )

    def test_emit_scan_progress_no_message(self):
        """Test emit_scan_progress without message"""
        with patch('api_gateway.websocket.emit_scan_event') as mock_emit:
            emit_scan_progress('scan-789', 75)
            
            mock_emit.assert_called_once()
            call_args = mock_emit.call_args[0]
            assert call_args[2]['message'] == ''

    def test_emit_scan_completed(self):
        """Test emit_scan_completed helper"""
        with patch('api_gateway.websocket.emit_scan_event') as mock_emit:
            emit_scan_completed('scan-abc', results_count=42, execution_time=120)
            
            mock_emit.assert_called_once_with(
                'scan-abc',
                'scan_completed',
                {
                    'status': 'completed',
                    'progress': 100,
                    'results_count': 42,
                    'execution_time': 120
                }
            )

    def test_emit_scan_completed_defaults(self):
        """Test emit_scan_completed with default values"""
        with patch('api_gateway.websocket.emit_scan_event') as mock_emit:
            emit_scan_completed('scan-abc')
            
            mock_emit.assert_called_once()
            call_args = mock_emit.call_args[0]
            assert call_args[2]['results_count'] == 0
            assert call_args[2]['execution_time'] == 0

    def test_emit_scan_failed(self):
        """Test emit_scan_failed helper"""
        with patch('api_gateway.websocket.emit_scan_event') as mock_emit:
            emit_scan_failed('scan-xyz', 'Connection timeout')
            
            mock_emit.assert_called_once_with(
                'scan-xyz',
                'scan_failed',
                {
                    'status': 'failed',
                    'error': 'Connection timeout'
                }
            )


class TestRoomStats:
    """Test room statistics tracking"""

    def test_get_room_stats_empty(self):
        """Test stats with no active rooms"""
        scan_rooms.clear()
        
        stats = get_room_stats()
        
        assert stats['total_rooms'] == 0
        assert stats['total_subscribers'] == 0
        assert stats['rooms'] == {}

    def test_get_room_stats_multiple_rooms(self):
        """Test stats with multiple active rooms"""
        scan_rooms.clear()
        scan_rooms['scan-1'] = {'client-a', 'client-b'}
        scan_rooms['scan-2'] = {'client-c'}
        scan_rooms['scan-3'] = {'client-d', 'client-e', 'client-f'}
        
        stats = get_room_stats()
        
        assert stats['total_rooms'] == 3
        assert stats['total_subscribers'] == 6
        assert stats['rooms']['scan-1'] == 2
        assert stats['rooms']['scan-2'] == 1
        assert stats['rooms']['scan-3'] == 3

    def test_get_room_stats_single_room(self):
        """Test stats with single room"""
        scan_rooms.clear()
        scan_rooms['scan-only'] = {'client-1'}
        
        stats = get_room_stats()
        
        assert stats['total_rooms'] == 1
        assert stats['total_subscribers'] == 1
        assert stats['rooms']['scan-only'] == 1
