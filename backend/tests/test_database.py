"""
Comprehensive tests for Database Configuration Module

Tests database connection pooling, connection management, and initialization.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock, call
import os

# Import the module
from config.database import (
    DatabaseConfig,
    get_db_connection,
    release_db_connection,
    test_connection,
    get_db_version,
    init_database
)


class TestDatabaseConfig:
    """Tests for DatabaseConfig class"""

    def setup_method(self):
        """Reset connection pool before each test"""
        DatabaseConfig._connection_pool = None

    def teardown_method(self):
        """Clean up after each test"""
        DatabaseConfig._connection_pool = None

    @patch('config.database.pool.SimpleConnectionPool')
    @patch.dict(os.environ, {'DATABASE_URL': 'postgresql://test:test@localhost:5432/testdb'})
    def test_get_connection_pool_creates_pool(self, mock_pool_class):
        """Test that connection pool is created with correct parameters"""
        mock_pool = Mock()
        mock_pool_class.return_value = mock_pool

        result = DatabaseConfig.get_connection_pool()

        assert result == mock_pool
        mock_pool_class.assert_called_once_with(
            minconn=1,
            maxconn=10,
            dsn='postgresql://test:test@localhost:5432/testdb'
        )

    @patch('config.database.pool.SimpleConnectionPool')
    @patch.dict(os.environ, {}, clear=True)
    def test_get_connection_pool_default_url(self, mock_pool_class):
        """Test connection pool uses default URL when DATABASE_URL not set"""
        mock_pool = Mock()
        mock_pool_class.return_value = mock_pool

        DatabaseConfig.get_connection_pool()

        # Check that default URL was used
        call_args = mock_pool_class.call_args
        assert 'postgresql://postgres:postgres@localhost:5432/vulnerability_scanner' in str(call_args)

    @patch('config.database.pool.SimpleConnectionPool')
    def test_get_connection_pool_reuses_existing(self, mock_pool_class):
        """Test that existing pool is reused"""
        mock_pool = Mock()
        mock_pool_class.return_value = mock_pool

        # First call creates pool
        pool1 = DatabaseConfig.get_connection_pool()
        # Second call should reuse
        pool2 = DatabaseConfig.get_connection_pool()

        assert pool1 == pool2
        assert mock_pool_class.call_count == 1

    @patch('config.database.pool.SimpleConnectionPool')
    def test_get_connection_pool_error_handling(self, mock_pool_class):
        """Test error handling when pool creation fails"""
        mock_pool_class.side_effect = Exception("Connection failed")

        with pytest.raises(Exception, match="Connection failed"):
            DatabaseConfig.get_connection_pool()

    @patch('config.database.pool.SimpleConnectionPool')
    def test_close_pool_closes_connections(self, mock_pool_class):
        """Test that close_pool closes all connections"""
        mock_pool = Mock()
        mock_pool_class.return_value = mock_pool

        # Create pool
        DatabaseConfig.get_connection_pool()
        
        # Close pool
        DatabaseConfig.close_pool()

        mock_pool.closeall.assert_called_once()
        assert DatabaseConfig._connection_pool is None

    def test_close_pool_when_no_pool(self):
        """Test close_pool when no pool exists"""
        DatabaseConfig._connection_pool = None
        
        # Should not raise error
        DatabaseConfig.close_pool()
        
        assert DatabaseConfig._connection_pool is None


class TestConnectionFunctions:
    """Tests for connection management functions"""

    def setup_method(self):
        """Reset connection pool before each test"""
        DatabaseConfig._connection_pool = None

    def teardown_method(self):
        """Clean up after each test"""
        DatabaseConfig._connection_pool = None

    @patch('config.database.DatabaseConfig.get_connection_pool')
    def test_get_db_connection_success(self, mock_get_pool):
        """Test successful connection retrieval"""
        mock_conn = Mock()
        mock_pool = Mock()
        mock_pool.getconn.return_value = mock_conn
        mock_get_pool.return_value = mock_pool

        result = get_db_connection()

        assert result == mock_conn
        mock_pool.getconn.assert_called_once()

    @patch('config.database.DatabaseConfig.get_connection_pool')
    def test_get_db_connection_error(self, mock_get_pool):
        """Test error handling in get_db_connection"""
        mock_pool = Mock()
        mock_pool.getconn.side_effect = Exception("Pool exhausted")
        mock_get_pool.return_value = mock_pool

        with pytest.raises(Exception, match="Pool exhausted"):
            get_db_connection()

    @patch('config.database.DatabaseConfig.get_connection_pool')
    def test_release_db_connection_success(self, mock_get_pool):
        """Test successful connection release"""
        mock_conn = Mock()
        mock_pool = Mock()
        mock_get_pool.return_value = mock_pool

        release_db_connection(mock_conn)

        mock_pool.putconn.assert_called_once_with(mock_conn)

    @patch('config.database.DatabaseConfig.get_connection_pool')
    def test_release_db_connection_error(self, mock_get_pool):
        """Test error handling in release_db_connection"""
        mock_conn = Mock()
        mock_pool = Mock()
        mock_pool.putconn.side_effect = Exception("Release failed")
        mock_get_pool.return_value = mock_pool

        # Should not raise error, just prints
        release_db_connection(mock_conn)

        mock_pool.putconn.assert_called_once_with(mock_conn)


class TestDatabaseUtilities:
    """Tests for database utility functions"""

    def setup_method(self):
        """Reset connection pool before each test"""
        DatabaseConfig._connection_pool = None

    def teardown_method(self):
        """Clean up after each test"""
        DatabaseConfig._connection_pool = None

    @patch('config.database.release_db_connection')
    @patch('config.database.get_db_connection')
    def test_test_connection_success(self, mock_get_conn, mock_release):
        """Test successful connection test"""
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (1,)
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        result = test_connection()

        assert result is True
        mock_cursor.execute.assert_called_once_with("SELECT 1")
        mock_cursor.close.assert_called_once()
        mock_release.assert_called_once_with(mock_conn)

    @patch('config.database.get_db_connection')
    def test_test_connection_failure(self, mock_get_conn):
        """Test connection test failure"""
        mock_get_conn.side_effect = Exception("Connection refused")

        result = test_connection()

        assert result is False

    @patch('config.database.release_db_connection')
    @patch('config.database.get_db_connection')
    def test_test_connection_query_error(self, mock_get_conn, mock_release):
        """Test connection test with query error"""
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_cursor.execute.side_effect = Exception("Query failed")
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        result = test_connection()

        assert result is False

    @patch('config.database.release_db_connection')
    @patch('config.database.get_db_connection')
    def test_get_db_version_success(self, mock_get_conn, mock_release):
        """Test successful database version retrieval"""
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = ('PostgreSQL 14.5',)
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        result = get_db_version()

        assert result == 'PostgreSQL 14.5'
        mock_cursor.execute.assert_called_once_with("SELECT version()")
        mock_cursor.close.assert_called_once()
        mock_release.assert_called_once_with(mock_conn)

    @patch('config.database.get_db_connection')
    def test_get_db_version_error(self, mock_get_conn):
        """Test database version retrieval error"""
        mock_get_conn.side_effect = Exception("Connection failed")

        result = get_db_version()

        assert result is None

    @patch('config.database.release_db_connection')
    @patch('config.database.get_db_connection')
    def test_get_db_version_no_result(self, mock_get_conn, mock_release):
        """Test database version when no result returned"""
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = None
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        result = get_db_version()

        assert result is None


class TestDatabaseInitialization:
    """Tests for database initialization"""

    def setup_method(self):
        """Reset connection pool before each test"""
        DatabaseConfig._connection_pool = None

    def teardown_method(self):
        """Clean up after each test"""
        DatabaseConfig._connection_pool = None

    @patch('config.database.release_db_connection')
    @patch('config.database.get_db_connection')
    def test_init_database_success(self, mock_get_conn, mock_release):
        """Test successful database initialization"""
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        init_database()

        # Verify all tables are created
        execute_calls = mock_cursor.execute.call_args_list
        assert any('CREATE TABLE IF NOT EXISTS scans' in str(call) for call in execute_calls)
        assert any('CREATE TABLE IF NOT EXISTS vulnerabilities' in str(call) for call in execute_calls)
        assert any('CREATE TABLE IF NOT EXISTS scan_history' in str(call) for call in execute_calls)
        
        # Verify indexes are created
        assert any('CREATE INDEX IF NOT EXISTS idx_scans_status' in str(call) for call in execute_calls)
        assert any('CREATE INDEX IF NOT EXISTS idx_vulns_scan' in str(call) for call in execute_calls)

        # Verify commit and cleanup
        mock_conn.commit.assert_called_once()
        mock_cursor.close.assert_called_once()
        mock_release.assert_called_once_with(mock_conn)

    @patch('config.database.release_db_connection')
    @patch('config.database.get_db_connection')
    def test_init_database_error_rollback(self, mock_get_conn, mock_release):
        """Test database initialization error triggers rollback"""
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_cursor.execute.side_effect = Exception("Table creation failed")
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        with pytest.raises(Exception, match="Table creation failed"):
            init_database()

        # Verify rollback was called
        mock_conn.rollback.assert_called_once()
        mock_release.assert_called_once_with(mock_conn)

    @patch('config.database.release_db_connection')
    @patch('config.database.get_db_connection')
    def test_init_database_creates_scans_table(self, mock_get_conn, mock_release):
        """Test that scans table is created with correct columns"""
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        init_database()

        # Find the CREATE TABLE scans call
        execute_calls = [str(call) for call in mock_cursor.execute.call_args_list]
        scans_table_call = next((call for call in execute_calls if 'CREATE TABLE IF NOT EXISTS scans' in call), None)
        
        assert scans_table_call is not None
        assert 'id VARCHAR(36) PRIMARY KEY' in scans_table_call
        assert 'target VARCHAR' in scans_table_call
        assert 'tool_name VARCHAR' in scans_table_call
        assert 'status VARCHAR' in scans_table_call

    @patch('config.database.release_db_connection')
    @patch('config.database.get_db_connection')
    def test_init_database_creates_vulnerabilities_table(self, mock_get_conn, mock_release):
        """Test that vulnerabilities table is created with foreign key"""
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        init_database()

        # Find the CREATE TABLE vulnerabilities call
        execute_calls = [str(call) for call in mock_cursor.execute.call_args_list]
        vulns_table_call = next((call for call in execute_calls if 'CREATE TABLE IF NOT EXISTS vulnerabilities' in call), None)
        
        assert vulns_table_call is not None
        assert 'vuln_id UUID PRIMARY KEY' in vulns_table_call
        assert 'scan_id VARCHAR(36) REFERENCES scans(id)' in vulns_table_call
        assert 'severity VARCHAR' in vulns_table_call
        assert 'cvss_score DECIMAL' in vulns_table_call

    @patch('config.database.release_db_connection')
    @patch('config.database.get_db_connection')
    def test_init_database_creates_all_indexes(self, mock_get_conn, mock_release):
        """Test that all required indexes are created"""
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        init_database()

        execute_calls = [str(call) for call in mock_cursor.execute.call_args_list]
        
        # Verify all indexes
        assert any('idx_scans_status' in call for call in execute_calls)
        assert any('idx_scans_tool' in call for call in execute_calls)
        assert any('idx_scans_created' in call for call in execute_calls)
        assert any('idx_vulns_scan' in call for call in execute_calls)
        assert any('idx_vulns_severity' in call for call in execute_calls)


class TestEdgeCases:
    """Tests for edge cases and error conditions"""

    def setup_method(self):
        """Reset connection pool before each test"""
        DatabaseConfig._connection_pool = None

    def teardown_method(self):
        """Clean up after each test"""
        DatabaseConfig._connection_pool = None

    @patch('config.database.pool.SimpleConnectionPool')
    def test_multiple_pool_creations_and_closes(self, mock_pool_class):
        """Test creating and closing pool multiple times"""
        mock_pool = Mock()
        mock_pool_class.return_value = mock_pool

        # Create and close multiple times
        for _ in range(3):
            DatabaseConfig.get_connection_pool()
            DatabaseConfig.close_pool()

        # Should have created pool 3 times (once per cycle)
        assert mock_pool_class.call_count == 3
        assert mock_pool.closeall.call_count == 3

    @patch('config.database.release_db_connection')
    @patch('config.database.get_db_connection')
    def test_test_connection_with_none_result(self, mock_get_conn, mock_release):
        """Test connection test when query returns None"""
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = None
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        result = test_connection()

        assert result is False

    @patch('config.database.release_db_connection')
    @patch('config.database.get_db_connection')
    def test_test_connection_with_wrong_result(self, mock_get_conn, mock_release):
        """Test connection test when query returns unexpected value"""
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = (0,)  # Wrong value
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        result = test_connection()

        assert result is False


class TestDatabaseModuleInit:
    '''Test database module initialization'''
    
    def test_module_loads_without_errors(self):
        '''Test module can be imported successfully'''
        import config.database
        assert config.database is not None
