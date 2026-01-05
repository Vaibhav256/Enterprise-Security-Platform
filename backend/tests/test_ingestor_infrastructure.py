"""
Tests for Data Ingestor

Tests ingestor initialization and database setup.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock


class TestIngestorInit:
    """Test DataIngestor initialization"""
    
    @patch('services.data_ingestor.ingestor.create_engine')
    @patch('services.data_ingestor.ingestor.sessionmaker')
    @patch('services.data_ingestor.ingestor.Base')
    def test_init_creates_engine(self, mock_base, mock_sessionmaker, mock_create_engine):
        """Test that init creates SQLAlchemy engine"""
        from services.data_ingestor.ingestor import DataIngestor
        
        mock_engine = Mock()
        mock_create_engine.return_value = mock_engine
        
        ingestor = DataIngestor(database_url='postgresql://user:pass@localhost/db')
        
        # Verify engine created with pool_pre_ping
        mock_create_engine.assert_called_once()
        args, kwargs = mock_create_engine.call_args
        assert args[0] == 'postgresql://user:pass@localhost/db'
        assert kwargs.get('pool_pre_ping') == True
        
        assert ingestor.engine == mock_engine
        
    @patch('services.data_ingestor.ingestor.create_engine')
    @patch('services.data_ingestor.ingestor.sessionmaker')
    @patch('services.data_ingestor.ingestor.Base')
    def test_init_creates_session_maker(self, mock_base, mock_sessionmaker, mock_create_engine):
        """Test that init creates sessionmaker"""
        from services.data_ingestor.ingestor import DataIngestor
        
        mock_engine = Mock()
        mock_create_engine.return_value = mock_engine
        mock_session_class = Mock()
        mock_sessionmaker.return_value = mock_session_class
        
        ingestor = DataIngestor(database_url='postgresql://test')
        
        # Verify sessionmaker created with correct settings
        mock_sessionmaker.assert_called_once_with(
            autocommit=False,
            autoflush=False,
            bind=mock_engine
        )
        
        assert ingestor.SessionLocal == mock_session_class
        
    @patch('services.data_ingestor.ingestor.create_engine')
    @patch('services.data_ingestor.ingestor.sessionmaker')
    @patch('services.data_ingestor.ingestor.Base')
    def test_init_creates_tables(self, mock_base, mock_sessionmaker, mock_create_engine):
        """Test that init creates database tables"""
        from services.data_ingestor.ingestor import DataIngestor
        
        mock_engine = Mock()
        mock_create_engine.return_value = mock_engine
        mock_metadata = Mock()
        mock_base.metadata = mock_metadata
        
        ingestor = DataIngestor(database_url='postgresql://test')
        
        # Verify tables created
        mock_metadata.create_all.assert_called_once_with(mock_engine)
        
    @patch('services.data_ingestor.ingestor.create_engine')
    @patch('services.data_ingestor.ingestor.sessionmaker')
    @patch('services.data_ingestor.ingestor.Base')
    def test_get_session(self, mock_base, mock_sessionmaker, mock_create_engine):
        """Test get_session returns a session instance"""
        from services.data_ingestor.ingestor import DataIngestor
        
        mock_engine = Mock()
        mock_create_engine.return_value = mock_engine
        
        mock_session = Mock()
        mock_session_class = Mock(return_value=mock_session)
        mock_sessionmaker.return_value = mock_session_class
        
        ingestor = DataIngestor(database_url='postgresql://test')
        
        session = ingestor.get_session()
        
        # Verify session created
        mock_session_class.assert_called_once()
        assert session == mock_session


class TestIngestorHelperFunction:
    """Test helper function for creating ingestor from config"""
    
    def test_create_ingestor_from_config_exists(self):
        """Test create_ingestor_from_config function exists"""
        from services.data_ingestor.ingestor import create_ingestor_from_config
        
        assert create_ingestor_from_config is not None
        assert callable(create_ingestor_from_config)
