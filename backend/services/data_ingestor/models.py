"""
Database Models

SQLAlchemy models for storing scan data and results.

Author: NTRO Security Team
Date: 2025-10-22
"""

from datetime import datetime
from enum import Enum
from typing import Optional
import os

from sqlalchemy import JSON, Column, DateTime, Enum as SQLEnum, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker

Base = declarative_base()


# Create a module-level SQLAlchemy engine and session factory.
# Use DATABASE_URL from environment (required for production).
# For development, it defaults to PostgreSQL on localhost.
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/vulnerability_scanner"
)

# PostgreSQL doesn't need check_same_thread parameter (that's SQLite-specific)
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_session():
    """Return a new SQLAlchemy session from the module-level SessionLocal."""
    return SessionLocal()


class ScanStatus(str, Enum):
    """Scan status enumeration"""
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Scan(Base):
    """
    Scan model representing a security scan job
    """
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True)
    target = Column(String(255), nullable=False, index=True)
    tool_name = Column(String(50), nullable=False, index=True)
    scan_type = Column(String(50), nullable=False)
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING, nullable=False, index=True)
    priority = Column(String(20), default="normal")
    options = Column(JSON, default=dict)
    tags = Column(JSON, default=list)
    
    # QA Issue #5: Optimistic locking for concurrency control
    version = Column(Integer, default=1, nullable=False)
    
    # Job tracking
    job_id = Column(String(100), nullable=True, index=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    queued_at = Column(DateTime, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    # Results
    error_message = Column(Text, nullable=True)
    
    # Relationships
    raw_results = relationship("RawScanResult", back_populates="scan", cascade="all, delete-orphan")
    summary = relationship("ScanSummary", back_populates="scan", uselist=False, cascade="all, delete-orphan")

    @property
    def progress(self) -> int:
        """Calculate scan progress percentage"""
        if self.status == ScanStatus.COMPLETED:
            return 100
        elif self.status == ScanStatus.FAILED or self.status == ScanStatus.CANCELLED:
            return 0
        elif self.status == ScanStatus.RUNNING:
            return 50  # Assume halfway through
        return 0

    @property
    def execution_time(self) -> Optional[int]:
        """Calculate execution time in seconds"""
        if self.started_at and self.completed_at:
            return int((self.completed_at - self.started_at).total_seconds())
        return None
    
    def to_dict(self):
        """Convert scan to dictionary for API responses"""
        return {
            'id': self.id,
            'scan_id': self.id,  # Alias for compatibility
            'target': self.target,
            'tool_name': self.tool_name,
            'scan_type': self.scan_type,
            'status': self.status.value if isinstance(self.status, Enum) else self.status,
            'progress': self.progress,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'execution_time': self.execution_time,
            'error_message': self.error_message,
            'options': self.options
        }

    def __repr__(self):
        return f"<Scan(id={self.id}, target={self.target}, tool={self.tool_name}, status={self.status})>"


class RawScanResult(Base):
    """
    Raw scan result model for storing unprocessed scan output
    """
    __tablename__ = "raw_scan_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    tool_name = Column(String(50), nullable=False)
    raw_output = Column(Text, nullable=False)
    output_format = Column(String(20), default="text")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationship
    scan = relationship("Scan", back_populates="raw_results")
    
    @property
    def timestamp(self):
        """Alias for created_at for compatibility"""
        return self.created_at
    
    @property
    def parsed_output(self):
        """Placeholder for parsed output - actual parsing done by summaries"""
        return None
    
    @property
    def file_size(self):
        """Calculate file size of raw_output"""
        if self.raw_output:
            return len(self.raw_output.encode('utf-8') if isinstance(self.raw_output, str) else self.raw_output)
        return 0

    def __repr__(self):
        return f"<RawScanResult(id={self.id}, scan_id={self.scan_id}, tool={self.tool_name})>"


class ScanSummary(Base):
    """
    Scan summary model for aggregated scan statistics
    """
    __tablename__ = "scan_summaries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    
    # Statistics
    total_hosts = Column(Integer, default=0)
    total_ports = Column(Integer, default=0)
    total_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    
    # AI-generated summary
    ai_summary = Column(JSON)  # Stores AI-generated summary (title, summary, risk_level, etc.)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    scan = relationship("Scan", back_populates="summary")

    def __repr__(self):
        return f"<ScanSummary(scan_id={self.scan_id}, vulns={self.total_vulnerabilities})>"


# Utility functions

def create_tables(engine):
    """
    Create all tables in the database
    
    Args:
        engine: SQLAlchemy engine instance
    """
    Base.metadata.create_all(bind=engine)


def drop_tables(engine):
    """
    Drop all tables from the database
    
    Args:
        engine: SQLAlchemy engine instance
    """
    Base.metadata.drop_all(bind=engine)
