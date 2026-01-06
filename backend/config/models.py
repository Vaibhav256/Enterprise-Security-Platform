"""
Database Models

SQLAlchemy models for the vulnerability scanner database.

Author: NTRO Security Team
Date: 2025-10-31
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import (
    Column, String, Integer, DateTime, Text, 
    DECIMAL, ARRAY, JSON, ForeignKey, Index
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import uuid

Base = declarative_base()


class FeedEntry(Base):
    """
    Threat Intelligence Feed Entry Model
    
    Stores threat intelligence data from various sources (NVD, ExploitDB, etc.)
    in the database instead of JSON files for better querying and persistence.
    """
    __tablename__ = 'feed_entries'
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Feed metadata
    feed_source = Column(String(50), nullable=False, index=True)  # 'nvd', 'exploitdb', etc.
    feed_type = Column(String(50), nullable=False)  # 'cve', 'exploit', etc.
    
    # Entry identification
    entry_id = Column(String(100), nullable=False, index=True)  # CVE-2024-1234, EDB-12345
    title = Column(String(500), nullable=False)
    description = Column(Text)
    
    # Severity and scoring
    severity = Column(String(20), index=True)  # 'critical', 'high', 'medium', 'low', 'info' - indexed for filtering
    cvss_score = Column(DECIMAL(3, 1))
    cvss_vector = Column(String(200))
    
    # Vulnerability details
    affected_products = Column(ARRAY(String))  # List of affected products/versions
    cwe_ids = Column(ARRAY(String))  # Common Weakness Enumeration IDs
    ref_urls = Column(ARRAY(String))  # URLs to references
    
    # Exploit information
    exploit_available = Column(String(10))  # 'yes', 'no', 'unknown'
    exploit_type = Column(String(50))  # 'remote', 'local', 'webapps', etc.
    exploit_platform = Column(String(50))  # 'linux', 'windows', 'multiple', etc.
    
    # Temporal data
    published_date = Column(DateTime, index=True)
    modified_date = Column(DateTime)
    discovered_date = Column(DateTime)
    
    # Additional feed data (flexible JSON field mapped from database 'metadata' column)
    feed_entry_data = Column('metadata', JSON)  # Maps to 'metadata' column in database
    
    # Tracking
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Indexes for common queries
    __table_args__ = (
        Index('idx_feed_source_type', 'feed_source', 'feed_type'),
        Index('idx_entry_id', 'entry_id'),
        Index('idx_severity', 'severity'),
        Index('idx_published_date', 'published_date'),
        Index('idx_cvss_score', 'cvss_score'),
    )
    
    def __repr__(self):
        return f"<FeedEntry(entry_id='{self.entry_id}', source='{self.feed_source}', severity='{self.severity}')>"
    
    def to_dict(self):
        """Convert model to dictionary for API responses"""
        return {
            'id': str(self.id),
            'feed_source': self.feed_source,
            'feed_type': self.feed_type,
            'entry_id': self.entry_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'cvss_score': float(self.cvss_score) if self.cvss_score else None,
            'cvss_vector': self.cvss_vector,
            'affected_products': self.affected_products,
            'cwe_ids': self.cwe_ids,
            'ref_urls': self.ref_urls,
            'exploit_available': self.exploit_available,
            'exploit_type': self.exploit_type,
            'exploit_platform': self.exploit_platform,
            'published_date': self.published_date.isoformat() if self.published_date else None,
            'modified_date': self.modified_date.isoformat() if self.modified_date else None,
            'discovered_date': self.discovered_date.isoformat() if self.discovered_date else None,
            'feed_entry_data': self.feed_entry_data,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class Scan(Base):
    """Scan model (for reference, already exists in database.py)"""
    __tablename__ = 'scans'
    
    id = Column(String(36), primary_key=True)
    target = Column(String(255), nullable=False)
    tool_name = Column(String(50), nullable=False)
    scan_type = Column(String(50), nullable=False)
    status = Column(String(50), default='pending')
    priority = Column(String(20), default='medium')
    created_at = Column(DateTime, default=datetime.utcnow)
    queued_at = Column(DateTime)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    error_message = Column(Text)
    job_id = Column(String(100))
    options = Column(JSON)
    tags = Column(JSON)
    
    # Relationships
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Scan(id='{self.id}', tool='{self.tool_name}', status='{self.status}')>"


class Vulnerability(Base):
    """Vulnerability model (for reference, already exists in database.py)"""
    __tablename__ = 'vulnerabilities'
    
    vuln_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(String(36), ForeignKey('scans.id', ondelete='CASCADE'), index=True)  # Explicit index for FK queries
    severity = Column(String(20), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    cvss_score = Column(DECIMAL(3, 1))
    cve_id = Column(String(50))
    port = Column(Integer)
    protocol = Column(String(10))
    service = Column(String(100))
    solution = Column(Text)
    references = Column(ARRAY(String))
    discovered_at = Column(DateTime, default=datetime.utcnow)
    vuln_data = Column('metadata', JSON)  # Map to 'metadata' column in database (metadata is reserved in SQLAlchemy)
    
    # Relationships
    scan = relationship("Scan", back_populates="vulnerabilities")
    
    def __repr__(self):
        return f"<Vulnerability(cve_id='{self.cve_id}', severity='{self.severity}')>"
