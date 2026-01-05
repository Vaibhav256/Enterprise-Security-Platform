"""
Database Configuration and Connection Management

This module provides database connection utilities for PostgreSQL.

Author: NTRO Security Team
Date: 2025-10-26
"""

import os
from typing import Optional

from dotenv import load_dotenv
from psycopg2 import pool

# Load environment variables
load_dotenv()


class DatabaseConfig:
    """Database configuration and connection pool"""

    _connection_pool: Optional[pool.SimpleConnectionPool] = None

    @classmethod
    def get_connection_pool(cls):
        """Get or create connection pool"""
        if cls._connection_pool is None:
            database_url = os.getenv(
                "DATABASE_URL",
                "postgresql://postgres:postgres@localhost:5432/vulnerability_scanner",
            )

            try:
                cls._connection_pool = pool.SimpleConnectionPool(
                    minconn=1, maxconn=10, dsn=database_url
                )
            except Exception as e:
                print(f"Error creating connection pool: {e}")
                raise

        return cls._connection_pool

    @classmethod
    def close_pool(cls):
        """Close all connections in the pool"""
        if cls._connection_pool:
            cls._connection_pool.closeall()
            cls._connection_pool = None


def get_db_connection():
    """
    Get a database connection from the pool

    Returns:
        psycopg2.connection: Database connection
    """
    try:
        pool = DatabaseConfig.get_connection_pool()
        conn = pool.getconn()
        return conn
    except Exception as e:
        print(f"Error getting database connection: {e}")
        raise


def release_db_connection(conn):
    """
    Release a database connection back to the pool

    Args:
        conn: Database connection to release
    """
    try:
        pool = DatabaseConfig.get_connection_pool()
        pool.putconn(conn)
    except Exception as e:
        print(f"Error releasing database connection: {e}")


def test_connection() -> bool:
    """
    Test database connectivity

    Returns:
        bool: True if connection successful, False otherwise
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        result = cursor.fetchone()
        cursor.close()
        release_db_connection(conn)
        return bool(result and result[0] == 1)
    except Exception as e:
        print(f"Database connection test failed: {e}")
        return False


def get_db_version() -> Optional[str]:
    """
    Get PostgreSQL version

    Returns:
        str: Database version or None if error
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT version()")
        version = cursor.fetchone()
        cursor.close()
        release_db_connection(conn)
        return str(version[0]) if version else None
    except Exception as e:
        print(f"Error getting database version: {e}")
        return None


def init_database():
    """
    Initialize database schema
    Creates all required tables if they don't exist
    """
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Create scans table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id VARCHAR(36) PRIMARY KEY,
                target VARCHAR(255) NOT NULL,
                tool_name VARCHAR(50) NOT NULL,
                scan_type VARCHAR(50) NOT NULL,
                status VARCHAR(50) DEFAULT 'pending',
                priority VARCHAR(20) DEFAULT 'medium',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                queued_at TIMESTAMP,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                error_message TEXT,
                job_id VARCHAR(100),
                options JSONB,
                tags JSONB
            )
        """
        )

        # Create raw_scan_results table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS raw_scan_results (
                id SERIAL PRIMARY KEY,
                scan_id VARCHAR(36) REFERENCES scans(id) ON DELETE CASCADE,
                tool_name VARCHAR(50) NOT NULL,
                raw_output TEXT NOT NULL,
                output_format VARCHAR(20) DEFAULT 'text',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """
        )

        # Create scan_summaries table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_summaries (
                id SERIAL PRIMARY KEY,
                scan_id VARCHAR(36) UNIQUE REFERENCES scans(id) ON DELETE CASCADE,
                total_hosts INTEGER DEFAULT 0,
                total_ports INTEGER DEFAULT 0,
                total_vulnerabilities INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                info_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """
        )

        # Create vulnerabilities table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                vuln_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                scan_id VARCHAR(36) REFERENCES scans(id) ON DELETE CASCADE,
                severity VARCHAR(20) NOT NULL,
                title VARCHAR(255) NOT NULL,
                description TEXT,
                cvss_score DECIMAL(3, 1),
                cve_id VARCHAR(50),
                port INTEGER,
                protocol VARCHAR(10),
                service VARCHAR(100),
                solution TEXT,
                "references" TEXT[],
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                metadata JSONB
            )
        """
        )

        # Create scan_history table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_history (
                history_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                scan_id VARCHAR(36) REFERENCES scans(id) ON DELETE CASCADE,
                status VARCHAR(50) NOT NULL,
                message TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                metadata JSONB
            )
        """
        )

        # Create reports table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                id VARCHAR(36) PRIMARY KEY,
                scan_id VARCHAR(36) REFERENCES scans(id) ON DELETE CASCADE,
                format VARCHAR(20) NOT NULL,
                filepath VARCHAR(500) NOT NULL,
                options TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """
        )

        # Create indexes
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)
        """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_scans_tool ON scans(tool_name)
        """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC)
        """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id)
        """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)
        """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_reports_scan ON reports(scan_id)
        """
        )

        conn.commit()
        cursor.close()
        print("Database schema initialized successfully")

    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Error initializing database: {e}")
        raise
    finally:
        if conn:
            release_db_connection(conn)


# Initialize database on module import (only if DATABASE_URL is set)
if os.getenv("DATABASE_URL"):
    try:
        if test_connection():
            init_database()
    except Exception as e:
        print(f"Warning: Could not initialize database: {e}")
