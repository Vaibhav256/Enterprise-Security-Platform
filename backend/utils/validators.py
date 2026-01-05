"""
Validation utilities for the API
"""

from config.database import get_db_connection, release_db_connection


def validate_scan_id(scan_id: str) -> bool:
    """
    Validate that a scan exists in the database.
    
    Args:
        scan_id: The scan identifier
    
    Returns:
        bool: True if scan exists, False otherwise
    """
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # PostgreSQL uses %s for parameter placeholders, not ?
        cursor.execute(
            "SELECT id FROM scans WHERE id = %s",
            (scan_id,)
        )
        
        result = cursor.fetchone()
        cursor.close()
        
        return result is not None
        
    except Exception:
        return False
    finally:
        if conn:
            release_db_connection(conn)
