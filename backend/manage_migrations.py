#!/usr/bin/env python
"""
Database Migration Management Script

Provides convenient commands for managing database migrations with Alembic.

Usage:
    python manage_migrations.py init        - Create initial migration
    python manage_migrations.py migrate     - Create new migration (autogenerate)
    python manage_migrations.py upgrade     - Apply all pending migrations
    python manage_migrations.py downgrade   - Rollback last migration
    python manage_migrations.py current     - Show current revision
    python manage_migrations.py history     - Show migration history
    python manage_migrations.py stamp       - Mark database as current (no changes)

Author: NTRO Security Team
Date: 2025-11-27
"""

import os
import sys
import subprocess
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


def run_alembic_command(args):
    """Run alembic command and return result"""
    cmd = ['alembic'] + args
    logger.info(f"Running: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd,
            cwd=os.path.dirname(__file__),
            capture_output=True,
            text=True,
            check=True
        )
        logger.info(result.stdout)
        if result.stderr:
            logger.warning(result.stderr)
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with exit code {e.returncode}")
        logger.error(f"stdout: {e.stdout}")
        logger.error(f"stderr: {e.stderr}")
        return False


def create_initial_migration():
    """Create initial migration from current schema"""
    logger.info("Creating initial migration...")
    message = f"initial_schema_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    return run_alembic_command(['revision', '--autogenerate', '-m', message])


def create_migration():
    """Create new migration with autogenerate"""
    message = input("Enter migration message (or press Enter for auto): ").strip()
    if not message:
        message = f"auto_migration_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    logger.info(f"Creating migration: {message}")
    return run_alembic_command(['revision', '--autogenerate', '-m', message])


def upgrade_database():
    """Apply all pending migrations"""
    logger.info("Applying pending migrations...")
    return run_alembic_command(['upgrade', 'head'])


def downgrade_database():
    """Rollback last migration"""
    confirm = input("⚠️  Rollback last migration? This may cause data loss! (yes/no): ")
    if confirm.lower() != 'yes':
        logger.info("Rollback cancelled")
        return False
    
    logger.info("Rolling back last migration...")
    return run_alembic_command(['downgrade', '-1'])


def show_current():
    """Show current database revision"""
    return run_alembic_command(['current'])


def show_history():
    """Show migration history"""
    return run_alembic_command(['history', '--verbose'])


def stamp_database():
    """Mark database as current without running migrations"""
    logger.warning("⚠️  This will mark database as current without applying migrations!")
    confirm = input("Continue? (yes/no): ")
    if confirm.lower() != 'yes':
        logger.info("Stamp cancelled")
        return False
    
    return run_alembic_command(['stamp', 'head'])


def show_help():
    """Show help message"""
    logger.info(__doc__)


def main():
    if len(sys.argv) < 2:
        show_help()
        sys.exit(1)
    
    command = sys.argv[1].lower()
    
    commands = {
        'init': create_initial_migration,
        'migrate': create_migration,
        'upgrade': upgrade_database,
        'downgrade': downgrade_database,
        'current': show_current,
        'history': show_history,
        'stamp': stamp_database,
        'help': show_help,
    }
    
    if command not in commands:
        logger.error(f"Unknown command: {command}")
        show_help()
        sys.exit(1)
    
    success = commands[command]()
    sys.exit(0 if success or success is None else 1)


if __name__ == '__main__':
    main()
