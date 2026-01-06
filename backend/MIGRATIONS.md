# Database Migrations Guide

## Overview
This project uses **Alembic** for database schema migrations. Alembic tracks changes to your database schema over time and allows you to upgrade/downgrade between versions safely.

## Quick Start

### 1. Check Current Status
```bash
python manage_migrations.py current
```

### 2. Create Initial Migration (First Time Only)
```bash
python manage_migrations.py init
```

### 3. Apply Migrations
```bash
python manage_migrations.py upgrade
```

## Common Commands

### Creating Migrations

**Auto-generate migration from model changes:**
```bash
python manage_migrations.py migrate
# or with custom message:
# Enter message when prompted
```

**Manual migration creation:**
```bash
alembic revision -m "add_user_roles"
```

### Applying Migrations

**Apply all pending migrations:**
```bash
python manage_migrations.py upgrade
```

**Apply specific migration:**
```bash
alembic upgrade <revision_id>
```

**Upgrade one step at a time:**
```bash
alembic upgrade +1
```

### Rolling Back

**Rollback last migration:**
```bash
python manage_migrations.py downgrade
```

**Rollback to specific revision:**
```bash
alembic downgrade <revision_id>
```

**Rollback all migrations:**
```bash
alembic downgrade base
```

### Viewing Status

**Show current database version:**
```bash
python manage_migrations.py current
```

**Show migration history:**
```bash
python manage_migrations.py history
```

**Show specific revision details:**
```bash
alembic show <revision_id>
```

## Migration Workflow

### When You Change Database Models:

1. **Make changes to SQLAlchemy models** in `config/database.py` or model files

2. **Create migration:**
   ```bash
   python manage_migrations.py migrate
   ```
   This will auto-detect changes and create a migration file in `alembic/versions/`

3. **Review the generated migration:**
   - Open `alembic/versions/<timestamp>_<message>.py`
   - Check `upgrade()` and `downgrade()` functions
   - Verify it captures your intended changes

4. **Test locally:**
   ```bash
   python manage_migrations.py upgrade
   ```

5. **Commit migration file** to git:
   ```bash
   git add alembic/versions/<new_migration>.py
   git commit -m "Add migration for X feature"
   ```

### Deployment Process:

1. **Pull latest code** on production server
2. **Backup database** (always!)
3. **Apply migrations:**
   ```bash
   python manage_migrations.py upgrade
   ```
4. **Restart application**

## Production Best Practices

### ⚠️ Before Running Migrations in Production:

1. **Always backup the database first**
   ```bash
   pg_dump vulnerability_scanner > backup_$(date +%Y%m%d_%H%M%S).sql
   ```

2. **Test migrations in staging environment** with production data copy

3. **Review SQL that will be executed:**
   ```bash
   alembic upgrade head --sql > migration.sql
   # Review migration.sql before applying
   ```

4. **Plan for rollback:**
   - Test downgrade migration
   - Keep backup ready
   - Document rollback procedure

### Migration Safety Checklist:

- [ ] Migration tested in development
- [ ] Migration tested in staging with production-like data
- [ ] Database backup created
- [ ] Downgrade path tested
- [ ] Zero-downtime considerations addressed
- [ ] Team notified of maintenance window
- [ ] Rollback plan documented

## Zero-Downtime Migrations

For production deployments, follow these patterns:

### Adding Columns:
✅ **Safe:** Add nullable columns
```python
op.add_column('table', sa.Column('new_col', sa.String(), nullable=True))
```

❌ **Risky:** Add non-nullable columns without defaults
```python
op.add_column('table', sa.Column('new_col', sa.String(), nullable=False))
```

### Removing Columns:
Use **3-step process:**
1. Deploy code that doesn't use column
2. Wait for all instances to deploy
3. Run migration to drop column

### Renaming Columns:
Use **4-step process:**
1. Add new column
2. Write to both columns
3. Backfill data
4. Remove old column

## Troubleshooting

### "Target database is not up to date"
```bash
# Check current version
python manage_migrations.py current

# Apply pending migrations
python manage_migrations.py upgrade
```

### "Multiple head revisions"
```bash
# Merge branches
alembic merge heads -m "merge migrations"
```

### "Can't locate revision identified by 'xyz'"
```bash
# Force stamp database (dangerous!)
alembic stamp head
```

### Migration conflicts after git merge:
```bash
# Merge migration branches
alembic merge <rev1> <rev2> -m "merge feature branches"
```

## Directory Structure

```
backend/
├── alembic/                    # Alembic configuration
│   ├── versions/              # Migration scripts (git-tracked)
│   │   └── xxx_initial.py
│   ├── env.py                 # Migration environment config
│   └── README
├── alembic.ini                # Alembic settings
├── manage_migrations.py       # Helper script
└── MIGRATIONS.md              # This file
```

## Tips

1. **Never edit applied migrations** - create new ones instead
2. **Keep migrations small** - easier to review and rollback
3. **Test both upgrade and downgrade** paths
4. **Use descriptive messages** for migration names
5. **Don't skip migrations** - apply them in order
6. **Backup before production migrations** - always!

## Example: Adding a New Table

1. **Define model in code:**
```python
# config/database.py
class NewFeature(Base):
    __tablename__ = 'new_features'
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
```

2. **Generate migration:**
```bash
python manage_migrations.py migrate
# Enter message: "add new_features table"
```

3. **Review generated file:**
```bash
cat alembic/versions/*_add_new_features_table.py
```

4. **Apply locally:**
```bash
python manage_migrations.py upgrade
```

5. **Test your feature** with the new table

6. **Commit and deploy:**
```bash
git add alembic/versions/*_add_new_features_table.py
git commit -m "Add new_features table"
```

## Resources

- [Alembic Documentation](https://alembic.sqlalchemy.org/)
- [SQLAlchemy Documentation](https://docs.sqlalchemy.org/)
- [Database Migration Best Practices](https://www.braintreepayments.com/blog/safe-database-migrations/)

## Support

For migration issues, contact the development team or check:
- Alembic history: `python manage_migrations.py history`
- Database state: `python manage_migrations.py current`
- Application logs: `tail -f logs/app.log`
