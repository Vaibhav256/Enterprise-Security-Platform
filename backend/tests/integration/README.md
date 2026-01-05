# Integration Tests

Comprehensive integration tests for the Vulnerability Scanner backend, organized similar to TestNG test suites.

## Overview

Integration tests verify the interaction between multiple components:
- **API Integration**: API Gateway + Database + Business Logic
- **E2E Workflows**: Complete scan workflows from creation to completion
- **Database Integration**: Data persistence, relationships, and transactions
- **Queue Integration**: Task queue and async processing (when available)

## Test Organization (TestNG-style)

Tests are organized using pytest markers (similar to TestNG groups):

- `@pytest.mark.integration` - All integration tests
- `@pytest.mark.api` - API endpoint integration tests
- `@pytest.mark.e2e` - End-to-end workflow tests
- `@pytest.mark.database` - Database integration tests
- `@pytest.mark.queue` - Task queue tests
- `@pytest.mark.slow` - Slow-running tests (> 1 second)

## Running Tests

### Run All Integration Tests
```bash
cd backend
python run_integration_tests.py
```

### Run Specific Test Groups
```bash
# API integration tests only
python run_integration_tests.py --group api

# End-to-end workflow tests
python run_integration_tests.py --group e2e

# Database integration tests
python run_integration_tests.py --group database

# Skip slow tests
python run_integration_tests.py --fast
```

### Run with Pytest Directly
```bash
# All integration tests
pytest tests/integration/ -m integration

# API tests only
pytest tests/integration/ -m "integration and api"

# E2E tests, excluding slow ones
pytest tests/integration/ -m "integration and e2e and not slow"

# With coverage
pytest tests/integration/ -m integration --cov=. --cov-report=html
```

## Test Files

### `test_api_integration.py`
Tests API endpoints with database integration:
- Scan creation and retrieval workflows
- Listing with filters and pagination
- Status update workflows
- Results storage and retrieval
- Scan deletion with cascades
- Statistics aggregation

### `test_e2e_workflows.py`
End-to-end workflow tests:
- Complete Nmap scan workflow (create → execute → parse → store → retrieve)
- Multi-tool sequential scans
- Error handling and retry workflows
- Data persistence across sessions
- Concurrent scan execution

### `test_database_integration.py`
Database-focused integration tests:
- Relationship integrity (scans ↔ results)
- Cascade deletes
- Transaction handling and rollback
- Complex queries and filters
- Database constraints
- Performance with large datasets

## Test Fixtures

### Session-scoped Fixtures
- `integration_app` - Flask app with in-memory database
- `integration_client` - Test client for API requests
- `integration_db` - Database session
- `integration_ingestor` - DataIngestor instance
- `integration_orchestrator` - ScanOrchestrator instance

### Function-scoped Fixtures
- `temp_output_dir` - Temporary directory for test outputs
- `mock_redis` - Mocked Redis connection
- `sample_scan_data` - Sample scan request data
- `sample_nmap_output` - Sample nmap tool output
- `sample_parsed_results` - Sample parsed scan results

## Test Coverage Goals

| Component | Target Coverage | Current |
|-----------|----------------|---------|
| API Endpoints | 95% | TBD |
| Database Layer | 90% | TBD |
| E2E Workflows | 80% | TBD |
| Error Scenarios | 85% | TBD |

## Best Practices

1. **Test Isolation**: Each test should be independent
2. **Clean State**: Use fixtures to ensure clean database state
3. **Realistic Data**: Use realistic scan data and outputs
4. **Error Cases**: Test both success and failure paths
5. **Performance**: Mark slow tests with `@pytest.mark.slow`
6. **Documentation**: Add docstrings explaining what each test verifies

## Example Test Structure

```python
@pytest.mark.integration
@pytest.mark.api
class TestScanAPIIntegration:
    """Integration tests for scan API endpoints."""
    
    def test_create_and_retrieve_scan(
        self, 
        integration_client, 
        integration_ingestor
    ):
        """
        Test complete workflow: create scan -> retrieve scan -> verify data.
        
        This test verifies:
        1. Scan can be created via API
        2. Scan is persisted in database
        3. Scan can be retrieved via API
        4. Retrieved data matches created data
        """
        # Test implementation...
```

## Continuous Integration

Integration tests run automatically on:
- Pull requests
- Commits to main branch
- Nightly builds (including slow tests)

CI Configuration:
```yaml
# Fast tests on PR
pytest tests/integration/ -m "integration and not slow"

# Full tests nightly
pytest tests/integration/ -m integration
```

## Troubleshooting

### Tests Failing Locally
1. Ensure database is accessible
2. Check Redis is running (for queue tests)
3. Verify environment variables are set
4. Run with `-v` for verbose output

### Slow Test Performance
1. Use `--fast` flag to skip slow tests during development
2. Run full suite before committing
3. Consider parallelization: `pytest -n auto`

### Database Errors
1. Check database connection string
2. Ensure migrations are up to date
3. Verify test database has correct schema

## Contributing

When adding new integration tests:
1. Follow existing test structure
2. Use appropriate markers
3. Add docstrings
4. Update this README if adding new test categories
5. Ensure tests are idempotent and isolated
