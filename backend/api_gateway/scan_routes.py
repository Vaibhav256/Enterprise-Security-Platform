"""
API Routes

REST API endpoints for scan management, execution, and results retrieval.
Implements the OpenAPI specification defined in docs/api_spec.yaml

Author: NTRO Security Team
Date: 2025-10-22
"""

import logging
import os
import sys
import time
from datetime import datetime

from flask import jsonify, request
from flask_restx import Namespace, Resource, fields
from markupsafe import escape
from werkzeug.exceptions import BadRequest, NotFound
import requests
from sqlalchemy.exc import SQLAlchemyError

from config.config import get_config
from services.data_ingestor.ingestor import DataIngestor
from services.data_ingestor.models import ScanStatus
from services.scan_orchestrator.orchestrator import ScanOrchestrator

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


logger = logging.getLogger(__name__)


def check_ollama_health(ollama_url: str = None, timeout: int = 10) -> dict:
    """
    Check if Ollama service is available and has required model installed.
    
    Args:
        ollama_url: Ollama base URL (defaults to env var or localhost)
        timeout: Request timeout in seconds (increased to 10s for model loading)
    
    Returns:
        dict with 'available' (bool), 'error' (str or None), 'response_time' (float),
        'has_model' (bool), 'models' (list)
    """
    if ollama_url is None:
        ollama_url = os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')
    
    start_time = time.time()
    try:
        response = requests.get(
            f"{ollama_url}/api/tags",
            timeout=timeout
        )
        response_time = time.time() - start_time
        
        if response.status_code == 200:
            # Verify the required model is present
            models = response.json().get('models', [])
            model_names = [m['name'] for m in models]
            required_model = "llama3.2:3b-instruct-q4_K_M"
            
            has_model = required_model in model_names
            
            if has_model:
                logger.info(f"✓ Ollama health check passed with model {required_model} ({response_time:.2f}s)")
                return {
                    'available': True,
                    'error': None,
                    'response_time': response_time,
                    'has_model': True,
                    'models': model_names
                }
            else:
                logger.warning(f"✗ Ollama running but model {required_model} not found")
                return {
                    'available': False,
                    'error': f'Required model {required_model} not installed. Run: ollama pull {required_model}',
                    'response_time': response_time,
                    'has_model': False,
                    'models': model_names
                }
        else:
            logger.warning(f"✗ Ollama returned status {response.status_code}")
            return {
                'available': False,
                'error': f'Ollama service returned status {response.status_code}',
                'response_time': response_time,
                'has_model': False,
                'models': []
            }
    except requests.exceptions.Timeout:
        response_time = time.time() - start_time
        logger.error(f"✗ Ollama health check timeout after {timeout}s")
        return {
            'available': False,
            'error': f'Ollama service timeout after {timeout}s (may be loading model)',
            'response_time': response_time,
            'has_model': False,
            'models': []
        }
    except requests.exceptions.ConnectionError as e:
        response_time = time.time() - start_time
        logger.error(f"✗ Ollama connection error: {e}")
        return {
            'available': False,
            'error': 'Ollama service is not running or unreachable',
            'response_time': response_time,
            'has_model': False,
            'models': []
        }
    except Exception as e:
        response_time = time.time() - start_time
        logger.error(f"✗ Ollama health check failed: {e}")
        return {
            'available': False,
            'error': f'Ollama service error: {str(e)}',
            'response_time': response_time,
            'has_model': False,
            'models': []
        }


# Initialize services
config = get_config(os.getenv('FLASK_ENV', 'development'))
orchestrator = ScanOrchestrator(
    redis_host=config.REDIS_HOST,
    redis_port=config.REDIS_PORT
)
ingestor = DataIngestor(database_url=config.DATABASE_URL)

# Create namespaces
scans_ns = Namespace('scans', description='Scan management operations')


# API Models for documentation and validation
scan_request_model = scans_ns.model(
    'ScanRequest',
    {
        'target': fields.String(
            required=True,
            description='Target IP, hostname, or CIDR range',
            example='192.168.1.1'),
        'tool_name': fields.String(
            required=True,
            description='Scanner tool name',
            enum=[
                'nmap',
                'openvas',
                'nikto',
                'nuclei'],
            example='nmap'),
        'scan_type': fields.String(
            required=True,
            description='Type of scan to perform',
            example='basic'),
        'priority': fields.String(
            required=False,
            description='Scan priority',
            enum=[
                'high',
                'normal',
                'low'],
            default='normal'),
        'options': fields.Raw(
            required=False,
            description='Additional tool-specific options',
            example={}),
        'tags': fields.List(
            fields.String,
            required=False,
            description='Tags for categorizing scans',
            example=[
                'production',
                'web-server'])})

scan_response_model = scans_ns.model('ScanResponse', {
    'scan_id': fields.String(description='Unique scan identifier'),
    'target': fields.String(description='Scan target'),
    'tool_name': fields.String(description='Scanner tool'),
    'scan_type': fields.String(description='Scan type'),
    'status': fields.String(description='Current scan status'),
    'priority': fields.String(description='Scan priority'),
    'created_at': fields.DateTime(description='Scan creation timestamp'),
    'job_id': fields.String(description='Job queue identifier')
})

scan_detail_model = scans_ns.model('ScanDetail', {
    'scan_id': fields.String(description='Unique scan identifier'),
    'target': fields.String(description='Scan target'),
    'tool_name': fields.String(description='Scanner tool'),
    'scan_type': fields.String(description='Scan type'),
    'status': fields.String(description='Current scan status'),
    'progress': fields.Integer(description='Scan progress percentage (0-100)'),
    'priority': fields.String(description='Scan priority'),
    'created_at': fields.DateTime(description='Creation timestamp'),
    'started_at': fields.DateTime(description='Start timestamp'),
    'completed_at': fields.DateTime(description='Completion timestamp'),
    'execution_time': fields.Float(description='Execution time in seconds'),
    'error_message': fields.String(description='Error message if failed'),
    'options': fields.Raw(description='Scan options'),
    'tags': fields.List(fields.String, description='Scan tags'),
    'job_id': fields.String(description='Job queue identifier'),
    'summary': fields.Raw(description='Scan summary with statistics')
})

scan_list_model = scans_ns.model('ScanList', {
    'scans': fields.List(fields.Nested(scan_response_model)),
    'total': fields.Integer(description='Total number of scans'),
    'page': fields.Integer(description='Current page number'),
    'per_page': fields.Integer(description='Items per page')
})

scan_status_model = scans_ns.model('ScanStatus', {
    'scan_id': fields.String(description='Scan identifier'),
    'status': fields.String(description='Current status'),
    'progress': fields.Integer(description='Progress percentage'),
    'job_status': fields.String(description='Job queue status'),
    'started_at': fields.DateTime(description='Start time'),
    'execution_time': fields.Float(description='Execution time in seconds')
})


def sanitize_output(data):
    """Sanitize data to prevent XSS"""
    if isinstance(data, dict):
        return {k: sanitize_output(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_output(item) for item in data]
    elif isinstance(data, str):
        return escape(data)
    return data


@scans_ns.route('/')
class ScanList(Resource):
    """Scan collection endpoint"""

    @scans_ns.doc('list_scans')
    @scans_ns.param('status', 'Filter by status', type=str)
    @scans_ns.param('tool_name', 'Filter by tool', type=str)
    @scans_ns.param('page', 'Page number', type=int, default=1)
    @scans_ns.param('per_page', 'Items per page', type=int, default=20)
    @scans_ns.marshal_with(scan_list_model)
    def get(self):
        """List all scans with optional filtering"""
        try:
            from utils.validation import validate_pagination, validate_status
            
            # Get and validate query parameters
            status_param = request.args.get('status')
            tool_name = request.args.get('tool_name')
            
            # Validate pagination
            try:
                page = int(request.args.get('page', 1))
                per_page = int(request.args.get('per_page', 20))
                page, per_page = validate_pagination(page, per_page)
            except (ValueError, TypeError) as e:
                raise BadRequest(f"Invalid pagination parameters: {e}")

            # Convert status string to enum
            status = None
            if status_param:
                try:
                    validated_status = validate_status(status_param)
                    status = ScanStatus[validated_status]
                except (KeyError, ValueError) as e:
                    raise BadRequest(f"Invalid status: {e}")

            # Get scans
            scans, total = ingestor.list_scans(
                status=status,
                tool=tool_name,
                limit=per_page,
                offset=(page - 1) * per_page
            )

            # Convert to response format
            scan_list = []
            for scan in scans:
                scan_list.append({
                    'scan_id': str(scan.id),
                    'target': scan.target,
                    'tool_name': scan.tool_name,
                    'scan_type': scan.scan_type,
                    'status': scan.status.value,
                    'priority': scan.priority,
                    'created_at': scan.created_at.isoformat() if scan.created_at else None,
                    'job_id': scan.job_id
                })

            # Sanitize output to prevent XSS
            response_data = {
                'scans': scan_list,
                'total': total,
                'page': page,
                'per_page': per_page
            }
            return sanitize_output(response_data)

        except BadRequest:
            raise
        except KeyError as e:
            logger.error(f"Missing required data field: {str(e)}", exc_info=True)
            scans_ns.abort(500, f"Internal error: missing data field {str(e)}")
        except TypeError as e:
            logger.error(f"Type validation failed: {str(e)}", exc_info=True)
            scans_ns.abort(500, f"Internal error: invalid data type")
        except ValueError as e:
            logger.error(f"Value validation failed: {str(e)}", exc_info=True)
            scans_ns.abort(500, f"Internal error: invalid value")
        except SQLAlchemyError as e:
            logger.error(f"Database error in list_scans: {str(e)}", exc_info=True)
            scans_ns.abort(500, "Database operation failed")
        except Exception as e:
            logger.error(f"Unexpected error listing scans: {str(e)}", exc_info=True)
            scans_ns.abort(500, "An unexpected error occurred")

    @scans_ns.doc('create_scan')
    @scans_ns.expect(scan_request_model, validate=True)
    @scans_ns.marshal_with(scan_response_model, code=201)
    def post(self):
        """Create and enqueue a new scan"""
        try:
            import uuid
            data = request.json

            # Validate required fields
            required_fields = ['target', 'tool_name', 'scan_type']
            for field in required_fields:
                if field not in data:
                    raise BadRequest(f"Missing required field: {field}")
                if not data[field] or (
                    isinstance(
                        data[field],
                        str) and not data[field].strip()):
                    raise BadRequest(f"Field '{field}' cannot be empty")

            # Generate scan ID
            scan_id = str(uuid.uuid4())

            # Create scan record in database (initial status: PENDING)
            scan = ingestor.create_scan(
                scan_id=scan_id,
                target=data['target'],
                tool_name=data['tool_name'],
                scan_type=data['scan_type'],
                options=data.get('options', {}),
                tags=data.get('tags', []),
                priority=data.get('priority', 'normal'),
                job_id=None  # Will be updated after enqueuing
            )

            # Enqueue scan job
            try:
                job_id = orchestrator.enqueue_scan(
                    scan_id=scan_id,
                    target=data['target'],
                    tool=data['tool_name'],
                    scan_type=data['scan_type'],
                    options=data.get('options', {}),
                    priority=data.get('priority', 'normal')
                )
                logger.info(f"✅ Successfully enqueued scan {scan_id} with job_id {job_id}")
                
                # Update scan status to QUEUED (valid transition: PENDING → QUEUED)
                ingestor.update_scan_status(scan_id=scan_id, status=ScanStatus.QUEUED)
                logger.info(f"✅ Scan {scan_id} status updated to QUEUED")
                
            except Exception as enqueue_error:
                logger.error("❌ Failed to enqueue scan %s: %s", scan_id, str(enqueue_error), exc_info=True)
                # Update scan to failed status
                try:
                    ingestor.update_scan_status(scan_id=scan_id, status=ScanStatus.FAILED, 
                                              error_message=f"Failed to enqueue: {str(enqueue_error)}")
                except Exception:
                    pass
                return {
                    'error': 'Failed to queue scan job',
                    'details': str(enqueue_error),
                    'suggestion': 'Ensure Redis and RQ worker are running. Check logs for details.'
                }, 500

            # Update the scan with job_id
            session = ingestor.get_session()
            try:
                from services.data_ingestor.models import Scan
                scan_obj = session.query(Scan).filter(
                    Scan.id == scan_id).first()
                if scan_obj:
                    scan_obj.job_id = job_id
                    session.commit()
            finally:
                session.close()

            # Refresh scan to get updated data
            scan = ingestor.get_scan(scan_id)

            response_data = {
                'scan_id': scan_id,
                'target': scan.target,
                'tool_name': scan.tool_name,
                'scan_type': scan.scan_type,
                'status': scan.status.value,
                'priority': scan.priority,
                'created_at': scan.created_at.isoformat(),
                'job_id': job_id
            }
            return sanitize_output(response_data), 201

        except BadRequest:
            raise
        except (KeyError, TypeError, ValueError, AttributeError) as e:
            logger.error("Error creating scan: %s", type(e).__name__)
            scans_ns.abort(500, "Failed to create scan")


@scans_ns.route('/<string:scan_id>')
@scans_ns.param('scan_id', 'The scan identifier')
class Scan(Resource):
    """Single scan endpoint"""

    @scans_ns.doc('get_scan')
    @scans_ns.response(404, 'Scan not found')
    def get(self, scan_id):
        """Get detailed scan information"""
        try:
            from utils.validation import validate_scan_id
            
            # Validate scan ID format
            try:
                scan_id = validate_scan_id(scan_id)
            except ValueError as e:
                raise BadRequest(str(e))
            
            scan = ingestor.get_scan(scan_id)
        except (KeyError, ValueError, AttributeError):
            # If any error occurs during lookup, treat as not found
            scans_ns.abort(404, f"Scan {scan_id} not found")

        if not scan:
            scans_ns.abort(404, f"Scan {scan_id} not found")

        try:
            # Get scan summary if available
            summary = ingestor.get_scan_summary(scan_id)
            summary_data = None  # Keep as None if no summary exists

            logger.info(
                "GET /api/scans/%s - Summary object: %s", scan_id, summary is not None)

            if summary:
                # Map persistent DB fields to the API fields. The DB model currently
                # uses names like `total_hosts` and `total_vulnerabilities`, while
                # older code (and exported files) expect `hosts_scanned` and
                # `vulnerabilities_found`. Use getattr with fallbacks so this code
                # is resilient to small schema/name mismatches.
                summary_data = {
                    'hosts_scanned': getattr(summary, 'total_hosts', getattr(summary, 'hosts_scanned', 0)),
                    'hosts_up': getattr(summary, 'hosts_up', None),
                    'total_ports': getattr(summary, 'total_ports', 0),
                    'open_ports': getattr(summary, 'open_ports', None),
                    'vulnerabilities_found': getattr(summary, 'total_vulnerabilities', getattr(summary, 'vulnerabilities_found', 0)),
                    'critical_count': getattr(summary, 'critical_count', 0),
                    'high_count': getattr(summary, 'high_count', 0),
                    'medium_count': getattr(summary, 'medium_count', 0),
                    'low_count': getattr(summary, 'low_count', 0),
                    'info_count': getattr(summary, 'info_count', 0)
                }
                logger.info("Summary data: %s", summary_data)

            # Build response safely with explicit types
            try:
                progress = int(scan.progress) if hasattr(scan, 'progress') else 0
            except (TypeError, ValueError):
                progress = 0
                logger.warning("Could not get progress for scan %s", scan_id)

            try:
                execution_time = int(scan.execution_time) if scan.execution_time else None
            except (TypeError, ValueError):
                execution_time = None
                logger.warning("Could not get execution_time for scan %s", scan_id)

            response_data = {
                'scan_id': str(scan.id),
                'target': scan.target,
                'tool_name': scan.tool_name,
                'scan_type': scan.scan_type,
                'status': scan.status.value,
                'progress': progress,
                'priority': scan.priority,
                'created_at': scan.created_at.isoformat() if scan.created_at else None,
                'started_at': scan.started_at.isoformat() if scan.started_at else None,
                'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
                'execution_time': execution_time,
                'error_message': scan.error_message,
                'options': scan.options,
                'tags': scan.tags,
                'job_id': scan.job_id,
                'summary': summary_data
            }

            logger.info(
                "Response has summary: %s, value: %s", 'summary' in response_data, response_data.get('summary'))

            final_response = sanitize_output(response_data)
            logger.info("Final response keys: %s", list(final_response.keys()))

            return jsonify(final_response)

        except NotFound:
            raise
        except BadRequest:
            raise
        except AttributeError as e:
            logger.error(f"Missing attribute in scan data: {str(e)}", exc_info=True)
            scans_ns.abort(500, "Internal error: invalid scan data structure")
        except TypeError as e:
            logger.error(f"Type error processing scan data: {str(e)}", exc_info=True)
            scans_ns.abort(500, "Internal error: data type mismatch")
        except SQLAlchemyError as e:
            logger.error(f"Database error getting scan {scan_id}: {str(e)}", exc_info=True)
            scans_ns.abort(500, "Database operation failed")
        except Exception as e:
            logger.error(f"Unexpected error getting scan {scan_id}: {str(e)}", exc_info=True)
            scans_ns.abort(500, "Failed to get scan")

    @scans_ns.doc('delete_scan')
    @scans_ns.response(204, 'Scan deleted/cancelled')
    def delete(self, scan_id):
        """Cancel and delete a scan"""
        try:
            scan = ingestor.get_scan(scan_id)

            if not scan:
                raise NotFound(f"Scan {scan_id} not found")

            # Cancel job if pending or running
            if scan.job_id and scan.status in [
                    ScanStatus.PENDING, ScanStatus.RUNNING]:  # pylint: disable=no-member
                orchestrator.cancel_job(scan.job_id)

            # Delete scan
            ingestor.delete_scan(scan_id)

            return '', 204

        except NotFound:
            raise
        except AttributeError as e:
            logger.error(f"Invalid scan data structure: {str(e)}", exc_info=True)
            scans_ns.abort(500, "Internal error: invalid scan data")
        except SQLAlchemyError as e:
            logger.error(f"Database error deleting scan {scan_id}: {str(e)}", exc_info=True)
            scans_ns.abort(500, "Database operation failed")
        except Exception as e:
            logger.error(f"Unexpected error deleting scan {scan_id}: {str(e)}", exc_info=True)
            scans_ns.abort(500, f"Failed to delete scan: {str(e)}")


@scans_ns.route('/<string:scan_id>/retry')
@scans_ns.param('scan_id', 'The scan identifier')
class ScanRetryResource(Resource):
    """Scan retry endpoint for failed scans"""

    @scans_ns.doc('retry_scan')
    @scans_ns.response(200, 'Scan retry successful', scan_detail_model)
    @scans_ns.response(400, 'Cannot retry scan in current status')
    @scans_ns.response(404, 'Scan not found')
    def post(self, scan_id):
        """Retry a failed scan"""
        try:
            from utils.validation import validate_scan_id
            
            # Validate scan ID format
            try:
                scan_id = validate_scan_id(scan_id)
            except ValueError as e:
                raise BadRequest(str(e))
            
            scan = ingestor.get_scan(scan_id)
            if not scan:
                raise NotFound(f"Scan {scan_id} not found")

            # Only allow retry for failed scans
            if scan.status != ScanStatus.FAILED:
                scans_ns.abort(400, f"Cannot retry scan with status '{scan.status.value}'. Only failed scans can be retried.")

            logger.info(f"🔄 Retrying failed scan {scan_id}")
            logger.info(f"📋 Original scan options: {scan.options}")

            # Re-enqueue the scan with updated configuration
            # Remove old timeout from options so it uses new adapter defaults
            retry_options = scan.options.copy() if scan.options else {}
            removed_keys = []
            if 'timeout' in retry_options:
                old_timeout = retry_options.pop('timeout')
                removed_keys.append(f'timeout={old_timeout}s')
            if 'per_test_timeout' in retry_options:
                old_per_test = retry_options.pop('per_test_timeout')
                removed_keys.append(f'per_test_timeout={old_per_test}s')
            
            logger.info(f"📋 Cleaned retry options: {retry_options}")
            if removed_keys:
                logger.info(f"Removing old timeout settings: {', '.join(removed_keys)} - will use adapter defaults")
            
            # Update the scan's stored options in database to remove old timeouts
            session = ingestor.get_session()
            try:
                db_scan = session.query(ingestor.scan_class).filter_by(id=scan_id).first()
                if db_scan:
                    db_scan.options = retry_options
                    session.commit()
                    logger.info(f"✅ Updated scan options in database (removed timeout settings)")
            finally:
                session.close()
            
            # Clear error message and reset status to PENDING first (state machine requirement)
            ingestor.update_scan_status(
                scan_id=scan_id,
                status=ScanStatus.PENDING,
                error_message=None
            )
            
            job_id = orchestrator.enqueue_scan(
                scan_id=str(scan.id),
                target=scan.target,
                tool=scan.tool_name,
                scan_type=scan.scan_type,
                options=retry_options
            )

            # Update to QUEUED status and job ID
            ingestor.update_scan_status(
                scan_id=scan_id,
                status=ScanStatus.QUEUED
            )
            
            # Update job ID
            session = ingestor.get_session()
            try:
                db_scan = session.query(ingestor.scan_class).filter_by(id=scan_id).first()
                if db_scan:
                    db_scan.job_id = job_id
                    session.commit()
            finally:
                session.close()

            logger.info(f"✅ Scan {scan_id} re-queued successfully with job {job_id} (using adapter default timeouts)")

            # Return updated scan
            updated_scan = ingestor.get_scan(scan_id)
            return updated_scan.to_dict(), 200

        except NotFound:
            raise
        except BadRequest:
            raise
        except AttributeError as e:
            logger.error(f"Invalid scan data structure: {str(e)}", exc_info=True)
            scans_ns.abort(500, "Internal error: invalid scan data")
        except SQLAlchemyError as e:
            logger.error(f"Database error retrying scan {scan_id}: {str(e)}", exc_info=True)
            scans_ns.abort(500, "Database operation failed")
        except Exception as e:
            logger.error(f"Unexpected error retrying scan {scan_id}: {str(e)}", exc_info=True)
            scans_ns.abort(500, f"Failed to retry scan: {str(e)}")


@scans_ns.route('/<string:scan_id>/status')
@scans_ns.param('scan_id', 'The scan identifier')
class ScanStatusResource(Resource):
    """Scan status endpoint"""

    @scans_ns.doc('get_scan_status')
    @scans_ns.marshal_with(scan_status_model)
    def get(self, scan_id):
        """Get current scan status"""
        try:
            from utils.validation import validate_scan_id
            
            # Validate scan ID format
            try:
                scan_id = validate_scan_id(scan_id)
            except ValueError as e:
                raise BadRequest(str(e))
            
            scan = ingestor.get_scan(scan_id)

            if not scan:
                raise NotFound(f"Scan {scan_id} not found")

            # Get job status if available
            job_status = None
            if scan.job_id:
                job_info = orchestrator.get_job_status(scan.job_id)
                job_status = job_info.get('status') if job_info else None

            return {
                'scan_id': str(scan.id),
                'status': scan.status.value,
                'progress': scan.progress,
                'job_status': job_status,
                'started_at': scan.started_at.isoformat() if scan.started_at else None,
                'execution_time': scan.execution_time}

        except NotFound:
            raise
        except Exception as e:
            scans_ns.abort(500, f"Failed to get scan status: {str(e)}")


@scans_ns.route('/<string:scan_id>/raw_results')
@scans_ns.param('scan_id', 'The scan identifier')
class ScanRawResults(Resource):
    """Raw scan results endpoint"""

    @scans_ns.doc('get_raw_results')
    def get(self, scan_id):
        """Get raw scan output"""
        try:
            results = ingestor.get_raw_results(scan_id)

            if not results:
                raise NotFound(f"No results found for scan {scan_id}")

            # Combine all raw outputs from multiple tools
            combined_output = ""
            result_list = []
            
            for result in results:
                # Format JSON output for better readability
                formatted_output = result.raw_output
                if result.output_format == 'json':
                    try:
                        import json
                        # Try to parse and pretty-print JSON with line wrapping
                        lines = formatted_output.strip().split('\n')
                        formatted_lines = []
                        for line in lines:
                            if line.strip():
                                try:
                                    json_obj = json.loads(line)
                                    # Pretty print with limited width to prevent long lines
                                    formatted_json = json.dumps(json_obj, indent=2)
                                    # Break long lines (especially for encoded data)
                                    wrapped_lines = []
                                    for json_line in formatted_json.split('\n'):
                                        # If line is too long, wrap it
                                        if len(json_line) > 120:
                                            # Find if it's a key-value pair
                                            if ':' in json_line and '"' in json_line:
                                                indent = len(json_line) - len(json_line.lstrip())
                                                key_part = json_line.split(':', 1)[0] + ':'
                                                value_part = json_line.split(':', 1)[1].strip()
                                                
                                                # If value is a long string, truncate it
                                                if value_part.startswith('"') and len(value_part) > 100:
                                                    # Truncate long string values
                                                    truncated = value_part[:100] + '...[truncated]"'
                                                    if value_part.endswith(','):
                                                        truncated += ','
                                                    wrapped_lines.append(' ' * indent + key_part + ' ' + truncated)
                                                else:
                                                    wrapped_lines.append(json_line)
                                            else:
                                                wrapped_lines.append(json_line)
                                        else:
                                            wrapped_lines.append(json_line)
                                    formatted_lines.append('\n'.join(wrapped_lines))
                                except (json.JSONDecodeError, ValueError, AttributeError) as e:
                                    logger.debug(f"JSON formatting failed: {e}")
                                    formatted_lines.append(line)
                        formatted_output = '\n'.join(formatted_lines)
                    except (json.JSONDecodeError, ValueError, TypeError) as e:
                        # If formatting fails, use original output
                        logger.debug(f"Output formatting failed: {e}")
                        pass
                
                result_list.append({
                    'id': str(result.id),
                    'scan_id': str(result.scan_id),
                    'tool_name': result.tool_name,
                    'raw_output': formatted_output,
                    'output_format': result.output_format,
                    'timestamp': result.timestamp.isoformat() if result.timestamp else None,
                    'file_size': result.file_size
                })
                # Combine outputs with separator
                if combined_output:
                    combined_output += f"\n\n--- {result.tool_name} Output ---\n\n"
                combined_output += formatted_output

            # Return first result as primary with combined output
            first_result = results[0]
            return {
                'scan_id': str(first_result.scan_id),
                'raw_output': combined_output,
                'output_format': first_result.output_format,
                'created_at': first_result.timestamp.isoformat() if first_result.timestamp else None,
                'results': result_list
            }

        except NotFound:
            raise
        except Exception as e:
            scans_ns.abort(500, f"Failed to get raw results: {str(e)}")


@scans_ns.route('/<string:scan_id>/parsed_results')
@scans_ns.param('scan_id', 'The scan identifier')
class ScanParsedResults(Resource):
    """Parsed scan results endpoint"""

    @scans_ns.doc('get_parsed_results')
    def get(self, scan_id):
        """Get parsed scan results and summary"""
        try:
            # Get scan to verify it exists
            scan = ingestor.get_scan(scan_id)
            if not scan:
                raise NotFound(f"Scan {scan_id} not found")

            # Get scan summary
            summary = ingestor.get_scan_summary(scan_id)
            
            # Get stored vulnerabilities from database
            stored_vulnerabilities = ingestor.get_vulnerabilities(scan_id)

            response = {
                'scan_id': scan_id,
                'parsed_results': {
                    'vulnerabilities': stored_vulnerabilities,
                    'findings': stored_vulnerabilities  # Alias for compatibility
                },
                'summary': None,
                'ai_summary': None,
                'ai_summary_text': None
            }

            # Build severity counts from stored vulnerabilities
            findings_by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            for vuln in stored_vulnerabilities:
                severity = vuln.get('severity', 'unknown').lower()
                if severity in findings_by_severity:
                    findings_by_severity[severity] += 1
            
            # Check if AI summary is already cached in database
            cached_ai_summary = None
            if summary and hasattr(summary, 'ai_summary') and summary.ai_summary:
                cached_ai_summary = summary.ai_summary
                logger.info(f"Using cached AI summary for scan {scan_id}")
            
            try:
                from intelligence_layer.rag.scan_processor import ScanAISummarizer, ScanReport, Vulnerability
                from datetime import datetime
                
                # Only generate AI summary if not cached and we have vulnerabilities
                if not cached_ai_summary and stored_vulnerabilities:
                    # PRE-FLIGHT CHECK: Verify Ollama is available before attempting generation
                    ollama_health = check_ollama_health(timeout=10)
                    
                    if not ollama_health['available']:
                        # Ollama is unavailable - RETRY ONCE after brief delay
                        # Ollama may need 1-2 seconds to warm up model on first request
                        OLLAMA_RETRY_DELAY_SECONDS = 2
                        logger.warning(f"Ollama unavailable for scan {scan_id}: {ollama_health['error']}")
                        logger.info(f"Retrying Ollama health check after {OLLAMA_RETRY_DELAY_SECONDS}s delay (may be warming up)...")
                        
                        import time
                        time.sleep(OLLAMA_RETRY_DELAY_SECONDS)
                        
                        # Retry health check
                        ollama_health_retry = check_ollama_health(timeout=10)
                        
                        if not ollama_health_retry['available']:
                            # Still unavailable after retry - store error state
                            logger.error(f"Ollama still unavailable after retry: {ollama_health_retry['error']}")
                            
                            error_summary = {
                                'status': 'failed',
                                'error': 'AI service is temporarily unavailable (retried)',
                                'error_details': ollama_health_retry['error'],
                                'can_retry': True,
                                'timestamp': datetime.now().isoformat(),
                                'retry_attempted': True
                            }
                            
                            # Store error state in database for tracking
                            try:
                                ingestor.update_ai_summary(scan_id, error_summary)
                            except Exception as cache_err:
                                logger.warning(f"Failed to cache error state: {cache_err}")
                            
                            # Return user-friendly error to frontend
                            response['ai_summary'] = {
                                'status': 'failed',
                                'error': 'AI summary service is currently unavailable. Please try regenerating the summary later.',
                                'can_retry': True,
                                'title': None,
                                'summary_text': None,
                                'confidence': 0.0,
                                'risk_level': None,
                                'risk_score': None,
                                'key_findings': [],
                                'recommendations': []
                            }
                            response['ai_summary_text'] = None
                        else:
                            # Retry succeeded! Continue with generation
                            logger.info(f"✅ Ollama available on retry, generating AI summary for scan {scan_id}")
                            ollama_health = ollama_health_retry  # Use retry result
                    
                    # If Ollama is healthy (either initially or after retry)
                    if ollama_health['available']:
                        # Ollama is healthy - proceed with generation
                        logger.info(f"Ollama health check passed, generating AI summary for scan {scan_id}")
                        
                        summarizer = ScanAISummarizer()
                        
                        # Convert stored vulnerabilities to Vulnerability objects for AI summarizer
                        vulnerability_objects = []
                        for vuln_dict in stored_vulnerabilities:
                            metadata = vuln_dict.get('metadata', {})
                            
                            # Extract host from metadata (could be in nuclei_data or nmap data)
                            host = metadata.get('host') or metadata.get('matched_at', 'unknown')
                            if isinstance(host, str) and ('http://' in host or 'https://' in host):
                                # Extract hostname from URL
                                from urllib.parse import urlparse
                                try:
                                    parsed = urlparse(host)
                                    host = parsed.netloc or parsed.hostname or host
                                except (ValueError, AttributeError) as e:
                                    logger.debug(f"URL parsing failed for host {host}: {e}")
                                    pass
                            
                            vuln_obj = Vulnerability(
                                id=vuln_dict.get('id', 'unknown'),
                                title=vuln_dict.get('title', 'Unknown Vulnerability'),
                                description=vuln_dict.get('description', ''),
                                severity=vuln_dict.get('severity', 'medium'),
                                host=str(host),
                                port=vuln_dict.get('port'),
                                protocol=vuln_dict.get('protocol', 'tcp'),
                                service=vuln_dict.get('service', 'unknown')
                            )
                            vulnerability_objects.append(vuln_obj)
                        
                        # Create scan report
                        scan_report = ScanReport(
                            scan_name=f"{scan.target if scan else 'Scan'}_{scan_id[:8]}",
                            scan_type="security_assessment",
                            source_tool=scan.tool_name if scan else 'unknown',
                            scan_date=datetime.now().isoformat(),
                            total_findings=len(vulnerability_objects),
                            findings_by_severity=findings_by_severity,
                            vulnerabilities=vulnerability_objects,
                            scan_notes=f"Scan ID: {scan_id}"
                        )
                        
                        # Generate AI summary with proper ScanReport object
                        ai_summary = summarizer.generate_ai_summary(scan_report)
                        
                        if ai_summary and ai_summary.get('executive_summary'):
                            # Successfully generated summary
                            ai_summary['status'] = 'completed'
                            ai_summary['timestamp'] = datetime.now().isoformat()
                            
                            # Store AI summary in database for future use
                            try:
                                ingestor.update_ai_summary(scan_id, ai_summary)
                                logger.info(f"Successfully cached AI summary for scan {scan_id}")
                            except Exception as cache_err:
                                logger.warning(f"Failed to cache AI summary: {cache_err}")
                            
                            # Format summary text for human readability
                            summary_text = ai_summary.get('executive_summary', '')
                            if summary_text:
                                summary_text = str(summary_text).strip()
                                if not summary_text.endswith('.'):
                                    summary_text += '.'
                            
                            response['ai_summary'] = {
                                'status': 'completed',
                                'title': ai_summary.get('title', 'Scan Analysis Report'),
                                'summary': ai_summary.get('summary', summary_text),
                                'summary_text': summary_text,
                                'confidence': min(1.0, max(0.0, float(ai_summary.get('confidence', 0.85)))),
                                'risk_level': str(ai_summary.get('risk_level', 'medium')).lower(),
                                'risk_score': float(ai_summary.get('risk_score', 5.0)),
                                'key_findings': list(ai_summary.get('key_findings', [])),
                                'recommendations': list(ai_summary.get('recommendations', [])),
                                'can_retry': False
                            }
                            response['ai_summary_text'] = ai_summary.get('executive_summary', '')
                        else:
                            # Generation failed (empty response from LLM)
                            logger.error(f"AI summary generation returned empty result for scan {scan_id}")
                            
                            error_summary = {
                                'status': 'failed',
                                'error': 'AI summary generation returned empty result',
                                'error_details': 'LLM did not generate a valid summary',
                                'can_retry': True,
                                'timestamp': datetime.now().isoformat()
                            }
                            
                            try:
                                ingestor.update_ai_summary(scan_id, error_summary)
                            except Exception as cache_err:
                                logger.warning(f"Failed to cache error state: {cache_err}")
                            
                            response['ai_summary'] = {
                                'status': 'failed',
                                'error': 'AI summary generation failed. Please try regenerating the summary.',
                                'can_retry': True,
                                'title': None,
                                'summary_text': None,
                                'confidence': 0.0,
                                'risk_level': None,
                                'risk_score': None,
                                'key_findings': [],
                                'recommendations': []
                            }
                            response['ai_summary_text'] = None
                
                elif cached_ai_summary:
                    # Use cached AI summary from database
                    cached_status = cached_ai_summary.get('status', 'completed')
                    
                    if cached_status == 'failed':
                        # Return cached error state with retry option
                        response['ai_summary'] = {
                            'status': 'failed',
                            'error': cached_ai_summary.get('error', 'AI summary generation failed previously'),
                            'error_details': cached_ai_summary.get('error_details', 'Unknown error'),
                            'can_retry': True,
                            'title': None,
                            'summary_text': None,
                            'confidence': 0.0,
                            'risk_level': None,
                            'risk_score': None,
                            'key_findings': [],
                            'recommendations': []
                        }
                        response['ai_summary_text'] = None
                        logger.info(f"Returned cached error state for scan {scan_id}")
                    else:
                        # Return successful cached summary
                        summary_text = cached_ai_summary.get('executive_summary', '')
                        if summary_text:
                            summary_text = str(summary_text).strip()
                            if not summary_text.endswith('.'):
                                summary_text += '.'
                        
                        response['ai_summary'] = {
                            'status': cached_status,
                            'title': cached_ai_summary.get('title', 'Scan Analysis Report'),
                            'summary': cached_ai_summary.get('summary', summary_text),
                            'summary_text': summary_text,
                            'confidence': min(1.0, max(0.0, float(cached_ai_summary.get('confidence', 0.85)))),
                            'risk_level': str(cached_ai_summary.get('risk_level', 'medium')).lower(),
                            'risk_score': float(cached_ai_summary.get('risk_score', 5.0)),
                            'key_findings': list(cached_ai_summary.get('key_findings', [])),
                            'recommendations': list(cached_ai_summary.get('recommendations', [])),
                            'can_retry': False
                        }
                        response['ai_summary_text'] = cached_ai_summary.get('executive_summary', '')
                        logger.info(f"Returned cached AI summary for scan {scan_id}")
            except Exception as e:
                logger.error(f"Failed to generate AI summary for scan {scan_id}: {str(e)}", exc_info=True)
                
                # Store error in database for tracking
                error_summary = {
                    'status': 'failed',
                    'error': 'Unexpected error during AI summary generation',
                    'error_details': str(e),
                    'can_retry': True,
                    'timestamp': datetime.now().isoformat()
                }
                
                try:
                    from datetime import datetime
                    ingestor.update_ai_summary(scan_id, error_summary)
                except Exception as cache_err:
                    logger.warning(f"Failed to cache error state: {cache_err}")
                
                # Return error to frontend with retry option
                response['ai_summary'] = {
                    'status': 'failed',
                    'error': 'An unexpected error occurred while generating the AI summary. Please try regenerating.',
                    'can_retry': True,
                    'title': None,
                    'summary_text': None,
                    'confidence': 0.0,
                    'risk_level': None,
                    'risk_score': None,
                    'key_findings': [],
                    'recommendations': []
                }
                response['ai_summary_text'] = None

            # Add summary
            if summary:
                # Provide a stable API shape while mapping DB model names.
                response['summary'] = {
                    'hosts_scanned': getattr(summary, 'total_hosts', getattr(summary, 'hosts_scanned', 0)),
                    'hosts_up': getattr(summary, 'hosts_up', None),
                    'total_ports': getattr(summary, 'total_ports', 0),
                    'open_ports': getattr(summary, 'open_ports', None),
                    'vulnerabilities_found': getattr(summary, 'total_vulnerabilities', getattr(summary, 'vulnerabilities_found', 0)),
                    'severity_counts': {
                        'critical': getattr(summary, 'critical_count', 0),
                        'high': getattr(summary, 'high_count', 0),
                        'medium': getattr(summary, 'medium_count', 0),
                        'low': getattr(summary, 'low_count', 0),
                        'info': getattr(summary, 'info_count', 0)
                    },
                    'additional_data': getattr(summary, 'summary_data', {})
                }
                # Override severity counts with freshly calculated ones from stored vulnerabilities
                if findings_by_severity:
                    response['summary']['severity_counts'] = findings_by_severity
                    response['summary']['vulnerabilities_found'] = len(stored_vulnerabilities)
                    
                    # Check if database summary needs updating (has all zeros but we have vulnerabilities)
                    if summary and len(stored_vulnerabilities) > 0:
                        db_total = (getattr(summary, 'critical_count', 0) + 
                                   getattr(summary, 'high_count', 0) + 
                                   getattr(summary, 'medium_count', 0) + 
                                   getattr(summary, 'low_count', 0) + 
                                   getattr(summary, 'info_count', 0))
                        
                        # If database summary is empty but we have vulnerabilities, update it
                        if db_total == 0:
                            try:
                                logger.info(f"Updating stale summary for scan {scan_id} with recalculated counts: {findings_by_severity}")
                                
                                # Update the database summary with fresh counts
                                from services.data_ingestor.models import SessionLocal, ScanSummary
                                db = SessionLocal()
                                try:
                                    db_summary = db.query(ScanSummary).filter(ScanSummary.scan_id == scan_id).first()
                                    if db_summary:
                                        db_summary.total_vulnerabilities = len(stored_vulnerabilities)
                                        db_summary.critical_count = findings_by_severity.get('critical', 0)
                                        db_summary.high_count = findings_by_severity.get('high', 0)
                                        db_summary.medium_count = findings_by_severity.get('medium', 0)
                                        db_summary.low_count = findings_by_severity.get('low', 0)
                                        db_summary.info_count = findings_by_severity.get('info', 0)
                                        from datetime import datetime
                                        db_summary.updated_at = datetime.utcnow()
                                        db.commit()
                                        logger.info(f"Successfully updated summary in database for scan {scan_id}")
                                finally:
                                    db.close()
                            except Exception as update_err:
                                logger.warning(f"Failed to update database summary: {update_err}")

            return response

        except NotFound:
            raise
        except Exception as e:
            scans_ns.abort(500, f"Failed to get parsed results: {str(e)}")


@scans_ns.route('/<string:scan_id>/summary')
@scans_ns.param('scan_id', 'The scan identifier')
class ScanSummaryResource(Resource):
    """Scan summary endpoint"""

    @scans_ns.doc('get_scan_summary')
    def get(self, scan_id):
        """Get scan summary with statistics"""
        try:
            # Get the scan
            scan = ingestor.get_scan(scan_id)
            if not scan:
                raise NotFound(f"Scan {scan_id} not found")

            # Get scan summary if available
            summary = ingestor.get_scan_summary(scan_id)

            if summary:
                # Return nested structure that frontend expects
                return {
                    'summary': {
                        'scan_id': str(scan.id),
                        'target': scan.target,
                        'tool_name': scan.tool_name,
                        'scan_type': scan.scan_type,
                        'status': scan.status.value,
                        'created_at': scan.created_at.isoformat() if scan.created_at else None,
                        'started_at': scan.started_at.isoformat() if scan.started_at else None,
                        'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
                        'execution_time': scan.execution_time,
                        'hosts_scanned': getattr(summary, 'total_hosts', getattr(summary, 'hosts_scanned', 0)),
                        'hosts_up': getattr(summary, 'hosts_up', None),
                        'total_ports': getattr(summary, 'total_ports', 0),
                        'open_ports': getattr(summary, 'open_ports', None),
                        'vulnerabilities_found': getattr(summary, 'total_vulnerabilities', getattr(summary, 'vulnerabilities_found', 0)),
                        'critical_count': getattr(summary, 'critical_count', 0),
                        'high_count': getattr(summary, 'high_count', 0),
                        'medium_count': getattr(summary, 'medium_count', 0),
                        'low_count': getattr(summary, 'low_count', 0),
                        'info_count': getattr(summary, 'info_count', 0)
                    }
                }
            else:
                # Return basic scan info if no summary exists
                return {
                    'summary': {
                        'scan_id': str(scan.id),
                        'target': scan.target,
                        'tool_name': scan.tool_name,
                        'scan_type': scan.scan_type,
                        'status': scan.status.value,
                        'created_at': scan.created_at.isoformat() if scan.created_at else None,
                        'started_at': scan.started_at.isoformat() if scan.started_at else None,
                        'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
                        'execution_time': scan.execution_time,
                        'message': 'Summary data not yet available',
                        'critical_count': 0,
                        'high_count': 0,
                        'medium_count': 0,
                        'low_count': 0,
                        'info_count': 0
                    }
                }

        except NotFound:
            raise
        except Exception as e:
            scans_ns.abort(500, f"Failed to get scan summary: {str(e)}")


@scans_ns.route('/<string:scan_id>/regenerate-summary')
@scans_ns.param('scan_id', 'The scan identifier')
class RegenerateAISummary(Resource):
    """Regenerate AI summary for a scan"""

    @scans_ns.doc('regenerate_ai_summary')
    def post(self, scan_id):
        """
        Manually regenerate AI summary for a scan.
        Useful when initial generation failed or Ollama was unavailable.
        """
        try:
            from intelligence_layer.rag.scan_processor import ScanAISummarizer, ScanReport, Vulnerability
            from datetime import datetime
            
            # Get scan to verify it exists
            scan = ingestor.get_scan(scan_id)
            if not scan:
                raise NotFound(f"Scan {scan_id} not found")
            
            # Clear any previous error state and mark as generating
            try:
                generating_state = {
                    'status': 'generating',
                    'timestamp': datetime.now().isoformat()
                }
                ingestor.update_ai_summary(scan_id, generating_state)
                logger.info(f"Marked scan {scan_id} as generating AI summary")
            except Exception as state_err:
                logger.warning(f"Failed to update generating state: {state_err}")
            
            # Pre-flight health check
            ollama_health = check_ollama_health(timeout=5)
            
            if not ollama_health['available']:
                logger.warning(f"Ollama unavailable for regeneration of scan {scan_id}: {ollama_health['error']}")
                
                # Store error state
                error_summary = {
                    'status': 'failed',
                    'error': 'AI service is currently unavailable',
                    'error_details': ollama_health['error'],
                    'can_retry': True,
                    'timestamp': datetime.now().isoformat()
                }
                try:
                    ingestor.update_ai_summary(scan_id, error_summary)
                except Exception as cache_err:
                    logger.warning(f"Failed to cache error state: {cache_err}")
                
                return {
                    'success': False,
                    'status': 'failed',
                    'error': 'AI service is currently unavailable',
                    'error_details': ollama_health['error'],
                    'message': 'Cannot regenerate summary while AI service is offline. Please try again later.'
                }, 503
            
            # Get stored vulnerabilities
            stored_vulnerabilities = ingestor.get_vulnerabilities(scan_id)
            
            if not stored_vulnerabilities:
                return {
                    'success': False,
                    'status': 'failed',
                    'error': 'No vulnerabilities found for this scan',
                    'message': 'Cannot generate AI summary for a scan with no vulnerabilities.'
                }, 400
            
            logger.info(f"Starting AI summary regeneration for scan {scan_id} with {len(stored_vulnerabilities)} vulnerabilities")
            
            # Build severity counts
            findings_by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            for vuln in stored_vulnerabilities:
                severity = vuln.get('severity', 'unknown').lower()
                if severity in findings_by_severity:
                    findings_by_severity[severity] += 1
            
            # Convert vulnerabilities to objects
            vulnerability_objects = []
            for vuln_dict in stored_vulnerabilities:
                metadata = vuln_dict.get('metadata', {})
                host = metadata.get('host') or metadata.get('matched_at', 'unknown')
                
                if isinstance(host, str) and ('http://' in host or 'https://' in host):
                    from urllib.parse import urlparse
                    try:
                        parsed = urlparse(host)
                        host = parsed.netloc or parsed.hostname or host
                    except (ValueError, AttributeError) as e:
                        logger.debug(f"URL parsing failed for host {host}: {e}")
                        pass
                
                vuln_obj = Vulnerability(
                    id=vuln_dict.get('id', 'unknown'),
                    title=vuln_dict.get('title', 'Unknown Vulnerability'),
                    description=vuln_dict.get('description', ''),
                    severity=vuln_dict.get('severity', 'medium'),
                    host=str(host),
                    port=vuln_dict.get('port'),
                    protocol=vuln_dict.get('protocol', 'tcp'),
                    service=vuln_dict.get('service', 'unknown')
                )
                vulnerability_objects.append(vuln_obj)
            
            # Create scan report
            scan_report = ScanReport(
                scan_name=f"{scan.target if scan else 'Scan'}_{scan_id[:8]}",
                scan_type="security_assessment",
                source_tool=scan.tool_name if scan else 'unknown',
                scan_date=datetime.now().isoformat(),
                total_findings=len(vulnerability_objects),
                findings_by_severity=findings_by_severity,
                vulnerabilities=vulnerability_objects,
                scan_notes=f"Scan ID: {scan_id} (Regenerated)"
            )
            
            # Generate AI summary
            summarizer = ScanAISummarizer()
            ai_summary = summarizer.generate_ai_summary(scan_report)
            
            if ai_summary and ai_summary.get('executive_summary'):
                # Successfully generated
                ai_summary['status'] = 'completed'
                ai_summary['timestamp'] = datetime.now().isoformat()
                ai_summary['regenerated'] = True
                
                # Store in database
                try:
                    ingestor.update_ai_summary(scan_id, ai_summary)
                    logger.info(f"Successfully regenerated and cached AI summary for scan {scan_id}")
                except Exception as cache_err:
                    logger.warning(f"Failed to cache regenerated summary: {cache_err}")
                
                return {
                    'success': True,
                    'status': 'completed',
                    'message': 'AI summary regenerated successfully',
                    'summary': {
                        'title': ai_summary.get('title', 'Scan Analysis Report'),
                        'executive_summary': ai_summary.get('executive_summary', ''),
                        'confidence': ai_summary.get('confidence', 0.85),
                        'risk_level': ai_summary.get('risk_level', 'medium'),
                        'risk_score': ai_summary.get('risk_score', 5.0),
                        'key_findings': ai_summary.get('key_findings', []),
                        'recommendations': ai_summary.get('recommendations', [])
                    }
                }, 200
            else:
                # Generation failed
                logger.error(f"AI summary regeneration returned empty result for scan {scan_id}")
                
                error_summary = {
                    'status': 'failed',
                    'error': 'AI summary regeneration returned empty result',
                    'error_details': 'LLM did not generate a valid summary',
                    'can_retry': True,
                    'timestamp': datetime.now().isoformat()
                }
                
                try:
                    ingestor.update_ai_summary(scan_id, error_summary)
                except Exception as cache_err:
                    logger.warning(f"Failed to cache error state: {cache_err}")
                
                return {
                    'success': False,
                    'status': 'failed',
                    'error': 'AI summary generation returned empty result',
                    'message': 'The AI service did not generate a valid summary. This may be due to LLM timeout or model issues.'
                }, 500
        
        except NotFound:
            raise
        except Exception as e:
            logger.error(f"Failed to regenerate AI summary for scan {scan_id}: {str(e)}", exc_info=True)
            
            # Store error state
            error_summary = {
                'status': 'failed',
                'error': 'Unexpected error during regeneration',
                'error_details': str(e),
                'can_retry': True,
                'timestamp': datetime.now().isoformat()
            }
            
            try:
                from datetime import datetime
                ingestor.update_ai_summary(scan_id, error_summary)
            except Exception as cache_err:
                logger.warning(f"Failed to cache error state: {cache_err}")
            
            return {
                'success': False,
                'status': 'failed',
                'error': str(e),
                'message': 'An unexpected error occurred during regeneration. Please try again later.'
            }, 500


@scans_ns.route('/<string:scan_id>/export/<string:format>')
@scans_ns.param('scan_id', 'The scan identifier')
@scans_ns.param('format', 'Export format (json, csv, xlsx, pdf)')
class ScanExport(Resource):
    """Scan export endpoint"""

    @scans_ns.doc('export_scan')
    def get(self, scan_id, format):
        """Export scan results in specified format"""
        from datetime import datetime

        from flask import send_file

        from services.export_service.exporters import ExportManager

        try:
            # Validate format
            valid_formats = ['json', 'csv', 'xlsx', 'pdf', 'xml']
            format = format.lower()

            if format not in valid_formats:
                scans_ns.abort(
                    400, f"Invalid export format. Supported: {', '.join(valid_formats)}")

            # Get scan data
            scan = ingestor.get_scan(scan_id)
            if not scan:
                raise NotFound(f"Scan {scan_id} not found")

            # Get parsed results
            results = ingestor.get_raw_results(scan_id)
            summary = ingestor.get_scan_summary(scan_id)

            # Build complete scan data
            scan_data = scan.to_dict()
            scan_data['parsed_results'] = []

            for result in results:
                if result.parsed_output:
                    scan_data['parsed_results'].append({
                        'tool_name': result.tool_name,
                        'data': result.parsed_output,
                        'timestamp': result.timestamp.isoformat() if result.timestamp else None
                    })

            # Add summary
            if summary:
                scan_data['summary'] = {
                    'hosts_scanned': getattr(summary, 'total_hosts', getattr(summary, 'hosts_scanned', 0)),
                    'hosts_up': getattr(summary, 'hosts_up', None),
                    'total_ports': getattr(summary, 'total_ports', 0),
                    'open_ports': getattr(summary, 'open_ports', None),
                    'vulnerabilities_found': getattr(summary, 'total_vulnerabilities', getattr(summary, 'vulnerabilities_found', 0)),
                    'critical_count': getattr(summary, 'critical_count', 0),
                    'high_count': getattr(summary, 'high_count', 0),
                    'medium_count': getattr(summary, 'medium_count', 0),
                    'low_count': getattr(summary, 'low_count', 0),
                    'info_count': getattr(summary, 'info_count', 0),
                    'additional_data': getattr(summary, 'summary_data', {})
                }
            else:
                # Create empty summary if not available
                scan_data['summary'] = {
                    'hosts_scanned': 0,
                    'hosts_up': 0,
                    'total_ports': 0,
                    'open_ports': 0,
                    'vulnerabilities_found': 0,
                    'critical_count': 0,
                    'high_count': 0,
                    'medium_count': 0,
                    'low_count': 0,
                    'info_count': 0,
                    'additional_data': {}
                }

            # Export scan data
            output_buffer = ExportManager.export_scan(scan_data, format)

            # Generate filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"scan_{scan_data.get('target', 'unknown')}_{timestamp}.{format}"

            # Get content type
            content_type = ExportManager.get_content_type(format)

            # Send file
            return send_file(
                output_buffer,
                mimetype=content_type,
                as_attachment=True,
                download_name=filename
            )

        except NotFound:
            raise
        except BadRequest:
            raise  # Don't convert BadRequest to 500
        except ValueError as e:
            scans_ns.abort(400, str(e))
        except Exception as e:
            logger.error("Export failed: %s", e, exc_info=True)
            scans_ns.abort(500, f"Failed to export scan: {str(e)}")


# Create additional namespaces
tools_ns = Namespace('tools', description='Scanning tools information')
stats_ns = Namespace('stats', description='Platform statistics')


@tools_ns.route('/')
class ToolsList(Resource):
    """Available scanning tools endpoint"""

    @tools_ns.doc('list_tools')
    def get(self):
        """Get list of available scanning tools with their capabilities"""
        try:
            tools = [{'name': 'nmap',
                      'display_name': 'Nmap',
                      'description': 'Network port scanner and service detection tool',
                      'category': 'Network Scanner',
                      'supported_scan_types': ['quick',
                                               'basic',
                                               'full',
                                               'stealth',
                                               'custom'],
                      'capabilities': ['Port Scanning',
                                       'Service Detection',
                                       'OS Detection',
                                       'Script Scanning']},
                     {'name': 'openvas',
                      'display_name': 'OpenVAS',
                      'description': 'Comprehensive vulnerability assessment scanner',
                      'category': 'Vulnerability Scanner',
                      'supported_scan_types': ['basic',
                                               'full',
                                               'discovery',
                                               'system',
                                               'custom'],
                      'capabilities': ['CVE Detection',
                                       'Misconfiguration',
                                       'Patch Management',
                                       'Compliance']},
                     {'name': 'nikto',
                      'display_name': 'Nikto',
                      'description': 'Web server scanner for vulnerabilities and misconfigurations',
                      'category': 'Web Scanner',
                      'supported_scan_types': ['quick',
                                               'basic',
                                               'full',
                                               'ssl',
                                               'custom'],
                      'capabilities': ['Dangerous Files',
                                       'Outdated Software',
                                       'Server Config',
                                       'SSL/TLS Issues']},
                     {'name': 'nuclei',
                      'display_name': 'Nuclei',
                      'description': 'Fast template-based vulnerability scanner',
                      'category': 'Web Scanner',
                      'supported_scan_types': ['basic',
                                               'full',
                                               'cve',
                                               'misconfig',
                                               'exposed',
                                               'custom'],
                      'capabilities': ['CVE Detection',
                                       'Misconfigurations',
                                       'Exposed Panels',
                                       'Template-based']}]

            return sanitize_output({'tools': tools, 'count': len(tools)})

        except Exception as e:
            tools_ns.abort(500, f"Failed to list tools: {str(e)}")


@stats_ns.route('/')
class StatsResource(Resource):
    """Statistics endpoint"""

    @stats_ns.doc('get_stats')
    def get(self):
        """Get overall scan statistics"""
        try:
            # Get scans for statistics (limited to 10K for performance)
            all_scans, total_count = ingestor.list_scans(limit=10000, offset=0)
            
            # Safety check: Warn if approaching limit
            if total_count > 9500:
                logger.warning(
                    "Statistics may be incomplete: %d total scans, only processing first 10,000. "
                    "Consider implementing database aggregation for statistics at scale.",
                    total_count
                )

            # Calculate statistics
            stats = {
                'total_scans': total_count,
                'stats_based_on': len(all_scans),  # Indicate sampling if limited
                'status_breakdown': {
                    'pending': 0,
                    'queued': 0,
                    'running': 0,
                    'completed': 0,
                    'failed': 0,
                    'cancelled': 0
                },
                'tool_usage': {},
                'scan_type_usage': {},
                'vulnerabilities': {
                    'total': 0,
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'info': 0
                }
            }

            # Aggregate data
            for scan in all_scans:
                # Status breakdown
                if scan.status:
                    status_key = scan.status.value.lower()
                    if status_key in stats['status_breakdown']:
                        stats['status_breakdown'][status_key] += 1

                # Tool usage
                if scan.tool_name:
                    stats['tool_usage'][scan.tool_name] = stats['tool_usage'].get(
                        scan.tool_name, 0) + 1

                # Scan type usage
                if scan.scan_type:
                    stats['scan_type_usage'][scan.scan_type] = stats['scan_type_usage'].get(
                        scan.scan_type, 0) + 1

            # Get vulnerability summary using SQL aggregation (Issue P2 - Unbounded query fix)
            try:
                session = ingestor.get_session()
                from services.data_ingestor.models import ScanSummary
                from sqlalchemy import func
                
                # Use SQL aggregation instead of loading all records
                result = session.query(
                    func.sum(ScanSummary.total_vulnerabilities).label('total'),
                    func.sum(ScanSummary.critical_count).label('critical'),
                    func.sum(ScanSummary.high_count).label('high'),
                    func.sum(ScanSummary.medium_count).label('medium'),
                    func.sum(ScanSummary.low_count).label('low'),
                    func.sum(ScanSummary.info_count).label('info')
                ).first()
                
                if result:
                    stats['vulnerabilities']['total'] += result.total or 0
                    stats['vulnerabilities']['critical'] += result.critical or 0
                    stats['vulnerabilities']['high'] += result.high or 0
                    stats['vulnerabilities']['medium'] += result.medium or 0
                    stats['vulnerabilities']['low'] += result.low or 0
                    stats['vulnerabilities']['info'] += result.info or 0

                session.close()
            except Exception as e:
                logger.warning("Could not fetch vulnerability stats: %s", str(e))

            # Calculate additional metrics
            completed_scans = stats['status_breakdown']['completed']
            failed_scans = stats['status_breakdown']['failed']
            total_finished = completed_scans + failed_scans

            stats['success_rate'] = (
                round((completed_scans / total_finished * 100), 2)
                if total_finished > 0 else 0
            )

            stats['active_scans'] = (
                stats['status_breakdown']['pending'] +
                stats['status_breakdown']['queued'] +
                stats['status_breakdown']['running']
            )

            return sanitize_output(stats)

        except Exception as e:
            logger.error("Error getting stats: %s", str(e))
            stats_ns.abort(500, f"Failed to get statistics: {str(e)}")


@stats_ns.route('/summary')
class StatsSummary(Resource):
    """Quick statistics summary endpoint"""

    @stats_ns.doc('get_stats_summary')
    def get(self):
        """Get quick statistics summary"""
        try:
            # Get all scans
            all_scans, total_count = ingestor.list_scans(limit=10000, offset=0)

            # Calculate statistics
            stats = {
                'total_scans': total_count,
                'status_breakdown': {
                    'pending': 0,
                    'queued': 0,
                    'running': 0,
                    'completed': 0,
                    'failed': 0,
                    'cancelled': 0
                },
                'tool_usage': {},
                'scan_type_usage': {},
                'vulnerabilities': {
                    'total': 0,
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'info': 0
                }
            }

            # Aggregate data
            for scan in all_scans:
                # Status breakdown
                if scan.status:
                    status_key = scan.status.value.lower()
                    if status_key in stats['status_breakdown']:
                        stats['status_breakdown'][status_key] += 1

                # Tool usage
                if scan.tool_name:
                    stats['tool_usage'][scan.tool_name] = stats['tool_usage'].get(
                        scan.tool_name, 0) + 1

                # Scan type usage
                if scan.scan_type:
                    stats['scan_type_usage'][scan.scan_type] = stats['scan_type_usage'].get(
                        scan.scan_type, 0) + 1

            # Get vulnerability summary using SQL aggregation (Issue P2 - Unbounded query fix)
            try:
                session = ingestor.get_session()
                from services.data_ingestor.models import ScanSummary
                from sqlalchemy import func
                
                # Use SQL aggregation instead of loading all records
                result = session.query(
                    func.sum(ScanSummary.vulnerabilities_found).label('total'),
                    func.sum(ScanSummary.critical_count).label('critical'),
                    func.sum(ScanSummary.high_count).label('high'),
                    func.sum(ScanSummary.medium_count).label('medium'),
                    func.sum(ScanSummary.low_count).label('low'),
                    func.sum(ScanSummary.info_count).label('info')
                ).first()
                
                if result:
                    stats['vulnerabilities']['total'] += result.total or 0
                    stats['vulnerabilities']['critical'] += result.critical or 0
                    stats['vulnerabilities']['high'] += result.high or 0
                    stats['vulnerabilities']['medium'] += result.medium or 0
                    stats['vulnerabilities']['low'] += result.low or 0
                    stats['vulnerabilities']['info'] += result.info or 0

                session.close()
            except Exception as e:
                logger.warning(
                    "Could not fetch vulnerability stats: %s", str(e))

            # Calculate additional metrics
            completed_scans = stats['status_breakdown']['completed']
            failed_scans = stats['status_breakdown']['failed']
            total_finished = completed_scans + failed_scans

            stats['success_rate'] = (
                round((completed_scans / total_finished * 100), 2)
                if total_finished > 0 else 0
            )

            stats['active_scans'] = (
                stats['status_breakdown']['pending'] +
                stats['status_breakdown']['queued'] +
                stats['status_breakdown']['running']
            )

            return sanitize_output(stats)

        except Exception as e:
            logger.error("Error getting stats: %s", str(e))
            stats_ns.abort(500, f"Failed to get statistics: {str(e)}")


@stats_ns.route('/summary')
class QuickStatsSummary(Resource):
    """Quick statistics summary endpoint"""

    @stats_ns.doc('get_stats_summary')
    def get(self):
        """Get quick statistics summary"""
        try:
            # Get basic scan counts
            all_scans, total_count = ingestor.list_scans(limit=10000, offset=0)
            
            completed = sum(1 for s in all_scans if s.status == ScanStatus.COMPLETED)
            running = sum(1 for s in all_scans if s.status == ScanStatus.RUNNING)
            failed = sum(1 for s in all_scans if s.status == ScanStatus.FAILED)
            
            summary = {
                'total_scans': total_count,
                'completed': completed,
                'running': running,
                'failed': failed,
                'success_rate': round((completed / (completed + failed) * 100), 2) if (completed + failed) > 0 else 0
            }
            
            return sanitize_output(summary)
            
        except Exception as e:
            logger.error("Error getting stats summary: %s", str(e))
            stats_ns.abort(500, f"Failed to get statistics summary: {str(e)}")


@scans_ns.route('/stats')
class ScanStatistics(Resource):
    """Scan statistics endpoint under /api/scans"""

    @scans_ns.doc('get_scan_statistics')
    def get(self):
        """Get scan statistics"""
        try:
            # Get all scans
            all_scans, total = ingestor.list_scans(limit=10000)

            # Calculate statistics
            stats = {
                'total_scans': total,
                'completed_scans': sum(1 for s in all_scans if s.status == ScanStatus.COMPLETED),
                'running_scans': sum(1 for s in all_scans if s.status == ScanStatus.RUNNING),
                'pending_scans': sum(1 for s in all_scans if s.status == ScanStatus.PENDING),
                'failed_scans': sum(1 for s in all_scans if s.status == ScanStatus.FAILED),
                'cancelled_scans': sum(1 for s in all_scans if s.status == ScanStatus.CANCELLED),
            }

            # Tool breakdown
            tool_counts = {}
            for scan in all_scans:
                tool = scan.tool_name
                tool_counts[tool] = tool_counts.get(tool, 0) + 1
            stats['tools'] = tool_counts

            return sanitize_output(stats)
        except Exception as e:
            logger.error("Failed to get statistics: %s", e)
            scans_ns.abort(500, "Failed to get statistics")


# 🆕 Phase 2 Day 8: Bulk Operations Endpoints
bulk_delete_model = scans_ns.model(
    'BulkDeleteRequest', {
        'scan_ids': fields.List(
            fields.String, required=True, description='List of scan IDs to delete', example=[
                'scan-123', 'scan-456'])})

bulk_delete_response_model = scans_ns.model(
    'BulkDeleteResponse', {
        'deleted': fields.Integer(
            description='Number of scans successfully deleted'), 'total': fields.Integer(
                description='Total number of scans requested'), 'failed': fields.List(
                    fields.String, description='List of scan IDs that failed to delete')})

bulk_export_model = scans_ns.model(
    'BulkExportRequest', {
        'scan_ids': fields.List(
            fields.String, required=True, description='List of scan IDs to export'), 'format': fields.String(
                required=False, description='Export format', enum=[
                    'json', 'csv', 'xlsx', 'pdf'], default='pdf')})


@scans_ns.route('/bulk/delete')
class BulkDelete(Resource):
    """Bulk delete scans endpoint"""

    @scans_ns.doc('bulk_delete_scans')
    @scans_ns.expect(bulk_delete_model)
    @scans_ns.response(200,
                       'Scans deleted successfully',
                       bulk_delete_response_model)
    @scans_ns.response(400, 'Invalid request')
    @scans_ns.response(500, 'Internal server error')
    def post(self):
        """
        Delete multiple scans

        Deletes multiple scans and all associated data (raw results, parsed results, summaries)
        """
        try:
            # Debugging: log incoming headers and raw body to diagnose client/server mismatch
            try:
                logger.info("Bulk delete incoming headers: %s", dict(request.headers))
            except Exception:
                logger.info("Bulk delete incoming headers: <unserializable headers>")

            raw = request.get_data(as_text=True)
            logger.info("Bulk delete raw body length=%d", len(raw) if raw is not None else 0)
            # Log a truncated preview of the body to avoid huge logs
            if raw:
                logger.info("Bulk delete raw body preview: %s", raw[:1000])

            # Log configured maximum to ensure runtime value is visible
            logger.info("Configured MAX_BULK_DELETE=%s", getattr(config, 'MAX_BULK_DELETE', 100))

            # Parse JSON safely and return 400 if invalid JSON was sent
            data = request.get_json(silent=True)
            if data is None:
                logger.warning("Bulk delete: request JSON parsing returned None or invalid JSON")
                scans_ns.abort(400, "Invalid JSON body")

            scan_ids = data.get('scan_ids', [])

            if not scan_ids:
                scans_ns.abort(400, "No scan IDs provided")

            # Respect configured maximum for bulk operations (config.MAX_BULK_DELETE)
            max_bulk = getattr(config, 'MAX_BULK_DELETE', 100)
            if len(scan_ids) > max_bulk:
                scans_ns.abort(
                    400, f"Cannot delete more than {max_bulk} scans at once")

            logger.info("🗑️ Bulk delete request for %s scans", len(scan_ids))

            deleted = 0
            failed = []

            for scan_id in scan_ids:
                try:
                    # Delete from all tables
                    ingestor.delete_scan(scan_id)  # This should cascade delete related records
                    # Note: delete_raw_results, delete_parsed_results, delete_summary
                    # are handled by cascade delete in delete_scan
                    deleted += 1
                    logger.info("✅ Deleted scan %s", scan_id)
                except Exception as e:
                    logger.error("❌ Failed to delete %s: %s", scan_id, str(e))
                    failed.append(scan_id)

            logger.info(
                "🎯 Bulk delete complete: %d/%d successful", deleted, len(scan_ids))

            response_data = {
                'deleted': deleted,
                'total': len(scan_ids),
                'failed': failed
            }
            return sanitize_output(response_data), 200

        except BadRequest as e:
            raise e
        except Exception as e:
            logger.error("Error in bulk delete: %s", str(e))
            scans_ns.abort(500, f"Bulk delete failed: {str(e)}")


@scans_ns.route('/bulk/export')
class BulkExport(Resource):
    """Bulk export scans endpoint"""

    @scans_ns.doc('bulk_export_scans')
    @scans_ns.expect(bulk_export_model)
    @scans_ns.response(200, 'ZIP file with exported scans')
    @scans_ns.response(400, 'Invalid request')
    @scans_ns.response(500, 'Internal server error')
    def post(self):
        """
        Export multiple scans as ZIP

        Creates a ZIP archive containing exported scan results in the specified format
        """
        import io
        import zipfile

        from flask import send_file

        from services.export_service.exporters import ExportManager

        try:
            data = request.get_json()
            scan_ids = data.get('scan_ids', [])
            format_type = data.get('format', 'pdf')

            if not scan_ids:
                scans_ns.abort(400, "No scan IDs provided")

            if len(scan_ids) > 50:
                scans_ns.abort(400, "Cannot export more than 50 scans at once")

            if format_type not in ['json', 'csv', 'xlsx', 'pdf', 'xml']:
                scans_ns.abort(400, f"Unsupported format: {format_type}")

            logger.info(
                "📦 Bulk export request for %d scans in %s format", len(scan_ids), format_type)

            # ExportManager uses classmethods, no need to instantiate
            zip_buffer = io.BytesIO()

            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                exported_count = 0

                for scan_id in scan_ids:
                    try:
                        # Get scan data
                        scan = ingestor.get_scan(scan_id)
                        if not scan:
                            logger.warning(
                                "⚠️ Scan %s not found, skipping", scan_id)
                            continue

                        # Build scan data for export
                        scan_data = scan.to_dict()
                        
                        # Get results
                        results = ingestor.get_raw_results(scan_id)
                        scan_data['parsed_results'] = []
                        for result in results:
                            if result.parsed_output:
                                scan_data['parsed_results'].append({
                                    'tool_name': result.tool_name,
                                    'data': result.parsed_output,
                                    'timestamp': result.timestamp.isoformat() if result.timestamp else None
                                })
                        
                        # Export scan using classmethod
                        result_buffer = ExportManager.export_scan(scan_data, format_type)

                        # Add to ZIP with proper filename
                        filename = f"scan-{scan_id[:8]}-{scan.target.replace('/', '_')}.{format_type}"
                        zip_file.writestr(filename, result_buffer.getvalue())

                        exported_count += 1
                        logger.info(
                            "✅ Exported scan %s (%d/%d)", scan_id, exported_count, len(scan_ids))

                    except Exception as e:
                        logger.error("❌ Failed to export %s: %s", scan_id, str(e))
                        # Continue with other scans
                        continue

            if exported_count == 0:
                scans_ns.abort(404, "No scans could be exported")

            logger.info(
                "🎯 Bulk export complete: %d/%d scans exported", exported_count, len(scan_ids))

            # Prepare ZIP for download
            zip_buffer.seek(0)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'bulk-export-{timestamp}.zip'

            return send_file(
                zip_buffer,
                mimetype='application/zip',
                as_attachment=True,
                download_name=filename
            )

        except BadRequest:
            raise  # Don't convert BadRequest to 500
        except NotFound:
            raise  # Don't convert NotFound to 500
        except Exception as e:
            logger.error("Error in bulk export: %s", str(e))
            scans_ns.abort(500, f"Bulk export failed: {str(e)}")


def register_routes(api):
    """
    Register all API namespaces

    Args:
        api: Flask-RESTX Api instance
    """
    api.add_namespace(scans_ns, path='/scans')
    api.add_namespace(tools_ns, path='/tools')
    api.add_namespace(stats_ns, path='/stats')
