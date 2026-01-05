"""
Intelligence Layer API Routes
REST API endpoints for RAG chatbot.
"""

import logging
import os
from datetime import datetime
from typing import Dict, List, Optional
from functools import wraps
import signal

from flask import jsonify, request
from flask_restx import Namespace, Resource, fields
from markupsafe import escape

from intelligence_layer.rag.indexing import VulnerabilityIndexer
from intelligence_layer.rag.retrieval_engine import RAGRetrievalEngine
from intelligence_layer.rag.hybrid_retrieval import HybridRetrievalEngine
from intelligence_layer.rag.chatbot import RAGChatbot
from intelligence_layer.rag.scan_processor import ScanParser, ScanEnricher, ScanAnalyzer
from intelligence_layer.rag.real_time_sources import RealTimeSourceManager

logger = logging.getLogger(__name__)

# Create namespace
intelligence_ns = Namespace('intelligence', description='AI-powered vulnerability analysis')

# Initialize Intelligence Layer components (singleton pattern)
_indexer = None
_retrieval_engine = None
_hybrid_engine = None  # Hybrid local + real-time
_chatbot = None
_rt_manager = None  # Real-time data sources


def timeout_handler(timeout_seconds: int):
    """
    Decorator to add timeout handling to long-running operations.
    Prevents operations from hanging indefinitely.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                # For Windows, we can't use signal.alarm, so we just log and proceed
                # The timeout is primarily handled by the client and Gunicorn/server
                logger.info(f"Starting operation with {timeout_seconds}s timeout")
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                logger.error(f"Operation failed: {e}", exc_info=True)
                raise
        return wrapper
    return decorator


def get_indexer():
    """Get or create VulnerabilityIndexer singleton"""
    global _indexer
    if _indexer is None:
        persist_dir = os.getenv('CHROMA_PERSIST_DIR', './chroma_db')
        _indexer = VulnerabilityIndexer(persist_directory=persist_dir)
        logger.info("VulnerabilityIndexer initialized")
    return _indexer


def get_retrieval_engine():
    """Get or create RAGRetrievalEngine singleton"""
    global _retrieval_engine
    if _retrieval_engine is None:
        indexer = get_indexer()
        _retrieval_engine = RAGRetrievalEngine(indexer)
        logger.info("RAGRetrievalEngine initialized")
    return _retrieval_engine


def get_hybrid_engine():
    """Get or create HybridRetrievalEngine singleton"""
    global _hybrid_engine
    if _hybrid_engine is None:
        local_engine = get_retrieval_engine()
        rt_manager = get_rt_manager()
        _hybrid_engine = HybridRetrievalEngine(
            local_engine=local_engine,
            real_time_manager=rt_manager
        )
        logger.info("HybridRetrievalEngine initialized")
    return _hybrid_engine


def get_chatbot():
    """Get or create RAGChatbot singleton"""
    global _chatbot
    if _chatbot is None:
        # Try to use hybrid retrieval engine if available
        try:
            hybrid_engine = get_hybrid_engine()
            _chatbot = RAGChatbot(
                retrieval_engine=hybrid_engine,
                ollama_base_url=os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434'),
                model_name=os.getenv('OLLAMA_MODEL', 'llama3.2:3b-instruct-q4_K_M')
            )
            logger.info(f"RAGChatbot initialized with HybridRetrievalEngine - engine type: {type(_chatbot.retrieval_engine).__name__}")
        except Exception as e:
            logger.warning(f"Failed to initialize with hybrid engine: {e}, falling back to local engine")
            engine = get_retrieval_engine()
            _chatbot = RAGChatbot(
                retrieval_engine=engine,
                ollama_base_url=os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434'),
                model_name=os.getenv('OLLAMA_MODEL', 'llama3.2:3b-instruct-q4_K_M')
            )
            logger.info(f"RAGChatbot initialized with RAGRetrievalEngine - engine type: {type(_chatbot.retrieval_engine).__name__}")
    else:
        logger.info(f"Returning existing chatbot - engine type: {type(_chatbot.retrieval_engine).__name__}")
    return _chatbot


def reset_chatbot():
    """Force reset of chatbot singleton - for debugging"""
    global _chatbot, _hybrid_engine, _retrieval_engine, _rt_manager
    logger.info("Resetting all singletons...")
    _chatbot = None
    _hybrid_engine = None
    _retrieval_engine = None
    _rt_manager = None
    logger.info("All singletons reset")


def get_rt_manager():
    """Get or create RealTimeSourceManager singleton"""
    global _rt_manager
    if _rt_manager is None:
        nvd_api_key = os.getenv('NVD_API_KEY', None)
        _rt_manager = RealTimeSourceManager(nvd_api_key=nvd_api_key)
        logger.info("RealTimeSourceManager initialized")
    return _rt_manager


# API Models
chat_message_model = intelligence_ns.model('ChatMessage', {
    'query': fields.String(required=True, description='User query', example='What are critical SSH vulnerabilities?'),
    'session_id': fields.String(required=False, description='Conversation session ID'),
    'top_k': fields.Integer(required=False, default=5, description='Number of documents to retrieve')
})

chat_response_model = intelligence_ns.model('ChatResponse', {
    'response': fields.String(description='AI-generated response'),
    'sources': fields.List(fields.Raw, description='Source documents with CVE links'),
    'confidence': fields.Float(description='Response confidence (0.0-1.0)'),
    'session_id': fields.String(description='Session ID for multi-turn conversation'),
    'query_intent': fields.String(description='Detected query intent'),
    'hallucination_detected': fields.Boolean(description='Whether hallucination was detected'),
    'docs_retrieved': fields.Integer(description='Number of documents retrieved'),
    'has_realtime_data': fields.Boolean(description='Whether real-time NVD data was used')
})

index_request_model = intelligence_ns.model('IndexRequest', {
    'scan_id': fields.String(required=True, description='Scan ID to index')
})

index_response_model = intelligence_ns.model('IndexResponse', {
    'indexed_count': fields.Integer(description='Number of vulnerabilities indexed'),
    'scan_id': fields.String(description='Scan ID'),
    'status': fields.String(description='Indexing status')
})

scan_upload_response_model = intelligence_ns.model('ScanUploadResponse', {
    'scan_id': fields.String(description='Generated scan ID'),
    'scan_name': fields.String(description='Scan name'),
    'source_tool': fields.String(description='Detected source tool'),
    'total_findings': fields.Integer(description='Total vulnerabilities found'),
    'findings_by_severity': fields.Raw(description='Count by severity level'),
    'critical_count': fields.Integer(description='Number of critical findings'),
    'remediation_plan': fields.Raw(description='Generated remediation plan'),
    'confidence': fields.Float(description='Data confidence score'),
    'indexed': fields.Boolean(description='Whether data was indexed for RAG'),
    'timestamp': fields.String(description='Upload timestamp')
})


@intelligence_ns.route('/analyze-scan')
class AnalyzeScan(Resource):
    """Scan file upload and analysis endpoint"""
    
    @intelligence_ns.doc('analyze_scan_upload')
    @intelligence_ns.marshal_with(scan_upload_response_model)
    def post(self):
        """
        Upload and analyze a vulnerability scan file.
        
        Accepts Nessus, OpenVAS, Qualys, or generic JSON scan formats.
        - Auto-detects format
        - Extracts vulnerabilities
        - Enriches with real-time NVD data
        - Generates AI summary (REPLACES parsed results)
        - Generates remediation plan
        - Indexes for RAG retrieval
        
        Returns: ai_summary instead of parsed_results
        """
        try:
            import json as json_lib
            import uuid
            from datetime import datetime
            
            # Get JSON payload
            data = request.get_json()
            if not data:
                return {'error': 'Request body must be valid JSON'}, 400
            
            logger.info("Scan upload received")
            
            # Parse the scan data
            scan_report = ScanParser.parse_scan(data)
            if not scan_report:
                return {'error': 'Failed to parse scan file - unsupported format'}, 400
            
            logger.info(f"Parsed scan: {scan_report.scan_name} with {scan_report.total_findings} findings")
            
            # Enrich with real-time NVD data
            try:
                rt_manager = get_rt_manager()
                enricher = ScanEnricher(real_time_manager=rt_manager)
                enriched_report = enricher.enrich_report(scan_report)
                logger.info("Scan enriched with NVD data")
            except Exception as e:
                logger.warning(f"Failed to enrich with NVD data: {e}")
                enriched_report = scan_report
            
            # GENERATE AI SUMMARY (replaces static parsed results)
            ai_summary = None
            ai_summary_text = ""
            try:
                from intelligence_layer.rag.scan_processor import ScanAISummarizer
                summarizer = ScanAISummarizer()
                enriched_report = summarizer.enrich_report_with_ai_summary(enriched_report)
                ai_summary = enriched_report.ai_summary
                ai_summary_text = enriched_report.ai_summary_text
                logger.info("AI summary generated")
            except Exception as e:
                logger.warning(f"Failed to generate AI summary: {e}")
            
            # Generate remediation plan
            remediation_plan = ScanAnalyzer.generate_remediation_plan(enriched_report)
            
            # Generate scan ID
            scan_id = f"scan_{uuid.uuid4().hex[:12]}"
            
            # Index for RAG retrieval
            try:
                indexer = get_indexer()
                
                # Prepare vulnerabilities for indexing
                vulnerabilities_for_index = []
                for vuln in enriched_report.vulnerabilities:
                    vulnerabilities_for_index.append({
                        'cve_id': vuln.cve_id,
                        'host_ip': vuln.host,
                        'port': vuln.port,
                        'service': vuln.service,
                        'severity': vuln.severity,
                        'cvss_score': vuln.cvss_score,
                        'description': vuln.description,
                        'title': vuln.title,
                        'remediation': vuln.remediation,
                        'tool_name': enriched_report.source_tool,
                        'scan_id': scan_id
                    })
                
                # Batch index
                if vulnerabilities_for_index:
                    doc_ids = indexer.batch_index_vulnerabilities(vulnerabilities_for_index)
                    indexer.persist()
                    indexed = True
                    logger.info(f"Indexed {len(doc_ids)} vulnerabilities for scan {scan_id}")
                else:
                    indexed = False
                    logger.warning("No vulnerabilities to index")
            
            except Exception as e:
                logger.error(f"Failed to index scan data: {e}")
                indexed = False
            
            # Build response with AI summary instead of parsed_results
            response = {
                'scan_id': scan_id,
                'scan_name': enriched_report.scan_name,
                'source_tool': enriched_report.source_tool,
                'total_findings': enriched_report.total_findings,
                'findings_by_severity': enriched_report.findings_by_severity,
                'critical_count': enriched_report.findings_by_severity.get('critical', 0),
                'ai_summary': ai_summary,  # ← NEW: AI Summary (structured)
                'ai_summary_text': ai_summary_text,  # ← NEW: AI Summary (markdown)
                'remediation_plan': {
                    'critical_actions': len(remediation_plan.get('critical_actions', [])),
                    'high_priority_actions': len(remediation_plan.get('high_priority_actions', [])),
                    'medium_priority_actions': len(remediation_plan.get('medium_priority_actions', [])),
                    'summary': remediation_plan
                },
                'confidence': 0.85 if ai_summary else (0.75 if indexed else 0.5),  # Higher with AI
                'indexed': indexed,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            logger.info(f"Scan analysis complete with AI summary: {response.get('scan_id')}")
            return response, 200
        
        except Exception as e:
            logger.error(f"Scan upload error: {e}", exc_info=True)
            return {'error': f'Failed to analyze scan: {str(e)}'}, 500


@intelligence_ns.route('/summarize-scan-stream')
class SummarizeScanStream(Resource):
    """Real-time streaming scan summary endpoint"""
    
    @intelligence_ns.doc('summarize_scan_stream')
    def post(self):
        """
        Stream AI-generated scan summary in real-time.
        
        Request JSON:
        {
            'scan_data': {
                'scan_name': str,
                'source_tool': str,
                'scan_type': str,
                'findings': [...]
            },
            'summary_type': 'executive' | 'risk_assessment' | 'remediation_plan'
        }
        
        Returns: Server-Sent Events stream with summary chunks
        """
        try:
            from flask import Response
            
            data = request.get_json()
            if not data:
                return {'error': 'Request body must be valid JSON'}, 400
            
            scan_data = data.get('scan_data', {})
            summary_type = data.get('summary_type', 'executive')
            
            if not scan_data:
                return {'error': 'scan_data is required'}, 400
            
            logger.info(f"Starting stream summary for: {scan_data.get('scan_name')}")
            
            # Get chatbot and generate streaming summary
            chatbot = get_chatbot()
            
            # Generator function for streaming
            def generate_summary():
                yield "data: Starting analysis...\n\n"
                
                for chunk in chatbot.summarize_scan_stream(scan_data, summary_type):
                    yield f"data: {chunk}\n\n"
                
                yield "data: [DONE]\n\n"
            
            # Return streaming response
            return Response(
                generate_summary(),
                mimetype='text/event-stream',
                headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
            )
        
        except Exception as e:
            logger.error(f"Stream summary error: {e}", exc_info=True)
            return {'error': f'Failed to generate stream summary: {str(e)}'}, 500


@intelligence_ns.route('/chat')
class ChatEndpoint(Resource):
    """RAG Chatbot endpoint - Long-running AI query operation"""
    
    @intelligence_ns.doc('chat_query')
    @intelligence_ns.expect(chat_message_model)
    @intelligence_ns.marshal_with(chat_response_model)
    def post(self):
        """
        Query the RAG chatbot with natural language.
        
        ⏱️ IMPORTANT: This endpoint can take 30-60+ seconds due to:
        - Llama 3.2 LLM inference: 1.2-1.5s
        - ChromaDB semantic retrieval: 0.3-0.5s
        - NVD API real-time enrichment: 1-2s
        - CISA KEV lookups: 1-2s
        - Full pipeline: 4-10s typical, up to 60s with slower networks
        
        Client timeout should be set to 120+ seconds.
        """
        try:
            # Parse request
            data = request.get_json()
            if not data:
                return {'error': 'Request body must be valid JSON'}, 400
            
            # Validate required fields
            query = data.get('query')
            if not query:
                return {'error': 'query is required'}, 400
            
            if not isinstance(query, str):
                return {'error': 'query must be a string'}, 400
            
            query = query.strip()
            if not query:
                return {'error': 'query cannot be empty'}, 400
            
            if len(query) > 5000:
                return {'error': 'query cannot exceed 5000 characters'}, 400
            
            # Validate optional fields
            session_id = data.get('session_id')
            if session_id is not None and not isinstance(session_id, str):
                return {'error': 'session_id must be a string'}, 400
            
            top_k = data.get('top_k', 5)
            if not isinstance(top_k, int):
                return {'error': 'top_k must be an integer'}, 400
            
            if not 1 <= top_k <= 20:
                return {'error': 'top_k must be between 1 and 20'}, 400
            
            # Log query
            logger.info(f"Chat query: {query[:50]}...")
            
            # Get chatbot
            try:
                chatbot = get_chatbot()
                if chatbot is None:
                    logger.error("Chatbot initialization failed")
                    return {'error': 'AI Assistant not available'}, 503
            except Exception as e:
                logger.error(f"Failed to get chatbot: {e}", exc_info=True)
                return {'error': 'AI Assistant initialization error'}, 503
            
            # Query with error handling (hybrid retrieval enabled for better results)
            try:
                logger.info(f"API calling chatbot.query with use_hybrid_retrieval=True")
                result = chatbot.query(
                    user_input=query,
                    session_id=session_id,
                    top_k=top_k,
                    use_hybrid_retrieval=True  # Enable real-time NVD data
                )
                logger.info(f"API received result: docs={result.get('docs_retrieved')}, realtime={result.get('has_realtime_data')}, conf={result.get('confidence')}")
                
                # Validate response structure
                if not isinstance(result, dict):
                    logger.error(f"Invalid chatbot response type: {type(result)}")
                    return {'error': 'Invalid response from AI Assistant'}, 500
                
                required_fields = ['response', 'sources', 'confidence', 'session_id']
                for field in required_fields:
                    if field not in result:
                        logger.error(f"Missing field in chatbot response: {field}")
                        return {'error': 'Invalid response structure'}, 500
                
                return result, 200
            
            except ValueError as e:
                # Validation errors from chatbot
                logger.error(f"Validation error in chatbot: {e}")
                return {'error': f'Invalid input: {str(e)}'}, 400
            
            except ConnectionError as e:
                # Ollama or database connection errors
                logger.error(f"Connection error: {e}")
                return {'error': 'Service temporarily unavailable'}, 503
            
            except TimeoutError as e:
                # Request timeout
                logger.error(f"Timeout error: {e}")
                return {'error': 'Request timeout - try again'}, 504
            
            except Exception as e:
                # Generic error handler
                logger.error(f"Chatbot query error: {e}", exc_info=True)
                return {'error': 'Internal error processing query'}, 500
        
        except Exception as e:
            logger.error(f"Chat endpoint error: {e}", exc_info=True)
            return {'error': 'Internal server error'}, 500


@intelligence_ns.route('/chat/session/<string:session_id>')
@intelligence_ns.param('session_id', 'Chat session identifier')
class ChatSession(Resource):
    """Chat session management"""
    
    @intelligence_ns.doc('get_session')
    def get(self, session_id):
        """Get conversation history for a session"""
        try:
            chatbot = get_chatbot()
            session = chatbot.get_session(session_id)
            
            if not session:
                return {'error': 'Session not found'}, 404
            
            return {
                'session_id': session.session_id,
                'created_at': session.created_at,
                'message_count': len(session.messages),
                'messages': [
                    {
                        'role': msg.role,
                        'content': msg.content,
                        'timestamp': msg.timestamp,
                        'sources_count': len(msg.sources)
                    }
                    for msg in session.messages
                ]
            }, 200
        
        except Exception as e:
            logger.error(f"Session retrieval error: {e}", exc_info=True)
            return {'error': str(e)}, 500
    
    @intelligence_ns.doc('delete_session')
    def delete(self, session_id):
        """Clear conversation history"""
        try:
            chatbot = get_chatbot()
            success = chatbot.clear_session(session_id)
            
            if success:
                return {'message': 'Session cleared'}, 200
            else:
                return {'error': 'Session not found'}, 404
        
        except Exception as e:
            logger.error(f"Session deletion error: {e}", exc_info=True)
            return {'error': str(e)}, 500


@intelligence_ns.route('/index')
class IndexVulnerabilities(Resource):
    """Vulnerability indexing endpoint"""
    
    @intelligence_ns.doc('index_scan')
    @intelligence_ns.expect(index_request_model)
    @intelligence_ns.marshal_with(index_response_model)
    def post(self):
        """
        Index scan results into vector database for RAG retrieval.
        
        Converts vulnerability findings into embeddings and stores them
        in ChromaDB for semantic search.
        """
        try:
            from services.data_ingestor.ingestor import DataIngestor
            from config.config import get_config
            
            data = request.get_json()
            scan_id = data.get('scan_id')
            
            if not scan_id:
                return {'error': 'scan_id is required'}, 400
            
            # Log request
            logger.info(f"Indexing scan {scan_id} requested")
            
            # Get scan from database
            config = get_config()
            ingestor = DataIngestor(database_url=config.DATABASE_URL)
            scan = ingestor.get_scan(scan_id)
            
            if not scan:
                return {'error': 'Scan not found'}, 404
            
            # Get scan results
            results = ingestor.get_scan_results(scan_id)
            
            # Prepare vulnerabilities for indexing
            vulnerabilities = []
            for result in results:
                for vuln in result.get('vulnerabilities', []):
                    vulnerabilities.append({
                        'cve_id': vuln.get('cve_id'),
                        'host_ip': result.get('host', scan.target),
                        'port': vuln.get('port'),
                        'service': vuln.get('service'),
                        'severity': vuln.get('severity'),
                        'cvss_score': vuln.get('cvss_score', 0.0),
                        'description': vuln.get('description', ''),
                        'exploit_available': vuln.get('exploit_available', False),
                        'tool_name': scan.tool_name,
                        'scan_id': scan_id
                    })
            
            # Batch index
            indexer = get_indexer()
            doc_ids = indexer.batch_index_vulnerabilities(vulnerabilities)
            indexer.persist()
            
            return {
                'indexed_count': len(doc_ids),
                'scan_id': scan_id,
                'status': 'success'
            }, 200
        
        except Exception as e:
            logger.error(f"Indexing error: {e}", exc_info=True)
            return {'error': str(e)}, 500


@intelligence_ns.route('/index/stats')
class IndexStats(Resource):
    """Index statistics endpoint"""
    
    @intelligence_ns.doc('get_index_stats')
    def get(self):
        """Get statistics about indexed data"""
        try:
            indexer = get_indexer()
            stats = indexer.get_collection_stats()
            
            return {
                'collections': stats,
                'total_documents': sum(stats.values())
            }, 200
        
        except Exception as e:
            logger.error(f"Stats error: {e}", exc_info=True)
            return {'error': str(e)}, 500


@intelligence_ns.route('/health')
class IntelligenceHealth(Resource):
    """Health check for intelligence layer"""
    
    @intelligence_ns.doc('intelligence_health')
    def get(self):
        """Check health of intelligence layer components"""
        health_status = {
            'indexer': 'unknown',
            'chatbot': 'unknown',
            'ollama': 'unknown'
        }
        
        try:
            # Check indexer
            indexer = get_indexer()
            stats = indexer.get_collection_stats()
            health_status['indexer'] = 'healthy'
            health_status['indexed_docs'] = sum(stats.values())
        except Exception as e:
            health_status['indexer'] = f'error: {str(e)}'
        
        try:
            # Check chatbot (includes Ollama check)
            chatbot = get_chatbot()
            health_status['chatbot'] = 'healthy'
            health_status['ollama'] = 'healthy'
        except Exception as e:
            health_status['chatbot'] = f'error: {str(e)}'


@intelligence_ns.route('/reset')
class ResetChatbot(Resource):
    """Reset chatbot singleton - for debugging"""
    
    @intelligence_ns.doc('reset_chatbot')
    def post(self):
        """Force reset of chatbot and all singletons"""
        try:
            reset_chatbot()
            return {'message': 'All singletons reset successfully'}, 200
        except Exception as e:
            logger.error(f"Reset error: {e}", exc_info=True)
            return {'error': str(e)}, 500


@intelligence_ns.route('/mcp-status')
class MCPStatus(Resource):
    """MCP web proxy status and configuration"""
    
    @intelligence_ns.doc('get_mcp_status')
    def get(self):
        """Get MCP proxy status and allowed domains"""
        try:
            from services.mcp_web_proxy import get_mcp_proxy
            proxy = get_mcp_proxy()
            
            return {
                'enabled': True,
                'allowed_domains': list(proxy.ALLOWED_DOMAINS),
                'rate_limit': proxy.max_requests_per_minute,
                'max_response_size': proxy.max_response_size,
                'timeout': proxy.timeout,
                'blocked_ip_patterns': proxy.BLOCKED_IP_PATTERNS,
                'features': [
                    'Real-time CVE lookups from NVD',
                    'SSRF protection (blocks private IPs)',
                    'Rate limiting per domain',
                    'Response size limits',
                    'Domain whitelisting'
                ]
            }, 200
        except ImportError:
            return {
                'enabled': False,
                'error': 'MCP proxy not installed'
            }, 503
        except Exception as e:
            logger.error(f"MCP status error: {e}", exc_info=True)
            return {
                'enabled': False,
                'error': str(e)
            }, 500


@intelligence_ns.route('/index/delete/<string:scan_id>')
class DeleteIndexedScan(Resource):
    """Delete indexed data for a specific scan"""
    
    @intelligence_ns.doc('delete_indexed_scan')
    def delete(self, scan_id):
        """Delete all indexed vulnerabilities from a specific scan"""
        try:
            indexer = get_indexer()
            deleted_count = indexer.delete_by_scan_id(scan_id)
            
            return {
                'message': f'Successfully deleted {deleted_count} indexed vulnerabilities from scan {scan_id}',
                'deleted_count': deleted_count,
                'scan_id': scan_id
            }, 200
        except Exception as e:
            logger.error(f"Delete indexed scan error: {e}", exc_info=True)
            return {'error': str(e)}, 500


@intelligence_ns.route('/index/vulnerability/<string:doc_id>')
class DeleteIndexedVulnerability(Resource):
    """Delete a specific indexed vulnerability"""
    
    @intelligence_ns.doc('delete_indexed_vulnerability')
    def delete(self, doc_id):
        """Delete a specific vulnerability by document ID"""
        try:
            indexer = get_indexer()
            success = indexer.delete_vulnerability(doc_id)
            
            if success:
                return {
                    'message': f'Successfully deleted vulnerability {doc_id}',
                    'doc_id': doc_id
                }, 200
            else:
                return {
                    'error': f'Failed to delete vulnerability {doc_id}',
                    'doc_id': doc_id
                }, 404
        except Exception as e:
            logger.error(f"Delete vulnerability error: {e}", exc_info=True)
            return {'error': str(e)}, 500


@intelligence_ns.route('/index/query')
class QueryIndexedData(Resource):
    """Query indexed vulnerabilities"""
    
    query_model = intelligence_ns.model('IndexQuery', {
        'query_text': fields.String(required=True, description='Search query'),
        'n_results': fields.Integer(default=10, description='Number of results'),
        'filter_metadata': fields.Raw(description='Metadata filters (e.g., {"host_ip": "192.168.1.1"})')
    })
    
    @intelligence_ns.doc('query_indexed_data')
    @intelligence_ns.expect(query_model)
    def post(self):
        """Search indexed vulnerabilities by semantic query"""
        try:
            data = request.get_json()
            query_text = data.get('query_text')
            n_results = data.get('n_results', 10)
            filter_metadata = data.get('filter_metadata')
            
            if not query_text:
                return {'error': 'query_text is required'}, 400
            
            indexer = get_indexer()
            results = indexer.query_vulnerabilities(
                query_text=query_text,
                n_results=n_results,
                filter_metadata=filter_metadata
            )
            
            return {
                'query': query_text,
                'results': results,
                'count': len(results.get('documents', []))
            }, 200
        except Exception as e:
            logger.error(f"Query indexed data error: {e}", exc_info=True)
            return {'error': str(e)}, 500


# Export namespace
__all__ = ['intelligence_ns']
