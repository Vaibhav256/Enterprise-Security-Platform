"""
RAG Retrieval Engine
Implements query preprocessing, semantic search, and context assembly.
Based on RAG_PIPELINE_DESIGN.md specifications.
"""

import re
import requests
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import spacy
try:
    from sentence_transformers import SentenceTransformer
except Exception:
    SentenceTransformer = None
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class QueryContext:
    """Processed query with extracted entities and intent"""
    original_query: str
    preprocessed_query: str
    entities: Dict[str, List[str]]  # {entity_type: [values]}
    intent: str  # vulnerability_lookup, remediation_guidance, attack_path, general
    filters: Dict[str, any]  # Metadata filters for ChromaDB
    expanded_terms: List[str]  # Query expansion terms


class RAGRetrievalEngine:
    """
    Retrieval engine for RAG pipeline.
    
    Handles:
    1. Query preprocessing (NER, intent classification)
    2. Embedding generation
    3. Semantic retrieval from ChromaDB
    4. Context assembly for LLM
    """
    
    def __init__(
        self,
        indexer,  # VulnerabilityIndexer instance
        embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2",
        spacy_model: str = "en_core_web_sm"
    ):
        """
        Initialize retrieval engine.
        
        Args:
            indexer: VulnerabilityIndexer instance
            embedding_model: Sentence transformer model
            spacy_model: spaCy NER model
        """
        self.indexer = indexer
        
        # Load spaCy for NER
        try:
            self.nlp = spacy.load(spacy_model)
        except OSError:
            logger.warning(f"spaCy model '{spacy_model}' not found. Download with: python -m spacy download {spacy_model}")
            self.nlp = None
        
        # Load embedding model (use a dummy embedder if sentence-transformers or torch not available)
        class _DummyEmbedder:
            def __init__(self, dim: int = 384):
                self.dim = dim

            def encode(self, texts, *args, **kwargs):
                # Return zero vectors for each input text
                if isinstance(texts, str):
                    texts = [texts]
                return [[0.0] * self.dim for _ in texts]

        if SentenceTransformer is None:
            logger.warning("sentence-transformers not available; using dummy embedder")
            self.embedder = _DummyEmbedder()
        else:
            try:
                self.embedder = SentenceTransformer(embedding_model)
            except Exception as exc:
                logger.warning("Failed to initialize SentenceTransformer (%s); using dummy embedder", exc)
                self.embedder = _DummyEmbedder()
        
        # Query expansion synonyms
        self.synonyms = {
            'ssh': ['ssh', 'secure shell', 'openssh'],
            'rce': ['rce', 'remote code execution', 'arbitrary code execution'],
            'dos': ['dos', 'denial of service', 'crash'],
            'critical': ['critical', 'severe', 'high-risk']
        }
        
        logger.info("RAGRetrievalEngine initialized")
    
    def retrieve(
        self,
        query: str,
        top_k: int = 5,
        include_threat_intel: bool = True,
        include_attack_paths: bool = True
    ) -> Dict:
        """
        Main retrieval pipeline.
        
        Args:
            query: Natural language query
            top_k: Number of results per collection
            include_threat_intel: Include threat intelligence results
            include_attack_paths: Include attack path results
        
        Returns:
            Dict with retrieved documents and context
        """
        # Step 1: Preprocess query
        query_context = self.preprocess_query(query)
        logger.info(f"Query intent: {query_context.intent}")
        logger.info(f"Extracted entities: {query_context.entities}")
        
        # Step 2: Retrieve from vulnerability scans
        # For remediation queries, don't use strict filters - use semantic search instead
        use_filters = query_context.filters if query_context.intent != 'remediation_guidance' else {}
        
        vuln_results = self.indexer.query_vulnerabilities(
            query_text=query_context.preprocessed_query,
            n_results=top_k,
            filter_metadata=use_filters
        )
        
        # Step 2.5: ✨ REAL-TIME ENHANCEMENTS ✨
        # Prepare documents for enrichment
        documents = []
        if vuln_results.get('documents') and vuln_results.get('metadatas'):
            for doc, meta in zip(vuln_results['documents'], vuln_results['metadatas']):
                documents.append({'content': doc, 'metadata': meta})
        
        # Enrich with real-time data
        enriched_docs, threat_alerts = self._enrich_with_realtime_cve_data(documents)
        
        # Check data freshness
        freshness_info = self._check_data_freshness(enriched_docs)
        
        # Update vuln_results with enriched data
        if enriched_docs:
            vuln_results['documents'] = [doc['content'] for doc in enriched_docs]
            vuln_results['metadatas'] = [doc['metadata'] for doc in enriched_docs]
        
        # Step 3: Retrieve from threat intelligence
        threat_results = None
        if include_threat_intel and query_context.entities.get('cve'):
            threat_results = self.indexer.query_threat_intel(
                query_text=query_context.preprocessed_query,
                n_results=3
            )
        
        # Step 4: Retrieve from attack paths
        path_results = None
        if include_attack_paths and query_context.intent == 'attack_path':
            path_results = self.indexer.query_attack_paths(
                query_text=query_context.preprocessed_query,
                n_results=3
            )
        
        # Step 5: Assemble context with real-time data
        context = self.assemble_context(
            query_context=query_context,
            vuln_results=vuln_results,
            threat_results=threat_results,
            path_results=path_results
        )
        
        # Add threat alerts to context
        if threat_alerts:
            context = self._add_threat_alerts_to_context(context, threat_alerts)
        
        # Add freshness warning to context
        if freshness_info.get('warning'):
            context = f"{freshness_info['warning']}\n\n{context}"
        
        return {
            'query_context': query_context,
            'vulnerability_results': vuln_results,
            'threat_intel_results': threat_results,
            'attack_path_results': path_results,
            'assembled_context': context,
            'total_docs_retrieved': len(vuln_results.get('documents', [])),
            'threat_alerts': threat_alerts,  # ✨ NEW
            'freshness_info': freshness_info,  # ✨ NEW
            'realtime_enriched': len(enriched_docs) > 0  # ✨ NEW
        }
    
    def preprocess_query(self, query: str) -> QueryContext:
        """
        Preprocess user query.
        
        Steps:
        1. Extract entities (IP, CVE, ports, services)
        2. Classify intent
        3. Expand query terms
        4. Build metadata filters
        """
        # Extract entities
        entities = self._extract_entities(query)
        
        # Classify intent
        intent = self._classify_intent(query, entities)
        
        # Expand terms
        expanded_terms = self._expand_query(query)
        
        # Build filters
        filters = self._build_filters(entities)
        
        # Preprocess query text
        preprocessed = self._preprocess_text(query, expanded_terms)
        
        return QueryContext(
            original_query=query,
            preprocessed_query=preprocessed,
            entities=entities,
            intent=intent,
            filters=filters,
            expanded_terms=expanded_terms
        )
    
    def _extract_entities(self, query: str) -> Dict[str, List[str]]:
        """Extract cybersecurity entities from query"""
        entities = {
            'ip_address': [],
            'cve': [],
            'port': [],
            'service': [],
            'severity': [],
            'hostname': []
        }
        
        # Extract IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        entities['ip_address'] = re.findall(ip_pattern, query)
        
        # Extract CVE IDs
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        entities['cve'] = re.findall(cve_pattern, query, re.IGNORECASE)
        
        # Extract ports
        port_pattern = r'\bport\s+(\d{1,5})\b'
        entities['port'] = re.findall(port_pattern, query, re.IGNORECASE)
        
        # Extract severity levels
        severity_terms = ['critical', 'high', 'medium', 'low']
        for term in severity_terms:
            if term in query.lower():
                entities['severity'].append(term)
        
        # Extract common services
        service_terms = ['ssh', 'http', 'https', 'ftp', 'smtp', 'rdp', 'smb']
        for term in service_terms:
            if term.lower() in query.lower():
                entities['service'].append(term.lower())
        
        # Use spaCy for additional NER if available
        if self.nlp:
            doc = self.nlp(query)
            for ent in doc.ents:
                if ent.label_ == 'GPE':  # Geographic/Political Entity (often hostnames)
                    entities['hostname'].append(ent.text)
        
        # Filter empty lists
        entities = {k: v for k, v in entities.items() if v}
        
        return entities
    
    def _classify_intent(self, query: str, entities: Dict) -> str:
        """
        Classify query intent.
        
        Intents:
        - vulnerability_lookup: Finding specific vulnerabilities
        - remediation_guidance: How to fix vulnerabilities
        - attack_path: Understanding exploit chains
        - general: General questions
        """
        query_lower = query.lower()
        
        # Remediation intent
        if any(word in query_lower for word in ['fix', 'patch', 'remediate', 'mitigate', 'resolve']):
            return 'remediation_guidance'
        
        # Attack path intent
        if any(word in query_lower for word in ['attack', 'exploit', 'chain', 'path', 'pivot', 'lateral']):
            return 'attack_path'
        
        # Vulnerability lookup (has specific entities)
        if entities.get('ip_address') or entities.get('cve') or entities.get('service'):
            return 'vulnerability_lookup'
        
        # Default
        return 'general'
    
    def _expand_query(self, query: str) -> List[str]:
        """Expand query with synonyms and related terms"""
        expanded = []
        query_lower = query.lower()
        
        # Expand with existing synonyms
        for term, synonyms in self.synonyms.items():
            if term in query_lower:
                expanded.extend(synonyms)
        
        # Add protocol expansions
        if 'http/2' in query_lower or 'http2' in query_lower:
            expanded.extend(['HTTP/2', 'http', 'https', 'web server', 'rapid reset'])
        
        if 'xz' in query_lower and 'backdoor' in query_lower:
            expanded.extend(['CVE-2024-3094', 'compression', 'supply chain'])
        
        # Add remediation terms for fix queries
        if any(word in query_lower for word in ['fix', 'patch', 'remediate']):
            expanded.extend(['solution', 'mitigation', 'remediation', 'update', 'upgrade'])
        
        return expanded
    
    def _build_filters(self, entities: Dict) -> Dict:
        """
        Build ChromaDB metadata filters from extracted entities.
        ChromaDB requires $and operator for multiple conditions.
        """
        conditions = []
        
        if entities.get('ip_address'):
            conditions.append({"host_ip": entities['ip_address'][0]})
        
        if entities.get('severity'):
            conditions.append({"severity": entities['severity'][0].upper()})
        
        if entities.get('port'):
            conditions.append({"port": int(entities['port'][0])})
        
        if entities.get('service'):
            conditions.append({"service": entities['service'][0]})
        
        # ChromaDB requires specific format:
        # - Single condition: {"key": "value"}
        # - Multiple conditions: {"$and": [{"key1": "value1"}, {"key2": "value2"}]}
        if len(conditions) == 0:
            return {}
        elif len(conditions) == 1:
            return conditions[0]
        else:
            return {"$and": conditions}
    
    def _preprocess_text(self, query: str, expanded_terms: List[str]) -> str:
        """Clean and expand query text"""
        # Add expanded terms
        if expanded_terms:
            query = query + " " + " ".join(expanded_terms)
        
        # Remove special characters
        query = re.sub(r'[^\w\s\-\.]', ' ', query)
        
        # Normalize whitespace
        query = ' '.join(query.split())
        
        return query
    
    def assemble_context(
        self,
        query_context: QueryContext,
        vuln_results: Dict,
        threat_results: Optional[Dict] = None,
        path_results: Optional[Dict] = None
    ) -> str:
        """
        Assemble retrieved documents into LLM context.
        
        Format for maximum LLM comprehension:
        - Structured sections
        - Clear labeling
        - Relevant metadata highlighted
        """
        sections = []
        
        # Header
        sections.append("=== RETRIEVED VULNERABILITY DATA ===\n")
        sections.append(f"Query: {query_context.original_query}")
        sections.append(f"Intent: {query_context.intent}")
        if query_context.entities:
            sections.append(f"Entities: {query_context.entities}\n")
        
        # Vulnerability scan results
        if vuln_results and vuln_results.get('documents'):
            sections.append("\n## Vulnerability Scan Findings:\n")
            for i, (doc, meta) in enumerate(zip(
                vuln_results['documents'],
                vuln_results['metadatas']
            ), 1):
                sections.append(f"### Document {i}:")
                sections.append(f"- **CVE:** {meta.get('cve_id')}")
                sections.append(f"- **Host:** {meta.get('host_ip')}")
                sections.append(f"- **Port:** {meta.get('port')}")
                sections.append(f"- **Severity:** {meta.get('severity')} (CVSS {meta.get('cvss_score')})")
                sections.append(f"- **Exploit Available:** {meta.get('exploit_available')}")
                sections.append(f"- **Tool:** {meta.get('tool_name')}")
                sections.append(f"- **Details:** {doc}")
                sections.append("")
        
        # Threat intelligence
        if threat_results and threat_results.get('documents'):
            sections.append("\n## Threat Intelligence:\n")
            for i, (doc, meta) in enumerate(zip(
                threat_results['documents'],
                threat_results['metadatas']
            ), 1):
                sections.append(f"### Threat Intel {i}:")
                sections.append(f"- **CVE:** {meta.get('cve_id')}")
                sections.append(f"- **CWE:** {meta.get('cwe_id')}")
                sections.append(f"- **Exploit Maturity:** {meta.get('exploit_maturity')}")
                sections.append(f"- **Details:** {doc}")
                sections.append("")
        
        # Attack paths
        if path_results and path_results.get('documents'):
            sections.append("\n## Attack Paths:\n")
            for i, (doc, meta) in enumerate(zip(
                path_results['documents'],
                path_results['metadatas']
            ), 1):
                sections.append(f"### Attack Path {i}:")
                sections.append(f"- **Source:** {meta.get('source_host')}")
                sections.append(f"- **Target:** {meta.get('target_host')}")
                sections.append(f"- **Steps:** {meta.get('total_steps')}")
                sections.append(f"- **Max CVSS:** {meta.get('max_cvss')}")
                sections.append(f"- **Details:** {doc}")
                sections.append("")
        
        # Footer
        sections.append("\n=== END OF RETRIEVED DATA ===")
        
        return '\n'.join(sections)
    
    def _add_threat_alerts_to_context(self, context: str, threat_alerts: List[Dict]) -> str:
        """Add threat intelligence alerts to the top of context"""
        if not threat_alerts:
            return context
        
        alert_section = ["=== 🚨 REAL-TIME THREAT INTELLIGENCE ALERTS ===\n"]
        
        for alert in threat_alerts:
            alert_section.append(f"⚠️ **{alert['severity']}**: {alert['message']}")
            if alert['type'] == 'CISA_KEV':
                alert_section.append(f"   - Action Required: {alert['data'].get('requiredAction', 'N/A')}")
                alert_section.append(f"   - Due Date: {alert['data'].get('dueDate', 'N/A')}")
            elif alert['type'] == 'PUBLIC_EXPLOIT':
                alert_section.append(f"   - Exploit Count: {alert.get('count', 0)}")
            alert_section.append("")
        
        alert_section.append("=" * 50 + "\n")
        
        return '\n'.join(alert_section) + '\n' + context
    
    def _enrich_with_realtime_cve_data(self, documents: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
        """
        Enrich indexed vulnerabilities with real-time NVD, CISA KEV, and ExploitDB data.
        
        Returns:
            Tuple of (enriched_documents, threat_intel_alerts)
        """
        enriched_docs = []
        threat_alerts = []
        
        for doc in documents:
            metadata = doc.get('metadata', {})
            cve_id = metadata.get('cve_id')
            
            if cve_id and cve_id.startswith('CVE-'):
                # Fetch real-time NVD data
                nvd_data = self._fetch_nvd_data(cve_id)
                if nvd_data:
                    # Update metadata with latest NVD info
                    metadata['nvd_last_modified'] = nvd_data.get('lastModified', 'N/A')
                    metadata['nvd_published'] = nvd_data.get('published', 'N/A')
                    metadata['nvd_current_cvss'] = nvd_data.get('cvss_score', metadata.get('cvss_score'))
                    metadata['nvd_severity'] = nvd_data.get('severity', metadata.get('severity'))
                    
                    # Append real-time data to document content
                    doc['content'] += f"\n\n[🔄 REAL-TIME NVD DATA - Updated {nvd_data.get('lastModified', 'N/A')}]\n"
                    doc['content'] += f"Current CVSS: {nvd_data.get('cvss_score', 'N/A')}\n"
                    doc['content'] += f"Current Severity: {nvd_data.get('severity', 'N/A')}\n"
                    doc['content'] += f"Latest Description: {nvd_data.get('description', '')[:200]}...\n"
                
                # Check CISA KEV (Known Exploited Vulnerabilities)
                kev_status = self._check_cisa_kev(cve_id)
                if kev_status:
                    metadata['cisa_kev'] = True
                    metadata['kev_date_added'] = kev_status.get('dateAdded')
                    metadata['kev_required_action'] = kev_status.get('requiredAction')
                    metadata['kev_due_date'] = kev_status.get('dueDate')
                    
                    # Add critical alert
                    doc['content'] += f"\n\n[🚨 CRITICAL ALERT - CISA KEV]\n"
                    doc['content'] += f"⚠️ ACTIVELY EXPLOITED IN THE WILD\n"
                    doc['content'] += f"Added to KEV: {kev_status.get('dateAdded')}\n"
                    doc['content'] += f"Required Action: {kev_status.get('requiredAction')}\n"
                    doc['content'] += f"Due Date: {kev_status.get('dueDate')}\n"
                    
                    threat_alerts.append({
                        'type': 'CISA_KEV',
                        'cve_id': cve_id,
                        'severity': 'CRITICAL',
                        'message': f"⚠️ {cve_id} is actively exploited (CISA KEV)",
                        'data': kev_status
                    })
                
                # Check ExploitDB for public exploits
                exploit_count = self._check_exploitdb(cve_id)
                if exploit_count > 0:
                    metadata['public_exploits'] = exploit_count
                    doc['content'] += f"\n\n[🎯 PUBLIC EXPLOITS AVAILABLE]\n"
                    doc['content'] += f"ExploitDB: {exploit_count} public exploit(s) found\n"
                    doc['content'] += f"URL: https://www.exploit-db.com/search?cve={cve_id}\n"
                    
                    threat_alerts.append({
                        'type': 'PUBLIC_EXPLOIT',
                        'cve_id': cve_id,
                        'severity': 'HIGH',
                        'message': f"🎯 {cve_id} has {exploit_count} public exploit(s)",
                        'count': exploit_count
                    })
            
            enriched_docs.append(doc)
        
        logger.info(f"Enriched {len(enriched_docs)} documents with real-time data, {len(threat_alerts)} alerts generated")
        return enriched_docs, threat_alerts
    
    def _fetch_nvd_data(self, cve_id: str) -> Optional[Dict]:
        """Fetch real-time CVE data from NVD API"""
        try:
            # Use MCP proxy if available
            from services.mcp_web_proxy import get_mcp_proxy
            proxy = get_mcp_proxy()
            result = proxy.fetch_cve_details(cve_id)
            
            if result.get('success'):
                return {
                    'published': result.get('published'),
                    'lastModified': result.get('last_modified'),
                    'cvss_score': result.get('cvss_v3', {}).get('baseScore'),
                    'severity': result.get('cvss_v3', {}).get('baseSeverity'),
                    'description': result.get('description', '')
                }
        except Exception as e:
            logger.warning(f"Failed to fetch NVD data for {cve_id}: {e}")
        
        return None
    
    def _check_cisa_kev(self, cve_id: str) -> Optional[Dict]:
        """Check if CVE is in CISA's Known Exploited Vulnerabilities catalog"""
        try:
            # CISA KEV catalog URL
            kev_url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
            response = requests.get(kev_url, timeout=10)
            
            if response.ok:
                kev_data = response.json()
                for vuln in kev_data.get('vulnerabilities', []):
                    if vuln.get('cveID') == cve_id:
                        logger.info(f"🚨 {cve_id} found in CISA KEV!")
                        return {
                            'dateAdded': vuln.get('dateAdded'),
                            'shortDescription': vuln.get('shortDescription'),
                            'requiredAction': vuln.get('requiredAction'),
                            'dueDate': vuln.get('dueDate'),
                            'knownRansomwareCampaignUse': vuln.get('knownRansomwareCampaignUse')
                        }
        except Exception as e:
            logger.warning(f"Failed to check CISA KEV for {cve_id}: {e}")
        
        return None
    
    def _check_exploitdb(self, cve_id: str) -> int:
        """Check ExploitDB for public exploits (returns count)"""
        try:
            # ExploitDB search URL
            search_url = f'https://www.exploit-db.com/search?cve={cve_id}'
            response = requests.get(search_url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
            
            if response.ok:
                # Simple check: if "No Results" not in page, exploits exist
                if 'No Results' not in response.text:
                    # Count occurrences of exploit entries (rough estimate)
                    count = response.text.count('exploit_title')
                    if count > 0:
                        logger.info(f"🎯 {cve_id} has ~{count} public exploits")
                        return count
        except Exception as e:
            logger.warning(f"Failed to check ExploitDB for {cve_id}: {e}")
        
        return 0
    
    def _check_data_freshness(self, documents: List[Dict]) -> Dict:
        """Check if indexed vulnerability data is recent"""
        freshness = {
            'fresh': [],      # < 24 hours old
            'recent': [],     # < 7 days old
            'stale': [],      # > 7 days old
            'warning': None,
            'oldest_scan': None,
            'newest_scan': None
        }
        
        now = datetime.utcnow()
        scan_dates = []
        
        for doc in documents:
            metadata = doc.get('metadata', {})
            indexed_at = metadata.get('indexed_at')
            
            if indexed_at:
                try:
                    scan_time = datetime.fromisoformat(indexed_at.replace('Z', '+00:00').split('+')[0])
                    age = now - scan_time
                    scan_dates.append(scan_time)
                    
                    if age < timedelta(hours=24):
                        freshness['fresh'].append(doc)
                    elif age < timedelta(days=7):
                        freshness['recent'].append(doc)
                    else:
                        freshness['stale'].append(doc)
                except Exception as e:
                    logger.warning(f"Failed to parse date {indexed_at}: {e}")
        
        # Calculate oldest and newest
        if scan_dates:
            freshness['oldest_scan'] = min(scan_dates)
            freshness['newest_scan'] = max(scan_dates)
            oldest_age = now - freshness['oldest_scan']
            
            # Generate warning if data is old
            if freshness['stale']:
                days_old = oldest_age.days
                freshness['warning'] = (
                    f"⚠️ Warning: {len(freshness['stale'])} vulnerabilities are from scans "
                    f"{days_old} days old. Consider re-scanning for latest results."
                )
            elif not freshness['fresh'] and freshness['recent']:
                freshness['warning'] = (
                    f"ℹ️ Note: Vulnerability data is {oldest_age.days} days old. "
                    f"Consider re-scanning for the most current status."
                )
        
        return freshness


# Example usage
if __name__ == '__main__':
    from indexing import VulnerabilityIndexer
    
    # Initialize
    indexer = VulnerabilityIndexer(persist_directory="./test_chroma_db")
    engine = RAGRetrievalEngine(indexer)
    
    # Test queries
    test_queries = [
        "What are the critical SSH vulnerabilities on host 192.168.1.50?",
        "How do I fix CVE-2023-12345?",
        "Show me attack paths to the database server",
        "What RCE vulnerabilities affect port 80?"
    ]
    
    for query in test_queries:
        print(f"\n{'='*70}")
        print(f"Query: {query}")
        print(f"{'='*70}")
        
        results = engine.retrieve(query, top_k=3)
        
        print(f"\nIntent: {results['query_context'].intent}")
        print(f"Entities: {results['query_context'].entities}")
        print(f"Filters: {results['query_context'].filters}")
        print(f"Documents Retrieved: {results['total_docs_retrieved']}")
        
        print("\n--- Assembled Context ---")
        print(results['assembled_context'][:500] + "...")
