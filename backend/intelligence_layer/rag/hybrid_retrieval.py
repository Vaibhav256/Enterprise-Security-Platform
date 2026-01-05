"""
Hybrid Retrieval Engine - Combines local and real-time data sources
Extends RAGRetrievalEngine to include real-time CVE data from NVD
"""

import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class HybridRetrievalResult:
    """Result from hybrid retrieval"""
    local_results: List[Dict[str, Any]]  # From ChromaDB
    realtime_results: List[Dict[str, Any]]  # From NVD
    combined_results: List[Dict[str, Any]]  # Merged and ranked
    retrieval_sources: Dict[str, int]  # Count by source
    confidence: float  # Overall confidence


class HybridRetrievalEngine:
    """
    Hybrid retrieval combining local (ChromaDB) and real-time (NVD) sources.
    
    Strategy:
    1. Query ChromaDB for locally indexed vulnerabilities
    2. Query NVD for real-time CVE data (if CVEs mentioned)
    3. Merge and rank results by relevance + recency
    4. Return unified context for LLM
    """
    
    def __init__(
        self,
        local_engine,  # RAGRetrievalEngine instance
        real_time_manager=None  # RealTimeSourceManager instance
    ):
        """
        Initialize hybrid retrieval engine.
        
        Args:
            local_engine: RAGRetrievalEngine for ChromaDB access
            real_time_manager: RealTimeSourceManager for NVD access
        """
        self.local_engine = local_engine
        self.real_time_manager = real_time_manager
        logger.info("HybridRetrievalEngine initialized")
    
    def retrieve_hybrid(
        self,
        query: str,
        top_k_local: int = 5,
        top_k_realtime: int = 3,
        prioritize: str = 'relevance'  # 'relevance', 'recency', 'confidence'
    ) -> HybridRetrievalResult:
        """
        Perform hybrid retrieval from local + real-time sources.
        
        Args:
            query: Natural language query
            top_k_local: Results from ChromaDB
            top_k_realtime: Results from NVD
            prioritize: How to rank combined results
        
        Returns:
            HybridRetrievalResult with combined data
        """
        logger.info(f"Hybrid retrieval for: {query}")
        
        # Step 1: Query local ChromaDB
        local_results = self._query_local(query, top_k_local)
        logger.info(f"Local results: {len(local_results)} documents")
        
        # Step 2: Extract CVEs from query and local results
        cves_in_context = self._extract_cves(query, local_results)
        logger.info(f"CVEs in context: {cves_in_context}")
        
        # Step 3: Query real-time NVD
        realtime_results = []
        if self.real_time_manager:
            # 3a. Enrich known CVEs with latest data
            if cves_in_context:
                realtime_results = self._query_realtime(cves_in_context, top_k_realtime)
                logger.info(f"Real-time CVE enrichment: {len(realtime_results)} CVEs")
            
            # 3b. If no local results, do keyword search on NVD
            if len(local_results) == 0:
                keywords = self._extract_keywords(query)
                if keywords:
                    logger.info(f"No local results, searching NVD with keywords: {keywords}")
                    keyword_results = self._search_nvd_by_keyword(keywords, max_results=top_k_realtime)
                    realtime_results.extend(keyword_results)
                    logger.info(f"NVD keyword search: {len(keyword_results)} new CVEs found")
        
        # Step 4: Merge and rank results
        combined = self._merge_results(
            local_results,
            realtime_results,
            prioritize=prioritize
        )
        
        # Step 5: Calculate confidence
        confidence = self._calculate_confidence(local_results, realtime_results)
        
        return HybridRetrievalResult(
            local_results=local_results,
            realtime_results=realtime_results,
            combined_results=combined,
            retrieval_sources={
                'local': len(local_results),
                'realtime': len(realtime_results)
            },
            confidence=confidence
        )
    
    def _query_local(self, query: str, top_k: int) -> List[Dict[str, Any]]:
        """Query local ChromaDB"""
        try:
            result = self.local_engine.retrieve(
                query=query,
                top_k=top_k,
                include_threat_intel=False,
                include_attack_paths=False
            )
            
            vuln_results = result.get('vulnerability_results', {})
            documents = vuln_results.get('documents', [])
            metadatas = vuln_results.get('metadatas', [])
            distances = vuln_results.get('distances', [])
            
            # Format results
            formatted = []
            for doc, meta, dist in zip(documents, metadatas, distances):
                formatted.append({
                    'id': meta.get('id', ''),
                    'cve_id': meta.get('cve_id'),
                    'host': meta.get('host_ip'),
                    'severity': meta.get('severity'),
                    'content': doc,
                    'source': 'local',
                    'relevance_score': 1.0 - dist,  # Convert distance to similarity
                    'indexed': True
                })
            
            return formatted
        
        except Exception as e:
            logger.error(f"Error querying local engine: {e}")
            return []
    
    def _extract_cves(self, query: str, local_results: List[Dict]) -> List[str]:
        """Extract unique CVE IDs from query and results"""
        cves = set()
        
        # Extract from query
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        matches = re.findall(cve_pattern, query, re.IGNORECASE)
        cves.update(matches)
        
        # Extract from local results - ONLY valid CVE format
        for result in local_results:
            cve_id = result.get('cve_id', '')
            # ✅ FIX: Only add if it's a valid CVE format (not VULN-xxxx)
            if cve_id and re.match(r'^CVE-\d{4}-\d{4,}$', cve_id, re.IGNORECASE):
                cves.add(cve_id)
        
        return list(cves)
    
    def _query_realtime(self, cves: List[str], top_k: int) -> List[Dict[str, Any]]:
        """Query NVD for real-time CVE data"""
        results = []
        
        if not self.real_time_manager:
            return results
        
        try:
            nvd_client = self.real_time_manager.nvd
            
            for cve_id in cves[:top_k]:
                try:
                    cve_details = nvd_client.get_cve_details(cve_id)
                    
                    if cve_details:
                        results.append({
                            'id': cve_details['id'],
                            'cve_id': cve_details['id'],
                            'title': cve_details['id'],  # Use CVE ID as title
                            'description': cve_details['description'],
                            'cvss_score': cve_details['cvss_score'],
                            'severity': cve_details['severity'],
                            'published': cve_details['published'],
                            'updated': cve_details['updated'],
                            'cwes': cve_details.get('cwes', []),
                            'references': cve_details.get('references', []),
                            'source': 'nist_nvd',
                            'relevance_score': 1.0,  # High relevance for explicitly mentioned CVEs
                            'real_time': True,
                            'retrieved_at': cve_details.get('retrieved_at')
                        })
                        logger.info(f"Fetched {cve_id} from NVD: CVSS {cve_details['cvss_score']}")
                
                except Exception as e:
                    logger.warning(f"Failed to fetch {cve_id} from NVD: {e}")
                    continue
            
            return results
        
        except Exception as e:
            logger.error(f"Error querying real-time sources: {e}")
            return []
    
    def _extract_keywords(self, query: str) -> List[str]:
        """
        Extract searchable keywords from natural language query.
        Identifies technology names, products, and vulnerability types.
        """
        keywords = []
        query_lower = query.lower()
        
        # Technology/product patterns
        tech_patterns = {
            r'\b(apache|httpd)\b': 'apache',
            r'\b(nginx)\b': 'nginx',
            r'\b(ssh|openssh|secure\s*shell)\b': 'ssh',
            r'\b(mysql|mariadb)\b': 'mysql',
            r'\b(postgres|postgresql)\b': 'postgresql',
            r'\b(windows|microsoft\s*windows)\b': 'windows',
            r'\b(linux|ubuntu|debian|centos|redhat)\b': 'linux',
            r'\b(wordpress)\b': 'wordpress',
            r'\b(drupal)\b': 'drupal',
            r'\b(joomla)\b': 'joomla',
            r'\b(php)\b': 'php',
            r'\b(python)\b': 'python',
            r'\b(java)\b': 'java',
            r'\b(node\.?js)\b': 'nodejs',
            r'\b(docker)\b': 'docker',
            r'\b(kubernetes|k8s)\b': 'kubernetes'
        }
        
        for pattern, keyword in tech_patterns.items():
            if re.search(pattern, query_lower):
                keywords.append(keyword)
        
        # Vulnerability type patterns (add as context)
        vuln_types = {
            r'sql\s*injection|sqli': 'sql injection',
            r'cross[\s-]*site\s*scripting|xss': 'xss',
            r'remote\s*code\s*execution|rce': 'remote code execution',
            r'buffer\s*overflow': 'buffer overflow',
            r'privilege\s*escalation': 'privilege escalation',
            r'denial\s*of\s*service|dos': 'denial of service',
            r'authentication\s*bypass': 'authentication bypass'
        }
        
        for pattern, vuln_type in vuln_types.items():
            if re.search(pattern, query_lower):
                # Add as secondary context, not primary search term
                if len(keywords) < 2:  # Only add if we have tech keywords
                    keywords.append(vuln_type)
        
        # Remove duplicates and limit to top 2 keywords
        return list(dict.fromkeys(keywords))[:2]
    
    def _search_nvd_by_keyword(self, keywords: List[str], max_results: int = 5) -> List[Dict[str, Any]]:
        """
        Search NVD using extracted keywords.
        Returns formatted results compatible with merge strategy.
        """
        results = []
        
        if not self.real_time_manager or not keywords:
            return results
        
        try:
            nvd_client = self.real_time_manager.nvd
            
            for keyword in keywords:
                try:
                    logger.info(f"Searching NVD for keyword: {keyword}")
                    cves = nvd_client.search_cves(keyword, max_results=max_results)
                    
                    for cve in cves:
                        results.append({
                            'id': cve['cve_id'],
                            'cve_id': cve['cve_id'],
                            'title': f"{cve['cve_id']} - {keyword.title()} Vulnerability",
                            'description': cve['description'][:300] + '...' if len(cve['description']) > 300 else cve['description'],
                            'content': cve['description'],
                            'cvss_score': cve['cvss_score'],
                            'severity': cve['severity'],
                            'published': cve.get('published_date', ''),
                            'source': 'nist_nvd',
                            'relevance_score': 0.85,  # High relevance for keyword match
                            'real_time': True,
                            'keyword': keyword
                        })
                    
                    logger.info(f"Found {len(cves)} CVEs for keyword '{keyword}'")
                
                except Exception as e:
                    logger.warning(f"Failed to search NVD for '{keyword}': {e}")
                    continue
            
            return results
        
        except Exception as e:
            logger.error(f"Error in NVD keyword search: {e}")
            return []
    
    def _merge_results(
        self,
        local_results: List[Dict],
        realtime_results: List[Dict],
        prioritize: str = 'relevance'
    ) -> List[Dict[str, Any]]:
        """
        Merge and rank local + real-time results.
        
        Deduplication strategy:
        - Group by CVE ID
        - Real-time data enriches local data
        - Rank by: relevance + recency + confidence
        """
        # Index results by CVE ID
        merged_by_cve = {}
        
        # Add local results
        for result in local_results:
            cve_id = result.get('cve_id')
            if cve_id:
                if cve_id not in merged_by_cve:
                    merged_by_cve[cve_id] = result.copy()
                    merged_by_cve[cve_id]['sources'] = ['local']
                else:
                    merged_by_cve[cve_id]['sources'].append('local')
            else:
                # Non-CVE vulnerability
                key = f"local_{result.get('id', 'unknown')}"
                merged_by_cve[key] = result.copy()
                merged_by_cve[key]['sources'] = ['local']
        
        # Enrich with real-time data
        for result in realtime_results:
            cve_id = result.get('cve_id')
            if cve_id in merged_by_cve:
                # Enrich existing local entry
                local = merged_by_cve[cve_id]
                
                # Update with real-time data (take max CVSS, latest updates)
                local['cvss_score'] = max(
                    local.get('cvss_score', 0),
                    result.get('cvss_score', 0)
                )
                local['severity'] = result.get('severity', local.get('severity'))
                local['references'] = list(set(
                    local.get('references', []) + result.get('references', [])
                ))
                local['published'] = result.get('published', local.get('published'))
                local['updated'] = result.get('updated', local.get('updated'))
                local['sources'].append('nist_nvd')
                local['enriched_with_realtime'] = True
            else:
                # New CVE from real-time
                merged_by_cve[cve_id] = result.copy()
                merged_by_cve[cve_id]['sources'] = ['nist_nvd']
        
        # Convert to list and rank
        combined = list(merged_by_cve.values())
        
        # Ranking function
        def rank_score(item):
            # Base relevance
            score = item.get('relevance_score', 0.5)
            
            # Boost if enriched with real-time
            if item.get('enriched_with_realtime'):
                score += 0.2
            
            # Boost by CVSS score (normalized 0-1)
            cvss = item.get('cvss_score', 0)
            score += min(cvss / 10.0, 0.15)
            
            # Prioritize strategy
            if prioritize == 'recency' and item.get('updated'):
                score += 0.1  # Boost recent updates
            elif prioritize == 'confidence' and len(item.get('sources', [])) > 1:
                score += 0.15  # Boost multi-source data
            
            return score
        
        # Sort by rank score (descending)
        combined.sort(key=rank_score, reverse=True)
        
        logger.info(f"Merged {len(combined)} unique results")
        return combined
    
    def _calculate_confidence(
        self,
        local_results: List[Dict],
        realtime_results: List[Dict]
    ) -> float:
        """
        Calculate overall confidence of retrieval results.
        
        Factors:
        - Number of local results (0.4)
        - Real-time data available (0.35)
        - Result quality (0.25)
        """
        confidence = 0.0
        
        # Local coverage (0-0.4)
        local_factor = min(len(local_results) / 5.0, 1.0) * 0.4
        confidence += local_factor
        
        # Real-time coverage (0-0.35)
        if realtime_results:
            realtime_factor = min(len(realtime_results) / 3.0, 1.0) * 0.35
            confidence += realtime_factor
        
        # Quality metrics (0-0.25)
        quality_boost = 0
        for result in local_results + realtime_results:
            if result.get('cvss_score', 0) >= 7.0:  # Critical finding
                quality_boost += 0.05
        quality_boost = min(quality_boost, 0.25)
        confidence += quality_boost
        
        # Clamp to 0-1
        confidence = min(max(confidence, 0.0), 1.0)
        
        logger.info(f"Confidence: {confidence:.2f} (local: {local_factor:.2f}, realtime: {realtime_results and 0.35 or 0:.2f})")
        return round(confidence, 2)
    
    def retrieve(self, query: str, top_k: int = 5) -> Dict[str, Any]:
        """
        Fallback retrieve method for compatibility with RAGRetrievalEngine interface.
        Delegates to hybrid retrieval if hybrid engine available, otherwise to local engine.
        
        Args:
            query: Search query
            top_k: Number of results to retrieve
            
        Returns:
            Standard retrieval result format
        """
        try:
            # Use hybrid retrieval as primary method
            result = self.retrieve_hybrid(
                query=query,
                top_k_local=top_k,
                top_k_realtime=3
            )
            
            # Convert to standard RAGRetrievalEngine format
            return {
                'assembled_context': self._format_context_from_results(result.combined_results),
                'vulnerability_results': {
                    'cves': [r.get('cve_id') for r in result.combined_results if r.get('cve_id')],
                    'details': result.combined_results
                },
                'query_context': type('obj', (object,), {'intent': 'vulnerability_lookup'})(),
                'total_docs_retrieved': len(result.combined_results),
                'retrieval_confidence': result.confidence,
                'has_realtime_data': len(result.realtime_results) > 0,
                'retrieved_sources': result.retrieval_sources
            }
        except Exception as e:
            logger.error(f"Error in retrieve method: {e}")
            # Fallback to local engine only
            return self.local_engine.retrieve(query=query, top_k=top_k)
    
    def _format_context_from_results(self, results: List[Dict]) -> str:
        """Format combined results as context text"""
        if not results:
            return "No vulnerabilities found."
        
        context = "## Vulnerabilities\n\n"
        for i, result in enumerate(results[:10], 1):
            context += f"{i}. **{result.get('cve_id', 'N/A')}** - {result.get('title', 'N/A')}\n"
            if result.get('description'):
                context += f"   Description: {result['description'][:200]}\n"
            if result.get('cvss_score'):
                context += f"   CVSS: {result['cvss_score']}\n"
            context += "\n"
        
        return context
    
    def retrieve_for_context(
        self,
        query: str,
        top_k_local: int = 5,
        top_k_realtime: int = 3
    ) -> Dict[str, Any]:
        """
        Main entry point for retrieving context for chatbot.
        
        Returns formatted context for LLM prompt.
        """
        try:
            result = self.retrieve_hybrid(
                query=query,
                top_k_local=top_k_local,
                top_k_realtime=top_k_realtime,
                prioritize='relevance'
            )
            
            # Format for LLM context
            context_text = "## Retrieved Context\n\n"
            
            if result.combined_results:
                context_text += "### Relevant Vulnerabilities\n"
                for i, vuln in enumerate(result.combined_results[:10], 1):
                    context_text += f"\n{i}. **{vuln.get('cve_id', 'N/A')}** - {vuln.get('title', vuln.get('id'))}\n"
                    context_text += f"   - Severity: {vuln.get('severity', 'Unknown')}\n"
                    context_text += f"   - CVSS: {vuln.get('cvss_score', 'N/A')}\n"
                    if vuln.get('description'):
                        context_text += f"   - Description: {vuln['description'][:200]}...\n"
                    context_text += f"   - Sources: {', '.join(vuln.get('sources', []))}\n"
            else:
                context_text += "### No vulnerabilities found in knowledge base\n"
            
            return {
                'context_text': context_text,
                'retrieved_count': len(result.combined_results),
                'local_count': len(result.local_results),
                'realtime_count': len(result.realtime_results),
                'confidence': result.confidence,
                'sources': result.retrieval_sources,
                'has_realtime_data': len(result.realtime_results) > 0
            }
        
        except Exception as e:
            logger.error(f"Error retrieving context: {e}")
            return {
                'context_text': "Unable to retrieve context from knowledge base.",
                'retrieved_count': 0,
                'confidence': 0.0,
                'error': str(e)
            }
