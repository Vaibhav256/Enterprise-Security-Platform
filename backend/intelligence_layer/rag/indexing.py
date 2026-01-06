"""
Data Indexing Pipeline for RAG System
Implements ChromaDB indexing for vulnerability scans and threat intelligence.
Based on DATA_INDEXING_SCHEMA.md specifications.
"""

import chromadb
import logging
from typing import List, Dict, Optional, Any
from datetime import datetime
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class VulnerabilityIndexer:
    """
    Indexes vulnerability scan data into ChromaDB for semantic search.
    
    Collections:
        - vulnerability_scans: Individual vulnerability findings
        - threat_intelligence: Enrichment data from NVD/ExploitDB
        - attack_paths: Discovered attack path models
    """
    
    def __init__(
        self,
        persist_directory: str = "./chroma_db",
        embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    ):
        """
        Initialize ChromaDB client and collections.
        
        Args:
            persist_directory: Directory to persist ChromaDB data
            embedding_model: Sentence transformer model for embeddings
        """
        # Initialize ChromaDB with new persistent client
        try:
            # New ChromaDB API (v0.5+) - Disable telemetry
            from chromadb.config import Settings as ChromaSettings
            self.client = chromadb.PersistentClient(
                path=persist_directory,
                settings=ChromaSettings(anonymized_telemetry=False)
            )
            logger.info(f"ChromaDB initialized with persistent storage at {persist_directory}")
        except (AttributeError, TypeError):
            # Fallback to older API if PersistentClient doesn't support settings parameter
            try:
                from chromadb.config import Settings
                self.client = chromadb.Client(Settings(
                    chroma_db_impl="duckdb+parquet",
                    persist_directory=persist_directory,
                    anonymized_telemetry=False
                ))
                logger.info("ChromaDB initialized with old API (Settings)")
            except Exception as e:
                logger.warning(f"Could not initialize ChromaDB with persistence: {e}")
                # Fall back to ephemeral client
                self.client = chromadb.EphemeralClient()
                logger.warning("Using ephemeral ChromaDB (data will not persist)")
        
        # Create or get collections (new API doesn't need explicit embedding function)
        try:
            self.vuln_collection = self.client.get_or_create_collection(
                name="vulnerability_scans",
                metadata={"hnsw:space": "cosine"}
            )
        except Exception as e:
            logger.warning(f"Could not create vulnerability_scans collection: {e}")
            self.vuln_collection = None
        
        try:
            self.threat_intel_collection = self.client.get_or_create_collection(
                name="threat_intelligence",
                metadata={"hnsw:space": "cosine"}
            )
        except Exception as e:
            logger.warning(f"Could not create threat_intelligence collection: {e}")
            self.threat_intel_collection = None
        
        try:
            self.attack_path_collection = self.client.get_or_create_collection(
                name="attack_paths",
                metadata={"hnsw:space": "cosine"}
            )
        except Exception as e:
            logger.warning(f"Could not create attack_paths collection: {e}")
            self.attack_path_collection = None
        
        logger.info("VulnerabilityIndexer initialized successfully")
    
    def _get_or_create_collection(
        self,
        name: str,
        metadata: Dict[str, Any]
    ):
        """Get existing collection or create new one"""
        try:
            return self.client.get_collection(name=name)
        except Exception:
            return self.client.create_collection(
                name=name,
                metadata=metadata
            )
    
    def _check_duplicate(self, doc_id: str) -> bool:
        """Check if document already exists in collection."""
        try:
            result = self.vuln_collection.get(ids=[doc_id])
            return len(result['ids']) > 0
        except Exception as e:
            logger.warning(f"Error checking duplicate for {doc_id}: {e}")
            return False
    
    def delete_vulnerability(self, doc_id: str) -> bool:
        """Delete a vulnerability by document ID."""
        try:
            self.vuln_collection.delete(ids=[doc_id])
            logger.info(f"Deleted vulnerability: {doc_id}")
            return True
        except Exception as e:
            logger.error(f"Error deleting vulnerability {doc_id}: {e}")
            return False
    
    def delete_by_scan_id(self, scan_id: str) -> int:
        """Delete all vulnerabilities from a specific scan."""
        try:
            results = self.vuln_collection.get(where={"scan_id": scan_id})
            if results['ids']:
                self.vuln_collection.delete(ids=results['ids'])
                count = len(results['ids'])
                logger.info(f"Deleted {count} vulnerabilities from scan {scan_id}")
                return count
            return 0
        except Exception as e:
            logger.error(f"Error deleting scan {scan_id}: {e}")
            return 0
    
    def update_vulnerability_metadata(self, doc_id: str, metadata: Dict) -> bool:
        """Update metadata for an existing vulnerability."""
        try:
            self.vuln_collection.update(
                ids=[doc_id],
                metadatas=[metadata]
            )
            logger.info(f"Updated vulnerability metadata: {doc_id}")
            return True
        except Exception as e:
            logger.error(f"Error updating vulnerability {doc_id}: {e}")
            return False
    
    def index_vulnerability(
        self,
        cve_id: str,
        host_ip: str,
        port: Optional[int],
        service: Optional[str],
        severity: str,
        cvss_score: float,
        description: str,
        exploit_available: bool,
        tool_name: str,
        scan_id: str,
        additional_metadata: Optional[Dict] = None,
        skip_duplicates: bool = True
    ) -> str:
        """
        Index a single vulnerability finding with deduplication.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2023-12345")
            host_ip: Target host IP address
            port: Affected port number
            service: Service name (e.g., "ssh", "http")
            severity: Severity level (critical, high, medium, low)
            cvss_score: CVSS v3 score (0.0 - 10.0)
            description: Vulnerability description
            exploit_available: Whether public exploit exists
            tool_name: Scanning tool that detected it
            scan_id: Associated scan ID
            additional_metadata: Extra metadata to store
            skip_duplicates: If True, skip indexing if document already exists
        
        Returns:
            Document ID
        """
        # Generate unique document ID
        doc_id = self._generate_doc_id(cve_id, host_ip, port)
        
        # Check for duplicates
        if skip_duplicates and self._check_duplicate(doc_id):
            logger.info(f"Skipping duplicate vulnerability: {doc_id}")
            return doc_id
        
        # Create composite document (natural language for semantic search)
        # Extract solution and other enrichment data if available
        solution = additional_metadata.get('solution') if additional_metadata else None
        cwe_id = additional_metadata.get('cwe_id') if additional_metadata else None
        references = additional_metadata.get('references') if additional_metadata else None
        
        document = self._create_vulnerability_document(
            cve_id=cve_id,
            host_ip=host_ip,
            port=port,
            service=service,
            severity=severity,
            cvss_score=cvss_score,
            description=description,
            exploit_available=exploit_available,
            solution=solution,
            cwe_id=cwe_id,
            references=references
        )
        
        # Prepare metadata (ChromaDB only supports str, int, float, bool)
        metadata = {
            "cve_id": cve_id,
            "host_ip": host_ip,
            "port": port or 0,
            "service": service or "unknown",
            "severity": severity,
            "cvss_score": cvss_score,
            "exploit_available": str(exploit_available),
            "tool_name": tool_name,
            "scan_id": scan_id,
            "indexed_at": datetime.utcnow().isoformat()
        }
        
        # Add additional metadata (convert lists to strings)
        if additional_metadata:
            for key, value in additional_metadata.items():
                if isinstance(value, list):
                    # Convert lists to comma-separated strings
                    metadata[key] = ", ".join(str(v) for v in value)
                elif isinstance(value, (str, int, float, bool)):
                    metadata[key] = value
                # Skip other types (dicts, etc.)
        
        # Add to collection
        self.vuln_collection.add(
            documents=[document],
            metadatas=[metadata],
            ids=[doc_id]
        )
        
        logger.info(f"Indexed vulnerability: {doc_id}")
        return doc_id
    
    def batch_index_vulnerabilities(
        self,
        vulnerabilities: List[Dict]
    ) -> List[str]:
        """
        Batch index multiple vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerability dicts with required fields
        
        Returns:
            List of document IDs
        """
        documents = []
        metadatas = []
        ids = []
        
        for vuln in vulnerabilities:
            # Generate document with enrichment
            solution = vuln.get('solution')
            cwe_id = vuln.get('cwe_id')
            references = vuln.get('references')
            
            doc = self._create_vulnerability_document(
                cve_id=vuln.get('cve_id'),
                host_ip=vuln.get('host_ip'),
                port=vuln.get('port'),
                service=vuln.get('service'),
                severity=vuln.get('severity'),
                cvss_score=vuln.get('cvss_score'),
                description=vuln.get('description', ''),
                exploit_available=vuln.get('exploit_available', False),
                solution=solution,
                cwe_id=cwe_id,
                references=references
            )
            
            # Generate ID
            doc_id = self._generate_doc_id(
                vuln.get('cve_id'),
                vuln.get('host_ip'),
                vuln.get('port')
            )
            
            # Prepare metadata
            metadata = {
                "cve_id": vuln.get('cve_id'),
                "host_ip": vuln.get('host_ip'),
                "port": vuln.get('port', 0),
                "service": vuln.get('service', 'unknown'),
                "severity": vuln.get('severity'),
                "cvss_score": vuln.get('cvss_score'),
                "exploit_available": str(vuln.get('exploit_available', False)),
                "tool_name": vuln.get('tool_name', 'unknown'),
                "scan_id": vuln.get('scan_id', 'unknown'),
                "indexed_at": datetime.utcnow().isoformat()
            }
            
            documents.append(doc)
            metadatas.append(metadata)
            ids.append(doc_id)
        
        # Batch add
        if documents:
            self.vuln_collection.add(
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )
            logger.info(f"Batch indexed {len(documents)} vulnerabilities")
        
        return ids
    
    def index_threat_intel(
        self,
        cve_id: str,
        cwe_id: Optional[str],
        exploit_maturity: str,
        affected_products: List[str],
        references: List[str],
        remediation: Optional[str] = None,
        source: str = "nvd"
    ) -> str:
        """
        Index threat intelligence data.
        
        Args:
            cve_id: CVE identifier
            cwe_id: CWE identifier (e.g., "CWE-79")
            exploit_maturity: proof_of_concept, functional, high
            affected_products: List of affected product names
            references: List of reference URLs
            remediation: Remediation guidance
            source: Data source (nvd, exploitdb, rapid7)
        
        Returns:
            Document ID
        """
        doc_id = f"threat_intel_{cve_id}_{source}"
        
        # Create document
        document = f"""
CVE: {cve_id}
CWE: {cwe_id or 'Not specified'}
Exploit Maturity: {exploit_maturity}
Affected Products: {', '.join(affected_products)}
Remediation: {remediation or 'See references for guidance'}
Source: {source}
"""
        
        # Metadata
        metadata = {
            "cve_id": cve_id,
            "cwe_id": cwe_id or "unknown",
            "exploit_maturity": exploit_maturity,
            "source": source,
            "indexed_at": datetime.utcnow().isoformat(),
            "has_remediation": str(bool(remediation))
        }
        
        # Add to collection
        self.threat_intel_collection.add(
            documents=[document],
            metadatas=[metadata],
            ids=[doc_id]
        )
        
        logger.info(f"Indexed threat intel: {doc_id}")
        return doc_id
    
    def index_attack_path(
        self,
        path_id: str,
        source_host: str,
        target_host: str,
        vulnerabilities_chained: List[str],
        total_steps: int,
        max_cvss: float,
        difficulty: float,
        description: str
    ) -> str:
        """
        Index discovered attack path.
        
        Args:
            path_id: Unique path identifier
            source_host: Entry point host IP
            target_host: Target host IP
            vulnerabilities_chained: List of CVE IDs in path
            total_steps: Number of exploitation steps
            max_cvss: Highest CVSS in path
            difficulty: Path difficulty (0.0 - 1.0)
            description: Human-readable path description
        
        Returns:
            Document ID
        """
        doc_id = f"attack_path_{path_id}"
        
        # Create document
        document = f"""
Attack Path: {source_host} → {target_host}
Vulnerabilities: {', '.join(vulnerabilities_chained)}
Total Steps: {total_steps}
Max CVSS: {max_cvss}
Difficulty: {difficulty:.2f}
Description: {description}
"""
        
        # Metadata
        metadata = {
            "path_id": path_id,
            "source_host": source_host,
            "target_host": target_host,
            "total_steps": total_steps,
            "max_cvss": max_cvss,
            "difficulty": difficulty,
            "num_vulnerabilities": len(vulnerabilities_chained),
            "indexed_at": datetime.utcnow().isoformat()
        }
        
        # Add to collection
        self.attack_path_collection.add(
            documents=[document],
            metadatas=[metadata],
            ids=[doc_id]
        )
        
        logger.info(f"Indexed attack path: {doc_id}")
        return doc_id
    
    def _create_vulnerability_document(
        self,
        cve_id: str,
        host_ip: str,
        port: Optional[int],
        service: Optional[str],
        severity: str,
        cvss_score: float,
        description: str,
        exploit_available: bool,
        solution: Optional[str] = None,
        cwe_id: Optional[str] = None,
        references: Optional[List[str]] = None
    ) -> str:
        """
        Create rich natural language document for semantic search.
        Enhanced with remediation and reference information for better LLM context.
        
        Combines all fields into comprehensive natural language text for better embedding
        and more accurate, detailed chatbot responses.
        """
        # Port info
        port_str = f"Port {port}" if port else "Multiple ports"
        service_str = f"({service})" if service else ""
        
        # Exploit status with urgency
        if exploit_available:
            exploit_str = "⚠️ PUBLIC EXPLOIT AVAILABLE - IMMEDIATE ACTION REQUIRED"
            urgency = "CRITICAL PRIORITY"
        else:
            exploit_str = "No known public exploit (monitor for updates)"
            urgency = "STANDARD PRIORITY"
        
        # CWE info
        cwe_str = f"\nWeakness Type: {cwe_id}" if cwe_id else ""
        
        # Solution info
        solution_str = ""
        if solution:
            solution_str = f"\n\nREMEDIATION STEPS:\n{solution}\n{urgency}: This vulnerability should be addressed {'immediately' if cvss_score >= 9.0 else 'urgently' if cvss_score >= 7.0 else 'in the next maintenance window'}."
        
        # References
        ref_str = ""
        if references:
            ref_str = f"\n\nADDITIONAL INFORMATION:\n" + "\n".join([f"- {ref}" for ref in references[:3]])
        
        # Compose comprehensive document with all context
        document = f"""
VULNERABILITY DETAILS: {cve_id}
Description: {description}

SEVERITY ASSESSMENT:
Risk Level: {severity.upper()}
CVSS Score: {cvss_score}/10.0
Exploit Status: {exploit_str}

AFFECTED SYSTEM:
Host: {host_ip}
Network Location: {port_str} {service_str}
Service Running: {service or 'Unknown service'}
{cwe_str}
{solution_str}
{ref_str}

RISK IMPACT: {'CRITICAL - This vulnerability poses an immediate threat to system security and requires urgent remediation. Exploits are publicly available.' if cvss_score >= 9.0 and exploit_available else 'CRITICAL - High severity vulnerability that could lead to complete system compromise.' if cvss_score >= 9.0 else 'HIGH - Significant security risk that should be addressed urgently to prevent potential exploitation.' if cvss_score >= 7.0 else 'MEDIUM - Moderate security concern that should be addressed during next maintenance window.' if cvss_score >= 4.0 else 'LOW - Minor security issue that should be monitored and planned for remediation.'}
"""
        
        return document.strip()
    
    def _generate_doc_id(
        self,
        cve_id: str,
        host_ip: str,
        port: Optional[int]
    ) -> str:
        """Generate unique document ID from CVE, host, and port"""
        # Use hash to ensure uniqueness
        content = f"{cve_id}_{host_ip}_{port or 0}"
        # Use a secure hash (SHA-256) for document ID generation to avoid weak-hash flags
        hash_suffix = hashlib.sha256(content.encode()).hexdigest()[:12]
        return f"vuln_{hash_suffix}"
    
    def query_vulnerabilities(
        self,
        query_text: str,
        n_results: int = 5,
        filter_metadata: Optional[Dict] = None
    ) -> Dict:
        """
        Semantic search for vulnerabilities.
        
        Args:
            query_text: Natural language query
            n_results: Number of results to return
            filter_metadata: Metadata filters (e.g., {"host_ip": "192.168.1.50"})
        
        Returns:
            Query results with documents, metadatas, and distances
        """
        results = self.vuln_collection.query(
            query_texts=[query_text],
            n_results=n_results,
            where=filter_metadata
        )
        
        return {
            "documents": results['documents'][0] if results['documents'] else [],
            "metadatas": results['metadatas'][0] if results['metadatas'] else [],
            "distances": results['distances'][0] if results['distances'] else []
        }
    
    def query_threat_intel(
        self,
        query_text: str,
        n_results: int = 3
    ) -> Dict:
        """Query threat intelligence collection"""
        results = self.threat_intel_collection.query(
            query_texts=[query_text],
            n_results=n_results
        )
        
        return {
            "documents": results['documents'][0] if results['documents'] else [],
            "metadatas": results['metadatas'][0] if results['metadatas'] else []
        }
    
    def query_attack_paths(
        self,
        query_text: str,
        n_results: int = 3
    ) -> Dict:
        """Query attack path collection"""
        results = self.attack_path_collection.query(
            query_texts=[query_text],
            n_results=n_results
        )
        
        return {
            "documents": results['documents'][0] if results['documents'] else [],
            "metadatas": results['metadatas'][0] if results['metadatas'] else []
        }
    
    def get_collection_stats(self) -> Dict:
        """Get statistics about indexed data"""
        return {
            "vulnerability_scans": self.vuln_collection.count(),
            "threat_intelligence": self.threat_intel_collection.count(),
            "attack_paths": self.attack_path_collection.count()
        }
    
    def persist(self):
        """Persist ChromaDB data to disk"""
        self.client.persist()
        logger.info("ChromaDB data persisted to disk")


# Example usage
if __name__ == '__main__':
    # Initialize indexer
    indexer = VulnerabilityIndexer(persist_directory="./test_chroma_db")
    
    # Index single vulnerability
    doc_id = indexer.index_vulnerability(
        cve_id="CVE-2023-12345",
        host_ip="192.168.1.50",
        port=80,
        service="http",
        severity="critical",
        cvss_score=9.8,
        description="Remote Code Execution in Apache HTTP Server 2.4.49",
        exploit_available=True,
        tool_name="nuclei",
        scan_id="scan_001"
    )
    print(f"Indexed vulnerability: {doc_id}")
    
    # Batch index
    vulns = [
        {
            "cve_id": "CVE-2023-22222",
            "host_ip": "192.168.1.50",
            "port": 22,
            "service": "ssh",
            "severity": "high",
            "cvss_score": 7.5,
            "description": "OpenSSH authentication bypass",
            "exploit_available": True,
            "tool_name": "nmap",
            "scan_id": "scan_001"
        },
        {
            "cve_id": "CVE-2023-33333",
            "host_ip": "192.168.1.60",
            "port": 5432,
            "service": "postgresql",
            "severity": "high",
            "cvss_score": 8.5,
            "description": "PostgreSQL privilege escalation",
            "exploit_available": False,
            "tool_name": "openvas",
            "scan_id": "scan_002"
        }
    ]
    
    ids = indexer.batch_index_vulnerabilities(vulns)
    print(f"Batch indexed {len(ids)} vulnerabilities")
    
    # Query
    print("\n=== Query Results ===")
    results = indexer.query_vulnerabilities(
        query_text="What are the critical SSH vulnerabilities on 192.168.1.50?",
        n_results=3,
        filter_metadata={"host_ip": "192.168.1.50"}
    )
    
    for i, (doc, meta) in enumerate(zip(results['documents'], results['metadatas']), 1):
        print(f"\n Result {i}:")
        print(f"  CVE: {meta['cve_id']}")
        print(f"  CVSS: {meta['cvss_score']}")
        print(f"  Document: {doc[:100]}...")
    
    # Stats
    print("\n=== Collection Stats ===")
    stats = indexer.get_collection_stats()
    print(f"Vulnerabilities: {stats['vulnerability_scans']}")
    print(f"Threat Intel: {stats['threat_intelligence']}")
    print(f"Attack Paths: {stats['attack_paths']}")
    
    # Persist
    indexer.persist()
