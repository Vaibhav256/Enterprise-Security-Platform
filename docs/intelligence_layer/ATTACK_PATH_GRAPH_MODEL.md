# Attack Path Graph Model

## Overview

This document defines the **graph-based data model** for attack path analysis in the Intelligence Layer. The model enables automated discovery of both **isolated** (single-step) and **chained** (multi-step) vulnerability exploitation scenarios, visualizing how attackers could compromise systems within the assessed environment.

---

## Graph Database Technology Selection

### Comparison: Neo4j vs. NetworkX

| Feature | **NetworkX** (Recommended) | Neo4j |
|---------|---------------------------|-------|
| **Setup Complexity** | ✅ Minimal (pip install) | ⚠️ Moderate (separate server) |
| **Learning Curve** | ✅ Low (Python-native) | ⚠️ Steep (Cypher query language) |
| **Cost** | ✅ Free (BSD license) | ⚠️ Free Community, but paid Enterprise |
| **Scalability** | ⚠️ Good (<10K nodes) | ✅ Excellent (millions of nodes) |
| **Integration** | ✅ Native Python (no API calls) | ⚠️ Requires Bolt protocol/REST API |
| **Visualization** | ✅ Matplotlib, Plotly | ✅ Neo4j Browser (built-in) |
| **Graph Algorithms** | ✅ 50+ built-in (shortest path, centrality) | ✅ 65+ (Graph Data Science library) |
| **Persistence** | ⚠️ Manual (Pickle, GraphML) | ✅ Automatic (database) |
| **Multi-User** | ❌ Not designed for concurrent access | ✅ Native support |
| **College Project Fit** | ✅ **Ideal** (no infra, fast prototyping) | ⚠️ Overkill (unless existing Neo4j expertise) |

### Recommendation: **NetworkX**

**Justification for College Project:**
1. **Zero Infrastructure:** No separate database server to install/manage
2. **Python-Native:** Seamless integration with existing backend (FastAPI, Flask)
3. **Rapid Prototyping:** Build and visualize graphs in <50 lines of code
4. **Sufficient Scale:** Typical network scan (100 hosts, 500 vulnerabilities) = ~1000 nodes, well within NetworkX's performance envelope
5. **Rich Algorithms:** Built-in shortest path, reachability, centrality—perfect for attack path discovery

**When to Upgrade to Neo4j:**
- Production deployment with >10K nodes
- Multi-analyst concurrent access required
- Real-time graph queries (<100ms latency)

---

## Graph Schema Definition

### Node Types

#### 1. **Host Node**

Represents a scanned network device (server, workstation, IoT device).

**Attributes:**
```python
{
    "node_id": "host_192.168.1.50",  # Unique identifier
    "node_type": "host",
    "ip_address": "192.168.1.50",
    "hostname": "web-server-01.example.com",
    "os": "Ubuntu 20.04.6 LTS",
    "network_segment": "DMZ",  # DMZ, Internal, Isolated
    "criticality": "high",  # high, medium, low (business impact)
    "open_ports": [22, 80, 443],
    "services": {
        22: "OpenSSH 7.4",
        80: "Apache 2.4.41",
        443: "Apache 2.4.41 (SSL/TLS)"
    }
}
```

**Visual Representation:** 🖥️ (shape: box, color: based on criticality)

---

#### 2. **Vulnerability Node**

Represents a specific CVE or security flaw.

**Attributes:**
```python
{
    "node_id": "vuln_CVE-2023-12345",
    "node_type": "vulnerability",
    "cve_id": "CVE-2023-12345",
    "title": "OpenSSH Auth Bypass RCE",
    "cvss_score": 9.8,
    "severity": "critical",
    "cwe_id": "CWE-287",  # Improper Authentication
    "exploit_available": True,
    "exploit_maturity": "Functional",  # PoC, Functional, High
    "attack_vector": "Network",  # Network, Adjacent, Local, Physical
    "attack_complexity": "Low",  # Low, High
    "privileges_required": "None",  # None, Low, High
    "user_interaction": "None",  # None, Required
    "description": "Remote code execution via authentication bypass...",
    "remediation": "Upgrade to OpenSSH 9.0+"
}
```

**Visual Representation:** ⚠️ (shape: diamond, color: red=critical, orange=high, yellow=medium)

---

#### 3. **Credential Node**

Represents authentication mechanisms (weak passwords, default creds, leaked keys).

**Attributes:**
```python
{
    "node_id": "cred_ssh_weak_admin",
    "node_type": "credential",
    "credential_type": "weak_password",  # weak_password, default_creds, leaked_key
    "service": "SSH",
    "username": "admin",
    "strength": "weak",  # weak, default, compromised
    "description": "Weak SSH password susceptible to brute-force"
}
```

**Visual Representation:** 🔑 (shape: triangle, color: gray)

---

#### 4. **Attack Technique Node** (Optional, for advanced modeling)

Represents MITRE ATT&CK techniques (e.g., T1078 - Valid Accounts).

**Attributes:**
```python
{
    "node_id": "technique_T1078",
    "node_type": "attack_technique",
    "mitre_id": "T1078",
    "name": "Valid Accounts",
    "tactic": "Privilege Escalation",
    "description": "Adversaries may obtain and abuse credentials..."
}
```

---

### Edge Types (Relationships)

#### 1. **HAS_VULNERABILITY** (Host → Vulnerability)

**Meaning:** A host is affected by a vulnerability.

**Attributes:**
```python
{
    "edge_type": "HAS_VULNERABILITY",
    "detected_by": "Nmap",  # Tool that found the vuln
    "detected_date": "2024-01-15",
    "port": 22,
    "service": "OpenSSH 7.4",
    "confidence": 0.95  # Detection confidence (0-1)
}
```

**Example:**
```
(Host: 192.168.1.50) --[HAS_VULNERABILITY]--> (CVE-2023-12345)
```

---

#### 2. **EXPLOITS** (Vulnerability → Host)

**Meaning:** Exploiting this vulnerability grants access to a host.

**Attributes:**
```python
{
    "edge_type": "EXPLOITS",
    "impact": "remote_code_execution",  # RCE, privilege_escalation, info_disclosure
    "privileges_gained": "root",  # user, admin, root
    "exploit_difficulty": "Low",  # Low, Medium, High
    "prerequisites": ["Network access to port 22"],
    "exploit_references": ["https://www.exploit-db.com/exploits/50001"]
}
```

**Example:**
```
(CVE-2023-12345) --[EXPLOITS]--> (Host: 192.168.1.50)
```

---

#### 3. **LEADS_TO** (Host → Host)

**Meaning:** Compromising source host enables lateral movement to target host.

**Attributes:**
```python
{
    "edge_type": "LEADS_TO",
    "method": "lateral_movement",  # lateral_movement, privilege_escalation, pivoting
    "mechanism": "SSH with weak credentials",
    "network_path": "DMZ to Internal",
    "difficulty": "Low"
}
```

**Example:**
```
(Host: 192.168.1.50) --[LEADS_TO]--> (Host: 192.168.10.20)
```

---

#### 4. **USES_CREDENTIAL** (Host → Credential)

**Meaning:** A host uses a specific credential for authentication.

**Attributes:**
```python
{
    "edge_type": "USES_CREDENTIAL",
    "service": "SSH",
    "strength": "weak"
}
```

**Example:**
```
(Host: 192.168.1.50) --[USES_CREDENTIAL]--> (Credential: admin/weak_password)
```

---

## Graph Construction Algorithm

### Phase 1: Build Base Graph (Hosts + Vulnerabilities)

```python
import networkx as nx

# Initialize directed graph
attack_graph = nx.DiGraph()

# Add host nodes
for host in scanned_hosts:
    attack_graph.add_node(
        f"host_{host['ip']}",
        node_type="host",
        **host  # Unpack all host attributes
    )

# Add vulnerability nodes
for vuln in detected_vulnerabilities:
    attack_graph.add_node(
        f"vuln_{vuln['cve_id']}",
        node_type="vulnerability",
        **vuln
    )

# Add HAS_VULNERABILITY edges
for mapping in host_vuln_mappings:
    attack_graph.add_edge(
        f"host_{mapping['host_ip']}",
        f"vuln_{mapping['cve_id']}",
        edge_type="HAS_VULNERABILITY",
        **mapping['detection_metadata']
    )
```

---

### Phase 2: Infer EXPLOITS Edges (Vulnerability → Host)

```python
def infer_exploits_edges(graph):
    """
    For each HAS_VULNERABILITY edge, create reverse EXPLOITS edge
    if vulnerability has known exploit and grants significant privileges.
    """
    for host_node, vuln_node, edge_data in graph.edges(data=True):
        if edge_data['edge_type'] == 'HAS_VULNERABILITY':
            vuln_attrs = graph.nodes[vuln_node]
            
            # Criteria for exploitability
            if (vuln_attrs['exploit_available'] and 
                vuln_attrs['cvss_score'] >= 7.0 and
                vuln_attrs['privileges_required'] in ['None', 'Low']):
                
                # Add EXPLOITS edge
                graph.add_edge(
                    vuln_node,
                    host_node,
                    edge_type="EXPLOITS",
                    impact=determine_impact(vuln_attrs),
                    privileges_gained=determine_privileges(vuln_attrs),
                    exploit_difficulty=vuln_attrs['attack_complexity']
                )

def determine_impact(vuln_attrs):
    """Map CVE metadata to impact type."""
    if "code execution" in vuln_attrs['description'].lower():
        return "remote_code_execution"
    elif "privilege" in vuln_attrs['description'].lower():
        return "privilege_escalation"
    else:
        return "information_disclosure"
```

---

### Phase 3: Discover LEADS_TO Edges (Lateral Movement)

```python
def discover_lateral_movement(graph):
    """
    Identify potential lateral movement paths between hosts
    based on network connectivity and weak credentials.
    """
    hosts = [n for n, d in graph.nodes(data=True) if d['node_type'] == 'host']
    
    for source_host in hosts:
        source_attrs = graph.nodes[source_host]
        
        for target_host in hosts:
            if source_host == target_host:
                continue
            
            target_attrs = graph.nodes[target_host]
            
            # Check network reachability
            can_reach = check_network_connectivity(
                source_attrs['network_segment'],
                target_attrs['network_segment']
            )
            
            if can_reach:
                # Check for weak credentials on target
                weak_creds = find_weak_credentials(target_attrs)
                
                if weak_creds:
                    graph.add_edge(
                        source_host,
                        target_host,
                        edge_type="LEADS_TO",
                        method="lateral_movement",
                        mechanism=f"SSH with {weak_creds['type']}",
                        network_path=f"{source_attrs['network_segment']} to {target_attrs['network_segment']}",
                        difficulty="Low"
                    )

def check_network_connectivity(source_segment, target_segment):
    """
    Define network connectivity rules.
    Example: DMZ can reach Internal, but Isolated cannot reach anything.
    """
    rules = {
        "DMZ": ["Internal", "DMZ"],
        "Internal": ["Internal"],
        "Isolated": []
    }
    return target_segment in rules.get(source_segment, [])
```

---

## Attack Path Discovery Algorithms

### 1. Simple Path Discovery (Single-Step Attacks)

**Goal:** Find vulnerabilities that directly compromise a host.

```python
def find_simple_attack_paths(graph, target_host):
    """
    Identify all direct exploitation paths to target host.
    
    Returns:
        List of (vuln_node, impact) tuples
    """
    simple_paths = []
    
    # Find all EXPLOITS edges pointing to target
    for source_node, target_node, edge_data in graph.in_edges(target_host, data=True):
        if edge_data['edge_type'] == 'EXPLOITS':
            vuln_attrs = graph.nodes[source_node]
            simple_paths.append({
                'vulnerability': vuln_attrs['cve_id'],
                'cvss_score': vuln_attrs['cvss_score'],
                'impact': edge_data['impact'],
                'difficulty': edge_data['exploit_difficulty'],
                'description': f"Exploit {vuln_attrs['cve_id']} to gain {edge_data['privileges_gained']} access"
            })
    
    # Sort by severity (CVSS score descending)
    return sorted(simple_paths, key=lambda x: x['cvss_score'], reverse=True)
```

**Example Output:**
```python
[
    {
        'vulnerability': 'CVE-2023-12345',
        'cvss_score': 9.8,
        'impact': 'remote_code_execution',
        'difficulty': 'Low',
        'description': 'Exploit CVE-2023-12345 to gain root access'
    }
]
```

---

### 2. Chained Attack Path Discovery (Multi-Step)

**Goal:** Find multi-hop exploitation sequences (e.g., RCE on web server → pivot to database).

```python
def find_chained_attack_paths(graph, entry_point, target_host, max_depth=5):
    """
    Discover chained vulnerability exploitation paths.
    
    Args:
        entry_point: Initial compromised host (e.g., DMZ web server)
        target_host: Final objective (e.g., database server)
        max_depth: Maximum chain length
    
    Returns:
        List of attack paths (sequences of nodes)
    """
    all_paths = nx.all_simple_paths(
        graph, 
        source=entry_point, 
        target=target_host, 
        cutoff=max_depth
    )
    
    chained_paths = []
    
    for path in all_paths:
        # Parse path into human-readable steps
        steps = []
        for i in range(len(path) - 1):
            source, target = path[i], path[i+1]
            edge_data = graph.get_edge_data(source, target)
            
            if edge_data['edge_type'] == 'EXPLOITS':
                vuln_attrs = graph.nodes[source]
                steps.append({
                    'step': i + 1,
                    'action': 'exploit',
                    'vulnerability': vuln_attrs['cve_id'],
                    'target': target,
                    'impact': edge_data['impact']
                })
            elif edge_data['edge_type'] == 'LEADS_TO':
                steps.append({
                    'step': i + 1,
                    'action': 'lateral_movement',
                    'method': edge_data['mechanism'],
                    'from': source,
                    'to': target
                })
        
        chained_paths.append({
            'path_length': len(steps),
            'steps': steps,
            'difficulty': calculate_overall_difficulty(steps),
            'cvss_max': max([s.get('cvss_score', 0) for s in steps if 'cvss_score' in s])
        })
    
    # Sort by difficulty (easier paths first - higher priority for remediation)
    return sorted(chained_paths, key=lambda x: x['difficulty'])

def calculate_overall_difficulty(steps):
    """
    Aggregate difficulty across chained steps.
    Low=1, Medium=2, High=3. Sum and normalize.
    """
    difficulty_map = {'Low': 1, 'Medium': 2, 'High': 3}
    total = sum([difficulty_map.get(s.get('difficulty', 'Medium'), 2) for s in steps])
    
    if total <= len(steps):
        return 'Low'
    elif total <= 2 * len(steps):
        return 'Medium'
    else:
        return 'High'
```

**Example Output:**
```python
[
    {
        'path_length': 3,
        'difficulty': 'Low',
        'cvss_max': 9.8,
        'steps': [
            {
                'step': 1,
                'action': 'exploit',
                'vulnerability': 'CVE-2023-11111',
                'target': 'host_192.168.1.50',
                'impact': 'remote_code_execution'
            },
            {
                'step': 2,
                'action': 'lateral_movement',
                'method': 'SSH with weak credentials',
                'from': 'host_192.168.1.50',
                'to': 'host_192.168.10.20'
            },
            {
                'step': 3,
                'action': 'exploit',
                'vulnerability': 'CVE-2023-22222',
                'target': 'host_192.168.10.20',
                'impact': 'privilege_escalation'
            }
        ]
    }
]
```

---

## Graph Visualization

```python
import matplotlib.pyplot as plt
import networkx as nx

def visualize_attack_graph(graph, highlight_path=None):
    """
    Render attack graph with color-coded nodes.
    
    Args:
        highlight_path: List of node IDs to emphasize (attack path)
    """
    pos = nx.spring_layout(graph, seed=42)  # Reproducible layout
    
    # Color mapping
    node_colors = []
    for node, attrs in graph.nodes(data=True):
        if highlight_path and node in highlight_path:
            node_colors.append('red')  # Highlight attack path
        elif attrs['node_type'] == 'host':
            node_colors.append('lightblue')
        elif attrs['node_type'] == 'vulnerability':
            # Color by severity
            if attrs['severity'] == 'critical':
                node_colors.append('darkred')
            elif attrs['severity'] == 'high':
                node_colors.append('orange')
            else:
                node_colors.append('yellow')
        else:
            node_colors.append('gray')
    
    # Draw graph
    plt.figure(figsize=(14, 10))
    nx.draw(
        graph,
        pos,
        node_color=node_colors,
        with_labels=True,
        labels={n: n.replace('host_', '').replace('vuln_', '') for n in graph.nodes()},
        node_size=1000,
        font_size=8,
        font_weight='bold',
        arrows=True,
        edge_color='gray',
        width=1.5
    )
    
    # Add edge labels
    edge_labels = {
        (u, v): d['edge_type'] 
        for u, v, d in graph.edges(data=True)
    }
    nx.draw_networkx_edge_labels(graph, pos, edge_labels, font_size=7)
    
    plt.title("Attack Path Graph", fontsize=16, fontweight='bold')
    plt.axis('off')
    plt.tight_layout()
    plt.savefig('attack_graph.png', dpi=300, bbox_inches='tight')
    plt.show()
```

---

## Persistence & Storage

```python
import pickle
import json

# Save graph to file (Pickle - preserves all NetworkX data)
def save_graph(graph, filepath='attack_graph.pkl'):
    with open(filepath, 'wb') as f:
        pickle.dump(graph, f)

# Load graph from file
def load_graph(filepath='attack_graph.pkl'):
    with open(filepath, 'rb') as f:
        return pickle.load(f)

# Export to JSON (for frontend visualization)
def export_graph_json(graph, filepath='attack_graph.json'):
    data = nx.node_link_data(graph)
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)
```

---

## Integration with RAG Chatbot

Attack paths are indexed in ChromaDB (see `DATA_INDEXING_SCHEMA.md` → Collection 3) to enable queries like:

**Query:** "Show me attack paths to the database server"

**RAG Retrieval:** Fetches indexed attack path documents from ChromaDB

**LLM Response:**
```
I found 2 attack paths to the database server (192.168.10.20):

**Path 1 (Low Difficulty):**
1. Exploit CVE-2023-11111 (SQL injection) on web server (192.168.1.50)
2. Use compromised web server to pivot via weak SSH credentials
3. Access database server with elevated privileges

**Mitigation Priority:**
1. Patch web server (CVE-2023-11111) - CRITICAL
2. Enforce SSH key authentication
3. Segment network (VLAN isolation)
```

---

## Example Graph Construction Script

See `backend/intelligence_layer/attack_path/graph_builder.py` (to be created in PoC phase).

---

## Performance Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Graph Build Time** | <5 sec (100 hosts) | Time to construct graph from scan data |
| **Path Discovery Time** | <1 sec (simple), <5 sec (chained) | NetworkX algorithm execution |
| **Memory Usage** | <50MB (1000 nodes) | Graph object size in RAM |

---

## Technology Stack Summary

| Component | Technology | Justification |
|-----------|------------|---------------|
| **Graph Database** | NetworkX | Python-native, no infra, fast prototyping |
| **Visualization** | Matplotlib + Plotly | Static images + interactive web viz |
| **Persistence** | Pickle + JSON | Simple serialization, frontend-compatible |
| **Algorithms** | NetworkX built-ins | Shortest path, reachability, centrality |

---

## Next Steps

1. **Implement graph builder** (`graph_builder.py`)
2. **Create path discovery functions** (simple + chained)
3. **Visualize sample attack graph** (using test data)
4. **Index attack paths** in ChromaDB for RAG queries
5. **Integrate with frontend** (display interactive graph)
