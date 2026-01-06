# 🔐 ESP - Enterprise Security Platform - Complete Project Understanding

**Last Updated:** December 12, 2025  
**Project Type:** Centralized Vulnerability Detection & Intelligence Platform  
**Architecture:** Full-Stack Web Application with AI-Powered Intelligence Layer

---

## 📋 Table of Contents

1. [Project Overview](#project-overview)
2. [Technology Stack](#technology-stack)
3. [Architecture Overview](#architecture-overview)
4. [Backend Deep Dive](#backend-deep-dive)
5. [Frontend Deep Dive](#frontend-deep-dive)
6. [Intelligence Layer (AI/RAG)](#intelligence-layer)
7. [Database Schema](#database-schema)
8. [Security Tools Integration](#security-tools-integration)
9. [DevOps & Infrastructure](#devops--infrastructure)
10. [Evaluation & Testing](#evaluation--testing)
11. [Workflow & Data Flow](#workflow--data-flow)
12. [Configuration & Environment](#configuration--environment)
13. [Key Features](#key-features)
14. [Development Guidelines](#development-guidelines)

---

## 📖 Project Overview

### What is ESP?

ESP (Enterprise Security Platform) is a **centralized vulnerability scanning and threat intelligence platform** that:

- 🎯 **Aggregates multiple security scanning tools** (Nmap, OpenVAS, Nikto, Nuclei) into a unified interface
- 🤖 **Leverages AI/RAG (Retrieval Augmented Generation)** for intelligent vulnerability analysis using local LLMs
- 📊 **Provides real-time threat intelligence** from NVD (National Vulnerability Database) and ExploitDB
- 🔍 **Offers natural language querying** through an AI-powered chatbot
- 📈 **Generates comprehensive reports** in PDF/Excel formats
- 🌐 **Real-time updates** via WebSocket connections
- 🚀 **Scalable architecture** using Redis queues for asynchronous task processing

### Core Purpose

The platform solves the problem of **fragmented security tooling** by:
1. Providing a single interface for multiple scanning tools
2. Automatically correlating scan results with known vulnerabilities (CVEs)
3. Using AI to answer complex security questions
4. Tracking and managing scans across your infrastructure
5. Generating actionable intelligence reports

---

## 🛠️ Technology Stack

### Backend Stack

| Technology | Version | Purpose |
|------------|---------|---------|
| **Python** | 3.9+ | Primary backend language |
| **Flask** | 3.0.0 | Web framework & API server |
| **Flask-RESTX** | 1.3.0 | REST API with Swagger documentation |
| **Flask-SocketIO** | 5.3.6 | WebSocket real-time communication |
| **SQLAlchemy** | 2.0.23 | ORM for database operations |
| **PostgreSQL** | 14+ | Primary relational database |
| **Redis** | 7+ | Caching & job queue |
| **RQ (Redis Queue)** | 1.15.1 | Asynchronous task processing |
| **Alembic** | 1.13.0 | Database migrations |
| **Gunicorn** | 21.2.0 | WSGI production server |

### AI/ML Stack

| Technology | Purpose |
|------------|---------|
| **Ollama** | Local LLM inference engine (Llama 3.2 3B) |
| **ChromaDB** | Vector database for RAG embeddings |
| **Sentence Transformers** | Text embeddings generation |
| **spaCy** | NLP preprocessing |
| **NLTK** | Natural language processing |
| **FAISS** | Vector similarity search |

### Frontend Stack

| Technology | Version | Purpose |
|------------|---------|---------|
| **React** | 19.1.1 | UI framework |
| **TypeScript** | 5.9.3 | Type-safe JavaScript |
| **Vite** | 7.1.7 | Build tool & dev server |
| **React Router** | 7.9.5 | Client-side routing |
| **Tailwind CSS** | 3.4.18 | Utility-first CSS framework |
| **Framer Motion** | 12.23.24 | Animations |
| **Recharts** | 3.3.0 | Data visualization |
| **Axios** | 1.13.1 | HTTP client |
| **Socket.IO Client** | 4.8.1 | WebSocket client |
| **Lucide React** | 0.548.0 | Icon library |

### Security Tools (WSL Integration)

| Tool | Purpose |
|------|---------|
| **Nmap** | Network discovery & port scanning |
| **OpenVAS** | Comprehensive vulnerability scanner |
| **Nikto** | Web server vulnerability scanner |
| **Nuclei** | Template-based vulnerability scanner |
| **GVM (Greenbone)** | OpenVAS management |

### Infrastructure & DevOps

| Technology | Purpose |
|------------|---------|
| **Docker** | Containerization |
| **Docker Compose** | Multi-container orchestration |
| **WSL (Windows Subsystem for Linux)** | Run Linux security tools on Windows |
| **Nginx** | Frontend reverse proxy |
| **Prometheus** | Metrics collection (configured) |

---

## 🏗️ Architecture Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CLIENT LAYER                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  React SPA (Vite)                                     │  │
│  │  - Dashboard  - Scans  - Intelligence  - Reports     │  │
│  └──────────────────────────────────────────────────────┘  │
└────────────────┬────────────────────────────────────────────┘
                 │ HTTP/REST + WebSocket
                 ▼
┌─────────────────────────────────────────────────────────────┐
│                  API GATEWAY (Flask)                        │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Routes: /api/scans, /api/intelligence, /api/feeds  │  │
│  │  WebSocket: Real-time scan updates                   │  │
│  │  Middleware: CORS, Rate Limiting, Error Handling     │  │
│  └──────────────────────────────────────────────────────┘  │
└─┬───────────────────┬────────────────────┬──────────────────┘
  │                   │                    │
  ▼                   ▼                    ▼
┌──────────────┐ ┌────────────────┐ ┌────────────────────────┐
│  SERVICES    │ │   INTELLIGENCE │ │   THREAT FEEDS         │
│              │ │   LAYER (AI)   │ │                        │
│ - Scan Orch. │ │                │ │ - NVD Client           │
│ - Adapters   │ │ - RAG Chatbot  │ │ - ExploitDB Client     │
│ - Export     │ │ - Retrieval    │ │ - Feed Sync Service    │
│ - Reporting  │ │ - Attack Path  │ │ - Scheduler            │
└──────┬───────┘ └────┬───────────┘ └──────┬─────────────────┘
       │              │                     │
       │              │                     │
       ▼              ▼                     ▼
┌─────────────────────────────────────────────────────────────┐
│                    DATA LAYER                               │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ PostgreSQL  │  │  ChromaDB    │  │     Redis         │  │
│  │             │  │              │  │                   │  │
│  │ - Scans     │  │ - Embeddings │  │ - Job Queue (RQ) │  │
│  │ - Vulns     │  │ - Vectors    │  │ - Caching        │  │
│  │ - Feeds     │  │ - RAG Index  │  │ - Sessions       │  │
│  └─────────────┘  └──────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
       ▲
       │
┌──────┴───────────────────────────────────────────────────┐
│         BACKGROUND WORKERS (RQ)                          │
│  - Scan Execution Tasks                                  │
│  - Threat Feed Update Tasks                              │
│  - AI Processing Tasks                                   │
└──────────────────────────────────────────────────────────┘
       ▲
       │
┌──────┴───────────────────────────────────────────────────┐
│         WSL KALI LINUX                                   │
│  Security Tools: Nmap, OpenVAS, Nikto, Nuclei           │
└──────────────────────────────────────────────────────────┘
```

### Request Flow Example

**User initiates a scan:**
1. Frontend sends POST `/api/scans` → Flask API
2. API validates request → Creates scan record in PostgreSQL
3. Scan job enqueued to Redis Queue (RQ)
4. RQ Worker picks up job → Executes via WSLHelper
5. WSL runs security tool (e.g., Nmap in Kali Linux)
6. Results parsed by adapter → Stored in PostgreSQL
7. WebSocket emits update → Frontend receives real-time notification
8. RAG system indexes results → Available for AI queries

---

## 🔧 Backend Deep Dive

### Directory Structure

```
backend/
├── api_gateway/           # Flask application & routing
│   ├── app.py            # Flask app factory
│   ├── websocket.py      # Socket.IO handlers
│   ├── health.py         # Health check endpoints
│   ├── scan_routes.py    # Scan management routes
│   ├── intelligence_routes.py  # AI chatbot routes
│   ├── auth_routes.py    # Authentication (currently disabled)
│   └── routes/           # Additional route modules
│       ├── feeds.py      # Threat feed routes
│       └── reports.py    # Report generation routes
│
├── services/             # Business logic layer
│   ├── adapters/        # Security tool integrations
│   │   ├── base_adapter.py      # Abstract base adapter
│   │   ├── nmap_adapter.py      # Nmap integration
│   │   ├── openvas_adapter.py   # OpenVAS integration
│   │   ├── nikto_adapter.py     # Nikto integration
│   │   └── nuclei_adapter.py    # Nuclei integration
│   │
│   ├── scan_orchestrator/      # Scan job management
│   │   ├── orchestrator.py     # RQ job orchestrator
│   │   └── tasks.py            # RQ worker tasks
│   │
│   ├── threat_feeds/           # Threat intelligence
│   │   ├── feed_manager.py     # Feed orchestration
│   │   ├── nvd_client.py       # NVD API client
│   │   ├── exploitdb_client.py # ExploitDB integration
│   │   └── feed_scheduler.py   # Automated updates
│   │
│   ├── export_service/         # Report generation
│   │   └── exporters/
│   │       ├── pdf_generator.py
│   │       └── excel_generator.py
│   │
│   └── reporting/              # Report templates
│
├── intelligence_layer/   # AI/RAG components
│   ├── rag/             # RAG pipeline
│   │   ├── chatbot.py           # RAG chatbot (Ollama)
│   │   ├── retrieval_engine.py  # Hybrid retrieval
│   │   ├── indexing.py          # ChromaDB indexing
│   │   ├── scan_processor.py    # Scan data preprocessing
│   │   └── ai_summary_generator.py  # AI summaries
│   │
│   └── models/          # AI data models
│
├── config/              # Configuration & models
│   ├── config.py       # App configuration classes
│   ├── database.py     # DB connection pool
│   └── models.py       # SQLAlchemy models
│
├── utils/              # Utility modules
│   ├── wsl_helper.py   # WSL command execution
│   ├── validation.py   # Input validation
│   ├── cors_config.py  # CORS configuration
│   └── error_handlers.py  # Error handling
│
├── evaluation/         # AI evaluation framework
│   ├── rag_evaluator.py
│   ├── dataset_loader.py
│   └── datasets/
│
├── alembic/           # Database migrations
├── tests/             # Unit & integration tests
├── requirements.txt   # Python dependencies
├── run_api.py        # API server entry point
└── start_worker.py   # RQ worker entry point
```

### Core Backend Components

#### 1. **Flask Application Factory** (`api_gateway/app.py`)

Creates and configures the Flask app with:
- **Rate Limiting**: Flask-Limiter (disabled in dev, Redis-backed in production)
- **CORS**: Environment-specific CORS policies
- **Metrics**: Prometheus counters for scans, API requests
- **API Documentation**: Swagger UI at `/api/docs`
- **Error Handling**: Centralized exception handling

```python
def create_app(config_name='development'):
    app = Flask(__name__)
    # Load config (Development/Production/Testing)
    # Initialize rate limiter with Redis
    # Configure CORS
    # Register blueprints (routes)
    # Initialize metrics
    return app
```

**Key Features:**
- Request body size limit: 16MB (DoS prevention)
- Health checks: `/health/ready`, `/health/live`
- Metrics endpoint: `/metrics` (Prometheus format)

#### 2. **Scan Orchestrator** (`services/scan_orchestrator/orchestrator.py`)

Manages asynchronous scan execution using Redis Queue:

```python
class ScanOrchestrator:
    def __init__(self, redis_host, redis_port):
        # Initialize Redis connection
        # Create RQ queues: high, default, low
        
    def enqueue_scan(self, scan_id, target, tool_name, options):
        # Validate scan parameters
        # Select appropriate adapter
        # Enqueue job to Redis queue
        # Return job_id for tracking
```

**Queue Priority System:**
- `high`: Critical scans (SLA < 5 min)
- `default`: Regular scans (SLA < 30 min)
- `low`: Bulk/scheduled scans (SLA < 2 hours)

**Worker Tasks** (`services/scan_orchestrator/tasks.py`):
```python
@job('default', timeout=3600)  # 1 hour timeout
def execute_scan(scan_id, target, tool_name, options):
    # 1. Update scan status to 'running'
    # 2. Initialize adapter (nmap/openvas/nikto/nuclei)
    # 3. Execute scan via WSL
    # 4. Parse results
    # 5. Store vulnerabilities in PostgreSQL
    # 6. Trigger AI indexing
    # 7. Emit WebSocket event
    # 8. Update scan status to 'completed'
```

#### 3. **Adapter Pattern** (`services/adapters/`)

All security tools implement the `BaseAdapter` interface:

```python
class BaseAdapter(ABC):
    @abstractmethod
    def get_tool_name() -> str
    
    @abstractmethod
    def build_command(target, scan_type, options) -> str
    
    @abstractmethod
    def parse_results(raw_output) -> dict
    
    def execute_scan(target, scan_type, options) -> ScanResult:
        # 1. Build command
        # 2. Execute via WSL
        # 3. Parse output
        # 4. Return ScanResult
```

**Example: Nmap Adapter**
```python
class NmapAdapter(BaseAdapter):
    def build_command(self, target, scan_type, options):
        cmd = f"nmap"
        if scan_type == "full":
            cmd += " -sV -sC -A -T4"
        elif scan_type == "quick":
            cmd += " -T5 -F"
        cmd += f" {target}"
        return cmd
    
    def parse_results(self, raw_output):
        # Parse XML/text output
        # Extract: hosts, ports, services, OS detection
        # Return structured dict
```

#### 4. **WSL Helper** (`utils/wsl_helper.py`)

Executes Linux security tools from Windows:

```python
class WSLHelper:
    def __init__(self, distribution="kali-linux"):
        self.distribution = distribution
        
    def execute_command(self, command, timeout=300):
        # Build WSL command: wsl -d kali-linux -- <command>
        # Execute with subprocess
        # Capture stdout/stderr
        # Handle timeouts
        # Return WSLCommandResult
        
    def check_tool_availability(self, tool_name):
        # Check if tool exists in WSL: which <tool>
```

**Why WSL?**
- Run Linux security tools natively on Windows
- No dual-boot or VM overhead
- Direct file system access
- Native performance

#### 5. **Threat Intelligence** (`services/threat_feeds/`)

**NVD Client** (`nvd_client.py`):
```python
class NVDClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def fetch_recent_cves(self, days=7):
        # Fetch CVEs published in last N days
        # Handle API rate limiting (with/without API key)
        # Parse JSON response
        # Return list of CVE entries
        
    def search_cve(self, cve_id):
        # Fetch specific CVE by ID
        # Extract: CVSS score, description, references
```

**ExploitDB Client** (`exploitdb_client.py`):
```python
class ExploitDBClient:
    def search_exploits(self, query):
        # Search exploit-db.com
        # Parse HTML results
        # Return exploit metadata
```

**Feed Manager** (`feed_manager.py`):
- Orchestrates feed updates
- Implements caching (24-hour TTL)
- Stores in PostgreSQL `feed_entries` table
- Scheduled via APScheduler

#### 6. **Real-time Updates** (`api_gateway/websocket.py`)

```python
socketio = SocketIO(app, cors_allowed_origins="*")

@socketio.on('connect')
def handle_connect():
    # Client connected
    
@socketio.on('subscribe_scan')
def handle_subscribe(scan_id):
    # Subscribe to scan updates
    join_room(f"scan_{scan_id}")

# Emit from worker:
socketio.emit('scan_update', {
    'scan_id': scan_id,
    'status': 'running',
    'progress': 45
}, room=f"scan_{scan_id}")
```

**Events:**
- `scan_update`: Scan progress/status changes
- `vulnerability_found`: New vulnerability detected
- `scan_completed`: Scan finished
- `feed_updated`: Threat feed refreshed

---

## 🎨 Frontend Deep Dive

### Directory Structure

```
frontend/
├── src/
│   ├── components/          # Reusable UI components
│   │   ├── Layout.tsx       # Main layout wrapper
│   │   ├── LoadingSpinner.tsx
│   │   ├── ErrorBoundary.tsx
│   │   └── ToastContainer.tsx
│   │
│   ├── pages/              # Route pages
│   │   ├── Dashboard.tsx        # Main dashboard
│   │   ├── ScanFormPage.tsx     # Create new scan
│   │   ├── ScansPage.tsx        # Scan list
│   │   ├── ScanDetailPage.tsx   # Scan results
│   │   ├── IntelligencePage.tsx # AI chatbot
│   │   ├── FeedsPage.tsx        # Threat feeds
│   │   ├── CVEDetailPage.tsx    # CVE details
│   │   ├── ReportsPage.tsx      # Report generation
│   │   └── SettingsPage.tsx     # Configuration
│   │
│   ├── App.tsx             # Root component & routing
│   ├── main.tsx            # Entry point
│   └── index.css           # Global styles (Tailwind)
│
├── public/                 # Static assets
├── vite.config.ts         # Vite configuration
├── tailwind.config.js     # Tailwind CSS config
├── tsconfig.json          # TypeScript config
└── package.json           # Dependencies

```

### Key Frontend Patterns

#### 1. **Routing** (`App.tsx`)

```tsx
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';

function App() {
  return (
    <ToastProvider>
      <Router>
        <ErrorBoundary>
          <Layout>
            <Suspense fallback={<LoadingSpinner />}>
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/scan/new" element={<ScanFormPage />} />
                <Route path="/scans" element={<ScansPage />} />
                <Route path="/scans/:scanId" element={<ScanDetailPage />} />
                <Route path="/intelligence" element={<IntelligencePage />} />
                <Route path="/feeds" element={<FeedsPage />} />
                <Route path="/feeds/cve/:cveId" element={<CVEDetailPage />} />
                <Route path="/reports" element={<ReportsPage />} />
              </Routes>
            </Suspense>
          </Layout>
        </ErrorBoundary>
      </Router>
    </ToastProvider>
  );
}
```

**Features:**
- Lazy loading for code splitting
- Error boundary for crash handling
- Toast notifications for user feedback
- Centralized layout component

#### 2. **API Communication**

**HTTP Requests (Axios):**
```tsx
import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  timeout: 30000
});

// Create scan
const createScan = async (scanData) => {
  const response = await api.post('/scans', scanData);
  return response.data;
};

// Fetch scans
const getScans = async () => {
  const response = await api.get('/scans');
  return response.data;
};
```

**WebSocket (Socket.IO):**
```tsx
import { io } from 'socket.io-client';

const socket = io('http://localhost:5000');

// Subscribe to scan updates
socket.emit('subscribe_scan', scanId);

socket.on('scan_update', (data) => {
  // Update UI with real-time progress
  setScanStatus(data.status);
  setProgress(data.progress);
});
```

#### 3. **State Management**

Uses **React hooks** (no Redux):
- `useState`: Component-level state
- `useEffect`: Side effects (API calls, subscriptions)
- `useContext`: Theme, toast notifications

Example:
```tsx
const [scans, setScans] = useState([]);
const [loading, setLoading] = useState(true);

useEffect(() => {
  fetchScans()
    .then(data => setScans(data))
    .finally(() => setLoading(false));
}, []);
```

#### 4. **UI Components** (Tailwind CSS)

```tsx
// Severity badge
const SeverityBadge = ({ severity }) => {
  const colors = {
    critical: 'bg-red-100 text-red-800',
    high: 'bg-orange-100 text-orange-800',
    medium: 'bg-yellow-100 text-yellow-800',
    low: 'bg-blue-100 text-blue-800'
  };
  
  return (
    <span className={`px-2 py-1 rounded ${colors[severity]}`}>
      {severity.toUpperCase()}
    </span>
  );
};
```

#### 5. **Build Optimization** (`vite.config.ts`)

```typescript
export default defineConfig({
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          'react-vendor': ['react', 'react-dom'],
          'router-vendor': ['react-router-dom'],
          'chart-vendor': ['recharts'],
          'http-vendor': ['axios', 'socket.io-client']
        }
      }
    }
  },
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true
      }
    }
  }
});
```

**Benefits:**
- Code splitting for faster loads
- Vendor chunk caching
- Development proxy for CORS-free API calls

---

## 🤖 Intelligence Layer (AI/RAG)

### What is RAG?

**Retrieval-Augmented Generation** combines:
1. **Retrieval**: Search relevant documents from knowledge base
2. **Augmentation**: Add retrieved context to user query
3. **Generation**: LLM generates answer based on context

### Architecture

```
User Query: "What is CVE-2024-1234?"
     │
     ▼
┌─────────────────────────────────────┐
│  Retrieval Engine                   │
│  1. Convert query to embedding      │
│  2. Search ChromaDB vector store    │
│  3. Retrieve top-5 relevant docs    │
└──────────────┬──────────────────────┘
               │
               ▼
         Context Documents
      (CVE data, scan results)
               │
               ▼
┌─────────────────────────────────────┐
│  RAG Chatbot                        │
│  1. Build prompt with context       │
│  2. Call Ollama LLM (Llama 3.2 3B)  │
│  3. Generate contextual answer      │
│  4. Verify citations (anti-halluc.) │
└──────────────┬──────────────────────┘
               │
               ▼
     AI-Generated Answer
   (with source citations)
```

### Components

#### 1. **Embedding Service** (`intelligence_layer/rag/indexing.py`)

```python
from sentence_transformers import SentenceTransformer

class EmbeddingService:
    def __init__(self):
        # Use all-MiniLM-L6-v2 (384 dimensions, fast)
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        
    def embed_text(self, text):
        return self.model.encode(text)
```

#### 2. **ChromaDB Indexing** (`intelligence_layer/rag/indexing.py`)

```python
import chromadb

class ChromaIndexer:
    def __init__(self, persist_directory="chroma_db"):
        self.client = chromadb.PersistentClient(path=persist_directory)
        self.collection = self.client.get_or_create_collection("vulnerabilities")
        
    def index_scan_results(self, scan_id, vulnerabilities):
        # Convert vulnerabilities to documents
        documents = []
        metadatas = []
        ids = []
        
        for vuln in vulnerabilities:
            doc = f"{vuln['title']} {vuln['description']}"
            documents.append(doc)
            metadatas.append({
                'scan_id': scan_id,
                'severity': vuln['severity'],
                'cve_id': vuln.get('cve_id')
            })
            ids.append(str(vuln['vuln_id']))
            
        # Add to ChromaDB (auto-embeds with default model)
        self.collection.add(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )
```

#### 3. **Retrieval Engine** (`intelligence_layer/rag/retrieval_engine.py`)

```python
class RAGRetrievalEngine:
    def __init__(self, chroma_indexer, postgres_session):
        self.chroma = chroma_indexer
        self.db = postgres_session
        
    def hybrid_retrieve(self, query, top_k=5):
        # Vector search in ChromaDB
        vector_results = self.chroma.collection.query(
            query_texts=[query],
            n_results=top_k
        )
        
        # Keyword search in PostgreSQL
        keyword_results = self.db.query(FeedEntry).filter(
            FeedEntry.description.ilike(f"%{query}%")
        ).limit(top_k).all()
        
        # Merge and re-rank results
        return self._merge_results(vector_results, keyword_results)
```

**Hybrid Retrieval Strategy:**
- **Vector Search**: Semantic similarity (ChromaDB)
- **Keyword Search**: Exact matches (PostgreSQL)
- **BM25**: Relevance ranking
- **Re-ranking**: Combine scores

#### 4. **RAG Chatbot** (`intelligence_layer/rag/chatbot.py`)

```python
class RAGChatbot:
    def __init__(self, retrieval_engine, ollama_url="http://localhost:11434"):
        self.retrieval_engine = retrieval_engine
        self.ollama_url = ollama_url
        self.model_name = "llama3.2:3b-instruct-q4_K_M"
        
    def chat(self, user_query, session_id=None):
        # 1. Retrieve relevant context
        context_docs = self.retrieval_engine.hybrid_retrieve(user_query, top_k=5)
        
        # 2. Build prompt
        prompt = self._build_prompt(user_query, context_docs)
        
        # 3. Call Ollama LLM
        response = requests.post(f"{self.ollama_url}/api/generate", json={
            "model": self.model_name,
            "prompt": prompt,
            "temperature": 0.3,  # Low temp = factual
            "max_tokens": 512
        })
        
        # 4. Parse and verify response
        answer = response.json()['response']
        verified_answer = self._verify_citations(answer, context_docs)
        
        return {
            "answer": verified_answer,
            "sources": context_docs,
            "confidence": self._calculate_confidence(answer, context_docs)
        }
        
    def _build_prompt(self, query, context_docs):
        context_str = "\n\n".join([doc['text'] for doc in context_docs])
        
        return f"""You are a cybersecurity expert assistant. Answer the user's question based on the provided vulnerability data.

Context (vulnerability database):
{context_str}

User Question: {query}

Instructions:
- Answer based ONLY on the provided context
- Cite specific CVE IDs when relevant
- If context doesn't contain the answer, say "I don't have enough information"
- Be concise and accurate

Answer:"""
```

**Anti-Hallucination Techniques:**
1. **Low temperature** (0.3) = more deterministic
2. **Explicit instructions** = "answer based ONLY on context"
3. **Citation verification** = check if mentioned CVEs exist in context
4. **Confidence scoring** = measure overlap between answer and sources

#### 5. **Local LLM (Ollama)**

**Why Ollama?**
- **No API costs** (runs locally)
- **Privacy** (data never leaves your infrastructure)
- **Fast** (GPU-accelerated)
- **Flexible** (swap models easily)

**Model: Llama 3.2 3B Instruct**
- Size: ~2GB
- Speed: ~30 tokens/sec on CPU, ~100 on GPU
- Quality: Good for factual Q&A
- Quantization: Q4_K_M (4-bit for speed)

**Installation:**
```powershell
# Install Ollama
winget install Ollama.Ollama

# Pull model
ollama pull llama3.2:3b-instruct-q4_K_M

# Start server
ollama serve  # Runs on http://localhost:11434
```

#### 6. **Attack Path Modeling** (`intelligence_layer/models/`)

Uses **NetworkX** for graph-based attack path discovery:

```python
import networkx as nx

class AttackPathGraph:
    def __init__(self):
        self.graph = nx.DiGraph()
        
    def build_from_scan(self, scan_results):
        # Nodes: hosts, vulnerabilities, services
        for host in scan_results['hosts']:
            self.graph.add_node(host['ip'], type='host')
            
            for vuln in host['vulnerabilities']:
                vuln_node = f"vuln_{vuln['cve_id']}"
                self.graph.add_node(vuln_node, type='vulnerability', severity=vuln['severity'])
                self.graph.add_edge(host['ip'], vuln_node, type='affects')
                
                # Check for exploits
                if vuln['exploit_available']:
                    self.graph.add_edge(vuln_node, host['ip'], type='exploit_path')
                    
    def find_attack_paths(self, source, target):
        # Find all paths from source to target
        paths = nx.all_simple_paths(self.graph, source, target)
        
        # Rank by severity
        ranked_paths = []
        for path in paths:
            severity_score = self._calculate_path_severity(path)
            ranked_paths.append((path, severity_score))
            
        return sorted(ranked_paths, key=lambda x: x[1], reverse=True)
```

**Use Cases:**
- Find exploitation chains (multi-hop attacks)
- Identify critical nodes (highest risk)
- Recommend mitigation priorities

---

## 🗄️ Database Schema

### PostgreSQL Tables

#### 1. **scans**

Stores scan metadata and execution status.

```sql
CREATE TABLE scans (
    id VARCHAR(36) PRIMARY KEY,              -- UUID
    target VARCHAR(255) NOT NULL,            -- IP/hostname/CIDR
    tool_name VARCHAR(50) NOT NULL,          -- nmap/openvas/nikto/nuclei
    scan_type VARCHAR(50) NOT NULL,          -- basic/full/quick/custom
    status VARCHAR(50) DEFAULT 'pending',    -- pending/queued/running/completed/failed
    priority VARCHAR(20) DEFAULT 'medium',   -- high/medium/low
    created_at TIMESTAMP DEFAULT NOW(),
    queued_at TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT,
    job_id VARCHAR(100),                     -- RQ job ID
    options JSON,                            -- Tool-specific options
    tags JSON                                -- User-defined tags
);

CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created_at ON scans(created_at);
CREATE INDEX idx_scans_tool ON scans(tool_name);
```

**Status Flow:**
`pending` → `queued` → `running` → `completed`/`failed`

#### 2. **vulnerabilities**

Stores discovered vulnerabilities from scans.

```sql
CREATE TABLE vulnerabilities (
    vuln_id UUID PRIMARY KEY,
    scan_id VARCHAR(36) REFERENCES scans(id) ON DELETE CASCADE,
    severity VARCHAR(20) NOT NULL,           -- critical/high/medium/low/info
    title VARCHAR(255) NOT NULL,
    description TEXT,
    cvss_score DECIMAL(3,1),                 -- 0.0 to 10.0
    cve_id VARCHAR(50),                      -- CVE-2024-1234
    port INTEGER,
    protocol VARCHAR(10),                    -- tcp/udp
    service VARCHAR(100),                    -- ssh/http/mysql
    solution TEXT,
    references JSON,                         -- URLs to advisories
    discovered_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_vuln_scan_id ON vulnerabilities(scan_id);
CREATE INDEX idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX idx_vuln_cve_id ON vulnerabilities(cve_id);
```

#### 3. **feed_entries**

Threat intelligence from NVD, ExploitDB, etc.

```sql
CREATE TABLE feed_entries (
    id UUID PRIMARY KEY,
    feed_source VARCHAR(50) NOT NULL,        -- nvd/exploitdb/rapid7
    feed_type VARCHAR(50) NOT NULL,          -- cve/exploit/advisory
    entry_id VARCHAR(100) NOT NULL,          -- CVE-2024-1234, EDB-12345
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20),
    cvss_score DECIMAL(3,1),
    cvss_vector VARCHAR(200),
    affected_products TEXT[],                -- Array of products
    cwe_ids TEXT[],                          -- Array of CWE IDs
    ref_urls TEXT[],                         -- Array of URLs
    exploit_available VARCHAR(10),           -- yes/no/unknown
    exploit_type VARCHAR(50),
    exploit_platform VARCHAR(50),
    published_date TIMESTAMP,
    modified_date TIMESTAMP,
    metadata JSON,                           -- Additional feed-specific data
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_feed_source_type ON feed_entries(feed_source, feed_type);
CREATE INDEX idx_feed_entry_id ON feed_entries(entry_id);
CREATE INDEX idx_feed_severity ON feed_entries(severity);
CREATE INDEX idx_feed_published ON feed_entries(published_date);
```

**Data Volume:**
- ~200k CVEs from NVD
- ~50k exploits from ExploitDB
- Updated daily via scheduled tasks

### ChromaDB Collections

**Collection: `vulnerabilities`**

```python
{
    "id": "vuln_uuid",
    "document": "SQL Injection vulnerability in login.php",
    "metadata": {
        "scan_id": "scan_123",
        "severity": "high",
        "cve_id": "CVE-2024-1234",
        "cvss_score": 8.5
    },
    "embedding": [0.123, -0.456, ...]  # 384-dim vector
}
```

**Why ChromaDB + PostgreSQL?**
- **PostgreSQL**: Structured data, ACID compliance, complex queries
- **ChromaDB**: Vector search, semantic similarity, fast retrieval
- **Best of both**: Keyword + semantic search (hybrid)

---

## 🔧 Security Tools Integration

### WSL Architecture

```
Windows Host
    │
    ├── Python Backend (Flask)
    │   └── WSLHelper.execute_command()
    │
    ▼
wsl -d kali-linux -- <command>
    │
    ▼
WSL Kali Linux
    │
    ├── Nmap (network scanner)
    ├── OpenVAS (vulnerability scanner)
    ├── Nikto (web scanner)
    └── Nuclei (template scanner)
    │
    ▼
Scan Results (XML/JSON/Text)
    │
    ▼
Adapter.parse_results()
    │
    ▼
PostgreSQL + ChromaDB
```

### Tool Capabilities

#### 1. **Nmap** - Network Discovery & Port Scanning

**Capabilities:**
- Host discovery (ping sweeps)
- Port scanning (TCP/UDP)
- Service/version detection
- OS fingerprinting
- NSE scripts (vulnerability checks)

**Scan Types:**
```python
scan_types = {
    'quick': '-T5 -F',                    # Fast, top 100 ports
    'basic': '-sV -sC',                   # Version + default scripts
    'full': '-sV -sC -A -T4 -p-',        # All ports, aggressive
    'stealth': '-sS -T2 -f',             # SYN scan, slow, fragmented
}
```

**Output Parsing:**
```python
def parse_nmap_xml(xml_output):
    # Extract:
    # - Open ports (22/tcp, 80/tcp)
    # - Services (OpenSSH 7.4, Apache 2.4.6)
    # - OS detection (Linux 3.x)
    # - NSE script results (CVEs, vulnerabilities)
```

#### 2. **OpenVAS** - Comprehensive Vulnerability Scanner

**Capabilities:**
- 50,000+ vulnerability tests (NVTs)
- Authenticated vs unauthenticated scans
- Compliance checks (PCI DSS, HIPAA)
- Detailed remediation guidance

**Scan Flow:**
```
1. Create target in GVM
2. Create scan task
3. Start task
4. Poll for completion (async)
5. Export report (XML)
6. Parse NVTs (vulnerabilities)
```

**Integration:**
```python
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp

class OpenVASAdapter(BaseAdapter):
    def execute_scan(self, target, options):
        connection = UnixSocketConnection()
        with Gmp(connection) as gmp:
            gmp.authenticate(username, password)
            
            # Create target
            target_id = gmp.create_target(name, hosts=target)
            
            # Create and start task
            task_id = gmp.create_task(name, target_id, scanner_id)
            gmp.start_task(task_id)
            
            # Wait for completion
            while True:
                status = gmp.get_task(task_id)
                if status == 'Done':
                    break
                time.sleep(30)
                
            # Get report
            report = gmp.get_report(task_id)
            return self.parse_results(report)
```

#### 3. **Nikto** - Web Server Scanner

**Capabilities:**
- 6,700+ vulnerability tests
- Server misconfiguration detection
- Dangerous files/programs
- Outdated software detection
- SSL/TLS testing

**Example Command:**
```bash
nikto -h https://example.com -output scan.json -Format json
```

**Parses:**
- OSVDB IDs
- HTTP methods allowed
- Server headers
- Directory listings
- SSL certificate issues

#### 4. **Nuclei** - Template-Based Scanner

**Capabilities:**
- 4,000+ YAML templates
- CVE detection
- Misconfigurations
- Exposed panels/APIs
- Custom template support

**Example:**
```bash
nuclei -u https://example.com -t cves/ -json -o results.json
```

**Templates:**
```yaml
id: CVE-2024-1234
info:
  name: Example Vulnerability
  severity: high
requests:
  - method: GET
    path:
      - "{{BaseURL}}/vulnerable-endpoint"
    matchers:
      - type: word
        words:
          - "error_signature"
```

---

## 🐳 DevOps & Infrastructure

### Docker Compose Services

```yaml
services:
  # PostgreSQL Database
  postgres:
    image: postgres:14-alpine
    environment:
      POSTGRES_DB: vulnerability_scanner
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      
  # Redis (Queue + Cache)
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      
  # API Gateway
  api_gateway:
    build: .
    environment:
      DATABASE_URL: postgresql://postgres@postgres:5432/vulnerability_scanner
      REDIS_HOST: redis
    ports:
      - "5000:5000"
    depends_on:
      - postgres
      - redis
    command: python run_api.py
    
  # RQ Worker
  worker:
    build: .
    environment:
      DATABASE_URL: postgresql://postgres@postgres:5432/vulnerability_scanner
      REDIS_HOST: redis
    depends_on:
      - postgres
      - redis
    command: rq worker --url redis://redis:6379 high default low
    
  # RQ Dashboard (Monitoring)
  rq_dashboard:
    image: eoranged/rq-dashboard:latest
    environment:
      RQ_DASHBOARD_REDIS_URL: redis://redis:6379
    ports:
      - "9181:9181"
```

### Deployment Modes

#### Development
```powershell
# Backend
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run_api.py

# Frontend
cd frontend
npm install
npm run dev

# Worker
python start_worker.py
```

#### Production (Docker)
```bash
docker-compose up -d
```

**Scaling Workers:**
```bash
docker-compose up -d --scale worker=5
```

### Monitoring

**Prometheus Metrics:**
- `scans_total{tool="nmap", status="completed"}`
- `scan_duration_seconds{tool="openvas"}`
- `api_requests_total{method="POST", endpoint="/scans"}`
- `api_request_duration_seconds`

**RQ Dashboard:**
- Queue sizes (high/default/low)
- Worker status
- Failed jobs
- Job execution times

**Health Checks:**
- `/health/live`: Service is running
- `/health/ready`: Database + Redis connected

---

## 🧪 Evaluation & Testing

### AI Evaluation Framework

Located in `backend/evaluation/`

**Metrics Measured:**

#### 1. **RAG Chatbot Quality**

```python
# BLEU Score (N-gram overlap)
from nltk.translate.bleu_score import sentence_bleu

bleu_score = sentence_bleu(
    [reference_answer.split()],  # Reference
    generated_answer.split(),     # Hypothesis
    weights=(0.5, 0.5, 0, 0)     # Bigram focus
)
# Target: > 40

# ROUGE-L (Longest Common Subsequence)
from rouge_score import rouge_scorer

scorer = rouge_scorer.RougeScorer(['rougeL'], use_stemmer=True)
rouge_l = scorer.score(reference_answer, generated_answer)['rougeL'].fmeasure
# Target: > 0.6

# Hallucination Rate
hallucination_detected = check_fake_cves(generated_answer, context_docs)
# Target: < 5%

# Precision@5 (Retrieval Accuracy)
relevant_in_top5 = count_relevant(retrieved_docs[:5], ground_truth)
precision_at_5 = relevant_in_top5 / 5
# Target: > 80%
```

#### 2. **Attack Path Modeling**

```python
# Graph Build Time
start = time.time()
graph = AttackPathGraph()
graph.build_from_scan(scan_results)
build_time = time.time() - start
# Target: < 5 seconds for 100 hosts

# F1 Score (Path Discovery Accuracy)
predicted_paths = graph.find_attack_paths(source, target)
f1 = calculate_f1(predicted_paths, ground_truth_paths)
# Target: > 0.85

# Spearman Correlation (Mitigation Ranking)
from scipy.stats import spearmanr

correlation = spearmanr(predicted_ranks, expert_ranks)
# Target: > 0.7
```

**Test Datasets:**

`evaluation/datasets/qa_pairs.json`:
```json
[
  {
    "query": "What is CVE-2024-1234?",
    "reference_answer": "CVE-2024-1234 is a SQL injection vulnerability...",
    "relevant_cves": ["CVE-2024-1234"]
  }
]
```

**Running Evaluations:**
```powershell
cd backend
python -m evaluation.run_all_evals

# Output:
# ✅ BLEU Score: 45.23 / 100 (Target: > 40) PASS
# ✅ ROUGE-L: 0.678 (Target: > 0.6) PASS
# ✅ Hallucination Rate: 0.0% (Target: < 5%) PASS
```

### Unit Tests

Located in `backend/tests/`

**Test Coverage:**
- Adapter tests (`test_all_adapters.py`)
- API endpoint tests (`test_api_response_format.py`)
- CVE endpoint tests (`test_cve_endpoint.py`)
- Threat intel tests (`test_threat_intel_features.py`)

**Running Tests:**
```powershell
pytest
pytest --cov=. --cov-report=html  # With coverage
```

**Test Structure:**
```python
def test_nmap_adapter():
    adapter = NmapAdapter(wsl_helper)
    
    # Mock WSL execution
    with patch.object(wsl_helper, 'execute_command') as mock_exec:
        mock_exec.return_value = WSLCommandResult(
            success=True,
            stdout=nmap_sample_output,
            stderr='',
            return_code=0
        )
        
        result = adapter.execute_scan('192.168.1.1', 'quick', {})
        
        assert result.success == True
        assert len(result.parsed_output['hosts']) > 0
```

---

## 🔄 Workflow & Data Flow

### Complete Scan Lifecycle

```
┌─────────────────────────────────────────────────────────────┐
│  USER INITIATES SCAN (Frontend)                             │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  API Gateway (Flask)                                        │
│  POST /api/scans                                            │
│  - Validate input (target, tool, options)                   │
│  - Create scan record in PostgreSQL (status: pending)       │
│  - Return scan_id to frontend                               │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Scan Orchestrator                                          │
│  - Build job payload                                        │
│  - Enqueue to Redis Queue (RQ)                              │
│  - Update scan status: queued                               │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  RQ Worker (Background Process)                             │
│  - Pick job from queue                                      │
│  - Update scan status: running                              │
│  - Emit WebSocket: {"status": "running"}                    │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Adapter Execution                                          │
│  1. Select adapter (NmapAdapter, OpenVASAdapter, etc.)      │
│  2. Build command: "nmap -sV -sC 192.168.1.1"              │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  WSL Helper                                                 │
│  - Execute: wsl -d kali-linux -- nmap -sV -sC 192.168.1.1  │
│  - Capture stdout/stderr                                    │
│  - Handle timeouts (default: 300s)                          │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  WSL Kali Linux                                             │
│  - Run Nmap                                                 │
│  - Scan network                                             │
│  - Return results (XML/text)                                │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Result Parsing                                             │
│  - Adapter.parse_results(raw_output)                        │
│  - Extract: hosts, ports, services, vulnerabilities         │
│  - Normalize to standard format                             │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Data Storage                                               │
│  - Insert vulnerabilities into PostgreSQL                   │
│  - Update scan: status=completed, completed_at=now()        │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  AI Indexing (Async)                                        │
│  - Convert vulnerabilities to text documents                │
│  - Generate embeddings (Sentence Transformers)              │
│  - Index in ChromaDB for RAG retrieval                      │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  WebSocket Notification                                     │
│  - Emit: {"scan_id": "123", "status": "completed"}          │
│  - Frontend receives update                                 │
│  - UI refreshes automatically                               │
└─────────────────────────────────────────────────────────────┘
```

### Threat Feed Update Workflow

```
┌─────────────────────────────────────────────────────────────┐
│  APScheduler (Every 24 hours)                               │
│  - Trigger feed update job                                  │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Feed Manager                                               │
│  - Check cache age (data/threat_feeds/*.json)               │
│  - If stale (>24h), fetch new data                          │
└───────────────────────┬─────────────────────────────────────┘
                        │
              ┌─────────┴─────────┐
              ▼                   ▼
    ┌──────────────────┐  ┌──────────────────┐
    │  NVD Client      │  │  ExploitDB Client│
    │  - API call      │  │  - Web scraping  │
    │  - Parse JSON    │  │  - Parse HTML    │
    └────────┬─────────┘  └────────┬─────────┘
             │                     │
             └──────────┬──────────┘
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Database Storage                                           │
│  - Upsert to feed_entries table                             │
│  - Update modified_date if exists                           │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  ChromaDB Indexing                                          │
│  - Index new CVEs for RAG retrieval                         │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  WebSocket Broadcast                                        │
│  - Notify connected clients: "feed_updated"                 │
└─────────────────────────────────────────────────────────────┘
```

### RAG Query Flow

```
User asks: "What is CVE-2024-1234?"
             │
             ▼
┌─────────────────────────────────────────────────────────────┐
│  Frontend sends: POST /api/intelligence/chat                │
│  Body: {"query": "What is CVE-2024-1234?"}                  │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  RAGChatbot.chat()                                          │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Retrieval Engine                                           │
│  1. Embed query: [0.123, -0.456, ...]                      │
│  2. Search ChromaDB: top 5 similar docs                     │
│  3. Search PostgreSQL: keyword match "CVE-2024-1234"        │
│  4. Merge results (hybrid retrieval)                        │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
              Context Documents:
              - CVE-2024-1234 description
              - Related vulnerabilities
              - Scan results mentioning this CVE
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Build RAG Prompt                                           │
│  Context: [documents]                                       │
│  Question: What is CVE-2024-1234?                           │
│  Instructions: Answer based on context only                 │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Ollama LLM (Llama 3.2 3B)                                  │
│  - Generate answer from context                             │
│  - Temperature: 0.3 (factual)                               │
│  - Max tokens: 512                                          │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Post-Processing                                            │
│  - Verify citations (check CVE IDs exist in context)        │
│  - Calculate confidence score                               │
│  - Format sources                                           │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Return Response                                            │
│  {                                                          │
│    "answer": "CVE-2024-1234 is a SQL injection...",        │
│    "sources": [...],                                        │
│    "confidence": 0.92                                       │
│  }                                                          │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
           Frontend displays answer with sources
```

---

## ⚙️ Configuration & Environment

### Environment Variables

**Backend** (`.env`):
```bash
# Database
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/vulnerability_scanner
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=vulnerability_scanner
POSTGRES_PORT=5432

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_URL=redis://localhost:6379/0

# Flask
FLASK_ENV=development
FLASK_DEBUG=1
API_PORT=5000

# Security Tools (WSL)
WSL_DISTRIBUTION=kali-linux
SCAN_TIMEOUT=3600

# Threat Feeds
NVD_API_KEY=your_nvd_api_key_here  # Optional, increases rate limit
EXPLOITDB_UPDATE_INTERVAL=86400     # 24 hours

# AI/LLM
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2:3b-instruct-q4_K_M
CHROMA_DB_PATH=./chroma_db

# Monitoring
PROMETHEUS_ENABLED=true
RQ_DASHBOARD_PORT=9181
```

**Frontend** (Vite proxy in `vite.config.ts`):
```typescript
server: {
  proxy: {
    '/api': {
      target: 'http://localhost:5000',
      changeOrigin: true
    }
  }
}
```

### Configuration Classes

**Backend** (`config/config.py`):
```python
class Config:
    """Base configuration"""
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')
    REDIS_URL = os.getenv('REDIS_URL')
    
class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = False
    
class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    # Additional production settings
    
class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
```

---

## 🎯 Key Features

### 1. **Unified Scanning Interface**
- Single UI for multiple tools (Nmap, OpenVAS, Nikto, Nuclei)
- Consistent result format across all tools
- Centralized scan history and management

### 2. **Real-Time Updates**
- WebSocket push notifications
- Live scan progress tracking
- Instant vulnerability alerts

### 3. **AI-Powered Intelligence**
- Natural language queries about vulnerabilities
- RAG-based chatbot (no hallucinations)
- Automated vulnerability summarization
- Attack path discovery

### 4. **Threat Intelligence Integration**
- Automatic CVE correlation
- Exploit availability checking
- Real-time threat feed updates (NVD, ExploitDB)

### 5. **Comprehensive Reporting**
- PDF reports with executive summaries
- Excel exports for analysis
- Customizable report templates
- Scheduled report generation

### 6. **Scalable Architecture**
- Async task processing (RQ)
- Horizontal worker scaling
- Redis-backed job queue
- Connection pooling for DB

### 7. **Security Features**
- Input validation and sanitization
- Rate limiting (production)
- CORS policies
- Request size limits
- Health checks for monitoring

---

## 👨‍💻 Development Guidelines

### Getting Started

#### Prerequisites
1. **Windows with WSL2** + Kali Linux distribution
2. **Python 3.9+**
3. **Node.js 18+**
4. **PostgreSQL 14+**
5. **Redis 7+**
6. **Ollama** (for AI features)

#### Initial Setup

**1. Clone and Setup Backend:**
```powershell
cd backend

# Create virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Setup database
python manage_migrations.py init
python manage_migrations.py migrate

# Install security tools in WSL
wsl -d kali-linux -- sudo apt update
wsl -d kali-linux -- sudo apt install nmap nikto nuclei openvas -y
```

**2. Setup Frontend:**
```powershell
cd frontend
npm install
```

**3. Setup Ollama (AI features):**
```powershell
# Install
winget install Ollama.Ollama

# Pull model
ollama pull llama3.2:3b-instruct-q4_K_M

# Start server
ollama serve
```

**4. Start Services:**
```powershell
# Terminal 1: PostgreSQL + Redis (Docker)
docker-compose up postgres redis

# Terminal 2: Backend API
cd backend
.\venv\Scripts\Activate.ps1
python run_api.py

# Terminal 3: RQ Worker
cd backend
.\venv\Scripts\Activate.ps1
python start_worker.py

# Terminal 4: Frontend
cd frontend
npm run dev
```

**5. Access Application:**
- Frontend: http://localhost:5173
- Backend API: http://localhost:5000
- API Docs: http://localhost:5000/api/docs
- RQ Dashboard: http://localhost:9181

### Project Commands

```powershell
# Backend
python run_api.py                    # Start API server
python start_worker.py               # Start RQ worker
python -m pytest                     # Run tests
python -m pytest --cov               # Test coverage

# Database
python manage_migrations.py init     # Initialize Alembic
python manage_migrations.py migrate  # Run migrations
python manage_migrations.py rollback # Rollback migration

# Frontend
npm run dev                          # Dev server (hot reload)
npm run build                        # Production build
npm run preview                      # Preview production build
npm run lint                         # ESLint

# AI Evaluation
cd backend/evaluation
python run_all_evals.py             # Run full evaluation suite
python run_basic_evals.py           # Quick evaluation
```

### Code Style Guidelines

**Python (Backend):**
- **PEP 8** compliance
- **Type hints** for function signatures
- **Docstrings** for all classes/methods (Google style)
- **Black** formatter (automated)
- **Flake8** linter
- **mypy** for type checking

Example:
```python
def execute_scan(
    target: str,
    scan_type: str,
    options: Dict[str, Any]
) -> ScanResult:
    """
    Execute security scan on target.
    
    Args:
        target: IP address, hostname, or CIDR range
        scan_type: Type of scan (basic, full, quick, custom)
        options: Tool-specific configuration options
        
    Returns:
        ScanResult object with parsed vulnerabilities
        
    Raises:
        ValidationError: If target format is invalid
        TimeoutError: If scan exceeds timeout limit
    """
    # Implementation
```

**TypeScript (Frontend):**
- **ESLint** + **Prettier**
- **Functional components** with hooks
- **Props interfaces** for all components
- **Named exports** preferred

Example:
```typescript
interface ScanCardProps {
  scan: Scan;
  onDelete: (scanId: string) => void;
}

export const ScanCard: React.FC<ScanCardProps> = ({ scan, onDelete }) => {
  return (
    <div className="p-4 border rounded">
      {/* Component JSX */}
    </div>
  );
};
```

### Database Migrations

**Creating a Migration:**
```powershell
# After modifying models.py
cd backend
python manage_migrations.py migrate

# Generates: alembic/versions/<hash>_description.py
```

**Migration File Structure:**
```python
def upgrade():
    # SQL to apply changes
    op.add_column('scans', sa.Column('new_field', sa.String(50)))
    
def downgrade():
    # SQL to rollback
    op.drop_column('scans', 'new_field')
```

### Testing Strategy

**Unit Tests:**
- Test individual adapters
- Mock WSL commands
- Verify parsing logic

**Integration Tests:**
- Test API endpoints
- Verify database operations
- Check WebSocket events

**AI Evaluation:**
- BLEU/ROUGE scores
- Hallucination detection
- Retrieval precision

### Common Development Tasks

#### Adding a New Security Tool

1. **Create Adapter:**
```python
# backend/services/adapters/mytool_adapter.py
from services.adapters.base_adapter import BaseAdapter, ScanResult

class MyToolAdapter(BaseAdapter):
    def get_tool_name(self) -> str:
        return "mytool"
        
    def build_command(self, target, scan_type, options) -> str:
        return f"mytool scan {target}"
        
    def parse_results(self, raw_output) -> dict:
        # Parse tool output
        return {"vulnerabilities": [...]}
```

2. **Register in Orchestrator:**
```python
# backend/services/scan_orchestrator/orchestrator.py
ADAPTER_MAP = {
    'nmap': NmapAdapter,
    'mytool': MyToolAdapter,  # Add here
}
```

3. **Add Tests:**
```python
# backend/tests/test_mytool_adapter.py
def test_mytool_execution():
    adapter = MyToolAdapter(wsl_helper)
    result = adapter.execute_scan('192.168.1.1', 'basic', {})
    assert result.success
```

#### Adding a New API Endpoint

1. **Create Route:**
```python
# backend/api_gateway/routes/myroute.py
from flask import Blueprint, jsonify, request

bp = Blueprint('myroute', __name__, url_prefix='/api/myroute')

@bp.route('/', methods=['GET'])
def get_items():
    # Implementation
    return jsonify({"items": []})
```

2. **Register Blueprint:**
```python
# backend/api_gateway/app.py
from api_gateway.routes import myroute

app.register_blueprint(myroute.bp)
```

3. **Add Frontend Service:**
```typescript
// frontend/src/services/myService.ts
export const getItems = async () => {
  const response = await axios.get('/api/myroute');
  return response.data;
};
```

---

## 📚 Additional Resources

### Documentation Files

| File | Description |
|------|-------------|
| `backend/ERROR_HANDLING_GUIDE.md` | Error handling patterns |
| `backend/MIGRATIONS.md` | Database migration guide |
| `backend/intelligence_layer/README.md` | AI layer documentation |
| `backend/evaluation/README.md` | Evaluation framework guide |
| `docs/intelligence_layer/LLM_SELECTION_REPORT.md` | LLM evaluation research |
| `docs/intelligence_layer/RAG_PIPELINE_DESIGN.md` | RAG architecture details |
| `docs/intelligence_layer/ATTACK_PATH_GRAPH_MODEL.md` | Attack path modeling |

### Key Directories

```
ESP/
├── backend/              # Python backend
├── frontend/             # React frontend
├── docs/                 # Project documentation
├── data/                 # Data files (threat feeds)
├── chroma_db/            # Vector database storage
├── reports/              # Generated reports
└── temp/                 # Temporary files
```

### External APIs Used

1. **NVD (National Vulnerability Database)**
   - URL: https://services.nvd.nist.gov/rest/json/cves/2.0
   - Rate Limit: 5 req/30s (no key), 50 req/30s (with key)
   - Purpose: CVE data, CVSS scores

2. **ExploitDB**
   - URL: https://www.exploit-db.com
   - Method: Web scraping
   - Purpose: Exploit availability

3. **Ollama API**
   - URL: http://localhost:11434
   - Purpose: Local LLM inference
   - No external API calls

---

## 🔑 Key Takeaways

### What Makes This Project Unique?

1. **Hybrid AI Approach:**
   - Local LLM (no API costs, privacy)
   - RAG prevents hallucinations
   - Hybrid retrieval (vector + keyword)

2. **Unified Security Platform:**
   - Multiple tools, one interface
   - Consistent data model
   - Centralized management

3. **Real-Time Architecture:**
   - WebSocket updates
   - Async task processing
   - Event-driven design

4. **Scalability:**
   - Horizontal worker scaling
   - Redis-backed queuing
   - Connection pooling

5. **Production-Ready:**
   - Docker containerization
   - Health checks
   - Metrics/monitoring
   - Comprehensive testing

### Technology Highlights

- **Backend:** Flask, SQLAlchemy, RQ, PostgreSQL
- **Frontend:** React 19, TypeScript, Vite, Tailwind
- **AI/ML:** Ollama, ChromaDB, Sentence Transformers
- **Security Tools:** Nmap, OpenVAS, Nikto, Nuclei (via WSL)
- **Infrastructure:** Docker, Redis, Prometheus

### Data Flow Summary

```
User → Frontend → API Gateway → Orchestrator → Worker → WSL → Tool
                                                                  ↓
Database ← Parser ← Adapter ← Results ←←←←←←←←←←←←←←←←←←←←←←←←←←←┘
    ↓
ChromaDB (AI Indexing)
    ↓
RAG Chatbot → Ollama LLM → Answer
```

---

## 🚀 Next Steps for Understanding

To dive deeper into specific areas:

1. **For Backend Development:**
   - Read `backend/api_gateway/app.py` (Flask setup)
   - Explore `backend/services/adapters/` (tool integrations)
   - Study `backend/config/models.py` (database schema)

2. **For Frontend Development:**
   - Check `frontend/src/App.tsx` (routing)
   - Review `frontend/src/pages/` (page components)
   - Examine `frontend/vite.config.ts` (build config)

3. **For AI/RAG Features:**
   - Read `backend/intelligence_layer/README.md`
   - Study `backend/intelligence_layer/rag/chatbot.py`
   - Review `docs/intelligence_layer/RAG_PIPELINE_DESIGN.md`

4. **For Security Tools:**
   - Explore `backend/services/adapters/`
   - Check `backend/utils/wsl_helper.py`
   - Test tools in WSL: `wsl -d kali-linux`

5. **For Database:**
   - Review `backend/config/models.py`
   - Check `backend/alembic/versions/`
   - Run: `psql vulnerability_scanner`

---

## 📞 Support & Contribution

### Project Structure Best Practices

- **Modular design:** Each service is independent
- **Clear separation:** API ↔ Business Logic ↔ Data
- **Type safety:** TypeScript frontend, type hints backend
- **Comprehensive docs:** Every major component documented
- **Testing:** Unit, integration, and AI evaluation tests

### Common Issues & Solutions

**Issue:** WSL command fails  
**Solution:** Check WSL distribution name: `wsl -l -v`

**Issue:** Ollama not responding  
**Solution:** Restart Ollama: `ollama serve`

**Issue:** Database connection error  
**Solution:** Check PostgreSQL is running: `docker-compose ps`

**Issue:** Frontend can't reach API  
**Solution:** Verify proxy in `vite.config.ts`, check CORS

**Issue:** RQ worker not processing jobs  
**Solution:** Check Redis connection, restart worker

---

## 🎓 Learning Path

### For Beginners

1. Start with **frontend** (`frontend/src/pages/Dashboard.tsx`)
2. Understand **API calls** (`axios` in page components)
3. Follow **data flow** (frontend → API → database)
4. Explore **WebSocket** updates (`socket.io-client`)

### For Intermediate

1. Study **Flask app factory** (`api_gateway/app.py`)
2. Understand **RQ workers** (`services/scan_orchestrator/`)
3. Learn **adapters pattern** (`services/adapters/`)
4. Explore **database models** (`config/models.py`)

### For Advanced

1. Deep dive **RAG pipeline** (`intelligence_layer/rag/`)
2. Study **ChromaDB indexing** (vector embeddings)
3. Understand **Ollama integration** (local LLM)
4. Explore **attack path modeling** (NetworkX graphs)
5. Review **evaluation framework** (`evaluation/`)

---

**End of Document**

This comprehensive guide covers the entire ESP (Enterprise Security Platform) project. Use the table of contents to navigate to specific sections. For more details on any component, refer to the source code and inline documentation.

