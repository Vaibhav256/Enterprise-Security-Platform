import axios from 'axios';
import type {
  Scan,
  ScanListResponse,
  CreateScanRequest,
  ScanStatusResponse,
  Statistics,
  RawResult,
  ChatMessage,
  ChatResponse,
} from '../types';

// Create axios instance with base configuration
const api = axios.create({
  baseURL: '/api',
  timeout: 120000, // 120 seconds for long-running RAG operations (LLM inference + retrieval + real-time enrichment can take 40-50s)
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor (no auth needed)
api.interceptors.request.use(
  (config) => {
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    // Just log errors, no auth redirect
    console.error('API Error:', error.response?.data || error.message);
    return Promise.reject(error);
  }
);

// ============================================================================
// Scan Management API
// ============================================================================

export const scanApi = {
  // List all scans with optional filtering
  listScans: async (params?: {
    status?: string;
    tool_name?: string;
    page?: number;
    per_page?: number;
  }): Promise<ScanListResponse> => {
    const response = await api.get<ScanListResponse>('/scans', { params });
    return response.data;
  },

  // Create a new scan
  createScan: async (data: CreateScanRequest): Promise<Scan> => {
    const response = await api.post<Scan>('/scans', data);
    return response.data;
  },

  // Get scan details
  getScan: async (scanId: string): Promise<Scan> => {
    const response = await api.get<Scan>(`/scans/${scanId}`);
    return response.data;
  },

  // Delete/cancel scan
  deleteScan: async (scanId: string): Promise<void> => {
    await api.delete(`/scans/${scanId}`);
  },

  // Get scan status
  getScanStatus: async (scanId: string): Promise<ScanStatusResponse> => {
    const response = await api.get<ScanStatusResponse>(`/scans/${scanId}/status`);
    return response.data;
  },

  // Get raw scan results
  getRawResults: async (scanId: string): Promise<{ results: RawResult[] }> => {
    const response = await api.get<{ results: RawResult[] }>(`/scans/${scanId}/raw_results`);
    return response.data;
  },

  // Get parsed scan results
  getParsedResults: async (scanId: string): Promise<any> => {
    const response = await api.get(`/scans/${scanId}/parsed_results`);
    return response.data;
  },

  // Get scan summary
  getScanSummary: async (scanId: string): Promise<any> => {
    const response = await api.get(`/scans/${scanId}/summary`);
    return response.data;
  },

  // Export scan results
  exportScan: async (scanId: string, format: 'json' | 'csv' | 'pdf' | 'xlsx' | 'xml'): Promise<Blob> => {
    const response = await api.get(`/scans/${scanId}/export/${format}`, {
      responseType: 'blob',
    });
    return response.data;
  },

  // Bulk delete scans
  bulkDelete: async (scanIds: string[]): Promise<any> => {
    const response = await api.post('/scans/bulk/delete', { scan_ids: scanIds });
    return response.data;
  },

  // Bulk export scans
  bulkExport: async (scanIds: string[], format: string): Promise<Blob> => {
    const response = await api.post(
      '/scans/bulk/export',
      { scan_ids: scanIds, format },
      { responseType: 'blob' }
    );
    return response.data;
  },
};

// ============================================================================
// Statistics API
// ============================================================================

export const statsApi = {
  // Get overall statistics
  getStats: async (): Promise<Statistics> => {
    const response = await api.get<Statistics>('/stats');
    return response.data;
  },

  // Get scan statistics
  getScanStats: async (): Promise<Statistics> => {
    const response = await api.get<Statistics>('/scans/stats');
    return response.data;
  },
};

// ============================================================================
// Tools API
// ============================================================================

export const toolsApi = {
  // Get available scanning tools
  getTools: async (): Promise<any> => {
    const response = await api.get('/tools');
    return response.data;
  },
};

// ============================================================================
// Intelligence Layer API
// ============================================================================

export const intelligenceApi = {
  // Chat with RAG chatbot
  chat: async (message: ChatMessage): Promise<ChatResponse> => {
    const response = await api.post<ChatResponse>('/intelligence/chat', message);
    return response.data;
  },

  // Index scan results
  indexScan: async (scanId: string): Promise<any> => {
    const response = await api.post('/intelligence/index', { scan_id: scanId });
    return response.data;
  },

  // Get indexing statistics
  getIndexStats: async (): Promise<any> => {
    const response = await api.get('/intelligence/index/stats');
    return response.data;
  },

  // Delete indexed scan data
  deleteIndexedScan: async (scanId: string): Promise<any> => {
    const response = await api.delete(`/intelligence/index/delete/${scanId}`);
    return response.data;
  },

  // Delete specific indexed vulnerability
  deleteIndexedVulnerability: async (docId: string): Promise<any> => {
    const response = await api.delete(`/intelligence/index/vulnerability/${docId}`);
    return response.data;
  },

  // Query indexed data
  queryIndexedData: async (queryText: string, nResults: number = 10, filterMetadata?: any): Promise<any> => {
    const response = await api.post('/intelligence/index/query', {
      query_text: queryText,
      n_results: nResults,
      filter_metadata: filterMetadata
    });
    return response.data;
  },

  // Health check
  healthCheck: async (): Promise<any> => {
    const response = await api.get('/intelligence/health');
    return response.data;
  },
};

// ============================================================================
// Threat Feeds API
// ============================================================================

export const feedsApi = {
  // Get feed status
  getStatus: async (): Promise<any> => {
    const response = await api.get('/feeds/status');
    return response.data;
  },

  // Get recent CVEs
  getRecent: async (params?: { days?: number; limit?: number }): Promise<any> => {
    const response = await api.get('/feeds/recent', { params });
    return response.data;
  },

  // Search vulnerabilities
  search: async (params?: {
    keyword?: string;
    severity?: string;
    days?: number;
    limit?: number;
    offset?: number;
  }): Promise<any> => {
    const response = await api.get('/feeds/search', { params });
    return response.data;
  },

  // Get specific CVE details
  getCVE: async (cveId: string): Promise<any> => {
    const response = await api.get(`/feeds/cve/${cveId}`);
    return response.data;
  },

  // Get specific exploit details
  getExploit: async (exploitId: string): Promise<any> => {
    const response = await api.get(`/feeds/exploits/${exploitId}`);
    return response.data;
  },

  // List all CVEs
  listCVEs: async (params?: {
    severity?: string;
    search?: string;
    limit?: number;
    offset?: number;
  }): Promise<any> => {
    const response = await api.get('/feeds/cves', { params });
    return response.data;
  },

  // List all exploits
  listExploits: async (params?: {
    search?: string;
    limit?: number;
    offset?: number;
  }): Promise<any> => {
    const response = await api.get('/feeds/exploits', { params });
    return response.data;
  },

  // Refresh feeds
  refresh: async (force?: boolean): Promise<any> => {
    const response = await api.post('/feeds/refresh', { force: force || false });
    return response.data;
  },

  // Get feed statistics
  getStats: async (): Promise<any> => {
    const response = await api.get('/feeds/stats');
    return response.data;
  },

  // Get feed alerts
  getAlerts: async (params?: { limit?: number; severity?: string }): Promise<any> => {
    const response = await api.get('/feeds/alerts', { params });
    return response.data;
  },
};

export default api;
