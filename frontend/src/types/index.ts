// Scan Types
export type ScanStatus = 'pending' | 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';

export type ScanTool = 'nmap' | 'openvas' | 'nikto' | 'nuclei';

export type ScanType = 'quick' | 'basic' | 'full' | 'stealth' | 'aggressive' | 'custom';

export interface Scan {
  scan_id: string;
  target: string;
  tool_name: ScanTool;
  scan_type: ScanType;
  status: ScanStatus;
  priority?: string;
  progress?: number;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  execution_time?: number;
  error_message?: string;
  options?: Record<string, any>;
  tags?: string[];
  job_id?: string;
  summary?: ScanSummary;
}

export interface ScanSummary {
  scan_id: string;
  target: string;
  tool_name: string;
  scan_type: string;
  status: string;
  total_hosts?: number;
  total_vulnerabilities?: number;
  critical_count?: number;
  high_count?: number;
  medium_count?: number;
  low_count?: number;
  info_count?: number;
  open_ports?: number[];
  services_detected?: string[];
  os_detection?: string;
  created_at: string;
  completed_at?: string;
}

export interface RawResult {
  id: string;
  scan_id: string;
  tool_name: string;
  raw_output: string;
  created_at: string;
}

export interface AISummary {
  status?: 'completed' | 'failed' | 'generating';
  error?: string;
  error_details?: string;
  can_retry?: boolean;
  summary?: string;
  summary_text?: string;
  confidence?: number;
  recommendations?: string[];
  risk_level?: string;
  risk_score?: number;
  key_findings?: string[];
  title?: string;
}

export interface ParsedResult {
  scan_id: string;
  tool_name: string;
  timestamp?: string;
  ai_summary?: AISummary;
  ai_summary_text?: string;
  data?: Record<string, any>;
  parsed_results?: Array<{
    tool_name: string;
    data: Record<string, any>;
    timestamp?: string;
  }>;
  summary?: Record<string, any>;
}

export interface Vulnerability {
  cve_id?: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description?: string;
  cvss_score?: number;
  port?: number;
  service?: string;
  solution?: string;
}

// API Response Types
export interface ScanListResponse {
  scans: Scan[];
  total: number;
  page: number;
  per_page: number;
}

export interface CreateScanRequest {
  target: string;
  tool_name: ScanTool;
  scan_type: ScanType;
  description?: string;
  options?: Record<string, any>;
  tags?: string[];
  priority?: 'low' | 'normal' | 'high';
}

export interface ScanStatusResponse {
  scan_id: string;
  status: ScanStatus;
  progress: number;
  job_status?: string;
  started_at?: string;
  execution_time?: number;
}

// Statistics Types
export interface Statistics {
  total_scans: number;
  status_breakdown: {
    pending: number;
    queued: number;
    running: number;
    completed: number;
    failed: number;
    cancelled: number;
  };
  tool_usage: Record<string, number>;
  scan_type_usage: Record<string, number>;
  vulnerabilities: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

// Intelligence Layer Types
export interface ChatMessage {
  query: string;
  session_id?: string;
  top_k?: number;
}

export interface ChatResponse {
  response: string;
  sources: any[];
  confidence: number;
  session_id: string;
  query_intent: string;
  hallucination_detected: boolean;
}

// WebSocket Message Types
export interface WSMessage {
  type: 'scan_update' | 'scan_complete' | 'scan_failed' | 'scan_cancelled';
  scan_id: string;
  data: any;
}
