// API Configuration
export const API_CONFIG = {
  BASE_URL: import.meta.env.VITE_API_URL || '/api',
  TIMEOUT: 30000,
  RETRY_ATTEMPTS: 3,
  RETRY_DELAY: 1000,
};

// WebSocket Configuration
export const WS_CONFIG = {
  URL: import.meta.env.VITE_WS_URL || 'http://localhost:5000',
  RECONNECTION_DELAY: 1000,
  RECONNECTION_ATTEMPTS: 5,
};

// Scan Configuration
export const SCAN_CONFIG = {
  TOOLS: ['nmap', 'openvas', 'nikto', 'nuclei'] as const,
  SCAN_TYPES: ['quick', 'basic', 'full', 'stealth'] as const,
  PRIORITIES: ['low', 'normal', 'high'] as const,
  STATUSES: ['pending', 'queued', 'running', 'completed', 'failed', 'cancelled'] as const,
};

// Pagination
export const PAGINATION = {
  DEFAULT_PAGE_SIZE: 20,
  PAGE_SIZE_OPTIONS: [10, 20, 50, 100],
};

// Auto-refresh Intervals (milliseconds)
export const REFRESH_INTERVALS = {
  DASHBOARD: 10000, // 10 seconds
  SCAN_DETAIL: 5000, // 5 seconds
  SCAN_LIST: 15000, // 15 seconds
};

// Export Formats
export const EXPORT_FORMATS = ['json', 'csv', 'pdf', 'xlsx'] as const;

// Severity Levels
export const SEVERITY_LEVELS = {
  CRITICAL: { value: 'critical', color: 'danger', score: 9.0 },
  HIGH: { value: 'high', color: 'orange', score: 7.0 },
  MEDIUM: { value: 'medium', color: 'warning', score: 4.0 },
  LOW: { value: 'low', color: 'blue', score: 0.1 },
  INFO: { value: 'info', color: 'gray', score: 0.0 },
} as const;

// Validation Patterns
export const VALIDATION = {
  IPV4_PATTERN: /^(\d{1,3}\.){3}\d{1,3}$/,
  IPV6_PATTERN: /^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$/,
  HOSTNAME_PATTERN: /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/,
  CIDR_PATTERN: /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/,
  PORT_PATTERN: /^\d{1,5}$/,
  CVE_PATTERN: /^CVE-\d{4}-\d{4,}$/i,
};

// Chart Colors
export const CHART_COLORS = {
  PRIMARY: '#0ea5e9',
  SUCCESS: '#22c55e',
  WARNING: '#f59e0b',
  DANGER: '#ef4444',
  INFO: '#6b7280',
  PURPLE: '#9333ea',
  ORANGE: '#f97316',
  TEAL: '#14b8a6',
};

// Local Storage Keys
export const STORAGE_KEYS = {
  SETTINGS: 'vuln_scanner_settings',
  THEME: 'vuln_scanner_theme',
  SESSION_ID: 'vuln_scanner_session',
  FILTERS: 'vuln_scanner_filters',
};

// Default Settings
export const DEFAULT_SETTINGS = {
  apiUrl: 'http://localhost:5000',
  dashboardRefreshRate: 10,
  scanDetailRefreshRate: 5,
  scansPerPage: 20,
  enableWebSocket: true,
  enableNotifications: true,
  theme: 'light',
};

// Toast Duration
export const TOAST_DURATION = {
  SHORT: 3000,
  MEDIUM: 5000,
  LONG: 8000,
};

// Suggested Prompts for AI Assistant
export const SUGGESTED_PROMPTS = [
  'What are the critical SSH vulnerabilities?',
  'Explain CVE-2023-12345',
  'How do I fix SQL injection vulnerabilities?',
  'What ports should I close for better security?',
  'Show me all high-severity vulnerabilities',
];

// Application Metadata
export const APP_INFO = {
  NAME: 'NTRO Vulnerability Scanner',
  VERSION: '1.0.0',
  DESCRIPTION: 'Centralized Vulnerability Detection and Intelligent Query Interface',
  AUTHOR: 'NTRO Security Team',
  SUPPORT_EMAIL: 'support@ntro.gov',
};
