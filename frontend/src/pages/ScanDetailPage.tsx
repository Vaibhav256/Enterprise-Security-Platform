import { useEffect, useState, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowDownToLine, RotateCw, ServerCog, Clock, TriangleAlert, Zap, ShieldAlert } from 'lucide-react';
import { motion } from 'framer-motion';
import { scanApi } from '../api/client';
import type { Scan, RawResult, ParsedResult } from '../types';
import { formatDate, formatDuration, getStatusBadgeClass, getSeverityColor } from '../utils/helpers';
import { TextShimmer } from '../components/ui/text-shimmer';
import { InteractiveHoverButton } from '../components/ui/interactive-hover-button';

const ScanDetailPage = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const [scan, setScan] = useState<Scan | null>(null);
  const [rawResults, setRawResults] = useState<RawResult[] | null>(null);
  const [parsedResults, setParsedResults] = useState<ParsedResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'overview' | 'raw' | 'parsed'>('overview');
  const [showExportMenu, setShowExportMenu] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [regenerating, setRegenerating] = useState(false);
  const exportMenuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!scanId) return;

    const fetchData = async () => {
      try {
        const [scanData, rawData, parsedData] = await Promise.all([
          scanApi.getScan(scanId),
          scanApi.getRawResults(scanId).catch(() => ({ results: [] })),
          scanApi.getParsedResults(scanId).catch(() => null),
        ]);
        setScan(scanData);
        setRawResults(rawData.results);
        if (parsedData) {
          setParsedResults(parsedData);
        }
      } catch (error) {
        console.error('Failed to fetch scan details:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    
    // Refresh if scan is running
    const interval = setInterval(() => {
      if (scan?.status === 'running' || scan?.status === 'queued') {
        fetchData();
      }
    }, 5000);

    return () => clearInterval(interval);
  }, [scanId, scan?.status]);

  // Close export menu when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (exportMenuRef.current && !exportMenuRef.current.contains(event.target as Node)) {
        setShowExportMenu(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleDelete = async () => {
    if (!scanId || !confirm('Delete this scan?')) return;

    try {
      await scanApi.deleteScan(scanId);
      navigate('/scans');
    } catch (error) {
      console.error('Failed to delete scan:', error);
    }
  };

  const handleExport = async (format: 'json' | 'csv' | 'xlsx' | 'pdf' | 'xml') => {
    if (!scanId) return;

    setExporting(true);
    setShowExportMenu(false);

    try {
      const blob = await scanApi.exportScan(scanId, format);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `scan-${scan?.target || scanId}-${Date.now()}.${format}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Failed to export scan:', error);
      alert('Failed to export scan. Please try again.');
    } finally {
      setExporting(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <RotateCw className="w-8 h-8 animate-spin text-primary-600" />
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="text-center py-12">
        <TriangleAlert className="w-12 h-12 mx-auto text-danger-600 mb-4" />
        <p className="text-gray-800 dark:text-gray-700">Scan not found</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <InteractiveHoverButton 
            onClick={() => navigate('/scans')} 
            text="Back"
            className="w-auto px-4"
          />
          <div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">{scan.target}</h1>
            <p className="text-gray-800 dark:text-gray-400 mt-1">
              {scan.tool_name} • {scan.scan_type} • {formatDate(scan.created_at)}
            </p>
          </div>
        </div>
        <div className="flex gap-2">
          {/* Export Dropdown */}
          <div className="relative" ref={exportMenuRef}>
            <InteractiveHoverButton
              onClick={() => setShowExportMenu(!showExportMenu)}
              disabled={exporting}
              text={exporting ? "Exporting..." : "Export"}
              className="w-auto px-6"
            />
            
            {showExportMenu && (
              <motion.div
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                className="absolute right-0 mt-2 w-48 bg-white dark:bg-neutral-800/80 backdrop-blur-sm rounded-lg shadow-xl shadow-gray-200/30 dark:shadow-none border border-gray-300/70 dark:border-neutral-700 py-1 z-10"
              >
                <button
                  onClick={() => handleExport('json')}
                  className="w-full px-4 py-2 text-left hover:bg-gradient-to-r hover:from-gray-50 hover:to-gray-100 dark:hover:bg-neutral-700/60 transition-all duration-150 flex items-center gap-2 text-sm"
                >
                  <ArrowDownToLine className="w-4 h-4 text-gray-900 dark:text-gray-300" />
                  <span>Export as JSON</span>
                </button>
                <button
                  onClick={() => handleExport('csv')}
                  className="w-full px-4 py-2 text-left hover:bg-gradient-to-r hover:from-gray-50 hover:to-gray-100 dark:hover:bg-neutral-700/60 transition-all duration-150 flex items-center gap-2 text-sm"
                >
                  <ArrowDownToLine className="w-4 h-4 text-gray-900 dark:text-gray-300" />
                  <span>Export as CSV</span>
                </button>
                <button
                  onClick={() => handleExport('xlsx')}
                  className="w-full px-4 py-2 text-left hover:bg-gradient-to-r hover:from-gray-50 hover:to-gray-100 dark:hover:bg-neutral-700/60 transition-all duration-150 flex items-center gap-2 text-sm"
                >
                  <ArrowDownToLine className="w-4 h-4 text-gray-900 dark:text-gray-300" />
                  <span>Export as Excel</span>
                </button>
                <button
                  onClick={() => handleExport('pdf')}
                  className="w-full px-4 py-2 text-left hover:bg-gradient-to-r hover:from-gray-50 hover:to-gray-100 dark:hover:bg-neutral-700/60 transition-all duration-150 flex items-center gap-2 text-sm"
                >
                  <ArrowDownToLine className="w-4 h-4 text-gray-900 dark:text-gray-300" />
                  <span>Export as PDF</span>
                </button>
                <button
                  onClick={() => handleExport('xml')}
                  className="w-full px-4 py-2 text-left hover:bg-gradient-to-r hover:from-gray-50 hover:to-gray-100 dark:hover:bg-neutral-700/60 transition-all duration-150 flex items-center gap-2 text-sm"
                >
                  <ArrowDownToLine className="w-4 h-4 text-gray-900 dark:text-gray-300" />
                  <span>Export as XML</span>
                </button>
              </motion.div>
            )}
          </div>
          
          <InteractiveHoverButton 
            onClick={handleDelete} 
            text="Delete"
            className="w-auto px-6 bg-red-600 hover:bg-red-700"
          />
        </div>
      </div>

      {/* Status Card */}
      <motion.div 
        className="card"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
      >
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <div>
            <p className="text-sm text-gray-800 dark:text-gray-400 mb-1 flex items-center gap-2">
              <ServerCog className="w-4 h-4" />
              Status
            </p>
            <span className={`badge ${getStatusBadgeClass(scan.status)}`}>
              {scan.status}
            </span>
          </div>
          <div>
            <p className="text-sm text-gray-800 dark:text-gray-400 mb-1">Progress</p>
            <div className="flex items-center gap-2">
              <div className="flex-1 bg-gray-200 dark:bg-neutral-700 rounded-full h-2">
                <div 
                  className="bg-primary-600 h-2 rounded-full transition-all" 
                  style={{ width: `${scan.progress || 0}%` }}
                />
              </div>
              <span className="text-lg font-semibold text-gray-900 dark:text-white">{scan.progress || 0}%</span>
            </div>
          </div>
          <div>
            <p className="text-sm text-gray-800 dark:text-gray-400 mb-1 flex items-center gap-2">
              <Clock className="w-4 h-4" />
              Duration
            </p>
            <p className="text-lg font-semibold text-gray-900 dark:text-white">{formatDuration(scan.execution_time)}</p>
          </div>
          <div>
            <p className="text-sm text-gray-800 dark:text-gray-400 mb-1">Priority</p>
            <span className={`badge ${
              scan.priority === 'high' ? 'badge-danger' :
              scan.priority === 'low' ? 'badge-secondary' :
              'badge-warning'
            }`}>
              {scan.priority || 'normal'}
            </span>
          </div>
        </div>
      </motion.div>

      {/* Tabs */}
      <div className="card">
        <div className="border-b mb-6">
          <nav className="flex gap-6">
            {[
              { id: 'overview', label: 'Overview' },
              { id: 'raw', label: 'Raw Results' },
              { id: 'parsed', label: 'Response' },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`pb-3 px-1 border-b-2 font-medium transition-colors ${
                  activeTab === tab.id
                    ? 'border-primary-600 text-primary-600'
                    : 'border-transparent text-gray-900 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        {/* Tab Content */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">Scan Information</h3>
              <dl className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <dt className="text-sm text-gray-800 dark:text-gray-700">Scan ID</dt>
                  <dd className="text-gray-900 dark:text-white font-mono text-sm mt-1">{scan.scan_id}</dd>
                </div>
                <div>
                  <dt className="text-sm text-gray-800 dark:text-gray-700">Target</dt>
                  <dd className="text-gray-900 dark:text-white mt-1">{scan.target}</dd>
                </div>
                <div>
                  <dt className="text-sm text-gray-800 dark:text-gray-700">Tool</dt>
                  <dd className="text-gray-900 dark:text-white mt-1">{scan.tool_name}</dd>
                </div>
                <div>
                  <dt className="text-sm text-gray-800 dark:text-gray-700">Scan Type</dt>
                  <dd className="text-gray-900 dark:text-white mt-1">{scan.scan_type}</dd>
                </div>
                {scan.started_at && (
                  <div>
                    <dt className="text-sm text-gray-800 dark:text-gray-700">Started At</dt>
                    <dd className="text-gray-900 dark:text-white mt-1">{formatDate(scan.started_at)}</dd>
                  </div>
                )}
                {scan.completed_at && (
                  <div>
                    <dt className="text-sm text-gray-800 dark:text-gray-700">Completed At</dt>
                    <dd className="text-gray-900 dark:text-white mt-1">{formatDate(scan.completed_at)}</dd>
                  </div>
                )}
                {scan.execution_time && (
                  <div>
                    <dt className="text-sm text-gray-800 dark:text-gray-700">Execution Time</dt>
                    <dd className="text-gray-900 dark:text-white mt-1">{formatDuration(scan.execution_time)}</dd>
                  </div>
                )}
              </dl>
            </div>

            {scan.summary && (
              <div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">Summary</h3>
                <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                  {scan.summary.critical_count !== undefined && (
                    <motion.div 
                      className="p-4 bg-danger-50 dark:bg-danger-900/20 rounded-lg border-2"
                      style={{ borderColor: getSeverityColor('critical') }}
                      whileHover={{ scale: 1.05 }}
                      transition={{ duration: 0.2 }}
                    >
                      <p className="text-sm text-danger-600 dark:text-danger-400 mb-1">Critical</p>
                      <p className="text-2xl font-bold text-danger-900 dark:text-danger-200">{scan.summary.critical_count}</p>
                    </motion.div>
                  )}
                  {scan.summary.high_count !== undefined && (
                    <motion.div 
                      className="p-4 bg-orange-50 dark:bg-orange-900/20 rounded-lg border-2"
                      style={{ borderColor: getSeverityColor('high') }}
                      whileHover={{ scale: 1.05 }}
                      transition={{ duration: 0.2 }}
                    >
                      <p className="text-sm text-orange-600 dark:text-orange-400 mb-1">High</p>
                      <p className="text-2xl font-bold text-orange-900 dark:text-orange-200">{scan.summary.high_count}</p>
                    </motion.div>
                  )}
                  {scan.summary.medium_count !== undefined && (
                    <motion.div 
                      className="p-4 bg-warning-50 dark:bg-warning-900/20 rounded-lg border-2"
                      style={{ borderColor: getSeverityColor('medium') }}
                      whileHover={{ scale: 1.05 }}
                      transition={{ duration: 0.2 }}
                    >
                      <p className="text-sm text-warning-600 dark:text-warning-400 mb-1">Medium</p>
                      <p className="text-2xl font-bold text-warning-900 dark:text-warning-200">{scan.summary.medium_count}</p>
                    </motion.div>
                  )}
                  {scan.summary.low_count !== undefined && (
                    <motion.div 
                      className="p-4 bg-gray-50 dark:bg-blue-900/20 rounded-lg border-2"
                      style={{ borderColor: getSeverityColor('low') }}
                      whileHover={{ scale: 1.05 }}
                      transition={{ duration: 0.2 }}
                    >
                      <p className="text-sm text-blue-600 dark:text-blue-400 mb-1">Low</p>
                      <p className="text-2xl font-bold text-gray-900 dark:text-blue-200">{scan.summary.low_count}</p>
                    </motion.div>
                  )}
                  {scan.summary.info_count !== undefined && (
                    <motion.div 
                      className="p-4 bg-gray-50/50 dark:bg-neutral-800/50 backdrop-blur-sm rounded-lg border-2"
                      style={{ borderColor: getSeverityColor('info') }}
                      whileHover={{ scale: 1.05 }}
                      transition={{ duration: 0.2 }}
                    >
                      <p className="text-sm text-gray-800 dark:text-gray-400 mb-1">Info</p>
                      <p className="text-2xl font-bold text-gray-900 dark:text-gray-200">{scan.summary.info_count}</p>
                    </motion.div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'raw' && (
          <div>
            {rawResults && rawResults.length > 0 ? (
              <div className="space-y-4">
                {rawResults.map((result) => (
                  <div key={result.id} className="bg-gradient-to-br from-gray-50/50 to-gray-100/30 dark:bg-neutral-800/50 backdrop-blur-sm rounded-lg p-4 border border-gray-300/60 dark:border-neutral-700 shadow-sm shadow-gray-200/20 dark:shadow-none">
                    <pre className="text-sm whitespace-pre-wrap break-all font-mono max-h-96 overflow-y-auto overflow-x-hidden text-gray-900 dark:text-gray-200">
                      {result.raw_output}
                    </pre>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-center text-gray-700 dark:text-gray-400 py-8">No raw results available</p>
            )}
          </div>
        )}

        {activeTab === 'parsed' && (
          <div className="space-y-6">
            {parsedResults && parsedResults.ai_summary ? (
              <>
                {/* AI Summary Section */}
                <div className={`rounded-lg border p-6 ${
                  parsedResults.ai_summary.status === 'failed' 
                    ? 'bg-gradient-to-r from-red-50 to-orange-50 dark:from-red-900/20 dark:to-orange-900/20 border-red-200 dark:border-red-800' 
                    : parsedResults.ai_summary.status === 'generating'
                    ? 'bg-gradient-to-r from-yellow-50 to-amber-50 dark:from-yellow-900/20 dark:to-amber-900/20 border-yellow-200 dark:border-yellow-800'
                    : 'bg-gradient-to-r from-gray-50 to-gray-100 dark:from-blue-900/20 dark:to-indigo-900/20 border-gray-300 dark:border-blue-800'
                }`}>
                  <div className="flex items-center gap-3 mb-4">
                    <Zap className={`w-5 h-5 ${
                      parsedResults.ai_summary.status === 'failed' ? 'text-red-600 dark:text-red-400' : 
                      parsedResults.ai_summary.status === 'generating' ? 'text-yellow-600 dark:text-yellow-400' :
                      'text-blue-600 dark:text-blue-400'
                    }`} />
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">AI Summary</h3>
                  </div>
                  
                  {/* Generating State */}
                  {parsedResults.ai_summary.status === 'generating' || regenerating ? (
                    <div className="space-y-4">
                      <div className="bg-white/80 dark:bg-neutral-800/80 backdrop-blur-sm dark:bg-neutral-800 rounded-lg p-6 border border-yellow-200 dark:border-yellow-700">
                        <div className="flex items-center gap-3 justify-center">
                          <TextShimmer duration={1.5} className="text-base font-medium">
                            Generating AI-powered vulnerability analysis...
                          </TextShimmer>
                        </div>
                        <p className="text-center text-sm text-gray-700 dark:text-gray-400 mt-2">
                          This may take 10-30 seconds
                        </p>
                      </div>
                    </div>
                  ) :
                  /* Error State */
                  parsedResults.ai_summary.status === 'failed' ? (
                    <div className="space-y-4">
                      <div className="bg-white/80 dark:bg-neutral-800/80 backdrop-blur-sm rounded-lg p-4 border border-red-200 dark:border-red-800">
                        <div className="flex items-start gap-3">
                          <ShieldAlert className="w-5 h-5 text-red-600 dark:text-red-400 mt-0.5 flex-shrink-0" />
                          <div className="flex-1">
                            <p className="font-medium text-red-900 dark:text-red-200 mb-1">
                              AI Summary Generation Failed
                            </p>
                            <p className="text-sm text-red-700 dark:text-red-300 mb-3">
                              {parsedResults.ai_summary.error || 'Unable to generate AI summary at this time.'}
                            </p>
                            {parsedResults.ai_summary.can_retry && (
                              <button
                                onClick={async () => {
                                  setRegenerating(true);
                                  try {
                                    const response = await fetch(`/api/scans/${scanId}/regenerate-summary`, {
                                      method: 'POST',
                                      headers: {
                                        'Content-Type': 'application/json',
                                      },
                                    });
                                    
                                    if (response.ok) {
                                      const result = await response.json();
                                      // Update the parsed results with new summary
                                      if (result.summary) {
                                        setParsedResults(prev => ({
                                          ...prev!,
                                          ai_summary: {
                                            status: 'completed',
                                            title: result.summary.title,
                                            summary_text: result.summary.executive_summary,
                                            confidence: result.summary.confidence,
                                            risk_level: result.summary.risk_level,
                                            risk_score: result.summary.risk_score,
                                            key_findings: result.summary.key_findings,
                                            recommendations: result.summary.recommendations,
                                            can_retry: false
                                          }
                                        }));
                                      }
                                    } else {
                                      const error = await response.json();
                                      alert(`Failed to regenerate: ${error.message || error.error || 'Unknown error'}`);
                                    }
                                  } catch (error) {
                                    console.error('Regeneration failed:', error);
                                    alert('Failed to regenerate summary. Please try again later.');
                                  } finally {
                                    setRegenerating(false);
                                  }
                                }}
                                disabled={regenerating}
                                className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                              >
                                {regenerating ? (
                                  <>
                                    <RotateCw className="w-4 h-4 animate-spin" />
                                    Generating...
                                  </>
                                ) : (
                                  <>
                                    <Zap className="w-4 h-4" />
                                    Regenerate AI Summary
                                  </>
                                )}
                              </button>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                  ) : regenerating ? (
                    <div className="space-y-4">
                      <div className="bg-white/80 dark:bg-neutral-800/80 backdrop-blur-sm rounded-lg p-6 border border-gray-300">
                        <div className="flex items-center gap-3 justify-center">
                          <RotateCw className="w-5 h-5 text-blue-600 animate-spin" />
                          <p className="text-gray-900 dark:text-gray-200">Generating AI summary... This may take 10-30 seconds.</p>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {/* Title */}
                      {parsedResults.ai_summary.title && (
                        <div>
                          <p className="text-sm font-medium text-gray-800 dark:text-gray-400 mb-1">Title</p>
                          <p className="text-base text-gray-900 dark:text-white">{parsedResults.ai_summary.title}</p>
                        </div>
                      )}

                    {/* Summary Text */}
                    {parsedResults.ai_summary.summary_text && (
                      <div>
                        <p className="text-sm font-medium text-gray-800 dark:text-gray-400 mb-2">Executive Summary</p>
                        <div className="bg-white/80 dark:bg-neutral-800/80 backdrop-blur-sm rounded p-4 text-sm text-gray-900 dark:text-gray-200 leading-relaxed border border-gray-200 dark:border-neutral-700">
                          {parsedResults.ai_summary.summary_text}
                        </div>
                      </div>
                    )}

                    {/* Risk Level and Confidence */}
                    <div className="grid grid-cols-2 gap-4">
                      {parsedResults.ai_summary.risk_level && (
                        <div className="bg-white/80 dark:bg-neutral-800/80 backdrop-blur-sm rounded p-3 border border-gray-200 dark:border-neutral-700">
                          <p className="text-xs font-medium text-gray-700 dark:text-gray-400 uppercase mb-1">Risk Level</p>
                          <p className={`text-base font-semibold ${
                            parsedResults.ai_summary.risk_level === 'critical' ? 'text-red-600 dark:text-red-400' :
                            parsedResults.ai_summary.risk_level === 'high' ? 'text-orange-600 dark:text-orange-400' :
                            parsedResults.ai_summary.risk_level === 'medium' ? 'text-yellow-600 dark:text-yellow-400' :
                            'text-green-600 dark:text-green-400'
                          }`}>
                            {parsedResults.ai_summary.risk_level.toUpperCase()}
                          </p>
                        </div>
                      )}
                      {/* Confidence */}
                      {parsedResults.ai_summary.confidence !== undefined && parsedResults.ai_summary.confidence > 0 && (
                        <div className="bg-white/80 dark:bg-neutral-800/80 backdrop-blur-sm rounded p-3 border border-gray-200 dark:border-neutral-700">
                          <p className="text-xs font-medium text-gray-700 dark:text-gray-400 uppercase mb-1">Confidence</p>
                          <p className="text-base font-semibold text-blue-600 dark:text-blue-400">
                            {(parsedResults.ai_summary.confidence * 100).toFixed(0)}%
                          </p>
                        </div>
                      )}
                    </div>

                    {/* Key Findings */}
                    {parsedResults.ai_summary.key_findings && parsedResults.ai_summary.key_findings.length > 0 && (
                      <div>
                        <p className="text-sm font-medium text-gray-800 dark:text-gray-400 mb-2">Key Findings</p>
                        <ul className="space-y-2">
                          {parsedResults.ai_summary.key_findings.map((finding, idx) => (
                            <li key={idx} className="flex items-start gap-2 text-sm text-gray-900 dark:text-gray-200">
                              <span className="text-blue-600 dark:text-blue-400 font-bold mt-0.5">•</span>
                              <span>{finding}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {/* Recommendations */}
                    {parsedResults.ai_summary.recommendations && parsedResults.ai_summary.recommendations.length > 0 && (
                      <div className="bg-white/80 dark:bg-neutral-800/80 backdrop-blur-sm rounded p-4 border border-green-200 dark:border-green-800">
                        <div className="flex items-center gap-2 mb-3">
                          <ShieldAlert className="w-4 h-4 text-green-600 dark:text-green-400" />
                          <p className="text-sm font-medium text-gray-900 dark:text-gray-200">Recommendations</p>
                        </div>
                        <ul className="space-y-2">
                          {parsedResults.ai_summary.recommendations.map((rec, idx) => (
                            <li key={idx} className="flex items-start gap-2 text-sm text-gray-900 dark:text-gray-200">
                              <span className="text-green-600 font-bold mt-0.5">✓</span>
                              <span>{rec}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    </div>
                  )}
                </div>

                {/* Response from Tools */}
                {parsedResults.parsed_results && parsedResults.parsed_results.length > 0 && (
                  <div>
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Tool Results</h3>
                    <div className="space-y-4">
                      {parsedResults.parsed_results.map((result, idx) => (
                        <div key={idx} className="bg-gray-50/50 dark:bg-neutral-800/50 backdrop-blur-sm rounded-lg p-4 border border-gray-200 dark:border-neutral-700">
                          <h4 className="font-semibold text-gray-900 dark:text-white mb-3 capitalize flex items-center gap-2">
                            <span className="inline-block w-2 h-2 bg-blue-600 rounded-full"></span>
                            {result.tool_name} Scan Results
                          </h4>
                          
                          {/* Display Nmap Results in Human-Readable Format */}
                          {result.tool_name === 'nmap' && result.data?.summary && (
                            <div className="space-y-4">
                              {/* Scan Summary */}
                              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                                {result.data.summary.hosts_scanned !== undefined && (
                                  <div className="bg-white/80 dark:bg-neutral-800/80 backdrop-blur-sm rounded p-3">
                                    <p className="text-xs text-gray-700 dark:text-gray-400 font-semibold uppercase mb-1">Hosts Scanned</p>
                                    <p className="text-2xl font-bold text-gray-900 dark:text-white">{result.data.summary.hosts_scanned}</p>
                                  </div>
                                )}
                                {result.data.summary.hosts_up !== undefined && (
                                  <div className="bg-white/80 dark:bg-neutral-800/80 backdrop-blur-sm rounded p-3">
                                    <p className="text-xs text-gray-700 dark:text-gray-400 font-semibold uppercase mb-1">Hosts Up</p>
                                    <p className="text-2xl font-bold text-green-600 dark:text-green-400">{result.data.summary.hosts_up}</p>
                                  </div>
                                )}
                                {result.data.summary.open_ports !== undefined && (
                                  <div className="bg-white/80 dark:bg-neutral-800/80 backdrop-blur-sm rounded p-3">
                                    <p className="text-xs text-gray-700 dark:text-gray-400 font-semibold uppercase mb-1">Open Ports</p>
                                    <p className="text-2xl font-bold text-orange-600 dark:text-orange-400">{result.data.summary.open_ports}</p>
                                  </div>
                                )}
                                {result.data.summary.total_ports !== undefined && (
                                  <div className="bg-white/80 dark:bg-neutral-800/80 backdrop-blur-sm rounded p-3">
                                    <p className="text-xs text-gray-700 dark:text-gray-400 font-semibold uppercase mb-1">Total Ports</p>
                                    <p className="text-2xl font-bold text-blue-600 dark:text-blue-400">{result.data.summary.total_ports}</p>
                                  </div>
                                )}
                              </div>

                              {/* Hosts Detail */}
                              {result.data.hosts && result.data.hosts.length > 0 && (
                                <div>
                                  <h5 className="font-semibold text-gray-900 dark:text-gray-200 mb-3">Scanned Hosts</h5>
                                  <div className="space-y-3">
                                    {result.data.hosts.map((host: any, hostIdx: number) => (
                                      <div key={hostIdx} className="bg-white/80 dark:bg-neutral-800/80 backdrop-blur-sm rounded p-3 border border-gray-200 dark:border-neutral-700">
                                        <div className="flex items-center justify-between mb-2">
                                          <span className="font-mono text-sm font-bold text-gray-900 dark:text-white">{host.ip_address}</span>
                                          <span className={`text-xs font-semibold px-2 py-1 rounded ${
                                            host.status === 'up' ? 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400' : 'bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-400'
                                          }`}>
                                            {host.status?.toUpperCase()}
                                          </span>
                                        </div>
                                        {host.hostname && <p className="text-xs text-gray-800 dark:text-gray-700">Hostname: <span className="font-mono">{host.hostname}</span></p>}
                                        {host.os_name && <p className="text-xs text-gray-800 dark:text-gray-700">OS: <span>{host.os_name}</span></p>}
                                        {host.ports && host.ports.length > 0 && (
                                          <div className="mt-2 pt-2 border-t border-gray-200 dark:border-neutral-700">
                                            <p className="text-xs font-medium text-gray-900 dark:text-gray-200 mb-2">Open Ports: {host.ports.filter((p: any) => p.state === 'open').length}</p>
                                            <div className="grid grid-cols-2 gap-2">
                                              {host.ports.filter((p: any) => p.state === 'open').map((port: any, portIdx: number) => (
                                                <div key={portIdx} className="text-xs bg-gray-50/50 dark:bg-neutral-800/50 backdrop-blur-sm rounded p-2 font-mono">
                                                  <span className="font-bold">{port.port}/{port.protocol}</span>
                                                  {port.service_name && <span className="text-gray-800 dark:text-gray-700"> - {port.service_name}</span>}
                                                </div>
                                              ))}
                                            </div>
                                          </div>
                                        )}
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                          )}

                          {/* Fallback for other tools */}
                          {result.tool_name !== 'nmap' && (
                            <div className="bg-white/80 dark:bg-neutral-800/80 backdrop-blur-sm rounded p-3 text-sm text-gray-900 dark:text-gray-200 overflow-x-auto max-h-64 overflow-y-auto">
                              <pre className="whitespace-pre-wrap break-words text-xs">
                                {JSON.stringify(result.data, null, 2)}
                              </pre>
                            </div>
                          )}

                          {result.timestamp && (
                            <p className="text-xs text-gray-700 dark:text-gray-400 mt-3 pt-3 border-t border-gray-200 dark:border-neutral-700">
                              Scan completed: {new Date(result.timestamp).toLocaleString()}
                            </p>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            ) : (
              <p className="text-center text-gray-700 dark:text-gray-400 py-8">
                No response available yet. Check back after the scan completes.
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default ScanDetailPage;
