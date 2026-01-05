import { useState, useEffect, useRef, useMemo, useCallback, memo } from 'react';
import { Link } from 'react-router-dom';
import { ScanEye, Trash2, ArrowDownToLine, Filter, Search } from 'lucide-react';
import { motion } from 'framer-motion';
import { scanApi } from '../api/client';
import { useWebSocket } from '../hooks/useWebSocket';
import type { Scan } from '../types';
import { formatDate, formatRelativeTime, getStatusBadgeClass } from '../utils/helpers';
import { InteractiveHoverButton } from './ui/interactive-hover-button';
import { useToast } from './ToastContainer';

// Memoized scan row component
const ScanRow = memo(({ scan, isSelected, onToggleSelect, onView, onDelete }: {
  scan: Scan;
  isSelected: boolean;
  onToggleSelect: (id: string) => void;
  onView: (id: string) => void;
  onDelete: (id: string) => void;
}) => (
  <motion.div
    initial={{ opacity: 0, y: 20 }}
    animate={{ opacity: 1, y: 0 }}
    className="glass p-4 hover:shadow-md transition-shadow contain-layout"
  >
    <div className="flex items-center gap-4">
      <input
        type="checkbox"
        checked={isSelected}
        onChange={() => onToggleSelect(scan.scan_id)}
        className="w-4 h-4"
      />
      <div className="flex-1">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">{scan.target}</h3>
          <span className={`badge ${getStatusBadgeClass(scan.status)}`}>
            {scan.status}
          </span>
        </div>
        <p className="text-sm text-gray-800 dark:text-gray-400 mt-1">
          {scan.tool_name} • {scan.scan_type} • {formatRelativeTime(scan.created_at)}
        </p>
      </div>
      <div className="flex gap-2">
        <button
          onClick={() => onView(scan.scan_id)}
          className="p-2 hover:bg-gray-100 rounded-lg"
          aria-label="View details"
        >
          <ScanEye className="w-4 h-4" />
        </button>
        <button
          onClick={() => onDelete(scan.scan_id)}
          className="p-2 hover:bg-red-100 text-red-600 rounded-lg"
          aria-label="Delete scan"
        >
          <Trash2 className="w-4 h-4" />
        </button>
      </div>
    </div>
  </motion.div>
));

ScanRow.displayName = 'ScanRow';

const ScanList = () => {
  const toast = useToast();
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  
  // Load filters from localStorage or use defaults
  const [filter, setFilter] = useState(() => {
    const saved = localStorage.getItem('scanListFilters');
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch {
        return { status: '', tool: '', search: '' };
      }
    }
    return { status: '', tool: '', search: '' };
  });
  
  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(25);
  
  const [selectedScans, setSelectedScans] = useState<Set<string>>(new Set());
  const [lastUpdateTime, setLastUpdateTime] = useState<Date | null>(null);
  const [showBulkExportMenu, setShowBulkExportMenu] = useState(false);
  const [bulkExporting, setBulkExporting] = useState(false);
  const bulkExportMenuRef = useRef<HTMLDivElement>(null);

  const { lastMessage, subscribe } = useWebSocket({
    onMessage: (msg) => {
      // Update scan in list when WebSocket message received
      setScans((prev) =>
        prev.map((scan) =>
          scan.scan_id === msg.scan_id
            ? { ...scan, ...msg.data }
            : scan
        )
      );
      setLastUpdateTime(new Date());
    },
  });

  // Save filters to localStorage whenever they change
  useEffect(() => {
    localStorage.setItem('scanListFilters', JSON.stringify(filter));
  }, [filter]);

  // Display last WebSocket update notification
  useEffect(() => {
    if (lastMessage) {
      console.log('WebSocket update received:', lastMessage);
    }
  }, [lastMessage]);

  const fetchScans = async () => {
    try {
      setLoading(true);
      const response = await scanApi.listScans({
        status: filter.status || undefined,
        tool_name: filter.tool || undefined,
      });
      setScans(response.scans);
      
      // Subscribe to all scans for real-time updates
      response.scans.forEach((scan) => {
        if (scan.status === 'running' || scan.status === 'queued') {
          subscribe(scan.scan_id);
        }
      });
    } catch (error) {
      console.error('Failed to fetch scans:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, [filter.status, filter.tool]);

  // Close bulk export menu when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (bulkExportMenuRef.current && !bulkExportMenuRef.current.contains(event.target as Node)) {
        setShowBulkExportMenu(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleDelete = async (scanId: string) => {
    if (!confirm('Are you sure you want to delete this scan?')) return;

    try {
      await scanApi.deleteScan(scanId);
      // Remove from UI
      setScans((prev) => prev.filter((s) => s.scan_id !== scanId));
      // Remove from selected scans if it was selected
      setSelectedScans((prev) => {
        const newSet = new Set(prev);
        newSet.delete(scanId);
        return newSet;
      });
      console.log('Scan deleted successfully:', scanId);
    } catch (error: any) {
      // If scan was already deleted (404), just remove it from UI
      if (error?.response?.status === 404) {
        console.log('Scan already deleted, removing from UI:', scanId);
        setScans((prev) => prev.filter((s) => s.scan_id !== scanId));
        setSelectedScans((prev) => {
          const newSet = new Set(prev);
          newSet.delete(scanId);
          return newSet;
        });
      } else {
        console.error('Failed to delete scan:', error);
        alert('Failed to delete scan. Please try again.');
      }
    }
  };

  const handleBulkDelete = async () => {
    if (selectedScans.size === 0) return;
    if (!confirm(`Delete ${selectedScans.size} selected scans?`)) return;

    try {
      const result = await scanApi.bulkDelete(Array.from(selectedScans));
      
      // Remove successfully deleted scans from UI
      setScans((prev) => prev.filter((s) => !selectedScans.has(s.scan_id)));
      setSelectedScans(new Set());
      
      // Show result if there were failures
      if (result?.failed && result.failed.length > 0) {
        console.warn('Some scans failed to delete:', result.failed);
        alert(`Deleted ${result.deleted || 0} scans. ${result.failed.length} scans could not be deleted.`);
      }
    } catch (error) {
      console.error('Failed to bulk delete:', error);
      // Still try to refresh the list to sync with backend
      fetchScans();
      alert('Some scans may have failed to delete. The list has been refreshed.');
    }
  };

  const handleBulkExport = async (format: 'json' | 'csv' | 'xlsx' | 'pdf') => {
    if (selectedScans.size === 0) return;

    setBulkExporting(true);
    setShowBulkExportMenu(false);

    try {
      const blob = await scanApi.bulkExport(Array.from(selectedScans), format);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `scans-bulk-export-${Date.now()}.zip`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
      
      // Show success toast
      toast.success(`Successfully exported ${selectedScans.size} scan${selectedScans.size > 1 ? 's' : ''} as ${format.toUpperCase()}`);
    } catch (error) {
      console.error('Failed to bulk export:', error);
      toast.error('Failed to export selected scans. Please try again.');
    } finally {
      setBulkExporting(false);
    }
  };

  const handleExport = async (scanId: string, format: 'json' | 'csv' | 'pdf') => {
    try {
      const blob = await scanApi.exportScan(scanId, format);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `scan-${scanId}.${format}`;
      a.click();
      
      // Show success toast
      toast.success(`Scan exported successfully as ${format.toUpperCase()}`);
    } catch (error) {
      console.error('Failed to export scan:', error);
      toast.error('Failed to export scan. Please try again.');
    }
  };

  const toggleScanSelection = useCallback((scanId: string) => {
    setSelectedScans(prev => {
      const newSet = new Set(prev);
      if (newSet.has(scanId)) {
        newSet.delete(scanId);
      } else {
        newSet.add(scanId);
      }
      return newSet;
    });
  }, []);

  const filteredScans = useMemo(() => 
    scans.filter((scan) =>
      filter.search
        ? scan.target.toLowerCase().includes(filter.search.toLowerCase()) ||
          scan.scan_id.toLowerCase().includes(filter.search.toLowerCase())
        : true
    ),
    [scans, filter.search]
  );

  // Paginated scans
  const paginatedScans = useMemo(() => {
    const startIndex = (currentPage - 1) * itemsPerPage;
    const endIndex = startIndex + itemsPerPage;
    return filteredScans.slice(startIndex, endIndex);
  }, [filteredScans, currentPage, itemsPerPage]);

  const totalPages = Math.ceil(filteredScans.length / itemsPerPage);

  // Reset to page 1 when filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [filter]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Scan History</h1>
          <p className="text-gray-800 dark:text-gray-400 mt-1">
            View and manage all vulnerability scans
            {lastUpdateTime && (
              <span className="ml-2 text-sm text-green-600 dark:text-green-400">
                • Live updates active (last: {formatRelativeTime(lastUpdateTime.toISOString())})
              </span>
            )}
          </p>
        </div>
        <div className="flex gap-3">
          <InteractiveHoverButton 
            onClick={fetchScans} 
            text={loading ? "Refreshing..." : "Refresh"}
            className="w-auto px-6"
          />
          <Link to="/scan/new">
            <InteractiveHoverButton text="New Scan" className="w-auto px-6" />
          </Link>
        </div>
      </div>

      {/* Filters */}
      <div className="card">
        <div className="flex flex-col md:flex-row gap-4">
          <div className="flex-1">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-700" />
              <input
                type="text"
                value={filter.search}
                onChange={(e) => setFilter({ ...filter, search: e.target.value })}
                placeholder="Search scans..."
                className="input pl-10"
              />
            </div>
          </div>
          <select
            value={filter.status}
            onChange={(e) => setFilter({ ...filter, status: e.target.value })}
            className="input md:w-48"
          >
            <option value="">All Statuses</option>
            <option value="pending">Pending</option>
            <option value="running">Running</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
          </select>
          <select
            value={filter.tool}
            onChange={(e) => setFilter({ ...filter, tool: e.target.value })}
            className="input md:w-48"
          >
            <option value="">All Tools</option>
            <option value="nmap">Nmap</option>
            <option value="openvas">OpenVAS</option>
            <option value="nikto">Nikto</option>
            <option value="nuclei">Nuclei</option>
          </select>
        </div>
      </div>

      {/* Bulk Actions */}
      {selectedScans.size > 0 && (
        <div className="card bg-primary-50 border border-primary-200">
          <div className="flex items-center justify-between">
            <p className="text-primary-900 font-medium">
              {selectedScans.size} scan{selectedScans.size > 1 ? 's' : ''} selected
            </p>
            <div className="flex gap-2">
              {/* Bulk Export Dropdown */}
              <div className="relative" ref={bulkExportMenuRef}>
                <InteractiveHoverButton
                  onClick={() => setShowBulkExportMenu(!showBulkExportMenu)}
                  disabled={bulkExporting}
                  text={bulkExporting ? "Exporting..." : "Export Selected"}
                  className="w-auto px-6"
                />
                
                {showBulkExportMenu && (
                  <motion.div
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="absolute right-0 mt-2 w-48 bg-white/90 dark:bg-neutral-800/90 backdrop-blur-md rounded-lg shadow-lg border border-white/20 dark:border-neutral-700/20 py-1 z-10"
                  >
                    <button
                      onClick={() => handleBulkExport('json')}
                      className="w-full px-4 py-2 text-left hover:bg-gray-100/60 dark:hover:bg-neutral-700/60 flex items-center gap-2 text-sm text-gray-900 dark:text-gray-200"
                    >
                      <ArrowDownToLine className="w-4 h-4 text-gray-900 dark:text-gray-300" />
                      <span>Export as JSON</span>
                    </button>
                    <button
                      onClick={() => handleBulkExport('csv')}
                      className="w-full px-4 py-2 text-left hover:bg-gray-100/60 dark:hover:bg-neutral-700/60 flex items-center gap-2 text-sm text-gray-900 dark:text-gray-200"
                    >
                      <ArrowDownToLine className="w-4 h-4 text-gray-900 dark:text-gray-300" />
                      <span>Export as CSV</span>
                    </button>
                    <button
                      onClick={() => handleBulkExport('xlsx')}
                      className="w-full px-4 py-2 text-left hover:bg-gray-100/60 dark:hover:bg-neutral-700/60 flex items-center gap-2 text-sm text-gray-900 dark:text-gray-200"
                    >
                      <ArrowDownToLine className="w-4 h-4 text-gray-900 dark:text-gray-300" />
                      <span>Export as Excel</span>
                    </button>
                    <button
                      onClick={() => handleBulkExport('pdf')}
                      className="w-full px-4 py-2 text-left hover:bg-gray-100/60 dark:hover:bg-neutral-700/60 flex items-center gap-2 text-sm text-gray-900 dark:text-gray-200"
                    >
                      <ArrowDownToLine className="w-4 h-4 text-gray-900 dark:text-gray-300" />
                      <span>Export as PDF</span>
                    </button>
                  </motion.div>
                )}
              </div>

              <InteractiveHoverButton 
                onClick={handleBulkDelete} 
                text="Delete Selected"
                className="w-auto px-6 bg-red-600 hover:bg-red-700"
              />
            </div>
          </div>
        </div>
      )}

      {/* Scan List */}
      <div className="card">
        {loading ? (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gradient-to-r from-gray-100/60 to-gray-200/40 dark:bg-neutral-800/50 backdrop-blur-sm border-b border-gray-300/60 dark:border-neutral-700">
                <tr>
                  <th className="p-4 text-left">
                    <div className="w-4 h-4 bg-gray-200 dark:bg-neutral-700 rounded animate-pulse"></div>
                  </th>
                  <th className="p-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-200">Target</th>
                  <th className="p-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-200">Tool</th>
                  <th className="p-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-200">Type</th>
                  <th className="p-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-200">Status</th>
                  <th className="p-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-200">Created</th>
                  <th className="p-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-200">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y dark:divide-neutral-700">
                {[...Array(5)].map((_, index) => (
                  <tr key={index} className="animate-pulse">
                    <td className="p-4">
                      <div className="w-4 h-4 bg-gray-200 dark:bg-neutral-700 rounded"></div>
                    </td>
                    <td className="p-4">
                      <div className="h-5 w-32 bg-gray-200 dark:bg-neutral-700 rounded"></div>
                    </td>
                    <td className="p-4">
                      <div className="h-5 w-20 bg-gray-200 dark:bg-neutral-700 rounded"></div>
                    </td>
                    <td className="p-4">
                      <div className="h-5 w-24 bg-gray-200 dark:bg-neutral-700 rounded"></div>
                    </td>
                    <td className="p-4">
                      <div className="h-6 w-20 bg-gray-200 dark:bg-neutral-700 rounded-full"></div>
                    </td>
                    <td className="p-4">
                      <div className="h-4 w-28 bg-gray-200 dark:bg-neutral-700 rounded"></div>
                    </td>
                    <td className="p-4">
                      <div className="flex items-center gap-2">
                        <div className="w-8 h-8 bg-gray-200 dark:bg-neutral-700 rounded-lg"></div>
                        <div className="w-8 h-8 bg-gray-200 dark:bg-neutral-700 rounded-lg"></div>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : filteredScans.length === 0 ? (
          <div className="text-center py-16">
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.5 }}
            >
              <div className="relative inline-block mb-4">
                <div className="absolute inset-0 bg-primary-500/20 rounded-full blur-xl"></div>
                <div className="relative backdrop-blur-sm bg-primary-500/10 p-6 rounded-full border border-primary-200 dark:border-primary-800">
                  <Filter className="w-12 h-12 text-primary-600 dark:text-primary-400" />
                </div>
              </div>
              <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
                No Scans Found
              </h3>
              <p className="text-gray-800 dark:text-gray-400 mb-6">
                {filter.search || filter.status || filter.tool
                  ? "Try adjusting your filters or search criteria"
                  : "Get started by creating your first vulnerability scan"}
              </p>
              {!filter.search && !filter.status && !filter.tool && (
                <Link to="/scan/new">
                  <InteractiveHoverButton text="Create New Scan" className="w-auto px-8" />
                </Link>
              )}
            </motion.div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gradient-to-r from-gray-100/60 to-gray-200/40 dark:bg-neutral-800/50 backdrop-blur-sm border-b border-gray-300/60 dark:border-neutral-700">
                <tr>
                  <th className="p-4 text-left">
                    <input
                      type="checkbox"
                      checked={selectedScans.size === filteredScans.length}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setSelectedScans(new Set(filteredScans.map((s) => s.scan_id)));
                        } else {
                          setSelectedScans(new Set());
                        }
                      }}
                    />
                  </th>
                  <th className="p-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-200">Target</th>
                  <th className="p-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-200">Tool</th>
                  <th className="p-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-200">Type</th>
                  <th className="p-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-200">Status</th>
                  <th className="p-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-200">Created</th>
                  <th className="p-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-200">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y dark:divide-neutral-700">
                {paginatedScans.map((scan, index) => (
                  <motion.tr
                    key={scan.scan_id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: index * 0.05, duration: 0.3 }}
                    whileHover={{ backgroundColor: 'rgba(0, 0, 0, 0.02)' }}
                    className="hover:bg-gray-50/50 dark:hover:bg-neutral-800/50 hover:shadow-sm transition-all duration-150"
                  >
                    <td className="p-4">
                      <input
                        type="checkbox"
                        checked={selectedScans.has(scan.scan_id)}
                        onChange={() => toggleScanSelection(scan.scan_id)}
                      />
                    </td>
                    <td className="p-4">
                      <Link
                        to={`/scans/${scan.scan_id}`}
                        className="font-medium text-primary-600 hover:text-primary-800"
                      >
                        {scan.target}
                      </Link>
                    </td>
                    <td className="p-4 text-gray-700 dark:text-gray-300">{scan.tool_name}</td>
                    <td className="p-4 text-gray-700 dark:text-gray-300">{scan.scan_type}</td>
                    <td className="p-4">
                      <span className={`badge ${getStatusBadgeClass(scan.status)}`}>
                        {scan.status}
                      </span>
                    </td>
                    <td className="p-4 text-gray-800 dark:text-gray-400 text-sm" title={formatDate(scan.created_at)}>
                      {formatRelativeTime(scan.created_at)}
                    </td>
                    <td className="p-4">
                      <div className="flex items-center gap-2">
                        <Link
                          to={`/scans/${scan.scan_id}`}
                          className="p-2 hover:bg-gray-100/60 dark:hover:bg-neutral-700/60 rounded-lg transition-all duration-200 hover:scale-110 hover:shadow-md"
                          title="View Details"
                        >
                          <ScanEye className="w-4 h-4 text-gray-800 dark:text-gray-300" />
                        </Link>
                        <button
                          onClick={() => handleExport(scan.scan_id, 'json')}
                          className="p-2 hover:bg-gray-100/60 dark:hover:bg-blue-900/30 rounded-lg transition-all duration-200 hover:scale-110 hover:shadow-md"
                          title="Export"
                        >
                          <ArrowDownToLine className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                        </button>
                        <button
                          onClick={() => handleDelete(scan.scan_id)}
                          className="p-2 hover:bg-red-50/60 dark:hover:bg-red-900/30 rounded-lg transition-all duration-200 hover:scale-110 hover:shadow-md"
                          title="Delete"
                        >
                          <Trash2 className="w-4 h-4 text-red-600 dark:text-red-400" />
                        </button>
                      </div>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        
        {/* Pagination Controls */}
        {!loading && filteredScans.length > 0 && (
          <div className="flex items-center justify-between px-4 py-3 border-t dark:border-neutral-700">
            <div className="flex items-center gap-4">
              <span className="text-sm text-gray-800 dark:text-gray-700">
                Showing {((currentPage - 1) * itemsPerPage) + 1} to {Math.min(currentPage * itemsPerPage, filteredScans.length)} of {filteredScans.length} scans
              </span>
              <select
                value={itemsPerPage}
                onChange={(e) => {
                  setItemsPerPage(Number(e.target.value));
                  setCurrentPage(1);
                }}
                className="px-3 py-1 border rounded-lg dark:bg-neutral-800 dark:border-neutral-700 text-sm"
              >
                <option value={10}>10 per page</option>
                <option value={25}>25 per page</option>
                <option value={50}>50 per page</option>
                <option value={100}>100 per page</option>
              </select>
            </div>
            
            <div className="flex items-center gap-2">
              <button
                onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                disabled={currentPage === 1}
                className="px-3 py-1 border rounded-lg hover:bg-gray-50 dark:hover:bg-neutral-800 dark:border-neutral-700 disabled:opacity-50 disabled:cursor-not-allowed text-sm"
              >
                Previous
              </button>
              
              <div className="flex items-center gap-1">
                {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                  let pageNum;
                  if (totalPages <= 5) {
                    pageNum = i + 1;
                  } else if (currentPage <= 3) {
                    pageNum = i + 1;
                  } else if (currentPage >= totalPages - 2) {
                    pageNum = totalPages - 4 + i;
                  } else {
                    pageNum = currentPage - 2 + i;
                  }
                  
                  return (
                    <button
                      key={pageNum}
                      onClick={() => setCurrentPage(pageNum)}
                      className={`px-3 py-1 rounded-lg text-sm transition-colors ${
                        currentPage === pageNum
                          ? 'bg-primary-600 text-white'
                          : 'hover:bg-gray-50 dark:hover:bg-neutral-800'
                      }`}
                    >
                      {pageNum}
                    </button>
                  );
                })}
              </div>
              
              <button
                onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                disabled={currentPage === totalPages}
                className="px-3 py-1 border rounded-lg hover:bg-gray-50 dark:hover:bg-neutral-800 dark:border-neutral-700 disabled:opacity-50 disabled:cursor-not-allowed text-sm"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ScanList;
