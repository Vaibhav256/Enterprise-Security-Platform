import { useState, useEffect } from 'react';
import { FileText, FileSpreadsheet, CalendarDays } from 'lucide-react';
import { motion } from 'framer-motion';
import axios from 'axios';
import type { Scan } from '../types';
import { InteractiveHoverButton } from '../components/ui/interactive-hover-button';

interface Report {
  report_id: string;
  scan_id: string;
  format: 'pdf' | 'excel';
  created_at: string;
  download_url: string;
}

interface GenerateReportRequest {
  scan_id: string;
  include_charts?: boolean;
  organization?: string;
  classification?: string;
}

const ReportsPage = () => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [selectedScan, setSelectedScan] = useState<string>('');
  const [reportOptions, setReportOptions] = useState({
    include_charts: true,
    organization: 'NTRO',
    classification: 'CONFIDENTIAL',
  });

  useEffect(() => {
    fetchScans();
  }, []);

  const fetchScans = async () => {
    try {
      const response = await axios.get('/api/scans');
      setScans(response.data.scans || []);
    } catch (error) {
      console.error('Failed to fetch scans:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchReportsForScan = async (scanId: string) => {
    try {
      const response = await axios.get(`/api/reports/scan/${scanId}`);
      setReports(response.data.reports || []);
    } catch (error) {
      console.error('Failed to fetch reports:', error);
      setReports([]);
    }
  };

  const generateReport = async (format: 'pdf' | 'excel') => {
    if (!selectedScan) {
      alert('Please select a scan first');
      return;
    }

    setGenerating(true);
    try {
      const endpoint = format === 'pdf' ? '/api/reports/pdf' : '/api/reports/excel';
      const request: GenerateReportRequest = {
        scan_id: selectedScan,
        ...reportOptions,
      };

      const response = await axios.post(endpoint, request);
      alert(`${format.toUpperCase()} report generated successfully!`);
      
      // Refresh reports list
      await fetchReportsForScan(selectedScan);
      
      // Auto-download - downloadUrl already includes /api/ prefix
      const downloadUrl = response.data.download_url;
      window.open(downloadUrl, '_blank');
    } catch (error: any) {
      console.error('Failed to generate report:', error);
      alert(error.response?.data?.error || 'Failed to generate report');
    } finally {
      setGenerating(false);
    }
  };

  const downloadReport = (reportId: string) => {
    // Download URL already includes /api/ prefix
    window.open(`/api/reports/${reportId}/download`, '_blank');
  };

  const deleteReport = async (reportId: string) => {
    if (!confirm('Are you sure you want to delete this report?')) return;

    try {
      await axios.delete(`/api/reports/${reportId}`);
      setReports(reports.filter(r => r.report_id !== reportId));
      alert('Report deleted successfully');
    } catch (error) {
      console.error('Failed to delete report:', error);
      alert('Failed to delete report');
    }
  };

  const handleScanChange = async (scanId: string) => {
    setSelectedScan(scanId);
    if (scanId) {
      await fetchReportsForScan(scanId);
    } else {
      setReports([]);
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="card"
      >
        <div className="flex items-center gap-3 mb-6">
          <motion.div
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            transition={{ type: "spring", stiffness: 200, delay: 0.2 }}
            className="p-3 bg-gray-100 dark:bg-blue-900/30 rounded-lg"
          >
            <FileText className="w-6 h-6 text-blue-600 dark:text-blue-400" />
          </motion.div>
          <div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Report Generation</h1>
            <p className="text-gray-800 dark:text-gray-700">Generate PDF and Excel reports for vulnerability scans</p>
          </div>
        </div>

        {/* Scan Selection */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.3 }}
          className="space-y-6"
        >
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Select Scan *
            </label>
            <select
              value={selectedScan}
              onChange={(e) => handleScanChange(e.target.value)}
              className="input w-full"
              disabled={loading}
            >
              <option value="">-- Choose a scan --</option>
              {scans.map((scan) => (
                <option key={scan.scan_id} value={scan.scan_id}>
                  {scan.scan_id} - {scan.target} ({new Date(scan.created_at).toLocaleDateString()})
                </option>
              ))}
            </select>
          </div>

          {/* Report Options */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
                Organization
              </label>
              <input
                type="text"
                value={reportOptions.organization}
                onChange={(e) => setReportOptions({ ...reportOptions, organization: e.target.value })}
                className="input w-full"
                placeholder="NTRO"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
                Classification
              </label>
              <select
                value={reportOptions.classification}
                onChange={(e) => setReportOptions({ ...reportOptions, classification: e.target.value })}
                className="input w-full"
              >
                <option value="PUBLIC">PUBLIC</option>
                <option value="INTERNAL">INTERNAL</option>
                <option value="CONFIDENTIAL">CONFIDENTIAL</option>
                <option value="SECRET">SECRET</option>
              </select>
            </div>
          </div>

          {/* Checkboxes */}
          <div className="space-y-3">
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={reportOptions.include_charts}
                onChange={(e) => setReportOptions({ ...reportOptions, include_charts: e.target.checked })}
                className="w-4 h-4 text-primary-600 rounded"
              />
              <span className="text-gray-700 dark:text-gray-300">Include Charts and Graphs</span>
              <span className="text-xs text-gray-900 dark:text-gray-300">(Excel reports only)</span>
            </label>
          </div>

          {/* Generate Buttons */}
          <div className="flex gap-3 pt-4 border-t">
            <InteractiveHoverButton
              onClick={() => generateReport('pdf')}
              disabled={!selectedScan || generating}
              text={generating ? "Generating..." : "PDF Report"}
              className="flex-1"
            />
            
            <InteractiveHoverButton
              onClick={() => generateReport('excel')}
              disabled={!selectedScan || generating}
              text={generating ? "Generating..." : "Excel Report"}
              className="flex-1 bg-green-600 hover:bg-green-700"
            />
          </div>
        </motion.div>
      </motion.div>

      {/* Reports List */}
      {selectedScan && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.5 }}
          className="card"
        >
          <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">Generated Reports</h2>

          {reports.length === 0 ? (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.6 }}
              className="text-center py-12"
            >
              <motion.div
                animate={{ y: [0, -10, 0] }}
                transition={{ duration: 2, repeat: Infinity }}
              >
                <FileText className="w-16 h-16 mx-auto mb-4 text-gray-300 dark:text-gray-600" />
              </motion.div>
              <p className="text-gray-700 dark:text-gray-400 font-medium">No reports generated yet</p>
              <p className="text-gray-700 dark:text-gray-500 text-sm mt-1">Generate your first report to get started</p>
            </motion.div>
          ) : (
            <div className="space-y-3">
              {reports.map((report) => (
                <motion.div
                  key={report.report_id}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="flex items-center justify-between p-4 bg-gray-50/50 dark:bg-neutral-800/50 backdrop-blur-sm rounded-lg hover:bg-gray-100/60 dark:hover:bg-neutral-700/60 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    {report.format === 'pdf' ? (
                      <FileText className="w-5 h-5 text-red-600" />
                    ) : (
                      <FileSpreadsheet className="w-5 h-5 text-green-600" />
                    )}
                    <div>
                      <p className="font-medium text-gray-900 dark:text-white">
                        {report.format.toUpperCase()} Report
                      </p>
                      <div className="flex items-center gap-2 text-sm text-gray-800 dark:text-gray-700">
                        <CalendarDays className="w-3 h-3" />
                        <span>{formatDate(report.created_at)}</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex gap-2">
                    <InteractiveHoverButton
                      onClick={() => downloadReport(report.report_id)}
                      text="Download"
                      className="w-auto px-6"
                    />

                    <InteractiveHoverButton
                      onClick={() => deleteReport(report.report_id)}
                      text="Delete"
                      className="w-auto px-6 bg-red-100 text-red-700 hover:bg-red-200 dark:bg-red-900/30 dark:text-red-300 dark:hover:bg-red-900/50"
                    />
                  </div>
                </motion.div>
              ))}
            </div>
          )}
        </motion.div>
      )}
    </div>
  );
};

export default ReportsPage;
