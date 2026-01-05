import { useState, useEffect } from 'react';
import { TrendingUp } from 'lucide-react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { feedsApi } from '../api/client';
import { TextShimmer } from '../components/ui/text-shimmer';
import { InteractiveHoverButton } from '../components/ui/interactive-hover-button';

interface CVE {
  cve_id?: string;
  id?: string;
  entry_id?: string;
  description?: string;
  title?: string;
  cvss_score?: number;
  severity?: string;
  published_date?: string;
  references?: string[];
}

interface FeedStatus {
  nvd?: { last_update: string; status: string };
  exploitdb?: { last_update: string; status: string };
  [key: string]: any;
}

const FeedsPage = () => {
  const [activeTab, setActiveTab] = useState<'search' | 'recent'>('recent');
  const [feedStatus, setFeedStatus] = useState<FeedStatus | null>(null);
  const [recentCVEs, setRecentCVEs] = useState<CVE[]>([]);
  const [searchResults, setSearchResults] = useState<CVE[]>([]);
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  
  const [searchParams, setSearchParams] = useState({
    keyword: '',
    severity: '',
    days: 7,
  });

  useEffect(() => {
    console.log('[FeedsPage] Mounted, fetching feed status...');
    fetchFeedStatus();
    if (activeTab === 'recent') {
      fetchRecentCVEs();
    }
  }, [activeTab]);

  const fetchFeedStatus = async () => {
    try {
      console.log('[FeedsPage] Fetching feed status from API...');
      const response = await feedsApi.getStatus();
      console.log('[FeedsPage] Feed status received:', response);
      setFeedStatus(response.data || response);
    } catch (error) {
      console.error('[FeedsPage] Failed to fetch feed status:', error);
    }
  };

  const fetchRecentCVEs = async () => {
    setLoading(true);
    try {
      console.log('[FeedsPage] Fetching recent CVEs...');
      const response = await feedsApi.getRecent({ days: 7, limit: 50 });
      console.log('[FeedsPage] Recent CVEs received:', response);
      setRecentCVEs(response.data || []);
    } catch (error) {
      console.error('[FeedsPage] Failed to fetch recent CVEs:', error);
    } finally {
      setLoading(false);
    }
  };

  const searchVulnerabilities = async () => {
    if (!searchParams.keyword.trim()) {
      alert('Please enter a search keyword');
      return;
    }

    setLoading(true);
    try {
      const response = await feedsApi.search({
        keyword: searchParams.keyword,
        severity: searchParams.severity || undefined,
        days: searchParams.days,
      });
      setSearchResults(response.data || []);
    } catch (error) {
      console.error('Failed to search vulnerabilities:', error);
      alert('Search failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const refreshFeeds = async () => {
    setRefreshing(true);
    try {
      await feedsApi.refresh(true);
      alert('Feeds refreshed successfully!');
      await fetchFeedStatus();
      if (activeTab === 'recent') {
        await fetchRecentCVEs();
      }
    } catch (error: any) {
      console.error('Failed to refresh feeds:', error);
      alert(error.response?.data?.error || 'Failed to refresh feeds');
    } finally {
      setRefreshing(false);
    }
  };

  return (
    <div className="max-w-7xl mx-auto">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="card mb-6"
      >
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <motion.div
              initial={{ scale: 0, rotate: -180 }}
              animate={{ scale: 1, rotate: 0 }}
              transition={{ delay: 0.2, type: 'spring', stiffness: 200 }}
              className="p-3 bg-purple-100 dark:bg-purple-900/20 rounded-lg"
            >
              <TrendingUp className="w-6 h-6 text-purple-600" />
            </motion.div>
            <motion.div
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.3 }}
            >
              <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Threat Intelligence Feeds</h1>
              <p className="text-gray-800 dark:text-gray-700">CVE database and vulnerability intelligence</p>
            </motion.div>
          </div>

          <motion.div
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.4 }}
          >
            <InteractiveHoverButton
              onClick={refreshFeeds}
              disabled={refreshing}
              text={refreshing ? "Refreshing..." : "Refresh Feeds"}
              className="w-auto px-6"
            />
          </motion.div>
        </div>

        {/* Feed Status */}
        {feedStatus && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
            {feedStatus.nvd && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.5 }}
                whileHover={{ scale: 1.02 }}
                className="p-4 bg-gray-50 dark:bg-blue-900/20 rounded-lg border border-gray-300 dark:border-blue-800"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-semibold text-gray-900 dark:text-blue-300">NVD Database</p>
                    <p className="text-sm text-gray-800 dark:text-blue-400">Last updated: {feedStatus.nvd.last_update}</p>
                  </div>
                  <div className={`px-3 py-1 rounded-full text-xs font-medium ${
                    feedStatus.nvd.status === 'active' ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400' : 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-400'
                  }`}>
                    {feedStatus.nvd.status}
                  </div>
                </div>
              </motion.div>
            )}

            {feedStatus.exploitdb && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.6 }}
                whileHover={{ scale: 1.02 }}
                className="p-4 bg-green-50 dark:bg-green-900/20 rounded-lg border border-green-200 dark:border-green-800"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-semibold text-green-900 dark:text-green-300">ExploitDB</p>
                    <p className="text-sm text-green-700 dark:text-green-400">Last updated: {feedStatus.exploitdb.last_update}</p>
                  </div>
                  <div className={`px-3 py-1 rounded-full text-xs font-medium ${
                    feedStatus.exploitdb.status === 'active' ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400' : 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-400'
                  }`}>
                    {feedStatus.exploitdb.status}
                  </div>
                </div>
              </motion.div>
            )}
          </div>
        )}
      </motion.div>

      {/* Tabs */}
      <div className="mb-6 border-b dark:border-neutral-700">
        <div className="flex gap-4">
          <button
            onClick={() => setActiveTab('recent')}
            className={`pb-3 px-4 font-medium transition-colors border-b-2 ${
              activeTab === 'recent'
                ? 'border-primary-600 text-primary-600'
                : 'border-transparent text-gray-900 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            Recent CVEs
          </button>
          <button
            onClick={() => setActiveTab('search')}
            className={`pb-3 px-4 font-medium transition-colors border-b-2 ${
              activeTab === 'search'
                ? 'border-primary-600 text-primary-600'
                : 'border-transparent text-gray-900 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            Search
          </button>
        </div>
      </div>

      {/* Search Tab */}
      {activeTab === 'search' && (
        <div className="card mb-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            <div className="md:col-span-2">
              <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
                Search Keyword
              </label>
              <input
                type="text"
                value={searchParams.keyword}
                onChange={(e) => setSearchParams({ ...searchParams, keyword: e.target.value })}
                placeholder="Enter CVE ID, keyword, or description..."
                className="input w-full"
                onKeyPress={(e) => e.key === 'Enter' && searchVulnerabilities()}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
                Severity Filter
              </label>
              <select
                value={searchParams.severity}
                onChange={(e) => setSearchParams({ ...searchParams, severity: e.target.value })}
                className="input w-full"
              >
                <option value="">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="flex-1">
              <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
                Time Range (days)
              </label>
              <input
                type="number"
                value={searchParams.days}
                onChange={(e) => setSearchParams({ ...searchParams, days: parseInt(e.target.value) || 7 })}
                min="1"
                max="365"
                className="input w-full"
              />
            </div>

            <InteractiveHoverButton
              onClick={searchVulnerabilities}
              disabled={loading}
              text={loading ? "Searching..." : "Search"}
              className="w-auto px-6 mt-7"
            />
          </div>

          {/* Search Results */}
          {searchResults.length > 0 && (
            <div className="mt-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                Search Results ({searchResults.length})
              </h3>
              <CVEList cves={searchResults} />
            </div>
          )}
        </div>
      )}

      {/* Recent CVEs Tab */}
      {activeTab === 'recent' && (
        <div className="card">
          <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">
            Recently Published CVEs
          </h2>

          {loading ? (
            <div className="text-center py-12">
              <TextShimmer duration={1.5} className="text-base">
                Loading recent CVEs...
              </TextShimmer>
            </div>
          ) : recentCVEs.length === 0 ? (
            <div className="text-center py-12 text-gray-900 dark:text-gray-300">
              <TrendingUp className="w-12 h-12 mx-auto mb-3 text-gray-300 dark:text-gray-600" />
              <p>No recent CVEs found</p>
            </div>
          ) : (
            <CVEList cves={recentCVEs} />
          )}
        </div>
      )}
    </div>
  );
};

// CVE List Component
const CVEList = ({ cves }: { cves: CVE[] }) => {
  const getSeverityColor = (severity?: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'text-red-700 dark:text-red-400 bg-red-100 dark:bg-red-900/20 border-red-300 dark:border-red-800';
      case 'high': return 'text-orange-700 dark:text-orange-400 bg-orange-100 dark:bg-orange-900/20 border-orange-300 dark:border-orange-800';
      case 'medium': return 'text-yellow-700 dark:text-yellow-400 bg-yellow-100 dark:bg-yellow-900/20 border-yellow-300 dark:border-yellow-800';
      case 'low': return 'text-gray-800 dark:text-blue-400 bg-gray-100 dark:bg-blue-900/20 border-gray-400 dark:border-blue-800';
      default: return 'text-gray-700 dark:text-gray-400 bg-gray-100 dark:bg-gray-800/50 border-gray-300 dark:border-gray-700';
    }
  };

  const formatDate = (dateString?: string) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleDateString();
  };

  const getCveId = (cve: CVE): string => {
    return cve.cve_id || cve.entry_id || cve.id || 'Unknown';
  };

  const getDescription = (cve: CVE): string => {
    return cve.description || cve.title || 'No description available';
  };

  return (
    <div className="space-y-3">
      {cves.map((cve, idx) => (
        <motion.div
          key={getCveId(cve) || idx}
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: idx * 0.05 }}
          className="p-4 bg-gradient-to-br from-gray-50/50 to-gray-100/30 dark:bg-neutral-800/50 backdrop-blur-sm rounded-lg hover:from-gray-100/60 hover:to-gray-200/40 dark:hover:bg-neutral-700/60 shadow-sm hover:shadow-md transition-all duration-200"
        >
          <div className="flex items-start justify-between gap-4">
            <div className="flex-1">
              <div className="flex items-center gap-3 mb-2">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">{getCveId(cve)}</h3>
                {cve.severity && (
                  <span className={`px-3 py-1 rounded-full text-xs font-medium border ${getSeverityColor(cve.severity)}`}>
                    {cve.severity}
                  </span>
                )}
                {cve.cvss_score !== undefined && (
                  <span className="px-3 py-1 bg-purple-100 dark:bg-purple-900/20 text-purple-700 dark:text-purple-400 border border-purple-300 dark:border-purple-800 rounded-full text-xs font-medium">
                    CVSS: {cve.cvss_score.toFixed(1)}
                  </span>
                )}
              </div>

              <p className="text-gray-900 dark:text-gray-200 mb-2">{getDescription(cve)}</p>

              <div className="flex items-center gap-4 text-sm">
                <span className="text-gray-800 dark:text-gray-700">Published: {formatDate(cve.published_date)}</span>
                <Link to={`/feeds/cve/${getCveId(cve)}`}>
                  <InteractiveHoverButton 
                    text="View Details"
                    className="w-auto px-4 text-xs"
                  />
                </Link>
              </div>
            </div>
          </div>
        </motion.div>
      ))}
    </div>
  );
};

export default FeedsPage;
