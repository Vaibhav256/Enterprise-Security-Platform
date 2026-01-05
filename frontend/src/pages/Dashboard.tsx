import { useState, useEffect, useMemo, memo } from 'react';
import { Zap, ShieldCheck, ShieldAlert, CircleCheck, TrendingUp } from 'lucide-react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import { statsApi, scanApi } from '../api/client';
import type { Statistics, Scan } from '../types';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { formatRelativeTime, getStatusBadgeClass } from '../utils/helpers';
import { InteractiveHoverButton } from '../components/ui/interactive-hover-button';

// Memoized stat card component
const StatCard = memo(({ icon: Icon, title, value, color, trend }: {
  icon: any;
  title: string;
  value: number | string;
  color: string;
  trend?: string;
}) => (
  <motion.div
    initial={{ opacity: 0, scale: 0.95 }}
    animate={{ opacity: 1, scale: 1 }}
    className="card contain-layout ring-1 ring-gray-200/50 dark:ring-0"
  >
    <div className="flex items-center justify-between">
      <div>
        <p className="text-sm text-gray-800 dark:text-gray-400 mb-1">{title}</p>
        <p className={`text-3xl font-bold ${color}`}>{value}</p>
        {trend && <p className="text-xs text-gray-700 dark:text-gray-400 mt-1">{trend}</p>}
      </div>
      <Icon className={`w-12 h-12 ${color} opacity-20`} />
    </div>
  </motion.div>
));

StatCard.displayName = 'StatCard';

// Memoized recent scan item component
const RecentScanItem = memo(({ scan }: { scan: Scan }) => (
  <motion.div
    whileHover={{ scale: 1.005 }}
    transition={{ duration: 0.2 }}
    className="p-4 border rounded-lg hover:border-primary-500 dark:hover:border-primary-400 hover:bg-primary-50/50 dark:hover:bg-primary-900/20 transition-all contain-layout backdrop-blur-sm bg-white dark:bg-neutral-800/50 shadow-md shadow-gray-200/30 dark:shadow-none ring-1 ring-gray-200/40 dark:ring-0"
  >
    <div className="flex items-center justify-between gap-4">
      <div className="flex-1">
        <p className="font-medium text-gray-900 dark:text-white">{scan.target}</p>
        <p className="text-sm text-gray-800 dark:text-gray-400 mt-1">
          {scan.tool_name} • {scan.scan_type}
        </p>
        <div className="flex items-center gap-2 mt-2">
          <span className={`badge ${getStatusBadgeClass(scan.status)}`}>
            {scan.status}
          </span>
          <span className="text-xs text-gray-900 dark:text-gray-300">
            {formatRelativeTime(scan.created_at)}
          </span>
        </div>
      </div>
      <Link to={`/scans/${scan.scan_id}`}>
        <InteractiveHoverButton 
          text="View Details"
          className="w-auto px-4 text-sm"
        />
      </Link>
    </div>
  </motion.div>
));

RecentScanItem.displayName = 'RecentScanItem';

const Dashboard = () => {
  const [stats, setStats] = useState<Statistics | null>(null);
  const [recentScans, setRecentScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [statsData, scansData] = await Promise.all([
          statsApi.getStats(),
          scanApi.listScans({ per_page: 5 }),
        ]);
        setStats(statsData);
        setRecentScans(scansData.scans);
      } catch (error) {
        console.error('Failed to fetch dashboard data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 10000); // Refresh every 10s
    return () => clearInterval(interval);
  }, []);

  // Memoize chart data to prevent recalculation on every render
  const vulnData = useMemo(() => {
    if (!stats) return [];
    return [
      { name: 'Critical', value: stats.vulnerabilities.critical, color: '#dc2626', label: `Critical: ${stats.vulnerabilities.critical} vulnerabilities` },
      { name: 'High', value: stats.vulnerabilities.high, color: '#ea580c', label: `High: ${stats.vulnerabilities.high} vulnerabilities` },
      { name: 'Medium', value: stats.vulnerabilities.medium, color: '#f59e0b', label: `Medium: ${stats.vulnerabilities.medium} vulnerabilities` },
      { name: 'Low', value: stats.vulnerabilities.low, color: '#0ea5e9', label: `Low: ${stats.vulnerabilities.low} vulnerabilities` },
      { name: 'Info', value: stats.vulnerabilities.info, color: '#6b7280', label: `Info: ${stats.vulnerabilities.info} vulnerabilities` },
    ].filter(item => item.value > 0);  // Filter out zero values
  }, [stats]);

  const toolUsageData = useMemo(() => {
    if (!stats?.tool_usage) return [];
    return Object.entries(stats.tool_usage).map(([name, value]) => ({ name, value }));
  }, [stats?.tool_usage]);

  if (loading) {
    return (
      <div className="space-y-6 animate-in fade-in duration-500">
        {/* Header Skeleton */}
        <div className="space-y-2">
          <div className="h-9 w-48 bg-gray-200/50 dark:bg-neutral-700/50 rounded-lg animate-pulse"></div>
          <div className="h-5 w-64 bg-gray-200/50 dark:bg-neutral-700/50 rounded-lg animate-pulse"></div>
        </div>

        {/* Stats Cards Skeleton */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {[0, 1, 2, 3].map((i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.1 }}
              className="card h-24 bg-gradient-to-br from-gray-100 to-gray-200 dark:from-neutral-800 dark:to-neutral-900 animate-pulse"
            />
          ))}
        </div>

        {/* Charts Skeleton */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {[0, 1].map((i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.4 + i * 0.1 }}
              className="card h-[350px] bg-gradient-to-br from-gray-100 to-gray-200 dark:from-neutral-800 dark:to-neutral-900 animate-pulse"
            />
          ))}
        </div>

        {/* Recent Scans Skeleton */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6 }}
          className="card h-64 bg-gradient-to-br from-gray-100 to-gray-200 dark:from-neutral-800 dark:to-neutral-900 animate-pulse"
        />
      </div>
    );
  }

  const COLORS = ['#0ea5e9', '#8b5cf6', '#ec4899', '#f59e0b', '#10b981'];

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Dashboard</h1>
        <p className="text-gray-800 dark:text-gray-400 mt-1">Overview of vulnerability scanning activity</p>
      </motion.div>

      {/* Stats Cards with stagger animation */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <motion.div
          initial={{ opacity: 0, scale: 0.9, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.1 }}
          whileHover={{ scale: 1.02, transition: { duration: 0.2 } }}
          className="card bg-gradient-to-br from-gray-600 to-gray-700 text-white shadow-lg shadow-gray-500/20 gpu-accelerated cursor-pointer overflow-hidden relative"
          role="region"
          aria-label={`Total Scans: ${stats?.total_scans || 0}`}
        >
          <div className="flex items-center justify-between">
            <div className="z-10 relative">
              <p className="text-blue-50 text-sm font-medium">Total Scans</p>
              <motion.p
                initial={{ opacity: 0, scale: 0.5 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.5, delay: 0.3 }}
                className="text-3xl font-bold mt-1"
              >
                {stats?.total_scans || 0}
              </motion.p>
              {stats && stats.total_scans > 0 && (
                <motion.div
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.3, delay: 0.8 }}
                  className="flex items-center gap-1 mt-2 text-blue-50 text-xs"
                >
                  <TrendingUp className="w-3 h-3" />
                  <span>+12% this week</span>
                </motion.div>
              )}
            </div>
            <div className="relative">
              <div className="absolute inset-0 bg-white/20 rounded-lg blur-xl" />
              <div className="relative backdrop-blur-sm bg-white/10 p-3 rounded-lg border border-white/20">
                <ShieldCheck className="w-12 h-12" />
              </div>
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, scale: 0.9, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.2 }}
          whileHover={{ scale: 1.02, transition: { duration: 0.2 } }}
          className="card bg-gradient-to-br from-green-400 to-green-500 text-white shadow-lg shadow-green-400/20 gpu-accelerated cursor-pointer overflow-hidden relative"
          role="region"
          aria-label={`Completed Scans: ${stats?.status_breakdown.completed || 0}`}
        >
          <div className="flex items-center justify-between">
            <div className="z-10 relative">
              <p className="text-green-50 text-sm font-medium">Completed</p>
              <motion.p
                initial={{ opacity: 0, scale: 0.5 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.5, delay: 0.4 }}
                className="text-3xl font-bold mt-1"
              >
                {stats?.status_breakdown.completed || 0}
              </motion.p>
              {stats && stats.status_breakdown.completed > 0 && (
                <motion.div
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.3, delay: 0.8 }}
                  className="flex items-center gap-1 mt-2 text-green-50 text-xs"
                >
                  <TrendingUp className="w-3 h-3" />
                  <span>+8% this week</span>
                </motion.div>
              )}
            </div>
            <div className="relative">
              <div className="absolute inset-0 bg-white/20 rounded-lg blur-xl" />
              <div className="relative backdrop-blur-sm bg-white/10 p-3 rounded-lg border border-white/20">
                <CircleCheck className="w-12 h-12" />
              </div>
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, scale: 0.9, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.3 }}
          whileHover={{ scale: 1.02, transition: { duration: 0.2 } }}
          className="card bg-gradient-to-br from-orange-400 to-orange-500 text-white shadow-lg shadow-orange-400/20 gpu-accelerated cursor-pointer overflow-hidden relative"
          role="region"
          aria-label={`Running Scans: ${stats?.status_breakdown.running || 0}`}
        >
          <div className="flex items-center justify-between">
            <div className="z-10 relative">
              <p className="text-orange-50 text-sm font-medium">Running</p>
              <motion.p
                initial={{ opacity: 0, scale: 0.5 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.5, delay: 0.5 }}
                className="text-3xl font-bold mt-1"
              >
                {stats?.status_breakdown.running || 0}
              </motion.p>
              {stats && stats.status_breakdown.running > 0 && (
                <motion.div
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.3, delay: 0.8 }}
                  className="flex items-center gap-1 mt-2 text-orange-50 text-xs"
                >
                  <Zap className="w-3 h-3" />
                  <span>Active now</span>
                </motion.div>
              )}
            </div>
            <div className="relative">
              <div className="absolute inset-0 bg-white/20 rounded-lg blur-xl" />
              <div className="relative backdrop-blur-sm bg-white/10 p-3 rounded-lg border border-white/20">
                <Zap className="w-12 h-12" />
              </div>
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, scale: 0.9, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.4 }}
          whileHover={{ scale: 1.02, transition: { duration: 0.2 } }}
          className="card bg-gradient-to-br from-red-400 to-red-500 text-white shadow-lg shadow-red-400/20 gpu-accelerated cursor-pointer overflow-hidden relative"
          role="region"
          aria-label={`Critical Vulnerabilities: ${stats?.vulnerabilities.critical || 0}`}
        >
          <div className="flex items-center justify-between">
            <div className="z-10 relative">
              <p className="text-red-50 text-sm font-medium">Critical Vulns</p>
              <motion.p
                initial={{ opacity: 0, scale: 0.5 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.5, delay: 0.6 }}
                className="text-3xl font-bold mt-1"
              >
                {stats?.vulnerabilities.critical || 0}
              </motion.p>
              {stats && stats.vulnerabilities.critical > 0 && (
                <motion.div
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.3, delay: 0.8 }}
                  className="flex items-center gap-1 mt-2 text-red-50 text-xs"
                >
                  <TrendingUp className="w-3 h-3" />
                  <span>Requires attention</span>
                </motion.div>
              )}
            </div>
            <div className="relative">
              <div className="absolute inset-0 bg-white/20 rounded-lg blur-xl" />
              <div className="relative backdrop-blur-sm bg-white/10 p-3 rounded-lg border border-white/20">
                <ShieldAlert className="w-12 h-12" />
              </div>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Vulnerability Severity Distribution */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.5, delay: 0.6 }}
          className="card contain-layout"
        >
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Vulnerability Severity</h3>
          {vulnData.length > 0 ? (
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.5, delay: 0.8 }}
            >
              <ResponsiveContainer width="100%" height={400}>
                <PieChart>
                  <Pie
                    data={vulnData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ label }) => String(label)}
                    outerRadius={130}
                    fill="#8884d8"
                    dataKey="value"
                    animationBegin={0}
                    animationDuration={800}
                  >
                    {vulnData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip formatter={(value: number, name: string) => [`${value} vulnerabilities`, name]} />
                </PieChart>
              </ResponsiveContainer>
            </motion.div>
          ) : (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ duration: 0.5, delay: 0.8 }}
              className="h-[400px] flex items-center justify-center bg-gradient-to-br from-gray-50/60 to-gray-100/40 dark:bg-neutral-800/50 backdrop-blur-sm rounded-lg border border-gray-300/60 dark:border-neutral-700 shadow-sm shadow-gray-200/20 dark:shadow-none"
            >
              <div className="text-center">
                <motion.div
                  className="relative inline-block"
                >
                  <div className="absolute inset-0 bg-primary-500/20 rounded-lg blur-xl" />
                  <div className="relative backdrop-blur-sm bg-white/10 dark:bg-black/10 p-4 rounded-lg border border-white/20 dark:border-white/10 mx-auto mb-3">
                    <ShieldCheck className="w-12 h-12 text-gray-900 dark:text-gray-300" />
                  </div>
                </motion.div>
                <p className="text-gray-700 dark:text-gray-400 font-medium">No vulnerabilities found</p>
                <p className="text-gray-700 dark:text-gray-500 text-sm mt-1">Start a scan to begin</p>
              </div>
            </motion.div>
          )}
        </motion.div>

        {/* Tool Usage */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.5, delay: 0.7 }}
          className="card contain-layout"
        >
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Tool Usage</h3>
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5, delay: 0.9 }}
          >
            <ResponsiveContainer width="100%" height={400}>
              <BarChart data={toolUsageData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" opacity={0.2} />
                <XAxis dataKey="name" stroke="#6b7280" />
                <YAxis stroke="#6b7280" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'rgba(255, 255, 255, 0.9)',
                    border: '1px solid #e5e7eb',
                    borderRadius: '8px',
                  }}
                  formatter={(value) => [`${value} scans`, 'Count']}
                />
                <Bar dataKey="value" fill="#0ea5e9" animationBegin={0} animationDuration={800} radius={[8, 8, 0, 0]}>
                  {toolUsageData.map((_, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          </motion.div>
        </motion.div>
      </div>

      {/* Recent Scans */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 1.0 }}
        className="card contain-layout"
      >
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Recent Scans</h3>
          <Link to="/scans">
            <InteractiveHoverButton 
              text="View All"
              className="w-auto px-4 text-sm"
            />
          </Link>
        </div>
        <div className="space-y-3">
          {recentScans.length === 0 ? (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="text-center py-12"
            >
              <motion.div
                className="relative inline-block"
              >
                <div className="absolute inset-0 bg-primary-500/20 rounded-lg blur-2xl" />
                <div className="relative backdrop-blur-sm bg-white/10 dark:bg-black/10 p-5 rounded-lg border border-white/20 dark:border-white/10 mx-auto mb-4">
                  <ShieldCheck className="w-16 h-16 text-gray-900 dark:text-gray-300" />
                </div>
              </motion.div>
              <p className="text-gray-700 dark:text-gray-400 font-medium">No scans yet</p>
              <p className="text-gray-700 dark:text-gray-500 text-sm mt-1">Create your first scan to get started</p>
            </motion.div>
          ) : (
            recentScans.map((scan, index) => (
              <motion.div
                key={scan.scan_id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.3, delay: 1.1 + index * 0.1 }}
              >
                <RecentScanItem scan={scan} />
              </motion.div>
            ))
          )}
        </div>
      </motion.div>
    </div>
  );
};

export default Dashboard;
