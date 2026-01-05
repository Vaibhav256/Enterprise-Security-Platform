import { useState, useEffect } from 'react';
import { RotateCw, Database, Zap, BellRing, CircleCheck } from 'lucide-react';
import { motion } from 'framer-motion';
import { InteractiveHoverButton } from '../components/ui/interactive-hover-button';

const SettingsPage = () => {
  const [settings, setSettings] = useState({
    apiUrl: 'http://localhost:5000',
    dashboardRefresh: 10,
    scanRefresh: 5,
    enableNotifications: true,
    enableWebSocket: true,
    maxScansPerPage: 20,
  });

  const [initialSettings, setInitialSettings] = useState(settings);
  const [saved, setSaved] = useState(false);
  const [hasUnsavedChanges, setHasUnsavedChanges] = useState(false);
  const [apiUrlError, setApiUrlError] = useState('');

  // Validate API URL
  const validateApiUrl = (url: string): string => {
    if (!url.trim()) {
      return 'API URL is required';
    }
    
    try {
      const parsedUrl = new URL(url);
      if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
        return 'URL must use HTTP or HTTPS protocol';
      }
      return '';
    } catch {
      return 'Please enter a valid URL (e.g., http://localhost:5000)';
    }
  };

  // Check for unsaved changes
  useEffect(() => {
    const changed = JSON.stringify(settings) !== JSON.stringify(initialSettings);
    setHasUnsavedChanges(changed);
  }, [settings, initialSettings]);

  // Warn before leaving with unsaved changes
  useEffect(() => {
    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      if (hasUnsavedChanges) {
        e.preventDefault();
        e.returnValue = '';
      }
    };

    window.addEventListener('beforeunload', handleBeforeUnload);
    return () => window.removeEventListener('beforeunload', handleBeforeUnload);
  }, [hasUnsavedChanges]);

  const handleApiUrlChange = (url: string) => {
    setSettings({ ...settings, apiUrl: url });
    const error = validateApiUrl(url);
    setApiUrlError(error);
  };

  const handleSave = () => {
    // Validate before saving
    const error = validateApiUrl(settings.apiUrl);
    if (error) {
      setApiUrlError(error);
      return;
    }

    // Save to localStorage
    localStorage.setItem('app_settings', JSON.stringify(settings));
    setInitialSettings(settings);
    setSaved(true);
    setHasUnsavedChanges(false);
    setTimeout(() => setSaved(false), 3000);
  };

  const handleReset = () => {
    const defaultSettings = {
      apiUrl: 'http://localhost:5000',
      dashboardRefresh: 10,
      scanRefresh: 5,
      enableNotifications: true,
      enableWebSocket: true,
      maxScansPerPage: 20,
    };
    setSettings(defaultSettings);
    localStorage.removeItem('app_settings');
  };

  return (
    <div className="max-w-4xl mx-auto">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="card"
      >
        <div className="flex items-center justify-between mb-6">
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.2 }}
          >
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Settings</h1>
            <p className="text-gray-800 dark:text-gray-400 mt-1">Configure application preferences</p>
          </motion.div>
          {saved && (
            <motion.div
              initial={{ opacity: 0, scale: 0.8, x: 20 }}
              animate={{ opacity: 1, scale: 1, x: 0 }}
              exit={{ opacity: 0, scale: 0.8 }}
              className="bg-gradient-to-r from-green-500 to-green-600 text-white px-4 py-2 rounded-lg flex items-center gap-2 shadow-lg"
            >
              <CircleCheck className="w-4 h-4" />
              <span className="font-medium">Settings saved!</span>
            </motion.div>
          )}
        </div>

        {/* API Settings */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3, duration: 0.4 }}
          className="mb-8"
        >
          <div className="flex items-center gap-2 mb-4">
            <motion.div
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ delay: 0.4, type: 'spring', stiffness: 200 }}
            >
              <Database className="w-5 h-5 text-primary-600" />
            </motion.div>
            <h2 className="text-xl font-semibold text-gray-900 dark:text-white">API Configuration</h2>
          </div>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Backend API URL
              </label>
              <input
                type="text"
                value={settings.apiUrl}
                onChange={(e) => handleApiUrlChange(e.target.value)}
                className={`input w-full ${apiUrlError ? 'border-danger-500 focus:ring-danger-500' : ''}`}
                placeholder="http://localhost:5000"
              />
              {apiUrlError ? (
                <motion.p
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="text-xs text-danger-600 dark:text-danger-400 mt-1"
                >
                  {apiUrlError}
                </motion.p>
              ) : (
                <p className="text-xs text-gray-700 dark:text-gray-400 mt-1">
                  Base URL for the vulnerability scanner API
                </p>
              )}
            </div>
          </div>
        </motion.div>

        {/* Refresh Settings */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4, duration: 0.4 }}
          className="mb-8"
        >
          <div className="flex items-center gap-2 mb-4">
            <motion.div
              initial={{ scale: 0 }}
              animate={{ scale: 1, rotate: 360 }}
              transition={{ delay: 0.5, type: 'spring', stiffness: 200 }}
            >
              <RotateCw className="w-5 h-5 text-primary-600" />
            </motion.div>
            <h2 className="text-xl font-semibold text-gray-900 dark:text-white">Auto-Refresh</h2>
          </div>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Dashboard Refresh Interval (seconds)
              </label>
              <input
                type="number"
                value={settings.dashboardRefresh}
                onChange={(e) =>
                  setSettings({ ...settings, dashboardRefresh: parseInt(e.target.value) })
                }
                className="input w-full"
                min="5"
                max="60"
              />
              <p className="text-xs text-gray-700 dark:text-gray-400 mt-1">
                How often to refresh statistics on the dashboard
              </p>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Scan Detail Refresh Interval (seconds)
              </label>
              <input
                type="number"
                value={settings.scanRefresh}
                onChange={(e) =>
                  setSettings({ ...settings, scanRefresh: parseInt(e.target.value) })
                }
                className="input w-full"
                min="3"
                max="30"
              />
              <p className="text-xs text-gray-700 dark:text-gray-400 mt-1">
                How often to refresh running scan details
              </p>
            </div>
          </div>
        </motion.div>

        {/* Display Settings */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5, duration: 0.4 }}
          className="mb-8"
        >
          <div className="flex items-center gap-2 mb-4">
            <motion.div
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ delay: 0.6, type: 'spring', stiffness: 200 }}
            >
              <Zap className="w-5 h-5 text-primary-600" />
            </motion.div>
            <h2 className="text-xl font-semibold text-gray-900 dark:text-white">Display & Performance</h2>
          </div>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Scans Per Page
              </label>
              <select
                value={settings.maxScansPerPage}
                onChange={(e) =>
                  setSettings({ ...settings, maxScansPerPage: parseInt(e.target.value) })
                }
                className="input w-full"
              >
                <option value={10}>10</option>
                <option value={20}>20</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
              </select>
              <p className="text-xs text-gray-700 dark:text-gray-400 mt-1">
                Number of scans to display per page
              </p>
            </div>
            <motion.div
              whileHover={{ scale: 1.01 }}
              className="flex items-center justify-between p-4 bg-gradient-to-br from-gray-50/40 to-gray-100/30 dark:bg-neutral-800/50 backdrop-blur-sm rounded-lg border border-gray-300/50 dark:border-neutral-700/30 shadow-sm"
            >
              <div>
                <p className="font-medium text-gray-900 dark:text-white">Enable WebSocket</p>
                <p className="text-sm text-gray-800 dark:text-gray-700">Real-time scan status updates</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={settings.enableWebSocket}
                  onChange={(e) =>
                    setSettings({ ...settings, enableWebSocket: e.target.checked })
                  }
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white/80 dark:bg-neutral-800/80 backdrop-blur-sm after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
              </label>
            </motion.div>
          </div>
        </motion.div>

        {/* Notification Settings */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6, duration: 0.4 }}
          className="mb-8"
        >
          <div className="flex items-center gap-2 mb-4">
            <motion.div
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ delay: 0.7, type: 'spring', stiffness: 200 }}
            >
              <BellRing className="w-5 h-5 text-primary-600" />
            </motion.div>
            <h2 className="text-xl font-semibold text-gray-900 dark:text-white">Notifications</h2>
          </div>
          <motion.div
            whileHover={{ scale: 1.01 }}
            className="flex items-center justify-between p-4 bg-gradient-to-br from-gray-50/40 to-gray-100/30 dark:bg-neutral-800/50 backdrop-blur-sm rounded-lg border border-gray-300/50 dark:border-neutral-700/30 shadow-sm"
          >
            <div>
              <p className="font-medium text-gray-900 dark:text-white">Enable Notifications</p>
              <p className="text-sm text-gray-800 dark:text-gray-700">Browser notifications for scan completion</p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={settings.enableNotifications}
                onChange={(e) =>
                  setSettings({ ...settings, enableNotifications: e.target.checked })
                }
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white/80 dark:bg-neutral-800/80 backdrop-blur-sm after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
            </label>
          </motion.div>
        </motion.div>

        {/* Action Buttons */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.7, duration: 0.4 }}
          className="pt-6 border-t dark:border-neutral-700 space-y-4"
        >
          {hasUnsavedChanges && !saved && (
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className="bg-warning-50 dark:bg-warning-900/20 border border-warning-200 dark:border-warning-800 rounded-lg p-3"
            >
              <p className="text-sm text-warning-800 dark:text-warning-200">
                You have unsaved changes. Save them before leaving this page.
              </p>
            </motion.div>
          )}
          
          <div className="flex gap-3">
            <InteractiveHoverButton 
              onClick={handleSave} 
              text={saved ? "Saved!" : hasUnsavedChanges ? "Save Changes" : "Save Settings"}
              className={`w-auto px-6 ${saved ? 'bg-green-500 hover:bg-green-600' : ''}`}
              disabled={!hasUnsavedChanges && !saved}
            />
            <InteractiveHoverButton
              onClick={handleReset}
              text="Reset to Defaults"
              className="w-auto px-6 bg-gray-100 text-gray-700 hover:bg-gray-200 dark:bg-neutral-700 dark:text-gray-300 dark:hover:bg-neutral-600"
            />
          </div>
        </motion.div>
      </motion.div>
    </div>
  );
};

export default SettingsPage;
