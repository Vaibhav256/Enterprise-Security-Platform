import { useState, useEffect, useMemo, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Crosshair, ShieldCheck, Zap, TriangleAlert, ChevronDown, Settings, CircleCheck, CircleX } from 'lucide-react';
import { motion } from 'framer-motion';
import { scanApi, toolsApi } from '../api/client';
import type { ScanTool, ScanType, CreateScanRequest } from '../types';
import { InteractiveHoverButton } from './ui/interactive-hover-button';

const ScanForm = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [toolsStatus, setToolsStatus] = useState<Record<string, { available: boolean; version?: string }>>({});
  const [loadingTools, setLoadingTools] = useState(true);
  
  const [formData, setFormData] = useState<CreateScanRequest>({
    target: '',
    tool_name: 'nmap',
    scan_type: 'quick',
    description: '',
    priority: 'normal',
    tags: [],
    options: {},
  });

  const [tagInput, setTagInput] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [advancedOptions, setAdvancedOptions] = useState<any>({
    // Nmap options
    ports: '',
    scripts: '',
    timing: 'T4',
    os_detection: false,
    service_detection: true,
    // Nikto options
    port: 80,
    ssl: false,
    timeout: 600,
    tuning: '1234567890ab',
    evasion: '',
    // Nuclei options
    severity: 'critical,high,medium,low,info',
    templates: '',
    tags: '',
    rate_limit: 150,
    concurrency: 25,
    retries: 1,
    follow_redirects: true,
    follow_host_redirects: false,
    max_redirects: 10,
    silent: false,
    verbose: false,
    // OpenVAS options
    scan_config: 'daba56c8-73ec-11df-a475-002264764cea',
    port_list: '33d0cd82-57c6-11e1-8ed1-406186ea4fc5',
    alive_test: 'ICMP Ping',
    max_checks: 4,
    max_hosts: 20,
    // Manual options for all tools
    manual_options: '',
  });

  const tools: { value: ScanTool; label: string; description: string }[] = [
    { value: 'nmap', label: 'Nmap', description: 'Network mapper for port scanning' },
    { value: 'openvas', label: 'OpenVAS', description: 'Comprehensive vulnerability scanner' },
    { value: 'nikto', label: 'Nikto', description: 'Web server vulnerability scanner' },
    { value: 'nuclei', label: 'Nuclei', description: 'Template-based vulnerability scanner' },
  ];

  // Tool-specific scan types (memoized function)
  const getScanTypesForTool = useCallback((tool: ScanTool): { value: ScanType; label: string; description: string }[] => {
    switch (tool) {
      case 'nmap':
        return [
          { value: 'quick', label: 'Quick', description: 'Fast scan of top 100 ports' },
          { value: 'basic', label: 'Basic', description: 'Top 1000 ports with service detection' },
          { value: 'full', label: 'Full', description: 'All 65535 ports (slow)' },
          { value: 'stealth', label: 'Stealth', description: 'SYN scan to evade detection' },
          { value: 'custom', label: 'Vulnerability Scan', description: 'Detect CVEs with vuln scripts' },
        ];
      case 'nikto':
        return [
          { value: 'quick', label: 'Quick', description: 'Essential web server tests' },
          { value: 'basic', label: 'Basic', description: 'Standard web vulnerability scan' },
          { value: 'full', label: 'Full Vulnerability Scan', description: 'Comprehensive web server testing' },
          { value: 'custom', label: 'Custom', description: 'Custom tuning options' },
        ];
      case 'nuclei':
        return [
          { value: 'basic', label: 'Basic', description: 'Critical & high severity templates' },
          { value: 'full', label: 'Full Vulnerability Scan', description: 'All severity levels (CVEs, misconfigs, exposures)' },
          { value: 'custom', label: 'CVE Only', description: 'Focus on known CVE vulnerabilities' },
        ];
      case 'openvas':
        return [
          { value: 'quick', label: 'Quick', description: 'Fast vulnerability assessment' },
          { value: 'basic', label: 'Basic', description: 'Standard vulnerability scan' },
          { value: 'full', label: 'Full Vulnerability Scan', description: 'Comprehensive security audit' },
          { value: 'custom', label: 'Custom', description: 'Custom scan configuration' },
        ];
      default:
        return [
          { value: 'quick', label: 'Quick', description: 'Fast scan' },
          { value: 'basic', label: 'Basic', description: 'Standard scan' },
          { value: 'full', label: 'Full', description: 'Comprehensive scan' },
          { value: 'custom', label: 'Custom', description: 'Custom configuration' },
        ];
    }
  }, []);

  const scanTypes = useMemo(() => getScanTypesForTool(formData.tool_name), [formData.tool_name, getScanTypesForTool]);

  // Validate target field inline
  const validateTarget = useCallback((target: string) => {
    if (!target.trim()) {
      return 'Target is required';
    }
    
    // Basic URL/IP/hostname validation
    const urlPattern = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/;
    const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
    const ipv6Pattern = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::1|::)$/;
    const hostnamePattern = /^[a-zA-Z0-9][a-zA-Z0-9-_.]*[a-zA-Z0-9]$/;
    const cidrPattern = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
    
    const isValid = urlPattern.test(target) || 
                    ipv4Pattern.test(target) || 
                    ipv6Pattern.test(target) || 
                    hostnamePattern.test(target) ||
                    cidrPattern.test(target) ||
                    target.includes(':'); // Allow port notation
    
    if (!isValid) {
      return 'Please enter a valid URL, IP address, hostname, or CIDR range';
    }
    
    return '';
  }, []);

  const handleTargetChange = useCallback((target: string) => {
    setFormData(prev => ({ ...prev, target }));
    
    // Validate after user stops typing
    const error = validateTarget(target);
    setFieldErrors(prev => ({ ...prev, target: error }));
  }, [validateTarget]);

  // Fetch tool availability on component mount
  useEffect(() => {
    const fetchToolsStatus = async () => {
      try {
        const response = await toolsApi.getTools();
        setToolsStatus(response.tools || {});
      } catch (err) {
        console.error('Failed to fetch tools status:', err);
      } finally {
        setLoadingTools(false);
      }
    };

    fetchToolsStatus();
  }, []);

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    // Validation
    if (!formData.target.trim()) {
      setError('Target IP/hostname/URL is required');
      return;
    }

    // Allow URLs, IPs, hostnames - backend will handle validation
    // Removed strict validation to support all target formats (URLs, IPv6, CIDR, ranges, etc.)

    try {
      setLoading(true);
      
      // Merge advanced options into request based on tool selected
      const baseOptions = { ...formData.options };
      
      // Tool-specific options
      if (formData.tool_name === 'nuclei') {
        // Nuclei options
        Object.assign(baseOptions, {
          ...(advancedOptions.severity && { severity: advancedOptions.severity }),
          ...(advancedOptions.templates && { templates: advancedOptions.templates }),
          ...(advancedOptions.tags && { tags: advancedOptions.tags }),
          ...(advancedOptions.rate_limit && { rate_limit: advancedOptions.rate_limit }),
          ...(advancedOptions.concurrency && { concurrency: advancedOptions.concurrency }),
          ...(advancedOptions.timeout && { timeout: advancedOptions.timeout }),
          ...(advancedOptions.retries && { retries: advancedOptions.retries }),
          follow_redirects: advancedOptions.follow_redirects,
          follow_host_redirects: advancedOptions.follow_host_redirects,
          ...(advancedOptions.max_redirects && { max_redirects: advancedOptions.max_redirects }),
          silent: advancedOptions.silent,
          verbose: advancedOptions.verbose,
        });
      } else if (formData.tool_name === 'nmap') {
        // Nmap options
        Object.assign(baseOptions, {
          ...(advancedOptions.ports && { ports: advancedOptions.ports }),
          ...(advancedOptions.scripts && { scripts: advancedOptions.scripts }),
          ...(advancedOptions.timing && { timing: advancedOptions.timing }),
          os_detection: advancedOptions.os_detection,
          service_detection: advancedOptions.service_detection,
        });
      } else if (formData.tool_name === 'nikto') {
        // Nikto options
        Object.assign(baseOptions, {
          ...(advancedOptions.port && { port: advancedOptions.port }),
          ssl: advancedOptions.ssl,
          ...(advancedOptions.timeout && { timeout: advancedOptions.timeout }),
          ...(advancedOptions.tuning && { tuning: advancedOptions.tuning }),
          ...(advancedOptions.evasion && { evasion: advancedOptions.evasion }),
        });
      } else if (formData.tool_name === 'openvas') {
        // OpenVAS options
        Object.assign(baseOptions, {
          ...(advancedOptions.scan_config && { scan_config: advancedOptions.scan_config }),
          ...(advancedOptions.port_list && { port_list: advancedOptions.port_list }),
          ...(advancedOptions.alive_test && { alive_test: advancedOptions.alive_test }),
          ...(advancedOptions.max_checks && { max_checks: advancedOptions.max_checks }),
          ...(advancedOptions.max_hosts && { max_hosts: advancedOptions.max_hosts }),
        });
      }
      
      const scanRequest: CreateScanRequest = {
        ...formData,
        options: {
          ...baseOptions,
          // Parse manual options JSON if provided
          ...(advancedOptions.manual_options && (() => {
            try {
              return JSON.parse(advancedOptions.manual_options);
            } catch (e) {
              console.warn('Invalid manual options JSON, skipping');
              return {};
            }
          })()),
        },
      };
      
      const scan = await scanApi.createScan(scanRequest);
      navigate(`/scans/${scan.scan_id}`);
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to create scan');
    } finally {
      setLoading(false);
    }
  }, [formData, advancedOptions, navigate]);

  const addTag = useCallback(() => {
    if (tagInput.trim() && !formData.tags?.includes(tagInput.trim())) {
      setFormData({
        ...formData,
        tags: [...(formData.tags || []), tagInput.trim()],
      });
      setTagInput('');
    }
  }, [tagInput, formData]);

  const removeTag = useCallback((tag: string) => {
    setFormData({
      ...formData,
      tags: formData.tags?.filter(t => t !== tag) || [],
    });
  }, [formData]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="max-w-4xl mx-auto"
    >
      <div className="card">
        <div className="flex items-center space-x-3 mb-6">
          <div className="p-3 bg-primary-100 rounded-lg">
            <Crosshair className="w-6 h-6 text-primary-600" />
          </div>
          <div>
            <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Create New Scan</h2>
            <p className="text-gray-800 dark:text-gray-700">Configure and launch a vulnerability scan</p>
          </div>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-danger-50 border border-danger-200 rounded-lg flex items-start space-x-3">
            <TriangleAlert className="w-5 h-5 text-danger-600 mt-0.5" />
            <p className="text-danger-800">{error}</p>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Target Input */}
          <div>
            <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
              Target (IP, Hostname, or URL) *
            </label>
            <input
              type="text"
              value={formData.target}
              onChange={(e) => handleTargetChange(e.target.value)}
              placeholder="scanme.nmap.org, http://example.com, 192.168.1.1, 2001:db8::1, 10.0.0.0/24"
              className={`input ${fieldErrors.target ? 'border-danger-500 focus:ring-danger-500' : ''}`}
              required
            />
            {fieldErrors.target && (
              <motion.p
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                className="mt-1 text-sm text-danger-600 dark:text-danger-400 flex items-center gap-1"
              >
                <TriangleAlert className="w-3.5 h-3.5" />
                {fieldErrors.target}
              </motion.p>
            )}
            {!fieldErrors.target && (
              <p className="mt-1 text-sm text-gray-800 dark:text-gray-700">
                Supports: URLs, IPv4, IPv6, hostnames, CIDR ranges, and port notation (e.g., example.com:8080)
              </p>
            )}
          </div>

          {/* Tool Selection */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
              Scanning Tool * {loadingTools && <span className="text-xs text-gray-700">(Checking availability...)</span>}
            </label>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {tools.map((tool, index) => {
                const status = toolsStatus[tool.value];
                const isAvailable = status?.available !== false; // Default to available if unknown
                
                return (
                  <motion.button
                    key={tool.value}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.1, duration: 0.3 }}
                    whileHover={{ scale: isAvailable ? 1.02 : 1 }}
                    whileTap={{ scale: isAvailable ? 0.98 : 1 }}
                    type="button"
                    onClick={() => setFormData({ ...formData, tool_name: tool.value })}
                    disabled={!isAvailable}
                    className={`p-4 border-2 rounded-lg text-left transition-all ${
                      formData.tool_name === tool.value
                        ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20'
                        : isAvailable
                        ? 'border-gray-200 dark:border-neutral-700 hover:border-gray-300 dark:hover:border-neutral-600'
                        : 'border-gray-200 dark:border-neutral-700 bg-gray-50/50 dark:bg-neutral-800/50 backdrop-blur-sm opacity-60 cursor-not-allowed'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-gray-900 dark:text-white">{tool.label}</span>
                        {!loadingTools && (
                          <motion.div
                            initial={{ scale: 0 }}
                            animate={{ scale: 1 }}
                            transition={{ delay: index * 0.1 + 0.2, type: 'spring', stiffness: 200 }}
                            title={isAvailable ? "Available" : "Not Available"}
                          >
                            {isAvailable ? (
                              <CircleCheck className="w-4 h-4 text-success-600" />
                            ) : (
                              <CircleX className="w-4 h-4 text-danger-600" />
                            )}
                          </motion.div>
                        )}
                      </div>
                      {formData.tool_name === tool.value && (
                        <motion.div
                          initial={{ scale: 0, rotate: -180 }}
                          animate={{ scale: 1, rotate: 0 }}
                          transition={{ type: 'spring', stiffness: 200 }}
                        >
                          <ShieldCheck className="w-5 h-5 text-primary-600" />
                        </motion.div>
                      )}
                    </div>
                    <p className="text-sm text-gray-800 dark:text-gray-700">{tool.description}</p>
                    {status?.version && (
                      <p className="text-xs text-gray-700 dark:text-gray-400 mt-1">Version: {status.version}</p>
                    )}
                    {!isAvailable && (
                      <p className="text-xs text-danger-600 mt-1 font-medium">Tool not available</p>
                    )}
                  </motion.button>
                );
              })}
            </div>
          </div>

          {/* Scan Type */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
              Scan Type *
            </label>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {scanTypes.map((type, index) => (
                <motion.button
                  key={type.value}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.4 + index * 0.1, duration: 0.3 }}
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  type="button"
                  onClick={() => setFormData({ ...formData, scan_type: type.value })}
                  className={`p-4 border-2 rounded-lg text-left transition-all ${
                    formData.scan_type === type.value
                      ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20'
                      : 'border-gray-200 dark:border-neutral-700 hover:border-gray-300 dark:hover:border-neutral-600'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-semibold text-gray-900 dark:text-white">{type.label}</span>
                    {formData.scan_type === type.value && (
                      <motion.div
                        initial={{ scale: 0, rotate: -180 }}
                        animate={{ scale: 1, rotate: 0 }}
                        transition={{ type: 'spring', stiffness: 200 }}
                      >
                        <Zap className="w-5 h-5 text-primary-600" />
                      </motion.div>
                    )}
                  </div>
                  <p className="text-sm text-gray-800 dark:text-gray-700">{type.description}</p>
                </motion.button>
              ))}
            </div>
          </div>

          {/* Description */}
          <div>
            <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
              Description (Optional)
            </label>
            <textarea
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              placeholder="Add notes about this scan..."
              rows={3}
              className="input resize-none"
            />
          </div>

          {/* Tags */}
          <div>
            <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
              Tags (Optional)
            </label>
            <div className="flex gap-2 mb-2">
              <input
                type="text"
                value={tagInput}
                onChange={(e) => setTagInput(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && (e.preventDefault(), addTag())}
                placeholder="Add tag..."
                className="input flex-1"
              />
              <InteractiveHoverButton
                type="button"
                onClick={addTag}
                text="Add"
                className="w-auto px-6"
              />
            </div>
            {formData.tags && formData.tags.length > 0 && (
              <div className="flex flex-wrap gap-2">
                {formData.tags.map((tag) => (
                  <span
                    key={tag}
                    className="px-3 py-1 bg-gray-100/80 text-gray-900 dark:text-gray-700 rounded-full text-sm flex items-center gap-2 ring-1 ring-gray-300/60 hover:bg-gray-200/60 transition-all duration-200"
                  >
                    {tag}
                    <button
                      type="button"
                      onClick={() => removeTag(tag)}
                      className="text-gray-700 hover:text-gray-900"
                    >
                      ×
                    </button>
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Advanced Options */}
          <div className="border-t dark:border-neutral-700 pt-6">
            <motion.button
              whileHover={{ x: 5 }}
              type="button"
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="flex items-center gap-2 text-gray-700 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white font-medium mb-4"
            >
              <Settings className="w-5 h-5" />
              <span>Advanced Options</span>
              <motion.div
                animate={{ rotate: showAdvanced ? 180 : 0 }}
                transition={{ duration: 0.3 }}
              >
                <ChevronDown className="w-4 h-4" />
              </motion.div>
            </motion.button>

            {showAdvanced && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                transition={{ duration: 0.3 }}
                className="space-y-4 bg-gradient-to-br from-gray-50/60 to-gray-100/40 dark:bg-neutral-800/50 backdrop-blur-sm p-4 rounded-lg border border-gray-300/40 dark:border-neutral-700/30 shadow-sm shadow-gray-200/20 dark:shadow-none"
              >
                {/* Nmap-specific options */}
                {formData.tool_name === 'nmap' && (
                  <>
                    <div>
                      <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
                        Port Range
                      </label>
                      <input
                        type="text"
                        value={advancedOptions.ports}
                        onChange={(e) => setAdvancedOptions({ ...advancedOptions, ports: e.target.value })}
                        placeholder="e.g., 1-1000, 80,443,8080"
                        className="input w-full"
                      />
                      <p className="text-xs text-gray-800 dark:text-gray-400 mt-1">
                        Specify custom port range or list (leave empty for default)
                      </p>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
                        🔍NSE Scripts (Vulnerability Detection)
                      </label>
                      <input
                        type="text"
                        value={advancedOptions.scripts}
                        onChange={(e) => setAdvancedOptions({ ...advancedOptions, scripts: e.target.value })}
                        placeholder="vuln (for vulnerability scan) or default,exploit,malware"
                        className="input w-full"
                      />
                      <p className="text-xs text-gray-800 dark:text-gray-400 mt-1">
                        <strong>Use "vuln"</strong> to detect vulnerabilities with CVE ratings. Other options: default, exploit, malware, auth, brute
                      </p>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
                        Timing Template
                      </label>
                      <select
                        value={advancedOptions.timing}
                        onChange={(e) => setAdvancedOptions({ ...advancedOptions, timing: e.target.value })}
                        className="input w-full"
                      >
                        <option value="T0">T0 - Paranoid (slowest)</option>
                        <option value="T1">T1 - Sneaky</option>
                        <option value="T2">T2 - Polite</option>
                        <option value="T3">T3 - Normal</option>
                        <option value="T4">T4 - Aggressive (default)</option>
                        <option value="T5">T5 - Insane (fastest)</option>
                      </select>
                    </div>

                    <div className="flex gap-4">
                      <label className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={advancedOptions.os_detection}
                          onChange={(e) => setAdvancedOptions({ ...advancedOptions, os_detection: e.target.checked })}
                          className="w-4 h-4 text-primary-600 rounded"
                        />
                        <span className="text-sm text-gray-700">Enable OS Detection</span>
                      </label>

                      <label className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={advancedOptions.service_detection}
                          onChange={(e) => setAdvancedOptions({ ...advancedOptions, service_detection: e.target.checked })}
                          className="w-4 h-4 text-primary-600 rounded"
                        />
                        <span className="text-sm text-gray-700">Enable Service Detection</span>
                      </label>
                    </div>
                  </>
                )}

                {/* OpenVAS options */}
                {formData.tool_name === 'openvas' && (
                  <>
                    <div className="bg-green-50 border border-green-200 rounded p-3 mb-4">
                      <p className="text-sm text-green-800">
                        <strong>💡 Tip:</strong> OpenVAS provides enterprise-grade vulnerability scanning with NVT (Network Vulnerability Tests).
                        Use "Full" scan for comprehensive security audit with CVE detection and compliance checks.
                      </p>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
                        Scan Configuration
                      </label>
                      <select
                        value={advancedOptions.scan_config || 'daba56c8-73ec-11df-a475-002264764cea'}
                        onChange={(e) => setAdvancedOptions({ ...advancedOptions, scan_config: e.target.value })}
                        className="input w-full"
                      >
                        <option value="daba56c8-73ec-11df-a475-002264764cea">Full and Fast (Default)</option>
                        <option value="8715c877-47a0-438d-98a3-27c7a6ab2196">Discovery</option>
                        <option value="085569ce-73ed-11df-83c3-002264764cea">Full and Very Deep</option>
                        <option value="2d3f051c-55ba-11e3-bf43-406186ea4fc5">System Discovery</option>
                      </select>
                      <p className="text-xs text-gray-800 dark:text-gray-400 mt-1">
                        Choose the scan configuration profile
                      </p>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
                        Port List
                      </label>
                      <select
                        value={advancedOptions.port_list || '33d0cd82-57c6-11e1-8ed1-406186ea4fc5'}
                        onChange={(e) => setAdvancedOptions({ ...advancedOptions, port_list: e.target.value })}
                        className="input w-full"
                      >
                        <option value="33d0cd82-57c6-11e1-8ed1-406186ea4fc5">All TCP + Top 100 UDP (Default)</option>
                        <option value="4a4717fe-57d2-11e1-9a26-406186ea4fc5">All IANA TCP</option>
                        <option value="730ef368-57e2-11e1-a90f-406186ea4fc5">All TCP</option>
                        <option value="c7e03b6c-3bbe-11e1-a057-406186ea4fc5">All Privileged TCP</option>
                      </select>
                      <p className="text-xs text-gray-800 dark:text-gray-400 mt-1">
                        Define which ports to scan
                      </p>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
                        Alive Test
                      </label>
                      <select
                        value={advancedOptions.alive_test || 'ICMP Ping'}
                        onChange={(e) => setAdvancedOptions({ ...advancedOptions, alive_test: e.target.value })}
                        className="input w-full"
                      >
                        <option value="ICMP Ping">ICMP Ping (Default)</option>
                        <option value="TCP-ACK Service Ping">TCP-ACK Service Ping</option>
                        <option value="TCP-SYN Service Ping">TCP-SYN Service Ping</option>
                        <option value="ARP Ping">ARP Ping</option>
                        <option value="ICMP & TCP-ACK Service Ping">ICMP & TCP-ACK Service Ping</option>
                        <option value="ICMP & ARP Ping">ICMP & ARP Ping</option>
                        <option value="Consider Alive">Consider Alive</option>
                      </select>
                      <p className="text-xs text-gray-800 dark:text-gray-400 mt-1">
                        Method to determine if host is alive
                      </p>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
                          Max Concurrent Checks
                        </label>
                        <input
                          type="number"
                          min="1"
                          max="20"
                          value={advancedOptions.max_checks || 4}
                          onChange={(e) => setAdvancedOptions({ ...advancedOptions, max_checks: parseInt(e.target.value) })}
                          className="input w-full"
                        />
                        <p className="text-xs text-gray-800 dark:text-gray-400 mt-1">
                          Checks per host (1-20)
                        </p>
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
                          Max Concurrent Hosts
                        </label>
                        <input
                          type="number"
                          min="1"
                          max="50"
                          value={advancedOptions.max_hosts || 20}
                          onChange={(e) => setAdvancedOptions({ ...advancedOptions, max_hosts: parseInt(e.target.value) })}
                          className="input w-full"
                        />
                        <p className="text-xs text-gray-800 dark:text-gray-400 mt-1">
                          Hosts in parallel (1-50)
                        </p>
                      </div>
                    </div>
                  </>
                )}

                {/* Nikto options */}
                {formData.tool_name === 'nikto' && (
                  <>
                    <div className="bg-gray-50 border border-gray-300 rounded p-3 mb-4">
                      <p className="text-sm text-blue-800">
                        <strong>💡 Tip:</strong> Nikto automatically scans for web vulnerabilities. 
                        Use "Full" scan type for comprehensive CVE detection, or customize tuning below.
                      </p>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
                          Port
                        </label>
                        <input
                          type="number"
                          min="1"
                          max="65535"
                          value={advancedOptions.port || 80}
                          onChange={(e) => setAdvancedOptions({ ...advancedOptions, port: parseInt(e.target.value) })}
                          className="input w-full"
                        />
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
                          Timeout (seconds)
                        </label>
                        <input
                          type="number"
                          min="60"
                          max="3600"
                          step="60"
                          value={advancedOptions.timeout || 600}
                          onChange={(e) => setAdvancedOptions({ ...advancedOptions, timeout: parseInt(e.target.value) })}
                          className="input w-full"
                        />
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <label className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={advancedOptions.ssl || false}
                          onChange={(e) => setAdvancedOptions({ ...advancedOptions, ssl: e.target.checked })}
                          className="w-4 h-4 text-primary-600 rounded"
                        />
                        <span className="text-sm text-gray-700">Use SSL/HTTPS</span>
                      </label>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
                        🔍 Tuning Options (Vulnerability Categories)
                      </label>
                      <input
                        type="text"
                        value={advancedOptions.tuning || '1234567890ab'}
                        onChange={(e) => setAdvancedOptions({ ...advancedOptions, tuning: e.target.value })}
                        placeholder="Default: 1234567890ab (all tests)"
                        className="input w-full"
                      />
                      <p className="text-xs text-gray-800 dark:text-gray-400 mt-1">
                        <strong>Recommended for vulns:</strong> "1234567890ab" (all), "479" (injection/RCE/SQLi), or "b" (SSL/TLS issues)
                      </p>
                      <details className="mt-2 text-xs text-gray-600">
                        <summary className="cursor-pointer hover:text-gray-800 font-medium">View tuning codes</summary>
                        <div className="mt-2 space-y-1 pl-4 border-l-2 border-gray-200">
                          <div><strong>1:</strong> Interesting files</div>
                          <div><strong>2:</strong> Misconfiguration</div>
                          <div><strong>3:</strong> Information disclosure</div>
                          <div><strong>4:</strong> Injection (XSS/SQL)</div>
                          <div><strong>5:</strong> Remote file inclusion</div>
                          <div><strong>6:</strong> Denial of service</div>
                          <div><strong>7:</strong> Remote code execution</div>
                          <div><strong>8:</strong> Command execution</div>
                          <div><strong>9:</strong> SQL injection</div>
                          <div><strong>0:</strong> File upload</div>
                          <div><strong>a:</strong> Authentication bypass</div>
                          <div><strong>b:</strong> Software identification</div>
                        </div>
                      </details>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
                        Evasion Technique (Optional)
                      </label>
                      <select
                        value={advancedOptions.evasion || ''}
                        onChange={(e) => setAdvancedOptions({ ...advancedOptions, evasion: e.target.value })}
                        className="input w-full"
                      >
                        <option value="">None</option>
                        <option value="1">1 - Random URI encoding</option>
                        <option value="2">2 - Directory self-reference</option>
                        <option value="3">3 - Premature URL ending</option>
                        <option value="4">4 - Prepend long random string</option>
                        <option value="5">5 - Fake parameter</option>
                        <option value="6">6 - TAB as request spacer</option>
                        <option value="7">7 - Change the case</option>
                        <option value="8">8 - Use Windows directory separator</option>
                      </select>
                      <p className="text-xs text-gray-800 dark:text-gray-400 mt-1">
                        IDS/IPS evasion techniques
                      </p>
                    </div>
                  </>
                )}

                {/* Nuclei options */}
                {formData.tool_name === 'nuclei' && (
                  <>
                    <div className="bg-purple-50 border border-purple-200 rounded p-3 mb-4">
                      <p className="text-sm text-purple-800">
                        <strong>💡 Tip:</strong> Nuclei uses community templates to detect CVEs, misconfigurations, and exposures.
                        Select "Full" scan for all vulnerabilities, or "CVE Only" for known exploits.
                      </p>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
                        🎯 Severity Levels (CVE Filtering)
                      </label>
                      <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
                        {[
                          { value: 'critical', label: 'Critical', color: 'red' },
                          { value: 'high', label: 'High', color: 'orange' },
                          { value: 'medium', label: 'Medium', color: 'yellow' },
                          { value: 'low', label: 'Low', color: 'blue' },
                          { value: 'info', label: 'Info', color: 'gray' }
                        ].map((severity) => {
                          const isSelected = (advancedOptions.severity || 'critical,high,medium,low,info')
                            .split(',').includes(severity.value);
                          return (
                            <button
                              key={severity.value}
                              type="button"
                              onClick={() => {
                                const current = (advancedOptions.severity || 'critical,high,medium,low,info').split(',');
                                const updated = isSelected
                                  ? current.filter((s: string) => s !== severity.value)
                                  : [...current, severity.value];
                                setAdvancedOptions({ ...advancedOptions, severity: updated.join(',') });
                              }}
                              className={`px-3 py-2 text-sm rounded-lg border-2 transition-all ${
                                isSelected
                                  ? `border-${severity.color}-500 bg-${severity.color}-50 text-${severity.color}-700`
                                  : 'border-gray-200 bg-white text-gray-600 hover:border-gray-300'
                              }`}
                            >
                              {severity.label}
                            </button>
                          );
                        })}
                      </div>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
                        Tags (Optional)
                      </label>
                      <input
                        type="text"
                        value={advancedOptions.tags || ''}
                        onChange={(e) => setAdvancedOptions({ ...advancedOptions, tags: e.target.value })}
                        placeholder="e.g., cve,rce,sqli"
                        className="input w-full"
                      />
                      <p className="text-xs text-gray-800 dark:text-gray-400 mt-1">
                        Comma-separated tags to filter templates (e.g., cve, misconfig, exposure, rce, sqli, xss)
                      </p>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
                        Template Path (Optional)
                      </label>
                      <input
                        type="text"
                        value={advancedOptions.templates || ''}
                        onChange={(e) => setAdvancedOptions({ ...advancedOptions, templates: e.target.value })}
                        placeholder="e.g., cves/ or exposures/"
                        className="input w-full"
                      />
                      <p className="text-xs text-gray-800 dark:text-gray-400 mt-1">
                        Specific template directory or file (leave empty for all templates)
                      </p>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
                          Rate Limit (req/s)
                        </label>
                        <input
                          type="number"
                          min="1"
                          max="500"
                          value={advancedOptions.rate_limit || 150}
                          onChange={(e) => setAdvancedOptions({ ...advancedOptions, rate_limit: parseInt(e.target.value) })}
                          className="input w-full"
                        />
                        <p className="text-xs text-gray-800 dark:text-gray-400 mt-1">
                          Requests per second (1-500)
                        </p>
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
                          Concurrency
                        </label>
                        <input
                          type="number"
                          min="1"
                          max="100"
                          value={advancedOptions.concurrency || 25}
                          onChange={(e) => setAdvancedOptions({ ...advancedOptions, concurrency: parseInt(e.target.value) })}
                          className="input w-full"
                        />
                        <p className="text-xs text-gray-800 dark:text-gray-400 mt-1">
                          Parallel templates (1-100)
                        </p>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
                          Timeout (seconds)
                        </label>
                        <input
                          type="number"
                          min="300"
                          max="1800"
                          step="60"
                          value={advancedOptions.timeout || 1800}
                          onChange={(e) => setAdvancedOptions({ ...advancedOptions, timeout: parseInt(e.target.value) })}
                          className="input w-full"
                        />
                        <p className="text-xs text-gray-800 dark:text-gray-400 mt-1">
                          Scan timeout in seconds (min 5 min, max 30 min). Nuclei scans on real targets typically take 5-15 minutes.
                        </p>
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
                          Retries
                        </label>
                        <input
                          type="number"
                          min="0"
                          max="5"
                          value={advancedOptions.retries || 1}
                          onChange={(e) => setAdvancedOptions({ ...advancedOptions, retries: parseInt(e.target.value) })}
                          className="input w-full"
                        />
                      </div>
                    </div>

                    <div className="space-y-2">
                      <label className="block text-sm font-medium text-gray-700">
                        Redirect Options
                      </label>
                      <label className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={advancedOptions.follow_redirects !== false}
                          onChange={(e) => setAdvancedOptions({ ...advancedOptions, follow_redirects: e.target.checked })}
                          className="w-4 h-4 text-primary-600 rounded"
                        />
                        <span className="text-sm text-gray-700">Follow HTTP redirects</span>
                      </label>
                      <label className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={advancedOptions.follow_host_redirects || false}
                          onChange={(e) => setAdvancedOptions({ ...advancedOptions, follow_host_redirects: e.target.checked })}
                          className="w-4 h-4 text-primary-600 rounded"
                        />
                        <span className="text-sm text-gray-700">Follow redirects to other hosts</span>
                      </label>
                      <div className="ml-6">
                        <label className="block text-xs text-gray-600 mb-1">
                          Max Redirects
                        </label>
                        <input
                          type="number"
                          min="1"
                          max="50"
                          value={advancedOptions.max_redirects || 10}
                          onChange={(e) => setAdvancedOptions({ ...advancedOptions, max_redirects: parseInt(e.target.value) })}
                          className="input w-32 text-sm"
                        />
                      </div>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
                        Verbosity
                      </label>
                      <select
                        value={advancedOptions.verbose ? 'verbose' : (advancedOptions.silent ? 'silent' : 'normal')}
                        onChange={(e) => {
                          if (e.target.value === 'silent') {
                            setAdvancedOptions({ ...advancedOptions, silent: true, verbose: false });
                          } else if (e.target.value === 'verbose') {
                            setAdvancedOptions({ ...advancedOptions, silent: false, verbose: true });
                          } else {
                            setAdvancedOptions({ ...advancedOptions, silent: false, verbose: false });
                          }
                        }}
                        className="input w-full"
                      >
                        <option value="silent">Silent (minimal output)</option>
                        <option value="normal">Normal</option>
                        <option value="verbose">Verbose (detailed output)</option>
                      </select>
                    </div>
                  </>
                )}

                {/* Manual options for all tools */}
                <div className="border-t pt-4 mt-4">
                  <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
                    Manual Options (JSON Format)
                  </label>
                  <textarea
                    value={advancedOptions.manual_options}
                    onChange={(e) => setAdvancedOptions({ ...advancedOptions, manual_options: e.target.value })}
                    placeholder='{"custom_option": "value", "another_option": true}'
                    rows={4}
                    className="input resize-none font-mono text-sm"
                  />
                  <p className="text-xs text-gray-700 dark:text-gray-400 mt-1">
                    Add custom options in JSON format. These will override default settings.
                    Example: {`{"timeout": 300, "max_retries": 3}`}
                  </p>
                </div>
              </motion.div>
            )}
          </div>

          {/* Priority */}
          <div>
            <label className="block text-sm font-medium text-gray-900 dark:text-gray-200 mb-2">
              Priority
            </label>
            <select
              value={formData.priority}
              onChange={(e) => setFormData({ ...formData, priority: e.target.value as any })}
              className="input"
            >
              <option value="low">Low</option>
              <option value="normal">Normal</option>
              <option value="high">High</option>
            </select>
          </div>

          {/* Submit Button */}
          <div className="flex gap-3">
            <InteractiveHoverButton
              type="submit"
              disabled={loading}
              text={loading ? "Creating..." : "Start Scan"}
              className="flex-1 w-full"
            />
            <InteractiveHoverButton
              type="button"
              onClick={() => navigate('/scans')}
              text="Cancel"
              className="w-auto px-6 bg-gradient-to-r from-gray-100 to-gray-100 text-gray-800 hover:from-gray-200 hover:to-gray-200 shadow-sm hover:shadow-md dark:bg-neutral-700 dark:text-gray-300 dark:hover:bg-neutral-600 dark:from-neutral-700 dark:to-neutral-700 transition-all duration-200"
            />
          </div>
        </form>
      </div>
    </motion.div>
  );
};

export default ScanForm;
