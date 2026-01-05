import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ExternalLink, AlertTriangle } from 'lucide-react';
import { motion } from 'framer-motion';
import { feedsApi } from '../api/client';
import { TextShimmer } from '../components/ui/text-shimmer';
import { InteractiveHoverButton } from '../components/ui/interactive-hover-button';

interface CVEDetail {
  cve_id?: string;
  entry_id?: string;
  id?: string;
  title?: string;
  description?: string;
  severity?: string;
  cvss_score?: number;
  cvss_v2?: number;
  cvss_v3?: number;
  cvss_vector?: string;
  published_date?: string;
  published?: string;
  modified_date?: string;
  last_modified?: string;
  references?: string[];
  affected_products?: string[];
  cwe_ids?: string[];
  weaknesses?: any[];
  source?: string;
  source_url?: string;
  [key: string]: any;
}

const CVEDetailPage = () => {
  const { cveId } = useParams<{ cveId: string }>();
  const navigate = useNavigate();
  const [cve, setCve] = useState<CVEDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!cveId) {
      setError('CVE ID not provided');
      setLoading(false);
      return;
    }

    const fetchCVEDetails = async () => {
      setLoading(true);
      setError(null);
      try {
        console.log(`[CVEDetailPage] Fetching details for ${cveId}...`);
        const response = await feedsApi.getCVE(cveId);
        console.log('[CVEDetailPage] CVE details received:', response);
        
        // Handle different response formats
        const cveData = response.data || response;
        if (cveData) {
          setCve(cveData);
        } else {
          setError('CVE not found');
        }
      } catch (err: any) {
        console.error('[CVEDetailPage] Error fetching CVE:', err);
        setError(err.response?.data?.error || err.message || 'Failed to load CVE details');
      } finally {
        setLoading(false);
      }
    };

    fetchCVEDetails();
  }, [cveId]);

  const getSeverityColor = (severity?: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'bg-red-100 dark:bg-red-900/20 text-red-900 dark:text-red-200 border-red-300 dark:border-red-800';
      case 'high': return 'bg-orange-100 dark:bg-orange-900/20 text-orange-900 dark:text-orange-200 border-orange-300 dark:border-orange-800';
      case 'medium': return 'bg-yellow-100 dark:bg-yellow-900/20 text-yellow-900 dark:text-yellow-200 border-yellow-300 dark:border-yellow-800';
      case 'low': return 'bg-gray-100 dark:bg-blue-900/20 text-gray-900 dark:text-blue-200 border-gray-400 dark:border-blue-800';
      default: return 'bg-gray-100 dark:bg-gray-800/50 text-gray-900 dark:text-gray-200 border-gray-300 dark:border-gray-700';
    }
  };

  const getSeverityBgClass = (severity?: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'bg-red-50 dark:bg-red-900/10';
      case 'high': return 'bg-orange-50 dark:bg-orange-900/10';
      case 'medium': return 'bg-yellow-50 dark:bg-yellow-900/10';
      case 'low': return 'bg-gray-50 dark:bg-blue-900/10';
      default: return 'bg-gray-50 dark:bg-gray-900/10';
    }
  };

  const formatDate = (dateString?: string) => {
    if (!dateString) return 'N/A';
    try {
      return new Date(dateString).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
      });
    } catch {
      return dateString;
    }
  };

  // Parse CVSS vector into human-readable format
  // Commented out as it's not currently used
  /*
  const parseCVSSVector = (vector: string) => {
    if (!vector) return null;
    
    const explanations: { [key: string]: { [key: string]: string } } = {
      'AV': {
        'N': 'Network - Can be exploited remotely',
        'A': 'Adjacent - Requires adjacent network access',
        'L': 'Local - Requires local system access',
        'P': 'Physical - Requires physical access'
      },
      'AC': {
        'L': 'Low - No special conditions required',
        'H': 'High - Special conditions must exist'
      },
      'PR': {
        'N': 'None - No privileges required',
        'L': 'Low - Low-level privileges required',
        'H': 'High - High-level privileges required'
      },
      'UI': {
        'N': 'None - No user interaction required',
        'R': 'Required - User must interact'
      },
      'S': {
        'U': 'Unchanged - Impact limited to vulnerable component',
        'C': 'Changed - Impact extends beyond vulnerable component'
      },
      'C': {
        'N': 'None - No confidentiality impact',
        'L': 'Low - Limited confidentiality impact',
        'H': 'High - Total confidentiality impact'
      },
      'I': {
        'N': 'None - No integrity impact',
        'L': 'Low - Limited integrity impact',
        'H': 'High - Total integrity impact'
      },
      'A': {
        'N': 'None - No availability impact',
        'L': 'Low - Limited availability impact',
        'H': 'High - Total availability impact'
      }
    };

    try {
      const parts = vector.split('/');
      const metrics: { [key: string]: string } = {};
      
      parts.forEach(part => {
        const [key, value] = part.split(':');
        if (key && value) {
          metrics[key] = value;
        }
      });

      return metrics;
    } catch {
      return null;
    }
  };
  */

  /*
  const getMetricLabel = (metricKey: string, value: string) => {
    const explanations: { [key: string]: { [key: string]: string } } = {
      'AV': {
        'N': 'Network - Can be exploited remotely',
        'A': 'Adjacent - Requires adjacent network access',
        'L': 'Local - Requires local system access',
        'P': 'Physical - Requires physical access'
      },
      'AC': {
        'L': 'Low - No special conditions required',
        'H': 'High - Special conditions must exist'
      },
      'PR': {
        'N': 'None - No privileges required',
        'L': 'Low - Low-level privileges required',
        'H': 'High - High-level privileges required'
      },
      'UI': {
        'N': 'None - No user interaction required',
        'R': 'Required - User must interact'
      },
      'S': {
        'U': 'Unchanged - Impact limited to vulnerable component',
        'C': 'Changed - Impact extends beyond vulnerable component'
      },
      'C': {
        'N': 'None - No confidentiality impact',
        'L': 'Low - Limited confidentiality impact',
        'H': 'High - Total confidentiality impact'
      },
      'I': {
        'N': 'None - No integrity impact',
        'L': 'Low - Limited integrity impact',
        'H': 'High - Total integrity impact'
      },
      'A': {
        'N': 'None - No availability impact',
        'L': 'Low - Limited availability impact',
        'H': 'High - Total availability impact'
      }
    };
    
    return explanations[metricKey]?.[value] || `${metricKey}: ${value}`;
  };
  */

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <TextShimmer duration={1.5} className="text-xl">
            Loading CVE details...
          </TextShimmer>
        </div>
      </div>
    );
  }

  if (error || !cve) {
    return (
      <div className="max-w-4xl mx-auto">
        <div className="mb-6" onClick={() => navigate(-1)}>
          <InteractiveHoverButton 
            text="Back"
            className="w-auto px-6"
          />
        </div>

        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-6">
          <div className="flex items-start gap-4">
            <AlertTriangle className="w-6 h-6 text-red-600 dark:text-red-400 flex-shrink-0 mt-1" />
            <div>
              <h2 className="text-xl font-semibold text-red-900 dark:text-red-200 mb-2">Error Loading CVE</h2>
              <p className="text-red-800 dark:text-red-300">{error || 'CVE not found'}</p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  const cveId_ = cve.cve_id || cve.entry_id || cve.id || 'Unknown';
  const title = cve.title || cve.description || 'No title';
  const description = cve.description || 'No description';

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="max-w-4xl mx-auto"
    >
      {/* Back Button */}
      <div className="mb-6" onClick={() => navigate(-1)}>
        <InteractiveHoverButton 
          text="Back to Feeds"
          className="w-auto px-6"
        />
      </div>

      {/* Header - Optimized */}
      <div className={`${getSeverityBgClass(cve.severity)} rounded-lg p-6 mb-6 border-l-4 ${getSeverityColor(cve.severity)} shadow-md`}>
        {/* CVE Title Section */}
        <div className="mb-4">
          <h1 className="text-4xl font-bold text-gray-900 dark:text-white mb-1 font-mono">{cveId_}</h1>
          <p className="text-gray-700 dark:text-gray-300 text-lg">{title}</p>
        </div>

        {/* Severity & CVSS Badges - Horizontal */}
        <div className="flex items-center gap-3 mb-5 flex-wrap">
          {cve.severity && (
            <div className={`px-4 py-2 rounded-full font-bold text-sm uppercase tracking-wider border-2 ${getSeverityColor(cve.severity)} shadow-sm`}>
              {cve.severity.toUpperCase()}
            </div>
          )}
          {cve.cvss_score !== undefined && (
            <div className="px-4 py-2 bg-gradient-to-r from-purple-100 to-purple-50 dark:from-purple-900/20 dark:to-purple-800/20 text-purple-900 dark:text-purple-200 rounded-full font-bold border border-purple-300 dark:border-purple-800 shadow-sm flex items-center gap-2">
              <span className="text-lg">CVSS</span>
              <span className="text-2xl font-mono">{cve.cvss_score.toFixed(1)}</span>
              <span className="text-sm">/10</span>
            </div>
          )}
        </div>

        {/* Timeline & Source - Grid */}
        <div className="grid grid-cols-2 md:grid-cols-3 gap-4 pt-4 border-t border-gray-200 dark:border-gray-700">
          <div>
            <p className="text-xs font-semibold text-gray-800 dark:text-gray-400 uppercase tracking-wider mb-1">📅 Published</p>
            <p className="text-gray-900 dark:text-white font-semibold">{formatDate(cve.published_date || cve.published)}</p>
          </div>
          {cve.modified_date || cve.last_modified ? (
            <div>
              <p className="text-xs font-semibold text-gray-800 dark:text-gray-400 uppercase tracking-wider mb-1">✏️ Modified</p>
              <p className="text-gray-900 dark:text-white font-semibold">{formatDate(cve.modified_date || cve.last_modified)}</p>
            </div>
          ) : null}
          {cve.source && (
            <div>
              <p className="text-xs font-semibold text-gray-800 dark:text-gray-400 uppercase tracking-wider mb-1">📌 Source</p>
              <p className="text-gray-900 dark:text-white font-semibold capitalize">{cve.source}</p>
            </div>
          )}
        </div>
      </div>

      {/* Main Content */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column - Details */}
        <div className="lg:col-span-2 space-y-6">
          {/* Description */}
          <div className="card">
            <div className="flex items-center gap-2 mb-4">
              <div className="w-1 h-6 bg-gradient-to-b from-primary-600 to-primary-400 rounded"></div>
              <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Description</h2>
            </div>
            <p className="text-gray-700 dark:text-gray-300 leading-relaxed whitespace-pre-wrap bg-gray-50/50 dark:bg-neutral-800/50 backdrop-blur-sm p-4 rounded-lg border border-gray-200 dark:border-neutral-700">
              {description}
            </p>
          </div>

          {/* CVSS Information - Optimized */}
          {(cve.cvss_v2 || cve.cvss_v3 || cve.cvss_vector) && (
            <div className="card">
              <div className="flex items-center gap-2 mb-4">
                <div className="w-1 h-6 bg-gradient-to-b from-purple-600 to-purple-400 rounded"></div>
                <h3 className="text-2xl font-bold text-gray-900 dark:text-white">CVSS Information</h3>
              </div>
              
              <div className="space-y-3">
                {/* CVSS Scores Row */}
                <div className="grid grid-cols-2 gap-3">
                  {cve.cvss_v2 !== undefined && (
                    <div className="bg-gradient-to-br from-orange-50 to-orange-100 dark:from-orange-900/20 dark:to-orange-800/20 p-4 rounded-lg border border-orange-200 dark:border-orange-800">
                      <p className="text-xs font-semibold text-orange-700 dark:text-orange-400 uppercase tracking-wider mb-1">CVSS v2.0</p>
                      <p className="text-3xl font-bold text-orange-900 dark:text-orange-200">{cve.cvss_v2.toFixed(1)}</p>
                      <p className="text-xs text-orange-700 dark:text-orange-400 mt-1">Severity Score</p>
                    </div>
                  )}
                  {cve.cvss_v3 !== undefined && (
                    <div className="bg-gradient-to-br from-gray-50 to-gray-100 dark:from-blue-900/20 dark:to-blue-800/20 p-4 rounded-lg border border-gray-300 dark:border-blue-800">
                      <p className="text-xs font-semibold text-gray-800 dark:text-blue-400 uppercase tracking-wider mb-1">CVSS v3.0</p>
                      <p className="text-3xl font-bold text-gray-900 dark:text-blue-200">{cve.cvss_v3.toFixed(1)}</p>
                      <p className="text-xs text-gray-800 dark:text-blue-400 mt-1">Severity Score</p>
                    </div>
                  )}
                </div>

                {/* CVSS Vector - Human Readable */}
                {cve.cvss_vector && (
                  <div className="space-y-3">
                    {/* Raw Vector */}
                    <div className="bg-gray-900 dark:bg-black text-white p-4 rounded-lg border border-gray-700 dark:border-gray-800">
                      <p className="text-xs font-semibold text-gray-800 dark:text-gray-400 uppercase tracking-wider mb-2">📋 CVSS Vector (Technical)</p>
                      <p className="text-sm font-mono break-all text-gray-100 dark:text-gray-200 bg-black bg-opacity-50 p-3 rounded border border-gray-700 dark:border-gray-800">
                        {cve.cvss_vector}
                      </p>
                    </div>

                    {/* Human Readable Vector */}
                    <div className="bg-gradient-to-br from-gray-50 to-gray-100 dark:from-indigo-900/20 dark:to-indigo-800/20 p-4 rounded-lg border border-gray-300 dark:border-indigo-800">
                      <p className="text-xs font-semibold text-indigo-700 dark:text-indigo-400 uppercase tracking-wider mb-3">🔍 CVSS Vector Explained</p>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                        {(() => {
                          const vectors = cve.cvss_vector.split('/').map(part => {
                            const [key, value] = part.split(':');
                            return { key, value };
                          });
                          
                          const metricLabels: { [key: string]: string } = {
                            'AV': 'Attack Vector',
                            'AC': 'Attack Complexity',
                            'PR': 'Privileges Required',
                            'UI': 'User Interaction',
                            'S': 'Scope',
                            'C': 'Confidentiality',
                            'I': 'Integrity',
                            'A': 'Availability'
                          };

                          const metricExplanations: { [key: string]: { [key: string]: string } } = {
                            'AV': {
                              'N': 'Network - Remotely exploitable',
                              'A': 'Adjacent - Adjacent network required',
                              'L': 'Local - Local access required',
                              'P': 'Physical - Physical access required'
                            },
                            'AC': {
                              'L': 'Low - Easy to exploit',
                              'H': 'High - Difficult conditions'
                            },
                            'PR': {
                              'N': 'None - No privileges needed',
                              'L': 'Low - Low privileges needed',
                              'H': 'High - High privileges needed'
                            },
                            'UI': {
                              'N': 'None - Automatic exploit',
                              'R': 'Required - User interaction needed'
                            },
                            'S': {
                              'U': 'Unchanged - Same component',
                              'C': 'Changed - Beyond component'
                            },
                            'C': {
                              'N': 'None - No data leaked',
                              'L': 'Low - Some data leaked',
                              'H': 'High - All data leaked'
                            },
                            'I': {
                              'N': 'None - No data changed',
                              'L': 'Low - Some data changed',
                              'H': 'High - All data changed'
                            },
                            'A': {
                              'N': 'None - No service impact',
                              'L': 'Low - Limited service impact',
                              'H': 'High - Complete service loss'
                            }
                          };

                          return vectors.map((vec, idx) => (
                            <div key={idx} className="bg-white/80 dark:bg-neutral-800/80 backdrop-blur-sm rounded p-3 border border-indigo-100 dark:border-indigo-800">
                              <div className="flex items-start justify-between gap-2 mb-1">
                                <span className="font-bold text-indigo-700 dark:text-indigo-400 font-mono">{vec.key}</span>
                                <span className="text-lg font-bold text-indigo-600 dark:text-indigo-400 font-mono">{vec.value}</span>
                              </div>
                              <p className="text-xs text-indigo-600 dark:text-indigo-400 leading-tight">
                                {metricExplanations[vec.key]?.[vec.value] || 'Unknown'}
                              </p>
                              <p className="text-xs text-gray-800 dark:text-gray-400 mt-1">
                                Full: {metricLabels[vec.key]}
                              </p>
                            </div>
                          ));
                        })()}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Affected Products */}
          {cve.affected_products && cve.affected_products.length > 0 && (
            <div className="card">
              <div className="flex items-center gap-2 mb-4">
                <div className="w-1 h-6 bg-gradient-to-b from-red-600 to-red-400 rounded"></div>
                <h3 className="text-2xl font-bold text-gray-900 dark:text-white">Affected Products</h3>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {cve.affected_products.map((product, idx) => (
                  <div key={idx} className="flex items-start gap-3 p-3 bg-red-50 dark:bg-red-900/20 rounded-lg border border-red-200 dark:border-red-800">
                    <span className="text-red-600 dark:text-red-400 font-bold mt-0.5">◆</span>
                    <span className="text-gray-700 dark:text-gray-300 text-sm">{product}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* CWE Information */}
          {cve.cwe_ids && cve.cwe_ids.length > 0 && (
            <div className="card">
              <div className="flex items-center gap-2 mb-4">
                <div className="w-1 h-6 bg-gradient-to-b from-yellow-600 to-yellow-400 rounded"></div>
                <h3 className="text-2xl font-bold text-gray-900 dark:text-white">Weaknesses (CWE)</h3>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {cve.cwe_ids.map((cwe, idx) => (
                  <a
                    key={idx}
                    href={`https://cwe.mitre.org/data/definitions/${cwe.replace('CWE-', '')}.html`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-4 py-3 bg-gradient-to-r from-yellow-100 to-yellow-50 dark:from-yellow-900/20 dark:to-yellow-800/20 text-yellow-900 dark:text-yellow-200 rounded-lg text-sm font-semibold hover:from-yellow-200 hover:to-yellow-100 dark:hover:from-yellow-900/30 dark:hover:to-yellow-800/30 transition-all border border-yellow-300 dark:border-yellow-800 flex items-center justify-between group"
                  >
                    <span className="font-mono">{cwe}</span>
                    <ExternalLink className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                  </a>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Right Column - References & Links */}
        <div className="space-y-6">
          {/* References */}
          {cve.references && cve.references.length > 0 && (
            <div className="card sticky top-6">
              <div className="flex items-center gap-2 mb-4">
                <div className="w-1 h-6 bg-gradient-to-b from-green-600 to-green-400 rounded"></div>
                <h3 className="text-xl font-bold text-gray-900 dark:text-white">References</h3>
                <span className="ml-auto text-sm font-semibold px-2 py-1 bg-green-100 dark:bg-green-900/20 text-green-800 dark:text-green-400 border border-green-300 dark:border-green-800 rounded-full">
                  {cve.references.length}
                </span>
              </div>
              <ul className="space-y-2 min-w-0">
                {cve.references.slice(0, 5).map((ref, idx) => (
                  <li key={idx} className="min-w-0 overflow-hidden">
                    <a
                      href={ref}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-green-600 dark:text-green-400 hover:text-green-700 dark:hover:text-green-300 flex items-center gap-2 text-xs p-2 bg-green-50 dark:bg-green-900/20 rounded-lg hover:bg-green-100 dark:hover:bg-green-900/30 transition-colors break-words overflow-hidden border border-green-200 dark:border-green-800"
                      title={ref}
                    >
                      <ExternalLink className="w-4 h-4 flex-shrink-0" />
                      <span className="underline font-medium truncate">{ref.substring(0, 35)}...</span>
                    </a>
                  </li>
                ))}
                {cve.references.length > 5 && (
                  <li className="text-xs text-gray-800 dark:text-gray-400 p-2 bg-gray-100 dark:bg-gray-800/50 rounded-lg font-semibold border border-gray-300 dark:border-gray-700">
                    +{cve.references.length - 5} more references
                  </li>
                )}
              </ul>
            </div>
          )}
        </div>
      </div>
    </motion.div>
  );
};

export default CVEDetailPage;
