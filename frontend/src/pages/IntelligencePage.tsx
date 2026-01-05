import { useState, useEffect, useMemo } from 'react';
import { Brain, Database, Sparkles, Check } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { intelligenceApi } from '../api/client';
import type { ChatMessage, ChatResponse } from '../types';
import { TextShimmer } from '../components/ui/text-shimmer';
import { InteractiveHoverButton } from '../components/ui/interactive-hover-button';
import { CopyButton } from '../components/ui/copy-button';

// Message type for display in UI
interface DisplayMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
  sources?: ChatResponse['sources'];
  confidence?: number;
}

const IntelligencePage = () => {
  const [activeTab, setActiveTab] = useState<'chat' | 'indexed-data'>('chat');
  const [messages, setMessages] = useState<DisplayMessage[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [sessionId, setSessionId] = useState<string>('');

  // Indexed data tab state
  const [indexStats, setIndexStats] = useState<any>(null);
  const [indexLoading, setIndexLoading] = useState(false);

  // Randomized placeholder hints
  const placeholderHints = useMemo(() => [
    'Ask about critical SSH vulnerabilities...',
    'Explain CVE-2024-12345...',
    'How to secure port 22?',
    'What are common web vulnerabilities?',
    'Tell me about SQL injection...',
    'How to prevent XSS attacks?',
    'What is CVE-2023-45678?',
    'Explain buffer overflow vulnerabilities...',
    'How to harden Apache server?',
    'What are zero-day exploits?',
    'Describe OWASP Top 10...',
    'How to secure Docker containers?',
    'What is a remote code execution?',
    'Explain privilege escalation...',
    'How to prevent CSRF attacks?',
  ], []);

  const [placeholder, setPlaceholder] = useState('');

  // Set random placeholder on mount and when messages change
  useEffect(() => {
    const randomIndex = Math.floor(Math.random() * placeholderHints.length);
    setPlaceholder(placeholderHints[randomIndex]);
  }, [messages.length, placeholderHints]);

  // Fetch index stats when switching to indexed data tab
  useEffect(() => {
    if (activeTab === 'indexed-data') {
      fetchIndexStats();
    }
  }, [activeTab]);

  // Keyboard shortcut: Ctrl+Enter to send message
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.key === 'Enter' && activeTab === 'chat' && input.trim() && !loading) {
        e.preventDefault();
        const form = document.querySelector('form');
        if (form) {
          form.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [input, loading, activeTab]);

  const fetchIndexStats = async () => {
    setIndexLoading(true);
    try {
      const stats = await intelligenceApi.getIndexStats();
      setIndexStats(stats);
    } catch (error) {
      console.error('Failed to fetch index stats:', error);
    } finally {
      setIndexLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || loading) return;

    const userMessage = input.trim();
    setInput('');
    
    // Add user message to display
    const userDisplayMessage: DisplayMessage = {
      id: `msg_${Date.now()}_user`,
      role: 'user',
      content: userMessage,
      timestamp: new Date(),
    };
    setMessages((prev) => [...prev, userDisplayMessage]);
    setLoading(true);

    try {
      const request: ChatMessage = {
        query: userMessage,
        session_id: sessionId || undefined,
        top_k: 5,
      };

      const response: ChatResponse = await intelligenceApi.chat(request);
      
      // Validate response
      if (!response || !response.response) {
        throw new Error('Invalid response from server');
      }
      
      setSessionId(response.session_id);
      
      // Add assistant message to display with sources and confidence
      const assistantDisplayMessage: DisplayMessage = {
        id: `msg_${Date.now()}_assistant`,
        role: 'assistant',
        content: response.response,
        timestamp: new Date(),
        sources: response.sources,
        confidence: response.confidence,
      };
      setMessages((prev) => [...prev, assistantDisplayMessage]);
    } catch (error: any) {
      console.error('Failed to get AI response:', error);
      
      // Provide specific error messages based on error type
      let errorContent = 'Sorry, I encountered an error. Please try again.';
      
      if (error.code === 'ECONNABORTED' || error.message?.includes('timeout')) {
        errorContent = '⏱️ Request timeout - The AI analysis took too long. This can happen with complex queries or slow networks. Please try a simpler question or check your internet connection.';
      } else if (error.response?.status === 504) {
        errorContent = '⏱️ Backend timeout - The server is processing your query but it\'s taking longer than expected. The analysis is likely still running. Please try again in a moment.';
      } else if (error.response?.status === 503) {
        errorContent = '🤖 AI Assistant unavailable - The chatbot is not ready. It may be loading. Please refresh and try again.';
      } else if (error.response?.data?.error) {
        errorContent = `Error: ${error.response.data.error}`;
      }
      
      const errorMessage: DisplayMessage = {
        id: `msg_${Date.now()}_error`,
        role: 'assistant',
        content: errorContent,
        timestamp: new Date(),
      };
      setMessages((prev) => [...prev, errorMessage]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto">
      {/* Tabs */}
      <div className="mb-6 border-b">
        <div className="flex gap-4">
          <button
            onClick={() => setActiveTab('chat')}
            className={`pb-3 px-4 font-medium transition-colors border-b-2 ${
              activeTab === 'chat'
                ? 'border-primary-600 text-primary-600'
                : 'border-transparent text-gray-900 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            <div className="flex items-center gap-2">
              <Brain className="w-4 h-4" />
              AI Chatbot
            </div>
          </button>
          <button
            onClick={() => setActiveTab('indexed-data')}
            className={`pb-3 px-4 font-medium transition-colors border-b-2 ${
              activeTab === 'indexed-data'
                ? 'border-primary-600 text-primary-600'
                : 'border-transparent text-gray-900 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            <div className="flex items-center gap-2">
              <Database className="w-4 h-4" />
              Indexed Data
            </div>
          </button>
        </div>
      </div>

      {/* Chat Tab */}
      {activeTab === 'chat' && (
        <div className="card h-[calc(100vh-16rem)] flex flex-col">
          {/* Header */}
          <div className="flex items-center gap-3 pb-4 border-b">
            <div className="p-3 bg-purple-100 rounded-lg">
              <Brain className="w-6 h-6 text-purple-600" />
            </div>
            <div className="flex-1">
              <h2 className="text-2xl font-bold text-gray-900 dark:text-white">AI Assistant</h2>
              <p className="text-gray-800 dark:text-gray-700">Ask questions about vulnerabilities and CVEs</p>
            </div>
            <div className="text-xs bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300 px-3 py-2 rounded-lg border border-blue-200 dark:border-blue-800">
              ⏱️ Responses may take 30-60 seconds (includes LLM analysis + real-time threat data)
            </div>
          </div>

          {/* Messages */}
          <div 
            className="flex-1 overflow-y-auto py-6 space-y-4 smooth-scroll"
            role="log"
            aria-live="polite"
            aria-label="Chat messages"
          >
            {messages.length === 0 && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5 }}
                className="text-center py-12"
              >
                <motion.div
                  animate={{ rotate: [0, 360] }}
                  transition={{ duration: 20, repeat: Infinity, ease: "linear" }}
                >
                  <Brain className="w-16 h-16 mx-auto text-purple-300 mb-4" />
                </motion.div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                  Start a conversation
                </h3>
                <p className="text-gray-800 dark:text-gray-700">Ask questions about cybersecurity threats and vulnerabilities</p>
              </motion.div>
            )}

            <AnimatePresence mode="popLayout">
              {messages.map((msg) => (
                <motion.div
                  key={msg.id}
                  initial={{ opacity: 0, y: 20, scale: 0.95 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.95 }}
                  transition={{ duration: 0.3 }}
                  className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
                >
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ duration: 0.3, delay: 0.1 }}
                    className={`max-w-[80%] p-4 rounded-2xl backdrop-blur-sm shadow-md relative group ${
                      msg.role === 'user'
                        ? 'bg-gradient-to-br from-primary-500 to-primary-600 text-white'
                        : 'bg-gradient-to-br from-gray-50 to-gray-100 dark:from-neutral-800 dark:to-neutral-900 text-gray-900 dark:text-white border border-gray-200 dark:border-neutral-700'
                    }`}
                  >
                    {/* Copy button for assistant messages */}
                    {msg.role === 'assistant' && (
                      <div className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity">
                        <CopyButton text={msg.content} size="sm" />
                      </div>
                    )}
                    <p className="whitespace-pre-wrap leading-relaxed">{msg.content}</p>
                    
                    {/* Show confidence badge for assistant messages */}
                    {msg.role === 'assistant' && msg.confidence !== undefined && (
                      <motion.div
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.3, delay: 0.2 }}
                        className="mt-3 pt-3 border-t border-gray-200 dark:border-neutral-700 flex items-center gap-2"
                      >
                        <div className="flex items-center gap-1.5 text-xs">
                          <Sparkles className="w-3.5 h-3.5 text-purple-500" />
                          <span className="text-gray-800 dark:text-gray-400 font-medium">
                            Confidence: {(msg.confidence * 100).toFixed(0)}%
                          </span>
                        </div>
                        <div className="flex-1 bg-gray-200 dark:bg-neutral-700 h-1.5 rounded-full overflow-hidden">
                          <motion.div
                            initial={{ width: 0 }}
                            animate={{ width: `${msg.confidence * 100}%` }}
                            transition={{ duration: 0.8, delay: 0.3 }}
                            className={`h-full ${
                              msg.confidence > 0.8 ? 'bg-green-500' :
                              msg.confidence > 0.6 ? 'bg-yellow-500' :
                              'bg-orange-500'
                            }`}
                          />
                        </div>
                      </motion.div>
                    )}
                    
                    {/* Show sources for assistant messages */}
                    {msg.role === 'assistant' && msg.sources && msg.sources.length > 0 && (
                      <motion.div
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.3, delay: 0.3 }}
                        className="mt-3 pt-3 border-t border-gray-200 dark:border-neutral-700"
                      >
                        <p className="text-xs font-semibold text-gray-800 dark:text-gray-400 mb-2 flex items-center gap-1.5">
                          <Check className="w-3.5 h-3.5" />
                          Sources:
                        </p>
                        <div className="space-y-1.5">
                          {msg.sources.slice(0, 3).map((source: any, idx: number) => (
                            <motion.div
                              key={idx}
                              initial={{ opacity: 0, x: -10 }}
                              animate={{ opacity: 1, x: 0 }}
                              transition={{ duration: 0.3, delay: 0.4 + idx * 0.1 }}
                              className="text-xs bg-white/50 dark:bg-neutral-700/50 backdrop-blur-sm px-2 py-1.5 rounded border border-gray-200 dark:border-neutral-600"
                            >
                              <span className="text-gray-700 dark:text-gray-300 font-mono">
                                {source.cve_id || source.type}
                              </span>
                            </motion.div>
                          ))}
                        </div>
                      </motion.div>
                    )}
                  </motion.div>
                </motion.div>
              ))}
            </AnimatePresence>

            {/* Typing indicator */}
            {loading && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.95 }}
                className="flex justify-start"
              >
                <div className="bg-gradient-to-br from-gray-50 to-gray-100 dark:from-neutral-800 dark:to-neutral-900 p-4 rounded-2xl border border-gray-200 dark:border-neutral-700 backdrop-blur-sm shadow-md">
                  <div className="flex items-center gap-2">
                    <motion.div
                      animate={{ rotate: 360 }}
                      transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                    >
                      <Brain className="w-4 h-4 text-purple-500" />
                    </motion.div>
                    <div className="flex gap-1">
                      {[0, 1, 2].map((i) => (
                        <motion.div
                          key={i}
                          animate={{ y: [0, -8, 0] }}
                          transition={{ duration: 0.6, repeat: Infinity, delay: i * 0.1 }}
                          className="w-2 h-2 bg-purple-500 rounded-full"
                        />
                      ))}
                    </div>
                    <span className="text-sm text-gray-800 dark:text-gray-700">Analyzing...</span>
                  </div>
                </div>
              </motion.div>
            )}
          </div>

          {/* Input */}
          <form onSubmit={handleSubmit} className="pt-4 border-t">
            <div className="flex gap-3">
              <input
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder={placeholder}
                className="input flex-1"
                disabled={loading}
              />
              <InteractiveHoverButton
                type="submit"
                disabled={loading || !input.trim()}
                text={loading ? "Sending..." : "Send"}
                className="w-auto px-6"
              />
            </div>
            <p className="text-xs text-gray-700 dark:text-gray-400 mt-2">
              Tip: Press <kbd className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-gray-700 dark:text-gray-300 font-mono">Ctrl+Enter</kbd> to send
            </p>
          </form>
        </div>
      )}

      {/* Indexed Data Tab */}
      {activeTab === 'indexed-data' && (
        <div className="space-y-6">
          <div className="card">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-3">
                <div className="p-3 bg-gray-100 dark:bg-blue-900/30 rounded-lg">
                  <Database className="w-6 h-6 text-blue-600 dark:text-blue-400" />
                </div>
                <div>
                  <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Indexed Vulnerabilities</h2>
                  <p className="text-gray-900 dark:text-gray-400">View and manage ChromaDB indexed data</p>
                </div>
              </div>
              <InteractiveHoverButton
                onClick={fetchIndexStats}
                disabled={indexLoading}
                text={indexLoading ? "Loading..." : "Refresh"}
                className="w-auto px-6"
              />
            </div>

            {indexLoading ? (
              <div className="flex justify-center py-12">
                <TextShimmer duration={1.5} className="text-base">
                  Loading intelligence index...
                </TextShimmer>
              </div>
            ) : indexStats ? (
              <div className="space-y-6">
                {/* Statistics Cards */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="bg-gradient-to-br from-purple-50 to-purple-100 dark:from-purple-900/20 dark:to-purple-800/20 p-6 rounded-lg border border-purple-200 dark:border-purple-800">
                    <div className="text-sm text-purple-700 dark:text-purple-400 font-medium mb-1">Vulnerability Scans</div>
                    <div className="text-3xl font-bold text-purple-900 dark:text-purple-200">
                      {indexStats.collections?.vulnerability_scans || 0}
                    </div>
                    <div className="text-xs text-purple-600 dark:text-purple-400 mt-2">Indexed vulnerabilities</div>
                  </div>
                  <div className="bg-gradient-to-br from-gray-50 to-gray-100 dark:from-blue-900/20 dark:to-blue-800/20 p-6 rounded-lg border border-gray-300 dark:border-blue-800">
                    <div className="text-sm text-gray-800 dark:text-blue-400 font-medium mb-1">Threat Intelligence</div>
                    <div className="text-3xl font-bold text-gray-900 dark:text-blue-200">
                      {indexStats.collections?.threat_intelligence || 0}
                    </div>
                    <div className="text-xs text-blue-600 dark:text-blue-400 mt-2">Enrichment data entries</div>
                  </div>
                  <div className="bg-gradient-to-br from-green-50 to-green-100 dark:from-green-900/20 dark:to-green-800/20 p-6 rounded-lg border border-green-200 dark:border-green-800">
                    <div className="text-sm text-green-700 dark:text-green-400 font-medium mb-1">Total Documents</div>
                    <div className="text-3xl font-bold text-green-900 dark:text-green-200">
                      {indexStats.total_documents || 0}
                    </div>
                    <div className="text-xs text-green-600 dark:text-green-400 mt-2">All indexed entries</div>
                  </div>
                </div>

                {/* Info Section */}
                <div className="bg-gray-50 dark:bg-blue-900/20 border border-gray-300 dark:border-blue-800 rounded-lg p-4">
                  <h3 className="font-semibold text-gray-900 dark:text-blue-200 mb-2">About Indexed Data</h3>
                  <p className="text-sm text-blue-800 dark:text-blue-300 mb-3">
                    The AI chatbot uses ChromaDB to semantically search through indexed vulnerabilities.
                    When you scan targets, vulnerability data is automatically indexed for fast retrieval.
                  </p>
                  <div className="space-y-2 text-sm text-blue-700 dark:text-blue-300">
                    <div className="flex items-start gap-2">
                      <span className="font-semibold">•</span>
                      <span><strong>Vulnerability Scans:</strong> Individual findings from Nikto, Nuclei, OpenVAS scans</span>
                    </div>
                    <div className="flex items-start gap-2">
                      <span className="font-semibold">•</span>
                      <span><strong>Threat Intelligence:</strong> Enrichment data from NVD, ExploitDB, and other sources</span>
                    </div>
                    <div className="flex items-start gap-2">
                      <span className="font-semibold">•</span>
                      <span><strong>Deduplication:</strong> Duplicate vulnerabilities are automatically detected and skipped</span>
                    </div>
                  </div>
                </div>

                {/* Management Actions */}
                <div className="bg-gray-50/50 dark:bg-neutral-800/50 backdrop-blur-sm border border-gray-200 dark:border-neutral-700 rounded-lg p-4">
                  <h3 className="font-semibold text-gray-900 dark:text-white mb-3">Data Management</h3>
                  <p className="text-sm text-gray-800 dark:text-gray-400 mb-4">
                    Use the scan details page to delete indexed data for specific scans. 
                    New scans are automatically indexed with deduplication.
                  </p>
                  <div className="flex gap-3">
                    <InteractiveHoverButton
                      onClick={() => window.location.href = '/scans'}
                      text="View Scans"
                      className="w-auto px-6"
                    />
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-center py-12 text-gray-900 dark:text-gray-300">
                <Database className="w-16 h-16 mx-auto text-gray-300 dark:text-gray-600 mb-4" />
                <p>No index statistics available</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default IntelligencePage;
