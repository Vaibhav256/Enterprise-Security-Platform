import { lazy, Suspense } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import ErrorBoundary from './components/ErrorBoundary';
import { ToastProvider } from './components/ToastContainer';
import Layout from './components/Layout';
import LoadingSpinner from './components/LoadingSpinner';

// Eager load only critical pages
import FeedsPage from './pages/FeedsPage';
import CVEDetailPage from './pages/CVEDetailPage';

// Lazy load all other pages with prefetch hints
const Dashboard = lazy(() => import(/* webpackPrefetch: true */ './pages/Dashboard'));
const ScanFormPage = lazy(() => import(/* webpackPrefetch: true */ './pages/ScanFormPage'));
const ScansPage = lazy(() => import(/* webpackPrefetch: true */ './pages/ScansPage'));
const ScanDetailPage = lazy(() => import('./pages/ScanDetailPage'));
const IntelligencePage = lazy(() => import('./pages/IntelligencePage'));
const ReportsPage = lazy(() => import('./pages/ReportsPage'));
const SettingsPage = lazy(() => import('./pages/SettingsPage'));
const NotFoundPage = lazy(() => import('./pages/NotFoundPage'));

function App() {
  return (
    <ToastProvider>
      <Router>
        <ErrorBoundary>
          <Layout>
            <div className="p-6">
              <Suspense fallback={<LoadingSpinner size="lg" fullScreen text="Loading page..." />}>
                <Routes>
                  <Route path="/" element={<Dashboard />} />
                  <Route path="/scan/new" element={<ScanFormPage />} />
                  <Route path="/scans" element={<ScansPage />} />
                  <Route path="/scans/:scanId" element={<ScanDetailPage />} />
                  <Route path="/intelligence" element={<IntelligencePage />} />
                  <Route path="/reports" element={<ReportsPage />} />
                  <Route path="/feeds" element={<FeedsPage />} />
                  <Route path="/feeds/cve/:cveId" element={<CVEDetailPage />} />
                  <Route path="/settings" element={<SettingsPage />} />
                  <Route path="*" element={<NotFoundPage />} />
                </Routes>
              </Suspense>
            </div>
          </Layout>
        </ErrorBoundary>
      </Router>
    </ToastProvider>
  );
}

export default App;
