import { lazy } from 'react';

// Lazy load all route components
export const Dashboard = lazy(() => import('../pages/Dashboard'));
export const ScansPage = lazy(() => import('../pages/ScansPage'));
export const ScanFormPage = lazy(() => import('../pages/ScanFormPage'));
export const ScanDetailPage = lazy(() => import('../pages/ScanDetailPage'));
export const ReportsPage = lazy(() => import('../pages/ReportsPage'));
export const IntelligencePage = lazy(() => import('../pages/IntelligencePage'));
export const FeedsPage = lazy(() => import('../pages/FeedsPage'));
export const CVEDetailPage = lazy(() => import('../pages/CVEDetailPage'));
export const SettingsPage = lazy(() => import('../pages/SettingsPage'));
export const NotFoundPage = lazy(() => import('../pages/NotFoundPage'));
