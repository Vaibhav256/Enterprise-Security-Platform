import React, { useState } from "react";
import { Link, useLocation } from "react-router-dom";
import {
  LayoutDashboard,
  ShieldCheck,
  Database,
  Brain,
  FileText,
  Rss,
  Settings,
  ChevronLeft,
  ChevronRight,
  WifiHigh,
  WifiOff,
} from "lucide-react";
import { ThemeToggle } from "@/components/ui/theme-toggle";
import { TextShimmer } from "@/components/ui/text-shimmer";
import { cn } from "@/lib/utils";

interface NavItem {
  label: string;
  href: string;
  icon: React.ElementType;
}

const navItems: NavItem[] = [
  { label: "Dashboard", href: "/", icon: LayoutDashboard },
  { label: "New Scan", href: "/new-scan", icon: ShieldCheck },
  { label: "Scan History", href: "/history", icon: Database },
  { label: "AI Assistant", href: "/ai-assistant", icon: Brain },
  { label: "Reports", href: "/reports", icon: FileText },
  { label: "Threat Feeds", href: "/threat-feeds", icon: Rss },
  { label: "Settings", href: "/settings", icon: Settings },
];

interface SidebarProps {
  isConnected: boolean;
  isConnecting?: boolean;
  activeScanCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  isConnected,
  isConnecting = false,
  activeScanCount = 0,
}) => {
  // Load collapsed state from localStorage or use default
  const [collapsed, setCollapsed] = useState(() => {
    const saved = localStorage.getItem('sidebarCollapsed');
    return saved ? JSON.parse(saved) : false;
  });
  const location = useLocation();

  // Save collapsed state to localStorage whenever it changes
  const handleToggleCollapsed = () => {
    const newState = !collapsed;
    setCollapsed(newState);
    localStorage.setItem('sidebarCollapsed', JSON.stringify(newState));
  };

  return (
    <aside
      className={cn(
        "fixed left-0 top-0 h-screen bg-gradient-to-b from-white to-gray-50/30 dark:bg-slate-900 border-r border-gray-300/70 dark:border-slate-700 shadow-lg shadow-gray-200/20 dark:shadow-none transition-all duration-300 z-50",
        collapsed ? "w-18" : "w-72"
      )}
    >
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-gray-300/60 dark:border-slate-700">
        {!collapsed && (
          <h1 className="text-xl font-semibold text-slate-900 dark:text-white">
            B Secure Platform
          </h1>
        )}
        <div className="flex items-center gap-2">
          {!collapsed && <ThemeToggle />}
          <button
            onClick={handleToggleCollapsed}
            className="p-2 rounded-lg hover:bg-gray-100/60 dark:hover:bg-slate-800 hover:shadow-sm transition-all duration-200"
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            {collapsed ? (
              <ChevronRight className="w-5 h-5 text-slate-800 dark:text-slate-700" />
            ) : (
              <ChevronLeft className="w-5 h-5 text-slate-800 dark:text-slate-700" />
            )}
          </button>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-4 space-y-1">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = location.pathname === item.href;

          return (
            <Link
              key={item.href}
              to={item.href}
              className={cn(
                "flex items-center gap-3 px-3 py-2 rounded-lg transition-all duration-200 group",
                isActive
                  ? "bg-primary-100 dark:bg-primary-900/20 text-primary-600 dark:text-primary-400 border-l-4 border-primary-600 shadow-sm shadow-gray-200/30 dark:shadow-none"
                  : "text-slate-700 dark:text-slate-300 hover:bg-gray-100/60 dark:hover:bg-slate-800 hover:shadow-sm",
                collapsed && "justify-center"
              )}
              aria-current={isActive ? "page" : undefined}
            >
              <Icon className="w-5 h-5 flex-shrink-0" />
              {!collapsed && <span className="font-medium">{item.label}</span>}
            </Link>
          );
        })}
      </nav>

      {/* Footer - Connection Status */}
      <div className="p-4 border-t border-gray-300/60 dark:border-slate-700">
        <div
          className={cn(
            "flex items-center gap-3 px-3 py-2 rounded-lg bg-gradient-to-r from-gray-50/60 to-gray-100/40 dark:bg-slate-800 shadow-sm shadow-gray-200/20 dark:shadow-none",
            collapsed && "justify-center"
          )}
        >
          {isConnected ? (
            <WifiHigh className="w-5 h-5 text-success-500 flex-shrink-0" />
          ) : (
            <WifiOff className="w-5 h-5 text-danger-500 flex-shrink-0 animate-pulse" />
          )}
          {!collapsed && (
            <div className="flex-1 min-w-0">
              {isConnecting ? (
                <TextShimmer duration={1} className="text-sm">
                  Connecting...
                </TextShimmer>
              ) : (
                <p className="text-sm text-slate-800 dark:text-slate-700">
                  {isConnected ? "Connected" : "Disconnected"}
                </p>
              )}
              {activeScanCount > 0 && (
                <p className="text-xs text-slate-700 dark:text-slate-700">
                  Active scans: {activeScanCount}
                </p>
              )}
            </div>
          )}
        </div>
      </div>
    </aside>
  );
};
