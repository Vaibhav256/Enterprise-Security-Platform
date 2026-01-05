import React from "react";
import { Sidebar } from "./Sidebar";

interface AppLayoutProps {
  children: React.ReactNode;
  isConnected: boolean;
  isConnecting?: boolean;
  activeScanCount?: number;
}

export const AppLayout: React.FC<AppLayoutProps> = ({
  children,
  isConnected,
  isConnecting,
  activeScanCount,
}) => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 via-gray-100 to-gray-200 dark:from-slate-900 dark:via-slate-900 dark:to-slate-900">
      <Sidebar
        isConnected={isConnected}
        isConnecting={isConnecting}
        activeScanCount={activeScanCount}
      />
      <main className="ml-72 transition-all duration-300">
        <div className="p-8">{children}</div>
      </main>
    </div>
  );
};
