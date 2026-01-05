import { useState } from 'react';
import type { ReactNode } from 'react';
import { 
  Shield, 
  LayoutDashboard, 
  Database, 
  Brain, 
  Settings, 
  FileText, 
  Rss,
  WifiHigh,
} from 'lucide-react';
import { motion } from 'framer-motion';
import { ThemeToggle } from './ui/theme-toggle';
import { Sidebar, SidebarBody, SidebarLink } from './ui/sidebar';
import { cn } from '@/lib/utils';

interface LayoutProps {
  children: ReactNode;
}

const Layout = ({ children }: LayoutProps) => {
  const [open, setOpen] = useState(false);

  const links = [
    {
      label: 'Dashboard',
      href: '/',
      icon: <LayoutDashboard className="text-neutral-700 dark:text-neutral-200 h-5 w-5 flex-shrink-0" />,
    },
    {
      label: 'New Scan',
      href: '/scan/new',
      icon: <Shield className="text-neutral-700 dark:text-neutral-200 h-5 w-5 flex-shrink-0" />,
    },
    {
      label: 'Scan History',
      href: '/scans',
      icon: <Database className="text-neutral-700 dark:text-neutral-200 h-5 w-5 flex-shrink-0" />,
    },
    {
      label: 'AI Assistant',
      href: '/intelligence',
      icon: <Brain className="text-neutral-700 dark:text-neutral-200 h-5 w-5 flex-shrink-0" />,
    },
    {
      label: 'Reports',
      href: '/reports',
      icon: <FileText className="text-neutral-700 dark:text-neutral-200 h-5 w-5 flex-shrink-0" />,
    },
    {
      label: 'Threat Feeds',
      href: '/feeds',
      icon: <Rss className="text-neutral-700 dark:text-neutral-200 h-5 w-5 flex-shrink-0" />,
    },
    {
      label: 'Settings',
      href: '/settings',
      icon: <Settings className="text-neutral-700 dark:text-neutral-200 h-5 w-5 flex-shrink-0" />,
    },
  ];

  return (
    <div className={cn(
      "flex flex-col md:flex-row w-full flex-1 mx-auto overflow-hidden relative",
      "h-screen"
    )}>
      <Sidebar open={open} setOpen={setOpen}>
        <SidebarBody className="justify-between gap-10 relative z-20">
          <div className="flex flex-col flex-1 overflow-y-auto overflow-x-hidden">
            {open ? <Logo /> : <LogoIcon />}
            <div className="mt-8 flex flex-col gap-2">
              {links.map((link, idx) => (
                <SidebarLink key={idx} link={link} />
              ))}
            </div>
          </div>
          <div className="border-t border-neutral-200 dark:border-neutral-700 pt-4">
            <div className="flex items-center gap-2 px-2">
              <WifiHigh className="h-5 w-5 text-green-500 flex-shrink-0" />
              {open && (
                <div className="flex flex-col">
                  <span className="text-xs text-neutral-700 dark:text-neutral-200">Status</span>
                  <span className="text-xs text-neutral-500 dark:text-neutral-400">Connected</span>
                </div>
              )}
            </div>
          </div>
        </SidebarBody>
      </Sidebar>
      <Dashboard>{children}</Dashboard>
    </div>
  );
};

// Logo Component
export const Logo = () => {
  return (
    <div className="font-normal flex space-x-2 items-center text-sm text-black py-1 relative z-20">
      <Shield className="h-6 w-6 text-neutral-800 dark:text-white flex-shrink-0" />
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="flex flex-col"
      >
        <span className="font-bold text-neutral-800 dark:text-white whitespace-pre">
          B Secure
        </span>
        <span className="text-xs text-neutral-600 dark:text-neutral-400 whitespace-pre">
          Vulnerability Scanner
        </span>
      </motion.div>
    </div>
  );
};

// Logo Icon (collapsed state)
export const LogoIcon = () => {
  return (
    <div className="font-normal flex space-x-2 items-center text-sm text-black py-1 relative z-20">
      <Shield className="h-6 w-6 text-neutral-800 dark:text-white flex-shrink-0" />
    </div>
  );
};

// Main content wrapper
const Dashboard = ({ children }: { children: ReactNode }) => {
  return (
    <div className="flex flex-1 flex-col h-full bg-gradient-to-br from-gray-50 via-gray-100 to-gray-200 dark:from-slate-900 dark:via-slate-800 dark:to-slate-900">
      {/* Content Layer */}
      <div className="flex-1 overflow-auto relative z-10 w-full">
        <div className="p-2 md:p-6 flex flex-col gap-2 w-full h-full">
          {/* Mobile header with theme toggle */}
          <div className="md:hidden flex items-center justify-between pb-4 border-b border-neutral-200/50 dark:border-neutral-700/50">
            <div>
              <h1 className="text-lg font-bold text-neutral-800 dark:text-white">B Secure Platform</h1>
              <p className="text-xs text-neutral-600 dark:text-neutral-400">Vulnerability Scanner</p>
            </div>
            <ThemeToggle />
          </div>

          {/* Desktop header with theme toggle */}
          <div className="hidden md:flex items-center justify-between pb-4">
            <div />
            <ThemeToggle />
          </div>

          {/* Page content */}
          <div className="relative z-10">
            {children}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Layout;
