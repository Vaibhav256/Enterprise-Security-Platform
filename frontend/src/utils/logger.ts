/**
 * Production-Safe Logger
 * 
 * Provides console logging in development but suppresses in production.
 * Use this instead of direct console.log() calls.
 */

const isDevelopment = import.meta.env.MODE === 'development';

export const logger = {
  log: (...args: any[]) => {
    if (isDevelopment) {
      console.log(...args);
    }
  },

  info: (...args: any[]) => {
    if (isDevelopment) {
      console.info(...args);
    }
  },

  warn: (...args: any[]) => {
    if (isDevelopment) {
      console.warn(...args);
    }
  },

  error: (...args: any[]) => {
    // Always log errors, even in production (for error tracking services)
    console.error(...args);
    
    // In production, you could send to error tracking service here
    // if (!isDevelopment) {
    //   // sendToSentry(args);
    // }
  },

  debug: (...args: any[]) => {
    if (isDevelopment) {
      console.debug(...args);
    }
  },

  group: (label: string) => {
    if (isDevelopment) {
      console.group(label);
    }
  },

  groupEnd: () => {
    if (isDevelopment) {
      console.groupEnd();
    }
  },

  table: (data: any) => {
    if (isDevelopment) {
      console.table(data);
    }
  },
};

export default logger;
