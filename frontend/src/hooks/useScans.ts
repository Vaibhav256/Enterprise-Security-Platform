import { useState, useEffect } from 'react';
import { scanApi } from '../api/client';
import type { Scan, ScanListResponse } from '../types';

interface UseScansOptions {
  status?: string;
  tool_name?: string;
  page?: number;
  per_page?: number;
  autoRefresh?: boolean;
  refreshInterval?: number;
}

export const useScans = (options: UseScansOptions = {}) => {
  const [data, setData] = useState<ScanListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const fetchScans = async () => {
    try {
      setLoading(true);
      const result = await scanApi.listScans({
        status: options.status,
        tool_name: options.tool_name,
        page: options.page || 1,
        per_page: options.per_page || 20,
      });
      setData(result);
      setError(null);
    } catch (err) {
      setError(err as Error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();

    // Auto-refresh if enabled
    if (options.autoRefresh) {
      const interval = setInterval(fetchScans, options.refreshInterval || 5000);
      return () => clearInterval(interval);
    }
  }, [options.status, options.tool_name, options.page, options.per_page]);

  return { data, loading, error, refetch: fetchScans };
};

export const useScan = (scanId: string | undefined) => {
  const [data, setData] = useState<Scan | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const fetchScan = async () => {
    if (!scanId) return;

    try {
      setLoading(true);
      const result = await scanApi.getScan(scanId);
      setData(result);
      setError(null);
    } catch (err) {
      setError(err as Error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScan();
  }, [scanId]);

  return { data, loading, error, refetch: fetchScan };
};
