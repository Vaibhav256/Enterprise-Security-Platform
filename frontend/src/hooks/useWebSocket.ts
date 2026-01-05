import { useEffect, useRef, useState, useCallback } from 'react';
import { io, Socket } from 'socket.io-client';
import type { WSMessage } from '../types';

interface UseWebSocketOptions {
  url?: string;
  autoConnect?: boolean;
  onMessage?: (message: WSMessage) => void;
  onConnect?: () => void;
  onDisconnect?: () => void;
  onError?: (error: Error) => void;
}

export const useWebSocket = (options: UseWebSocketOptions = {}) => {
  const {
    url = 'http://localhost:5000',
    autoConnect = true,
    onMessage,
    onConnect,
    onDisconnect,
    onError,
  } = options;

  const socketRef = useRef<Socket | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<WSMessage | null>(null);
  
  // Store callbacks in refs to avoid recreating connect/disconnect functions
  const onMessageRef = useRef(onMessage);
  const onConnectRef = useRef(onConnect);
  const onDisconnectRef = useRef(onDisconnect);
  const onErrorRef = useRef(onError);
  
  // Update refs when callbacks change
  useEffect(() => {
    onMessageRef.current = onMessage;
    onConnectRef.current = onConnect;
    onDisconnectRef.current = onDisconnect;
    onErrorRef.current = onError;
  }, [onMessage, onConnect, onDisconnect, onError]);

  const connect = useCallback(() => {
    if (socketRef.current?.connected) return;

    const socket = io(url, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      reconnectionAttempts: 5,
    });

    socket.on('connect', () => {
      console.log('WebSocket connected');
      setIsConnected(true);
      onConnectRef.current?.();
    });

    socket.on('disconnect', () => {
      console.log('WebSocket disconnected');
      setIsConnected(false);
      onDisconnectRef.current?.();
    });

    socket.on('scan_update', (data: any) => {
      const message: WSMessage = {
        type: 'scan_update',
        scan_id: data.scan_id,
        data,
      };
      setLastMessage(message);
      onMessageRef.current?.(message);
    });

    socket.on('scan_complete', (data: any) => {
      const message: WSMessage = {
        type: 'scan_complete',
        scan_id: data.scan_id,
        data,
      };
      setLastMessage(message);
      onMessageRef.current?.(message);
    });

    socket.on('scan_failed', (data: any) => {
      const message: WSMessage = {
        type: 'scan_failed',
        scan_id: data.scan_id,
        data,
      };
      setLastMessage(message);
      onMessageRef.current?.(message);
    });

    socket.on('error', (error: Error) => {
      console.error('WebSocket error:', error);
      onErrorRef.current?.(error);
    });

    socketRef.current = socket;
  }, [url]);

  const disconnect = useCallback(() => {
    if (socketRef.current) {
      socketRef.current.disconnect();
      socketRef.current = null;
      setIsConnected(false);
    }
  }, []);

  const subscribe = useCallback((scanId: string) => {
    if (socketRef.current?.connected) {
      socketRef.current.emit('subscribe', { scan_id: scanId });
      console.log(`Subscribed to scan: ${scanId}`);
    }
  }, []);

  const unsubscribe = useCallback((scanId: string) => {
    if (socketRef.current?.connected) {
      socketRef.current.emit('unsubscribe', { scan_id: scanId });
      console.log(`Unsubscribed from scan: ${scanId}`);
    }
  }, []);

  useEffect(() => {
    if (autoConnect) {
      connect();
    }

    // Cleanup: only disconnect when component unmounts
    return () => {
      disconnect();
    };
    // Only reconnect if autoConnect or url changes
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoConnect, url]);

  return {
    isConnected,
    lastMessage,
    connect,
    disconnect,
    subscribe,
    unsubscribe,
  };
};
