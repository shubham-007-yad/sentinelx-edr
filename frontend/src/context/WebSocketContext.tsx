import React, { createContext, useContext, useEffect, useState, useRef } from "react";
import { useAuth } from "./AuthContext";

export interface LiveAlertPayload {
  id?: string;
  threat_id?: string;
  device_id?: string;
  title: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | string;
  device: string;
  file: string;
  message?: string;
  time: string;
  created_at?: string;
  status?: string;
}

interface WebSocketContextType {
  isConnected: boolean;
  liveAlerts: LiveAlertPayload[];
  activeToasts: LiveAlertPayload[];
  dismissToast: (index: number) => void;
  clearLiveAlerts: () => void;
}

const WebSocketContext = createContext<WebSocketContextType | undefined>(undefined);

const getWebSocketUrl = () => {
  const apiBase = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api/v1";
  const wsProto = apiBase.startsWith("https") ? "wss" : "ws";
  const host = apiBase.replace(/^https?:\/\//, "");
  return `${wsProto}://${host}/ws/alerts`;
};

export const WebSocketProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated } = useAuth();
  const [isConnected, setIsConnected] = useState<boolean>(false);
  const [liveAlerts, setLiveAlerts] = useState<LiveAlertPayload[]>([]);
  const [activeToasts, setActiveToasts] = useState<LiveAlertPayload[]>([]);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const isAuthenticatedRef = useRef<boolean>(isAuthenticated);
  const reconnectAttemptsRef = useRef<number>(0);

  useEffect(() => {
    isAuthenticatedRef.current = isAuthenticated;
  }, [isAuthenticated]);

  const connectWebSocket = () => {
    if (!isAuthenticatedRef.current) return;
    if (wsRef.current && (wsRef.current.readyState === WebSocket.CONNECTING || wsRef.current.readyState === WebSocket.OPEN)) {
      return;
    }

    const wsUrl = getWebSocketUrl();
    console.log(`[SentinelX WS] Opening connection to ${wsUrl}`);
    const socket = new WebSocket(wsUrl);
    wsRef.current = socket;

    socket.onopen = () => {
      console.log("[SentinelX WS] Real-Time Alert Stream Connected.");
      setIsConnected(true);
      reconnectAttemptsRef.current = 0;
    };

    socket.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.event === "NEW_ALERT" && payload.data) {
          const alertData: LiveAlertPayload = payload.data;
          setLiveAlerts((prev) => [alertData, ...prev]);
          setActiveToasts((prev) => [alertData, ...prev]);
        }
      } catch (err) {
        console.error("[SentinelX WS] Error parsing WebSocket message:", err);
      }
    };

    socket.onclose = (event) => {
      setIsConnected(false);
      wsRef.current = null;
      if (isAuthenticatedRef.current) {
        // Backoff reconnect delay up to 10 seconds
        reconnectAttemptsRef.current += 1;
        const delay = Math.min(10000, 3000 * Math.pow(1.5, reconnectAttemptsRef.current - 1));
        console.log(`[SentinelX WS] Closed (code: ${event.code}). Reconnecting in ${(delay / 1000).toFixed(1)}s...`);
        if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = setTimeout(connectWebSocket, delay);
      }
    };

    socket.onerror = () => {
      console.warn("[SentinelX WS] WebSocket connection failed. Backend might be restarting or offline.");
      socket.close();
    };
  };

  useEffect(() => {
    if (isAuthenticated) {
      connectWebSocket();
    } else {
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
      setIsConnected(false);
      reconnectAttemptsRef.current = 0;
    }

    return () => {
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [isAuthenticated]);

  const dismissToast = (index: number) => {
    setActiveToasts((prev) => prev.filter((_, i) => i !== index));
  };

  const clearLiveAlerts = () => {
    setLiveAlerts([]);
  };

  return (
    <WebSocketContext.Provider
      value={{
        isConnected,
        liveAlerts,
        activeToasts,
        dismissToast,
        clearLiveAlerts,
      }}
    >
      {children}
    </WebSocketContext.Provider>
  );
};

export const useWebSocket = () => {
  const context = useContext(WebSocketContext);
  if (!context) {
    throw new Error("useWebSocket must be used within a WebSocketProvider");
  }
  return context;
};
