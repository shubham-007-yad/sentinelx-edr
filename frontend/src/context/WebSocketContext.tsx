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
  dismissToast: (id: string | number) => void;
  clearLiveAlerts: () => void;
}

const WebSocketContext = createContext<WebSocketContextType | undefined>(undefined);

const getWebSocketUrl = (token?: string | null) => {
  const apiBase = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api/v1";
  const wsProto = apiBase.startsWith("https") ? "wss" : "ws";
  const host = apiBase.replace(/^https?:\/\//, "");
  const authToken = token || localStorage.getItem("sentinelx_token") || "";
  const tokenQuery = authToken ? `?token=${encodeURIComponent(authToken)}` : "";
  return `${wsProto}://${host}/ws/alerts${tokenQuery}`;
};

export const WebSocketProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, token } = useAuth();
  const [isConnected, setIsConnected] = useState<boolean>(false);
  const [liveAlerts, setLiveAlerts] = useState<LiveAlertPayload[]>([]);
  const [activeToasts, setActiveToasts] = useState<LiveAlertPayload[]>([]);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const isAuthenticatedRef = useRef<boolean>(isAuthenticated);
  const tokenRef = useRef<string | null>(token);
  const reconnectAttemptsRef = useRef<number>(0);

  useEffect(() => {
    isAuthenticatedRef.current = isAuthenticated;
    tokenRef.current = token;
  }, [isAuthenticated, token]);

  const connectWebSocket = () => {
    if (!isAuthenticatedRef.current) return;
    const currentToken = tokenRef.current || localStorage.getItem("sentinelx_token");
    if (!currentToken) {
      console.warn("[SentinelX WS] No authentication token found. Connection aborted.");
      return;
    }

    if (wsRef.current && (wsRef.current.readyState === WebSocket.CONNECTING || wsRef.current.readyState === WebSocket.OPEN)) {
      return;
    }

    const wsUrl = getWebSocketUrl(currentToken);
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
        if ((payload.event === "NEW_ALERT" || payload.event === "DETECTION_EVENT") && payload.data) {
          const raw = payload.data;
          const toastId = raw.id || raw.alert_id || `toast-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
          const alertData: LiveAlertPayload = {
            id: toastId,
            threat_id: raw.threat_id,
            device_id: raw.device_id,
            title: raw.title || raw.rule_name || "Security Alert Detected",
            severity: raw.severity || "HIGH",
            device: raw.device || raw.device_id || "Endpoint Node",
            file: raw.file || raw.file_name || raw.process_name || raw.file_path || "Security Event",
            message: raw.message || raw.description || "",
            time: raw.time || raw.created_at || new Date().toISOString(),
            status: raw.status || "UNREAD",
          };
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
      if (event.code === 1008) {
        console.error("[SentinelX WS] Connection rejected due to policy violation / unauthorized (1008). Reconnect stopped.");
        return;
      }
      if (isAuthenticatedRef.current) {
        reconnectAttemptsRef.current += 1;
        const delay = Math.min(10000, 3000 * Math.pow(1.5, reconnectAttemptsRef.current - 1));
        if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = setTimeout(connectWebSocket, delay);
      }
    };

    socket.onerror = () => {
      socket.close();
    };
  };

  useEffect(() => {
    if (isAuthenticated && (token || localStorage.getItem("sentinelx_token"))) {
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
  }, [isAuthenticated, token]);

  const dismissToast = (id: string | number) => {
    setActiveToasts((prev) => prev.filter((t, idx) => (t.id !== id && idx !== id)));
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
