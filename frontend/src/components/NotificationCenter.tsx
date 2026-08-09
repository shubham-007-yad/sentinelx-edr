import React, { useState, useEffect, useRef } from "react";
import { useWebSocket } from "../context/WebSocketContext";
import { getAlerts, getUnreadCount, markAlertRead, markAllAlertsRead, type AlertRecord } from "../services/alert";

export const NotificationCenter: React.FC = () => {
  const { liveAlerts } = useWebSocket();
  const [isOpen, setIsOpen] = useState<boolean>(false);
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [unreadCount, setUnreadCount] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const fetchAlertData = async () => {
    try {
      const [alertsData, count] = await Promise.all([
        getAlerts(30),
        getUnreadCount()
      ]);
      setAlerts(alertsData);
      setUnreadCount(count);
    } catch (err) {
      console.error("Failed to load notifications:", err);
    }
  };

  useEffect(() => {
    fetchAlertData();
  }, []);

  // Refresh when new real-time WebSocket alert arrives
  useEffect(() => {
    if (liveAlerts.length > 0) {
      fetchAlertData();
    }
  }, [liveAlerts]);

  // Close dropdown on click outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const handleMarkRead = async (alertId: string, currentStatus: string) => {
    if (currentStatus === "READ") return;
    try {
      await markAlertRead(alertId);
      setAlerts((prev) =>
        prev.map((a) => (a.id === alertId ? { ...a, status: "READ" } : a))
      );
      setUnreadCount((prev) => Math.max(0, prev - 1));
    } catch (err) {
      console.error("Failed to mark alert as read:", err);
    }
  };

  const handleMarkAllRead = async () => {
    setLoading(true);
    try {
      await markAllAlertsRead();
      setAlerts((prev) => prev.map((a) => ({ ...a, status: "READ" })));
      setUnreadCount(0);
    } catch (err) {
      console.error("Failed to mark all as read:", err);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityBadgeColor = (severity: string) => {
    switch (severity.toUpperCase()) {
      case "CRITICAL":
        return "#ff0055";
      case "HIGH":
        return "#ffaa00";
      case "MEDIUM":
        return "#00f0ff";
      default:
        return "#8a8f9d";
    }
  };

  return (
    <div ref={dropdownRef} style={{ position: "relative", display: "inline-block", zIndex: 9999, flexShrink: 0 }}>
      {/* Bell Icon Trigger */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        style={{
          position: "relative",
          background: isOpen ? "rgba(0, 240, 255, 0.15)" : "rgba(255, 255, 255, 0.05)",
          border: isOpen ? "1px solid var(--accent-cyan)" : "1px solid rgba(255, 255, 255, 0.1)",
          color: "var(--text-main)",
          padding: "0.4rem 0.8rem",
          borderRadius: "6px",
          cursor: "pointer",
          display: "flex",
          alignItems: "center",
          gap: "0.5rem",
          fontWeight: "600",
          fontSize: "0.9rem",
          whiteSpace: "nowrap",
          flexShrink: 0,
          transition: "all 0.2s ease",
        }}
      >
        <span style={{ whiteSpace: "nowrap" }}>🔔</span>
        {unreadCount > 0 ? (
          <span
            style={{
              background: "#ff0055",
              color: "#ffffff",
              borderRadius: "10px",
              padding: "0.1rem 0.45rem",
              fontSize: "0.75rem",
              fontWeight: "800",
              fontFamily: "var(--font-mono)",
              boxShadow: "0 0 10px rgba(255, 0, 85, 0.6)",
              whiteSpace: "nowrap",
              display: "inline-block",
            }}
          >
            ({unreadCount})
          </span>
        ) : (
          <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)", whiteSpace: "nowrap", display: "inline-block" }}>
            (0)
          </span>
        )}
      </button>

      {/* Dropdown Notification Center */}
      {isOpen && (
        <div
          style={{
            position: "absolute",
            top: "calc(100% + 8px)",
            right: 0,
            width: "min(380px, calc(100vw - 32px))",
            maxHeight: "min(480px, 80vh)",
            background: "rgba(12, 16, 26, 0.95)",
            backdropFilter: "blur(16px)",
            border: "1px solid rgba(255, 255, 255, 0.12)",
            borderRadius: "10px",
            boxShadow: "0 16px 40px rgba(0, 0, 0, 0.6), 0 0 20px rgba(0, 240, 255, 0.1)",
            zIndex: 99999,
            display: "flex",
            flexDirection: "column",
            overflow: "hidden",
          }}
        >
          {/* Notification Header */}
          <div
            style={{
              padding: "0.8rem 1rem",
              borderBottom: "1px solid rgba(255, 255, 255, 0.08)",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              background: "rgba(0, 240, 255, 0.03)",
            }}
          >
            <div style={{ fontWeight: "700", fontSize: "0.9rem", color: "var(--accent-cyan)" }}>
              Notifications {unreadCount > 0 && `(${unreadCount} Unread)`}
            </div>
            {unreadCount > 0 && (
              <button
                onClick={handleMarkAllRead}
                disabled={loading}
                style={{
                  background: "transparent",
                  border: "none",
                  color: "#00f0ff",
                  fontSize: "0.75rem",
                  fontWeight: "600",
                  cursor: "pointer",
                  textDecoration: "underline",
                }}
              >
                Mark all as read
              </button>
            )}
          </div>

          {/* Alert List */}
          <div style={{ overflowY: "auto", flex: 1 }}>
            {alerts.length === 0 ? (
              <div style={{ padding: "2rem", textAlign: "center", color: "var(--text-muted)", fontSize: "0.85rem" }}>
                No notifications recorded.
              </div>
            ) : (
              alerts.map((alertItem: AlertRecord) => {
                const isUnread = alertItem.status === "UNREAD";
                const badgeColor = getSeverityBadgeColor(alertItem.severity);

                return (
                  <div
                    key={alertItem.id}
                    onClick={() => handleMarkRead(alertItem.id, alertItem.status)}
                    style={{
                      padding: "0.8rem 1rem",
                      borderBottom: "1px solid rgba(255, 255, 255, 0.05)",
                      background: isUnread ? "rgba(255, 0, 85, 0.06)" : "transparent",
                      cursor: isUnread ? "pointer" : "default",
                      transition: "background 0.2s ease",
                      display: "flex",
                      flexDirection: "column",
                      gap: "0.25rem",
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <span style={{ fontWeight: "700", fontSize: "0.85rem", color: isUnread ? "#ffffff" : "#aaa" }}>
                        {alertItem.title}
                      </span>
                      <span
                        style={{
                          background: `${badgeColor}22`,
                          color: badgeColor,
                          border: `1px solid ${badgeColor}`,
                          fontSize: "0.65rem",
                          fontWeight: "800",
                          padding: "0.1rem 0.4rem",
                          borderRadius: "4px",
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        {alertItem.severity}
                      </span>
                    </div>

                    <div style={{ fontSize: "0.8rem", color: "#00f0ff", fontFamily: "var(--font-mono)" }}>
                      {alertItem.file || alertItem.message}
                    </div>

                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "0.2rem", fontSize: "0.7rem", color: "var(--text-muted)" }}>
                      <span>Host: {alertItem.device}</span>
                      <span>{new Date(alertItem.created_at).toLocaleTimeString()}</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
};
