import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { useWebSocket } from "../context/WebSocketContext";
import { WebSocketStatusBadge } from "../components/WebSocketStatusBadge";
import { NotificationCenter } from "../components/NotificationCenter";
import {
  getAlerts,
  bulkMarkAlertsRead,
  bulkAcknowledgeAlerts,
  type AlertRecord,
} from "../services/alert";

export const AlertManagement: React.FC = () => {
  const { user, logout } = useAuth();
  const { liveAlerts } = useWebSocket();

  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters & Search
  const [selectedSeverity, setSelectedSeverity] = useState<string>("");
  const [selectedStatus, setSelectedStatus] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState<string>("");

  // Bulk Selection
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [isProcessingBulk, setIsProcessingBulk] = useState<boolean>(false);

  const fetchAlertsData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await getAlerts(
        0,
        100,
        selectedStatus || undefined,
        selectedSeverity || undefined,
        undefined,
        searchQuery || undefined
      );
      setAlerts(data);
      setSelectedIds([]);
    } catch (err: any) {
      console.error("Failed to load alerts:", err);
      setError(err.response?.data?.detail || "Failed to load real-time alerts.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchAlertsData();
  }, [selectedSeverity, selectedStatus]);

  // Live WebSocket Update
  useEffect(() => {
    if (liveAlerts.length > 0) {
      fetchAlertsData();
    }
  }, [liveAlerts]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchAlertsData();
  };

  // Checkbox handlers
  const handleSelectAll = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.checked) {
      setSelectedIds(alerts.map((a) => a.id));
    } else {
      setSelectedIds([]);
    }
  };

  const handleToggleSelect = (id: string) => {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  // Bulk Action handlers
  const handleBulkMarkRead = async () => {
    if (selectedIds.length === 0) return;
    setIsProcessingBulk(true);
    try {
      await bulkMarkAlertsRead(selectedIds);
      await fetchAlertsData();
    } catch (err: any) {
      alert("Failed to mark selected alerts as read: " + (err.response?.data?.detail || err.message));
    } finally {
      setIsProcessingBulk(false);
    }
  };

  const handleBulkAcknowledge = async () => {
    if (selectedIds.length === 0) return;
    setIsProcessingBulk(true);
    try {
      await bulkAcknowledgeAlerts(selectedIds);
      await fetchAlertsData();
    } catch (err: any) {
      alert("Failed to acknowledge selected alerts: " + (err.response?.data?.detail || err.message));
    } finally {
      setIsProcessingBulk(false);
    }
  };

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity.toUpperCase()) {
      case "CRITICAL":
        return "badge-danger";
      case "HIGH":
        return "badge-warning";
      case "MEDIUM":
        return "badge-info";
      default:
        return "badge-secondary";
    }
  };

  const getStatusBadgeStyle = (status: string) => {
    switch (status.toUpperCase()) {
      case "UNREAD":
        return { background: "rgba(255, 0, 85, 0.15)", color: "#ff0055", border: "1px solid #ff0055" };
      case "READ":
        return { background: "rgba(0, 240, 255, 0.15)", color: "#00f0ff", border: "1px solid #00f0ff" };
      case "ACKNOWLEDGED":
        return { background: "rgba(0, 255, 157, 0.15)", color: "#00ff9d", border: "1px solid #00ff9d" };
      default:
        return { background: "rgba(255, 255, 255, 0.1)", color: "#aaa", border: "1px solid #666" };
    }
  };

  const allSelected = alerts.length > 0 && selectedIds.length === alerts.length;

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg-primary)", color: "var(--text-main)", padding: "2rem" }}>
      {/* Navigation Header */}
      <header className="glass-panel" style={{ position: "relative", zIndex: 100, display: "flex", justifyContent: "space-between", alignItems: "center", gap: "1rem", padding: "0.8rem 1.5rem", marginBottom: "2rem", flexWrap: "wrap" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "1.5rem", flexWrap: "wrap" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.8rem", flexShrink: 0 }}>
            <div style={{ fontSize: "1.4rem", fontWeight: "800", color: "var(--accent-cyan)", letterSpacing: "1px" }}>
              SENTINEL<span style={{ color: "var(--text-main)" }}>X</span>
            </div>
            <span style={{ background: "rgba(0, 240, 255, 0.15)", color: "var(--accent-cyan)", border: "1px solid var(--accent-cyan)", padding: "0.2rem 0.5rem", borderRadius: "4px", fontSize: "0.7rem", fontFamily: "var(--font-mono)", fontWeight: "700", whiteSpace: "nowrap" }}>
              🚨 ALERT MANAGEMENT
            </span>
            <WebSocketStatusBadge />
          </div>

          <nav style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap" }}>
            <Link
              to="/dashboard"
              style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem", borderRadius: "6px", whiteSpace: "nowrap" }}
            >
              Overview
            </Link>
            <Link
              to="/threats"
              style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem", borderRadius: "6px", whiteSpace: "nowrap" }}
            >
              Threat Dashboard
            </Link>
            <Link
              to="/alerts"
              style={{ color: "var(--accent-cyan)", background: "rgba(0, 240, 255, 0.1)", border: "1px solid rgba(0, 240, 255, 0.4)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem", borderRadius: "6px", whiteSpace: "nowrap" }}
            >
              Alerts
            </Link>
            <Link
              to="/usb-activity"
              style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem", borderRadius: "6px", whiteSpace: "nowrap" }}
            >
              USB Activity
            </Link>
            <Link
              to="/usb-scans"
              style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem", borderRadius: "6px", whiteSpace: "nowrap" }}
            >
              USB Scan Results
            </Link>
          </nav>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "1.2rem", marginLeft: "auto", flexShrink: 0 }}>
          <NotificationCenter />
          <div style={{ textAlign: "right" }}>
            <div style={{ fontWeight: "600", fontSize: "0.9rem", whiteSpace: "nowrap" }}>{user?.username}</div>
            <div style={{ fontSize: "0.7rem", color: "var(--text-muted)", whiteSpace: "nowrap" }}>{user?.email}</div>
          </div>
          <span className={`badge badge-${user?.role?.toLowerCase()}`}>{user?.role}</span>
          <button onClick={logout} className="btn-secondary" style={{ padding: "0.4rem 0.8rem", fontSize: "0.8rem", whiteSpace: "nowrap" }}>
            Logout
          </button>
        </div>
      </header>

      {/* Main Alert Management Content */}
      <main style={{ maxWidth: "1400px", margin: "0 auto" }}>
        {/* Header & Controls Panel */}
        <div className="glass-panel" style={{ padding: "1.5rem", marginBottom: "2rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "1rem" }}>
            <div>
              <h2 style={{ fontSize: "1.3rem", fontWeight: "700", color: "var(--accent-cyan)", margin: 0 }}>
                Real-Time Security Alert Feed
              </h2>
              <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", margin: "0.3rem 0 0 0" }}>
                Filter, search, and manage system security alerts broadcast by the Threat Engine.
              </p>
            </div>

            {/* Bulk Action Controls */}
            {selectedIds.length > 0 && (
              <div style={{ display: "flex", alignItems: "center", gap: "1rem", background: "rgba(0, 240, 255, 0.08)", padding: "0.6rem 1rem", borderRadius: "8px", border: "1px solid rgba(0, 240, 255, 0.3)" }}>
                <span style={{ fontSize: "0.85rem", fontWeight: "600", color: "var(--accent-cyan)" }}>
                  {selectedIds.length} Alert(s) Selected
                </span>
                <button
                  onClick={handleBulkMarkRead}
                  disabled={isProcessingBulk}
                  style={{
                    background: "rgba(0, 240, 255, 0.2)",
                    border: "1px solid #00f0ff",
                    color: "#00f0ff",
                    padding: "0.35rem 0.75rem",
                    borderRadius: "6px",
                    cursor: "pointer",
                    fontWeight: "600",
                    fontSize: "0.8rem",
                  }}
                >
                  Mark Selected as Read
                </button>
                <button
                  onClick={handleBulkAcknowledge}
                  disabled={isProcessingBulk}
                  style={{
                    background: "rgba(0, 255, 157, 0.2)",
                    border: "1px solid #00ff9d",
                    color: "#00ff9d",
                    padding: "0.35rem 0.75rem",
                    borderRadius: "6px",
                    cursor: "pointer",
                    fontWeight: "600",
                    fontSize: "0.8rem",
                  }}
                >
                  Acknowledge Selected
                </button>
              </div>
            )}
          </div>

          {/* Filters Form */}
          <form onSubmit={handleSearchSubmit} style={{ display: "flex", gap: "1rem", marginTop: "1.5rem", flexWrap: "wrap", alignItems: "center" }}>
            <div style={{ display: "flex", flexDirection: "column", gap: "0.3rem" }}>
              <label style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: "600" }}>SEVERITY</label>
              <select
                value={selectedSeverity}
                onChange={(e) => setSelectedSeverity(e.target.value)}
                style={{
                  background: "rgba(15, 20, 32, 0.9)",
                  border: "1px solid rgba(255, 255, 255, 0.15)",
                  color: "#fff",
                  padding: "0.5rem 0.8rem",
                  borderRadius: "6px",
                  fontSize: "0.85rem",
                }}
              >
                <option value="">All Severities</option>
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "0.3rem" }}>
              <label style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: "600" }}>STATUS</label>
              <select
                value={selectedStatus}
                onChange={(e) => setSelectedStatus(e.target.value)}
                style={{
                  background: "rgba(15, 20, 32, 0.9)",
                  border: "1px solid rgba(255, 255, 255, 0.15)",
                  color: "#fff",
                  padding: "0.5rem 0.8rem",
                  borderRadius: "6px",
                  fontSize: "0.85rem",
                }}
              >
                <option value="">All Statuses</option>
                <option value="UNREAD">UNREAD</option>
                <option value="READ">READ</option>
                <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
              </select>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "0.3rem", flex: 1, minWidth: "220px" }}>
              <label style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: "600" }}>SEARCH ALERTS</label>
              <input
                type="text"
                placeholder="Search by title, message, host device..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{
                  background: "rgba(15, 20, 32, 0.9)",
                  border: "1px solid rgba(255, 255, 255, 0.15)",
                  color: "#fff",
                  padding: "0.5rem 0.8rem",
                  borderRadius: "6px",
                  fontSize: "0.85rem",
                }}
              />
            </div>

            <button
              type="submit"
              style={{
                marginTop: "1.2rem",
                background: "rgba(0, 240, 255, 0.15)",
                border: "1px solid var(--accent-cyan)",
                color: "var(--accent-cyan)",
                padding: "0.5rem 1rem",
                borderRadius: "6px",
                cursor: "pointer",
                fontWeight: "600",
                fontSize: "0.85rem",
              }}
            >
              Apply Filter
            </button>
          </form>
        </div>

        {/* Table View */}
        <div className="glass-panel" style={{ padding: "1.5rem", overflowX: "auto" }}>
          {error && (
            <div style={{ background: "rgba(255, 0, 85, 0.1)", border: "1px solid #ff0055", color: "#ff0055", padding: "1rem", borderRadius: "8px", marginBottom: "1rem" }}>
              {error}
            </div>
          )}

          {isLoading ? (
            <div style={{ padding: "3rem", textAlign: "center", color: "var(--accent-cyan)" }}>
              Loading real-time alerts database...
            </div>
          ) : alerts.length === 0 ? (
            <div style={{ padding: "3rem", textAlign: "center", color: "var(--text-muted)" }}>
              No alerts match the current filter criteria.
            </div>
          ) : (
            <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.1)", color: "var(--text-muted)", fontSize: "0.8rem", textTransform: "uppercase" }}>
                  <th style={{ padding: "0.8rem", width: "40px" }}>
                    <input
                      type="checkbox"
                      checked={allSelected}
                      onChange={handleSelectAll}
                      style={{ cursor: "pointer" }}
                    />
                  </th>
                  <th style={{ padding: "0.8rem" }}>Title</th>
                  <th style={{ padding: "0.8rem" }}>Severity</th>
                  <th style={{ padding: "0.8rem" }}>Device</th>
                  <th style={{ padding: "0.8rem" }}>Threat File / Description</th>
                  <th style={{ padding: "0.8rem" }}>Status</th>
                  <th style={{ padding: "0.8rem" }}>Created Time</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alertItem: AlertRecord) => {
                  const isSelected = selectedIds.includes(alertItem.id);
                  const statusStyle = getStatusBadgeStyle(alertItem.status);

                  return (
                    <tr
                      key={alertItem.id}
                      style={{
                        borderBottom: "1px solid rgba(255, 255, 255, 0.05)",
                        background: isSelected ? "rgba(0, 240, 255, 0.06)" : "transparent",
                        transition: "background 0.15s ease",
                      }}
                    >
                      <td style={{ padding: "0.8rem" }}>
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => handleToggleSelect(alertItem.id)}
                          style={{ cursor: "pointer" }}
                        />
                      </td>
                      <td style={{ padding: "0.8rem", fontWeight: "700", fontSize: "0.9rem" }}>
                        {alertItem.title}
                      </td>
                      <td style={{ padding: "0.8rem" }}>
                        <span className={`badge ${getSeverityBadgeClass(alertItem.severity)}`}>
                          {alertItem.severity}
                        </span>
                      </td>
                      <td style={{ padding: "0.8rem", fontFamily: "var(--font-mono)", color: "var(--accent-cyan)", fontSize: "0.85rem" }}>
                        {alertItem.device}
                      </td>
                      <td style={{ padding: "0.8rem", fontSize: "0.85rem", color: "#e0e0e0" }}>
                        <div>{alertItem.message}</div>
                        {alertItem.file && (
                          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                            File: {alertItem.file}
                          </div>
                        )}
                      </td>
                      <td style={{ padding: "0.8rem" }}>
                        <span
                          style={{
                            ...statusStyle,
                            padding: "0.2rem 0.6rem",
                            borderRadius: "4px",
                            fontSize: "0.75rem",
                            fontWeight: "700",
                            fontFamily: "var(--font-mono)",
                          }}
                        >
                          {alertItem.status}
                        </span>
                      </td>
                      <td style={{ padding: "0.8rem", fontSize: "0.8rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                        {new Date(alertItem.created_at).toLocaleString()}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </main>
    </div>
  );
};
