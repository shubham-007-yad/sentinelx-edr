import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { WebSocketStatusBadge } from "../components/WebSocketStatusBadge";
import { NotificationCenter } from "../components/NotificationCenter";
import {
  getResponseActions,
  triggerResponseAction,
  retryResponseAction,
  cancelResponseAction,
  getAuditLogsForAction
} from "../services/response";
import type { ResponseActionRecord, ResponseAuditLog } from "../services/response";
import { getDevices } from "../services/usb";
import type { Device } from "../types/usb";

export const ResponseDashboard: React.FC = () => {
  const { user, logout } = useAuth();
  const [actions, setActions] = useState<ResponseActionRecord[]>([]);
  const [devicesMap, setDevicesMap] = useState<Record<string, string>>({});
  const [devicesList, setDevicesList] = useState<Device[]>([]);
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Manual Trigger Modal State
  const [showModal, setShowModal] = useState<boolean>(false);
  const [selectedDevice, setSelectedDevice] = useState<string>("");
  const [selectedAction, setSelectedAction] = useState<string>("QUARANTINE");
  const [triggering, setTriggering] = useState<boolean>(false);

  // Audit Trail Drawer State
  const [selectedAuditAction, setSelectedAuditAction] = useState<ResponseActionRecord | null>(null);
  const [auditLogs, setAuditLogs] = useState<ResponseAuditLog[]>([]);
  const [loadingAudit, setLoadingAudit] = useState<boolean>(false);

  const handleOpenAuditTrail = async (actionRecord: ResponseActionRecord) => {
    setSelectedAuditAction(actionRecord);
    setLoadingAudit(true);
    try {
      const logs = await getAuditLogsForAction(actionRecord.id);
      setAuditLogs(logs);
    } catch (err) {
      console.error("Failed to load audit logs:", err);
    } finally {
      setLoadingAudit(false);
    }
  };

  const fetchData = async () => {
    setLoading(true);
    try {
      const [actionsData, devicesData] = await Promise.all([
        getResponseActions(0, 100, undefined, statusFilter),
        getDevices()
      ]);
      setActions(actionsData);
      setDevicesList(devicesData);

      const dMap: Record<string, string> = {};
      devicesData.forEach((d) => {
        dMap[d.id] = d.hostname;
      });
      setDevicesMap(dMap);
      setError(null);
    } catch (err: any) {
      console.error("Failed to fetch response actions:", err);
      setError("Failed to load response engine logs from backend.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [statusFilter]);

  const handleRetry = async (actionId: string) => {
    try {
      await retryResponseAction(actionId);
      fetchData();
    } catch (err: any) {
      alert(`Retry failed: ${err?.response?.data?.detail || err.message}`);
    }
  };

  const handleCancel = async (actionId: string) => {
    try {
      await cancelResponseAction(actionId);
      fetchData();
    } catch (err: any) {
      alert(`Cancellation failed: ${err?.response?.data?.detail || err.message}`);
    }
  };

  const handleTriggerSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedDevice) {
      alert("Please select a target device.");
      return;
    }
    setTriggering(true);
    try {
      await triggerResponseAction(selectedDevice, selectedAction, undefined, user?.username || "ADMIN");
      setShowModal(false);
      fetchData();
    } catch (err: any) {
      alert(`Trigger action failed: ${err?.response?.data?.detail || err.message}`);
    } finally {
      setTriggering(false);
    }
  };

  const formatDuration = (startedAt: string, completedAt?: string): string => {
    if (!completedAt) return "In progress...";
    const start = new Date(startedAt).getTime();
    const end = new Date(completedAt).getTime();
    const diffMs = Math.max(0, end - start);
    if (diffMs < 1000) return `${diffMs}ms`;
    return `${(diffMs / 1000).toFixed(2)}s`;
  };

  const getStatusBadgeClass = (status: string) => {
    switch (status) {
      case "SUCCESS": return "badge badge-low"; // green
      case "FAILED": return "badge badge-critical"; // red
      case "RUNNING": return "badge badge-medium"; // yellow/orange
      case "PENDING": return "badge badge-info"; // cyan
      case "CANCELLED": return "badge badge-offline";
      default: return "badge";
    }
  };

  const getActionBadgeStyle = (actionType: string) => {
    switch (actionType) {
      case "ISOLATE":
      case "ISOLATE_DEVICE":
        return { background: "rgba(255, 0, 85, 0.15)", color: "#ff0055", border: "1px solid rgba(255, 0, 85, 0.4)" };
      case "QUARANTINE":
      case "QUARANTINE_FILE":
        return { background: "rgba(255, 170, 0, 0.15)", color: "#ffaa00", border: "1px solid rgba(255, 170, 0, 0.4)" };
      case "DELETE":
      case "DELETE_FILE":
        return { background: "rgba(255, 50, 50, 0.15)", color: "#ff4444", border: "1px solid rgba(255, 50, 50, 0.4)" };
      case "START_SCAN":
        return { background: "rgba(0, 240, 255, 0.15)", color: "var(--accent-cyan)", border: "1px solid rgba(0, 240, 255, 0.4)" };
      default:
        return { background: "rgba(255, 255, 255, 0.1)", color: "var(--text-muted)" };
    }
  };

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg-primary)", color: "var(--text-main)", padding: "2rem" }}>
      {/* Header Navigation */}
      <header className="glass-panel" style={{ position: "relative", zIndex: 100, display: "flex", justifyContent: "space-between", alignItems: "center", gap: "1rem", padding: "0.8rem 1.5rem", marginBottom: "2rem", flexWrap: "wrap" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "1.5rem", flexWrap: "wrap" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.8rem", flexShrink: 0 }}>
            <div style={{ fontSize: "1.4rem", fontWeight: "800", color: "var(--accent-cyan)", letterSpacing: "1px" }}>
              SENTINEL<span style={{ color: "var(--text-main)" }}>X</span>
            </div>
            <span style={{ background: "rgba(0, 240, 255, 0.1)", color: "var(--accent-cyan)", padding: "0.2rem 0.5rem", borderRadius: "4px", fontSize: "0.7rem", fontFamily: "var(--font-mono)", whiteSpace: "nowrap" }}>
              RESPONSE ENGINE v1.0
            </span>
            <WebSocketStatusBadge />
          </div>

          <nav style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap" }}>
            <Link to="/dashboard" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>
              Overview
            </Link>
            <Link to="/threats" style={{ color: "#ff0055", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>
              Threat Dashboard
            </Link>
            <Link to="/alerts" style={{ color: "var(--accent-cyan)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>
              Alerts
            </Link>
            <Link to="/respond" style={{ color: "#00f0ff", background: "rgba(0, 240, 255, 0.15)", border: "1px solid rgba(0, 240, 255, 0.4)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>
              Response Console
            </Link>
            <Link to="/usb-activity" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>
              USB Activity
            </Link>
            <Link to="/usb-scans" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>
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
          <button onClick={logout} style={{ background: "rgba(255, 0, 85, 0.15)", border: "1px solid var(--accent-danger)", color: "var(--accent-danger)", padding: "0.5rem 1rem", borderRadius: "6px", cursor: "pointer", fontWeight: "600", fontSize: "0.8rem" }}>
            Logout
          </button>
        </div>
      </header>

      {/* Main Container */}
      <main style={{ maxWidth: "1280px", margin: "0 auto", display: "grid", gap: "2rem" }}>
        {/* Actions Controls Bar */}
        <div className="glass-panel" style={{ padding: "1.5rem", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "1rem" }}>
          <div>
            <h1 style={{ fontSize: "1.3rem", fontWeight: "800", color: "var(--accent-cyan)", margin: 0 }}>
              ENDPOINT RESPONSE ACTIONS
            </h1>
            <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", margin: "0.3rem 0 0 0" }}>
              Monitor, retry, or cancel real-time threat response dispatches across connected endpoints.
            </p>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "1rem", flexWrap: "wrap" }}>
            {/* Status Filter */}
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <span style={{ fontSize: "0.8rem", color: "var(--text-muted)", fontWeight: "600" }}>Filter Status:</span>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                style={{
                  background: "rgba(10, 13, 20, 0.9)",
                  color: "var(--text-main)",
                  border: "1px solid rgba(255, 255, 255, 0.15)",
                  borderRadius: "6px",
                  padding: "0.4rem 0.8rem",
                  fontSize: "0.85rem"
                }}
              >
                <option value="ALL">ALL STATUSES</option>
                <option value="PENDING">PENDING</option>
                <option value="RUNNING">RUNNING</option>
                <option value="SUCCESS">SUCCESS</option>
                <option value="FAILED">FAILED</option>
                <option value="CANCELLED">CANCELLED</option>
              </select>
            </div>

            {/* Manual Trigger Button */}
            <button
              onClick={() => setShowModal(true)}
              style={{
                background: "linear-gradient(135deg, rgba(0, 240, 255, 0.2), rgba(0, 150, 255, 0.4))",
                border: "1px solid var(--accent-cyan)",
                color: "#ffffff",
                padding: "0.5rem 1.2rem",
                borderRadius: "6px",
                fontWeight: "700",
                fontSize: "0.85rem",
                cursor: "pointer",
                boxShadow: "0 0 15px rgba(0, 240, 255, 0.2)"
              }}
            >
              + Dispatch Action
            </button>
          </div>
        </div>

        {/* Response Actions Table */}
        <div className="glass-panel" style={{ padding: "1.5rem" }}>
          {error && (
            <div style={{ background: "rgba(255, 0, 85, 0.1)", border: "1px solid var(--accent-danger)", color: "var(--accent-danger)", padding: "1rem", borderRadius: "6px", marginBottom: "1.5rem" }}>
              {error}
            </div>
          )}

          {loading ? (
            <div style={{ textAlign: "center", padding: "3rem", color: "var(--text-muted)" }}>
              Loading response logs...
            </div>
          ) : actions.length === 0 ? (
            <div style={{ textAlign: "center", padding: "3rem", color: "var(--text-muted)" }}>
              No response actions found for the selected filter.
            </div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left", fontSize: "0.85rem" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.1)", color: "var(--text-muted)", textTransform: "uppercase", fontSize: "0.75rem" }}>
                    <th style={{ padding: "0.8rem" }}>Device</th>
                    <th style={{ padding: "0.8rem" }}>Action</th>
                    <th style={{ padding: "0.8rem" }}>Status</th>
                    <th style={{ padding: "0.8rem" }}>Operator</th>
                    <th style={{ padding: "0.8rem" }}>Time</th>
                    <th style={{ padding: "0.8rem" }}>Duration</th>
                    <th style={{ padding: "0.8rem", textAlign: "right" }}>Control Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {actions.map((act) => (
                    <tr key={act.id} style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.05)", transition: "background 0.2s" }}>
                      {/* Device */}
                      <td style={{ padding: "0.9rem" }}>
                        <div style={{ fontWeight: "700", color: "var(--text-main)" }}>
                          {devicesMap[act.device_id] || "Unknown Endpoint"}
                        </div>
                        <div style={{ fontSize: "0.7rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                          {act.device_id}
                        </div>
                      </td>

                      {/* Action */}
                      <td style={{ padding: "0.9rem" }}>
                        <span style={{ padding: "0.25rem 0.6rem", borderRadius: "4px", fontSize: "0.75rem", fontWeight: "700", ...getActionBadgeStyle(act.action_type) }}>
                          {act.action_type}
                        </span>
                      </td>

                      {/* Status */}
                      <td style={{ padding: "0.9rem" }}>
                        <span className={getStatusBadgeClass(act.status)}>
                          {act.status}
                        </span>
                      </td>

                      {/* Operator */}
                      <td style={{ padding: "0.9rem", color: "var(--accent-cyan)", fontWeight: "600" }}>
                        {act.initiated_by}
                      </td>

                      {/* Time */}
                      <td style={{ padding: "0.9rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                        {new Date(act.started_at).toLocaleString()}
                      </td>

                      {/* Duration */}
                      <td style={{ padding: "0.9rem", fontFamily: "var(--font-mono)", color: "var(--text-main)" }}>
                        {formatDuration(act.started_at, act.completed_at)}
                      </td>

                      {/* Control Actions */}
                      <td style={{ padding: "0.9rem", textAlign: "right" }}>
                        <button
                          onClick={() => handleOpenAuditTrail(act)}
                          style={{
                            background: "rgba(0, 240, 255, 0.15)",
                            border: "1px solid rgba(0, 240, 255, 0.4)",
                            color: "var(--accent-cyan)",
                            padding: "0.3rem 0.7rem",
                            borderRadius: "4px",
                            fontWeight: "700",
                            fontSize: "0.75rem",
                            cursor: "pointer",
                            marginRight: "0.4rem"
                          }}
                        >
                          Audit Trail
                        </button>
                        {act.status === "FAILED" && (
                          <button
                            onClick={() => handleRetry(act.id)}
                            style={{
                              background: "rgba(255, 170, 0, 0.2)",
                              border: "1px solid #ffaa00",
                              color: "#ffaa00",
                              padding: "0.3rem 0.7rem",
                              borderRadius: "4px",
                              fontWeight: "700",
                              fontSize: "0.75rem",
                              cursor: "pointer",
                              marginRight: "0.4rem"
                            }}
                          >
                            Retry
                          </button>
                        )}
                        {(act.status === "PENDING" || act.status === "RUNNING") && (
                          <button
                            onClick={() => handleCancel(act.id)}
                            style={{
                              background: "rgba(255, 0, 85, 0.2)",
                              border: "1px solid var(--accent-danger)",
                              color: "var(--accent-danger)",
                              padding: "0.3rem 0.7rem",
                              borderRadius: "4px",
                              fontWeight: "700",
                              fontSize: "0.75rem",
                              cursor: "pointer"
                            }}
                          >
                            Cancel
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </main>

      {/* Manual Trigger Modal */}
      {showModal && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.75)", display: "flex", justifyContent: "center", alignItems: "center", zIndex: 1000 }}>
          <div className="glass-panel" style={{ width: "100%", maxWidth: "480px", padding: "2rem", border: "1px solid var(--accent-cyan)" }}>
            <h2 style={{ fontSize: "1.2rem", fontWeight: "800", color: "var(--accent-cyan)", marginBottom: "1.2rem" }}>
              DISPATCH RESPONSE ACTION
            </h2>

            <form onSubmit={handleTriggerSubmit} style={{ display: "grid", gap: "1.2rem" }}>
              <div>
                <label style={{ display: "block", fontSize: "0.8rem", color: "var(--text-muted)", marginBottom: "0.4rem" }}>
                  Target Endpoint Device
                </label>
                <select
                  value={selectedDevice}
                  onChange={(e) => setSelectedDevice(e.target.value)}
                  required
                  style={{
                    width: "100%",
                    background: "rgba(10, 13, 20, 0.9)",
                    color: "var(--text-main)",
                    border: "1px solid rgba(255,255,255,0.2)",
                    borderRadius: "6px",
                    padding: "0.6rem",
                    fontSize: "0.85rem"
                  }}
                >
                  <option value="">-- Select Target Device --</option>
                  {devicesList.map((d) => (
                    <option key={d.id} value={d.id}>
                      {d.hostname} ({d.ip_address || "No IP"}) - Status: {d.status}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label style={{ display: "block", fontSize: "0.8rem", color: "var(--text-muted)", marginBottom: "0.4rem" }}>
                  Action Type
                </label>
                <select
                  value={selectedAction}
                  onChange={(e) => setSelectedAction(e.target.value)}
                  style={{
                    width: "100%",
                    background: "rgba(10, 13, 20, 0.9)",
                    color: "var(--text-main)",
                    border: "1px solid rgba(255,255,255,0.2)",
                    borderRadius: "6px",
                    padding: "0.6rem",
                    fontSize: "0.85rem"
                  }}
                >
                  <option value="QUARANTINE">QUARANTINE (Vault File)</option>
                  <option value="DELETE">DELETE (Remove File)</option>
                  <option value="ISOLATE">ISOLATE (Endpoint Isolation)</option>
                  <option value="IGNORE">IGNORE (Dismiss Threat)</option>
                </select>
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.8rem", marginTop: "1rem" }}>
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  style={{ background: "transparent", border: "1px solid var(--text-muted)", color: "var(--text-muted)", padding: "0.5rem 1rem", borderRadius: "6px", cursor: "pointer" }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={triggering}
                  style={{ background: "var(--accent-cyan)", color: "#000", border: "none", padding: "0.5rem 1.2rem", borderRadius: "6px", fontWeight: "700", cursor: "pointer" }}
                >
                  {triggering ? "Dispatching..." : "Confirm Dispatch"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Forensic Audit Trail Modal */}
      {selectedAuditAction && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.8)", display: "flex", justifyContent: "center", alignItems: "center", zIndex: 1100 }}>
          <div className="glass-panel" style={{ width: "100%", maxWidth: "680px", maxHeight: "85vh", overflowY: "auto", padding: "2rem", border: "1px solid var(--accent-cyan)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
              <div>
                <h2 style={{ fontSize: "1.2rem", fontWeight: "800", color: "var(--accent-cyan)", margin: 0 }}>
                  FORENSIC AUDIT TRAIL
                </h2>
                <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginTop: "0.3rem" }}>
                  Action ID: {selectedAuditAction.id} | Target: {devicesMap[selectedAuditAction.device_id] || selectedAuditAction.device_id}
                </div>
              </div>
              <button
                onClick={() => setSelectedAuditAction(null)}
                style={{ background: "transparent", border: "none", color: "var(--text-muted)", fontSize: "1.2rem", cursor: "pointer" }}
              >
                ✕
              </button>
            </div>

            {loadingAudit ? (
              <div style={{ textAlign: "center", padding: "2rem", color: "var(--text-muted)" }}>
                Loading forensic timeline logs...
              </div>
            ) : auditLogs.length === 0 ? (
              <div style={{ textAlign: "center", padding: "2rem", color: "var(--text-muted)" }}>
                No audit log entries recorded for this action.
              </div>
            ) : (
              <div style={{ display: "grid", gap: "1rem", position: "relative", paddingLeft: "1rem", borderLeft: "2px solid rgba(0, 240, 255, 0.3)" }}>
                {auditLogs.map((log, index) => (
                  <div key={log.id || index} style={{ position: "relative", paddingLeft: "1.2rem" }}>
                    <div style={{ position: "absolute", left: "-1.7rem", top: "0.2rem", width: "10px", height: "10px", borderRadius: "50%", background: "var(--accent-cyan)" }} />
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", flexWrap: "wrap" }}>
                      <span style={{ fontWeight: "700", color: "var(--text-main)", fontSize: "0.9rem" }}>
                        {log.message}
                      </span>
                      <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </span>
                    </div>

                    <div style={{ display: "flex", gap: "0.8rem", fontSize: "0.75rem", marginTop: "0.3rem" }}>
                      <span style={{ color: "var(--accent-cyan)", fontWeight: "600" }}>Stage: {log.stage}</span>
                      <span style={{ color: "var(--text-muted)" }}>Actor: {log.actor}</span>
                    </div>

                    {log.details && (
                      <pre style={{ background: "rgba(10, 13, 20, 0.8)", padding: "0.6rem", borderRadius: "4px", fontSize: "0.7rem", fontFamily: "var(--font-mono)", color: "var(--text-muted)", marginTop: "0.5rem", overflowX: "auto" }}>
                        {JSON.stringify(log.details, null, 2)}
                      </pre>
                    )}
                  </div>
                ))}
              </div>
            )}

            <div style={{ textAlign: "right", marginTop: "2rem" }}>
              <button
                onClick={() => setSelectedAuditAction(null)}
                style={{ background: "var(--accent-cyan)", color: "#000", border: "none", padding: "0.5rem 1.2rem", borderRadius: "6px", fontWeight: "700", cursor: "pointer" }}
              >
                Close Audit Viewer
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
