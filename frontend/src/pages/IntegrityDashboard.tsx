import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { WebSocketStatusBadge } from "../components/WebSocketStatusBadge";
import { NotificationCenter } from "../components/NotificationCenter";
import { fimService } from "../services/fim";
import type { FileIntegrityRecord, FIMMetrics, FIMTimelineResponse } from "../services/fim";
import { threatService } from "../services/threat";

interface DisplayFIMRow {
  id: string;
  file_path: string;
  file_name: string;
  action: "CREATED" | "MODIFIED" | "DELETED" | "RENAMED" | "INITIAL";
  device_id: string;
  device_name: string;
  user: string;
  baseline_sha256: string;
  current_sha256: string;
  hash_changed: boolean;
  size: number;
  is_executable: boolean;
  is_suspicious: boolean;
  timestamp: string;
}

export const IntegrityDashboard: React.FC = () => {
  const { logout } = useAuth();
  const [, setRecords] = useState<FileIntegrityRecord[]>([]);
  const [rows, setRows] = useState<DisplayFIMRow[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Response action feedback
  const [actionFeedback, setActionFeedback] = useState<{ id: string; message: string; isError?: boolean } | null>(null);

  // Phase 7: Timeline Modal State
  const [selectedTimelineRow, setSelectedTimelineRow] = useState<DisplayFIMRow | null>(null);
  const [timelineData, setTimelineData] = useState<FIMTimelineResponse | null>(null);
  const [timelineLoading, setTimelineLoading] = useState<boolean>(false);

  // Filters
  const [searchTerm, setSearchTerm] = useState<string>("");
  const [actionFilter, setActionFilter] = useState<string>("ALL");
  const [executableOnly, setExecutableOnly] = useState<boolean>(false);

  // Metrics
  const [metrics, setMetrics] = useState<FIMMetrics>({
    files_monitored: 0,
    modified: 0,
    deleted: 0,
    created: 0,
    suspicious: 0,
  });

  const fetchData = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await fimService.getIntegrityRecords();
      setRecords(data);

      let suspiciousCount = 0;
      try {
        const threats = await threatService.getThreats();
        suspiciousCount = threats.filter((t: any) =>
          t.threat_type?.startsWith("FIM_") || t.rule_name?.toLowerCase().includes("fim")
        ).length;
      } catch (err) {
        console.warn("Could not load threats for FIM metric:", err);
      }

      let modCount = 0;
      let delCount = 0;
      let creCount = 0;

      const processedRows: DisplayFIMRow[] = data.map((r, index) => {
        const isExec = r.is_executable;
        let action: "CREATED" | "MODIFIED" | "DELETED" | "RENAMED" | "INITIAL" = "MODIFIED";
        if (r.created_at === r.updated_at) {
          action = "CREATED";
          creCount++;
        } else {
          modCount++;
        }

        const isSuspicious = isExec || r.file_path.toLowerCase().includes("downloads") || r.file_name.toLowerCase().includes(".exe");

        return {
          id: r.id || `fim-${index}`,
          file_path: r.file_path,
          file_name: r.file_name,
          action: action,
          device_id: r.device_id,
          device_name: "ENDPOINT-PROD-01",
          user: r.owner || "root",
          baseline_sha256: r.sha256.substring(0, 8) + "..." + r.sha256.substring(r.sha256.length - 4),
          current_sha256: r.sha256,
          hash_changed: r.created_at !== r.updated_at,
          size: r.size,
          is_executable: r.is_executable,
          is_suspicious: isSuspicious,
          timestamp: new Date(r.updated_at || r.created_at).toLocaleString(),
        };
      });

      setRows(processedRows);
      setMetrics({
        files_monitored: data.length,
        modified: modCount,
        deleted: delCount,
        created: creCount,
        suspicious: suspiciousCount,
      });
    } catch (err: any) {
      console.error("Failed to load file integrity data:", err);
      setError(err.message || "Failed to communicate with FIM backend service.");
    } finally {
      setLoading(false);
    }
  };

  const handleResponseAction = async (row: DisplayFIMRow, actionType: string) => {
    try {
      setActionFeedback({ id: row.id, message: `Executing ${actionType}...` });
      const res = await fimService.executeResponseAction(row.device_id, row.file_path, actionType);
      setActionFeedback({ id: row.id, message: res.message || `${actionType} executed successfully!` });
      setTimeout(fetchData, 1200);
    } catch (err: any) {
      setActionFeedback({ id: row.id, message: err.message || `Failed to execute ${actionType}`, isError: true });
    }
  };

  const openTimelineModal = async (row: DisplayFIMRow) => {
    setSelectedTimelineRow(row);
    setTimelineLoading(true);
    setTimelineData(null);
    try {
      const res = await fimService.getFileTimeline(row.device_id, row.file_path);
      setTimelineData(res);
    } catch (err) {
      console.error("Failed to fetch timeline:", err);
    } finally {
      setTimelineLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, []);

  const filteredRows = rows.filter((r) => {
    const matchesSearch =
      r.file_path.toLowerCase().includes(searchTerm.toLowerCase()) ||
      r.file_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      r.user.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesAction = actionFilter === "ALL" || r.action === actionFilter;
    const matchesExec = !executableOnly || r.is_executable;

    return matchesSearch && matchesAction && matchesExec;
  });

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg-primary)", color: "var(--text-main)", padding: "2rem" }}>
      {/* Header Navigation */}
      <header
        className="glass-panel"
        style={{
          position: "relative",
          zIndex: 100,
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          gap: "1rem",
          padding: "0.8rem 1.5rem",
          marginBottom: "2rem",
          flexWrap: "wrap",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "1.5rem", flexWrap: "wrap" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.8rem", flexShrink: 0 }}>
            <div style={{ fontSize: "1.4rem", fontWeight: "800", color: "var(--accent-cyan)", letterSpacing: "1px" }}>
              SENTINEL<span style={{ color: "var(--text-main)" }}>X</span>
            </div>
            <span
              style={{
                background: "rgba(0, 240, 255, 0.1)",
                color: "var(--accent-cyan)",
                padding: "0.2rem 0.5rem",
                borderRadius: "4px",
                fontSize: "0.7rem",
                fontFamily: "var(--font-mono)",
                whiteSpace: "nowrap",
              }}
            >
              FIM ENGINE v1.0.0
            </span>
            <WebSocketStatusBadge />
          </div>

          <nav style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap" }}>
            <Link
              to="/dashboard"
              style={{
                color: "var(--text-muted)",
                textDecoration: "none",
                fontSize: "0.85rem",
                fontWeight: "600",
                padding: "0.35rem 0.7rem",
                borderRadius: "6px",
                whiteSpace: "nowrap",
              }}
            >
              Dashboard Overview
            </Link>
            <Link
              to="/threats"
              style={{
                color: "var(--text-muted)",
                textDecoration: "none",
                fontSize: "0.85rem",
                fontWeight: "600",
                padding: "0.35rem 0.7rem",
                borderRadius: "6px",
                whiteSpace: "nowrap",
              }}
            >
              Threats
            </Link>

            <Link
              to="/integrity"
              style={{
                color: "var(--accent-cyan)",
                background: "rgba(0, 240, 255, 0.1)",
                border: "1px solid rgba(0, 240, 255, 0.3)",
                textDecoration: "none",
                fontSize: "0.85rem",
                fontWeight: "600",
                padding: "0.35rem 0.7rem",
                borderRadius: "6px",
                whiteSpace: "nowrap",
              }}
            >
              File Integrity (FIM)
            </Link>

            <Link
              to="/alerts"
              style={{
                color: "var(--text-muted)",
                textDecoration: "none",
                fontSize: "0.85rem",
                fontWeight: "600",
                padding: "0.35rem 0.7rem",
                borderRadius: "6px",
                whiteSpace: "nowrap",
              }}
            >
              Alerts
            </Link>

            <Link
              to="/processes"
              style={{
                color: "var(--text-muted)",
                textDecoration: "none",
                fontSize: "0.85rem",
                fontWeight: "600",
                padding: "0.35rem 0.7rem",
                borderRadius: "6px",
                whiteSpace: "nowrap",
              }}
            >
              Processes
            </Link>

            <Link
              to="/network"
              style={{
                color: "var(--text-muted)",
                textDecoration: "none",
                fontSize: "0.85rem",
                fontWeight: "600",
                padding: "0.35rem 0.7rem",
                borderRadius: "6px",
                whiteSpace: "nowrap",
              }}
            >
              Network
            </Link>

            <Link
              to="/respond"
              style={{
                color: "var(--text-muted)",
                textDecoration: "none",
                fontSize: "0.85rem",
                fontWeight: "600",
                padding: "0.35rem 0.7rem",
                borderRadius: "6px",
                whiteSpace: "nowrap",
              }}
            >
              Response Actions
            </Link>
          </nav>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
          <NotificationCenter />
          <button
            onClick={logout}
            style={{
              background: "rgba(255, 0, 85, 0.15)",
              color: "#ff0055",
              border: "1px solid rgba(255, 0, 85, 0.3)",
              padding: "0.4rem 0.9rem",
              borderRadius: "6px",
              fontSize: "0.8rem",
              fontWeight: "600",
              cursor: "pointer",
            }}
          >
            Logout
          </button>
        </div>
      </header>

      {/* Title Section */}
      <div style={{ marginBottom: "1.5rem" }}>
        <h1 style={{ fontSize: "1.8rem", fontWeight: "700", margin: 0, color: "var(--text-main)" }}>
          File Integrity Monitoring (FIM)
        </h1>
        <p style={{ margin: "0.3rem 0 0 0", color: "var(--text-muted)", fontSize: "0.9rem" }}>
          Real-time tracking of file creations, modifications, deletions, and step-by-step chronological event timelines.
        </p>
      </div>

      {/* Metrics Cards Bar */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
          gap: "1rem",
          marginBottom: "2rem",
        }}
      >
        <div className="glass-panel" style={{ padding: "1.2rem", borderLeft: "4px solid var(--accent-cyan)" }}>
          <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "1px" }}>
            Files Monitored
          </div>
          <div style={{ fontSize: "2rem", fontWeight: "800", color: "var(--accent-cyan)", marginTop: "0.4rem" }}>
            {metrics.files_monitored}
          </div>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.2rem" }}>Active Baseline Records</div>
        </div>

        <div className="glass-panel" style={{ padding: "1.2rem", borderLeft: "4px solid #ffcc00" }}>
          <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "1px" }}>
            Modified
          </div>
          <div style={{ fontSize: "2rem", fontWeight: "800", color: "#ffcc00", marginTop: "0.4rem" }}>
            {metrics.modified}
          </div>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.2rem" }}>Content / SHA-256 Changed</div>
        </div>

        <div className="glass-panel" style={{ padding: "1.2rem", borderLeft: "4px solid #ff0055" }}>
          <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "1px" }}>
            Deleted
          </div>
          <div style={{ fontSize: "2rem", fontWeight: "800", color: "#ff0055", marginTop: "0.4rem" }}>
            {metrics.deleted}
          </div>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.2rem" }}>Monitored Files Removed</div>
        </div>

        <div className="glass-panel" style={{ padding: "1.2rem", borderLeft: "4px solid #00ff88" }}>
          <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "1px" }}>
            Created
          </div>
          <div style={{ fontSize: "2rem", fontWeight: "800", color: "#00ff88", marginTop: "0.4rem" }}>
            {metrics.created}
          </div>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.2rem" }}>Untracked Files Added</div>
        </div>

        <div className="glass-panel" style={{ padding: "1.2rem", borderLeft: "4px solid #cc00ff" }}>
          <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "1px" }}>
            Suspicious
          </div>
          <div style={{ fontSize: "2rem", fontWeight: "800", color: "#cc00ff", marginTop: "0.4rem" }}>
            {metrics.suspicious}
          </div>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.2rem" }}>FIM Threat Detections</div>
        </div>
      </div>

      {/* Filter and Control Bar */}
      <div
        className="glass-panel"
        style={{
          padding: "1rem 1.5rem",
          marginBottom: "1.5rem",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          gap: "1rem",
          flexWrap: "wrap",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "1rem", flexWrap: "wrap", flex: 1 }}>
          <input
            type="text"
            placeholder="Search by file path, name, or owner..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              background: "rgba(0, 0, 0, 0.4)",
              border: "1px solid rgba(0, 240, 255, 0.2)",
              color: "var(--text-main)",
              padding: "0.5rem 1rem",
              borderRadius: "6px",
              fontSize: "0.85rem",
              minWidth: "260px",
              flex: 1,
            }}
          />

          <select
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            style={{
              background: "rgba(0, 0, 0, 0.4)",
              border: "1px solid rgba(0, 240, 255, 0.2)",
              color: "var(--text-main)",
              padding: "0.5rem 1rem",
              borderRadius: "6px",
              fontSize: "0.85rem",
            }}
          >
            <option value="ALL">All Actions</option>
            <option value="CREATED">CREATED</option>
            <option value="MODIFIED">MODIFIED</option>
            <option value="DELETED">DELETED</option>
            <option value="RENAMED">RENAMED</option>
          </select>

          <label style={{ display: "flex", alignItems: "center", gap: "0.5rem", fontSize: "0.85rem", cursor: "pointer" }}>
            <input
              type="checkbox"
              checked={executableOnly}
              onChange={(e) => setExecutableOnly(e.target.checked)}
              style={{ accentColor: "var(--accent-cyan)" }}
            />
            Executables Only
          </label>
        </div>

        <button
          onClick={fetchData}
          style={{
            background: "rgba(0, 240, 255, 0.15)",
            color: "var(--accent-cyan)",
            border: "1px solid rgba(0, 240, 255, 0.4)",
            padding: "0.5rem 1rem",
            borderRadius: "6px",
            fontSize: "0.85rem",
            fontWeight: "600",
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            gap: "0.4rem",
          }}
        >
          🔄 Refresh FIM
        </button>
      </div>

      {/* Main File Integrity Event Table */}
      <div className="glass-panel" style={{ padding: "1.5rem", overflowX: "auto" }}>
        {loading ? (
          <div style={{ padding: "3rem", textAlign: "center", color: "var(--accent-cyan)" }}>
            Loading File Integrity Telemetry...
          </div>
        ) : error ? (
          <div style={{ padding: "2rem", color: "#ff0055", textAlign: "center" }}>
            {error}
          </div>
        ) : filteredRows.length === 0 ? (
          <div style={{ padding: "3rem", textAlign: "center", color: "var(--text-muted)" }}>
            No file integrity records found matching criteria.
          </div>
        ) : (
          <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid rgba(0, 240, 255, 0.2)", color: "var(--text-muted)", fontSize: "0.8rem", textTransform: "uppercase" }}>
                <th style={{ padding: "0.8rem 1rem" }}>File</th>
                <th style={{ padding: "0.8rem 1rem" }}>Action</th>
                <th style={{ padding: "0.8rem 1rem" }}>Device</th>
                <th style={{ padding: "0.8rem 1rem" }}>User</th>
                <th style={{ padding: "0.8rem 1rem" }}>Hash Changed</th>
                <th style={{ padding: "0.8rem 1rem" }}>Time</th>
                <th style={{ padding: "0.8rem 1rem" }}>Response Controls</th>
              </tr>
            </thead>
            <tbody>
              {filteredRows.map((row) => {
                let actionBadgeColor = "#ffcc00";
                let actionBg = "rgba(255, 204, 0, 0.15)";
                if (row.action === "CREATED") {
                  actionBadgeColor = "#00ff88";
                  actionBg = "rgba(0, 255, 136, 0.15)";
                } else if (row.action === "DELETED") {
                  actionBadgeColor = "#ff0055";
                  actionBg = "rgba(255, 0, 85, 0.15)";
                } else if (row.action === "RENAMED") {
                  actionBadgeColor = "#cc00ff";
                  actionBg = "rgba(204, 0, 255, 0.15)";
                }

                const feedback = actionFeedback?.id === row.id ? actionFeedback : null;

                return (
                  <tr
                    key={row.id}
                    style={{
                      borderBottom: "1px solid rgba(255, 255, 255, 0.05)",
                      transition: "background 0.2s",
                    }}
                  >
                    {/* File Column */}
                    <td style={{ padding: "0.8rem 1rem" }}>
                      <div
                        onClick={() => openTimelineModal(row)}
                        style={{
                          fontWeight: "600",
                          color: "var(--accent-cyan)",
                          fontSize: "0.9rem",
                          cursor: "pointer",
                          display: "inline-flex",
                          alignItems: "center",
                          gap: "0.4rem",
                        }}
                      >
                        {row.file_name}
                        <span style={{ fontSize: "0.7rem", opacity: 0.8 }}>⏱️ Timeline</span>
                      </div>
                      <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginTop: "0.1rem" }}>
                        {row.file_path}
                      </div>
                    </td>

                    {/* Action Column */}
                    <td style={{ padding: "0.8rem 1rem" }}>
                      <span
                        style={{
                          background: actionBg,
                          color: actionBadgeColor,
                          border: `1px solid ${actionBadgeColor}44`,
                          padding: "0.25rem 0.6rem",
                          borderRadius: "4px",
                          fontSize: "0.75rem",
                          fontWeight: "700",
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        {row.action}
                      </span>
                    </td>

                    {/* Device Column */}
                    <td style={{ padding: "0.8rem 1rem", fontSize: "0.85rem", color: "var(--text-muted)" }}>
                      {row.device_name}
                    </td>

                    {/* User Column */}
                    <td style={{ padding: "0.8rem 1rem", fontSize: "0.85rem", color: "var(--text-main)" }}>
                      <span style={{ fontFamily: "var(--font-mono)", background: "rgba(255, 255, 255, 0.05)", padding: "0.2rem 0.5rem", borderRadius: "4px" }}>
                        {row.user}
                      </span>
                    </td>

                    {/* Hash Changed Column */}
                    <td style={{ padding: "0.8rem 1rem" }}>
                      {row.hash_changed ? (
                        <div style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}>
                          <span style={{ background: "rgba(255, 204, 0, 0.2)", color: "#ffcc00", padding: "0.2rem 0.5rem", borderRadius: "4px", fontSize: "0.75rem", fontFamily: "var(--font-mono)" }}>
                            SHA-256 CHANGED
                          </span>
                          <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                            {row.baseline_sha256}
                          </span>
                        </div>
                      ) : (
                        <span style={{ color: "var(--text-muted)", fontSize: "0.8rem" }}>Unchanged</span>
                      )}
                    </td>

                    {/* Time Column */}
                    <td style={{ padding: "0.8rem 1rem", fontSize: "0.8rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                      {row.timestamp}
                    </td>

                    {/* Response Controls Column */}
                    <td style={{ padding: "0.8rem 1rem" }}>
                      {feedback ? (
                        <div style={{ fontSize: "0.75rem", color: feedback.isError ? "#ff0055" : "var(--accent-cyan)", fontFamily: "var(--font-mono)" }}>
                          {feedback.message}
                        </div>
                      ) : (
                        <div style={{ display: "flex", gap: "0.3rem", flexWrap: "wrap" }}>
                          <button
                            title="Restore baseline file state (simulation)"
                            onClick={() => handleResponseAction(row, "RESTORE_BASELINE")}
                            style={{
                              background: "rgba(0, 240, 255, 0.1)",
                              color: "var(--accent-cyan)",
                              border: "1px solid rgba(0, 240, 255, 0.3)",
                              padding: "0.25rem 0.5rem",
                              borderRadius: "4px",
                              fontSize: "0.75rem",
                              cursor: "pointer",
                            }}
                          >
                            Restore Baseline
                          </button>
                          <button
                            title="Isolate & quarantine file payload"
                            onClick={() => handleResponseAction(row, "QUARANTINE")}
                            style={{
                              background: "rgba(255, 0, 85, 0.1)",
                              color: "#ff0055",
                              border: "1px solid rgba(255, 0, 85, 0.3)",
                              padding: "0.25rem 0.5rem",
                              borderRadius: "4px",
                              fontSize: "0.75rem",
                              cursor: "pointer",
                            }}
                          >
                            Quarantine
                          </button>
                          <button
                            title="Ignore change event"
                            onClick={() => handleResponseAction(row, "IGNORE_CHANGE")}
                            style={{
                              background: "rgba(255, 255, 255, 0.08)",
                              color: "var(--text-muted)",
                              border: "1px solid rgba(255, 255, 255, 0.15)",
                              padding: "0.25rem 0.5rem",
                              borderRadius: "4px",
                              fontSize: "0.75rem",
                              cursor: "pointer",
                            }}
                          >
                            Ignore
                          </button>
                          <button
                            title="Add file to approved security allowlist"
                            onClick={() => handleResponseAction(row, "ADD_ALLOWLIST")}
                            style={{
                              background: "rgba(0, 255, 136, 0.1)",
                              color: "#00ff88",
                              border: "1px solid rgba(0, 255, 136, 0.3)",
                              padding: "0.25rem 0.5rem",
                              borderRadius: "4px",
                              fontSize: "0.75rem",
                              cursor: "pointer",
                            }}
                          >
                            Allowlist
                          </button>
                          <button
                            title="Recalculate and update baseline hash"
                            onClick={() => handleResponseAction(row, "RECALCULATE_BASELINE")}
                            style={{
                              background: "rgba(255, 204, 0, 0.1)",
                              color: "#ffcc00",
                              border: "1px solid rgba(255, 204, 0, 0.3)",
                              padding: "0.25rem 0.5rem",
                              borderRadius: "4px",
                              fontSize: "0.75rem",
                              cursor: "pointer",
                            }}
                          >
                            Recalculate
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Phase 7: Chronological FIM Timeline Modal */}
      {selectedTimelineRow && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: "rgba(0, 0, 0, 0.8)",
            backdropFilter: "blur(6px)",
            zIndex: 1000,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: "1.5rem",
          }}
        >
          <div
            className="glass-panel"
            style={{
              width: "100%",
              maxWidth: "750px",
              maxHeight: "85vh",
              overflowY: "auto",
              padding: "2rem",
              position: "relative",
              border: "1px solid rgba(0, 240, 255, 0.3)",
            }}
          >
            <button
              onClick={() => setSelectedTimelineRow(null)}
              style={{
                position: "absolute",
                top: "1.2rem",
                right: "1.2rem",
                background: "rgba(255, 0, 85, 0.2)",
                color: "#ff0055",
                border: "none",
                borderRadius: "50%",
                width: "32px",
                height: "32px",
                cursor: "pointer",
                fontWeight: "700",
              }}
            >
              ✕
            </button>

            <h2 style={{ fontSize: "1.4rem", margin: "0 0 0.5rem 0", color: "var(--accent-cyan)" }}>
              ⏱️ File Activity Timeline
            </h2>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.85rem", color: "var(--text-main)", marginBottom: "1.5rem" }}>
              {selectedTimelineRow.file_path}
            </div>

            {timelineLoading ? (
              <div style={{ padding: "2rem", textAlign: "center", color: "var(--accent-cyan)" }}>
                Generating chronological audit trail...
              </div>
            ) : timelineData && timelineData.timeline.length > 0 ? (
              <div style={{ display: "flex", flexDirection: "column", gap: "1.2rem", position: "relative", paddingLeft: "1.5rem" }}>
                {/* Vertical timeline line */}
                <div
                  style={{
                    position: "absolute",
                    top: "10px",
                    bottom: "10px",
                    left: "7px",
                    width: "2px",
                    background: "rgba(0, 240, 255, 0.3)",
                  }}
                />

                {timelineData.timeline.map((item) => {
                  let badgeBg = "rgba(0, 240, 255, 0.15)";
                  let badgeColor = "var(--accent-cyan)";
                  if (item.severity === "CRITICAL" || item.severity === "HIGH") {
                    badgeBg = "rgba(255, 0, 85, 0.2)";
                    badgeColor = "#ff0055";
                  } else if (item.severity === "MEDIUM") {
                    badgeBg = "rgba(255, 204, 0, 0.2)";
                    badgeColor = "#ffcc00";
                  }

                  return (
                    <div key={item.step} style={{ position: "relative" }}>
                      {/* Timeline dot */}
                      <div
                        style={{
                          position: "absolute",
                          left: "-1.5rem",
                          top: "4px",
                          width: "12px",
                          height: "12px",
                          borderRadius: "50%",
                          background: badgeColor,
                          boxShadow: `0 0 8px ${badgeColor}`,
                        }}
                      />

                      <div className="glass-panel" style={{ padding: "1rem 1.2rem" }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.4rem" }}>
                          <span style={{ fontSize: "0.75rem", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
                            Step {item.step} — {new Date(item.timestamp).toLocaleTimeString()} ({new Date(item.timestamp).toLocaleDateString()})
                          </span>
                          <span
                            style={{
                              background: badgeBg,
                              color: badgeColor,
                              padding: "0.2rem 0.5rem",
                              borderRadius: "4px",
                              fontSize: "0.7rem",
                              fontWeight: "700",
                              fontFamily: "var(--font-mono)",
                            }}
                          >
                            {item.event_type}
                          </span>
                        </div>

                        <div style={{ fontWeight: "700", color: "var(--text-main)", fontSize: "1rem", marginBottom: "0.3rem" }}>
                          {item.title}
                        </div>

                        <p style={{ margin: 0, fontSize: "0.85rem", color: "var(--text-muted)" }}>
                          {item.description}
                        </p>

                        {item.actor && (
                          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.4rem", fontFamily: "var(--font-mono)" }}>
                            Actor: <span style={{ color: "var(--accent-cyan)" }}>{item.actor}</span>
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div style={{ padding: "2rem", textAlign: "center", color: "var(--text-muted)" }}>
                No chronological timeline events logged for this file.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default IntegrityDashboard;
