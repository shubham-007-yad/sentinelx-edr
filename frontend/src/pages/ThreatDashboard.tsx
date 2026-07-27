import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import {
  getThreats,
  getThreatSummary,
  updateThreatStatus,
} from "../services/threat";
import type { ThreatRecord, ThreatStats, ThreatStatus, ThreatSeverity } from "../types/threat";

export const ThreatDashboard: React.FC = () => {
  const { user, logout } = useAuth();

  const [threats, setThreats] = useState<ThreatRecord[]>([]);
  const [stats, setStats] = useState<ThreatStats | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters & Pagination
  const [selectedSeverity, setSelectedSeverity] = useState<string>("");
  const [selectedStatus, setSelectedStatus] = useState<string>("");
  const [selectedType, setSelectedType] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [skip, setSkip] = useState<number>(0);
  const limit = 20;

  // Selected Threat for Forensic Detail Modal
  const [selectedThreat, setSelectedThreat] = useState<ThreatRecord | null>(null);
  const [newStatus, setNewStatus] = useState<ThreatStatus>("OPEN");
  const [remediationNote, setRemediationNote] = useState<string>("");
  const [isUpdating, setIsUpdating] = useState<boolean>(false);

  const fetchThreatData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [threatsData, statsData] = await Promise.all([
        getThreats(
          skip,
          limit,
          selectedSeverity || undefined,
          selectedType || undefined,
          selectedStatus || undefined,
          undefined,
          undefined,
          searchQuery || undefined
        ),
        getThreatSummary(),
      ]);
      setThreats(threatsData);
      setStats(statsData);
    } catch (err: any) {
      console.error("Failed to load threat detection data:", err);
      setError(err.response?.data?.detail || "Failed to load threat detection findings.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchThreatData();
  }, [skip, selectedSeverity, selectedStatus, selectedType]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setSkip(0);
    fetchThreatData();
  };

  const handleOpenModal = (threat: ThreatRecord) => {
    setSelectedThreat(threat);
    setNewStatus(threat.status);
    setRemediationNote(threat.remediation || "");
  };

  const handleUpdateStatus = async () => {
    if (!selectedThreat) return;
    setIsUpdating(true);
    try {
      const updated = await updateThreatStatus(selectedThreat.id, newStatus, remediationNote);
      setSelectedThreat(updated);
      await fetchThreatData();
    } catch (err: any) {
      alert("Failed to update threat status: " + (err.response?.data?.detail || err.message));
    } finally {
      setIsUpdating(false);
    }
  };

  const getSeverityBadgeClass = (severity: ThreatSeverity | string) => {
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

  const getStatusBadgeStyle = (status: ThreatStatus | string) => {
    switch (status.toUpperCase()) {
      case "OPEN":
        return { background: "rgba(255, 0, 85, 0.15)", color: "#ff0055", border: "1px solid #ff0055" };
      case "QUARANTINED":
        return { background: "rgba(255, 170, 0, 0.15)", color: "#ffaa00", border: "1px solid #ffaa00" };
      case "RESOLVED":
        return { background: "rgba(0, 255, 157, 0.15)", color: "#00ff9d", border: "1px solid #00ff9d" };
      case "FALSE_POSITIVE":
        return { background: "rgba(0, 240, 255, 0.15)", color: "#00f0ff", border: "1px solid #00f0ff" };
      default:
        return { background: "rgba(255, 255, 255, 0.1)", color: "#aaa", border: "1px solid #666" };
    }
  };

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg-primary)", color: "var(--text-main)", padding: "2rem" }}>
      {/* Navigation Header */}
      <header className="glass-panel" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "1rem 2rem", marginBottom: "2rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "2rem" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
            <div style={{ fontSize: "1.5rem", fontWeight: "800", color: "var(--accent-cyan)", letterSpacing: "1px" }}>
              SENTINEL<span style={{ color: "var(--text-main)" }}>X</span>
            </div>
            <span style={{ background: "rgba(255, 0, 85, 0.15)", color: "#ff0055", border: "1px solid #ff0055", padding: "0.2rem 0.6rem", borderRadius: "4px", fontSize: "0.75rem", fontFamily: "var(--font-mono)", fontWeight: "700" }}>
              🛡️ THREAT ENGINE
            </span>
          </div>

          <nav style={{ display: "flex", gap: "1rem" }}>
            <Link
              to="/dashboard"
              style={{
                color: "var(--text-muted)",
                textDecoration: "none",
                fontSize: "0.9rem",
                fontWeight: "600",
                padding: "0.4rem 0.8rem",
                borderRadius: "6px",
                transition: "all 0.2s"
              }}
            >
              Dashboard Overview
            </Link>
            <Link
              to="/threats"
              style={{
                color: "#ff0055",
                background: "rgba(255, 0, 85, 0.1)",
                border: "1px solid rgba(255, 0, 85, 0.4)",
                textDecoration: "none",
                fontSize: "0.9rem",
                fontWeight: "600",
                padding: "0.4rem 0.8rem",
                borderRadius: "6px"
              }}
            >
              Threat Dashboard
            </Link>
            <Link
              to="/usb-activity"
              style={{
                color: "var(--text-muted)",
                textDecoration: "none",
                fontSize: "0.9rem",
                fontWeight: "600",
                padding: "0.4rem 0.8rem",
                borderRadius: "6px",
                transition: "all 0.2s"
              }}
            >
              USB Activity
            </Link>
            <Link
              to="/usb-scans"
              style={{
                color: "var(--text-muted)",
                textDecoration: "none",
                fontSize: "0.9rem",
                fontWeight: "600",
                padding: "0.4rem 0.8rem",
                borderRadius: "6px",
                transition: "all 0.2s"
              }}
            >
              USB Scan Results
            </Link>
            {user?.role === "ADMIN" && (
              <Link
                to="/users"
                style={{
                  color: "#ffaa00",
                  textDecoration: "none",
                  fontSize: "0.9rem",
                  fontWeight: "600",
                  padding: "0.4rem 0.8rem",
                  borderRadius: "6px",
                  border: "1px solid rgba(255, 170, 0, 0.4)",
                  background: "rgba(255, 170, 0, 0.1)",
                  transition: "all 0.2s"
                }}
              >
                User Management
              </Link>
            )}
          </nav>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "1.5rem" }}>
          <div style={{ textAlign: "right" }}>
            <div style={{ fontWeight: "600", fontSize: "0.95rem" }}>{user?.username}</div>
            <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>{user?.email}</div>
          </div>
          <span className={`badge badge-${user?.role?.toLowerCase()}`}>{user?.role}</span>
          <button
            onClick={logout}
            style={{
              background: "rgba(255, 0, 85, 0.15)",
              border: "1px solid var(--accent-danger)",
              color: "var(--accent-danger)",
              padding: "0.5rem 1rem",
              borderRadius: "6px",
              cursor: "pointer",
              fontWeight: "600",
              fontSize: "0.8rem"
            }}
          >
            Logout
          </button>
        </div>
      </header>

      {/* Main Content Area */}
      <main style={{ maxWidth: "1400px", margin: "0 auto", display: "flex", flexDirection: "column", gap: "2rem" }}>
        
        {/* Metric Overview Cards */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "1.5rem" }}>
          <div className="glass-panel" style={{ padding: "1.25rem", borderLeft: "4px solid #ff0055" }}>
            <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase" }}>Total Threat Findings</div>
            <div style={{ fontSize: "1.8rem", fontWeight: "800", color: "#ff0055", marginTop: "0.4rem" }}>
              {stats ? stats.total_threats : "-"}
            </div>
          </div>

          <div className="glass-panel" style={{ padding: "1.25rem", borderLeft: "4px solid #ff0055" }}>
            <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase" }}>Critical Severity</div>
            <div style={{ fontSize: "1.8rem", fontWeight: "800", color: "#ff0055", marginTop: "0.4rem" }}>
              {stats ? stats.severity_breakdown.CRITICAL : "-"}
            </div>
          </div>

          <div className="glass-panel" style={{ padding: "1.25rem", borderLeft: "4px solid #ffaa00" }}>
            <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase" }}>High Severity</div>
            <div style={{ fontSize: "1.8rem", fontWeight: "800", color: "#ffaa00", marginTop: "0.4rem" }}>
              {stats ? stats.severity_breakdown.HIGH : "-"}
            </div>
          </div>

          <div className="glass-panel" style={{ padding: "1.25rem", borderLeft: "4px solid #00f0ff" }}>
            <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase" }}>Open Actionable</div>
            <div style={{ fontSize: "1.8rem", fontWeight: "800", color: "#00f0ff", marginTop: "0.4rem" }}>
              {stats ? stats.open_threats : "-"}
            </div>
          </div>

          <div className="glass-panel" style={{ padding: "1.25rem", borderLeft: "4px solid #00ff9d" }}>
            <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase" }}>Quarantined / Resolved</div>
            <div style={{ fontSize: "1.8rem", fontWeight: "800", color: "#00ff9d", marginTop: "0.4rem" }}>
              {stats ? stats.quarantined + stats.resolved_threats : "-"}
            </div>
          </div>
        </div>

        {/* Filter Control Bar */}
        <div className="glass-panel" style={{ padding: "1.25rem", display: "flex", flexWrap: "wrap", gap: "1rem", alignItems: "center", justifyContent: "space-between" }}>
          <form onSubmit={handleSearchSubmit} style={{ display: "flex", gap: "0.8rem", flex: 1, minWidth: "300px" }}>
            <input
              type="text"
              placeholder="Search by file name, threat name, or SHA-256..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                flex: 1,
                background: "rgba(10, 13, 20, 0.8)",
                border: "1px solid rgba(255,255,255,0.1)",
                color: "#fff",
                padding: "0.5rem 1rem",
                borderRadius: "6px",
                fontSize: "0.85rem",
                fontFamily: "var(--font-mono)"
              }}
            />
            <button
              type="submit"
              style={{
                background: "rgba(0, 240, 255, 0.15)",
                border: "1px solid var(--accent-cyan)",
                color: "var(--accent-cyan)",
                padding: "0.5rem 1rem",
                borderRadius: "6px",
                cursor: "pointer",
                fontWeight: "600",
                fontSize: "0.85rem"
              }}
            >
              Search
            </button>
          </form>

          <div style={{ display: "flex", gap: "0.8rem", alignItems: "center", flexWrap: "wrap" }}>
            {/* Severity Filter */}
            <select
              value={selectedSeverity}
              onChange={(e) => { setSelectedSeverity(e.target.value); setSkip(0); }}
              style={{
                background: "rgba(10, 13, 20, 0.8)",
                border: "1px solid rgba(255,255,255,0.1)",
                color: "#fff",
                padding: "0.5rem 0.8rem",
                borderRadius: "6px",
                fontSize: "0.85rem"
              }}
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>

            {/* Status Filter */}
            <select
              value={selectedStatus}
              onChange={(e) => { setSelectedStatus(e.target.value); setSkip(0); }}
              style={{
                background: "rgba(10, 13, 20, 0.8)",
                border: "1px solid rgba(255,255,255,0.1)",
                color: "#fff",
                padding: "0.5rem 0.8rem",
                borderRadius: "6px",
                fontSize: "0.85rem"
              }}
            >
              <option value="">All Statuses</option>
              <option value="OPEN">OPEN</option>
              <option value="QUARANTINED">QUARANTINED</option>
              <option value="RESOLVED">RESOLVED</option>
              <option value="FALSE_POSITIVE">FALSE POSITIVE</option>
            </select>

            {/* Threat Type Filter */}
            <select
              value={selectedType}
              onChange={(e) => { setSelectedType(e.target.value); setSkip(0); }}
              style={{
                background: "rgba(10, 13, 20, 0.8)",
                border: "1px solid rgba(255,255,255,0.1)",
                color: "#fff",
                padding: "0.5rem 0.8rem",
                borderRadius: "6px",
                fontSize: "0.85rem"
              }}
            >
              <option value="">All Threat Types</option>
              <option value="KNOWN_MALWARE">KNOWN MALWARE</option>
              <option value="DOUBLE_EXTENSION">DOUBLE EXTENSION</option>
              <option value="HIDDEN_EXECUTABLE">HIDDEN EXECUTABLE</option>
              <option value="AUTORUN_SCRIPT">AUTORUN SCRIPT</option>
              <option value="SUSPICIOUS_EXTENSION">SUSPICIOUS EXTENSION</option>
              <option value="ANOMALOUS_FILE">ANOMALOUS FILE</option>
            </select>

            <button
              onClick={() => {
                setSelectedSeverity("");
                setSelectedStatus("");
                setSelectedType("");
                setSearchQuery("");
                setSkip(0);
                fetchThreatData();
              }}
              style={{
                background: "rgba(255, 255, 255, 0.05)",
                border: "1px solid rgba(255, 255, 255, 0.1)",
                color: "var(--text-muted)",
                padding: "0.5rem 0.8rem",
                borderRadius: "6px",
                cursor: "pointer",
                fontSize: "0.85rem"
              }}
            >
              Reset
            </button>
          </div>
        </div>

        {/* Forensic Threat Records Table */}
        <div className="glass-panel" style={{ padding: "1.5rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
            <h3 style={{ fontSize: "1.1rem", fontWeight: "700", color: "#ff0055", display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <span>🛡️</span> DETECTED THREAT RECORDS FORENSIC TABLE
            </h3>
            <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
              Showing {threats.length} threats
            </span>
          </div>

          {error && (
            <div style={{ background: "rgba(255, 0, 85, 0.1)", border: "1px solid var(--accent-danger)", color: "var(--accent-danger)", padding: "1rem", borderRadius: "6px", marginBottom: "1rem" }}>
              {error}
            </div>
          )}

          {isLoading ? (
            <div style={{ textAlign: "center", padding: "3rem", color: "var(--accent-cyan)" }}>
              Analyzing threat engine records...
            </div>
          ) : threats.length === 0 ? (
            <div style={{ textAlign: "center", padding: "3rem", color: "var(--text-muted)" }}>
              No security threats found matching the selected filters.
            </div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left", fontSize: "0.85rem" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.1)", color: "var(--text-muted)" }}>
                    <th style={{ padding: "0.8rem" }}>STATUS</th>
                    <th style={{ padding: "0.8rem" }}>SEVERITY</th>
                    <th style={{ padding: "0.8rem" }}>THREAT NAME</th>
                    <th style={{ padding: "0.8rem" }}>TYPE</th>
                    <th style={{ padding: "0.8rem" }}>FILE NAME / PATH</th>
                    <th style={{ padding: "0.8rem" }}>SHA-256 FINGERPRINT</th>
                    <th style={{ padding: "0.8rem" }}>DETECTED AT</th>
                    <th style={{ padding: "0.8rem", textAlign: "center" }}>ACTION</th>
                  </tr>
                </thead>
                <tbody>
                  {threats.map((threat) => (
                    <tr key={threat.id} style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                      <td style={{ padding: "0.8rem" }}>
                        <span style={{ padding: "0.2rem 0.5rem", borderRadius: "4px", fontSize: "0.75rem", fontFamily: "var(--font-mono)", fontWeight: "600", ...getStatusBadgeStyle(threat.status) }}>
                          {threat.status}
                        </span>
                      </td>
                      <td style={{ padding: "0.8rem" }}>
                        <span className={`badge ${getSeverityBadgeClass(threat.severity)}`}>
                          {threat.severity}
                        </span>
                      </td>
                      <td style={{ padding: "0.8rem", fontWeight: "600", color: "#fff" }}>
                        {threat.threat_name}
                      </td>
                      <td style={{ padding: "0.8rem" }}>
                        <span style={{ background: "rgba(255,255,255,0.08)", padding: "0.2rem 0.5rem", borderRadius: "4px", fontSize: "0.75rem", fontFamily: "var(--font-mono)" }}>
                          {threat.threat_type}
                        </span>
                      </td>
                      <td style={{ padding: "0.8rem" }}>
                        <div style={{ fontWeight: "600", color: "var(--accent-cyan)" }}>{threat.file_name}</div>
                        <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>{threat.full_path}</div>
                      </td>
                      <td style={{ padding: "0.8rem", fontFamily: "var(--font-mono)", fontSize: "0.75rem", color: "var(--text-muted)" }}>
                        {threat.sha256.substring(0, 16)}...
                      </td>
                      <td style={{ padding: "0.8rem", fontSize: "0.75rem", color: "var(--text-muted)" }}>
                        {new Date(threat.detected_at).toLocaleString()}
                      </td>
                      <td style={{ padding: "0.8rem", textAlign: "center" }}>
                        <button
                          onClick={() => handleOpenModal(threat)}
                          style={{
                            background: "rgba(0, 240, 255, 0.15)",
                            border: "1px solid var(--accent-cyan)",
                            color: "var(--accent-cyan)",
                            padding: "0.3rem 0.6rem",
                            borderRadius: "4px",
                            fontSize: "0.75rem",
                            cursor: "pointer",
                            fontWeight: "600"
                          }}
                        >
                          Inspect & Remediate
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Pagination Controls */}
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "1.5rem" }}>
            <button
              disabled={skip === 0}
              onClick={() => setSkip((prev) => Math.max(0, prev - limit))}
              style={{
                background: "rgba(255,255,255,0.05)",
                border: "1px solid rgba(255,255,255,0.1)",
                color: skip === 0 ? "#555" : "#fff",
                padding: "0.4rem 1rem",
                borderRadius: "6px",
                cursor: skip === 0 ? "not-allowed" : "pointer"
              }}
            >
              Previous Page
            </button>
            <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
              Page {Math.floor(skip / limit) + 1}
            </span>
            <button
              disabled={threats.length < limit}
              onClick={() => setSkip((prev) => prev + limit)}
              style={{
                background: "rgba(255,255,255,0.05)",
                border: "1px solid rgba(255,255,255,0.1)",
                color: threats.length < limit ? "#555" : "#fff",
                padding: "0.4rem 1rem",
                borderRadius: "6px",
                cursor: threats.length < limit ? "not-allowed" : "pointer"
              }}
            >
              Next Page
            </button>
          </div>
        </div>
      </main>

      {/* Threat Forensic & Remediation Detail Modal */}
      {selectedThreat && (
        <div style={{
          position: "fixed",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: "rgba(0, 0, 0, 0.8)",
          backdropFilter: "blur(6px)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          zIndex: 1000,
          padding: "1rem"
        }}>
          <div className="glass-panel" style={{ maxWidth: "700px", width: "100%", padding: "2rem", border: "1px solid var(--accent-cyan)", maxHeight: "90vh", overflowY: "auto" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
              <h3 style={{ fontSize: "1.2rem", fontWeight: "700", color: "#ff0055", display: "flex", alignItems: "center", gap: "0.5rem" }}>
                <span>🛡️</span> FORENSIC THREAT INSPECTOR
              </h3>
              <button
                onClick={() => setSelectedThreat(null)}
                style={{ background: "none", border: "none", color: "#fff", fontSize: "1.2rem", cursor: "pointer" }}
              >
                ✕
              </button>
            </div>

            <div style={{ display: "grid", gap: "1rem", fontSize: "0.85rem" }}>
              <div style={{ background: "rgba(10, 13, 20, 0.8)", padding: "1rem", borderRadius: "6px" }}>
                <div style={{ color: "var(--text-muted)", fontSize: "0.75rem", textTransform: "uppercase" }}>Threat Name & Classification</div>
                <div style={{ fontSize: "1.1rem", fontWeight: "700", color: "#fff", marginTop: "0.2rem" }}>{selectedThreat.threat_name}</div>
                <div style={{ display: "flex", gap: "0.5rem", marginTop: "0.5rem" }}>
                  <span className={`badge ${getSeverityBadgeClass(selectedThreat.severity)}`}>{selectedThreat.severity}</span>
                  <span style={{ background: "rgba(255,255,255,0.08)", padding: "0.2rem 0.5rem", borderRadius: "4px", fontFamily: "var(--font-mono)" }}>
                    {selectedThreat.threat_type}
                  </span>
                </div>
              </div>

              <div style={{ background: "rgba(10, 13, 20, 0.8)", padding: "1rem", borderRadius: "6px" }}>
                <div style={{ color: "var(--text-muted)", fontSize: "0.75rem", textTransform: "uppercase" }}>File Forensic Target</div>
                <div style={{ fontWeight: "600", color: "var(--accent-cyan)", marginTop: "0.2rem" }}>{selectedThreat.file_name}</div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.8rem", color: "var(--text-muted)", wordBreak: "break-all", marginTop: "0.2rem" }}>
                  {selectedThreat.full_path}
                </div>
              </div>

              <div style={{ background: "rgba(10, 13, 20, 0.8)", padding: "1rem", borderRadius: "6px" }}>
                <div style={{ color: "var(--text-muted)", fontSize: "0.75rem", textTransform: "uppercase" }}>Cryptographic SHA-256 Fingerprint</div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.8rem", color: "var(--accent-cyan)", wordBreak: "break-all", marginTop: "0.2rem" }}>
                  {selectedThreat.sha256}
                </div>
              </div>

              <div style={{ background: "rgba(10, 13, 20, 0.8)", padding: "1rem", borderRadius: "6px" }}>
                <div style={{ color: "var(--text-muted)", fontSize: "0.75rem", textTransform: "uppercase" }}>Detection Analysis & Description</div>
                <div style={{ marginTop: "0.4rem", lineHeight: "1.5", color: "#ddd" }}>{selectedThreat.description}</div>
              </div>

              <div style={{ background: "rgba(10, 13, 20, 0.8)", padding: "1rem", borderRadius: "6px" }}>
                <div style={{ color: "var(--text-muted)", fontSize: "0.75rem", textTransform: "uppercase" }}>Recommended Remediation Action</div>
                <div style={{ marginTop: "0.4rem", color: "#00ff9d", fontWeight: "600" }}>
                  {selectedThreat.remediation || "Isolate endpoint and inspect payload."}
                </div>
              </div>

              {/* Status Update Form */}
              <div style={{ background: "rgba(255, 0, 85, 0.08)", border: "1px solid rgba(255, 0, 85, 0.3)", padding: "1rem", borderRadius: "6px" }}>
                <div style={{ fontWeight: "700", color: "#ff0055", marginBottom: "0.8rem" }}>Update Threat Incident Status</div>
                
                <div style={{ display: "flex", gap: "1rem", marginBottom: "1rem" }}>
                  <label style={{ display: "flex", flexDirection: "column", gap: "0.4rem", flex: 1 }}>
                    <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Incident Status</span>
                    <select
                      value={newStatus}
                      onChange={(e) => setNewStatus(e.target.value as ThreatStatus)}
                      style={{
                        background: "rgba(10, 13, 20, 0.9)",
                        border: "1px solid rgba(255,255,255,0.2)",
                        color: "#fff",
                        padding: "0.5rem",
                        borderRadius: "4px"
                      }}
                    >
                      <option value="OPEN">OPEN</option>
                      <option value="QUARANTINED">QUARANTINED</option>
                      <option value="RESOLVED">RESOLVED</option>
                      <option value="FALSE_POSITIVE">FALSE POSITIVE</option>
                    </select>
                  </label>
                </div>

                <label style={{ display: "flex", flexDirection: "column", gap: "0.4rem" }}>
                  <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Remediation Notes / Analyst Comments</span>
                  <textarea
                    rows={3}
                    value={remediationNote}
                    onChange={(e) => setRemediationNote(e.target.value)}
                    placeholder="Enter analyst resolution notes or quarantine action details..."
                    style={{
                      background: "rgba(10, 13, 20, 0.9)",
                      border: "1px solid rgba(255,255,255,0.2)",
                      color: "#fff",
                      padding: "0.5rem",
                      borderRadius: "4px",
                      fontSize: "0.85rem"
                    }}
                  />
                </label>

                <button
                  onClick={handleUpdateStatus}
                  disabled={isUpdating}
                  style={{
                    marginTop: "1rem",
                    width: "100%",
                    background: "rgba(0, 255, 157, 0.2)",
                    border: "1px solid #00ff9d",
                    color: "#00ff9d",
                    padding: "0.6rem",
                    borderRadius: "6px",
                    cursor: "pointer",
                    fontWeight: "700"
                  }}
                >
                  {isUpdating ? "Saving Status..." : "Save Threat Resolution"}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
