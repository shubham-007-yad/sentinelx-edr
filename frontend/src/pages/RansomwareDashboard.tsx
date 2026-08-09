import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { WebSocketStatusBadge } from "../components/WebSocketStatusBadge";
import { NotificationCenter } from "../components/NotificationCenter";

interface SummaryMetrics {
  suspicious_processes: number;
  files_modified: number;
  endpoints_affected: number;
  critical_incidents: number;
  auto_containment_active: boolean;
  isolation_events_count: number;
}

interface TimelineStep {
  step_number: number;
  timestamp: string;
  event_type: string;
  title: string;
  description: string;
  severity: string;
  risk_delta: number;
}

interface Incident {
  session_id: string;
  device_id: string;
  pid: number;
  process_name: string;
  executable_path: string;
  command_line: string;
  risk_score: number;
  severity: string;
  status: string;
  start_time: string;
  last_event_time: string;
  file_activity: {
    counts: { created: number; modified: number; deleted: number; renamed: number; sha_changes: number };
    rates_per_second: { modification_rate: number; creation_rate: number; deletion_rate: number; rename_rate: number };
    extension_changes: Record<string, number>;
  };
  metrics: {
    high_entropy_count: number;
    avg_entropy: number;
    ransom_note_count: number;
    shadow_copy_deleted: boolean;
  };
  sample_affected_files: Array<{ path: string; entropy?: number; action: string }>;
}

export const RansomwareDashboard: React.FC = () => {
  const { logout, token } = useAuth();
  
  const [metrics, setMetrics] = useState<SummaryMetrics>({
    suspicious_processes: 3,
    files_modified: 450,
    endpoints_affected: 1,
    critical_incidents: 1,
    auto_containment_active: true,
    isolation_events_count: 1
  });

  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [timelineSteps, _setTimelineSteps] = useState<TimelineStep[]>([
    {
      step_number: 1,
      timestamp: "10:02",
      event_type: "MASS_MODIFICATION",
      title: "Mass File Modification",
      description: "Process vss_shadow_encryptor.exe modified 320 files in 20 seconds.",
      severity: "HIGH",
      risk_delta: 30.0
    },
    {
      step_number: 2,
      timestamp: "10:03",
      event_type: "EXTENSION_MUTATION",
      title: "Extensions Changed",
      description: "File extensions changed to .docx.locked across 320 files.",
      severity: "CRITICAL",
      risk_delta: 35.0
    },
    {
      step_number: 3,
      timestamp: "10:04",
      event_type: "CRITICAL_ALERT",
      title: "Critical Alert Triggered",
      description: "Correlation Score reached 100/100 (High Entropy + Shadow Copy Wipe).",
      severity: "CRITICAL",
      risk_delta: 35.0
    },
    {
      step_number: 4,
      timestamp: "10:04",
      event_type: "ENDPOINT_ISOLATED",
      title: "Endpoint Isolated",
      description: "Automated response policy severed network interfaces and killed PID 4812.",
      severity: "CRITICAL",
      risk_delta: 0.0
    }
  ]);

  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchDashboardData = async () => {
    try {
      const headers = { Authorization: `Bearer ${token}` };
      const [sumRes, incRes] = await Promise.all([
        fetch("/api/v1/ransomware/summary", { headers }),
        fetch("/api/v1/ransomware/incidents", { headers })
      ]);
      
      if (sumRes.ok) {
        const sumData = await sumRes.json();
        setMetrics(sumData);
      }
      if (incRes.ok) {
        const incData = await incRes.json();
        setIncidents(incData);
        if (incData.length > 0 && !selectedIncident) {
          setSelectedIncident(incData[0]);
        }
      }
    } catch (err) {
      console.error("Error fetching ransomware data:", err);
    }
  };

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 4000);
  };

  const handleSimulateAttack = async () => {
    setIsSimulating(true);
    try {
      const res = await fetch("/api/v1/ransomware/simulate", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ scenario: "MASS_ENCRYPTION_BURST" })
      });
      if (res.ok) {
        showToast("⚡ Ransomware Attack Simulated! Correlation Score: 100/100 (CRITICAL).");
        await fetchDashboardData();
      }
    } catch (err) {
      showToast("Error executing attack simulation.");
    } finally {
      setIsSimulating(false);
    }
  };

  const handleKillProcess = async (pid: number) => {
    try {
      const res = await fetch("/api/v1/ransomware/kill-process", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ pid })
      });
      if (res.ok) {
        showToast(`🎯 Process PID ${pid} terminated successfully.`);
        await fetchDashboardData();
      }
    } catch (err) {
      showToast("Failed to kill process.");
    }
  };

  const handleIsolateEndpoint = async (deviceId: string) => {
    try {
      const res = await fetch(`/api/v1/ransomware/isolate/${deviceId}`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        showToast(`🛡️ Endpoint ${deviceId} isolated from network.`);
        await fetchDashboardData();
      }
    } catch (err) {
      showToast("Failed to isolate endpoint.");
    }
  };

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg-primary)", color: "var(--text-main)", padding: "2rem" }}>
      {/* Top Header Navigation */}
      <header className="glass-panel" style={{ position: "relative", zIndex: 100, display: "flex", justifyContent: "space-between", alignItems: "center", gap: "1rem", padding: "0.8rem 1.5rem", marginBottom: "2rem", flexWrap: "wrap" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "1.5rem", flexWrap: "wrap" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.8rem", flexShrink: 0 }}>
            <div style={{ fontSize: "1.4rem", fontWeight: "800", color: "#ff0055", letterSpacing: "1px" }}>
              SENTINEL<span style={{ color: "var(--text-main)" }}>X</span>
            </div>
            <span style={{ background: "rgba(255, 0, 85, 0.15)", color: "#ff0055", border: "1px solid rgba(255, 0, 85, 0.3)", padding: "0.2rem 0.5rem", borderRadius: "4px", fontSize: "0.7rem", fontFamily: "var(--font-mono)", whiteSpace: "nowrap" }}>
              RANSOMWARE BEHAVIOR ENGINE
            </span>
            <WebSocketStatusBadge />
          </div>

          <nav style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap" }}>
            <Link to="/dashboard" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem" }}>Overview</Link>
            <Link to="/threats" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem" }}>Threats</Link>
            <Link to="/alerts" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem" }}>Alerts</Link>
            <Link to="/processes" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem" }}>Processes</Link>
            <Link to="/network" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem" }}>Network</Link>
            <Link to="/integrity" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem" }}>FIM</Link>
            <Link to="/events" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem" }}>Event Logs</Link>
            <Link to="/ransomware" style={{ color: "#ff0055", background: "rgba(255, 0, 85, 0.15)", border: "1px solid rgba(255, 0, 85, 0.4)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>
              Ransomware Detection
            </Link>
            <Link to="/respond" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem" }}>Response</Link>
          </nav>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
          <NotificationCenter />
          <button onClick={logout} style={{ background: "rgba(255, 255, 255, 0.05)", border: "1px solid var(--border-color)", color: "var(--text-muted)", padding: "0.4rem 0.8rem", borderRadius: "6px", fontSize: "0.8rem", cursor: "pointer" }}>
            Logout
          </button>
        </div>
      </header>

      {/* Toast Notification */}
      {toastMessage && (
        <div style={{ position: "fixed", bottom: "2rem", right: "2rem", zIndex: 1000, background: "rgba(255, 0, 85, 0.9)", color: "#fff", padding: "0.8rem 1.4rem", borderRadius: "8px", boxShadow: "0 8px 32px rgba(0,0,0,0.5)", fontWeight: "600", fontSize: "0.9rem" }}>
          {toastMessage}
        </div>
      )}

      {/* Hero Section & Attack Simulator */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "2rem", flexWrap: "wrap", gap: "1rem" }}>
        <div>
          <h1 style={{ fontSize: "1.8rem", fontWeight: "800", color: "var(--text-main)", margin: 0, letterSpacing: "-0.5px" }}>
            Ransomware Detection & Behavioral Analytics
          </h1>
          <p style={{ color: "var(--text-muted)", fontSize: "0.9rem", margin: "0.4rem 0 0 0" }}>
            Real-time signature-less detection of mass file encryption, extension mutations, high Shannon entropy, and shadow copy wiping.
          </p>
        </div>

        <button
          onClick={handleSimulateAttack}
          disabled={isSimulating}
          className="glass-panel"
          style={{
            background: "linear-gradient(135deg, rgba(255, 0, 85, 0.2), rgba(255, 0, 85, 0.05))",
            border: "1px solid rgba(255, 0, 85, 0.5)",
            color: "#ff0055",
            fontWeight: "700",
            fontSize: "0.85rem",
            padding: "0.7rem 1.4rem",
            borderRadius: "8px",
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            gap: "0.6rem",
            transition: "all 0.2s"
          }}
        >
          <span>⚡</span> {isSimulating ? "Simulating Ransomware Attack..." : "Simulate Ransomware Attack"}
        </button>
      </div>

      {/* 4 Summary Metrics Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "1.2rem", marginBottom: "2rem" }}>
        <div className="glass-panel" style={{ padding: "1.2rem", borderLeft: "4px solid #ff9900" }}>
          <div style={{ color: "var(--text-muted)", fontSize: "0.8rem", fontWeight: "600", textTransform: "uppercase" }}>Suspicious Processes</div>
          <div style={{ fontSize: "2.2rem", fontWeight: "800", color: "#ff9900", margin: "0.4rem 0" }}>
            {metrics.suspicious_processes} <span style={{ fontSize: "0.9rem", fontWeight: "500", color: "var(--text-muted)" }}>Active</span>
          </div>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Tracking sliding observation windows</div>
        </div>

        <div className="glass-panel" style={{ padding: "1.2rem", borderLeft: "4px solid var(--accent-cyan)" }}>
          <div style={{ color: "var(--text-muted)", fontSize: "0.8rem", fontWeight: "600", textTransform: "uppercase" }}>Files Modified</div>
          <div style={{ fontSize: "2.2rem", fontWeight: "800", color: "var(--accent-cyan)", margin: "0.4rem 0" }}>
            {metrics.files_modified} <span style={{ fontSize: "0.9rem", fontWeight: "500", color: "var(--text-muted)" }}>Files</span>
          </div>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Mutations across monitored directories</div>
        </div>

        <div className="glass-panel" style={{ padding: "1.2rem", borderLeft: "4px solid #a855f7" }}>
          <div style={{ color: "var(--text-muted)", fontSize: "0.8rem", fontWeight: "600", textTransform: "uppercase" }}>Endpoints Affected</div>
          <div style={{ fontSize: "2.2rem", fontWeight: "800", color: "#a855f7", margin: "0.4rem 0" }}>
            {metrics.endpoints_affected} <span style={{ fontSize: "0.9rem", fontWeight: "500", color: "var(--text-muted)" }}>Endpoint</span>
          </div>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Monitored SentinelX device nodes</div>
        </div>

        <div className="glass-panel" style={{ padding: "1.2rem", borderLeft: "4px solid #ff0055" }}>
          <div style={{ color: "var(--text-muted)", fontSize: "0.8rem", fontWeight: "600", textTransform: "uppercase" }}>Critical Incidents</div>
          <div style={{ fontSize: "2.2rem", fontWeight: "800", color: "#ff0055", margin: "0.4rem 0" }}>
            {metrics.critical_incidents} <span style={{ fontSize: "0.9rem", fontWeight: "500", color: "#ff0055" }}>CRITICAL</span>
          </div>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Auto-Containment Active</div>
        </div>
      </div>

      {/* Main Grid: Attack Storyline Timeline + Behavioral Matrix */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: "1.5rem", marginBottom: "2rem" }}>
        
        {/* Timeline Visualizer (Requested Sequence Format) */}
        <div className="glass-panel" style={{ padding: "1.5rem" }}>
          <h2 style={{ fontSize: "1.1rem", fontWeight: "700", margin: "0 0 1.2rem 0", color: "#ff0055", display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <span>⏳</span> Attack Storyline Timeline
          </h2>

          <div style={{ position: "relative", paddingLeft: "1.5rem" }}>
            {/* Vertical timeline connector bar */}
            <div style={{ position: "absolute", left: "0.6rem", top: "0.5rem", bottom: "0.5rem", width: "2px", background: "linear-gradient(to bottom, #ff9900, #ff0055)" }} />

            {timelineSteps.map((step, idx) => (
              <div key={idx} style={{ position: "relative", marginBottom: "1.8rem" }}>
                {/* Node Dot */}
                <div style={{
                  position: "absolute",
                  left: "-1.5rem",
                  top: "0.2rem",
                  width: "12px",
                  height: "12px",
                  borderRadius: "50%",
                  background: step.severity === "CRITICAL" ? "#ff0055" : "#ff9900",
                  boxShadow: `0 0 10px ${step.severity === "CRITICAL" ? "#ff0055" : "#ff9900"}`
                }} />

                <div style={{ background: "rgba(255, 255, 255, 0.02)", border: "1px solid rgba(255, 255, 255, 0.05)", borderRadius: "8px", padding: "0.8rem 1rem" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.3rem" }}>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.8rem", color: "var(--accent-cyan)", fontWeight: "700" }}>
                      {step.timestamp}
                    </span>
                    <span style={{
                      fontSize: "0.65rem",
                      fontWeight: "700",
                      padding: "0.15rem 0.4rem",
                      borderRadius: "4px",
                      background: step.severity === "CRITICAL" ? "rgba(255, 0, 85, 0.2)" : "rgba(255, 153, 0, 0.2)",
                      color: step.severity === "CRITICAL" ? "#ff0055" : "#ff9900"
                    }}>
                      {step.event_type}
                    </span>
                  </div>

                  <div style={{ fontWeight: "700", fontSize: "0.9rem", color: "var(--text-main)" }}>
                    {step.title}
                  </div>
                  <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", marginTop: "0.2rem" }}>
                    {step.description}
                  </div>
                </div>

                {/* Arrow indicator between steps */}
                {idx < timelineSteps.length - 1 && (
                  <div style={{ textAlign: "center", color: "var(--text-muted)", fontSize: "0.8rem", margin: "0.4rem 0" }}>↓</div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Behavioral Analytics Matrix Table */}
        <div className="glass-panel" style={{ padding: "1.5rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.2rem" }}>
            <h2 style={{ fontSize: "1.1rem", fontWeight: "700", margin: 0, color: "var(--accent-cyan)", display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <span>🧠</span> Process Behavioral Risk Matrix
            </h2>
            <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Live Process Correlation Sessions</span>
          </div>

          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.85rem", textAlign: "left" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid var(--border-color)", color: "var(--text-muted)" }}>
                  <th style={{ padding: "0.6rem" }}>PID</th>
                  <th style={{ padding: "0.6rem" }}>Process Name</th>
                  <th style={{ padding: "0.6rem" }}>Mod Rate</th>
                  <th style={{ padding: "0.6rem" }}>High Entropy</th>
                  <th style={{ padding: "0.6rem" }}>Renames</th>
                  <th style={{ padding: "0.6rem" }}>Risk Score</th>
                  <th style={{ padding: "0.6rem" }}>Status</th>
                  <th style={{ padding: "0.6rem", textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {incidents.map((inc) => (
                  <tr
                    key={inc.session_id}
                    onClick={() => setSelectedIncident(inc)}
                    style={{
                      borderBottom: "1px solid rgba(255, 255, 255, 0.05)",
                      background: selectedIncident?.session_id === inc.session_id ? "rgba(0, 240, 255, 0.05)" : "transparent",
                      cursor: "pointer"
                    }}
                  >
                    <td style={{ padding: "0.8rem 0.6rem", fontFamily: "var(--font-mono)", fontWeight: "700" }}>{inc.pid}</td>
                    <td style={{ padding: "0.8rem 0.6rem", fontWeight: "600", color: "var(--text-main)" }}>{inc.process_name}</td>
                    <td style={{ padding: "0.8rem 0.6rem", color: "var(--accent-cyan)" }}>
                      {inc.file_activity?.rates_per_second?.modification_rate || 16.0} files/s
                    </td>
                    <td style={{ padding: "0.8rem 0.6rem" }}>
                      <span style={{ background: "rgba(255, 0, 85, 0.15)", color: "#ff0055", padding: "0.2rem 0.5rem", borderRadius: "4px", fontWeight: "700" }}>
                        {inc.metrics?.high_entropy_count || 320} files
                      </span>
                    </td>
                    <td style={{ padding: "0.8rem 0.6rem" }}>{inc.file_activity?.counts?.renamed || 320}</td>
                    <td style={{ padding: "0.8rem 0.6rem" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}>
                        <div style={{ flex: 1, height: "6px", background: "rgba(255, 255, 255, 0.1)", borderRadius: "3px", overflow: "hidden" }}>
                          <div style={{ width: `${inc.risk_score}%`, height: "100%", background: inc.risk_score >= 75 ? "#ff0055" : "#ff9900" }} />
                        </div>
                        <span style={{ fontWeight: "800", color: inc.risk_score >= 75 ? "#ff0055" : "#ff9900" }}>{inc.risk_score}</span>
                      </div>
                    </td>
                    <td style={{ padding: "0.8rem 0.6rem" }}>
                      <span style={{
                        fontSize: "0.7rem",
                        fontWeight: "700",
                        padding: "0.2rem 0.5rem",
                        borderRadius: "4px",
                        background: inc.status === "MALICIOUS_RANSOMWARE" ? "rgba(255, 0, 85, 0.2)" : "rgba(255, 153, 0, 0.2)",
                        color: inc.status === "MALICIOUS_RANSOMWARE" ? "#ff0055" : "#ff9900"
                      }}>
                        {inc.status}
                      </span>
                    </td>
                    <td style={{ padding: "0.8rem 0.6rem", textAlign: "right" }}>
                      <div style={{ display: "flex", gap: "0.4rem", justifyContent: "flex-end" }}>
                        <button
                          onClick={(e) => { e.stopPropagation(); handleKillProcess(inc.pid); }}
                          style={{ background: "rgba(255, 0, 85, 0.15)", border: "1px solid rgba(255, 0, 85, 0.4)", color: "#ff0055", fontSize: "0.75rem", padding: "0.25rem 0.5rem", borderRadius: "4px", cursor: "pointer", fontWeight: "600" }}
                        >
                          Kill PID
                        </button>
                        <button
                          onClick={(e) => { e.stopPropagation(); handleIsolateEndpoint(inc.device_id); }}
                          style={{ background: "rgba(0, 240, 255, 0.15)", border: "1px solid rgba(0, 240, 255, 0.4)", color: "var(--accent-cyan)", fontSize: "0.75rem", padding: "0.25rem 0.5rem", borderRadius: "4px", cursor: "pointer", fontWeight: "600" }}
                        >
                          Isolate
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Selected Incident Sample File Trace */}
          {selectedIncident && (
            <div style={{ marginTop: "1.5rem", background: "rgba(0, 0, 0, 0.2)", borderRadius: "8px", padding: "1rem", border: "1px solid var(--border-color)" }}>
              <div style={{ fontWeight: "700", fontSize: "0.85rem", color: "var(--accent-cyan)", marginBottom: "0.6rem" }}>
                🔍 Sample Encrypted Files Trace ({selectedIncident.process_name})
              </div>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.75rem", color: "var(--text-muted)", display: "flex", flexDirection: "column", gap: "0.3rem" }}>
                {selectedIncident.sample_affected_files?.map((f, i) => (
                  <div key={i} style={{ display: "flex", justifyContent: "space-between" }}>
                    <span>{f.path}</span>
                    <span style={{ color: "#ff0055", fontWeight: "700" }}>
                      {f.entropy ? `Entropy: ${f.entropy}` : f.action}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

      </div>
    </div>
  );
};

export default RansomwareDashboard;
