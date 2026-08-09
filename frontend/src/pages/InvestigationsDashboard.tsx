import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { WebSocketStatusBadge } from "../components/WebSocketStatusBadge";
import { NotificationCenter } from "../components/NotificationCenter";
import {
  investigationService,
  type InvestigationCase,
  type UnifiedTimeline,
  type ThreatHuntMatch
} from "../services/investigation";

export const InvestigationsDashboard: React.FC = () => {
  const { user, logout } = useAuth();

  const [_loading, setLoading] = useState<boolean>(true);
  const [summaryData, setSummaryData] = useState<any>(null);
  const [cases, setCases] = useState<InvestigationCase[]>([]);
  const [selectedCorrelationId, setSelectedCorrelationId] = useState<string>("");
  const [activeTimeline, setActiveTimeline] = useState<UnifiedTimeline | null>(null);
  const [timelineLoading, setTimelineLoading] = useState<boolean>(false);

  // Threat Hunting Query State
  const [huntProcess, setHuntProcess] = useState<string>("powershell.exe");
  const [huntMinSeverity, setHuntMinSeverity] = useState<string>("HIGH");
  const [huntTimeRange, setHuntTimeRange] = useState<number>(24);
  const [huntResults, setHuntResults] = useState<ThreatHuntMatch[]>([]);
  const [huntLoading, setHuntLoading] = useState<boolean>(false);

  // New Case Modal State
  const [newCaseTitle, setNewCaseTitle] = useState<string>("");
  const [newCaseSeverity, setNewCaseSeverity] = useState<string>("HIGH");
  const [newCaseSummary, setNewCaseSummary] = useState<string>("");

  const fetchData = async () => {
    setLoading(true);
    try {
      const summary = await investigationService.getDashboardSummary();
      setSummaryData(summary);
      const caseList = await investigationService.getCases();
      setCases(caseList);

      // Auto-fetch initial threat hunt
      runThreatHunt();
    } catch (err) {
      console.error("Error fetching investigation dashboard data:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleFetchTimeline = async (corrId?: string) => {
    const targetId = corrId || selectedCorrelationId;
    if (!targetId) return;
    setTimelineLoading(true);
    try {
      const res = await investigationService.getTimeline(targetId);
      setActiveTimeline(res);
    } catch (err) {
      console.error("Error loading timeline:", err);
    } finally {
      setTimelineLoading(false);
    }
  };

  const runThreatHunt = async () => {
    setHuntLoading(true);
    try {
      const res = await investigationService.executeHunt({
        process: huntProcess || undefined,
        min_severity: huntMinSeverity || undefined,
        time_range_hours: Number(huntTimeRange)
      });
      setHuntResults(res.matches || []);
    } catch (err) {
      console.error("Error executing hunt:", err);
    } finally {
      setHuntLoading(false);
    }
  };

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCaseTitle) return;
    try {
      await investigationService.createCase({
        title: newCaseTitle,
        severity: newCaseSeverity as any,
        summary: newCaseSummary,
        assigned_to: user?.username || "Analyst"
      });
      setNewCaseTitle("");
      setNewCaseSummary("");
      fetchData();
    } catch (err) {
      console.error("Error creating case:", err);
    }
  };

  const getSeverityBadge = (severity: string) => {
    const s = severity?.toUpperCase();
    let bg = "rgba(0, 240, 255, 0.1)";
    let border = "rgba(0, 240, 255, 0.3)";
    let color = "var(--accent-cyan)";

    if (s === "CRITICAL") {
      bg = "rgba(255, 0, 85, 0.2)";
      border = "rgba(255, 0, 85, 0.5)";
      color = "#ff0055";
    } else if (s === "HIGH") {
      bg = "rgba(255, 170, 0, 0.2)";
      border = "rgba(255, 170, 0, 0.5)";
      color = "#ffaa00";
    } else if (s === "MEDIUM") {
      bg = "rgba(0, 240, 255, 0.15)";
      border = "rgba(0, 240, 255, 0.4)";
      color = "var(--accent-cyan)";
    }

    return (
      <span
        style={{
          background: bg,
          border: `1px solid ${border}`,
          color: color,
          padding: "0.2rem 0.5rem",
          borderRadius: "4px",
          fontSize: "0.75rem",
          fontWeight: "700"
        }}
      >
        {s}
      </span>
    );
  };

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg-primary)", color: "var(--text-main)", padding: "2rem" }}>
      {/* Top Header Navigation */}
      <header className="glass-panel" style={{ position: "relative", zIndex: 100, display: "flex", justifyContent: "space-between", alignItems: "center", gap: "1rem", padding: "0.8rem 1.5rem", marginBottom: "2rem", flexWrap: "wrap" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "1.5rem", flexWrap: "wrap" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.8rem", flexShrink: 0 }}>
            <div style={{ fontSize: "1.4rem", fontWeight: "800", color: "var(--accent-cyan)", letterSpacing: "1px" }}>
              SENTINEL<span style={{ color: "var(--text-main)" }}>X</span>
            </div>
            <span style={{ background: "rgba(0, 240, 255, 0.1)", color: "var(--accent-cyan)", padding: "0.2rem 0.5rem", borderRadius: "4px", fontSize: "0.7rem", fontFamily: "var(--font-mono)", whiteSpace: "nowrap" }}>
              INVESTIGATIONS v1.0.0
            </span>
            <WebSocketStatusBadge />
          </div>

          <nav style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap" }}>
            <Link to="/dashboard" style={{ color: "var(--text-main)", textDecoration: "none", fontSize: "0.85rem", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>Dashboard</Link>
            <Link to="/investigations" style={{ color: "var(--accent-cyan)", background: "rgba(0, 240, 255, 0.1)", border: "1px solid rgba(0, 240, 255, 0.3)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>Threat Hunting & Investigations</Link>
            <Link to="/threats" style={{ color: "#ff0055", textDecoration: "none", fontSize: "0.85rem", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>Threats</Link>
            <Link to="/alerts" style={{ color: "var(--text-main)", textDecoration: "none", fontSize: "0.85rem", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>Alerts</Link>
            <Link to="/processes" style={{ color: "var(--text-main)", textDecoration: "none", fontSize: "0.85rem", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>Processes</Link>
            <Link to="/network" style={{ color: "var(--text-main)", textDecoration: "none", fontSize: "0.85rem", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>Network</Link>
            <Link to="/integrity" style={{ color: "var(--text-main)", textDecoration: "none", fontSize: "0.85rem", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>FIM</Link>
            <Link to="/respond" style={{ color: "var(--text-main)", textDecoration: "none", fontSize: "0.85rem", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>Responses</Link>
          </nav>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
          <NotificationCenter />
          <button onClick={logout} style={{ background: "rgba(255,0,85,0.1)", color: "#ff0055", border: "1px solid rgba(255,0,85,0.3)", padding: "0.35rem 0.8rem", borderRadius: "6px", cursor: "pointer", fontSize: "0.85rem" }}>Logout</button>
        </div>
      </header>

      {/* Main Title Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "2rem", flexWrap: "wrap", gap: "1rem" }}>
        <div>
          <h1 style={{ fontSize: "1.8rem", fontWeight: "700", margin: "0 0 0.4rem 0", color: "var(--accent-cyan)" }}>
            📅 Threat Hunting & Investigation Console
          </h1>
          <p style={{ color: "var(--text-muted)", margin: 0, fontSize: "0.9rem" }}>
            Cross-telemetry incident reconstruction, open cases, attack timelines, IOC matches, response actions & endpoints.
          </p>
        </div>
        <div style={{ display: "flex", gap: "0.8rem" }}>
          <button
            onClick={() => investigationService.downloadReportPdf(undefined, selectedCorrelationId || undefined)}
            style={{ background: "#ff0055", color: "#fff", border: "none", padding: "0.5rem 1rem", borderRadius: "6px", fontWeight: "700", cursor: "pointer", fontSize: "0.85rem", display: "flex", alignItems: "center", gap: "0.4rem" }}
          >
            📄 Export PDF Report
          </button>
          <button
            onClick={async () => {
              const data = await investigationService.getReportJson(undefined, selectedCorrelationId || undefined);
              const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a");
              a.href = url;
              a.download = `Investigation_Report_${selectedCorrelationId || "Summary"}.json`;
              a.click();
            }}
            style={{ background: "rgba(0, 240, 255, 0.15)", color: "var(--accent-cyan)", border: "1px solid rgba(0, 240, 255, 0.4)", padding: "0.5rem 1rem", borderRadius: "6px", fontWeight: "700", cursor: "pointer", fontSize: "0.85rem", display: "flex", alignItems: "center", gap: "0.4rem" }}
          >
            💾 Export JSON Report
          </button>
        </div>
      </div>

      {/* Grid Layout for Sections */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem", marginBottom: "2rem" }}>

        {/* SECTION 1: Open Cases */}
        <div className="glass-panel" style={{ padding: "1.5rem", borderRadius: "10px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
            <h2 style={{ fontSize: "1.2rem", fontWeight: "600", margin: 0, color: "var(--accent-cyan)" }}>
              📁 1. Open Cases ({cases.length})
            </h2>
          </div>

          <form onSubmit={handleCreateCase} style={{ display: "flex", gap: "0.5rem", marginBottom: "1rem", flexWrap: "wrap" }}>
            <input
              type="text"
              placeholder="Case Title..."
              value={newCaseTitle}
              onChange={(e) => setNewCaseTitle(e.target.value)}
              style={{ flex: "2", background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)", color: "#fff", padding: "0.4rem 0.8rem", borderRadius: "6px", fontSize: "0.85rem" }}
            />
            <select
              value={newCaseSeverity}
              onChange={(e) => setNewCaseSeverity(e.target.value)}
              style={{ flex: "1", background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)", color: "#fff", padding: "0.4rem 0.8rem", borderRadius: "6px", fontSize: "0.85rem" }}
            >
              <option value="LOW" style={{ background: "#111" }}>LOW</option>
              <option value="MEDIUM" style={{ background: "#111" }}>MEDIUM</option>
              <option value="HIGH" style={{ background: "#111" }}>HIGH</option>
              <option value="CRITICAL" style={{ background: "#111" }}>CRITICAL</option>
            </select>
            <button type="submit" style={{ background: "var(--accent-cyan)", color: "#000", border: "none", padding: "0.4rem 1rem", borderRadius: "6px", fontWeight: "700", cursor: "pointer", fontSize: "0.85rem" }}>
              + Open Case
            </button>
          </form>

          {cases.length === 0 ? (
            <div style={{ color: "var(--text-muted)", fontSize: "0.85rem", fontStyle: "italic" }}>No open cases recorded. Create a new case above.</div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "0.8rem", maxHeight: "300px", overflowY: "auto" }}>
              {cases.map((c) => (
                <div key={c.id} style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)", padding: "0.8rem", borderRadius: "8px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <div>
                    <div style={{ fontWeight: "600", fontSize: "0.95rem", marginBottom: "0.2rem" }}>{c.title}</div>
                    <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                      Assigned: <span style={{ color: "#fff" }}>{c.assigned_to || "Unassigned"}</span> | Status: <span style={{ color: "var(--accent-cyan)" }}>{c.status}</span>
                    </div>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: "0.8rem" }}>
                    {getSeverityBadge(c.severity)}
                    {c.correlation_id && (
                      <button
                        onClick={() => {
                          setSelectedCorrelationId(c.correlation_id!);
                          handleFetchTimeline(c.correlation_id!);
                        }}
                        style={{ background: "rgba(0,240,255,0.1)", color: "var(--accent-cyan)", border: "1px solid rgba(0,240,255,0.3)", padding: "0.25rem 0.5rem", borderRadius: "4px", fontSize: "0.75rem", cursor: "pointer" }}
                      >
                        View Timeline
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* SECTION 2: Recent Incidents */}
        <div className="glass-panel" style={{ padding: "1.5rem", borderRadius: "10px" }}>
          <h2 style={{ fontSize: "1.2rem", fontWeight: "600", margin: "0 0 1rem 0", color: "#ffaa00" }}>
            🚨 2. Recent Incidents
          </h2>
          {summaryData?.recent_incidents?.length === 0 ? (
            <div style={{ color: "var(--text-muted)", fontSize: "0.85rem", fontStyle: "italic" }}>No recent incidents detected.</div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "0.8rem", maxHeight: "350px", overflowY: "auto" }}>
              {summaryData?.recent_incidents?.map((inc: any) => (
                <div key={inc.id} style={{ background: "rgba(255,170,0,0.05)", border: "1px solid rgba(255,170,0,0.2)", padding: "0.8rem", borderRadius: "8px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <div>
                    <div style={{ fontWeight: "600", fontSize: "0.9rem", color: "#fff" }}>{inc.title}</div>
                    <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                      Type: {inc.threat_type} | Detected: {new Date(inc.created_at).toLocaleTimeString()}
                    </div>
                  </div>
                  <div>{getSeverityBadge(inc.severity)}</div>
                </div>
              ))}
            </div>
          )}
        </div>

      </div>

      {/* SECTION 3: Timeline Viewer */}
      <div className="glass-panel" style={{ padding: "1.5rem", borderRadius: "10px", marginBottom: "2rem" }}>
        <h2 style={{ fontSize: "1.2rem", fontWeight: "600", margin: "0 0 1rem 0", color: "var(--accent-cyan)" }}>
          ⏱ 3. Unified Timeline Viewer
        </h2>

        <div style={{ display: "flex", gap: "0.8rem", marginBottom: "1.5rem" }}>
          <input
            type="text"
            placeholder="Enter Correlation ID (e.g., UUID)..."
            value={selectedCorrelationId}
            onChange={(e) => setSelectedCorrelationId(e.target.value)}
            style={{ flex: 1, background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)", color: "#fff", padding: "0.5rem 1rem", borderRadius: "6px", fontSize: "0.85rem" }}
          />
          <button
            onClick={() => handleFetchTimeline()}
            style={{ background: "var(--accent-cyan)", color: "#000", border: "none", padding: "0.5rem 1.2rem", borderRadius: "6px", fontWeight: "700", cursor: "pointer", fontSize: "0.85rem" }}
          >
            {timelineLoading ? "Loading..." : "Inspect Timeline"}
          </button>
        </div>

        {activeTimeline ? (
          <div>
            <div style={{ fontSize: "0.85rem", color: "var(--text-muted)", marginBottom: "1rem" }}>
              Showing <strong style={{ color: "var(--accent-cyan)" }}>{activeTimeline.total_events}</strong> correlated timeline events for ID: <code>{activeTimeline.correlation_id}</code>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: "0.6rem", borderLeft: "2px solid var(--accent-cyan)", paddingLeft: "1rem" }}>
              {activeTimeline.timeline.map((ev, idx) => (
                <div key={idx} style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", padding: "0.75rem 1rem", borderRadius: "6px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <div>
                    <span style={{ color: "var(--accent-cyan)", fontWeight: "700", fontFamily: "var(--font-mono)", marginRight: "0.8rem" }}>
                      [{ev.time_formatted}]
                    </span>
                    <span style={{ fontWeight: "600", fontSize: "0.9rem", color: "#fff" }}>
                      {ev.title}
                    </span>
                    {ev.description && (
                      <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", marginTop: "0.2rem" }}>
                        {ev.description}
                      </div>
                    )}
                  </div>
                  <div>{getSeverityBadge(ev.severity)}</div>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div style={{ color: "var(--text-muted)", fontSize: "0.85rem", fontStyle: "italic", textAlign: "center", padding: "1.5rem 0" }}>
            Enter or select a Correlation ID above to render the unified step-by-step incident timeline.
          </div>
        )}
      </div>

      {/* SECTION 4: IOC Matches */}
      <div className="glass-panel" style={{ padding: "1.5rem", borderRadius: "10px", marginBottom: "2rem" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
          <h2 style={{ fontSize: "1.2rem", fontWeight: "600", margin: 0, color: "var(--accent-cyan)" }}>
            🔍 4. IOC Matches & Threat Hunting Engine
          </h2>
          <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>Filter: process=powershell.exe | min_severity=HIGH | Last 24h</span>
        </div>

        <div style={{ display: "flex", gap: "0.8rem", marginBottom: "1rem", flexWrap: "wrap" }}>
          <input
            type="text"
            placeholder="Process (e.g. powershell.exe)..."
            value={huntProcess}
            onChange={(e) => setHuntProcess(e.target.value)}
            style={{ flex: 1, background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)", color: "#fff", padding: "0.4rem 0.8rem", borderRadius: "6px", fontSize: "0.85rem" }}
          />
          <select
            value={huntMinSeverity}
            onChange={(e) => setHuntMinSeverity(e.target.value)}
            style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)", color: "#fff", padding: "0.4rem 0.8rem", borderRadius: "6px", fontSize: "0.85rem" }}
          >
            <option value="LOW" style={{ background: "#111" }}>Min Severity: LOW</option>
            <option value="MEDIUM" style={{ background: "#111" }}>Min Severity: MEDIUM</option>
            <option value="HIGH" style={{ background: "#111" }}>Min Severity: HIGH</option>
            <option value="CRITICAL" style={{ background: "#111" }}>Min Severity: CRITICAL</option>
          </select>
          <select
            value={huntTimeRange}
            onChange={(e) => setHuntTimeRange(Number(e.target.value))}
            style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)", color: "#fff", padding: "0.4rem 0.8rem", borderRadius: "6px", fontSize: "0.85rem" }}
          >
            <option value={1} style={{ background: "#111" }}>Last 1 Hour</option>
            <option value={24} style={{ background: "#111" }}>Last 24 Hours</option>
            <option value={168} style={{ background: "#111" }}>Last 7 Days</option>
          </select>
          <button
            onClick={runThreatHunt}
            style={{ background: "#ff0055", color: "#fff", border: "none", padding: "0.4rem 1rem", borderRadius: "6px", fontWeight: "700", cursor: "pointer", fontSize: "0.85rem" }}
          >
            {huntLoading ? "Searching..." : "Execute Hunt"}
          </button>
        </div>

        {huntResults.length === 0 ? (
          <div style={{ color: "var(--text-muted)", fontSize: "0.85rem", fontStyle: "italic" }}>No IOC matches found for current criteria.</div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "0.6rem", maxHeight: "300px", overflowY: "auto" }}>
            {huntResults.map((m) => (
              <div key={m.event_id} style={{ background: "rgba(255,0,85,0.04)", border: "1px solid rgba(255,0,85,0.15)", padding: "0.75rem 1rem", borderRadius: "6px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div>
                  <span style={{ fontWeight: "700", fontSize: "0.85rem", color: "#ff0055", marginRight: "0.6rem" }}>
                    [{m.category}]
                  </span>
                  <span style={{ fontWeight: "600", fontSize: "0.9rem", color: "#fff" }}>
                    {m.title}
                  </span>
                  <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.2rem" }}>
                    Process: {m.process_name || "N/A"} | IP: {m.ip || "N/A"} | Timestamp: {m.time_formatted}
                  </div>
                </div>
                <div>{getSeverityBadge(m.severity)}</div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Grid Layout for Section 5 & 6 */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem" }}>

        {/* SECTION 5: Response Actions */}
        <div className="glass-panel" style={{ padding: "1.5rem", borderRadius: "10px" }}>
          <h2 style={{ fontSize: "1.2rem", fontWeight: "600", margin: "0 0 1rem 0", color: "#00f0ff" }}>
            ⚡ 5. Response Actions Executed
          </h2>
          {summaryData?.response_actions?.length === 0 ? (
            <div style={{ color: "var(--text-muted)", fontSize: "0.85rem", fontStyle: "italic" }}>No response actions recorded.</div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "0.6rem" }}>
              {summaryData?.response_actions?.map((r: any) => (
                <div key={r.id} style={{ background: "rgba(0,240,255,0.03)", border: "1px solid rgba(0,240,255,0.15)", padding: "0.75rem 1rem", borderRadius: "6px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <div>
                    <div style={{ fontWeight: "600", fontSize: "0.85rem", color: "#fff" }}>{r.action_type}</div>
                    <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>{r.details || "Automated containment trigger"}</div>
                  </div>
                  <span style={{ background: "rgba(0,240,255,0.1)", color: "var(--accent-cyan)", padding: "0.2rem 0.5rem", borderRadius: "4px", fontSize: "0.7rem", fontWeight: "700" }}>
                    {r.status}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* SECTION 6: Related Devices */}
        <div className="glass-panel" style={{ padding: "1.5rem", borderRadius: "10px" }}>
          <h2 style={{ fontSize: "1.2rem", fontWeight: "600", margin: "0 0 1rem 0", color: "var(--text-main)" }}>
            💻 6. Related Endpoint Devices
          </h2>
          {summaryData?.related_devices?.length === 0 ? (
            <div style={{ color: "var(--text-muted)", fontSize: "0.85rem", fontStyle: "italic" }}>No endpoint devices connected.</div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "0.6rem" }}>
              {summaryData?.related_devices?.map((d: any) => (
                <div key={d.id} style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)", padding: "0.75rem 1rem", borderRadius: "6px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <div>
                    <div style={{ fontWeight: "600", fontSize: "0.9rem", color: "#fff" }}>{d.hostname}</div>
                    <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                      IP: {d.ip_address} | OS: {d.os_type}
                    </div>
                  </div>
                  <span style={{ background: d.status === "ONLINE" ? "rgba(0,255,136,0.1)" : "rgba(255,0,85,0.1)", color: d.status === "ONLINE" ? "#00ff88" : "#ff0055", border: `1px solid ${d.status === "ONLINE" ? "rgba(0,255,136,0.3)" : "rgba(255,0,85,0.3)"}`, padding: "0.2rem 0.5rem", borderRadius: "4px", fontSize: "0.7rem", fontWeight: "700" }}>
                    {d.status}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

      </div>
    </div>
  );
};

export default InvestigationsDashboard;
