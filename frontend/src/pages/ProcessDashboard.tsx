import React, { useEffect, useState, useMemo } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { getProcesses, getDevices, getProcessAuditLogs } from "../services/process";
import { triggerResponseAction } from "../services/response";
import type { ProcessItem, DeviceItem, ProcessAuditLogItem } from "../types/process";
import { WebSocketStatusBadge } from "../components/WebSocketStatusBadge";
import { NotificationCenter } from "../components/NotificationCenter";

export const ProcessDashboard: React.FC = () => {
  const { user, logout } = useAuth();

  const [processes, setProcesses] = useState<ProcessItem[]>([]);
  const [auditLogs, setAuditLogs] = useState<ProcessAuditLogItem[]>([]);
  const [devices, setDevices] = useState<DeviceItem[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Tab State
  const [activeTab, setActiveTab] = useState<"ACTIVE_PROCESSES" | "AUDIT_LOGS">("ACTIVE_PROCESSES");

  // Filters State
  const [selectedDevice, setSelectedDevice] = useState<string>("ALL");
  const [nameFilter, setNameFilter] = useState<string>("");
  const [userFilter, setUserFilter] = useState<string>("");
  const [highCpuOnly, setHighCpuOnly] = useState<boolean>(false);
  const [highMemoryOnly, setHighMemoryOnly] = useState<boolean>(false);
  const [selectedEventType, setSelectedEventType] = useState<string>("ALL");

  // Device ID to Hostname Lookup map
  const deviceMap = useMemo(() => {
    const map: Record<string, string> = {};
    devices.forEach((d) => {
      map[d.id] = d.hostname || d.id.substring(0, 8);
    });
    return map;
  }, [devices]);

  const fetchData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [procData, devData, logsData] = await Promise.all([
        getProcesses(0, 500),
        getDevices(),
        getProcessAuditLogs(0, 500),
      ]);
      setProcesses(procData);
      setDevices(devData);
      setAuditLogs(logsData);
    } catch (err: any) {
      console.error("Failed to load process inventory:", err);
      setError(err.message || "Failed to fetch process inventory data.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const timer = setInterval(() => {
      fetchData();
    }, 10000);
    return () => clearInterval(timer);
  }, []);

  // Filtered Processes Logic
  const filteredProcesses = useMemo(() => {
    return processes.filter((proc) => {
      // 1. Device Filter
      if (selectedDevice !== "ALL" && proc.device_id !== selectedDevice) {
        return false;
      }
      // 2. Process Name Filter
      if (
        nameFilter.trim() !== "" &&
        !proc.name.toLowerCase().includes(nameFilter.trim().toLowerCase())
      ) {
        return false;
      }
      // 3. User Filter
      if (
        userFilter.trim() !== "" &&
        !(proc.username || "").toLowerCase().includes(userFilter.trim().toLowerCase())
      ) {
        return false;
      }
      // 4. High CPU (> 10%)
      if (highCpuOnly && (proc.cpu_percent || 0) < 10.0) {
        return false;
      }
      // 5. High Memory (> 5%)
      if (highMemoryOnly && (proc.memory_percent || 0) < 5.0) {
        return false;
      }

      return true;
    });
  }, [processes, selectedDevice, nameFilter, userFilter, highCpuOnly, highMemoryOnly]);

  // Filtered Audit Logs Logic
  const filteredAuditLogs = useMemo(() => {
    return auditLogs.filter((log) => {
      if (selectedDevice !== "ALL" && log.device_id !== selectedDevice) {
        return false;
      }
      if (selectedEventType !== "ALL" && log.event_type !== selectedEventType) {
        return false;
      }
      if (
        nameFilter.trim() !== "" &&
        !log.process_name.toLowerCase().includes(nameFilter.trim().toLowerCase())
      ) {
        return false;
      }
      return true;
    });
  }, [auditLogs, selectedDevice, selectedEventType, nameFilter]);

  // Statistics
  const totalProcessesCount = processes.length;
  const highCpuCount = useMemo(() => processes.filter((p) => (p.cpu_percent || 0) >= 10.0).length, [processes]);
  const highMemoryCount = useMemo(() => processes.filter((p) => (p.memory_percent || 0) >= 5.0).length, [processes]);
  const uniqueDevicesCount = useMemo(() => new Set(processes.map((p) => p.device_id)).size, [processes]);

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg-primary)", color: "var(--text-main)", padding: "2rem" }}>
      {/* Top Header Navigation */}
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
              EDR CONSOLE v1.0.0
            </span>
            <WebSocketStatusBadge />
          </div>

          <nav style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap" }}>
            <Link
              to="/dashboard"
              style={{
                color: "var(--text-muted)",
                background: "rgba(255, 255, 255, 0.03)",
                border: "1px solid rgba(255, 255, 255, 0.1)",
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
                color: "#ff0055",
                background: "rgba(255, 0, 85, 0.1)",
                border: "1px solid rgba(255, 0, 85, 0.3)",
                textDecoration: "none",
                fontSize: "0.85rem",
                fontWeight: "600",
                padding: "0.35rem 0.7rem",
                borderRadius: "6px",
                whiteSpace: "nowrap",
              }}
            >
              Threat Dashboard
            </Link>
            <Link
              to="/alerts"
              style={{
                color: "#ffaa00",
                background: "rgba(255, 170, 0, 0.1)",
                border: "1px solid rgba(255, 170, 0, 0.3)",
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
              to="/respond"
              style={{
                color: "#a855f7",
                background: "rgba(168, 85, 247, 0.1)",
                border: "1px solid rgba(168, 85, 247, 0.3)",
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
            <Link
              to="/processes"
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
              Process Inventory
            </Link>
            <Link
              to="/usb-activity"
              style={{
                color: "var(--text-muted)",
                background: "rgba(255, 255, 255, 0.03)",
                border: "1px solid rgba(255, 255, 255, 0.1)",
                textDecoration: "none",
                fontSize: "0.85rem",
                fontWeight: "600",
                padding: "0.35rem 0.7rem",
                borderRadius: "6px",
                whiteSpace: "nowrap",
              }}
            >
              USB Activity
            </Link>
            <Link
              to="/usb-scans"
              style={{
                color: "var(--text-muted)",
                background: "rgba(255, 255, 255, 0.03)",
                border: "1px solid rgba(255, 255, 255, 0.1)",
                textDecoration: "none",
                fontSize: "0.85rem",
                fontWeight: "600",
                padding: "0.35rem 0.7rem",
                borderRadius: "6px",
                whiteSpace: "nowrap",
              }}
            >
              USB Scans
            </Link>
            {user?.role === "ADMIN" && (
              <Link
                to="/users"
                style={{
                  color: "#3b82f6",
                  background: "rgba(59, 130, 246, 0.1)",
                  border: "1px solid rgba(59, 130, 246, 0.3)",
                  textDecoration: "none",
                  fontSize: "0.85rem",
                  fontWeight: "600",
                  padding: "0.35rem 0.7rem",
                  borderRadius: "6px",
                  whiteSpace: "nowrap",
                }}
              >
                Users
              </Link>
            )}
          </nav>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
          <NotificationCenter />
          <div style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
            Logged in as <strong style={{ color: "var(--accent-cyan)" }}>{user?.username}</strong> ({user?.role})
          </div>
          <button
            onClick={logout}
            style={{
              background: "rgba(255, 0, 85, 0.15)",
              color: "#ff0055",
              border: "1px solid rgba(255, 0, 85, 0.3)",
              padding: "0.4rem 0.8rem",
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

      {/* Page Title Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem", flexWrap: "wrap", gap: "1rem" }}>
        <div>
          <h1 style={{ fontSize: "1.8rem", fontWeight: "700", margin: 0, color: "var(--text-main)" }}>
            ⚡ Process Inventory & Telemetry
          </h1>
          <p style={{ color: "var(--text-muted)", fontSize: "0.9rem", margin: "0.2rem 0 0 0" }}>
            Live endpoint process execution monitoring, behavioral heuristics, and resource telemetry.
          </p>
        </div>

        <button
          onClick={fetchData}
          style={{
            background: "rgba(0, 240, 255, 0.15)",
            color: "var(--accent-cyan)",
            border: "1px solid rgba(0, 240, 255, 0.3)",
            padding: "0.55rem 1.2rem",
            borderRadius: "6px",
            fontSize: "0.85rem",
            fontWeight: "600",
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            gap: "0.5rem"
          }}
        >
          🔄 Refresh Telemetry
        </button>
      </div>

      {/* View Tab Selection */}
      <div style={{ display: "flex", gap: "0.5rem", marginBottom: "1.5rem" }}>
        <button
          onClick={() => setActiveTab("ACTIVE_PROCESSES")}
          style={{
            background: activeTab === "ACTIVE_PROCESSES" ? "rgba(0, 240, 255, 0.2)" : "rgba(255, 255, 255, 0.03)",
            color: activeTab === "ACTIVE_PROCESSES" ? "var(--accent-cyan)" : "var(--text-muted)",
            border: activeTab === "ACTIVE_PROCESSES" ? "1px solid rgba(0, 240, 255, 0.4)" : "1px solid rgba(255, 255, 255, 0.1)",
            padding: "0.55rem 1.2rem",
            borderRadius: "6px",
            fontSize: "0.85rem",
            fontWeight: "700",
            cursor: "pointer",
          }}
        >
          ⚡ Active Running Processes ({processes.length})
        </button>

        <button
          onClick={() => setActiveTab("AUDIT_LOGS")}
          style={{
            background: activeTab === "AUDIT_LOGS" ? "rgba(168, 85, 247, 0.2)" : "rgba(255, 255, 255, 0.03)",
            color: activeTab === "AUDIT_LOGS" ? "#a855f7" : "var(--text-muted)",
            border: activeTab === "AUDIT_LOGS" ? "1px solid rgba(168, 85, 247, 0.4)" : "1px solid rgba(255, 255, 255, 0.1)",
            padding: "0.55rem 1.2rem",
            borderRadius: "6px",
            fontSize: "0.85rem",
            fontWeight: "700",
            cursor: "pointer",
          }}
        >
          📜 Process Audit & Event History ({auditLogs.length})
        </button>
      </div>

      {/* Top Metric Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1rem))", gap: "1.2rem", marginBottom: "2rem" }}>
        <div className="glass-panel" style={{ padding: "1.2rem", borderLeft: "4px solid var(--accent-cyan)" }}>
          <div style={{ color: "var(--text-muted)", fontSize: "0.8rem", textTransform: "uppercase", fontWeight: "600" }}>Total Active Processes</div>
          <div style={{ fontSize: "2rem", fontWeight: "800", color: "var(--accent-cyan)", marginTop: "0.4rem" }}>{totalProcessesCount}</div>
        </div>

        <div className="glass-panel" style={{ padding: "1.2rem", borderLeft: "4px solid #a855f7" }}>
          <div style={{ color: "var(--text-muted)", fontSize: "0.8rem", textTransform: "uppercase", fontWeight: "600" }}>Monitored Endpoints</div>
          <div style={{ fontSize: "2rem", fontWeight: "800", color: "#a855f7", marginTop: "0.4rem" }}>{uniqueDevicesCount}</div>
        </div>

        <div className="glass-panel" style={{ padding: "1.2rem", borderLeft: "4px solid #ff0055" }}>
          <div style={{ color: "var(--text-muted)", fontSize: "0.8rem", textTransform: "uppercase", fontWeight: "600" }}>High CPU Processes (&gt;10%)</div>
          <div style={{ fontSize: "2rem", fontWeight: "800", color: "#ff0055", marginTop: "0.4rem" }}>{highCpuCount}</div>
        </div>

        <div className="glass-panel" style={{ padding: "1.2rem", borderLeft: "4px solid #ffaa00" }}>
          <div style={{ color: "var(--text-muted)", fontSize: "0.8rem", textTransform: "uppercase", fontWeight: "600" }}>High Memory Processes (&gt;5%)</div>
          <div style={{ fontSize: "2rem", fontWeight: "800", color: "#ffaa00", marginTop: "0.4rem" }}>{highMemoryCount}</div>
        </div>
      </div>

      {/* Filters Panel */}
      <div className="glass-panel" style={{ padding: "1.2rem", marginBottom: "1.5rem", display: "flex", gap: "1rem", flexWrap: "wrap", alignItems: "center" }}>
        {/* Device Filter */}
        <div style={{ display: "flex", flexDirection: "column", gap: "0.3rem", minWidth: "180px" }}>
          <label style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: "600" }}>Device Endpoint</label>
          <select
            value={selectedDevice}
            onChange={(e) => setSelectedDevice(e.target.value)}
            style={{
              background: "rgba(0, 0, 0, 0.4)",
              color: "var(--text-main)",
              border: "1px solid rgba(255, 255, 255, 0.15)",
              borderRadius: "6px",
              padding: "0.45rem 0.7rem",
              fontSize: "0.85rem"
            }}
          >
            <option value="ALL">All Devices ({devices.length})</option>
            {devices.map((dev) => (
              <option key={dev.id} value={dev.id}>
                {dev.hostname || dev.id} ({dev.os_type})
              </option>
            ))}
          </select>
        </div>

        {/* Process Name Search */}
        <div style={{ display: "flex", flexDirection: "column", gap: "0.3rem", minWidth: "200px" }}>
          <label style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: "600" }}>Process Name</label>
          <input
            type="text"
            placeholder="Search name (e.g. powershell)..."
            value={nameFilter}
            onChange={(e) => setNameFilter(e.target.value)}
            style={{
              background: "rgba(0, 0, 0, 0.4)",
              color: "var(--text-main)",
              border: "1px solid rgba(255, 255, 255, 0.15)",
              borderRadius: "6px",
              padding: "0.45rem 0.7rem",
              fontSize: "0.85rem"
            }}
          />
        </div>

        {activeTab === "AUDIT_LOGS" && (
          <div style={{ display: "flex", flexDirection: "column", gap: "0.3rem", minWidth: "180px" }}>
            <label style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: "600" }}>Event Type</label>
            <select
              value={selectedEventType}
              onChange={(e) => setSelectedEventType(e.target.value)}
              style={{
                background: "rgba(0, 0, 0, 0.4)",
                color: "var(--text-main)",
                border: "1px solid rgba(255, 255, 255, 0.15)",
                borderRadius: "6px",
                padding: "0.45rem 0.7rem",
                fontSize: "0.85rem"
              }}
            >
              <option value="ALL">All Event Types</option>
              <option value="PROCESS_STARTED">Process Started</option>
              <option value="PROCESS_TERMINATED">Process Terminated</option>
              <option value="RESPONSE_ACTION">Response Action</option>
              <option value="DETECTION_FOUND">Detection Found</option>
            </select>
          </div>
        )}

        {activeTab === "ACTIVE_PROCESSES" && (
          <>
            {/* User Search */}
            <div style={{ display: "flex", flexDirection: "column", gap: "0.3rem", minWidth: "160px" }}>
              <label style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: "600" }}>Execution User</label>
              <input
                type="text"
                placeholder="Search user (e.g. root)..."
                value={userFilter}
                onChange={(e) => setUserFilter(e.target.value)}
                style={{
                  background: "rgba(0, 0, 0, 0.4)",
                  color: "var(--text-main)",
                  border: "1px solid rgba(255, 255, 255, 0.15)",
                  borderRadius: "6px",
                  padding: "0.45rem 0.7rem",
                  fontSize: "0.85rem"
                }}
              />
            </div>

            {/* Checkbox Toggles */}
            <div style={{ display: "flex", alignItems: "center", gap: "1.2rem", marginTop: "1.2rem", flexWrap: "wrap" }}>
              <label style={{ display: "flex", alignItems: "center", gap: "0.4rem", fontSize: "0.85rem", cursor: "pointer", color: highCpuOnly ? "#ff0055" : "var(--text-main)" }}>
                <input
                  type="checkbox"
                  checked={highCpuOnly}
                  onChange={(e) => setHighCpuOnly(e.target.checked)}
                />
                🔥 High CPU (&gt;10%)
              </label>

              <label style={{ display: "flex", alignItems: "center", gap: "0.4rem", fontSize: "0.85rem", cursor: "pointer", color: highMemoryOnly ? "#ffaa00" : "var(--text-main)" }}>
                <input
                  type="checkbox"
                  checked={highMemoryOnly}
                  onChange={(e) => setHighMemoryOnly(e.target.checked)}
                />
                💾 High Memory (&gt;5%)
              </label>
            </div>
          </>
        )}
      </div>

      {/* Main Content Table (Switch between Active Processes and Audit Logs) */}
      <div className="glass-panel" style={{ padding: "1.2rem", overflowX: "auto" }}>
        {activeTab === "ACTIVE_PROCESSES" ? (
          isLoading && processes.length === 0 ? (
            <div style={{ padding: "3rem", textAlign: "center", color: "var(--accent-cyan)" }}>
              Loading process inventory telemetry...
            </div>
          ) : error ? (
            <div style={{ padding: "2rem", textAlign: "center", color: "#ff0055" }}>
              {error}
            </div>
          ) : filteredProcesses.length === 0 ? (
            <div style={{ padding: "3rem", textAlign: "center", color: "var(--text-muted)" }}>
              No process records match the selected filter criteria.
            </div>
          ) : (
            <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left", fontSize: "0.85rem" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.1)", color: "var(--text-muted)", textTransform: "uppercase", fontSize: "0.75rem", letterSpacing: "0.5px" }}>
                  <th style={{ padding: "0.8rem" }}>PID</th>
                  <th style={{ padding: "0.8rem" }}>Name</th>
                  <th style={{ padding: "0.8rem" }}>User</th>
                  <th style={{ padding: "0.8rem" }}>CPU %</th>
                  <th style={{ padding: "0.8rem" }}>Memory %</th>
                  <th style={{ padding: "0.8rem" }}>Device</th>
                  <th style={{ padding: "0.8rem" }}>Started</th>
                  <th style={{ padding: "0.8rem", textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredProcesses.map((proc) => {
                  const deviceName = deviceMap[proc.device_id] || proc.device_id.substring(0, 8);
                  const cpuVal = proc.cpu_percent || 0.0;
                  const memVal = proc.memory_percent || 0.0;

                  const isHighCpu = cpuVal >= 10.0;
                  const isHighMem = memVal >= 5.0;

                  const handleAction = async (actionType: string) => {
                    try {
                      await triggerResponseAction(proc.device_id, actionType);
                      alert(`Response action '${actionType}' initiated for process '${proc.name}' (PID: ${proc.pid}).`);
                    } catch (err: any) {
                      alert(`Failed to trigger '${actionType}': ` + (err.message || "Error"));
                    }
                  };

                  return (
                    <tr
                      key={proc.id}
                      style={{
                        borderBottom: "1px solid rgba(255, 255, 255, 0.05)",
                        transition: "background 0.2s"
                      }}
                    >
                      <td style={{ padding: "0.8rem" }}>
                        <span style={{ fontFamily: "var(--font-mono)", fontWeight: "700", color: "var(--accent-cyan)" }}>
                          {proc.pid}
                        </span>
                        {proc.ppid && (
                          <div style={{ fontSize: "0.7rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                            PPID: {proc.ppid}
                          </div>
                        )}
                      </td>

                      <td style={{ padding: "0.8rem" }}>
                        <div style={{ fontWeight: "600", color: "var(--text-main)" }}>{proc.name}</div>
                        {proc.exe_path && (
                          <div style={{ fontSize: "0.7rem", color: "var(--text-muted)", maxWidth: "300px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={proc.exe_path}>
                            {proc.exe_path}
                          </div>
                        )}
                        {proc.cmdline && (
                          <div style={{ fontSize: "0.68rem", color: "rgba(0, 240, 255, 0.7)", fontFamily: "var(--font-mono)", maxWidth: "300px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={proc.cmdline}>
                            CMD: {proc.cmdline}
                          </div>
                        )}
                      </td>

                      <td style={{ padding: "0.8rem" }}>
                        <span
                          style={{
                            background: proc.username === "root" || proc.username === "SYSTEM" ? "rgba(255, 0, 85, 0.15)" : "rgba(255, 255, 255, 0.08)",
                            color: proc.username === "root" || proc.username === "SYSTEM" ? "#ff0055" : "var(--text-main)",
                            padding: "0.2rem 0.5rem",
                            borderRadius: "4px",
                            fontSize: "0.75rem",
                            fontWeight: "600"
                          }}
                        >
                          {proc.username || "unknown"}
                        </span>
                      </td>

                      <td style={{ padding: "0.8rem" }}>
                        <span
                          style={{
                            color: isHighCpu ? "#ff0055" : "var(--accent-cyan)",
                            fontWeight: isHighCpu ? "800" : "600",
                            fontFamily: "var(--font-mono)"
                          }}
                        >
                          {cpuVal.toFixed(1)}%
                        </span>
                      </td>

                      <td style={{ padding: "0.8rem" }}>
                        <span
                          style={{
                            color: isHighMem ? "#ffaa00" : "var(--text-main)",
                            fontWeight: isHighMem ? "800" : "600",
                            fontFamily: "var(--font-mono)"
                          }}
                        >
                          {memVal.toFixed(1)}%
                        </span>
                      </td>

                      <td style={{ padding: "0.8rem" }}>
                        <span style={{ background: "rgba(0, 240, 255, 0.08)", color: "var(--accent-cyan)", padding: "0.2rem 0.5rem", borderRadius: "4px", fontSize: "0.75rem", fontWeight: "600" }}>
                          🖥️ {deviceName}
                        </span>
                      </td>

                      <td style={{ padding: "0.8rem", color: "var(--text-muted)", fontSize: "0.75rem" }}>
                        {proc.started_at ? new Date(proc.started_at).toLocaleString() : proc.start_time || "N/A"}
                      </td>

                      <td style={{ padding: "0.8rem", textAlign: "right" }}>
                        <div style={{ display: "flex", gap: "0.3rem", justifyContent: "flex-end", flexWrap: "wrap" }}>
                          <button
                            onClick={() => handleAction("TERMINATE_PROCESS")}
                            title="Terminate Process"
                            style={{
                              background: "rgba(255, 0, 85, 0.15)",
                              color: "#ff0055",
                              border: "1px solid rgba(255, 0, 85, 0.3)",
                              padding: "0.25rem 0.5rem",
                              borderRadius: "4px",
                              fontSize: "0.72rem",
                              fontWeight: "600",
                              cursor: "pointer"
                            }}
                          >
                            🛑 Terminate
                          </button>

                          <button
                            onClick={() => handleAction("SUSPEND_PROCESS")}
                            title="Suspend Process"
                            style={{
                              background: "rgba(255, 170, 0, 0.15)",
                              color: "#ffaa00",
                              border: "1px solid rgba(255, 170, 0, 0.3)",
                              padding: "0.25rem 0.5rem",
                              borderRadius: "4px",
                              fontSize: "0.72rem",
                              fontWeight: "600",
                              cursor: "pointer"
                            }}
                          >
                            ⏸️ Suspend
                          </button>

                          <button
                            onClick={() => handleAction("MARK_TRUSTED")}
                            title="Mark as Trusted"
                            style={{
                              background: "rgba(0, 240, 255, 0.15)",
                              color: "var(--accent-cyan)",
                              border: "1px solid rgba(0, 240, 255, 0.3)",
                              padding: "0.25rem 0.5rem",
                              borderRadius: "4px",
                              fontSize: "0.72rem",
                              fontWeight: "600",
                              cursor: "pointer"
                            }}
                          >
                            🛡️ Trust
                          </button>

                          <button
                            onClick={() => handleAction("ADD_ALLOWLIST")}
                            title="Add to Allowlist"
                            style={{
                              background: "rgba(168, 85, 247, 0.15)",
                              color: "#a855f7",
                              border: "1px solid rgba(168, 85, 247, 0.3)",
                              padding: "0.25rem 0.5rem",
                              borderRadius: "4px",
                              fontSize: "0.72rem",
                              fontWeight: "600",
                              cursor: "pointer"
                            }}
                          >
                            📋 Allowlist
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )
        ) : (
          /* Process Audit & History Table */
          isLoading && auditLogs.length === 0 ? (
            <div style={{ padding: "3rem", textAlign: "center", color: "#a855f7" }}>
              Loading process audit event history...
            </div>
          ) : filteredAuditLogs.length === 0 ? (
            <div style={{ padding: "3rem", textAlign: "center", color: "var(--text-muted)" }}>
              No audit log entries match the selected filter criteria.
            </div>
          ) : (
            <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left", fontSize: "0.85rem" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.1)", color: "var(--text-muted)", textTransform: "uppercase", fontSize: "0.75rem", letterSpacing: "0.5px" }}>
                  <th style={{ padding: "0.8rem" }}>Timestamp</th>
                  <th style={{ padding: "0.8rem" }}>Event Type</th>
                  <th style={{ padding: "0.8rem" }}>Process Name</th>
                  <th style={{ padding: "0.8rem" }}>PID</th>
                  <th style={{ padding: "0.8rem" }}>Device</th>
                  <th style={{ padding: "0.8rem" }}>Audit Details</th>
                </tr>
              </thead>
              <tbody>
                {filteredAuditLogs.map((log) => {
                  const deviceName = deviceMap[log.device_id] || log.device_id.substring(0, 8);

                  let badgeBg = "rgba(255, 255, 255, 0.08)";
                  let badgeColor = "var(--text-main)";

                  if (log.event_type === "PROCESS_STARTED") {
                    badgeBg = "rgba(0, 240, 255, 0.15)";
                    badgeColor = "var(--accent-cyan)";
                  } else if (log.event_type === "PROCESS_TERMINATED") {
                    badgeBg = "rgba(255, 0, 85, 0.15)";
                    badgeColor = "#ff0055";
                  } else if (log.event_type === "DETECTION_FOUND") {
                    badgeBg = "rgba(255, 170, 0, 0.15)";
                    badgeColor = "#ffaa00";
                  } else if (log.event_type === "RESPONSE_ACTION") {
                    badgeBg = "rgba(168, 85, 247, 0.15)";
                    badgeColor = "#a855f7";
                  }

                  return (
                    <tr key={log.id} style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.05)" }}>
                      <td style={{ padding: "0.8rem", color: "var(--text-muted)", fontSize: "0.75rem", fontFamily: "var(--font-mono)" }}>
                        {new Date(log.timestamp).toLocaleString()}
                      </td>

                      <td style={{ padding: "0.8rem" }}>
                        <span style={{ background: badgeBg, color: badgeColor, padding: "0.25rem 0.6rem", borderRadius: "4px", fontSize: "0.72rem", fontWeight: "700" }}>
                          {log.event_type}
                        </span>
                      </td>

                      <td style={{ padding: "0.8rem", fontWeight: "600", color: "var(--text-main)" }}>
                        {log.process_name}
                      </td>

                      <td style={{ padding: "0.8rem", fontFamily: "var(--font-mono)", color: "var(--accent-cyan)" }}>
                        {log.pid}
                        {log.ppid && <span style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}> (PPID: {log.ppid})</span>}
                      </td>

                      <td style={{ padding: "0.8rem" }}>
                        <span style={{ background: "rgba(0, 240, 255, 0.08)", color: "var(--accent-cyan)", padding: "0.2rem 0.5rem", borderRadius: "4px", fontSize: "0.75rem", fontWeight: "600" }}>
                          🖥️ {deviceName}
                        </span>
                      </td>

                      <td style={{ padding: "0.8rem", color: "var(--text-main)", fontSize: "0.8rem" }}>
                        {log.details || "N/A"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )
        )}
      </div>
    </div>
  );
};

export default ProcessDashboard;
