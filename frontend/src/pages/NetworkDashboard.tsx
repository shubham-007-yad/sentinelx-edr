import React, { useState, useEffect, useMemo } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { WebSocketStatusBadge } from "../components/WebSocketStatusBadge";
import { NotificationCenter } from "../components/NotificationCenter";
import { networkService, type NetworkConnection, type NetworkCorrelatedPivot, type NetworkTimelineItem } from "../services/network";
import { api } from "../services/api";

interface DeviceOption {
  id: string;
  hostname: string;
  ip_address?: string;
  status?: string;
}

export const NetworkDashboard: React.FC = () => {
  const { user, logout } = useAuth();

  const [connections, setConnections] = useState<NetworkConnection[]>([]);
  const [devices, setDevices] = useState<DeviceOption[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters State
  const [selectedDevice, setSelectedDevice] = useState<string>("");
  const [filterProcess, setFilterProcess] = useState<string>("");
  const [filterProtocol, setFilterProtocol] = useState<string>("");
  const [filterPort, setFilterPort] = useState<string>("");
  const [filterState, setFilterState] = useState<string>("");
  const [searchTerm, setSearchTerm] = useState<string>("");

  // Pivot Investigation Modal State
  const [selectedPivot, setSelectedPivot] = useState<NetworkCorrelatedPivot | null>(null);
  const [timelineItems, setTimelineItems] = useState<NetworkTimelineItem[]>([]);
  const [actionMessage, setActionMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  const fetchNetworkTelemetry = async () => {
    try {
      setIsLoading(true);
      setError(null);

      // Fetch connections and devices in parallel
      const [connsData, devicesRes] = await Promise.all([
        networkService.getNetworkConnections(),
        api.get<DeviceOption[]>("/devices").catch(() => ({ data: [] as DeviceOption[] }))
      ]);

      setConnections(connsData);
      setDevices(devicesRes.data || []);
    } catch (err: any) {
      console.error("Failed to load network connection telemetry:", err);
      setError(err.response?.data?.detail || "Failed to load network connections.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchNetworkTelemetry();
    const interval = setInterval(fetchNetworkTelemetry, 5000);
    return () => clearInterval(interval);
  }, []);

  const formatBytes = (bytes: number): string => {
    if (!bytes || bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
  };

  const isExternalIP = (ip?: string): boolean => {
    if (!ip || ip === "0.0.0.0" || ip === "127.0.0.1" || ip === "::1") return false;
    // Simple check for internal RFC1918 ranges
    if (ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("127.") || ip.startsWith("169.254.")) {
      return false;
    }
    if (ip.startsWith("172.")) {
      const parts = ip.split(".");
      if (parts.length > 1) {
        const second = parseInt(parts[1], 10);
        if (second >= 16 && second <= 31) return false;
      }
    }
    return true;
  };

  // Compute 5 Required Metrics Cards
  const metrics = useMemo(() => {
    const active = connections.length;
    let external = 0;
    let internal = 0;
    let suspicious = 0;
    let blocked = 0;

    connections.forEach((conn) => {
      if (isExternalIP(conn.remote_ip)) {
        external++;
      } else {
        internal++;
      }

      if (conn.threat_id || conn.alert_id) {
        suspicious++;
      }

      if (conn.state === "CLOSE_WAIT" || conn.state === "CLOSE" || conn.state === "CLOSED" || (conn as any).is_blocked) {
        blocked++;
      }
    });

    return { active, external, internal, suspicious, blocked };
  }, [connections]);

  // Filtered Connections List
  const filteredConnections = useMemo(() => {
    return connections.filter((conn) => {
      // Device filter
      if (selectedDevice && conn.device_id !== selectedDevice) return false;

      // Process filter
      if (filterProcess && !conn.process_name?.toLowerCase().includes(filterProcess.toLowerCase())) {
        return false;
      }

      // Protocol filter
      if (filterProtocol && conn.protocol?.toUpperCase() !== filterProtocol.toUpperCase()) {
        return false;
      }

      // Port filter
      if (filterPort) {
        const pNum = parseInt(filterPort, 10);
        if (conn.local_port !== pNum && conn.remote_port !== pNum) {
          return false;
        }
      }

      // State filter
      if (filterState && conn.state?.toUpperCase() !== filterState.toUpperCase()) {
        return false;
      }

      // Free Search
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        const procName = conn.process_name?.toLowerCase() || "";
        const localIp = conn.local_ip?.toLowerCase() || "";
        const remoteIp = conn.remote_ip?.toLowerCase() || "";
        const pidStr = conn.pid ? String(conn.pid) : "";
        const stateStr = conn.state?.toLowerCase() || "";

        if (
          !procName.includes(term) &&
          !localIp.includes(term) &&
          !remoteIp.includes(term) &&
          !pidStr.includes(term) &&
          !stateStr.includes(term)
        ) {
          return false;
        }
      }

      return true;
    });
  }, [connections, selectedDevice, filterProcess, filterProtocol, filterPort, filterState, searchTerm]);

  // Handle Analyst Pivot Modal
  const handleOpenPivot = async (connectionId: string) => {
    try {
      setActionMessage(null);
      setTimelineItems([]);
      const [pivotData, timelineRes] = await Promise.all([
        networkService.getCorrelatedConnection(connectionId),
        networkService.getConnectionTimeline(connectionId).catch(() => ({ timeline: [] }))
      ]);
      setSelectedPivot(pivotData);
      setTimelineItems(timelineRes.timeline || []);
    } catch (err: any) {
      console.error("Failed to load correlated pivot data:", err);
      setActionMessage({ type: "error", text: "Failed to load 360° correlated telemetry." });
    }
  };

  const handleTerminateProcess = async (deviceId: string, pid?: number, processName?: string) => {
    if (!pid) return;
    try {
      setActionMessage(null);
      await api.post("/responses", {
        device_id: deviceId,
        action_type: "TERMINATE_PROCESS",
        parameters: { pid, process_name: processName }
      });
      setActionMessage({ type: "success", text: `Triggered process termination for PID ${pid} (${processName}).` });
      fetchNetworkTelemetry();
    } catch (err: any) {
      setActionMessage({ type: "error", text: err.response?.data?.detail || "Failed to trigger process termination." });
    }
  };

  const handleIsolateDevice = async (deviceId: string) => {
    try {
      setActionMessage(null);
      await api.post(`/devices/${deviceId}/isolate`);
      setActionMessage({ type: "success", text: "Endpoint device network isolation initiated." });
      fetchNetworkTelemetry();
    } catch (err: any) {
      setActionMessage({ type: "error", text: err.response?.data?.detail || "Failed to isolate device." });
    }
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
              EDR CONSOLE v1.0.0
            </span>
            <WebSocketStatusBadge />
          </div>

          <nav style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap" }}>
            <Link to="/dashboard" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>
              Dashboard Overview
            </Link>
            <Link to="/threats" style={{ color: "#ff0055", background: "rgba(255, 0, 85, 0.1)", border: "1px solid rgba(255, 0, 85, 0.3)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>
              Threat Dashboard
            </Link>
            <Link to="/alerts" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>
              Alerts
            </Link>
            <Link to="/respond" style={{ color: "#00f0ff", background: "rgba(0, 240, 255, 0.1)", border: "1px solid rgba(0, 240, 255, 0.3)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>
              Response Console
            </Link>
            <Link to="/processes" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>
              Process Inventory
            </Link>
            <Link to="/network" style={{ color: "var(--accent-cyan)", background: "rgba(0, 240, 255, 0.15)", border: "1px solid rgba(0, 240, 255, 0.5)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "700", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>
              Network Monitoring
            </Link>
            <Link to="/usb-activity" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>
              USB Activity
            </Link>
            <Link to="/usb-scans" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>
              USB Scan Results
            </Link>
          </nav>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
          <NotificationCenter />
          <button onClick={logout} className="btn" style={{ background: "rgba(255, 255, 255, 0.05)", border: "1px solid rgba(255, 255, 255, 0.1)", color: "var(--text-muted)", padding: "0.35rem 0.8rem", fontSize: "0.85rem", borderRadius: "6px", cursor: "pointer" }}>
            Logout ({user?.username})
          </button>
        </div>
      </header>

      {/* Page Title & Subhead */}
      <div style={{ marginBottom: "1.5rem" }}>
        <h1 style={{ fontSize: "1.8rem", fontWeight: "800", margin: 0, display: "flex", alignItems: "center", gap: "0.6rem" }}>
          <span style={{ color: "var(--accent-cyan)" }}>🌐 Network Monitoring</span> & Connection Analysis
        </h1>
        <p style={{ color: "var(--text-muted)", margin: "0.3rem 0 0 0", fontSize: "0.9rem" }}>
          Real-time endpoint socket monitoring, process-to-network correlation, behavioral threat detection, and analyst response pivot.
        </p>
      </div>

      {/* 5 Key Metric Summary Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "1rem", marginBottom: "1.5rem" }}>
        {/* Metric 1: Active Connections */}
        <div className="glass-panel" style={{ padding: "1.2rem", borderLeft: "4px solid var(--accent-cyan)" }}>
          <div style={{ color: "var(--text-muted)", fontSize: "0.8rem", fontWeight: "600", textTransform: "uppercase", letterSpacing: "0.5px" }}>
            Active Connections
          </div>
          <div style={{ fontSize: "2rem", fontWeight: "800", color: "var(--accent-cyan)", margin: "0.4rem 0 0 0" }}>
            {metrics.active}
          </div>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.2rem" }}>
            Total socket inventory
          </div>
        </div>

        {/* Metric 2: External Connections */}
        <div className="glass-panel" style={{ padding: "1.2rem", borderLeft: "4px solid #b026ff" }}>
          <div style={{ color: "var(--text-muted)", fontSize: "0.8rem", fontWeight: "600", textTransform: "uppercase", letterSpacing: "0.5px" }}>
            External Connections
          </div>
          <div style={{ fontSize: "2rem", fontWeight: "800", color: "#b026ff", margin: "0.4rem 0 0 0" }}>
            {metrics.external}
          </div>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.2rem" }}>
            Public Internet destinations
          </div>
        </div>

        {/* Metric 3: Internal Connections */}
        <div className="glass-panel" style={{ padding: "1.2rem", borderLeft: "4px solid #00aaff" }}>
          <div style={{ color: "var(--text-muted)", fontSize: "0.8rem", fontWeight: "600", textTransform: "uppercase", letterSpacing: "0.5px" }}>
            Internal Connections
          </div>
          <div style={{ fontSize: "2rem", fontWeight: "800", color: "#00aaff", margin: "0.4rem 0 0 0" }}>
            {metrics.internal}
          </div>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.2rem" }}>
            Local & LAN bindings
          </div>
        </div>

        {/* Metric 4: Suspicious Connections */}
        <div className="glass-panel" style={{ padding: "1.2rem", borderLeft: "4px solid #ff0055" }}>
          <div style={{ color: "var(--text-muted)", fontSize: "0.8rem", fontWeight: "600", textTransform: "uppercase", letterSpacing: "0.5px" }}>
            Suspicious Connections
          </div>
          <div style={{ fontSize: "2rem", fontWeight: "800", color: "#ff0055", margin: "0.4rem 0 0 0" }}>
            {metrics.suspicious}
          </div>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.2rem" }}>
            Flagged threat sockets
          </div>
        </div>

        {/* Metric 5: Blocked Connections */}
        <div className="glass-panel" style={{ padding: "1.2rem", borderLeft: "4px solid #ffaa00" }}>
          <div style={{ color: "var(--text-muted)", fontSize: "0.8rem", fontWeight: "600", textTransform: "uppercase", letterSpacing: "0.5px" }}>
            Blocked Connections
          </div>
          <div style={{ fontSize: "2rem", fontWeight: "800", color: "#ffaa00", margin: "0.4rem 0 0 0" }}>
            {metrics.blocked}
          </div>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.2rem" }}>
            Terminated / closed sockets
          </div>
        </div>
      </div>

      {/* Filter Control Bar */}
      <div className="glass-panel" style={{ padding: "1rem 1.5rem", marginBottom: "1.5rem", display: "flex", gap: "1rem", flexWrap: "wrap", alignItems: "center" }}>
        {/* Device Filter */}
        <div style={{ display: "flex", flexDirection: "column", gap: "0.3rem" }}>
          <label style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: "600" }}>Device Endpoint</label>
          <select
            value={selectedDevice}
            onChange={(e) => setSelectedDevice(e.target.value)}
            style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.15)", color: "var(--text-main)", padding: "0.4rem 0.8rem", borderRadius: "6px", fontSize: "0.85rem", minWidth: "160px" }}
          >
            <option value="">All Managed Devices</option>
            {devices.map((dev) => (
              <option key={dev.id} value={dev.id}>
                {dev.hostname} ({dev.ip_address || "No IP"})
              </option>
            ))}
          </select>
        </div>

        {/* Process Filter */}
        <div style={{ display: "flex", flexDirection: "column", gap: "0.3rem" }}>
          <label style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: "600" }}>Process Name</label>
          <input
            type="text"
            placeholder="e.g. powershell.exe"
            value={filterProcess}
            onChange={(e) => setFilterProcess(e.target.value)}
            style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.15)", color: "var(--text-main)", padding: "0.4rem 0.8rem", borderRadius: "6px", fontSize: "0.85rem", width: "150px" }}
          />
        </div>

        {/* Protocol Filter */}
        <div style={{ display: "flex", flexDirection: "column", gap: "0.3rem" }}>
          <label style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: "600" }}>Protocol</label>
          <select
            value={filterProtocol}
            onChange={(e) => setFilterProtocol(e.target.value)}
            style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.15)", color: "var(--text-main)", padding: "0.4rem 0.8rem", borderRadius: "6px", fontSize: "0.85rem" }}
          >
            <option value="">All Protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
          </select>
        </div>

        {/* Port Filter */}
        <div style={{ display: "flex", flexDirection: "column", gap: "0.3rem" }}>
          <label style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: "600" }}>Port Number</label>
          <input
            type="text"
            placeholder="e.g. 4444"
            value={filterPort}
            onChange={(e) => setFilterPort(e.target.value)}
            style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.15)", color: "var(--text-main)", padding: "0.4rem 0.8rem", borderRadius: "6px", fontSize: "0.85rem", width: "100px" }}
          />
        </div>

        {/* State Filter */}
        <div style={{ display: "flex", flexDirection: "column", gap: "0.3rem" }}>
          <label style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: "600" }}>Socket State</label>
          <select
            value={filterState}
            onChange={(e) => setFilterState(e.target.value)}
            style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.15)", color: "var(--text-main)", padding: "0.4rem 0.8rem", borderRadius: "6px", fontSize: "0.85rem" }}
          >
            <option value="">All States</option>
            <option value="ESTABLISHED">ESTABLISHED</option>
            <option value="LISTEN">LISTEN</option>
            <option value="SYN_SENT">SYN_SENT</option>
            <option value="CLOSE_WAIT">CLOSE_WAIT</option>
            <option value="TIME_WAIT">TIME_WAIT</option>
            <option value="NONE">NONE</option>
          </select>
        </div>

        {/* Search Input */}
        <div style={{ display: "flex", flexDirection: "column", gap: "0.3rem", flexGrow: 1 }}>
          <label style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: "600" }}>Search Telemetry</label>
          <input
            type="text"
            placeholder="Search process, IP address, PID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.15)", color: "var(--text-main)", padding: "0.4rem 0.8rem", borderRadius: "6px", fontSize: "0.85rem", width: "100%" }}
          />
        </div>

        {/* Refresh & Reset Buttons */}
        <div style={{ display: "flex", gap: "0.5rem", marginTop: "auto" }}>
          <button
            onClick={fetchNetworkTelemetry}
            className="btn"
            style={{ background: "rgba(0, 240, 255, 0.1)", border: "1px solid rgba(0, 240, 255, 0.3)", color: "var(--accent-cyan)", padding: "0.45rem 0.9rem", borderRadius: "6px", fontSize: "0.85rem", cursor: "pointer" }}
          >
            Refresh
          </button>
          <button
            onClick={() => {
              setSelectedDevice("");
              setFilterProcess("");
              setFilterProtocol("");
              setFilterPort("");
              setFilterState("");
              setSearchTerm("");
            }}
            className="btn"
            style={{ background: "rgba(255, 255, 255, 0.05)", border: "1px solid rgba(255, 255, 255, 0.1)", color: "var(--text-muted)", padding: "0.45rem 0.9rem", borderRadius: "6px", fontSize: "0.85rem", cursor: "pointer" }}
          >
            Clear Filters
          </button>
        </div>
      </div>

      {/* Network Connections Telemetry Table */}
      <div className="glass-panel" style={{ padding: "1.5rem" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
          <h3 style={{ margin: 0, fontSize: "1.1rem", fontWeight: "700" }}>
            Live Network Socket Telemetry ({filteredConnections.length} Sockets)
          </h3>
        </div>

        {isLoading && connections.length === 0 ? (
          <div style={{ textAlign: "center", padding: "3rem", color: "var(--accent-cyan)" }}>
            Harvesting active network connection telemetry...
          </div>
        ) : error ? (
          <div style={{ padding: "1rem", background: "rgba(255,0,85,0.1)", border: "1px solid rgba(255,0,85,0.3)", color: "#ff0055", borderRadius: "6px" }}>
            {error}
          </div>
        ) : filteredConnections.length === 0 ? (
          <div style={{ textAlign: "center", padding: "3rem", color: "var(--text-muted)" }}>
            No active network connections found matching specified filter criteria.
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.85rem", textAlign: "left" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.1)", color: "var(--text-muted)" }}>
                  <th style={{ padding: "0.8rem 0.6rem" }}>Process</th>
                  <th style={{ padding: "0.8rem 0.6rem" }}>PID</th>
                  <th style={{ padding: "0.8rem 0.6rem" }}>Local Address</th>
                  <th style={{ padding: "0.8rem 0.6rem" }}>Remote Address</th>
                  <th style={{ padding: "0.8rem 0.6rem" }}>Protocol</th>
                  <th style={{ padding: "0.8rem 0.6rem" }}>State</th>
                  <th style={{ padding: "0.8rem 0.6rem" }}>Bytes Sent</th>
                  <th style={{ padding: "0.8rem 0.6rem" }}>Bytes Recv</th>
                  <th style={{ padding: "0.8rem 0.6rem" }}>Device</th>
                  <th style={{ padding: "0.8rem 0.6rem" }}>Time</th>
                  <th style={{ padding: "0.8rem 0.6rem", textAlign: "right" }}>Investigation Pivot</th>
                </tr>
              </thead>
              <tbody>
                {filteredConnections.map((conn) => {
                  const isExt = isExternalIP(conn.remote_ip);
                  const isThreat = Boolean(conn.threat_id || conn.alert_id);
                  const devObj = devices.find((d) => d.id === conn.device_id);

                  return (
                    <tr
                      key={conn.id}
                      style={{
                        borderBottom: "1px solid rgba(255,255,255,0.05)",
                        background: isThreat ? "rgba(255, 0, 85, 0.05)" : "transparent"
                      }}
                    >
                      {/* 1. Process Column */}
                      <td style={{ padding: "0.8rem 0.6rem", fontWeight: "600" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                          <span style={{ fontSize: "1rem" }}>⚡</span>
                          <div>
                            <div>{conn.process_name || "unknown"}</div>
                            {conn.executable_path && (
                              <div style={{ fontSize: "0.7rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)", maxWidth: "180px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={conn.executable_path}>
                                {conn.executable_path}
                              </div>
                            )}
                          </div>
                        </div>
                      </td>

                      {/* 2. PID Column */}
                      <td style={{ padding: "0.8rem 0.6rem", fontFamily: "var(--font-mono)" }}>
                        <span style={{ background: "rgba(255,255,255,0.05)", padding: "0.2rem 0.4rem", borderRadius: "4px" }}>
                          {conn.pid || "N/A"}
                        </span>
                      </td>

                      {/* 3. Local Address */}
                      <td style={{ padding: "0.8rem 0.6rem", fontFamily: "var(--font-mono)" }}>
                        {conn.local_ip || "0.0.0.0"}:{conn.local_port || "*"}
                      </td>

                      {/* 4. Remote Address */}
                      <td style={{ padding: "0.8rem 0.6rem", fontFamily: "var(--font-mono)" }}>
                        {conn.remote_ip ? (
                          <span style={{ color: isExt ? "#b026ff" : "var(--text-main)", fontWeight: isExt ? "700" : "normal" }}>
                            {conn.remote_ip}:{conn.remote_port || "*"} {isExt && "🌐"}
                          </span>
                        ) : (
                          <span style={{ color: "var(--text-muted)" }}>*</span>
                        )}
                      </td>

                      {/* 5. Protocol */}
                      <td style={{ padding: "0.8rem 0.6rem" }}>
                        <span
                          style={{
                            background: conn.protocol === "TCP" ? "rgba(0, 240, 255, 0.1)" : "rgba(255, 170, 0, 0.1)",
                            color: conn.protocol === "TCP" ? "var(--accent-cyan)" : "#ffaa00",
                            border: `1px solid ${conn.protocol === "TCP" ? "rgba(0, 240, 255, 0.3)" : "rgba(255, 170, 0, 0.3)"}`,
                            padding: "0.15rem 0.4rem",
                            borderRadius: "4px",
                            fontSize: "0.75rem",
                            fontWeight: "700"
                          }}
                        >
                          {conn.protocol}
                        </span>
                      </td>

                      {/* 6. State */}
                      <td style={{ padding: "0.8rem 0.6rem" }}>
                        <span
                          style={{
                            background:
                              conn.state === "ESTABLISHED" ? "rgba(0, 255, 136, 0.1)" :
                              conn.state === "LISTEN" ? "rgba(0, 170, 255, 0.1)" : "rgba(255, 255, 255, 0.05)",
                            color:
                              conn.state === "ESTABLISHED" ? "#00ff88" :
                              conn.state === "LISTEN" ? "#00aaff" : "var(--text-muted)",
                            padding: "0.15rem 0.4rem",
                            borderRadius: "4px",
                            fontSize: "0.75rem",
                            fontWeight: "600"
                          }}
                        >
                          {conn.state || "NONE"}
                        </span>
                      </td>

                      {/* 7. Bytes Sent */}
                      <td style={{ padding: "0.8rem 0.6rem", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
                        {formatBytes(conn.bytes_sent)}
                      </td>

                      {/* 8. Bytes Received */}
                      <td style={{ padding: "0.8rem 0.6rem", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
                        {formatBytes(conn.bytes_received)}
                      </td>

                      {/* 9. Device */}
                      <td style={{ padding: "0.8rem 0.6rem" }}>
                        <div>{devObj?.hostname || conn.device_id.slice(0, 8)}</div>
                        <div style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>{devObj?.ip_address || ""}</div>
                      </td>

                      {/* 10. Time */}
                      <td style={{ padding: "0.8rem 0.6rem", color: "var(--text-muted)", fontSize: "0.75rem" }}>
                        {new Date(conn.created_at).toLocaleTimeString()}
                      </td>

                      {/* Pivot Action */}
                      <td style={{ padding: "0.8rem 0.6rem", textAlign: "right" }}>
                        <button
                          onClick={() => handleOpenPivot(conn.id)}
                          className="btn"
                          style={{
                            background: isThreat ? "rgba(255, 0, 85, 0.2)" : "rgba(0, 240, 255, 0.1)",
                            border: `1px solid ${isThreat ? "rgba(255, 0, 85, 0.5)" : "rgba(0, 240, 255, 0.3)"}`,
                            color: isThreat ? "#ff0055" : "var(--accent-cyan)",
                            padding: "0.3rem 0.6rem",
                            borderRadius: "4px",
                            fontSize: "0.75rem",
                            fontWeight: "700",
                            cursor: "pointer"
                          }}
                        >
                          360° Pivot {isThreat ? "🚨" : "🔍"}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* 360° Correlated Analyst Pivot Modal */}
      {selectedPivot && (
        <div
          style={{
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
            padding: "1.5rem"
          }}
        >
          <div
            className="glass-panel"
            style={{
              width: "100%",
              maxWidth: "800px",
              maxHeight: "90vh",
              overflowY: "auto",
              padding: "2rem",
              border: "1px solid rgba(0, 240, 255, 0.4)",
              boxShadow: "0 0 30px rgba(0, 240, 255, 0.15)"
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem", borderBottom: "1px solid rgba(255,255,255,0.1)", paddingBottom: "0.8rem" }}>
              <h2 style={{ margin: 0, fontSize: "1.3rem", color: "var(--accent-cyan)", display: "flex", alignItems: "center", gap: "0.5rem" }}>
                <span>🔍 360° Analyst Correlation & Pivot</span>
              </h2>
              <button
                onClick={() => setSelectedPivot(null)}
                style={{ background: "none", border: "none", color: "var(--text-muted)", fontSize: "1.4rem", cursor: "pointer" }}
              >
                ✕
              </button>
            </div>

            {actionMessage && (
              <div
                style={{
                  padding: "0.8rem 1rem",
                  marginBottom: "1rem",
                  borderRadius: "6px",
                  fontSize: "0.85rem",
                  background: actionMessage.type === "success" ? "rgba(0, 255, 136, 0.1)" : "rgba(255, 0, 85, 0.1)",
                  border: `1px solid ${actionMessage.type === "success" ? "rgba(0, 255, 136, 0.3)" : "rgba(255, 0, 85, 0.3)"}`,
                  color: actionMessage.type === "success" ? "#00ff88" : "#ff0055"
                }}
              >
                {actionMessage.text}
              </div>
            )}

            {/* Pivot Correlation Grid */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem", marginBottom: "1.5rem" }}>
              {/* Box 1: Endpoint Device */}
              <div style={{ background: "rgba(0,0,0,0.3)", padding: "1rem", borderRadius: "8px", border: "1px solid rgba(255,255,255,0.05)" }}>
                <h4 style={{ margin: "0 0 0.5rem 0", color: "var(--accent-cyan)", fontSize: "0.9rem" }}>🖥️ Endpoint Device</h4>
                <div style={{ fontSize: "0.8rem", display: "flex", flexDirection: "column", gap: "0.3rem" }}>
                  <div><strong>Hostname:</strong> {selectedPivot.device_hostname || "N/A"}</div>
                  <div><strong>IP Address:</strong> {selectedPivot.device_ip || "N/A"}</div>
                  <div><strong>Device ID:</strong> {selectedPivot.device_id}</div>
                  <div><strong>Status:</strong> {selectedPivot.device_status || "ONLINE"}</div>
                </div>
              </div>

              {/* Box 2: Socket Telemetry */}
              <div style={{ background: "rgba(0,0,0,0.3)", padding: "1rem", borderRadius: "8px", border: "1px solid rgba(255,255,255,0.05)" }}>
                <h4 style={{ margin: "0 0 0.5rem 0", color: "var(--accent-cyan)", fontSize: "0.9rem" }}>🌐 Network Socket</h4>
                <div style={{ fontSize: "0.8rem", display: "flex", flexDirection: "column", gap: "0.3rem", fontFamily: "var(--font-mono)" }}>
                  <div><strong>Local:</strong> {selectedPivot.local_ip}:{selectedPivot.local_port}</div>
                  <div><strong>Remote:</strong> {selectedPivot.remote_ip}:{selectedPivot.remote_port}</div>
                  <div><strong>Protocol / State:</strong> {selectedPivot.protocol} ({selectedPivot.state})</div>
                </div>
              </div>

              {/* Box 3: Process Lineage */}
              <div style={{ background: "rgba(0,0,0,0.3)", padding: "1rem", borderRadius: "8px", border: "1px solid rgba(255,255,255,0.05)", gridColumn: "1 / -1" }}>
                <h4 style={{ margin: "0 0 0.5rem 0", color: "var(--accent-cyan)", fontSize: "0.9rem" }}>⚡ Process Telemetry & Lineage</h4>
                <div style={{ fontSize: "0.8rem", display: "flex", flexDirection: "column", gap: "0.4rem" }}>
                  <div><strong>Process:</strong> {selectedPivot.process_name || "N/A"} (PID {selectedPivot.pid || "N/A"} | PPID {selectedPivot.ppid || "N/A"})</div>
                  <div><strong>User:</strong> {selectedPivot.username || "N/A"}</div>
                  <div><strong>Executable:</strong> <span style={{ fontFamily: "var(--font-mono)" }}>{selectedPivot.executable_path || "N/A"}</span></div>
                  <div><strong>Command Line:</strong> <span style={{ fontFamily: "var(--font-mono)", color: "var(--accent-cyan)" }}>{selectedPivot.cmdline || "N/A"}</span></div>
                </div>
              </div>

              {/* Box 4: Threat & Alert Correlation */}
              {selectedPivot.threat_id && (
                <div style={{ background: "rgba(255, 0, 85, 0.08)", padding: "1rem", borderRadius: "8px", border: "1px solid rgba(255, 0, 85, 0.3)", gridColumn: "1 / -1" }}>
                  <h4 style={{ margin: "0 0 0.5rem 0", color: "#ff0055", fontSize: "0.9rem" }}>🚨 Threat & Alert Findings</h4>
                  <div style={{ fontSize: "0.8rem", display: "flex", flexDirection: "column", gap: "0.3rem" }}>
                    <div><strong>Rule:</strong> {selectedPivot.rule_name}</div>
                    <div><strong>Severity:</strong> <span style={{ color: "#ff0055", fontWeight: "700" }}>{selectedPivot.threat_severity}</span></div>
                    <div><strong>Threat Type:</strong> {selectedPivot.threat_type}</div>
                    <div><strong>Description:</strong> {selectedPivot.threat_description}</div>
                  </div>
                </div>
              )}

              {/* Box 5: Phase 7 Connection Investigation Timeline */}
              {timelineItems.length > 0 && (
                <div style={{ background: "rgba(0,0,0,0.3)", padding: "1rem", borderRadius: "8px", border: "1px solid rgba(0,240,255,0.2)", gridColumn: "1 / -1" }}>
                  <h4 style={{ margin: "0 0 1rem 0", color: "var(--accent-cyan)", fontSize: "0.95rem", display: "flex", alignItems: "center", gap: "0.5rem" }}>
                    <span>📅 Connection Investigation Timeline</span>
                  </h4>
                  <div style={{ display: "flex", flexDirection: "column", gap: "0.8rem", position: "relative", paddingLeft: "1.5rem", borderLeft: "2px dashed rgba(0,240,255,0.3)" }}>
                    {timelineItems.map((item, idx) => (
                      <div key={idx} style={{ position: "relative", display: "flex", flexDirection: "column", gap: "0.2rem" }}>
                        {/* Timeline Step Bullet */}
                        <div
                          style={{
                            position: "absolute",
                            left: "-2.15rem",
                            top: "0.1rem",
                            width: "22px",
                            height: "22px",
                            borderRadius: "50%",
                            background: "var(--bg-primary)",
                            border: `2px solid ${item.severity === "CRITICAL" || item.severity === "HIGH" ? "#ff0055" : "var(--accent-cyan)"}`,
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            fontSize: "0.65rem"
                          }}
                        >
                          {item.icon}
                        </div>

                        {/* Timeline Step Details */}
                        <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
                          <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.75rem", color: "var(--accent-cyan)", fontWeight: "700" }}>
                            {item.time_formatted}
                          </span>
                          <span style={{ fontSize: "0.85rem", fontWeight: "700", color: item.severity === "CRITICAL" || item.severity === "HIGH" ? "#ff0055" : "var(--text-main)" }}>
                            {item.title}
                          </span>
                        </div>
                        <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                          {item.description}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Analyst Response Action Buttons */}
            <div style={{ display: "flex", gap: "0.8rem", justifyContent: "flex-end", borderTop: "1px solid rgba(255,255,255,0.1)", paddingTop: "1rem" }}>
              {selectedPivot.pid && (
                <button
                  onClick={() => handleTerminateProcess(selectedPivot.device_id, selectedPivot.pid, selectedPivot.process_name)}
                  className="btn"
                  style={{ background: "#ff0055", border: "none", color: "#fff", padding: "0.5rem 1rem", borderRadius: "6px", fontSize: "0.85rem", fontWeight: "700", cursor: "pointer" }}
                >
                  ⚡ Kill Process (PID {selectedPivot.pid})
                </button>
              )}
              <button
                onClick={() => handleIsolateDevice(selectedPivot.device_id)}
                className="btn"
                style={{ background: "#ffaa00", border: "none", color: "#000", padding: "0.5rem 1rem", borderRadius: "6px", fontSize: "0.85rem", fontWeight: "700", cursor: "pointer" }}
              >
                🔒 Isolate Endpoint
              </button>
              <button
                onClick={() => setSelectedPivot(null)}
                className="btn"
                style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)", color: "var(--text-muted)", padding: "0.5rem 1rem", borderRadius: "6px", fontSize: "0.85rem", cursor: "pointer" }}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
