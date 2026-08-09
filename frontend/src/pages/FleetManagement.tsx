import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { WebSocketStatusBadge } from "../components/WebSocketStatusBadge";
import { NotificationCenter } from "../components/NotificationCenter";
import { fleetService } from "../services/fleet";
import type {
  FleetMetrics, FleetDevice, DeviceStatus, HealthStatus,
  AgentCommand, AgentCommandType, AgentCommandAuditLog, AgentDiagnosticPackage,
  AgentUpgradeRecord
} from "../types/fleet";

export const FleetManagement: React.FC = () => {
  const { logout } = useAuth();

  const [metrics, setMetrics] = useState<FleetMetrics>({
    total_agents: 0,
    online: 0,
    offline: 0,
    outdated: 0,
    unhealthy: 0,
  });

  const [devices, setDevices] = useState<FleetDevice[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Phase 4 Filter States: OS, Version, Status, Policy, Search
  const [search, setSearch] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [osFilter, setOsFilter] = useState<string>("");
  const [versionFilter, setVersionFilter] = useState<string>("");
  const [policyFilter, setPolicyFilter] = useState<string>("");

  // Phase 5 Selection & Bulk Operations State
  const [selectedDeviceIds, setSelectedDeviceIds] = useState<string[]>([]);
  const [bulkActionNotice, setBulkActionNotice] = useState<string | null>(null);
  const [isBulkProcessing, setIsBulkProcessing] = useState<boolean>(false);

  // Push Policy Modal State
  const [showPolicyModal, setShowPolicyModal] = useState<boolean>(false);
  const [policyVersionInput, setPolicyVersionInput] = useState<string>("3.2");

  // Single Remote Command Center Modal & Audit Drawer State
  const [selectedDevice, setSelectedDevice] = useState<FleetDevice | null>(null);
  const [commandType, setCommandType] = useState<AgentCommandType>("START_SCAN");
  const [commandPayload, setCommandPayload] = useState<string>("{}");
  const [issuingCommand, setIssuingCommand] = useState<boolean>(false);
  const [commandNotice, setCommandNotice] = useState<string | null>(null);

  // Phase 6 Diagnostics Modal State
  const [showDiagnosticsModal, setShowDiagnosticsModal] = useState<boolean>(false);
  const [diagDevice, setDiagDevice] = useState<FleetDevice | null>(null);
  const [diagPackage, setDiagPackage] = useState<AgentDiagnosticPackage | null>(null);
  const [loadingDiag, setLoadingDiag] = useState<boolean>(false);

  // Phase 7 Upgrade Framework Modal State
  const [showUpgradeModal, setShowUpgradeModal] = useState<boolean>(false);
  const [upgradeTargetVersion, setUpgradeTargetVersion] = useState<string>("1.2.0");
  const [activeUpgradeRecord, setActiveUpgradeRecord] = useState<AgentUpgradeRecord | null>(null);
  const [upgradeHistory, setUpgradeHistory] = useState<AgentUpgradeRecord[]>([]);
  const [showUpgradeHistoryModal, setShowUpgradeHistoryModal] = useState<boolean>(false);
  const [loadingUpgrade, setLoadingUpgrade] = useState<boolean>(false);

  // Audit Logs State
  const [showAuditDrawer, setShowAuditDrawer] = useState<boolean>(false);
  const [auditLogs, setAuditLogs] = useState<AgentCommandAuditLog[]>([]);
  const [commandHistory, setCommandHistory] = useState<AgentCommand[]>([]);
  const [loadingAudits, setLoadingAudits] = useState<boolean>(false);

  const fetchFleetData = async () => {
    setLoading(true);
    setError(null);
    try {
      const metricsData = await fleetService.getMetrics();
      setMetrics(metricsData);

      const devicesData = await fleetService.getDevices({
        search: search || undefined,
        status: statusFilter || undefined,
        os_type: osFilter || undefined,
        version: versionFilter || undefined,
        policy: policyFilter ? parseInt(policyFilter, 10) : undefined,
      });
      setDevices(devicesData);
      setSelectedDeviceIds((prev) => prev.filter((id) => devicesData.some((d) => d.id === id)));
    } catch (err: any) {
      console.error("Failed to fetch fleet data:", err);
      setError(err.response?.data?.detail || "Failed to connect to Fleet Management backend.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFleetData();
  }, [search, statusFilter, osFilter, versionFilter, policyFilter]);

  // Bulk Operations Handlers
  const handleSelectAll = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.checked) {
      setSelectedDeviceIds(devices.map((d) => d.id));
    } else {
      setSelectedDeviceIds([]);
    }
  };

  const handleToggleSelectDevice = (id: string) => {
    setSelectedDeviceIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  const handleBulkRestart = async () => {
    if (selectedDeviceIds.length === 0) return;
    setIsBulkProcessing(true);
    setBulkActionNotice(null);
    try {
      const cmds = await fleetService.dispatchBatchCommand(selectedDeviceIds, "RESTART_AGENT");
      setBulkActionNotice(`Successfully queued restart command on ${cmds.length} devices.`);
      await fetchFleetData();
    } catch (err: any) {
      setBulkActionNotice(`Bulk restart failed: ${err.response?.data?.detail || err.message}`);
    } finally {
      setIsBulkProcessing(false);
    }
  };

  const handleBulkStartScan = async () => {
    if (selectedDeviceIds.length === 0) return;
    setIsBulkProcessing(true);
    setBulkActionNotice(null);
    try {
      const cmds = await fleetService.dispatchBatchCommand(selectedDeviceIds, "START_SCAN");
      setBulkActionNotice(`Successfully triggered on-demand threat scan on ${cmds.length} devices.`);
      await fetchFleetData();
    } catch (err: any) {
      setBulkActionNotice(`Bulk scan trigger failed: ${err.response?.data?.detail || err.message}`);
    } finally {
      setIsBulkProcessing(false);
    }
  };

  const handleBulkPushPolicy = async () => {
    if (selectedDeviceIds.length === 0) return;
    setIsBulkProcessing(true);
    setBulkActionNotice(null);
    try {
      const verNum = parseFloat(policyVersionInput) || 3;
      const cmds = await fleetService.dispatchBatchCommand(selectedDeviceIds, "REFRESH_POLICY", {
        policy_version: verNum,
        policy_label: `v${policyVersionInput}`
      });
      setBulkActionNotice(`${cmds.length} devices updated with Policy v${policyVersionInput}`);
      setShowPolicyModal(false);
      await fetchFleetData();
    } catch (err: any) {
      setBulkActionNotice(`Bulk policy push failed: ${err.response?.data?.detail || err.message}`);
    } finally {
      setIsBulkProcessing(false);
    }
  };

  const handleBulkExportInventory = async () => {
    try {
      await fleetService.exportInventory(selectedDeviceIds.length > 0 ? selectedDeviceIds : undefined);
      setBulkActionNotice(`Fleet inventory CSV exported successfully.`);
    } catch (err: any) {
      console.error("Export failed:", err);
      setBulkActionNotice(`Export failed: ${err.message}`);
    }
  };

  const handleEvaluateHealth = async () => {
    try {
      const result = await fleetService.evaluateHealth();
      setBulkActionNotice(`Health evaluated across fleet: ${result.evaluated_devices} agents checked, ${result.health_alerts_generated} alerts generated.`);
      await fetchFleetData();
    } catch (err: any) {
      console.error("Failed to evaluate fleet health:", err);
    }
  };

  // Phase 7 Upgrade Framework Handlers
  const handleOpenUpgradeModal = async (targetDevIds?: string[]) => {
    const idsToUpgrade = targetDevIds || selectedDeviceIds;
    if (idsToUpgrade.length === 0) return;

    setLoadingUpgrade(true);
    setShowUpgradeModal(true);
    try {
      const records = await fleetService.triggerUpgrade(idsToUpgrade, upgradeTargetVersion);
      if (records.length > 0) {
        setActiveUpgradeRecord(records[0]);
      }
    } catch (err: any) {
      console.error("Failed to trigger upgrade:", err);
    } finally {
      setLoadingUpgrade(false);
    }
  };

  const handleAdvanceUpgradeStep = async () => {
    if (!activeUpgradeRecord) return;
    setLoadingUpgrade(true);
    try {
      const updated = await fleetService.advanceUpgradeStep(activeUpgradeRecord.id);
      setActiveUpgradeRecord(updated);
      if (updated.status === "SUCCESS") {
        await fetchFleetData();
      }
    } catch (err: any) {
      console.error("Advance upgrade failed:", err);
    } finally {
      setLoadingUpgrade(false);
    }
  };

  const handleRollbackUpgrade = async () => {
    if (!activeUpgradeRecord) return;
    setLoadingUpgrade(true);
    try {
      const rolledBack = await fleetService.rollbackUpgrade(activeUpgradeRecord.id);
      setActiveUpgradeRecord(rolledBack);
      await fetchFleetData();
    } catch (err: any) {
      console.error("Rollback failed:", err);
    } finally {
      setLoadingUpgrade(false);
    }
  };

  const fetchUpgradeHistory = async () => {
    try {
      const history = await fleetService.getUpgradeHistory();
      setUpgradeHistory(history);
      setShowUpgradeHistoryModal(true);
    } catch (err) {
      console.error("Failed to fetch upgrade history:", err);
    }
  };

  const handleOpenCommandModal = (dev: FleetDevice) => {
    setSelectedDevice(dev);
    setCommandNotice(null);
    setCommandType("START_SCAN");
    setCommandPayload("{}");
  };

  const handleOpenDiagnosticsModal = async (dev: FleetDevice) => {
    setDiagDevice(dev);
    setShowDiagnosticsModal(true);
    setLoadingDiag(true);
    try {
      const pkg = await fleetService.getDiagnostics(dev.id);
      setDiagPackage(pkg);
    } catch (err) {
      console.error("Failed to fetch diagnostics:", err);
    } finally {
      setLoadingDiag(false);
    }
  };

  const handleDownloadDiagnostics = async () => {
    if (!diagDevice) return;
    try {
      await fleetService.downloadDiagnostics(diagDevice.id);
    } catch (err) {
      console.error("Download diagnostics failed:", err);
    }
  };

  const handleIssueCommand = async () => {
    if (!selectedDevice) return;
    setIssuingCommand(true);
    setCommandNotice(null);

    let parsedPayload = {};
    try {
      if (commandPayload.trim()) {
        parsedPayload = JSON.parse(commandPayload);
      }
    } catch {
      setCommandNotice("Invalid JSON payload. Please provide valid JSON.");
      setIssuingCommand(false);
      return;
    }

    try {
      const cmd = await fleetService.queueCommand(selectedDevice.id, commandType, parsedPayload);
      setCommandNotice(`Command '${cmd.command_type}' queued successfully (ID: ${cmd.id.slice(0, 8)}...). State: QUEUED -> DISPATCHED.`);
      await fetchFleetData();
    } catch (err: any) {
      console.error("Failed to issue command:", err);
      setCommandNotice(`Error issuing command: ${err.response?.data?.detail || err.message}`);
    } finally {
      setIssuingCommand(false);
    }
  };

  const fetchAuditLogsAndHistory = async () => {
    setLoadingAudits(true);
    try {
      const logs = await fleetService.getCommandAuditLogs(selectedDevice?.id);
      const hist = await fleetService.getCommandHistory(selectedDevice?.id);
      setAuditLogs(logs);
      setCommandHistory(hist);
      setShowAuditDrawer(true);
    } catch (err) {
      console.error("Failed to fetch audit logs:", err);
    } finally {
      setLoadingAudits(false);
    }
  };

  const getStatusBadgeStyle = (status: DeviceStatus) => {
    switch (status) {
      case "ONLINE":
        return { background: "rgba(16, 185, 129, 0.15)", color: "#10b981", border: "1px solid rgba(16, 185, 129, 0.3)" };
      case "OFFLINE":
        return { background: "rgba(148, 163, 184, 0.15)", color: "#94a3b8", border: "1px solid rgba(148, 163, 184, 0.3)" };
      case "ISOLATED":
        return { background: "rgba(239, 68, 68, 0.15)", color: "#ef4444", border: "1px solid rgba(239, 68, 68, 0.3)" };
      case "OUTDATED":
        return { background: "rgba(245, 158, 11, 0.15)", color: "#f59e0b", border: "1px solid rgba(245, 158, 11, 0.3)" };
      case "UNHEALTHY":
        return { background: "rgba(225, 29, 72, 0.15)", color: "#e11d48", border: "1px solid rgba(225, 29, 72, 0.3)" };
      default:
        return { background: "rgba(148, 163, 184, 0.1)", color: "#cbd5e1", border: "1px solid rgba(148, 163, 184, 0.2)" };
    }
  };

  const getHealthBadgeStyle = (health: HealthStatus) => {
    switch (health) {
      case "HEALTHY":
        return { background: "rgba(16, 185, 129, 0.15)", color: "#10b981", border: "1px solid rgba(16, 185, 129, 0.3)" };
      case "WARNING":
        return { background: "rgba(245, 158, 11, 0.15)", color: "#f59e0b", border: "1px solid rgba(245, 158, 11, 0.3)" };
      case "DEGRADED":
      case "UNHEALTHY":
        return { background: "rgba(225, 29, 72, 0.15)", color: "#e11d48", border: "1px solid rgba(225, 29, 72, 0.3)" };
      case "OUTDATED":
        return { background: "rgba(217, 119, 6, 0.15)", color: "#d97706", border: "1px solid rgba(217, 119, 6, 0.3)" };
      default:
        return { background: "rgba(148, 163, 184, 0.1)", color: "#cbd5e1", border: "1px solid rgba(148, 163, 184, 0.2)" };
    }
  };

  const formatDateTime = (dtStr?: string | null) => {
    if (!dtStr) return "Never";
    try {
      const d = new Date(dtStr);
      return d.toLocaleString();
    } catch {
      return dtStr;
    }
  };

  const allSelected = devices.length > 0 && selectedDeviceIds.length === devices.length;

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg-primary)", color: "var(--text-main)", padding: "2rem" }}>
      {/* Navigation Header */}
      <header className="glass-panel" style={{ position: "relative", zIndex: 100, display: "flex", justifyContent: "space-between", alignItems: "center", gap: "1rem", padding: "0.8rem 1.5rem", marginBottom: "2rem", flexWrap: "wrap" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "1.5rem", flexWrap: "wrap" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.8rem", flexShrink: 0 }}>
            <div style={{ fontSize: "1.4rem", fontWeight: "800", color: "var(--accent-cyan)", letterSpacing: "1px" }}>
              SENTINEL<span style={{ color: "var(--text-main)" }}>X</span>
            </div>
            <span style={{ background: "rgba(0, 240, 255, 0.1)", color: "var(--accent-cyan)", padding: "0.2rem 0.5rem", borderRadius: "4px", fontSize: "0.7rem", fontFamily: "var(--font-mono)", whiteSpace: "nowrap" }}>
              FLEET DASHBOARD
            </span>
            <WebSocketStatusBadge />
          </div>

          <nav style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap" }}>
            <Link to="/dashboard" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>Overview</Link>
            <Link to="/threats" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>Threats</Link>
            <Link to="/fleet" style={{ color: "var(--accent-cyan)", background: "rgba(0, 240, 255, 0.1)", border: "1px solid rgba(0, 240, 255, 0.3)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>Agent Fleet</Link>
            <Link to="/policies" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>Policies</Link>
            <Link to="/events" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>Events</Link>
            <Link to="/ransomware" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>Response</Link>
          </nav>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
          <NotificationCenter />
          <button onClick={logout} style={{ background: "rgba(255,0,85,0.1)", border: "1px solid rgba(255,0,85,0.3)", color: "#ff0055", padding: "0.4rem 0.8rem", borderRadius: "6px", cursor: "cursor", fontSize: "0.8rem", fontWeight: "600" }}>Logout</button>
        </div>
      </header>

      {/* Main Fleet Container */}
      <main style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
        <div>
          <h1 style={{ fontSize: "1.8rem", fontWeight: "700", color: "#fff", marginBottom: "0.3rem" }}>
            🖥️ Fleet Management & Remote Administration
          </h1>
          <p style={{ color: "var(--text-muted)", fontSize: "0.9rem" }}>
            Real-time agent inventory, operational health telemetry, multi-device bulk operations, agent upgrade framework, and remote policy distribution.
          </p>
        </div>

        {/* 5 KPI Summary Cards */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "1rem" }}>
          <div className="glass-panel" style={{ padding: "1.2rem", borderRadius: "10px", borderLeft: "4px solid var(--accent-cyan)" }}>
            <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: "600" }}>Total Agents</div>
            <div style={{ fontSize: "2rem", fontWeight: "800", color: "#fff", marginTop: "0.4rem" }}>{metrics.total_agents}</div>
          </div>
          <div className="glass-panel" style={{ padding: "1.2rem", borderRadius: "10px", borderLeft: "4px solid #10b981" }}>
            <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: "600" }}>Online</div>
            <div style={{ fontSize: "2rem", fontWeight: "800", color: "#10b981", marginTop: "0.4rem" }}>{metrics.online}</div>
          </div>
          <div className="glass-panel" style={{ padding: "1.2rem", borderRadius: "10px", borderLeft: "4px solid #94a3b8" }}>
            <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: "600" }}>Offline</div>
            <div style={{ fontSize: "2rem", fontWeight: "800", color: "#94a3b8", marginTop: "0.4rem" }}>{metrics.offline}</div>
          </div>
          <div className="glass-panel" style={{ padding: "1.2rem", borderRadius: "10px", borderLeft: "4px solid #f59e0b" }}>
            <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: "600" }}>Outdated</div>
            <div style={{ fontSize: "2rem", fontWeight: "800", color: "#f59e0b", marginTop: "0.4rem" }}>{metrics.outdated}</div>
          </div>
          <div className="glass-panel" style={{ padding: "1.2rem", borderRadius: "10px", borderLeft: "4px solid #e11d48" }}>
            <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: "600" }}>Unhealthy</div>
            <div style={{ fontSize: "2rem", fontWeight: "800", color: "#e11d48", marginTop: "0.4rem" }}>{metrics.unhealthy}</div>
          </div>
        </div>

        {/* Phase 5 & 7 Sticky Bulk Operations & Upgrade Toolbar */}
        {selectedDeviceIds.length > 0 && (
          <div className="glass-panel" style={{ background: "rgba(0, 240, 255, 0.1)", border: "1px solid rgba(0, 240, 255, 0.4)", padding: "0.9rem 1.4rem", borderRadius: "10px", display: "flex", justifyContent: "space-between", alignItems: "center", gap: "1rem", flexWrap: "wrap" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "0.8rem" }}>
              <span style={{ fontSize: "1rem", fontWeight: "800", color: "var(--accent-cyan)" }}>
                ⚡ {selectedDeviceIds.length} Devices Selected
              </span>
              <button
                onClick={() => setSelectedDeviceIds([])}
                style={{ background: "none", border: "none", color: "var(--text-muted)", fontSize: "0.8rem", cursor: "pointer", textDecoration: "underline" }}
              >
                Clear Selection
              </button>
            </div>

            <div style={{ display: "flex", gap: "0.8rem", flexWrap: "wrap" }}>
              <button
                onClick={() => handleOpenUpgradeModal()}
                disabled={isBulkProcessing}
                style={{ background: "rgba(168, 85, 247, 0.25)", border: "1px solid #a855f7", color: "#a855f7", padding: "0.45rem 0.9rem", borderRadius: "6px", fontSize: "0.85rem", fontWeight: "700", cursor: "pointer" }}
              >
                🚀 Upgrade Agents (v{upgradeTargetVersion})
              </button>

              <button
                onClick={handleBulkRestart}
                disabled={isBulkProcessing}
                style={{ background: "rgba(245, 158, 11, 0.2)", border: "1px solid rgba(245, 158, 11, 0.5)", color: "#f59e0b", padding: "0.45rem 0.9rem", borderRadius: "6px", fontSize: "0.85rem", fontWeight: "700", cursor: "pointer" }}
              >
                🔄 Restart Selected
              </button>

              <button
                onClick={() => setShowPolicyModal(true)}
                disabled={isBulkProcessing}
                style={{ background: "rgba(16, 185, 129, 0.2)", border: "1px solid rgba(16, 185, 129, 0.5)", color: "#10b981", padding: "0.45rem 0.9rem", borderRadius: "6px", fontSize: "0.85rem", fontWeight: "700", cursor: "pointer" }}
              >
                📋 Push Policy
              </button>

              <button
                onClick={handleBulkStartScan}
                disabled={isBulkProcessing}
                style={{ background: "rgba(0, 240, 255, 0.2)", border: "1px solid rgba(0, 240, 255, 0.5)", color: "var(--accent-cyan)", padding: "0.45rem 0.9rem", borderRadius: "6px", fontSize: "0.85rem", fontWeight: "700", cursor: "pointer" }}
              >
                🔍 Start Scan
              </button>

              <button
                onClick={handleBulkExportInventory}
                style={{ background: "rgba(255, 255, 255, 0.1)", border: "1px solid rgba(255, 255, 255, 0.2)", color: "#fff", padding: "0.45rem 0.9rem", borderRadius: "6px", fontSize: "0.85rem", fontWeight: "700", cursor: "pointer" }}
              >
                📊 Export CSV
              </button>
            </div>
          </div>
        )}

        {/* Action Notice Banner */}
        {bulkActionNotice && (
          <div style={{ background: "rgba(16, 185, 129, 0.15)", border: "1px solid rgba(16, 185, 129, 0.4)", color: "#10b981", padding: "0.9rem 1.2rem", borderRadius: "8px", fontSize: "0.9rem", fontWeight: "600", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span>✅ {bulkActionNotice}</span>
            <button onClick={() => setBulkActionNotice(null)} style={{ background: "none", border: "none", color: "#10b981", cursor: "pointer", fontWeight: "700" }}>✕</button>
          </div>
        )}

        {/* Phase 4 Filters Toolbar: OS, Version, Status, Policy, Search */}
        <div className="glass-panel" style={{ padding: "1rem 1.2rem", borderRadius: "10px", display: "flex", gap: "1rem", flexWrap: "wrap", alignItems: "center", justifyContent: "space-between" }}>
          <div style={{ display: "flex", gap: "0.8rem", flexWrap: "wrap", alignItems: "center", flex: 1 }}>
            {/* Search Filter */}
            <input
              type="text"
              placeholder="Search Hostname, IP, MAC..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              style={{
                background: "rgba(0,0,0,0.3)",
                border: "1px solid rgba(255,255,255,0.1)",
                color: "#fff",
                padding: "0.5rem 0.9rem",
                borderRadius: "6px",
                fontSize: "0.85rem",
                minWidth: "220px"
              }}
            />

            {/* OS Filter */}
            <select
              value={osFilter}
              onChange={(e) => setOsFilter(e.target.value)}
              style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.1)", color: "#fff", padding: "0.5rem 0.8rem", borderRadius: "6px", fontSize: "0.85rem" }}
            >
              <option value="">Filter by OS (All)</option>
              <option value="WINDOWS">WINDOWS</option>
              <option value="LINUX">LINUX</option>
              <option value="MACOS">MACOS</option>
              <option value="OTHER">OTHER</option>
            </select>

            {/* Version Filter */}
            <select
              value={versionFilter}
              onChange={(e) => setVersionFilter(e.target.value)}
              style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.1)", color: "#fff", padding: "0.5rem 0.8rem", borderRadius: "6px", fontSize: "0.85rem" }}
            >
              <option value="">Filter by Version (All)</option>
              <option value="1.2.0">v1.2.0 (Target)</option>
              <option value="1.0.0">v1.0.0 (Baseline)</option>
              <option value="0.9.8">v0.9.8</option>
              <option value="0.9.0">v0.9.0</option>
            </select>

            {/* Status Filter */}
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.1)", color: "#fff", padding: "0.5rem 0.8rem", borderRadius: "6px", fontSize: "0.85rem" }}
            >
              <option value="">Filter by Status (All)</option>
              <option value="ONLINE">ONLINE</option>
              <option value="OFFLINE">OFFLINE</option>
              <option value="ISOLATED">ISOLATED</option>
              <option value="OUTDATED">OUTDATED</option>
              <option value="UNHEALTHY">UNHEALTHY</option>
            </select>

            {/* Policy Filter */}
            <select
              value={policyFilter}
              onChange={(e) => setPolicyFilter(e.target.value)}
              style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.1)", color: "#fff", padding: "0.5rem 0.8rem", borderRadius: "6px", fontSize: "0.85rem" }}
            >
              <option value="">Filter by Policy (All)</option>
              <option value="1">Policy v1</option>
              <option value="2">Policy v2</option>
              <option value="3">Policy v3 (Strict Baseline)</option>
            </select>
          </div>

          <div style={{ display: "flex", gap: "0.8rem" }}>
            <button
              onClick={handleEvaluateHealth}
              style={{
                background: "rgba(225, 29, 72, 0.15)",
                border: "1px solid rgba(225, 29, 72, 0.4)",
                color: "#e11d48",
                padding: "0.5rem 1rem",
                borderRadius: "6px",
                fontSize: "0.85rem",
                fontWeight: "600",
                cursor: "pointer"
              }}
            >
              🩺 Refresh Health
            </button>

            <button
              onClick={fetchUpgradeHistory}
              style={{
                background: "rgba(168, 85, 247, 0.15)",
                border: "1px solid rgba(168, 85, 247, 0.4)",
                color: "#a855f7",
                padding: "0.5rem 1rem",
                borderRadius: "6px",
                fontSize: "0.85rem",
                fontWeight: "600",
                cursor: "pointer"
              }}
            >
              🚀 Upgrade History
            </button>

            <button
              onClick={handleBulkExportInventory}
              style={{
                background: "rgba(255, 255, 255, 0.1)",
                border: "1px solid rgba(255, 255, 255, 0.2)",
                color: "#fff",
                padding: "0.5rem 1rem",
                borderRadius: "6px",
                fontSize: "0.85rem",
                fontWeight: "600",
                cursor: "pointer"
              }}
            >
              📊 Export Inventory
            </button>

            <button
              onClick={fetchAuditLogsAndHistory}
              style={{
                background: "rgba(0, 240, 255, 0.15)",
                border: "1px solid rgba(0, 240, 255, 0.4)",
                color: "var(--accent-cyan)",
                padding: "0.5rem 1rem",
                borderRadius: "6px",
                fontSize: "0.85rem",
                fontWeight: "600",
                cursor: "pointer"
              }}
            >
              📜 Audit Logs
            </button>
          </div>
        </div>

        {/* Error Banner */}
        {error && (
          <div style={{ background: "rgba(239,68,68,0.15)", border: "1px solid rgba(239,68,68,0.4)", color: "#ef4444", padding: "1rem", borderRadius: "8px", fontSize: "0.9rem" }}>
            {error}
          </div>
        )}

        {/* Fleet Table */}
        <div className="glass-panel" style={{ borderRadius: "10px", padding: "1.2rem", overflowX: "auto" }}>
          <h2 style={{ fontSize: "1.1rem", fontWeight: "700", color: "#fff", marginBottom: "1rem" }}>
            Fleet Inventory & Operational Telemetry ({devices.length})
          </h2>

          {loading ? (
            <div style={{ textAlign: "center", padding: "2rem", color: "var(--text-muted)" }}>
              Loading Fleet Devices & Health Telemetry...
            </div>
          ) : devices.length === 0 ? (
            <div style={{ textAlign: "center", padding: "2rem", color: "var(--text-muted)" }}>
              No managed agents found matching criteria.
            </div>
          ) : (
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.85rem", textAlign: "left" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.1)", color: "var(--text-muted)" }}>
                  <th style={{ padding: "0.8rem", width: "40px" }}>
                    <input
                      type="checkbox"
                      checked={allSelected}
                      onChange={handleSelectAll}
                      style={{ cursor: "pointer" }}
                    />
                  </th>
                  <th style={{ padding: "0.8rem" }}>Hostname</th>
                  <th style={{ padding: "0.8rem" }}>Device</th>
                  <th style={{ padding: "0.8rem" }}>OS</th>
                  <th style={{ padding: "0.8rem" }}>Agent Version</th>
                  <th style={{ padding: "0.8rem" }}>Policy Version</th>
                  <th style={{ padding: "0.8rem" }}>Status</th>
                  <th style={{ padding: "0.8rem" }}>Last Seen</th>
                  <th style={{ padding: "0.8rem" }}>Health</th>
                  <th style={{ padding: "0.8rem" }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {devices.map((dev) => {
                  const isChecked = selectedDeviceIds.includes(dev.id);
                  return (
                    <tr
                      key={dev.id}
                      style={{
                        borderBottom: "1px solid rgba(255,255,255,0.05)",
                        background: isChecked ? "rgba(0, 240, 255, 0.05)" : "transparent"
                      }}
                    >
                      <td style={{ padding: "0.8rem" }}>
                        <input
                          type="checkbox"
                          checked={isChecked}
                          onChange={() => handleToggleSelectDevice(dev.id)}
                          style={{ cursor: "pointer" }}
                        />
                      </td>
                      <td style={{ padding: "0.8rem", fontWeight: "600", color: "#fff" }}>
                        {dev.hostname}
                      </td>
                      <td style={{ padding: "0.8rem", fontFamily: "var(--font-mono)", color: "var(--accent-cyan)" }}>
                        {dev.ip_address || dev.mac_address || dev.id.slice(0, 8)}
                      </td>
                      <td style={{ padding: "0.8rem" }}>
                        {dev.operating_system || dev.os_type}
                      </td>
                      <td style={{ padding: "0.8rem", fontFamily: "var(--font-mono)", color: dev.agent_version === upgradeTargetVersion ? "#10b981" : "#f59e0b" }}>
                        v{dev.agent_version || "1.0.0"}
                      </td>
                      <td style={{ padding: "0.8rem", fontFamily: "var(--font-mono)" }}>
                        v{dev.policy_version ?? dev.applied_policy_version ?? 1}
                      </td>
                      <td style={{ padding: "0.8rem" }}>
                        <span style={{ padding: "0.25rem 0.5rem", borderRadius: "4px", fontSize: "0.75rem", fontWeight: "700", ...getStatusBadgeStyle(dev.status) }}>
                          {dev.status}
                        </span>
                      </td>
                      <td style={{ padding: "0.8rem", color: "var(--text-muted)" }}>
                        {formatDateTime(dev.last_seen || dev.last_heartbeat || dev.last_checkin)}
                      </td>
                      <td style={{ padding: "0.8rem" }}>
                        <span style={{ padding: "0.25rem 0.5rem", borderRadius: "4px", fontSize: "0.75rem", fontWeight: "700", ...getHealthBadgeStyle(dev.health_status) }}>
                          {dev.health_status}
                        </span>
                      </td>
                      <td style={{ padding: "0.8rem", display: "flex", gap: "0.4rem" }}>
                        <button
                          onClick={() => handleOpenUpgradeModal([dev.id])}
                          style={{
                            background: "rgba(168, 85, 247, 0.15)",
                            border: "1px solid rgba(168, 85, 247, 0.4)",
                            color: "#a855f7",
                            padding: "0.3rem 0.6rem",
                            borderRadius: "4px",
                            fontSize: "0.75rem",
                            fontWeight: "600",
                            cursor: "pointer"
                          }}
                        >
                          🚀 Upgrade
                        </button>

                        <button
                          onClick={() => handleOpenCommandModal(dev)}
                          style={{
                            background: "rgba(0, 240, 255, 0.15)",
                            border: "1px solid rgba(0, 240, 255, 0.4)",
                            color: "var(--accent-cyan)",
                            padding: "0.3rem 0.6rem",
                            borderRadius: "4px",
                            fontSize: "0.75rem",
                            fontWeight: "600",
                            cursor: "pointer"
                          }}
                        >
                          ⚡ Command
                        </button>
                        <button
                          onClick={() => handleOpenDiagnosticsModal(dev)}
                          style={{
                            background: "rgba(255, 255, 255, 0.1)",
                            border: "1px solid rgba(255, 255, 255, 0.2)",
                            color: "#fff",
                            padding: "0.3rem 0.6rem",
                            borderRadius: "4px",
                            fontSize: "0.75rem",
                            fontWeight: "600",
                            cursor: "pointer"
                          }}
                        >
                          🩺 Diag
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* Phase 7 Agent Upgrade Framework Pipeline Modal */}
        {showUpgradeModal && activeUpgradeRecord && (
          <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.8)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 240, padding: "1.5rem" }}>
            <div className="glass-panel" style={{ width: "100%", maxWidth: "680px", borderRadius: "12px", padding: "1.8rem", background: "var(--bg-card)", border: "1px solid rgba(168, 85, 247, 0.4)" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.2rem" }}>
                <div>
                  <h3 style={{ fontSize: "1.3rem", fontWeight: "700", color: "#fff" }}>
                    🚀 Agent Upgrade Pipeline ➔ <span style={{ color: "#a855f7" }}>v{activeUpgradeRecord.target_version}</span>
                  </h3>
                  <div style={{ display: "flex", gap: "0.5rem", alignItems: "center", marginTop: "0.2rem" }}>
                    <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
                      Current Version: v{activeUpgradeRecord.current_version} ➔ Target:
                    </span>
                    <select
                      value={upgradeTargetVersion}
                      onChange={(e) => setUpgradeTargetVersion(e.target.value)}
                      style={{ background: "rgba(0,0,0,0.4)", border: "1px solid rgba(168,85,247,0.4)", color: "#a855f7", padding: "0.2rem 0.5rem", borderRadius: "4px", fontSize: "0.75rem", fontWeight: "700" }}
                    >
                      <option value="1.2.0">v1.2.0 (Stable)</option>
                      <option value="1.3.0">v1.3.0 (Beta)</option>
                    </select>
                  </div>
                </div>
                <button onClick={() => setShowUpgradeModal(false)} style={{ background: "none", border: "none", color: "#888", fontSize: "1.3rem", cursor: "pointer" }}>✕</button>
              </div>

              {/* Step Pipeline Flow Indicator */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: "0.4rem", marginBottom: "1.5rem", textAlign: "center" }}>
                <div style={{ background: activeUpgradeRecord.progress_percent >= 0 ? "rgba(168, 85, 247, 0.25)" : "rgba(255,255,255,0.05)", padding: "0.6rem 0.3rem", borderRadius: "6px", border: activeUpgradeRecord.progress_percent >= 0 ? "1px solid #a855f7" : "1px solid transparent" }}>
                  <div style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>Step 1</div>
                  <div style={{ fontSize: "0.75rem", fontWeight: "700", color: activeUpgradeRecord.progress_percent >= 0 ? "#a855f7" : "#888" }}>Available</div>
                </div>
                <div style={{ background: activeUpgradeRecord.progress_percent >= 25 ? "rgba(0, 240, 255, 0.25)" : "rgba(255,255,255,0.05)", padding: "0.6rem 0.3rem", borderRadius: "6px", border: activeUpgradeRecord.progress_percent >= 25 ? "1px solid var(--accent-cyan)" : "1px solid transparent" }}>
                  <div style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>Step 2</div>
                  <div style={{ fontSize: "0.75rem", fontWeight: "700", color: activeUpgradeRecord.progress_percent >= 25 ? "var(--accent-cyan)" : "#888" }}>Download</div>
                </div>
                <div style={{ background: activeUpgradeRecord.progress_percent >= 65 ? "rgba(245, 158, 11, 0.25)" : "rgba(255,255,255,0.05)", padding: "0.6rem 0.3rem", borderRadius: "6px", border: activeUpgradeRecord.progress_percent >= 65 ? "1px solid #f59e0b" : "1px solid transparent" }}>
                  <div style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>Step 3</div>
                  <div style={{ fontSize: "0.75rem", fontWeight: "700", color: activeUpgradeRecord.progress_percent >= 65 ? "#f59e0b" : "#888" }}>Install</div>
                </div>
                <div style={{ background: activeUpgradeRecord.progress_percent >= 90 ? "rgba(225, 29, 72, 0.25)" : "rgba(255,255,255,0.05)", padding: "0.6rem 0.3rem", borderRadius: "6px", border: activeUpgradeRecord.progress_percent >= 90 ? "1px solid #e11d48" : "1px solid transparent" }}>
                  <div style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>Step 4</div>
                  <div style={{ fontSize: "0.75rem", fontWeight: "700", color: activeUpgradeRecord.progress_percent >= 90 ? "#e11d48" : "#888" }}>Restart</div>
                </div>
                <div style={{ background: activeUpgradeRecord.progress_percent >= 100 ? "rgba(16, 185, 129, 0.25)" : "rgba(255,255,255,0.05)", padding: "0.6rem 0.3rem", borderRadius: "6px", border: activeUpgradeRecord.progress_percent >= 100 ? "1px solid #10b981" : "1px solid transparent" }}>
                  <div style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>Step 5</div>
                  <div style={{ fontSize: "0.75rem", fontWeight: "700", color: activeUpgradeRecord.progress_percent >= 100 ? "#10b981" : "#888" }}>Success</div>
                </div>
              </div>

              {/* Progress Bar */}
              <div style={{ background: "rgba(0,0,0,0.5)", borderRadius: "8px", height: "12px", overflow: "hidden", marginBottom: "1.2rem", border: "1px solid rgba(255,255,255,0.1)" }}>
                <div style={{ background: activeUpgradeRecord.status === "ROLLED_BACK" ? "#ef4444" : activeUpgradeRecord.progress_percent === 100 ? "#10b981" : "#a855f7", width: `${activeUpgradeRecord.progress_percent}%`, height: "100%", transition: "width 0.4s ease" }} />
              </div>

              {/* Live Upgrade Logs */}
              <div style={{ background: "#090d16", padding: "1rem", borderRadius: "6px", fontFamily: "var(--font-mono)", fontSize: "0.78rem", color: "#94a3b8", border: "1px solid rgba(168,85,247,0.3)", maxHeight: "180px", overflowY: "auto", marginBottom: "1.2rem" }}>
                <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{activeUpgradeRecord.logs || "No logs recorded yet."}</pre>
              </div>

              {/* Pipeline Actions */}
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "0.8rem" }}>
                <div style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
                  Status: <strong style={{ color: activeUpgradeRecord.status === "SUCCESS" ? "#10b981" : activeUpgradeRecord.status === "ROLLED_BACK" ? "#ef4444" : "#a855f7" }}>{activeUpgradeRecord.status}</strong>
                  {activeUpgradeRecord.rollback_status !== "NONE" && (
                    <span style={{ marginLeft: "0.8rem" }}>Rollback: <strong style={{ color: "#ef4444" }}>{activeUpgradeRecord.rollback_status}</strong></span>
                  )}
                </div>

                <div style={{ display: "flex", gap: "0.8rem" }}>
                  {activeUpgradeRecord.status !== "SUCCESS" && activeUpgradeRecord.status !== "ROLLED_BACK" && (
                    <>
                      <button
                        onClick={handleRollbackUpgrade}
                        disabled={loadingUpgrade}
                        style={{ background: "rgba(239,68,68,0.2)", border: "1px solid #ef4444", color: "#ef4444", padding: "0.45rem 0.9rem", borderRadius: "6px", fontSize: "0.85rem", fontWeight: "700", cursor: "pointer" }}
                      >
                        ⏪ Rollback to v{activeUpgradeRecord.current_version}
                      </button>

                      <button
                        onClick={handleAdvanceUpgradeStep}
                        disabled={loadingUpgrade}
                        style={{ background: "rgba(168,85,247,0.25)", border: "1px solid #a855f7", color: "#a855f7", padding: "0.45rem 1.1rem", borderRadius: "6px", fontSize: "0.85rem", fontWeight: "700", cursor: "pointer" }}
                      >
                        {loadingUpgrade ? "Advancing..." : "▶ Step Next Stage"}
                      </button>
                    </>
                  )}

                  <button
                    onClick={() => setShowUpgradeModal(false)}
                    style={{ background: "rgba(255,255,255,0.08)", border: "1px solid rgba(255,255,255,0.15)", color: "#fff", padding: "0.45rem 0.9rem", borderRadius: "6px", fontSize: "0.85rem", cursor: "pointer" }}
                  >
                    Close
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Upgrade History Drawer Modal */}
        {showUpgradeHistoryModal && (
          <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.75)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 220, padding: "1rem" }}>
            <div className="glass-panel" style={{ width: "100%", maxWidth: "820px", maxHeight: "85vh", borderRadius: "12px", padding: "1.8rem", background: "var(--bg-card)", overflowY: "auto", border: "1px solid rgba(168,85,247,0.4)" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.2rem" }}>
                <h3 style={{ fontSize: "1.2rem", fontWeight: "700", color: "#fff" }}>
                  🚀 Enterprise Fleet Agent Upgrade History
                </h3>
                <button onClick={() => setShowUpgradeHistoryModal(false)} style={{ background: "none", border: "none", color: "#888", fontSize: "1.2rem", cursor: "pointer" }}>✕</button>
              </div>

              {upgradeHistory.length === 0 ? (
                <div style={{ textAlign: "center", padding: "2rem", color: "var(--text-muted)" }}>
                  No agent upgrade records found in history.
                </div>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8rem", textAlign: "left" }}>
                  <thead>
                    <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.1)", color: "var(--text-muted)" }}>
                      <th style={{ padding: "0.6rem" }}>Device ID</th>
                      <th style={{ padding: "0.6rem" }}>Current Ver</th>
                      <th style={{ padding: "0.6rem" }}>Target Ver</th>
                      <th style={{ padding: "0.6rem" }}>Status</th>
                      <th style={{ padding: "0.6rem" }}>Progress</th>
                      <th style={{ padding: "0.6rem" }}>Rollback</th>
                      <th style={{ padding: "0.6rem" }}>Started At</th>
                    </tr>
                  </thead>
                  <tbody>
                    {upgradeHistory.map((rec) => (
                      <tr key={rec.id} style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                        <td style={{ padding: "0.6rem", fontFamily: "var(--font-mono)", color: "var(--accent-cyan)" }}>{rec.device_id.slice(0, 8)}</td>
                        <td style={{ padding: "0.6rem", fontFamily: "var(--font-mono)" }}>v{rec.current_version}</td>
                        <td style={{ padding: "0.6rem", fontFamily: "var(--font-mono)", color: "#10b981" }}>v{rec.target_version}</td>
                        <td style={{ padding: "0.6rem", fontWeight: "700", color: rec.status === "SUCCESS" ? "#10b981" : rec.status === "ROLLED_BACK" ? "#ef4444" : "#a855f7" }}>{rec.status}</td>
                        <td style={{ padding: "0.6rem", fontFamily: "var(--font-mono)" }}>{rec.progress_percent}%</td>
                        <td style={{ padding: "0.6rem", color: rec.rollback_status === "SUCCESSFUL" ? "#ef4444" : "var(--text-muted)" }}>{rec.rollback_status}</td>
                        <td style={{ padding: "0.6rem", color: "var(--text-muted)" }}>{formatDateTime(rec.started_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        )}

        {/* Phase 6 Diagnostics Package Modal */}
        {showDiagnosticsModal && diagDevice && (
          <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.8)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 230, padding: "1.5rem" }}>
            <div className="glass-panel" style={{ width: "100%", maxWidth: "900px", maxHeight: "88vh", borderRadius: "12px", padding: "1.8rem", background: "var(--bg-card)", overflowY: "auto", border: "1px solid rgba(168, 85, 247, 0.4)" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.2rem" }}>
                <div>
                  <h3 style={{ fontSize: "1.3rem", fontWeight: "700", color: "#fff" }}>
                    🩺 Agent Diagnostic Package ➔ <span style={{ color: "var(--accent-cyan)" }}>{diagDevice.hostname}</span>
                  </h3>
                  <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
                    Diagnostic Package generated for troubleshooting & root-cause analysis
                  </span>
                </div>
                <div style={{ display: "flex", gap: "0.8rem", alignItems: "center" }}>
                  <button
                    onClick={handleDownloadDiagnostics}
                    style={{ background: "rgba(168, 85, 247, 0.2)", border: "1px solid #a855f7", color: "#a855f7", padding: "0.4rem 0.8rem", borderRadius: "6px", fontSize: "0.8rem", fontWeight: "700", cursor: "pointer" }}
                  >
                    📥 Download Bundle (JSON)
                  </button>
                  <button onClick={() => setShowDiagnosticsModal(false)} style={{ background: "none", border: "none", color: "#888", fontSize: "1.3rem", cursor: "pointer" }}>✕</button>
                </div>
              </div>

              {loadingDiag ? (
                <div style={{ textAlign: "center", padding: "3rem", color: "var(--text-muted)" }}>
                  Generating Agent Diagnostic Package...
                </div>
              ) : !diagPackage ? (
                <div style={{ textAlign: "center", padding: "3rem", color: "#ef4444" }}>
                  Failed to load diagnostic package.
                </div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
                  {/* Synchronization Metadata Cards */}
                  <div>
                    <h4 style={{ fontSize: "0.95rem", fontWeight: "700", color: "var(--accent-cyan)", marginBottom: "0.6rem" }}>
                      📡 Synchronization & Heartbeat Timestamps
                    </h4>
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "0.8rem" }}>
                      <div style={{ background: "rgba(0,0,0,0.3)", padding: "0.8rem", borderRadius: "6px", border: "1px solid rgba(255,255,255,0.08)" }}>
                        <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Last Heartbeat</div>
                        <div style={{ fontSize: "0.85rem", fontWeight: "600", color: "#fff", marginTop: "0.2rem" }}>{formatDateTime(diagPackage.synchronization.last_heartbeat)}</div>
                      </div>
                      <div style={{ background: "rgba(0,0,0,0.3)", padding: "0.8rem", borderRadius: "6px", border: "1px solid rgba(255,255,255,0.08)" }}>
                        <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Last Policy Sync</div>
                        <div style={{ fontSize: "0.85rem", fontWeight: "600", color: "#fff", marginTop: "0.2rem" }}>{formatDateTime(diagPackage.synchronization.last_policy_sync)}</div>
                      </div>
                      <div style={{ background: "rgba(0,0,0,0.3)", padding: "0.8rem", borderRadius: "6px", border: "1px solid rgba(255,255,255,0.08)" }}>
                        <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Last Telemetry Upload</div>
                        <div style={{ fontSize: "0.85rem", fontWeight: "600", color: "#fff", marginTop: "0.2rem" }}>{formatDateTime(diagPackage.synchronization.last_telemetry_upload)}</div>
                      </div>
                    </div>
                  </div>

                  {/* Installed Collectors */}
                  <div>
                    <h4 style={{ fontSize: "0.95rem", fontWeight: "700", color: "#10b981", marginBottom: "0.6rem" }}>
                      🧩 Installed Telemetry Collectors
                    </h4>
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: "0.8rem" }}>
                      {diagPackage.installed_collectors.map((c, i) => (
                        <div key={i} style={{ background: "rgba(0,0,0,0.3)", padding: "0.8rem", borderRadius: "6px", border: "1px solid rgba(16,185,129,0.2)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                          <div>
                            <div style={{ fontSize: "0.85rem", fontWeight: "600", color: "#fff" }}>{c.name}</div>
                            <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>{c.events_collected_24h.toLocaleString()} events / 24h</div>
                          </div>
                          <span style={{ padding: "0.2rem 0.5rem", borderRadius: "4px", fontSize: "0.7rem", fontWeight: "700", background: "rgba(16,185,129,0.2)", color: "#10b981" }}>
                            {c.status}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Active Configuration */}
                  <div>
                    <h4 style={{ fontSize: "0.95rem", fontWeight: "700", color: "#f59e0b", marginBottom: "0.6rem" }}>
                      ⚙️ Active Agent Configuration Parameters
                    </h4>
                    <div style={{ background: "rgba(0,0,0,0.4)", padding: "1rem", borderRadius: "6px", fontFamily: "var(--font-mono)", fontSize: "0.8rem", color: "var(--accent-cyan)", border: "1px solid rgba(245,158,11,0.2)" }}>
                      <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{JSON.stringify(diagPackage.configuration, null, 2)}</pre>
                    </div>
                  </div>

                  {/* Diagnostic Agent Logs */}
                  <div>
                    <h4 style={{ fontSize: "0.95rem", fontWeight: "700", color: "#a855f7", marginBottom: "0.6rem" }}>
                      📋 Recent Agent Daemon Logs & Traces
                    </h4>
                    <div style={{ background: "#090d16", padding: "1rem", borderRadius: "6px", fontFamily: "var(--font-mono)", fontSize: "0.78rem", color: "#e2e8f0", border: "1px solid rgba(168,85,247,0.3)", maxHeight: "200px", overflowY: "auto" }}>
                      {diagPackage.agent_logs.map((log, idx) => (
                        <div key={idx} style={{ color: log.includes("ERROR") ? "#ef4444" : log.includes("WARN") ? "#f59e0b" : "#94a3b8", marginBottom: "0.2rem" }}>
                          {log}
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Recent Errors & Alerts */}
                  <div>
                    <h4 style={{ fontSize: "0.95rem", fontWeight: "700", color: "#ef4444", marginBottom: "0.6rem" }}>
                      ⚠️ Recent Diagnostic Errors & Health Alerts ({diagPackage.last_errors.length})
                    </h4>
                    {diagPackage.last_errors.length === 0 ? (
                      <div style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>No diagnostic errors or health alerts logged for this endpoint.</div>
                    ) : (
                      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8rem", textAlign: "left" }}>
                        <thead>
                          <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.1)", color: "var(--text-muted)" }}>
                            <th style={{ padding: "0.5rem" }}>Title</th>
                            <th style={{ padding: "0.5rem" }}>Severity</th>
                            <th style={{ padding: "0.5rem" }}>Description</th>
                            <th style={{ padding: "0.5rem" }}>Timestamp</th>
                          </tr>
                        </thead>
                        <tbody>
                          {diagPackage.last_errors.map((err: any) => (
                            <tr key={err.id} style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                              <td style={{ padding: "0.5rem", fontWeight: "600", color: "#fff" }}>{err.title}</td>
                              <td style={{ padding: "0.5rem", fontWeight: "700", color: err.severity === "CRITICAL" || err.severity === "HIGH" ? "#ef4444" : "#f59e0b" }}>{err.severity}</td>
                              <td style={{ padding: "0.5rem", color: "var(--text-muted)" }}>{err.description}</td>
                              <td style={{ padding: "0.5rem", color: "var(--text-muted)" }}>{formatDateTime(err.timestamp)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Push Policy Bulk Modal */}
        {showPolicyModal && (
          <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.75)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 220, padding: "1rem" }}>
            <div className="glass-panel" style={{ width: "100%", maxWidth: "480px", borderRadius: "12px", padding: "1.8rem", background: "var(--bg-card)", border: "1px solid rgba(16,185,129,0.4)" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
                <h3 style={{ fontSize: "1.2rem", fontWeight: "700", color: "#fff" }}>
                  📋 Bulk Push Policy
                </h3>
                <button onClick={() => setShowPolicyModal(false)} style={{ background: "none", border: "none", color: "#888", fontSize: "1.2rem", cursor: "pointer" }}>✕</button>
              </div>

              <p style={{ fontSize: "0.85rem", color: "var(--text-muted)", marginBottom: "1.2rem" }}>
                Distribute and enforce security policy update across <strong style={{ color: "#10b981" }}>{selectedDeviceIds.length} selected agents</strong>.
              </p>

              <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
                <div>
                  <label style={{ display: "block", fontSize: "0.8rem", color: "var(--text-muted)", marginBottom: "0.4rem", fontWeight: "600" }}>
                    Policy Version Tag
                  </label>
                  <input
                    type="text"
                    value={policyVersionInput}
                    onChange={(e) => setPolicyVersionInput(e.target.value)}
                    placeholder="e.g. 3.2"
                    style={{ width: "100%", background: "rgba(0,0,0,0.4)", border: "1px solid rgba(255,255,255,0.15)", color: "#fff", padding: "0.6rem", borderRadius: "6px", fontSize: "0.9rem" }}
                  />
                </div>

                <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.8rem", marginTop: "0.5rem" }}>
                  <button onClick={() => setShowPolicyModal(false)} style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.15)", color: "#fff", padding: "0.5rem 1rem", borderRadius: "6px", cursor: "pointer", fontSize: "0.85rem" }}>Cancel</button>
                  <button onClick={handleBulkPushPolicy} disabled={isBulkProcessing} style={{ background: "rgba(16,185,129,0.25)", border: "1px solid #10b981", color: "#10b981", padding: "0.5rem 1.2rem", borderRadius: "6px", cursor: "pointer", fontSize: "0.85rem", fontWeight: "700" }}>
                    {isBulkProcessing ? "Updating..." : `Push Policy v${policyVersionInput}`}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Remote Command Dispatcher Modal */}
        {selectedDevice && !showAuditDrawer && (
          <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.75)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 200, padding: "1rem" }}>
            <div className="glass-panel" style={{ width: "100%", maxWidth: "550px", borderRadius: "12px", padding: "1.8rem", background: "var(--bg-card)", border: "1px solid rgba(0,240,255,0.3)" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
                <h3 style={{ fontSize: "1.2rem", fontWeight: "700", color: "#fff" }}>
                  Dispatch Command ➔ <span style={{ color: "var(--accent-cyan)" }}>{selectedDevice.hostname}</span>
                </h3>
                <button onClick={() => setSelectedDevice(null)} style={{ background: "none", border: "none", color: "#888", fontSize: "1.2rem", cursor: "pointer" }}>✕</button>
              </div>

              {commandNotice && (
                <div style={{ background: commandNotice.includes("Error") ? "rgba(239,68,68,0.15)" : "rgba(16,185,129,0.15)", border: commandNotice.includes("Error") ? "1px solid rgba(239,68,68,0.4)" : "1px solid rgba(16,185,129,0.4)", color: commandNotice.includes("Error") ? "#ef4444" : "#10b981", padding: "0.8rem", borderRadius: "6px", fontSize: "0.85rem", marginBottom: "1rem" }}>
                  {commandNotice}
                </div>
              )}

              <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
                <div>
                  <label style={{ display: "block", fontSize: "0.8rem", color: "var(--text-muted)", marginBottom: "0.4rem", fontWeight: "600" }}>Command Type</label>
                  <select
                    value={commandType}
                    onChange={(e) => setCommandType(e.target.value as AgentCommandType)}
                    style={{ width: "100%", background: "rgba(0,0,0,0.4)", border: "1px solid rgba(255,255,255,0.15)", color: "#fff", padding: "0.6rem", borderRadius: "6px", fontSize: "0.9rem" }}
                  >
                    <option value="START_SCAN">🔍 Start On-Demand Threat Scan</option>
                    <option value="RESTART_AGENT">🔄 Restart Agent Daemon</option>
                    <option value="REFRESH_POLICY">📋 Synchronize Security Policy</option>
                    <option value="COLLECT_DIAGNOSTICS">🩺 Collect System Diagnostics</option>
                    <option value="UPLOAD_LOGS">📁 Upload Event & Telemetry Logs</option>
                    <option value="RECONNECT">🔌 Reconnect Network Socket</option>
                    <option value="SHUTDOWN_AGENT">🛑 Shutdown Agent (Simulation)</option>
                    <option value="UPDATE_CONFIG">⚙️ Update Agent Configuration</option>
                  </select>
                </div>

                <div>
                  <label style={{ display: "block", fontSize: "0.8rem", color: "var(--text-muted)", marginBottom: "0.4rem", fontWeight: "600" }}>Command Payload Parameters (JSON)</label>
                  <textarea
                    rows={4}
                    value={commandPayload}
                    onChange={(e) => setCommandPayload(e.target.value)}
                    style={{ width: "100%", background: "rgba(0,0,0,0.5)", border: "1px solid rgba(255,255,255,0.15)", color: "var(--accent-cyan)", fontFamily: "var(--font-mono)", padding: "0.6rem", borderRadius: "6px", fontSize: "0.85rem" }}
                  />
                </div>

                <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.8rem", marginTop: "0.5rem" }}>
                  <button onClick={() => setSelectedDevice(null)} style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.15)", color: "#fff", padding: "0.5rem 1rem", borderRadius: "6px", cursor: "pointer", fontSize: "0.85rem" }}>Cancel</button>
                  <button onClick={handleIssueCommand} disabled={issuingCommand} style={{ background: "rgba(0,240,255,0.2)", border: "1px solid var(--accent-cyan)", color: "var(--accent-cyan)", padding: "0.5rem 1.2rem", borderRadius: "6px", cursor: "pointer", fontSize: "0.85rem", fontWeight: "700" }}>
                    {issuingCommand ? "Enqueueing..." : "⚡ Issue Command"}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Command Audit Logs & Execution History Modal */}
        {showAuditDrawer && (
          <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.75)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 200, padding: "1rem" }}>
            <div className="glass-panel" style={{ width: "100%", maxWidth: "800px", maxHeight: "85vh", borderRadius: "12px", padding: "1.8rem", background: "var(--bg-card)", overflowY: "auto", border: "1px solid rgba(168,85,247,0.3)" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.2rem" }}>
                <h3 style={{ fontSize: "1.2rem", fontWeight: "700", color: "#fff" }}>
                  📜 Remote Command Audit Trail & Lifecycle Log
                </h3>
                <button onClick={() => setShowAuditDrawer(false)} style={{ background: "none", border: "none", color: "#888", fontSize: "1.2rem", cursor: "pointer" }}>✕</button>
              </div>

              {loadingAudits ? (
                <div style={{ textAlign: "center", padding: "2rem", color: "var(--text-muted)" }}>Loading Audit Logs...</div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
                  <div>
                    <h4 style={{ fontSize: "0.95rem", fontWeight: "700", color: "var(--accent-cyan)", marginBottom: "0.5rem" }}>Command History ({commandHistory.length})</h4>
                    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8rem", textAlign: "left" }}>
                      <thead>
                        <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.1)", color: "var(--text-muted)" }}>
                          <th style={{ padding: "0.5rem" }}>Command</th>
                          <th style={{ padding: "0.5rem" }}>State</th>
                          <th style={{ padding: "0.5rem" }}>Duration</th>
                          <th style={{ padding: "0.5rem" }}>Result Output</th>
                          <th style={{ padding: "0.5rem" }}>Queued At</th>
                        </tr>
                      </thead>
                      <tbody>
                        {commandHistory.map((cmd) => (
                          <tr key={cmd.id} style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                            <td style={{ padding: "0.5rem", fontWeight: "600", color: "#fff" }}>{cmd.command_type}</td>
                            <td style={{ padding: "0.5rem", fontWeight: "700", color: cmd.status === "SUCCESS" ? "#10b981" : cmd.status === "FAILED" ? "#ef4444" : "#f59e0b" }}>{cmd.status}</td>
                            <td style={{ padding: "0.5rem", fontFamily: "var(--font-mono)" }}>{cmd.execution_duration_ms != null ? `${cmd.execution_duration_ms}ms` : "—"}</td>
                            <td style={{ padding: "0.5rem", color: "var(--text-muted)" }}>{cmd.result_output || cmd.error_message || "—"}</td>
                            <td style={{ padding: "0.5rem", color: "var(--text-muted)" }}>{formatDateTime(cmd.queued_at)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  <div>
                    <h4 style={{ fontSize: "0.95rem", fontWeight: "700", color: "#a855f7", marginBottom: "0.5rem" }}>Immutable Audit Logs ({auditLogs.length})</h4>
                    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8rem", textAlign: "left" }}>
                      <thead>
                        <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.1)", color: "var(--text-muted)" }}>
                          <th style={{ padding: "0.5rem" }}>Issuer</th>
                          <th style={{ padding: "0.5rem" }}>Command</th>
                          <th style={{ padding: "0.5rem" }}>Status</th>
                          <th style={{ padding: "0.5rem" }}>Audit Details</th>
                          <th style={{ padding: "0.5rem" }}>Logged At</th>
                        </tr>
                      </thead>
                      <tbody>
                        {auditLogs.map((log) => (
                          <tr key={log.id} style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                            <td style={{ padding: "0.5rem", fontWeight: "600", color: "#fff" }}>{log.issuer_username}</td>
                            <td style={{ padding: "0.5rem", fontFamily: "var(--font-mono)" }}>{log.command_type}</td>
                            <td style={{ padding: "0.5rem", fontWeight: "700", color: log.status === "SUCCESS" ? "#10b981" : "#a855f7" }}>{log.status}</td>
                            <td style={{ padding: "0.5rem", color: "var(--text-muted)" }}>{log.details}</td>
                            <td style={{ padding: "0.5rem", color: "var(--text-muted)" }}>{formatDateTime(log.created_at)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
};
