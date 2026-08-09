import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { WebSocketStatusBadge } from "../components/WebSocketStatusBadge";
import { NotificationCenter } from "../components/NotificationCenter";
import {
  policyService
} from "../services/policy";
import type {
  USBPolicyConfig,
  ProcessPolicyConfig,
  NetworkPolicyConfig,
  FIMPolicyConfig,
  SecurityPolicyRecord,
  UnifiedPolicySync
} from "../services/policy";

type TabType = "USB" | "PROCESS" | "NETWORK" | "FIM" | "RANSOMWARE" | "HISTORY";

export const PolicyDashboard: React.FC = () => {
  const { logout } = useAuth();

  const [activeTab, setActiveTab] = useState<TabType>("USB");
  const [loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [toastMsg, setToastMsg] = useState<string | null>(null);

  // Policy States
  const [usbPolicy, setUsbPolicy] = useState<USBPolicyConfig | null>(null);
  const [processPolicy, setProcessPolicy] = useState<ProcessPolicyConfig | null>(null);
  const [networkPolicy, setNetworkPolicy] = useState<NetworkPolicyConfig | null>(null);
  const [fimPolicy, setFimPolicy] = useState<FIMPolicyConfig | null>(null);
  const [syncData, setSyncData] = useState<UnifiedPolicySync | null>(null);
  const [history, setHistory] = useState<SecurityPolicyRecord[]>([]);

  // Diff comparison modal state
  const [diffModalPolicy, setDiffModalPolicy] = useState<SecurityPolicyRecord | null>(null);

  useEffect(() => {
    fetchAllPolicies();
  }, []);

  const showToast = (msg: string) => {
    setToastMsg(msg);
    setTimeout(() => setToastMsg(null), 4000);
  };

  const fetchAllPolicies = async () => {
    setLoading(true);
    try {
      const [usb, proc, net, fim, sync, hist] = await Promise.all([
        policyService.getUSBPolicy(),
        policyService.getProcessPolicy(),
        policyService.getNetworkPolicy(),
        policyService.getFIMPolicy(),
        policyService.getLatestSync(),
        policyService.getPolicyHistory()
      ]);
      setUsbPolicy(usb);
      setProcessPolicy(proc);
      setNetworkPolicy(net);
      setFimPolicy(fim);
      setSyncData(sync);
      setHistory(hist);
    } catch (err: any) {
      showToast("Error loading policies: " + (err.message || err));
    } finally {
      setLoading(false);
    }
  };

  const handleSaveUSB = async () => {
    if (!usbPolicy) return;
    setSaving(true);
    try {
      const updated = await policyService.updateUSBPolicy(usbPolicy);
      setUsbPolicy(updated);
      showToast("✅ USB Security Policy saved successfully.");
      fetchAllPolicies();
    } catch (err: any) {
      showToast("❌ Failed to save USB policy: " + err.message);
    } finally {
      setSaving(false);
    }
  };

  const handleSaveProcess = async () => {
    if (!processPolicy) return;
    setSaving(true);
    try {
      const updated = await policyService.updateProcessPolicy(processPolicy);
      setProcessPolicy(updated);
      showToast("✅ Process Security Policy saved successfully.");
      fetchAllPolicies();
    } catch (err: any) {
      showToast("❌ Failed to save Process policy: " + err.message);
    } finally {
      setSaving(false);
    }
  };

  const handleSaveNetwork = async () => {
    if (!networkPolicy) return;
    setSaving(true);
    try {
      const updated = await policyService.updateNetworkPolicy(networkPolicy);
      setNetworkPolicy(updated);
      showToast("✅ Network Security Policy saved successfully.");
      fetchAllPolicies();
    } catch (err: any) {
      showToast("❌ Failed to save Network policy: " + err.message);
    } finally {
      setSaving(false);
    }
  };

  const handleSaveFIM = async () => {
    if (!fimPolicy) return;
    setSaving(true);
    try {
      const updated = await policyService.updateFIMPolicy(fimPolicy);
      setFimPolicy(updated);
      showToast("✅ File Integrity & Ransomware Policy saved successfully.");
      fetchAllPolicies();
    } catch (err: any) {
      showToast("❌ Failed to save FIM policy: " + err.message);
    } finally {
      setSaving(false);
    }
  };

  const handleTogglePolicy = async (rec: SecurityPolicyRecord) => {
    try {
      await policyService.togglePolicy(rec.id, !rec.enabled);
      showToast(`Updated policy status to ${!rec.enabled ? "ENABLED" : "DISABLED"}.`);
      fetchAllPolicies();
    } catch (err: any) {
      showToast("Failed to toggle policy: " + err.message);
    }
  };

  const handleClonePolicy = async (id: string) => {
    try {
      const cloned = await policyService.clonePolicy(id);
      showToast(`Cloned policy '${cloned.policy_name}' v${cloned.version}.`);
      fetchAllPolicies();
    } catch (err: any) {
      showToast("Failed to clone policy: " + err.message);
    }
  };

  const handleRollbackPolicy = async (id: string) => {
    try {
      const rolled = await policyService.rollbackPolicy(id);
      showToast(`Rolled back to version v${rolled.version} ('${rolled.policy_name}').`);
      fetchAllPolicies();
    } catch (err: any) {
      showToast("Failed to rollback policy: " + err.message);
    }
  };

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg-primary)", color: "var(--text-main)", padding: "2rem" }}>
      {/* Toast Notice */}
      {toastMsg && (
        <div style={{
          position: "fixed",
          top: "1.5rem",
          right: "1.5rem",
          zIndex: 9999,
          background: "rgba(0, 240, 255, 0.15)",
          border: "1px solid var(--accent-cyan)",
          color: "var(--accent-cyan)",
          padding: "0.8rem 1.4rem",
          borderRadius: "8px",
          backdropFilter: "blur(10px)",
          boxShadow: "0 8px 32px rgba(0,0,0,0.5)",
          fontWeight: "600"
        }}>
          {toastMsg}
        </div>
      )}

      {/* Navigation Header */}
      <header className="glass-panel" style={{ position: "relative", zIndex: 100, display: "flex", justifyContent: "space-between", alignItems: "center", gap: "1rem", padding: "0.8rem 1.5rem", marginBottom: "2rem", flexWrap: "wrap" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "1.5rem", flexWrap: "wrap" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.8rem", flexShrink: 0 }}>
            <div style={{ fontSize: "1.4rem", fontWeight: "800", color: "var(--accent-cyan)", letterSpacing: "1px" }}>
              SENTINEL<span style={{ color: "var(--text-main)" }}>X</span>
            </div>
            <span style={{ background: "rgba(0, 240, 255, 0.1)", color: "var(--accent-cyan)", padding: "0.2rem 0.5rem", borderRadius: "4px", fontSize: "0.7rem", fontFamily: "var(--font-mono)", whiteSpace: "nowrap" }}>
              POLICY ENGINE
            </span>
            <WebSocketStatusBadge />
          </div>

          <nav style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap" }}>
            <Link to="/dashboard" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem" }}>Dashboard</Link>
            <Link to="/threats" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem" }}>Threats</Link>
            <Link to="/alerts" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem" }}>Alerts</Link>
            <Link to="/ransomware" style={{ color: "#ff0055", background: "rgba(255, 0, 85, 0.1)", border: "1px solid rgba(255, 0, 85, 0.3)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>Ransomware</Link>
            <Link to="/policies" style={{ color: "var(--accent-cyan)", background: "rgba(0, 240, 255, 0.1)", border: "1px solid rgba(0, 240, 255, 0.3)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem", borderRadius: "6px" }}>Security Policies</Link>
            <Link to="/respond" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem" }}>Response</Link>
            <Link to="/processes" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem" }}>Processes</Link>
            <Link to="/network" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem" }}>Network</Link>
            <Link to="/integrity" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem" }}>FIM</Link>
            <Link to="/events" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem" }}>Event Logs</Link>
            <Link to="/investigations" style={{ color: "var(--text-muted)", textDecoration: "none", fontSize: "0.85rem", fontWeight: "600", padding: "0.35rem 0.7rem" }}>Cases</Link>
          </nav>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
          <NotificationCenter />
          <button onClick={logout} style={{ background: "transparent", border: "1px solid rgba(255, 255, 255, 0.2)", color: "var(--text-muted)", padding: "0.35rem 0.8rem", borderRadius: "6px", cursor: "pointer", fontSize: "0.8rem" }}>Logout</button>
        </div>
      </header>

      {/* Main Title & Global Sync Summary */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem", flexWrap: "wrap", gap: "1rem" }}>
        <div>
          <h1 style={{ margin: 0, fontSize: "1.8rem", fontWeight: "800", letterSpacing: "0.5px" }}>Central Security Policy Management</h1>
          <p style={{ margin: "0.3rem 0 0 0", color: "var(--text-muted)", fontSize: "0.9rem" }}>Define, enforce, audit, and distribute central policies across all SentinelX managed endpoints.</p>
        </div>

        {syncData && (
          <div className="glass-panel" style={{ padding: "0.8rem 1.2rem", display: "flex", alignItems: "center", gap: "1rem" }}>
            <div>
              <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase" }}>Global Policy Sync</div>
              <div style={{ fontSize: "1.1rem", fontWeight: "700", color: "var(--accent-cyan)" }}>Version #{syncData.version}</div>
            </div>
            <div style={{ background: "rgba(0, 255, 136, 0.1)", color: "#00ff88", padding: "0.3rem 0.6rem", borderRadius: "4px", fontSize: "0.75rem", fontWeight: "600" }}>ACTIVE</div>
          </div>
        )}
      </div>

      {/* Policy Category Tabs */}
      <div style={{ display: "flex", gap: "0.6rem", marginBottom: "1.5rem", borderBottom: "1px solid rgba(255, 255, 255, 0.1)", paddingBottom: "0.6rem", flexWrap: "wrap" }}>
        {(["USB", "PROCESS", "NETWORK", "FIM", "RANSOMWARE", "HISTORY"] as TabType[]).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            style={{
              background: activeTab === tab ? "rgba(0, 240, 255, 0.15)" : "transparent",
              color: activeTab === tab ? "var(--accent-cyan)" : "var(--text-muted)",
              border: activeTab === tab ? "1px solid var(--accent-cyan)" : "1px solid transparent",
              padding: "0.5rem 1.2rem",
              borderRadius: "6px",
              fontWeight: "700",
              fontSize: "0.85rem",
              cursor: "pointer",
              transition: "all 0.2s"
            }}
          >
            {tab === "USB" && "🔌 USB Policies"}
            {tab === "PROCESS" && "⚡ Process Policies"}
            {tab === "NETWORK" && "🌐 Network Policies"}
            {tab === "FIM" && "📁 File Integrity Policies"}
            {tab === "RANSOMWARE" && "🛡️ Ransomware Policies"}
            {tab === "HISTORY" && "📜 Version History & Audits"}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="glass-panel" style={{ padding: "3rem", textAlign: "center", color: "var(--accent-cyan)" }}>
          Loading security policies from central backend...
        </div>
      ) : (
        <div>
          {/* ==================== USB POLICIES ==================== */}
          {activeTab === "USB" && usbPolicy && (
            <div className="glass-panel" style={{ padding: "1.8rem" }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "1.5rem" }}>
                <h2 style={{ margin: 0, fontSize: "1.2rem", color: "var(--accent-cyan)" }}>USB Hardware Storage & Peripheral Enforcement</h2>
                <button onClick={handleSaveUSB} disabled={saving} style={{ background: "var(--accent-cyan)", color: "#000", border: "none", padding: "0.5rem 1.2rem", borderRadius: "6px", fontWeight: "700", cursor: "pointer" }}>
                  {saving ? "Saving..." : "Save USB Policy"}
                </button>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "1.2rem" }}>
                <label style={{ display: "flex", alignItems: "center", gap: "0.8rem", cursor: "pointer", background: "rgba(255,255,255,0.03)", padding: "1rem", borderRadius: "8px" }}>
                  <input type="checkbox" checked={usbPolicy.enable_usb_monitoring} onChange={(e) => setUsbPolicy({ ...usbPolicy, enable_usb_monitoring: e.target.checked })} />
                  <div>
                    <div style={{ fontWeight: "700" }}>Enable USB Monitoring</div>
                    <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Monitor USB insertion & removal events</div>
                  </div>
                </label>

                <label style={{ display: "flex", alignItems: "center", gap: "0.8rem", cursor: "pointer", background: "rgba(255,255,255,0.03)", padding: "1rem", borderRadius: "8px" }}>
                  <input type="checkbox" checked={usbPolicy.enable_auto_scanning} onChange={(e) => setUsbPolicy({ ...usbPolicy, enable_auto_scanning: e.target.checked })} />
                  <div>
                    <div style={{ fontWeight: "700" }}>Automatic Drive Scanning</div>
                    <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Auto-scan files on USB insertion</div>
                  </div>
                </label>

                <label style={{ display: "flex", alignItems: "center", gap: "0.8rem", cursor: "pointer", background: "rgba(255,255,255,0.03)", padding: "1rem", borderRadius: "8px" }}>
                  <input type="checkbox" checked={usbPolicy.enable_sha256_hashing} onChange={(e) => setUsbPolicy({ ...usbPolicy, enable_sha256_hashing: e.target.checked })} />
                  <div>
                    <div style={{ fontWeight: "700" }}>SHA-256 Cryptographic Hashing</div>
                    <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Compute SHA-256 for all scanned files</div>
                  </div>
                </label>

                <label style={{ display: "flex", alignItems: "center", gap: "0.8rem", cursor: "pointer", background: "rgba(255,255,255,0.03)", padding: "1rem", borderRadius: "8px" }}>
                  <input type="checkbox" checked={usbPolicy.auto_quarantine_suspicious} onChange={(e) => setUsbPolicy({ ...usbPolicy, auto_quarantine_suspicious: e.target.checked })} />
                  <div>
                    <div style={{ fontWeight: "700" }}>Auto-Quarantine Threats</div>
                    <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Move dangerous executables straight to vault</div>
                  </div>
                </label>

                <label style={{ display: "flex", alignItems: "center", gap: "0.8rem", cursor: "pointer", background: "rgba(255,255,255,0.03)", padding: "1rem", borderRadius: "8px" }}>
                  <input type="checkbox" checked={usbPolicy.read_only_mode} onChange={(e) => setUsbPolicy({ ...usbPolicy, read_only_mode: e.target.checked })} />
                  <div>
                    <div style={{ fontWeight: "700" }}>Read-Only Mode</div>
                    <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Enforce read-only write protection on USB</div>
                  </div>
                </label>
              </div>

              <div style={{ marginTop: "1.5rem" }}>
                <label style={{ display: "block", marginBottom: "0.5rem", fontWeight: "700" }}>Max File Size Inspection Limit (MB): {usbPolicy.max_file_size_mb} MB</label>
                <input type="range" min="1" max="500" value={usbPolicy.max_file_size_mb} onChange={(e) => setUsbPolicy({ ...usbPolicy, max_file_size_mb: parseInt(e.target.value) })} style={{ width: "100%" }} />
              </div>

              <div style={{ marginTop: "1.5rem" }}>
                <label style={{ display: "block", marginBottom: "0.5rem", fontWeight: "700" }}>Ignored File Extensions (Comma Separated)</label>
                <input type="text" value={usbPolicy.ignored_extensions.join(", ")} onChange={(e) => setUsbPolicy({ ...usbPolicy, ignored_extensions: e.target.value.split(",").map(s => s.trim()) })} style={{ width: "100%", padding: "0.7rem", background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.2)", color: "#fff", borderRadius: "6px" }} />
              </div>
            </div>
          )}

          {/* ==================== PROCESS POLICIES ==================== */}
          {activeTab === "PROCESS" && processPolicy && (
            <div className="glass-panel" style={{ padding: "1.8rem" }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "1.5rem" }}>
                <h2 style={{ margin: 0, fontSize: "1.2rem", color: "var(--accent-cyan)" }}>Process Monitoring & Behavioral Execution Rules</h2>
                <button onClick={handleSaveProcess} disabled={saving} style={{ background: "var(--accent-cyan)", color: "#000", border: "none", padding: "0.5rem 1.2rem", borderRadius: "6px", fontWeight: "700", cursor: "pointer" }}>
                  {saving ? "Saving..." : "Save Process Policy"}
                </button>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "1.2rem" }}>
                <label style={{ display: "flex", alignItems: "center", gap: "0.8rem", cursor: "pointer", background: "rgba(255,255,255,0.03)", padding: "1rem", borderRadius: "8px" }}>
                  <input type="checkbox" checked={processPolicy.monitor_powershell} onChange={(e) => setProcessPolicy({ ...processPolicy, monitor_powershell: e.target.checked })} />
                  <div>
                    <div style={{ fontWeight: "700" }}>Monitor PowerShell</div>
                    <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Inspect encoded commands & memory downloads</div>
                  </div>
                </label>

                <label style={{ display: "flex", alignItems: "center", gap: "0.8rem", cursor: "pointer", background: "rgba(255,255,255,0.03)", padding: "1rem", borderRadius: "8px" }}>
                  <input type="checkbox" checked={processPolicy.monitor_lolbins} onChange={(e) => setProcessPolicy({ ...processPolicy, monitor_lolbins: e.target.checked })} />
                  <div>
                    <div style={{ fontWeight: "700" }}>Monitor LOLBins</div>
                    <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Living-off-the-land binaries (certutil, bitsadmin)</div>
                  </div>
                </label>

                <label style={{ display: "flex", alignItems: "center", gap: "0.8rem", cursor: "pointer", background: "rgba(255,255,255,0.03)", padding: "1rem", borderRadius: "8px" }}>
                  <input type="checkbox" checked={processPolicy.auto_kill_blocklisted} onChange={(e) => setProcessPolicy({ ...processPolicy, auto_kill_blocklisted: e.target.checked })} />
                  <div>
                    <div style={{ fontWeight: "700" }}>Auto-Kill Blocklisted Processes</div>
                    <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Automatically terminate unauthorized binaries</div>
                  </div>
                </label>

                <label style={{ display: "flex", alignItems: "center", gap: "0.8rem", cursor: "pointer", background: "rgba(255,255,255,0.03)", padding: "1rem", borderRadius: "8px" }}>
                  <input type="checkbox" checked={processPolicy.parent_child_rules_enabled} onChange={(e) => setProcessPolicy({ ...processPolicy, parent_child_rules_enabled: e.target.checked })} />
                  <div>
                    <div style={{ fontWeight: "700" }}>Parent-Child Lineage Rules</div>
                    <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Detect suspicious child process spawning</div>
                  </div>
                </label>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem", marginTop: "1.5rem" }}>
                <div>
                  <label style={{ display: "block", marginBottom: "0.5rem", fontWeight: "700" }}>CPU Consumption Alert Threshold: {processPolicy.cpu_threshold_percent}%</label>
                  <input type="range" min="10" max="100" value={processPolicy.cpu_threshold_percent} onChange={(e) => setProcessPolicy({ ...processPolicy, cpu_threshold_percent: parseFloat(e.target.value) })} style={{ width: "100%" }} />
                </div>
                <div>
                  <label style={{ display: "block", marginBottom: "0.5rem", fontWeight: "700" }}>Memory Threshold: {processPolicy.memory_threshold_mb} MB</label>
                  <input type="range" min="50" max="4096" step="50" value={processPolicy.memory_threshold_mb} onChange={(e) => setProcessPolicy({ ...processPolicy, memory_threshold_mb: parseFloat(e.target.value) })} style={{ width: "100%" }} />
                </div>
              </div>

              <div style={{ marginTop: "1.5rem" }}>
                <label style={{ display: "block", marginBottom: "0.5rem", fontWeight: "700" }}>Blocklisted Executables (Comma Separated)</label>
                <input type="text" value={processPolicy.blocklisted_processes.join(", ")} onChange={(e) => setProcessPolicy({ ...processPolicy, blocklisted_processes: e.target.value.split(",").map(s => s.trim()) })} style={{ width: "100%", padding: "0.7rem", background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.2)", color: "#fff", borderRadius: "6px" }} />
              </div>
            </div>
          )}

          {/* ==================== NETWORK POLICIES ==================== */}
          {activeTab === "NETWORK" && networkPolicy && (
            <div className="glass-panel" style={{ padding: "1.8rem" }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "1.5rem" }}>
                <h2 style={{ margin: 0, fontSize: "1.2rem", color: "var(--accent-cyan)" }}>Network Connection & C2 Beaconing Thresholds</h2>
                <button onClick={handleSaveNetwork} disabled={saving} style={{ background: "var(--accent-cyan)", color: "#000", border: "none", padding: "0.5rem 1.2rem", borderRadius: "6px", fontWeight: "700", cursor: "pointer" }}>
                  {saving ? "Saving..." : "Save Network Policy"}
                </button>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "1.2rem" }}>
                <label style={{ display: "flex", alignItems: "center", gap: "0.8rem", cursor: "pointer", background: "rgba(255,255,255,0.03)", padding: "1rem", borderRadius: "8px" }}>
                  <input type="checkbox" checked={networkPolicy.monitor_external_connections} onChange={(e) => setNetworkPolicy({ ...networkPolicy, monitor_external_connections: e.target.checked })} />
                  <div>
                    <div style={{ fontWeight: "700" }}>External Connection Monitoring</div>
                    <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Inspect non-RFC1918 public IP sockets</div>
                  </div>
                </label>

                <label style={{ display: "flex", alignItems: "center", gap: "0.8rem", cursor: "pointer", background: "rgba(255,255,255,0.03)", padding: "1rem", borderRadius: "8px" }}>
                  <input type="checkbox" checked={networkPolicy.auto_block_c2_connections} onChange={(e) => setNetworkPolicy({ ...networkPolicy, auto_block_c2_connections: e.target.checked })} />
                  <div>
                    <div style={{ fontWeight: "700" }}>Auto-Sever C2 Connections</div>
                    <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Kill process initiating connections to blocklisted IPs/ports</div>
                  </div>
                </label>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem", marginTop: "1.5rem" }}>
                <div>
                  <label style={{ display: "block", marginBottom: "0.5rem", fontWeight: "700" }}>Prohibited Destination Ports (Comma Separated)</label>
                  <input type="text" value={networkPolicy.blocked_ports.join(", ")} onChange={(e) => setNetworkPolicy({ ...networkPolicy, blocked_ports: e.target.value.split(",").map(s => parseInt(s.trim())).filter(n => !isNaN(n)) })} style={{ width: "100%", padding: "0.7rem", background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.2)", color: "#fff", borderRadius: "6px" }} />
                </div>
                <div>
                  <label style={{ display: "block", marginBottom: "0.5rem", fontWeight: "700" }}>Blocklisted C2 Remote IPs (Comma Separated)</label>
                  <input type="text" value={networkPolicy.blocklisted_ips.join(", ")} onChange={(e) => setNetworkPolicy({ ...networkPolicy, blocklisted_ips: e.target.value.split(",").map(s => s.trim()) })} style={{ width: "100%", padding: "0.7rem", background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.2)", color: "#fff", borderRadius: "6px" }} />
                </div>
              </div>
            </div>
          )}

          {/* ==================== FILE INTEGRITY & RANSOMWARE ==================== */}
          {(activeTab === "FIM" || activeTab === "RANSOMWARE") && fimPolicy && (
            <div className="glass-panel" style={{ padding: "1.8rem" }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "1.5rem" }}>
                <h2 style={{ margin: 0, fontSize: "1.2rem", color: "var(--accent-cyan)" }}>
                  {activeTab === "FIM" ? "File Integrity Monitoring (FIM) Watchlist Rules" : "Ransomware Behavioral Analytics & Entropy Rules"}
                </h2>
                <button onClick={handleSaveFIM} disabled={saving} style={{ background: "var(--accent-cyan)", color: "#000", border: "none", padding: "0.5rem 1.2rem", borderRadius: "6px", fontWeight: "700", cursor: "pointer" }}>
                  {saving ? "Saving..." : "Save FIM & Ransomware Policy"}
                </button>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "1.2rem" }}>
                <label style={{ display: "flex", alignItems: "center", gap: "0.8rem", cursor: "pointer", background: "rgba(255,255,255,0.03)", padding: "1rem", borderRadius: "8px" }}>
                  <input type="checkbox" checked={fimPolicy.ignore_temporary_files} onChange={(e) => setFimPolicy({ ...fimPolicy, ignore_temporary_files: e.target.checked })} />
                  <div>
                    <div style={{ fontWeight: "700" }}>Ignore Temporary Files</div>
                    <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Skip editor swap files (.tmp, .swp, ~$)</div>
                  </div>
                </label>

                <label style={{ display: "flex", alignItems: "center", gap: "0.8rem", cursor: "pointer", background: "rgba(255,255,255,0.03)", padding: "1rem", borderRadius: "8px" }}>
                  <input type="checkbox" checked={fimPolicy.auto_quarantine_ransomware} onChange={(e) => setFimPolicy({ ...fimPolicy, auto_quarantine_ransomware: e.target.checked })} />
                  <div>
                    <div style={{ fontWeight: "700" }}>Auto-Quarantine Ransomware</div>
                    <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Automatically quarantine files upon mass encryption</div>
                  </div>
                </label>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem", marginTop: "1.5rem" }}>
                <div>
                  <label style={{ display: "block", marginBottom: "0.5rem", fontWeight: "700" }}>Ransomware Mass Modification Limit (files/min): {fimPolicy.ransomware_modification_threshold}</label>
                  <input type="range" min="5" max="100" value={fimPolicy.ransomware_modification_threshold} onChange={(e) => setFimPolicy({ ...fimPolicy, ransomware_modification_threshold: parseInt(e.target.value) })} style={{ width: "100%" }} />
                </div>
                <div>
                  <label style={{ display: "block", marginBottom: "0.5rem", fontWeight: "700" }}>Ransomware Shannon Entropy Threshold: {fimPolicy.ransomware_entropy_threshold}</label>
                  <input type="range" min="5.0" max="8.0" step="0.1" value={fimPolicy.ransomware_entropy_threshold} onChange={(e) => setFimPolicy({ ...fimPolicy, ransomware_entropy_threshold: parseFloat(e.target.value) })} style={{ width: "100%" }} />
                </div>
              </div>

              <div style={{ marginTop: "1.5rem" }}>
                <label style={{ display: "block", marginBottom: "0.5rem", fontWeight: "700" }}>Protected Watchlist Folders (Comma Separated)</label>
                <input type="text" value={fimPolicy.protected_folders.join(", ")} onChange={(e) => setFimPolicy({ ...fimPolicy, protected_folders: e.target.value.split(",").map(s => s.trim()) })} style={{ width: "100%", padding: "0.7rem", background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.2)", color: "#fff", borderRadius: "6px" }} />
              </div>
            </div>
          )}

          {/* ==================== VERSION HISTORY & AUDITS ==================== */}
          {activeTab === "HISTORY" && (
            <div className="glass-panel" style={{ padding: "1.8rem" }}>
              <h2 style={{ margin: "0 0 1rem 0", fontSize: "1.2rem", color: "var(--accent-cyan)" }}>Central Security Policy Version History & Audit Trail</h2>
              
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.85rem" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.1)", color: "var(--text-muted)", textAlign: "left" }}>
                    <th style={{ padding: "0.8rem" }}>Version</th>
                    <th style={{ padding: "0.8rem" }}>Policy Name</th>
                    <th style={{ padding: "0.8rem" }}>Category</th>
                    <th style={{ padding: "0.8rem" }}>Status</th>
                    <th style={{ padding: "0.8rem" }}>Priority</th>
                    <th style={{ padding: "0.8rem" }}>Updated At</th>
                    <th style={{ padding: "0.8rem" }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((rec) => (
                    <tr key={rec.id} style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                      <td style={{ padding: "0.8rem", fontWeight: "700", color: "var(--accent-cyan)" }}>v{rec.version}</td>
                      <td style={{ padding: "0.8rem" }}>{rec.policy_name}</td>
                      <td style={{ padding: "0.8rem" }}>
                        <span style={{ background: "rgba(255,255,255,0.1)", padding: "0.2rem 0.5rem", borderRadius: "4px", fontSize: "0.75rem" }}>{rec.category}</span>
                      </td>
                      <td style={{ padding: "0.8rem" }}>
                        <span style={{ color: rec.enabled ? "#00ff88" : "#ff0055", fontWeight: "700" }}>{rec.enabled ? "ENABLED" : "DISABLED"}</span>
                      </td>
                      <td style={{ padding: "0.8rem" }}>{rec.priority}</td>
                      <td style={{ padding: "0.8rem", color: "var(--text-muted)" }}>{new Date(rec.updated_at).toLocaleString()}</td>
                      <td style={{ padding: "0.8rem", display: "flex", gap: "0.5rem" }}>
                        <button onClick={() => handleTogglePolicy(rec)} style={{ background: "transparent", border: "1px solid rgba(255,255,255,0.2)", color: "#fff", padding: "0.25rem 0.5rem", borderRadius: "4px", cursor: "pointer", fontSize: "0.75rem" }}>
                          {rec.enabled ? "Disable" : "Enable"}
                        </button>
                        <button onClick={() => handleClonePolicy(rec.id)} style={{ background: "transparent", border: "1px solid var(--accent-cyan)", color: "var(--accent-cyan)", padding: "0.25rem 0.5rem", borderRadius: "4px", cursor: "pointer", fontSize: "0.75rem" }}>
                          Clone
                        </button>
                        <button onClick={() => handleRollbackPolicy(rec.id)} style={{ background: "rgba(255, 0, 85, 0.1)", border: "1px solid #ff0055", color: "#ff0055", padding: "0.25rem 0.5rem", borderRadius: "4px", cursor: "pointer", fontSize: "0.75rem" }}>
                          Rollback
                        </button>
                        <button onClick={() => setDiffModalPolicy(rec)} style={{ background: "transparent", border: "1px solid rgba(255,255,255,0.3)", color: "var(--text-muted)", padding: "0.25rem 0.5rem", borderRadius: "4px", cursor: "pointer", fontSize: "0.75rem" }}>
                          Compare JSON
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* JSON Diff Modal */}
      {diffModalPolicy && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.8)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 10000, padding: "2rem" }}>
          <div className="glass-panel" style={{ width: "100%", maxWidth: "700px", background: "#0a0c10", padding: "2rem", borderRadius: "12px", border: "1px solid var(--accent-cyan)" }}>
            <h3 style={{ margin: "0 0 1rem 0", color: "var(--accent-cyan)" }}>Policy Inspect & JSON Diff: {diffModalPolicy.policy_name} (v{diffModalPolicy.version})</h3>
            <pre style={{ background: "rgba(0,0,0,0.6)", padding: "1rem", borderRadius: "8px", color: "#00ff88", fontFamily: "var(--font-mono)", fontSize: "0.85rem", overflowX: "auto", maxHeight: "400px" }}>
              {JSON.stringify(diffModalPolicy.configuration, null, 2)}
            </pre>
            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: "1.5rem" }}>
              <button onClick={() => setDiffModalPolicy(null)} style={{ background: "var(--accent-cyan)", color: "#000", border: "none", padding: "0.5rem 1.2rem", borderRadius: "6px", fontWeight: "700", cursor: "pointer" }}>Close</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
