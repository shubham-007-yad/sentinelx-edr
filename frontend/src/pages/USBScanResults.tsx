import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { getUsbScans, getUsbEvents } from "../services/usb";
import type { USBScanResult, USBEvent } from "../types/usb";

export const USBScanResults: React.FC = () => {
  const { user, logout } = useAuth();

  const [scans, setScans] = useState<USBScanResult[]>([]);
  const [usbEvents, setUsbEvents] = useState<USBEvent[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Filter and Pagination state
  const [page, setPage] = useState<number>(1);
  const [limit, setLimit] = useState<number>(10);
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [selectedExtension, setSelectedExtension] = useState<string>("");
  const [hiddenFilter, setHiddenFilter] = useState<string>("ALL"); // ALL, HIDDEN, VISIBLE
  const [selectedUsbEventId, setSelectedUsbEventId] = useState<string>("");

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      // Fetch recent USB events for device/event filter dropdown
      const eventsData = await getUsbEvents(0, 50);
      setUsbEvents(eventsData);

      // Determine isHidden boolean for query
      let isHiddenParam: boolean | undefined = undefined;
      if (hiddenFilter === "HIDDEN") isHiddenParam = true;
      if (hiddenFilter === "VISIBLE") isHiddenParam = false;

      const skip = (page - 1) * limit;
      const scansData = await getUsbScans(
        skip,
        limit,
        selectedUsbEventId || undefined,
        selectedExtension || undefined,
        isHiddenParam,
        searchQuery || undefined
      );
      setScans(scansData);
    } catch (err: any) {
      console.error("Failed to fetch USB scan results:", err);
      setError("Failed to load USB file scan results from backend.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [page, limit, selectedUsbEventId, selectedExtension, hiddenFilter, searchQuery]);

  const formatBytes = (bytes?: number) => {
    if (bytes === undefined || bytes === null || bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  const formatDate = (isoString?: string) => {
    if (!isoString) return "N/A";
    try {
      const d = new Date(isoString);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + " (" + d.toLocaleDateString() + ")";
    } catch {
      return isoString;
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const resetFilters = () => {
    setSearchQuery("");
    setSelectedExtension("");
    setHiddenFilter("ALL");
    setSelectedUsbEventId("");
    setPage(1);
  };

  const totalFilesScanned = scans.length;
  const hiddenFilesCount = scans.filter((s) => s.is_hidden).length;
  const executablesCount = scans.filter((s) => s.extension?.toLowerCase() === ".exe" || s.extension?.toLowerCase() === ".dll" || s.extension?.toLowerCase() === ".bat" || s.extension?.toLowerCase() === ".sh").length;

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg-primary)", color: "var(--text-main)", padding: "2rem" }}>
      {/* Top Header Navigation */}
      <header className="glass-panel" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "1rem 2rem", marginBottom: "2rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "2rem" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
            <div style={{ fontSize: "1.5rem", fontWeight: "800", color: "var(--accent-cyan)", letterSpacing: "1px" }}>
              SENTINEL<span style={{ color: "var(--text-main)" }}>X</span>
            </div>
            <span style={{ background: "rgba(0, 240, 255, 0.1)", color: "var(--accent-cyan)", padding: "0.2rem 0.6rem", borderRadius: "4px", fontSize: "0.75rem", fontFamily: "var(--font-mono)" }}>
              EDR CONSOLE v1.0.0
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
                color: "var(--accent-cyan)",
                background: "rgba(0, 240, 255, 0.1)",
                border: "1px solid rgba(0, 240, 255, 0.3)",
                textDecoration: "none",
                fontSize: "0.9rem",
                fontWeight: "600",
                padding: "0.4rem 0.8rem",
                borderRadius: "6px",
              }}
            >
              USB Scan Results
            </Link>
          </nav>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "1.5rem" }}>
          <div style={{ textAlign: "right" }}>
            <div style={{ fontWeight: "600", fontSize: "0.95rem" }}>{user?.username}</div>
            <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>{user?.email}</div>
          </div>
          <button
            onClick={logout}
            style={{
              background: "rgba(255, 0, 85, 0.1)",
              border: "1px solid rgba(255, 0, 85, 0.3)",
              color: "#ff3366",
              padding: "0.5rem 1rem",
              borderRadius: "6px",
              cursor: "pointer",
              fontWeight: "600",
              fontSize: "0.85rem",
              transition: "all 0.2s"
            }}
          >
            Logout
          </button>
        </div>
      </header>

      {/* Main Container */}
      <main style={{ maxWidth: "1400px", margin: "0 auto" }}>
        <div style={{ marginBottom: "2rem" }}>
          <h1 style={{ fontSize: "1.8rem", fontWeight: "700", marginBottom: "0.5rem" }}>
            🛡️ USB File Scanning Forensics Console
          </h1>
          <p style={{ color: "var(--text-muted)", fontSize: "0.95rem" }}>
            Detailed inventory, SHA-256 cryptographic fingerprints, and metadata for every file enumerated from connected USB devices.
          </p>
        </div>

        {/* Top Summary Metrics Cards */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: "1.5rem", marginBottom: "2rem" }}>
          <div className="glass-panel" style={{ padding: "1.5rem", borderRadius: "12px", borderLeft: "4px solid var(--accent-cyan)" }}>
            <div style={{ color: "var(--text-muted)", fontSize: "0.85rem", textTransform: "uppercase", letterSpacing: "1px", marginBottom: "0.5rem" }}>
              Page Files Discovered
            </div>
            <div style={{ fontSize: "2rem", fontWeight: "800", color: "var(--accent-cyan)" }}>
              {totalFilesScanned}
            </div>
          </div>

          <div className="glass-panel" style={{ padding: "1.5rem", borderRadius: "12px", borderLeft: "4px solid #ff9900" }}>
            <div style={{ color: "var(--text-muted)", fontSize: "0.85rem", textTransform: "uppercase", letterSpacing: "1px", marginBottom: "0.5rem" }}>
              Hidden Files
            </div>
            <div style={{ fontSize: "2rem", fontWeight: "800", color: "#ff9900" }}>
              {hiddenFilesCount}
            </div>
          </div>

          <div className="glass-panel" style={{ padding: "1.5rem", borderRadius: "12px", borderLeft: "4px solid #ff3366" }}>
            <div style={{ color: "var(--text-muted)", fontSize: "0.85rem", textTransform: "uppercase", letterSpacing: "1px", marginBottom: "0.5rem" }}>
              Executable Binaries
            </div>
            <div style={{ fontSize: "2rem", fontWeight: "800", color: "#ff3366" }}>
              {executablesCount}
            </div>
          </div>

          <div className="glass-panel" style={{ padding: "1.5rem", borderRadius: "12px", borderLeft: "4px solid #00ffaa" }}>
            <div style={{ color: "var(--text-muted)", fontSize: "0.85rem", textTransform: "uppercase", letterSpacing: "1px", marginBottom: "0.5rem" }}>
              Forensic Status
            </div>
            <div style={{ fontSize: "1.2rem", fontWeight: "700", color: "#00ffaa", marginTop: "0.5rem" }}>
              Evidence Collection Active
            </div>
          </div>
        </div>

        {/* Filter Control Panel */}
        <div className="glass-panel" style={{ padding: "1.5rem", borderRadius: "12px", marginBottom: "2rem" }}>
          <div style={{ fontWeight: "700", marginBottom: "1rem", color: "var(--accent-cyan)", fontSize: "0.95rem" }}>
            🔍 SEARCH & FORENSIC FILTERS
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "1rem", alignItems: "end" }}>
            
            {/* Search Input */}
            <div>
              <label style={{ display: "block", fontSize: "0.8rem", color: "var(--text-muted)", marginBottom: "0.4rem" }}>
                Search File Name / Path
              </label>
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => { setSearchQuery(e.target.value); setPage(1); }}
                placeholder="e.g. setup.exe or /Tools..."
                style={{
                  width: "100%",
                  padding: "0.6rem 0.8rem",
                  background: "rgba(0, 0, 0, 0.4)",
                  border: "1px solid rgba(0, 240, 255, 0.2)",
                  borderRadius: "6px",
                  color: "var(--text-main)",
                  outline: "none"
                }}
              />
            </div>

            {/* Extension Filter */}
            <div>
              <label style={{ display: "block", fontSize: "0.8rem", color: "var(--text-muted)", marginBottom: "0.4rem" }}>
                File Extension
              </label>
              <select
                value={selectedExtension}
                onChange={(e) => { setSelectedExtension(e.target.value); setPage(1); }}
                style={{
                  width: "100%",
                  padding: "0.6rem 0.8rem",
                  background: "rgba(0, 0, 0, 0.4)",
                  border: "1px solid rgba(0, 240, 255, 0.2)",
                  borderRadius: "6px",
                  color: "var(--text-main)",
                  outline: "none"
                }}
              >
                <option value="">All Extensions</option>
                <option value=".exe">.exe (Executables)</option>
                <option value=".dll">.dll (Dynamic Libraries)</option>
                <option value=".pdf">.pdf (PDF Documents)</option>
                <option value=".docx">.docx (Word Documents)</option>
                <option value=".xlsx">.xlsx (Excel Sheets)</option>
                <option value=".txt">.txt (Text Files)</option>
                <option value=".inf">.inf (Setup Information)</option>
                <option value=".zip">.zip (Archives)</option>
              </select>
            </div>

            {/* Hidden Files Filter */}
            <div>
              <label style={{ display: "block", fontSize: "0.8rem", color: "var(--text-muted)", marginBottom: "0.4rem" }}>
                Hidden Attribute
              </label>
              <select
                value={hiddenFilter}
                onChange={(e) => { setHiddenFilter(e.target.value); setPage(1); }}
                style={{
                  width: "100%",
                  padding: "0.6rem 0.8rem",
                  background: "rgba(0, 0, 0, 0.4)",
                  border: "1px solid rgba(0, 240, 255, 0.2)",
                  borderRadius: "6px",
                  color: "var(--text-main)",
                  outline: "none"
                }}
              >
                <option value="ALL">All Files</option>
                <option value="HIDDEN">Hidden Only (is_hidden: true)</option>
                <option value="VISIBLE">Visible Only (is_hidden: false)</option>
              </select>
            </div>

            {/* USB Event / Device Filter */}
            <div>
              <label style={{ display: "block", fontSize: "0.8rem", color: "var(--text-muted)", marginBottom: "0.4rem" }}>
                USB Event / Drive
              </label>
              <select
                value={selectedUsbEventId}
                onChange={(e) => { setSelectedUsbEventId(e.target.value); setPage(1); }}
                style={{
                  width: "100%",
                  padding: "0.6rem 0.8rem",
                  background: "rgba(0, 0, 0, 0.4)",
                  border: "1px solid rgba(0, 240, 255, 0.2)",
                  borderRadius: "6px",
                  color: "var(--text-main)",
                  outline: "none"
                }}
              >
                <option value="">All USB Events</option>
                {usbEvents.map((evt) => (
                  <option key={evt.id} value={evt.id}>
                    {evt.drive_letter || 'USB'} — {evt.volume_label || 'Unnamed'} ({evt.id.substring(0, 8)})
                  </option>
                ))}
              </select>
            </div>

            {/* Reset Button */}
            <div>
              <button
                onClick={resetFilters}
                style={{
                  width: "100%",
                  padding: "0.6rem 1rem",
                  background: "rgba(255, 255, 255, 0.05)",
                  border: "1px solid rgba(255, 255, 255, 0.2)",
                  color: "var(--text-main)",
                  borderRadius: "6px",
                  cursor: "pointer",
                  fontWeight: "600",
                  fontSize: "0.85rem"
                }}
              >
                Reset Filters
              </button>
            </div>

          </div>
        </div>

        {/* Error Notification */}
        {error && (
          <div style={{ padding: "1rem", background: "rgba(255, 0, 85, 0.15)", border: "1px solid #ff3366", color: "#ff3366", borderRadius: "8px", marginBottom: "1.5rem" }}>
            {error}
          </div>
        )}

        {/* Scan Results Data Table */}
        <div className="glass-panel" style={{ borderRadius: "12px", overflow: "hidden" }}>
          <div style={{ padding: "1rem 1.5rem", borderBottom: "1px solid rgba(255, 255, 255, 0.1)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <h3 style={{ fontSize: "1.1rem", fontWeight: "700" }}>
              USB Scanned Files Inventory
            </h3>
            {copiedHash && (
              <span style={{ background: "rgba(0, 255, 170, 0.2)", color: "#00ffaa", padding: "0.2rem 0.6rem", borderRadius: "4px", fontSize: "0.8rem", fontWeight: "600" }}>
                ✓ SHA-256 copied to clipboard!
              </span>
            )}
          </div>

          {loading ? (
            <div style={{ padding: "3rem", textAlign: "center", color: "var(--accent-cyan)" }}>
              Loading USB scan results...
            </div>
          ) : scans.length === 0 ? (
            <div style={{ padding: "3rem", textAlign: "center", color: "var(--text-muted)" }}>
              No scanned files found matching current filter criteria.
            </div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left", fontSize: "0.9rem" }}>
                <thead>
                  <tr style={{ background: "rgba(0, 0, 0, 0.4)", color: "var(--text-muted)", borderBottom: "1px solid rgba(255, 255, 255, 0.1)" }}>
                    <th style={{ padding: "1rem 1.5rem" }}>File</th>
                    <th style={{ padding: "1rem 1rem" }}>Extension</th>
                    <th style={{ padding: "1rem 1rem" }}>Size</th>
                    <th style={{ padding: "1rem 1rem" }}>Hidden</th>
                    <th style={{ padding: "1rem 1.5rem" }}>SHA-256 Cryptographic Hash</th>
                    <th style={{ padding: "1rem 1.5rem" }}>Scanned At</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.map((item) => (
                    <tr
                      key={item.id}
                      style={{
                        borderBottom: "1px solid rgba(255, 255, 255, 0.05)",
                        transition: "background 0.2s"
                      }}
                    >
                      {/* File Name & Path */}
                      <td style={{ padding: "1rem 1.5rem" }}>
                        <div style={{ fontWeight: "700", color: "var(--text-main)", wordBreak: "break-all" }}>
                          {item.file_name}
                        </div>
                        <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginTop: "0.2rem", wordBreak: "break-all" }}>
                          {item.full_path}
                        </div>
                      </td>

                      {/* Extension */}
                      <td style={{ padding: "1rem 1rem" }}>
                        <span
                          style={{
                            background: item.extension?.toLowerCase() === ".exe" ? "rgba(255, 0, 136, 0.15)" : "rgba(0, 240, 255, 0.1)",
                            color: item.extension?.toLowerCase() === ".exe" ? "#ff0088" : "var(--accent-cyan)",
                            border: `1px solid ${item.extension?.toLowerCase() === ".exe" ? "rgba(255, 0, 136, 0.3)" : "rgba(0, 240, 255, 0.3)"}`,
                            padding: "0.2rem 0.5rem",
                            borderRadius: "4px",
                            fontSize: "0.78rem",
                            fontFamily: "var(--font-mono)",
                            fontWeight: "600"
                          }}
                        >
                          {item.extension || "N/A"}
                        </span>
                      </td>

                      {/* Size */}
                      <td style={{ padding: "1rem 1rem", fontFamily: "var(--font-mono)" }}>
                        {formatBytes(item.file_size)}
                      </td>

                      {/* Hidden Status */}
                      <td style={{ padding: "1rem 1rem" }}>
                        <span
                          style={{
                            background: item.is_hidden ? "rgba(255, 153, 0, 0.15)" : "rgba(255, 255, 255, 0.05)",
                            color: item.is_hidden ? "#ff9900" : "var(--text-muted)",
                            border: `1px solid ${item.is_hidden ? "rgba(255, 153, 0, 0.3)" : "rgba(255, 255, 255, 0.1)"}`,
                            padding: "0.2rem 0.6rem",
                            borderRadius: "4px",
                            fontSize: "0.75rem",
                            fontWeight: "700"
                          }}
                        >
                          {item.is_hidden ? "YES" : "NO"}
                        </span>
                      </td>

                      {/* SHA-256 */}
                      <td style={{ padding: "1rem 1.5rem" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                          <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.8rem", color: "var(--accent-cyan)", background: "rgba(0, 0, 0, 0.5)", padding: "0.3rem 0.6rem", borderRadius: "4px" }}>
                            {item.sha256 ? `${item.sha256.substring(0, 16)}...${item.sha256.substring(item.sha256.length - 8)}` : "N/A"}
                          </span>
                          {item.sha256 && (
                            <button
                              onClick={() => copyToClipboard(item.sha256)}
                              title="Copy SHA-256 Hash"
                              style={{
                                background: "none",
                                border: "1px solid rgba(0, 240, 255, 0.2)",
                                color: "var(--accent-cyan)",
                                padding: "0.2rem 0.4rem",
                                borderRadius: "4px",
                                cursor: "pointer",
                                fontSize: "0.75rem"
                              }}
                            >
                              📋
                            </button>
                          )}
                        </div>
                      </td>

                      {/* Scanned At */}
                      <td style={{ padding: "1rem 1.5rem", fontSize: "0.8rem", color: "var(--text-muted)" }}>
                        {formatDate(item.scanned_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Pagination Controls */}
          <div style={{ padding: "1rem 1.5rem", borderTop: "1px solid rgba(255, 255, 255, 0.1)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <span style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>Items per page:</span>
              <select
                value={limit}
                onChange={(e) => { setLimit(Number(e.target.value)); setPage(1); }}
                style={{
                  padding: "0.3rem 0.6rem",
                  background: "rgba(0, 0, 0, 0.4)",
                  border: "1px solid rgba(0, 240, 255, 0.2)",
                  borderRadius: "4px",
                  color: "var(--text-main)",
                  outline: "none"
                }}
              >
                <option value={10}>10</option>
                <option value={25}>25</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
              </select>
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
              <button
                disabled={page <= 1}
                onClick={() => setPage(page - 1)}
                style={{
                  padding: "0.4rem 0.8rem",
                  background: page <= 1 ? "rgba(255, 255, 255, 0.05)" : "rgba(0, 240, 255, 0.1)",
                  border: "1px solid rgba(0, 240, 255, 0.3)",
                  color: page <= 1 ? "var(--text-muted)" : "var(--accent-cyan)",
                  borderRadius: "6px",
                  cursor: page <= 1 ? "not-allowed" : "pointer",
                  fontWeight: "600"
                }}
              >
                Previous
              </button>
              <span style={{ fontSize: "0.85rem", fontWeight: "600" }}>
                Page {page}
              </span>
              <button
                disabled={scans.length < limit}
                onClick={() => setPage(page + 1)}
                style={{
                  padding: "0.4rem 0.8rem",
                  background: scans.length < limit ? "rgba(255, 255, 255, 0.05)" : "rgba(0, 240, 255, 0.1)",
                  border: "1px solid rgba(0, 240, 255, 0.3)",
                  color: scans.length < limit ? "var(--text-muted)" : "var(--accent-cyan)",
                  borderRadius: "6px",
                  cursor: scans.length < limit ? "not-allowed" : "pointer",
                  fontWeight: "600"
                }}
              >
                Next
              </button>
            </div>
          </div>

        </div>
      </main>
    </div>
  );
};
