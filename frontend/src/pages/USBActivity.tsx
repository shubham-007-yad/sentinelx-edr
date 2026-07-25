import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { getUsbEvents, getDevices } from "../services/usb";
import type { USBEvent, Device } from "../types/usb";

export const USBActivity: React.FC = () => {
  const { user, logout } = useAuth();

  const [events, setEvents] = useState<USBEvent[]>([]);
  const [devicesMap, setDevicesMap] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Pagination state
  const [page, setPage] = useState<number>(1);
  const [limit, setLimit] = useState<number>(10);
  const [selectedDevice, setSelectedDevice] = useState<string>("");
  const [selectedEventType, setSelectedEventType] = useState<string>("");

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      // Fetch devices to map device_id -> hostname
      const devicesData = await getDevices();
      const map: Record<string, string> = {};
      devicesData.forEach((d: Device) => {
        map[d.id] = d.hostname;
      });
      setDevicesMap(map);

      // Fetch USB events with pagination and filters
      const skip = (page - 1) * limit;
      const eventsData = await getUsbEvents(
        skip,
        limit,
        selectedDevice || undefined,
        selectedEventType || undefined
      );
      setEvents(eventsData);
    } catch (err: any) {
      console.error("Failed to fetch USB activity events:", err);
      setError("Failed to load USB events from backend service.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [page, limit, selectedDevice, selectedEventType]);

  const formatBytes = (bytes?: number) => {
    if (!bytes || bytes === 0) return "N/A";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  const formatDate = (isoString: string) => {
    try {
      const d = new Date(isoString);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + " (" + d.toLocaleDateString() + ")";
    } catch {
      return isoString;
    }
  };

  const insertCount = events.filter((e) => e.event_type === "INSERT").length;
  const removeCount = events.filter((e) => e.event_type === "REMOVE").length;

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
              USB Activity
            </Link>
          </nav>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "1.5rem" }}>
          <div style={{ textAlign: "right" }}>
            <div style={{ fontWeight: "600", fontSize: "0.95rem" }}>{user?.username}</div>
            <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>{user?.email}</div>
          </div>

          <span className={`badge badge-${user?.role?.toLowerCase()}`}>
            {user?.role}
          </span>

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
              fontSize: "0.8rem",
            }}
          >
            Logout
          </button>
        </div>
      </header>

      {/* Main Container */}
      <main style={{ maxWidth: "1280px", margin: "0 auto", display: "grid", gap: "2rem" }}>
        {/* Metric Cards */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "1.5rem" }}>
          <div className="glass-panel" style={{ padding: "1.25rem" }}>
            <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: "600" }}>Total Page Events</div>
            <div style={{ fontSize: "1.8rem", fontWeight: "800", color: "var(--accent-cyan)", marginTop: "0.4rem" }}>{events.length}</div>
          </div>

          <div className="glass-panel" style={{ padding: "1.25rem" }}>
            <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: "600" }}>Insertions</div>
            <div style={{ fontSize: "1.8rem", fontWeight: "800", color: "var(--accent-success)", marginTop: "0.4rem" }}>{insertCount}</div>
          </div>

          <div className="glass-panel" style={{ padding: "1.25rem" }}>
            <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: "600" }}>Removals</div>
            <div style={{ fontSize: "1.8rem", fontWeight: "800", color: "var(--accent-danger)", marginTop: "0.4rem" }}>{removeCount}</div>
          </div>

          <div className="glass-panel" style={{ padding: "1.25rem" }}>
            <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: "600" }}>Monitored Endpoints</div>
            <div style={{ fontSize: "1.8rem", fontWeight: "800", color: "var(--text-main)", marginTop: "0.4rem" }}>{Object.keys(devicesMap).length}</div>
          </div>
        </div>

        {/* Filter and Control Bar */}
        <div className="glass-panel" style={{ padding: "1.5rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem", flexWrap: "wrap", gap: "1rem" }}>
            <div>
              <h2 style={{ fontSize: "1.2rem", fontWeight: "700", color: "var(--accent-cyan)" }}>
                USB EVENT LOG AUDIT
              </h2>
              <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", marginTop: "0.2rem" }}>
                Real-time forensic monitoring of USB device attachments and file storage volume metadata.
              </p>
            </div>

            <div style={{ display: "flex", gap: "1rem", alignItems: "center", flexWrap: "wrap" }}>
              {/* Event Type Filter */}
              <select
                value={selectedEventType}
                onChange={(e) => {
                  setSelectedEventType(e.target.value);
                  setPage(1);
                }}
                className="input-field"
                style={{ width: "160px", padding: "0.5rem" }}
              >
                <option value="">All Event Types</option>
                <option value="INSERT">INSERT</option>
                <option value="REMOVE">REMOVE</option>
              </select>

              {/* Device Filter */}
              <select
                value={selectedDevice}
                onChange={(e) => {
                  setSelectedDevice(e.target.value);
                  setPage(1);
                }}
                className="input-field"
                style={{ width: "200px", padding: "0.5rem" }}
              >
                <option value="">All Endpoints</option>
                {Object.entries(devicesMap).map(([id, hostname]) => (
                  <option key={id} value={id}>
                    {hostname} ({id.substring(0, 8)})
                  </option>
                ))}
              </select>

              {/* Limit Selector */}
              <select
                value={limit}
                onChange={(e) => {
                  setLimit(Number(e.target.value));
                  setPage(1);
                }}
                className="input-field"
                style={{ width: "110px", padding: "0.5rem" }}
              >
                <option value={10}>10 / page</option>
                <option value={25}>25 / page</option>
                <option value={50}>50 / page</option>
              </select>

              <button
                onClick={fetchData}
                className="btn-primary"
                style={{ padding: "0.55rem 1rem", fontSize: "0.8rem" }}
              >
                Refresh
              </button>
            </div>
          </div>

          {/* Error display */}
          {error && (
            <div style={{ background: "rgba(255, 0, 85, 0.1)", border: "1px solid var(--accent-danger)", color: "var(--accent-danger)", padding: "0.75rem", borderRadius: "6px", marginBottom: "1rem", fontSize: "0.85rem" }}>
              {error}
            </div>
          )}

          {/* Table View */}
          <div style={{ overflowX: "auto" }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Device</th>
                  <th>Event</th>
                  <th>Drive Letter</th>
                  <th>Volume Label</th>
                  <th>Filesystem</th>
                  <th>Capacity / Free Space</th>
                  <th>Serial Number</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan={8} style={{ textAlign: "center", padding: "2rem", color: "var(--accent-cyan)" }}>
                      Loading USB event records...
                    </td>
                  </tr>
                ) : events.length === 0 ? (
                  <tr>
                    <td colSpan={8} style={{ textAlign: "center", padding: "2.5rem", color: "var(--text-muted)" }}>
                      No USB events recorded matching the current filter.
                    </td>
                  </tr>
                ) : (
                  events.map((evt) => (
                    <tr key={evt.id}>
                      <td style={{ fontFamily: "var(--font-mono)", fontSize: "0.85rem" }}>
                        {formatDate(evt.detected_at)}
                      </td>
                      <td style={{ fontWeight: "600" }}>
                        {devicesMap[evt.device_id] || evt.device_id.substring(0, 8)}
                      </td>
                      <td>
                        <span className={evt.event_type === "INSERT" ? "badge badge-insert" : "badge badge-remove"}>
                          {evt.event_type === "INSERT" ? "Inserted" : "Removed"}
                        </span>
                      </td>
                      <td style={{ fontFamily: "var(--font-mono)", fontWeight: "700", color: "var(--accent-cyan)" }}>
                        {evt.drive_letter || "N/A"}
                      </td>
                      <td>
                        {evt.volume_label || <span style={{ color: "var(--text-subtle)" }}>Unlabeled</span>}
                      </td>
                      <td>
                        {evt.filesystem || <span style={{ color: "var(--text-subtle)" }}>N/A</span>}
                      </td>
                      <td style={{ fontSize: "0.85rem" }}>
                        {evt.total_size ? (
                          <span>
                            {formatBytes(evt.total_size)}
                            {evt.free_space !== undefined && (
                              <span style={{ color: "var(--text-muted)", fontSize: "0.75rem", display: "block" }}>
                                ({formatBytes(evt.free_space)} free)
                              </span>
                            )}
                          </span>
                        ) : (
                          <span style={{ color: "var(--text-subtle)" }}>N/A</span>
                        )}
                      </td>
                      <td style={{ fontFamily: "var(--font-mono)", fontSize: "0.8rem", color: "var(--text-muted)" }}>
                        {evt.serial_number || "N/A"}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination Footer */}
          <div className="pagination-container">
            <div style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
              Page <span style={{ color: "var(--accent-cyan)", fontWeight: "700" }}>{page}</span> (Showing {events.length} items)
            </div>

            <div style={{ display: "flex", gap: "0.5rem" }}>
              <button
                className="pagination-btn"
                onClick={() => setPage((p) => Math.max(p - 1, 1))}
                disabled={page === 1 || loading}
              >
                Previous
              </button>

              <button
                className="pagination-btn"
                onClick={() => setPage((p) => p + 1)}
                disabled={events.length < limit || loading}
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
