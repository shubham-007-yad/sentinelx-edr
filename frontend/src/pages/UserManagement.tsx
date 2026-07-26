import React, { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import { api } from "../services/api";
import type { User, UserRole } from "../types/auth";
import { Link } from "react-router-dom";

export const UserManagement: React.FC = () => {
  const { user: currentUser, logout } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string>("");
  const [success, setSuccess] = useState<string>("");

  // New User Form State
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<UserRole>("ANALYST");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const fetchUsers = async () => {
    try {
      setLoading(true);
      const res = await api.get<User[]>("/users");
      setUsers(res.data);
    } catch (err: any) {
      setError(err.response?.data?.detail || "Failed to load user roster.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSuccess("");
    setIsSubmitting(true);

    try {
      await api.post("/users", { email, username, password, role });
      setSuccess(`User '${username}' created successfully as ${role}.`);
      setEmail("");
      setUsername("");
      setPassword("");
      setRole("ANALYST");
      fetchUsers();
    } catch (err: any) {
      const detail = err.response?.data?.detail;
      setError(Array.isArray(detail) ? detail.map((d: any) => d.msg).join(" | ") : detail || "Failed to create user.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRoleChange = async (userId: string, newRole: UserRole) => {
    try {
      await api.patch(`/users/${userId}`, { role: newRole });
      setSuccess("User role updated successfully.");
      fetchUsers();
    } catch (err: any) {
      setError(err.response?.data?.detail || "Failed to update user role.");
    }
  };

  const handleToggleActive = async (userId: string, currentStatus: boolean) => {
    try {
      await api.patch(`/users/${userId}`, { is_active: !currentStatus });
      setSuccess(`User status updated to ${!currentStatus ? "Active" : "Inactive"}.`);
      fetchUsers();
    } catch (err: any) {
      setError(err.response?.data?.detail || "Failed to update user status.");
    }
  };

  const handleDeleteUser = async (userId: string, username: string) => {
    if (!window.confirm(`Are you sure you want to delete user '${username}'?`)) return;
    try {
      await api.delete(`/users/${userId}`);
      setSuccess(`User '${username}' deleted successfully.`);
      fetchUsers();
    } catch (err: any) {
      setError(err.response?.data?.detail || "Failed to delete user.");
    }
  };

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg-primary)", color: "var(--text-main)", padding: "1.5rem 2rem" }}>
      {/* Top Header Navigation */}
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "2rem", borderBottom: "1px solid var(--border-color)", paddingBottom: "1rem" }}>
        <div>
          <div style={{ fontSize: "1.5rem", fontWeight: "800", letterSpacing: "1px", color: "var(--accent-cyan)" }}>
            SENTINEL<span style={{ color: "var(--text-main)" }}>X</span> EDR
          </div>
          <span style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>Admin User Access Management</span>
        </div>

        <div style={{ display: "flex", gap: "1rem", alignItems: "center" }}>
          <Link to="/dashboard" className="btn-secondary" style={{ textDecoration: "none", fontSize: "0.85rem", padding: "0.5rem 1rem" }}>
            📊 Executive Dashboard
          </Link>
          <Link to="/usb-activity" className="btn-secondary" style={{ textDecoration: "none", fontSize: "0.85rem", padding: "0.5rem 1rem" }}>
            🔌 USB Activity Console
          </Link>
          <button onClick={logout} className="btn-danger" style={{ fontSize: "0.85rem", padding: "0.5rem 1rem" }}>
            Sign Out
          </button>
        </div>
      </header>

      {/* Main Grid */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: "2rem" }}>
        
        {/* Create User Form Panel */}
        <div className="glass-panel" style={{ padding: "1.5rem" }}>
          <h3 style={{ fontSize: "1.1rem", marginBottom: "1rem", color: "var(--accent-cyan)" }}>
            ➕ Provision New User Account
          </h3>

          {error && (
            <div style={{ background: "rgba(255, 0, 85, 0.15)", border: "1px solid var(--accent-danger)", color: "var(--accent-danger)", padding: "0.75rem", borderRadius: "6px", fontSize: "0.85rem", marginBottom: "1rem" }}>
              {error}
            </div>
          )}

          {success && (
            <div style={{ background: "rgba(0, 255, 136, 0.15)", border: "1px solid var(--accent-success)", color: "var(--accent-success)", padding: "0.75rem", borderRadius: "6px", fontSize: "0.85rem", marginBottom: "1rem" }}>
              {success}
            </div>
          )}

          <form onSubmit={handleCreateUser} style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
            <div>
              <label style={{ display: "block", fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "0.3rem" }}>EMAIL ADDRESS</label>
              <input
                type="email"
                className="input-field"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@company.com"
                required
              />
            </div>

            <div>
              <label style={{ display: "block", fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "0.3rem" }}>USERNAME</label>
              <input
                type="text"
                className="input-field"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="username"
                required
              />
            </div>

            <div>
              <label style={{ display: "block", fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "0.3rem" }}>ASSIGN ROLE</label>
              <select className="input-field" value={role} onChange={(e) => setRole(e.target.value as UserRole)}>
                <option value="ANALYST">ANALYST (Security Operations)</option>
                <option value="ADMIN">ADMIN (Full System Controls)</option>
                <option value="VIEWER">VIEWER (Read-Only Access)</option>
              </select>
            </div>

            <div>
              <label style={{ display: "block", fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "0.3rem" }}>INITIAL PASSWORD</label>
              <input
                type="password"
                className="input-field"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Min 8 chars, 1 Upper, 1 Special"
                required
              />
            </div>

            <button type="submit" className="btn-primary" disabled={isSubmitting} style={{ marginTop: "0.5rem" }}>
              {isSubmitting ? "Provisioning..." : "Provision Account"}
            </button>
          </form>
        </div>

        {/* User Roster Table */}
        <div className="glass-panel" style={{ padding: "1.5rem" }}>
          <h3 style={{ fontSize: "1.1rem", marginBottom: "1rem", color: "var(--accent-cyan)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span>👥 Active User Roster ({users.length})</span>
            <button onClick={fetchUsers} className="btn-secondary" style={{ fontSize: "0.75rem", padding: "0.3rem 0.6rem" }}>
              🔄 Refresh
            </button>
          </h3>

          {loading ? (
            <div style={{ color: "var(--text-muted)", padding: "2rem", textAlign: "center" }}>Loading users...</div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left", fontSize: "0.85rem" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid var(--border-color)", color: "var(--text-muted)" }}>
                    <th style={{ padding: "0.75rem 0.5rem" }}>USER</th>
                    <th style={{ padding: "0.75rem 0.5rem" }}>ROLE</th>
                    <th style={{ padding: "0.75rem 0.5rem" }}>STATUS</th>
                    <th style={{ padding: "0.75rem 0.5rem", textAlign: "right" }}>ACTIONS</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => (
                    <tr key={u.id} style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                      <td style={{ padding: "0.75rem 0.5rem" }}>
                        <div style={{ fontWeight: "600" }}>{u.username}</div>
                        <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>{u.email}</div>
                      </td>
                      <td style={{ padding: "0.75rem 0.5rem" }}>
                        <select
                          className="input-field"
                          value={u.role}
                          onChange={(e) => handleRoleChange(u.id, e.target.value as UserRole)}
                          style={{ padding: "0.2rem 0.4rem", fontSize: "0.8rem", width: "auto" }}
                        >
                          <option value="ADMIN">ADMIN</option>
                          <option value="ANALYST">ANALYST</option>
                          <option value="VIEWER">VIEWER</option>
                        </select>
                      </td>
                      <td style={{ padding: "0.75rem 0.5rem" }}>
                        <button
                          onClick={() => handleToggleActive(u.id, u.is_active)}
                          style={{
                            background: u.is_active ? "rgba(0, 255, 136, 0.15)" : "rgba(255, 0, 85, 0.15)",
                            color: u.is_active ? "var(--accent-success)" : "var(--accent-danger)",
                            border: `1px solid ${u.is_active ? "var(--accent-success)" : "var(--accent-danger)"}`,
                            padding: "0.2rem 0.5rem",
                            borderRadius: "4px",
                            fontSize: "0.75rem",
                            cursor: "pointer"
                          }}
                        >
                          {u.is_active ? "Active" : "Disabled"}
                        </button>
                      </td>
                      <td style={{ padding: "0.75rem 0.5rem", textAlign: "right" }}>
                        {u.id !== currentUser?.id ? (
                          <button
                            onClick={() => handleDeleteUser(u.id, u.username)}
                            className="btn-danger"
                            style={{ padding: "0.25rem 0.5rem", fontSize: "0.75rem" }}
                          >
                            Delete
                          </button>
                        ) : (
                          <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>(You)</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

      </div>
    </div>
  );
};
