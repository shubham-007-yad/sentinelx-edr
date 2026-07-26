import React from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export const Dashboard: React.FC = () => {
  const { user, logout, token } = useAuth();

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

      {/* Main Dashboard Overview */}
      <main style={{ maxWidth: "1200px", margin: "0 auto", display: "grid", gap: "2rem" }}>
        <div className="glass-panel" style={{ padding: "2rem" }}>
          <h2 style={{ fontSize: "1.25rem", fontWeight: "700", marginBottom: "1rem", color: "var(--accent-cyan)" }}>
            AUTHENTICATION LIFECYCLE VERIFIED
          </h2>
          <p style={{ color: "var(--text-muted)", fontSize: "0.9rem", lineHeight: "1.6" }}>
            Your account is authenticated via PostgreSQL-backed Bcrypt hashing and JSON Web Token (JWT) Bearer authorization.
          </p>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "1.5rem", marginTop: "1.5rem" }}>
            <div style={{ background: "rgba(10, 13, 20, 0.8)", padding: "1.25rem", borderRadius: "8px", border: "1px solid rgba(255,255,255,0.08)" }}>
              <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase" }}>UUID User Identifier</div>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.85rem", color: "var(--accent-cyan)", marginTop: "0.4rem", wordBreak: "break-all" }}>
                {user?.id}
              </div>
            </div>

            <div style={{ background: "rgba(10, 13, 20, 0.8)", padding: "1.25rem", borderRadius: "8px", border: "1px solid rgba(255,255,255,0.08)" }}>
              <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase" }}>Assigned System Role</div>
              <div style={{ marginTop: "0.4rem" }}>
                <span className={`badge badge-${user?.role?.toLowerCase()}`}>
                  {user?.role}
                </span>
              </div>
            </div>

            <div style={{ background: "rgba(10, 13, 20, 0.8)", padding: "1.25rem", borderRadius: "8px", border: "1px solid rgba(255,255,255,0.08)" }}>
              <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase" }}>Session JWT Token</div>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.4rem", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {token}
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};
