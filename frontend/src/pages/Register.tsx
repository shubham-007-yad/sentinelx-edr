import React from "react";
import { Link } from "react-router-dom";

export const Register: React.FC = () => {
  return (
    <div style={{ display: "flex", minHeight: "100vh", alignItems: "center", justifyContent: "center", padding: "1rem" }}>
      <div className="glass-panel glow-effect" style={{ width: "100%", maxWidth: "460px", padding: "2.5rem", textAlign: "center" }}>
        <div style={{ marginBottom: "1.5rem" }}>
          <div style={{ fontSize: "2rem", fontWeight: "800", letterSpacing: "1px", color: "var(--accent-cyan)" }}>
            SENTINEL<span style={{ color: "var(--text-main)" }}>X</span> EDR
          </div>
          <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", marginTop: "0.4rem" }}>
            Endpoint Detection & Response Platform
          </p>
        </div>

        <div style={{
          background: "rgba(255, 170, 0, 0.1)",
          border: "1px solid rgba(255, 170, 0, 0.4)",
          color: "#ffaa00",
          padding: "1.25rem",
          borderRadius: "8px",
          fontSize: "0.9rem",
          marginBottom: "2rem",
          lineHeight: "1.5"
        }}>
          <strong>🔒 Public Registration Disabled</strong>
          <p style={{ margin: "0.5rem 0 0 0", fontSize: "0.85rem", color: "var(--text-muted)" }}>
            Public registration is disabled. Please contact your SentinelX administrator if you need access.
          </p>
        </div>

        <Link to="/login" className="btn-primary" style={{ display: "inline-block", textDecoration: "none", width: "100%" }}>
          Return to Sign In
        </Link>
      </div>
    </div>
  );
};
