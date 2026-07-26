import React, { useState } from "react";
import { useAuth } from "../context/AuthContext";
import { useNavigate } from "react-router-dom";

export const Login: React.FC = () => {
  const { login } = useAuth();
  const navigate = useNavigate();

  const [usernameOrEmail, setUsernameOrEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setIsSubmitting(true);

    try {
      await login(usernameOrEmail, password);
      navigate("/dashboard");
    } catch (err: any) {
      setError(err.response?.data?.detail || "Authentication failed. Please check your credentials.");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div style={{ display: "flex", minHeight: "100vh", alignItems: "center", justifyContent: "center", padding: "1rem" }}>
      <div className="glass-panel glow-effect" style={{ width: "100%", maxWidth: "420px", padding: "2.5rem" }}>
        <div style={{ textAlign: "center", marginBottom: "2rem" }}>
          <div style={{ fontSize: "2rem", fontWeight: "800", letterSpacing: "1px", color: "var(--accent-cyan)" }}>
            SENTINEL<span style={{ color: "var(--text-main)" }}>X</span> EDR
          </div>
          <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", marginTop: "0.4rem" }}>
            Endpoint Detection & Response Platform
          </p>
        </div>

        {error && (
          <div style={{ background: "rgba(255, 0, 85, 0.15)", border: "1px solid var(--accent-danger)", color: "var(--accent-danger)", padding: "0.75rem", borderRadius: "6px", fontSize: "0.85rem", marginBottom: "1.5rem" }}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
          <div>
            <label style={{ display: "block", fontSize: "0.8rem", color: "var(--text-muted)", marginBottom: "0.4rem", textTransform: "uppercase", letterSpacing: "0.5px" }}>
              Username or Email
            </label>
            <input
              type="text"
              className="input-field"
              value={usernameOrEmail}
              onChange={(e) => setUsernameOrEmail(e.target.value)}
              placeholder="e.g. analyst or analyst@sentinelx.io"
              required
            />
          </div>

          <div>
            <label style={{ display: "block", fontSize: "0.8rem", color: "var(--text-muted)", marginBottom: "0.4rem", textTransform: "uppercase", letterSpacing: "0.5px" }}>
              Password
            </label>
            <input
              type="password"
              className="input-field"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              required
            />
          </div>

          <button type="submit" className="btn-primary" disabled={isSubmitting} style={{ marginTop: "0.5rem" }}>
            {isSubmitting ? "Authenticating..." : "Sign In"}
          </button>
        </form>

        <div style={{ textAlign: "center", marginTop: "1.5rem", fontSize: "0.85rem", color: "var(--text-muted)", lineHeight: "1.4" }}>
          Public registration is disabled.<br />
          Please contact your SentinelX administrator if you need access.
        </div>
      </div>
    </div>
  );
};
