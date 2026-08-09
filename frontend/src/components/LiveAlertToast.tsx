import React, { useState, useEffect } from "react";
import { useWebSocket, type LiveAlertPayload } from "../context/WebSocketContext";
import { markAlertRead } from "../services/alert";

const SingleToastCard: React.FC<{
  toast: LiveAlertPayload;
  onDismiss: () => void;
  onOpenDetails: (toast: LiveAlertPayload) => void;
}> = ({ toast, onDismiss, onOpenDetails }) => {
  useEffect(() => {
    const timer = setTimeout(() => {
      onDismiss();
    }, 6000); // 6 seconds auto-dismiss
    return () => clearTimeout(timer);
  }, [onDismiss]);

  const getSeverityIcon = (severity?: string) => {
    switch ((severity || "").toUpperCase()) {
      case "CRITICAL":
        return "⚠️";
      case "HIGH":
        return "🚨";
      case "MEDIUM":
        return "⚡";
      default:
        return "ℹ️";
    }
  };

  const getSeverityColor = (severity?: string) => {
    switch ((severity || "").toUpperCase()) {
      case "CRITICAL":
        return "#ff0055";
      case "HIGH":
        return "#ffaa00";
      case "MEDIUM":
        return "#00f0ff";
      default:
        return "#a0a0b0";
    }
  };

  const severityColor = getSeverityColor(toast.severity);

  return (
    <div
      onClick={() => onOpenDetails(toast)}
      style={{
        pointerEvents: "auto",
        background: "rgba(15, 20, 32, 0.95)",
        backdropFilter: "blur(14px)",
        borderLeft: `6px solid ${severityColor}`,
        border: `1px solid rgba(255, 255, 255, 0.12)`,
        borderRadius: "8px",
        padding: "1rem",
        boxShadow: `0 8px 32px rgba(0, 0, 0, 0.6), 0 0 16px ${severityColor}44`,
        color: "#ffffff",
        cursor: "pointer",
        transition: "transform 0.2s ease, boxShadow 0.2s ease",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.4rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <span style={{ fontSize: "1.1rem" }}>{getSeverityIcon(toast.severity)}</span>
          <span style={{ fontWeight: "700", fontSize: "0.95rem", color: severityColor }}>
            {toast.title}
          </span>
        </div>
        <button
          onClick={(e) => {
            e.stopPropagation();
            onDismiss();
          }}
          style={{
            background: "transparent",
            border: "none",
            color: "#aaa",
            fontSize: "1.1rem",
            cursor: "pointer",
            padding: "0 0.2rem",
            lineHeight: "1",
          }}
        >
          ✕
        </button>
      </div>

      <div style={{ fontSize: "0.9rem", fontWeight: "600", color: "#e0e0e0", margin: "0.3rem 0", fontFamily: "var(--font-mono)" }}>
        {toast.file || "Unknown file"}
      </div>

      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "0.8rem", color: "var(--text-muted)", marginTop: "0.4rem" }}>
        <div>
          <span>Device: </span>
          <strong style={{ color: "var(--accent-cyan)", fontFamily: "var(--font-mono)" }}>{toast.device}</strong>
        </div>
        <span style={{ fontSize: "0.7rem", fontFamily: "var(--font-mono)", color: "#666" }}>
          Click for details
        </span>
      </div>
    </div>
  );
};

export const LiveAlertToast: React.FC = () => {
  const { activeToasts, dismissToast } = useWebSocket();
  const [selectedToast, setSelectedToast] = useState<LiveAlertPayload | null>(null);

  if (activeToasts.length === 0 && !selectedToast) return null;

  const handleMarkReadInModal = async (toast: LiveAlertPayload) => {
    if (toast.id) {
      try {
        await markAlertRead(toast.id);
      } catch (err) {
        console.error("Failed to mark alert as read:", err);
      }
    }
    setSelectedToast(null);
  };

  return (
    <>
      {/* Toast Notification Queue fixed at top right */}
      <div
        style={{
          position: "fixed",
          top: "20px",
          right: "20px",
          zIndex: 9999,
          display: "flex",
          flexDirection: "column",
          gap: "12px",
          maxWidth: "420px",
          width: "90%",
          pointerEvents: "none",
        }}
      >
        {activeToasts.slice(0, 5).map((toast: LiveAlertPayload, index: number) => (
          <SingleToastCard
            key={index}
            toast={toast}
            onDismiss={() => dismissToast(index)}
            onOpenDetails={(t) => setSelectedToast(t)}
          />
        ))}
      </div>

      {/* Alert Detail Modal */}
      {selectedToast && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: "rgba(0, 0, 0, 0.75)",
            backdropFilter: "blur(8px)",
            zIndex: 10000,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: "1rem",
          }}
        >
          <div
            className="glass-panel"
            style={{
              maxWidth: "540px",
              width: "100%",
              padding: "2rem",
              background: "rgba(15, 20, 32, 0.95)",
              border: "1px solid rgba(0, 240, 255, 0.3)",
              borderRadius: "12px",
              boxShadow: "0 20px 50px rgba(0, 0, 0, 0.8), 0 0 30px rgba(0, 240, 255, 0.15)",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "1.5rem" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "0.8rem" }}>
                <span style={{ fontSize: "1.5rem" }}>⚠️</span>
                <div>
                  <h3 style={{ fontSize: "1.2rem", fontWeight: "700", color: "var(--accent-cyan)", margin: 0 }}>
                    {selectedToast.title}
                  </h3>
                  <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.2rem" }}>
                    Real-Time Security Alert Details
                  </div>
                </div>
              </div>
              <button
                onClick={() => setSelectedToast(null)}
                style={{ background: "transparent", border: "none", color: "#aaa", fontSize: "1.2rem", cursor: "pointer" }}
              >
                ✕
              </button>
            </div>

            <div style={{ display: "grid", gap: "1rem", marginBottom: "1.5rem" }}>
              <div style={{ background: "rgba(255, 255, 255, 0.03)", padding: "1rem", borderRadius: "8px", border: "1px solid rgba(255, 255, 255, 0.08)" }}>
                <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase" }}>TARGET FILE</div>
                <div style={{ fontSize: "1rem", fontWeight: "700", color: "#fff", fontFamily: "var(--font-mono)", marginTop: "0.3rem" }}>
                  {selectedToast.file}
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
                <div style={{ background: "rgba(255, 255, 255, 0.03)", padding: "1rem", borderRadius: "8px", border: "1px solid rgba(255, 255, 255, 0.08)" }}>
                  <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase" }}>TARGET DEVICE</div>
                  <div style={{ fontSize: "0.95rem", fontWeight: "700", color: "var(--accent-cyan)", fontFamily: "var(--font-mono)", marginTop: "0.3rem" }}>
                    {selectedToast.device}
                  </div>
                </div>

                <div style={{ background: "rgba(255, 255, 255, 0.03)", padding: "1rem", borderRadius: "8px", border: "1px solid rgba(255, 255, 255, 0.08)" }}>
                  <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase" }}>SEVERITY LEVEL</div>
                  <div style={{ marginTop: "0.3rem" }}>
                    <span className={`badge badge-${selectedToast.severity?.toLowerCase()}`}>
                      {selectedToast.severity}
                    </span>
                  </div>
                </div>
              </div>

              {selectedToast.message && (
                <div style={{ background: "rgba(255, 255, 255, 0.03)", padding: "1rem", borderRadius: "8px", border: "1px solid rgba(255, 255, 255, 0.08)" }}>
                  <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase" }}>THREAT DESCRIPTION</div>
                  <p style={{ fontSize: "0.85rem", color: "#ddd", marginTop: "0.4rem", lineHeight: "1.5" }}>
                    {selectedToast.message}
                  </p>
                </div>
              )}

              <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                DETECTED AT: {new Date(selectedToast.time || selectedToast.created_at || "").toLocaleString()}
              </div>
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end", gap: "1rem" }}>
              <button
                onClick={() => setSelectedToast(null)}
                style={{
                  background: "rgba(255, 255, 255, 0.1)",
                  border: "1px solid rgba(255, 255, 255, 0.2)",
                  color: "#fff",
                  padding: "0.5rem 1rem",
                  borderRadius: "6px",
                  cursor: "pointer",
                  fontWeight: "600",
                  fontSize: "0.85rem",
                }}
              >
                Close
              </button>
              <button
                onClick={() => handleMarkReadInModal(selectedToast)}
                style={{
                  background: "rgba(0, 240, 255, 0.2)",
                  border: "1px solid var(--accent-cyan)",
                  color: "var(--accent-cyan)",
                  padding: "0.5rem 1rem",
                  borderRadius: "6px",
                  cursor: "pointer",
                  fontWeight: "600",
                  fontSize: "0.85rem",
                }}
              >
                Mark as Read
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
