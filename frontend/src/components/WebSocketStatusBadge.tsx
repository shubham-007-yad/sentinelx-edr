import React from "react";
import { useWebSocket } from "../context/WebSocketContext";

export const WebSocketStatusBadge: React.FC = () => {
  const { isConnected } = useWebSocket();

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: "0.5rem",
        background: isConnected ? "rgba(0, 255, 157, 0.1)" : "rgba(255, 170, 0, 0.1)",
        border: `1px solid ${isConnected ? "rgba(0, 255, 157, 0.4)" : "rgba(255, 170, 0, 0.4)"}`,
        color: isConnected ? "#00ff9d" : "#ffaa00",
        padding: "0.2rem 0.6rem",
        borderRadius: "4px",
        fontSize: "0.75rem",
        fontFamily: "var(--font-mono)",
        fontWeight: "600",
        whiteSpace: "nowrap",
        flexShrink: 0,
      }}
    >
      <span
        style={{
          width: "8px",
          height: "8px",
          borderRadius: "50%",
          background: isConnected ? "#00ff9d" : "#ffaa00",
          boxShadow: isConnected ? "0 0 8px #00ff9d" : "0 0 8px #ffaa00",
          animation: isConnected ? "pulse 2s infinite" : "none",
        }}
      />
      {isConnected ? "LIVE WS CONNECTED" : "RECONNECTING WS..."}
    </div>
  );
};
