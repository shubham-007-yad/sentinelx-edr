import React from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider, useAuth } from "./context/AuthContext";
import { WebSocketProvider } from "./context/WebSocketContext";
import { LiveAlertToast } from "./components/LiveAlertToast";
import { Login } from "./pages/Login";
import { Register } from "./pages/Register";
import { Dashboard } from "./pages/Dashboard";
import { USBActivity } from "./pages/USBActivity";
import { USBScanResults } from "./pages/USBScanResults";
import { ThreatDashboard } from "./pages/ThreatDashboard";
import { AlertManagement } from "./pages/AlertManagement";
import { UserManagement } from "./pages/UserManagement";
import { ResponseDashboard } from "./pages/ResponseDashboard";
import { ProcessDashboard } from "./pages/ProcessDashboard";
import { NetworkDashboard } from "./pages/NetworkDashboard";
import { IntegrityDashboard } from "./pages/IntegrityDashboard";
import { EventLogDashboard } from "./pages/EventLogDashboard";
import { RansomwareDashboard } from "./pages/RansomwareDashboard";
import { InvestigationsDashboard } from "./pages/InvestigationsDashboard";
import { PolicyDashboard } from "./pages/PolicyDashboard";
import { FleetManagement } from "./pages/FleetManagement";



const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div style={{ display: "flex", minHeight: "100vh", alignItems: "center", justifyContent: "center", background: "var(--bg-primary)", color: "var(--accent-cyan)" }}>
        Loading SentinelX Security Console...
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
};

const AdminRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { user, isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div style={{ display: "flex", minHeight: "100vh", alignItems: "center", justifyContent: "center", background: "var(--bg-primary)", color: "var(--accent-cyan)" }}>
        Loading SentinelX Security Console...
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  if (user?.role !== "ADMIN") {
    return <Navigate to="/dashboard" replace />;
  }

  return <>{children}</>;
};

export function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <WebSocketProvider>
          <LiveAlertToast />
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
            <Route
              path="/dashboard"
              element={
                <ProtectedRoute>
                  <Dashboard />
                </ProtectedRoute>
              }
            />
            <Route
              path="/investigations"
              element={
                <ProtectedRoute>
                  <InvestigationsDashboard />
                </ProtectedRoute>
              }
            />
            <Route
              path="/threats"
              element={
                <ProtectedRoute>
                  <ThreatDashboard />
                </ProtectedRoute>
              }
            />
            <Route
              path="/alerts"
              element={
                <ProtectedRoute>
                  <AlertManagement />
                </ProtectedRoute>
              }
            />
            <Route
              path="/respond"
              element={
                <ProtectedRoute>
                  <ResponseDashboard />
                </ProtectedRoute>
              }
            />
            <Route
              path="/processes"
              element={
                <ProtectedRoute>
                  <ProcessDashboard />
                </ProtectedRoute>
              }
            />
            <Route
              path="/network"
              element={
                <ProtectedRoute>
                  <NetworkDashboard />
                </ProtectedRoute>
              }
            />
            <Route
              path="/integrity"
              element={
                <ProtectedRoute>
                  <IntegrityDashboard />
                </ProtectedRoute>
              }
            />
            <Route
              path="/events"
              element={
                <ProtectedRoute>
                  <EventLogDashboard />
                </ProtectedRoute>
              }
            />
            <Route
              path="/ransomware"
              element={
                <ProtectedRoute>
                  <RansomwareDashboard />
                </ProtectedRoute>
              }
            />
            <Route
              path="/policies"
              element={
                <ProtectedRoute>
                  <PolicyDashboard />
                </ProtectedRoute>
              }
            />
            <Route
              path="/fleet"
              element={
                <ProtectedRoute>
                  <FleetManagement />
                </ProtectedRoute>
              }
            />


            <Route
              path="/devices"
              element={
                <ProtectedRoute>
                  <FleetManagement />
                </ProtectedRoute>
              }
            />
            <Route
              path="/analytics"
              element={
                <ProtectedRoute>
                  <Dashboard />
                </ProtectedRoute>
              }
            />
            <Route
              path="/threat-intelligence"
              element={
                <ProtectedRoute>
                  <ThreatDashboard />
                </ProtectedRoute>
              }
            />
            <Route
              path="/usb-activity"
              element={
                <ProtectedRoute>
                  <USBActivity />
                </ProtectedRoute>
              }
            />
            <Route
              path="/usb-scans"
              element={
                <ProtectedRoute>
                  <USBScanResults />
                </ProtectedRoute>
              }
            />
            <Route
              path="/users"
              element={
                <AdminRoute>
                  <UserManagement />
                </AdminRoute>
              }
            />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </WebSocketProvider>
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;