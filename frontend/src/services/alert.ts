import { api } from "./api";
import type { LiveAlertPayload } from "../context/WebSocketContext";

export interface AlertRecord extends LiveAlertPayload {
  id: string;
  threat_id: string;
  device_id: string;
  title: string;
  message: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | string;
  status: "UNREAD" | "READ" | "ACKNOWLEDGED" | string;
  created_at: string;
  read_at?: string | null;
  acknowledged_at?: string | null;
  device: string;
  file: string;
  time: string;
}

export const getAlerts = async (
  skip: number = 0,
  limit: number = 100,
  status?: string,
  severity?: string,
  deviceId?: string,
  search?: string
): Promise<AlertRecord[]> => {
  const params = new URLSearchParams();
  params.append("skip", skip.toString());
  params.append("limit", limit.toString());
  if (status) params.append("status_filter", status);
  if (severity) params.append("severity_filter", severity);
  if (deviceId) params.append("device_id", deviceId);
  if (search) params.append("search", search);

  const response = await api.get(`/alerts?${params.toString()}`);
  return response.data;
};

export const getUnreadCount = async (): Promise<number> => {
  const response = await api.get("/alerts/unread-count");
  return response.data.unread_count;
};

export const markAlertRead = async (alertId: string): Promise<AlertRecord> => {
  const response = await api.patch(`/alerts/${alertId}/read`);
  return response.data;
};

export const markAllAlertsRead = async (): Promise<void> => {
  await api.patch("/alerts/mark-all-read");
};

export const bulkMarkAlertsRead = async (alertIds: string[]): Promise<void> => {
  await api.post("/alerts/bulk-read", { alert_ids: alertIds });
};

export const bulkAcknowledgeAlerts = async (alertIds: string[]): Promise<void> => {
  await api.post("/alerts/bulk-acknowledge", { alert_ids: alertIds });
};
