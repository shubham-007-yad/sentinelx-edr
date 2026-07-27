import { api } from "./api";
import type { ThreatRecord, ThreatStats, ThreatStatus } from "../types/threat";

export const getThreats = async (
  skip: number = 0,
  limit: number = 100,
  severity?: string,
  threatType?: string,
  status?: string,
  usbEventId?: string,
  deviceId?: string,
  search?: string
): Promise<ThreatRecord[]> => {
  const params: Record<string, any> = { skip, limit };
  if (severity) params.severity = severity;
  if (threatType) params.threat_type = threatType;
  if (status) params.status = status;
  if (usbEventId) params.usb_event_id = usbEventId;
  if (deviceId) params.device_id = deviceId;
  if (search) params.search = search;

  const response = await api.get<ThreatRecord[]>("/threats", { params });
  return response.data;
};

export const getThreatSummary = async (): Promise<ThreatStats> => {
  const response = await api.get<ThreatStats>("/threats/summary");
  return response.data;
};

export const getThreatById = async (id: string): Promise<ThreatRecord> => {
  const response = await api.get<ThreatRecord>(`/threats/${id}`);
  return response.data;
};

export const updateThreatStatus = async (
  id: string,
  status: ThreatStatus,
  remediation?: string
): Promise<ThreatRecord> => {
  const response = await api.patch<ThreatRecord>(`/threats/${id}/status`, {
    status,
    remediation,
  });
  return response.data;
};

export const analyzeUsbEventScans = async (usbEventId: string): Promise<ThreatRecord[]> => {
  const response = await api.post<ThreatRecord[]>(`/threats/analyze/${usbEventId}`);
  return response.data;
};
