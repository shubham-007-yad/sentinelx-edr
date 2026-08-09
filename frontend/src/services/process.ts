import { api } from "./api";
import type { ProcessItem, DeviceItem, ProcessAuditLogItem } from "../types/process";

export const getProcesses = async (
  skip: number = 0,
  limit: number = 500,
  deviceId?: string,
  name?: string
): Promise<ProcessItem[]> => {
  const params: Record<string, any> = { skip, limit };
  if (deviceId) params.device_id = deviceId;
  if (name) params.name = name;

  const response = await api.get<ProcessItem[]>("/processes", { params });
  return response.data;
};

export const getDevices = async (): Promise<DeviceItem[]> => {
  const response = await api.get<DeviceItem[]>("/devices");
  return response.data;
};

export const getProcessAuditLogs = async (
  skip: number = 0,
  limit: number = 200,
  deviceId?: string,
  eventType?: string,
  processName?: string
): Promise<ProcessAuditLogItem[]> => {
  const params: Record<string, any> = { skip, limit };
  if (deviceId && deviceId !== "ALL") params.device_id = deviceId;
  if (eventType && eventType !== "ALL") params.event_type = eventType;
  if (processName) params.process_name = processName;

  const response = await api.get<ProcessAuditLogItem[]>("/processes/audit-logs", { params });
  return response.data;
};
