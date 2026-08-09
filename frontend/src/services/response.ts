import { api } from "./api";

export interface ResponseAuditLog {
  id: string;
  action_id: string;
  timestamp: string;
  stage: string;
  actor: string;
  message: string;
  details?: any;
}

export interface ResponseActionRecord {
  id: string;
  alert_id?: string;
  device_id: string;
  action_type: string;
  status: "PENDING" | "RUNNING" | "SUCCESS" | "FAILED" | "CANCELLED";
  initiated_by: string;
  started_at: string;
  completed_at?: string;
  result?: string;
  audit_logs?: ResponseAuditLog[];
}

export const getResponseActions = async (
  skip: number = 0,
  limit: number = 100,
  deviceId?: string,
  statusFilter?: string
): Promise<ResponseActionRecord[]> => {
  const params: Record<string, any> = { skip, limit };
  if (deviceId) params.device_id = deviceId;
  if (statusFilter && statusFilter !== "ALL") params.status_filter = statusFilter;

  const response = await api.get<ResponseActionRecord[]>("/responses", { params });
  return response.data;
};

export const triggerResponseAction = async (
  deviceId: string,
  actionType: string,
  alertId?: string,
  initiatedBy: string = "ADMIN"
): Promise<ResponseActionRecord> => {
  const response = await api.post<ResponseActionRecord>("/responses/trigger", {
    device_id: deviceId,
    action_type: actionType,
    alert_id: alertId,
    initiated_by: initiatedBy
  });
  return response.data;
};

export const retryResponseAction = async (actionId: string): Promise<ResponseActionRecord> => {
  const response = await api.post<ResponseActionRecord>(`/responses/${actionId}/retry`);
  return response.data;
};

export const cancelResponseAction = async (actionId: string): Promise<ResponseActionRecord> => {
  const response = await api.post<ResponseActionRecord>(`/responses/${actionId}/cancel`);
  return response.data;
};

export const getAuditLogsForAction = async (actionId: string): Promise<ResponseAuditLog[]> => {
  const response = await api.get<ResponseAuditLog[]>(`/responses/${actionId}/audit-logs`);
  return response.data;
};
