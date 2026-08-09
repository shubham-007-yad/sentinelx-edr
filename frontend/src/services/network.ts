import { api } from "./api";

export interface NetworkConnection {
  id: string;
  device_id: string;
  process_id?: string;
  threat_id?: string;
  alert_id?: string;
  pid?: number;
  process_name?: string;
  executable_path?: string;
  local_ip?: string;
  local_port?: number;
  remote_ip?: string;
  remote_port?: number;
  protocol: string;
  state?: string;
  bytes_sent: number;
  bytes_received: number;
  created_at: string;
  updated_at: string;
}

export interface NetworkCorrelatedPivot {
  connection_id: string;
  device_id: string;
  device_hostname?: string;
  device_ip?: string;
  device_status?: string;

  process_id?: string;
  pid?: number;
  process_name?: string;
  executable_path?: string;
  cmdline?: string;
  username?: string;
  ppid?: number;

  local_ip?: string;
  local_port?: number;
  remote_ip?: string;
  remote_port?: number;
  protocol: string;
  state?: string;

  threat_id?: string;
  threat_type?: string;
  threat_severity?: string;
  rule_name?: string;
  threat_description?: string;

  alert_id?: string;
  alert_title?: string;
  alert_message?: string;
  alert_severity?: string;
  alert_status?: string;

  available_response_actions: string[];
}

export interface NetworkTimelineItem {
  timestamp: string;
  time_formatted: string;
  event_type: string;
  title: string;
  description: string;
  severity: string;
  icon: string;
  metadata?: any;
}

export interface ConnectionTimelineResponse {
  connection_id: string;
  device_id: string;
  timeline: NetworkTimelineItem[];
}

export const networkService = {
  getNetworkConnections: async (params?: {
    device_id?: string;
    pid?: number;
    process_name?: string;
    protocol?: string;
    state?: string;
    remote_ip?: string;
  }): Promise<NetworkConnection[]> => {
    const response = await api.get<NetworkConnection[]>("/network/connections", { params });
    return response.data;
  },

  getDeviceNetworkConnections: async (
    deviceId: string,
    params?: { protocol?: string; state?: string }
  ): Promise<NetworkConnection[]> => {
    const response = await api.get<NetworkConnection[]>(`/devices/${deviceId}/network`, { params });
    return response.data;
  },

  getCorrelatedConnection: async (connectionId: string): Promise<NetworkCorrelatedPivot> => {
    const response = await api.get<NetworkCorrelatedPivot>(`/network/connections/${connectionId}/correlated`);
    return response.data;
  },

  getConnectionTimeline: async (connectionId: string): Promise<ConnectionTimelineResponse> => {
    const response = await api.get<ConnectionTimelineResponse>(`/network/connections/${connectionId}/timeline`);
    return response.data;
  }
};
