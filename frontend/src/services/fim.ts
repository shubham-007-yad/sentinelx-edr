import { api } from "./api";

export interface FileIntegrityRecord {
  id: string;
  device_id: string;
  file_path: string;
  file_name: string;
  sha256: string;
  size: number;
  last_modified?: string;
  owner?: string;
  is_executable: boolean;
  created_at: string;
  updated_at: string;
}

export interface FIMEvent {
  id?: string;
  file_path: string;
  file_name: string;
  action: "CREATED" | "MODIFIED" | "DELETED" | "RENAMED" | "UNCHANGED";
  device_id: string;
  device_name?: string;
  user?: string;
  baseline_sha256?: string;
  sha256: string;
  hash_changed: boolean;
  size: number;
  is_executable: boolean;
  is_suspicious: boolean;
  timestamp: string;
}

export interface FIMMetrics {
  files_monitored: number;
  modified: number;
  deleted: number;
  created: number;
  suspicious: number;
}

export interface FIMTimelineItem {
  step: number;
  timestamp: string;
  event_type: string;
  title: string;
  description: string;
  severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  actor?: string;
  details?: Record<string, any>;
}

export interface FIMTimelineResponse {
  device_id: string;
  file_path: string;
  file_name: string;
  current_sha256: string;
  current_status: string;
  timeline: FIMTimelineItem[];
}

export const fimService = {
  getIntegrityRecords: async (params?: {
    device_id?: string;
    file_path?: string;
    file_name?: string;
    is_executable?: boolean;
  }): Promise<FileIntegrityRecord[]> => {
    const response = await api.get<FileIntegrityRecord[]>("/fim/records", { params });
    return response.data;
  },

  verifyFileChange: async (deviceId: string, payload: any) => {
    const response = await api.post(`/fim/verify/${deviceId}`, payload);
    return response.data;
  },

  executeResponseAction: async (deviceId: string, filePath: string, actionType: string) => {
    const response = await api.post(`/fim/respond/${deviceId}`, {
      file_path: filePath,
      action_type: actionType,
    });
    return response.data;
  },

  getFileTimeline: async (deviceId: string, filePath: string): Promise<FIMTimelineResponse> => {
    const response = await api.get<FIMTimelineResponse>(`/fim/timeline/${deviceId}`, {
      params: { file_path: filePath },
    });
    return response.data;
  }
};
