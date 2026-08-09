export interface ProcessItem {
  id: string;
  device_id: string;
  pid: number;
  ppid?: number | null;
  name: string;
  exe_path?: string | null;
  username?: string | null;
  cpu_percent?: number | null;
  memory_percent?: number | null;
  start_time?: string | null;
  started_at?: string | null;
  cmdline?: string | null;
  captured_at: string;
}

export interface DeviceItem {
  id: string;
  hostname: string;
  ip_address?: string;
  mac_address?: string;
  os_type: string;
  status: string;
}

export interface ProcessAuditLogItem {
  id: string;
  device_id: string;
  pid: number;
  ppid?: number | null;
  process_name: string;
  event_type: "PROCESS_STARTED" | "PROCESS_TERMINATED" | "RESPONSE_ACTION" | "DETECTION_FOUND" | string;
  details?: string | null;
  timestamp: string;
}
