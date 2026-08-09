export type DeviceStatus = "ONLINE" | "OFFLINE" | "ISOLATED" | "UNREGISTERED" | "OUTDATED" | "UNHEALTHY";
export type HealthStatus = "HEALTHY" | "UNHEALTHY" | "WARNING" | "DEGRADED" | "OUTDATED";
export type CommandStatus = "NONE" | "PENDING" | "DISPATCHED" | "EXECUTED" | "SUCCESS" | "FAILED";
export type OSType = "WINDOWS" | "LINUX" | "MACOS" | "OTHER";

export interface FleetDevice {
  id: string;
  hostname: string;
  ip_address?: string | null;
  mac_address?: string | null;
  os_type: OSType;
  os_version?: string | null;
  operating_system?: string | null;
  agent_version?: string | null;
  applied_policy_version?: number | null;
  policy_version?: number | null;
  status: DeviceStatus;
  health_status: HealthStatus;
  last_command_status: CommandStatus;
  cpu_usage_percent?: number | null;
  ram_usage_mb?: number | null;
  ram_usage_percent?: number | null;
  disk_usage_percent?: number | null;
  agent_uptime_seconds?: number | null;
  service_status?: string | null;
  last_telemetry_upload?: string | null;
  last_policy_sync?: string | null;
  is_active: boolean;
  last_seen?: string | null;
  last_checkin?: string | null;
  last_heartbeat?: string | null;
  created_at: string;
  updated_at: string;
}

export interface FleetMetrics {
  total_agents: number;
  online: number;
  offline: number;
  outdated: number;
  unhealthy: number;
}

export interface FleetSummary {
  metrics: FleetMetrics;
  recent_devices: FleetDevice[];
  timestamp: string;
}

export type AgentCommandType =
  | "START_SCAN"
  | "RESTART_AGENT"
  | "REFRESH_POLICY"
  | "COLLECT_DIAGNOSTICS"
  | "UPLOAD_LOGS"
  | "RECONNECT"
  | "SHUTDOWN_AGENT"
  | "UPDATE_CONFIG";

export type AgentCommandState = "PENDING" | "DISPATCHED" | "EXECUTING" | "SUCCESS" | "FAILED" | "CANCELLED";

export interface AgentCommand {
  id: string;
  device_id: string;
  issuer_id?: string | null;
  command_type: AgentCommandType;
  status: AgentCommandState;
  payload?: Record<string, any> | null;
  result_output?: string | null;
  error_message?: string | null;
  execution_duration_ms?: number | null;
  queued_at: string;
  dispatched_at?: string | null;
  acknowledged_at?: string | null;
}

export interface AgentCommandAuditLog {
  id: string;
  command_id: string;
  device_id: string;
  issuer_username: string;
  command_type: string;
  status: string;
  details?: string | null;
  created_at: string;
}

export interface SynchronizationMetadata {
  last_heartbeat?: string | null;
  last_checkin?: string | null;
  last_telemetry_upload?: string | null;
  last_policy_sync?: string | null;
}

export interface AgentCollectorStatus {
  name: string;
  enabled: boolean;
  status: string;
  events_collected_24h: number;
}

export interface AgentDiagnosticPackage {
  device_id: string;
  hostname: string;
  os_type: string;
  operating_system: string;
  agent_version: string;
  policy_version: number;
  health_status: string;
  status: string;
  generated_at: string;

  configuration: Record<string, any>;
  installed_collectors: AgentCollectorStatus[];
  synchronization: SynchronizationMetadata;
  last_commands: AgentCommand[];
  last_errors: Array<Record<string, any>>;
  agent_logs: string[];
}

export type AgentUpgradeStatus =
  | "IDLE"
  | "AVAILABLE"
  | "DOWNLOADING"
  | "INSTALLING"
  | "RESTARTING"
  | "SUCCESS"
  | "FAILED"
  | "ROLLED_BACK";

export type RollbackStatus = "NONE" | "PENDING" | "IN_PROGRESS" | "SUCCESSFUL" | "FAILED";

export interface AgentUpgradeRecord {
  id: string;
  device_id: string;
  current_version: string;
  target_version: string;
  status: AgentUpgradeStatus;
  rollback_status: RollbackStatus;
  progress_percent: number;
  logs?: string | null;
  error_message?: string | null;
  started_at: string;
  completed_at?: string | null;
}
