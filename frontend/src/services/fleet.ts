import api from "./api";
import type { FleetMetrics, FleetDevice, FleetSummary, AgentCommand, AgentCommandType, AgentCommandAuditLog } from "../types/fleet";

export const fleetService = {
  async getMetrics(): Promise<FleetMetrics> {
    const res = await api.get<FleetMetrics>("/fleet/metrics");
    return res.data;
  },

  async getDevices(params?: {
    skip?: number;
    limit?: number;
    status?: string;
    health_status?: string;
    os_type?: string;
    version?: string;
    policy?: number;
    search?: string;
  }): Promise<FleetDevice[]> {
    const res = await api.get<FleetDevice[]>("/fleet/devices", { params });
    return res.data;
  },

  async getSummary(): Promise<FleetSummary> {
    const res = await api.get<FleetSummary>("/fleet/summary");
    return res.data;
  },

  async evaluateHealth(): Promise<{ evaluated_devices: number; health_alerts_generated: number; timestamp: string }> {
    const res = await api.post("/fleet/health/evaluate");
    return res.data;
  },

  async queueCommand(deviceId: string, commandType: AgentCommandType, payload?: Record<string, any>): Promise<AgentCommand> {
    const res = await api.post<AgentCommand>("/fleet/commands", {
      device_id: deviceId,
      command_type: commandType,
      payload: payload || {}
    });
    return res.data;
  },

  async dispatchBatchCommand(deviceIds: string[], commandType: AgentCommandType, payload?: Record<string, any>): Promise<AgentCommand[]> {
    const res = await api.post<AgentCommand[]>("/fleet/commands/batch", {
      device_ids: deviceIds,
      command_type: commandType,
      payload: payload || {}
    });
    return res.data;
  },

  async exportInventory(deviceIds?: string[]): Promise<void> {
    const params = deviceIds && deviceIds.length > 0 ? { device_ids: deviceIds.join(",") } : {};
    const res = await api.get("/fleet/export", {
      params,
      responseType: "blob"
    });
    const url = window.URL.createObjectURL(new Blob([res.data], { type: "text/csv" }));
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", `sentinelx_fleet_inventory_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  },

  async getCommandHistory(deviceId?: string): Promise<AgentCommand[]> {
    const res = await api.get<AgentCommand[]>("/fleet/commands/history", {
      params: { device_id: deviceId }
    });
    return res.data;
  },

  async getCommandAuditLogs(deviceId?: string): Promise<AgentCommandAuditLog[]> {
    const res = await api.get<AgentCommandAuditLog[]>("/fleet/commands/audit-logs", {
      params: { device_id: deviceId }
    });
    return res.data;
  },

  async getDiagnostics(deviceId: string): Promise<import("../types/fleet").AgentDiagnosticPackage> {
    const res = await api.get<import("../types/fleet").AgentDiagnosticPackage>(`/fleet/devices/${deviceId}/diagnostics`);
    return res.data;
  },

  async downloadDiagnostics(deviceId: string): Promise<void> {
    const res = await api.get(`/fleet/devices/${deviceId}/diagnostics/download`, {
      responseType: "blob"
    });
    const url = window.URL.createObjectURL(new Blob([res.data], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", `sentinelx_agent_diagnostics_${deviceId.slice(0, 8)}_${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  },

  async triggerUpgrade(deviceIds: string[], targetVersion: string = "1.2.0"): Promise<import("../types/fleet").AgentUpgradeRecord[]> {
    const res = await api.post<import("../types/fleet").AgentUpgradeRecord[]>("/fleet/upgrade/trigger", {
      device_ids: deviceIds,
      target_version: targetVersion
    });
    return res.data;
  },

  async advanceUpgradeStep(upgradeId: string): Promise<import("../types/fleet").AgentUpgradeRecord> {
    const res = await api.post<import("../types/fleet").AgentUpgradeRecord>("/fleet/upgrade/step", null, {
      params: { upgrade_id: upgradeId }
    });
    return res.data;
  },

  async rollbackUpgrade(upgradeId: string, targetRollbackVersion?: string): Promise<import("../types/fleet").AgentUpgradeRecord> {
    const res = await api.post<import("../types/fleet").AgentUpgradeRecord>("/fleet/upgrade/rollback", {
      upgrade_id: upgradeId,
      target_rollback_version: targetRollbackVersion
    });
    return res.data;
  },

  async getUpgradeHistory(deviceId?: string): Promise<import("../types/fleet").AgentUpgradeRecord[]> {
    const res = await api.get<import("../types/fleet").AgentUpgradeRecord[]>("/fleet/upgrade/history", {
      params: { device_id: deviceId }
    });
    return res.data;
  }
};
