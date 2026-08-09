import api from "./api";

export interface USBPolicyConfig {
  enable_usb_monitoring: boolean;
  enable_auto_scanning: boolean;
  scan_removable_only: boolean;
  max_file_size_mb: number;
  ignored_extensions: string[];
  enable_sha256_hashing: boolean;
  block_unauthorized_usbs: boolean;
  auto_quarantine_suspicious: boolean;
  allowed_vendor_ids: string[];
  read_only_mode: boolean;
}

export interface ProcessPolicyConfig {
  monitor_powershell: boolean;
  monitor_lolbins: boolean;
  cpu_threshold_percent: number;
  memory_threshold_mb: number;
  allowed_processes: string[];
  blocklisted_processes: string[];
  auto_kill_blocklisted: boolean;
  parent_child_rules_enabled: boolean;
}

export interface NetworkPolicyConfig {
  allowed_ports: number[];
  blocked_ports: number[];
  allowlisted_ips: string[];
  blocklisted_ips: string[];
  monitor_external_connections: boolean;
  beacon_interval_threshold_seconds: number;
  beacon_jitter_percent: number;
  auto_block_c2_connections: boolean;
}

export interface FIMPolicyConfig {
  protected_folders: string[];
  excluded_folders: string[];
  hash_algorithm: string;
  ransomware_modification_threshold: number;
  ransomware_entropy_threshold: number;
  ignore_temporary_files: boolean;
  auto_quarantine_ransomware: boolean;
}

export interface SecurityPolicyRecord {
  id: string;
  policy_name: string;
  category: "USB" | "PROCESS" | "NETWORK" | "FIM" | "RANSOMWARE";
  version: number;
  enabled: boolean;
  priority: number;
  configuration: Record<string, any>;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface UnifiedPolicySync {
  version: number;
  timestamp: string;
  usb: USBPolicyConfig;
  process: ProcessPolicyConfig;
  network: NetworkPolicyConfig;
  fim: FIMPolicyConfig;
}

export const policyService = {
  getUSBPolicy: async (): Promise<USBPolicyConfig> => {
    const res = await api.get("/usb/policy");
    return res.data;
  },
  updateUSBPolicy: async (data: USBPolicyConfig): Promise<USBPolicyConfig> => {
    const res = await api.put("/usb/policy", data);
    return res.data;
  },
  getProcessPolicy: async (): Promise<ProcessPolicyConfig> => {
    const res = await api.get("/processes/policy");
    return res.data;
  },
  updateProcessPolicy: async (data: ProcessPolicyConfig): Promise<ProcessPolicyConfig> => {
    const res = await api.put("/processes/policy", data);
    return res.data;
  },
  getNetworkPolicy: async (): Promise<NetworkPolicyConfig> => {
    const res = await api.get("/network/policy");
    return res.data;
  },
  updateNetworkPolicy: async (data: NetworkPolicyConfig): Promise<NetworkPolicyConfig> => {
    const res = await api.put("/network/policy", data);
    return res.data;
  },
  getFIMPolicy: async (): Promise<FIMPolicyConfig> => {
    const res = await api.get("/fim/policy");
    return res.data;
  },
  updateFIMPolicy: async (data: FIMPolicyConfig): Promise<FIMPolicyConfig> => {
    const res = await api.put("/fim/policy", data);
    return res.data;
  },
  getPolicyHistory: async (category?: string): Promise<SecurityPolicyRecord[]> => {
    const res = await api.get("/policies/history", { params: { category } });
    return res.data;
  },
  togglePolicy: async (id: string, enabled: boolean): Promise<SecurityPolicyRecord> => {
    const res = await api.patch(`/policies/${id}/toggle`, null, { params: { enabled } });
    return res.data;
  },
  clonePolicy: async (id: string): Promise<SecurityPolicyRecord> => {
    const res = await api.post(`/policies/${id}/clone`);
    return res.data;
  },
  rollbackPolicy: async (id: string): Promise<SecurityPolicyRecord> => {
    const res = await api.post(`/policies/${id}/rollback`);
    return res.data;
  },
  getLatestSync: async (): Promise<UnifiedPolicySync> => {
    const res = await api.get("/policies/latest");
    return res.data;
  }
};
