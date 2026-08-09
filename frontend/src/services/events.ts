import { api } from "./api";


export interface SecurityEventItem {
  id: string;
  device_id: string;
  event_source: string;
  event_id: string;
  event_type: string;
  level: "Information" | "Warning" | "Error" | "Critical";
  username: string | null;
  domain: string | null;
  computer: string | null;
  logon_type: string | null;
  ip_address: string | null;
  status: string | null;
  description: string;
  raw_event: any;
  timestamp: string;
}

export interface SecurityEventSummary {
  total_events: number;
  logins: number;
  failed_logons: number;
  privilege_changes: number;
  persistence_events: number;
  critical_events: number;
}

export interface AuthTimelineItem {
  id: string;
  timestamp: string;
  event_id: string;
  event_type: string;
  category: "USER_LOGIN" | "FAILED_AUTHENTICATION" | "REMOTE_LOGIN" | "ADMINISTRATOR_LOGIN";
  username: string;
  domain: string | null;
  logon_type: string;
  ip_address: string;
  status: string | null;
  description: string;
}

export interface AttackChainItem {
  step: number;
  time: string;
  timestamp: string;
  event_title: string;
  badge_type: "FAILED_LOGIN" | "ADMIN_LOGIN" | "USER_LOGIN" | "PERSISTENCE" | "CRITICAL_ALERT" | "INFO";
  severity: string;
  user: string;
  device: string;
  event_id: string;
  description: string;
  source: string;
}

export interface EventListResponse {
  total: number;
  items: SecurityEventItem[];
  skip: number;
  limit: number;
}

export const eventLogService = {
  getEvents: async (params?: {
    device_id?: string;
    event_type?: string;
    level?: string;
    username?: string;
    search?: string;
    date_range?: string;
    skip?: number;
    limit?: number;
  }): Promise<EventListResponse> => {
    const response = await api.get<EventListResponse>("/events", { params });
    return response.data;
  },

  getSummary: async (device_id?: string): Promise<SecurityEventSummary> => {
    const response = await api.get<SecurityEventSummary>("/events/summary", {
      params: { device_id },
    });
    return response.data;
  },

  getAuthTimeline: async (
    device_id?: string,
    limit: number = 30
  ): Promise<AuthTimelineItem[]> => {
    const response = await api.get<AuthTimelineItem[]>("/events/auth-timeline", {
      params: { device_id, limit },
    });
    return response.data;
  },

  getAttackChainTimeline: async (
    device_id?: string,
    limit: number = 20
  ): Promise<AttackChainItem[]> => {
    const response = await api.get<AttackChainItem[]>("/events/attack-chain", {
      params: { device_id, limit },
    });
    return response.data;
  },

  triggerSimulate: async (
    scenario: "BRUTE_FORCE" | "PRIVILEGE_ESCALATION" | "ACCOUNT_DISABLED" | "OFF_HOURS" | "PERSISTENCE" | "LOG_CLEARING" | "ATTACK_CHAIN",
    device_id?: string
  ) => {
    const response = await api.post("/events/simulate", { scenario, device_id });
    return response.data;
  },

  executeResponseAction: async (params: {
    action_type: "DISABLE_USER" | "FORCE_LOGOUT" | "INVESTIGATE" | "IGNORE" | "ALLOWLIST";
    device_id?: string;
    username?: string;
    event_id?: string;
  }) => {
    const response = await api.post("/events/action", params);
    return response.data;
  },
};
