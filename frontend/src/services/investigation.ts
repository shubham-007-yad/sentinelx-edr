import api from "./api";

export interface InvestigationCase {
  id: string;
  title: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  status: "OPEN" | "IN_PROGRESS" | "CLOSED";
  assigned_to?: string;
  correlation_id?: string;
  summary?: string;
  created_at: string;
  closed_at?: string;
}

export interface TimelineEvent {
  event_id: string;
  timestamp: string;
  time_formatted: string;
  correlation_id: string;
  category: string;
  title: string;
  description?: string;
  severity: string;
  source?: string;
  device_id?: string;
  metadata?: Record<string, any>;
}

export interface UnifiedTimeline {
  correlation_id: string;
  total_events: number;
  start_time?: string;
  end_time?: string;
  timeline: TimelineEvent[];
}

export interface ThreatHuntMatch {
  event_id: string;
  timestamp: string;
  time_formatted: string;
  category: string;
  event_type: string;
  severity: string;
  title: string;
  description?: string;
  hostname?: string;
  username?: string;
  process_name?: string;
  sha256?: string;
  ip?: string;
  correlation_id?: string;
  payload: Record<string, any>;
}

export interface ThreatHuntingResponse {
  total_matches: number;
  applied_filters: Record<string, any>;
  matches: ThreatHuntMatch[];
}

export const investigationService = {
  getDashboardSummary: async () => {
    const res = await api.get("/investigation/dashboard-summary");
    return res.data;
  },

  getCases: async (status?: string) => {
    const res = await api.get("/investigation/cases", { params: { status } });
    return res.data as InvestigationCase[];
  },

  createCase: async (caseData: Partial<InvestigationCase>) => {
    const res = await api.post("/investigation/cases", caseData);
    return res.data as InvestigationCase;
  },

  updateCase: async (caseId: string, caseData: Partial<InvestigationCase>) => {
    const res = await api.patch(`/investigation/cases/${caseId}`, caseData);
    return res.data as InvestigationCase;
  },

  getTimeline: async (correlationId: string) => {
    const res = await api.get(`/investigation/timeline/${correlationId}`);
    return res.data as UnifiedTimeline;
  },

  executeHunt: async (queryData: {
    query?: string;
    process?: string;
    sha256?: string;
    ip?: string;
    domain?: string;
    min_severity?: string;
    correlation_id?: string;
    time_range_hours?: number;
  }) => {
    const res = await api.post("/investigation/hunt", queryData);
    return res.data as ThreatHuntingResponse;
  },

  getReportJson: async (caseId?: string, correlationId?: string) => {
    const res = await api.get("/investigation/reports/json", {
      params: { case_id: caseId, correlation_id: correlationId }
    });
    return res.data;
  },

  downloadReportPdf: async (caseId?: string, correlationId?: string) => {
    const res = await api.get("/investigation/reports/pdf", {
      params: { case_id: caseId, correlation_id: correlationId },
      responseType: "blob"
    });
    const url = window.URL.createObjectURL(new Blob([res.data], { type: "application/pdf" }));
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", `Investigation_Report_${caseId || correlationId || "Summary"}.pdf`);
    document.body.appendChild(link);
    link.click();
    link.remove();
  }
};

export default investigationService;
