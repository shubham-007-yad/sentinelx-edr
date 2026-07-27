export type ThreatSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type ThreatType =
  | "KNOWN_MALWARE"
  | "DOUBLE_EXTENSION"
  | "HIDDEN_EXECUTABLE"
  | "AUTORUN_SCRIPT"
  | "SUSPICIOUS_EXTENSION"
  | "ANOMALOUS_FILE";

export type ThreatStatus = "OPEN" | "INVESTIGATING" | "RESOLVED" | "FALSE_POSITIVE" | "QUARANTINED";

export interface ThreatRecord {
  id: string;
  usb_event_id: string;
  scan_result_id?: string;
  device_id?: string;
  file_name: string;
  full_path: string;
  sha256: string;
  threat_name: string;
  threat_type: ThreatType | string;
  severity: ThreatSeverity;
  description: string;
  remediation?: string;
  status: ThreatStatus;
  detected_at: string;
}

export interface ThreatSeverityCount {
  CRITICAL: number;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
  INFO: number;
}

export interface ThreatStats {
  total_threats: number;
  open_threats: number;
  resolved_threats: number;
  false_positives: number;
  quarantined: number;
  severity_breakdown: ThreatSeverityCount;
  threat_type_breakdown: Record<string, number>;
}
