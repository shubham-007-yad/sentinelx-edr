export type USBEventType = "INSERT" | "REMOVE";

export interface USBEvent {
  id: string;
  device_id: string;
  event_type: USBEventType;
  drive_letter?: string;
  volume_label?: string;
  filesystem?: string;
  total_size?: number;
  free_space?: number;
  serial_number?: string;
  detected_at: string;
}

export interface USBScanResult {
  id: string;
  usb_event_id: string;
  file_name: string;
  full_path: string;
  extension?: string;
  file_size: number;
  sha256: string;
  is_hidden: boolean;
  created_at?: string;
  modified_at?: string;
  scanned_at: string;
}

export interface Device {
  id: string;
  hostname: string;
  ip_address?: string;
  mac_address?: string;
  os_type: string;
  status: string;
  last_seen?: string;
}
