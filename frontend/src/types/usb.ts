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

export interface Device {
  id: string;
  hostname: string;
  ip_address?: string;
  mac_address?: string;
  os_type: string;
  status: string;
  last_seen?: string;
}
