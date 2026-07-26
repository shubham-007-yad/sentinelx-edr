import { api } from "./api";
import type { USBEvent, USBScanResult, Device } from "../types/usb";

export const getUsbEvents = async (
  skip: number = 0,
  limit: number = 10,
  deviceId?: string,
  eventType?: string
): Promise<USBEvent[]> => {
  const params: Record<string, any> = { skip, limit };
  if (deviceId) params.device_id = deviceId;
  if (eventType) params.event_type = eventType;

  const response = await api.get<USBEvent[]>("/usb/events", { params });
  return response.data;
};

export const getUsbEventById = async (id: string): Promise<USBEvent> => {
  const response = await api.get<USBEvent>(`/usb/events/${id}`);
  return response.data;
};

export const getUsbScans = async (
  skip: number = 0,
  limit: number = 10,
  usbEventId?: string,
  extension?: string,
  isHidden?: boolean,
  search?: string
): Promise<USBScanResult[]> => {
  const params: Record<string, any> = { skip, limit };
  if (usbEventId) params.usb_event_id = usbEventId;
  if (extension) params.extension = extension;
  if (isHidden !== undefined) params.is_hidden = isHidden;
  if (search) params.search = search;

  const response = await api.get<USBScanResult[]>("/usb/scans", { params });
  return response.data;
};

export const getUsbScanById = async (id: string): Promise<USBScanResult> => {
  const response = await api.get<USBScanResult>(`/usb/scans/${id}`);
  return response.data;
};

export const getDevices = async (): Promise<Device[]> => {
  const response = await api.get<Device[]>("/devices");
  return response.data;
};
