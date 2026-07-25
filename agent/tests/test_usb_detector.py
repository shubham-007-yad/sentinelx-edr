import time
import pytest
from detectors.usb_detector import (
    USBDeviceDetails,
    USBEventData,
    USBEventListener,
    WindowsUSBDetector,
    MockUSBDetector,
    USBDetectorService
)


def test_usb_event_listener_registration_and_emit():
    listener = USBEventListener()
    received_events = []

    def callback(event: USBEventData):
        received_events.append(event)

    listener.register_callback(callback)

    test_event = USBEventData(
        event_type="INSERT",
        drive_letter="E:",
        volume_label="TEST_USB",
        filesystem="FAT32",
        total_size=1000000,
        free_space=500000,
        serial_number="12345"
    )

    listener.emit(test_event)

    assert len(received_events) == 1
    assert received_events[0].event_type == "INSERT"
    assert received_events[0].drive_letter == "E:"
    assert received_events[0].volume_label == "TEST_USB"
    assert received_events[0].serial_number == "12345"

    # Test unregister
    listener.unregister_callback(callback)
    listener.emit(test_event)
    assert len(received_events) == 1  # Should not increase


def test_usb_event_data_to_dict():
    event = USBEventData(
        event_type="REMOVE",
        drive_letter="F:",
        volume_label="BACKUP",
        filesystem="NTFS",
        total_size=64000000000,
        free_space=32000000000,
        serial_number="SN-999"
    )
    data = event.to_dict()
    assert data["event_type"] == "REMOVE"
    assert data["drive_letter"] == "F:"
    assert data["volume_label"] == "BACKUP"
    assert data["filesystem"] == "NTFS"
    assert data["total_size"] == 64000000000
    assert data["free_space"] == 32000000000
    assert data["serial_number"] == "SN-999"
    assert "detected_at" in data


def test_usb_detector_service_insert_remove_detection():
    mock_detector = MockUSBDetector()
    service = USBDetectorService(detector=mock_detector)

    detected_events = []
    service.event_listener.register_callback(lambda evt: detected_events.append(evt))

    # Initial scan - empty baseline
    events = service.scan_and_detect()
    assert len(events) == 0
    assert len(detected_events) == 0

    # 1. Plug in USB device E:
    usb_e = USBDeviceDetails(
        drive_letter="E:",
        volume_label="PENDRIVE",
        filesystem="FAT32",
        total_size=16000000000,
        free_space=8000000000,
        serial_number="USB-SER-001"
    )
    mock_detector.plug_in(usb_e)

    events_insert = service.scan_and_detect()
    assert len(events_insert) == 1
    assert events_insert[0].event_type == "INSERT"
    assert events_insert[0].drive_letter == "E:"
    assert events_insert[0].volume_label == "PENDRIVE"
    assert len(detected_events) == 1

    # 2. No changes scan
    events_no_change = service.scan_and_detect()
    assert len(events_no_change) == 0
    assert len(detected_events) == 1

    # 3. Unplug USB device E:
    mock_detector.unplug("E:")

    events_remove = service.scan_and_detect()
    assert len(events_remove) == 1
    assert events_remove[0].event_type == "REMOVE"
    assert events_remove[0].drive_letter == "E:"
    assert events_remove[0].volume_label == "PENDRIVE"
    assert len(detected_events) == 2


def test_usb_detector_service_background_monitoring():
    mock_detector = MockUSBDetector()
    service = USBDetectorService(detector=mock_detector)

    events_received = []
    service.event_listener.register_callback(lambda evt: events_received.append(evt))

    service.start_monitoring(interval=0.1)
    time.sleep(0.15)

    # Plug in drive while monitoring
    usb_g = USBDeviceDetails(
        drive_letter="G:",
        volume_label="MONITOR_USB",
        filesystem="exFAT",
        total_size=32000000000,
        free_space=16000000000,
        serial_number="SN-MON-123"
    )
    mock_detector.plug_in(usb_g)

    time.sleep(0.25)
    assert len(events_received) == 1
    assert events_received[0].event_type == "INSERT"
    assert events_received[0].drive_letter == "G:"

    # Unplug drive while monitoring
    mock_detector.unplug("G:")
    time.sleep(0.25)

    service.stop_monitoring()

    assert len(events_received) == 2
    assert events_received[1].event_type == "REMOVE"
    assert events_received[1].drive_letter == "G:"


def test_windows_usb_detector_instantiation():
    win_detector = WindowsUSBDetector()
    drives = win_detector.get_connected_usb_drives()
    assert isinstance(drives, dict)
