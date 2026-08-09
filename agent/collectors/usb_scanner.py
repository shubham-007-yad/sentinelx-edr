import os
import sys

# Ensure parent agent directory is imported
agent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if agent_dir not in sys.path:
    sys.path.insert(0, agent_dir)

try:
    from usb_scanner import USBScanner, enumerate_usb_files
except ImportError:
    USBScanner = None
    enumerate_usb_files = None

__all__ = ["USBScanner", "enumerate_usb_files"]
