from datetime import datetime, timezone
import logging
from typing import List, Dict, Any, Optional
import psutil
import requests

logger = logging.getLogger("SentinelXAgent.ProcessCollector")


class ProcessCollector:
    """
    Collects system process inventory from endpoint using psutil.
    Gathers process metadata: PID, PPID, name, exe_path, username, cpu_percent, memory_percent, start_time, and cmdline.
    """

    def collect(self) -> List[Dict[str, Any]]:
        processes: List[Dict[str, Any]] = []

        # Iterate over all running processes
        for proc in psutil.process_iter(
            ['pid', 'ppid', 'name', 'exe', 'username', 'cpu_percent', 'memory_percent', 'create_time', 'cmdline']
        ):
            try:
                info = proc.info
                pid = info.get('pid')
                ppid = info.get('ppid')
                name = info.get('name') or "unknown"
                exe_path = info.get('exe')
                username = info.get('username')
                cpu_percent = info.get('cpu_percent') or 0.0
                memory_percent = info.get('memory_percent') or 0.0

                # Convert create_time to ISO format timestamp string
                create_time_raw = info.get('create_time')
                started_at_str = None
                if create_time_raw:
                    try:
                        started_at_str = datetime.fromtimestamp(create_time_raw, tz=timezone.utc).isoformat()
                    except Exception:
                        started_at_str = str(create_time_raw)

                cmdline_list = info.get('cmdline')
                cmdline_str = None
                if cmdline_list and isinstance(cmdline_list, list):
                    cmdline_str = " ".join(cmdline_list)
                elif isinstance(cmdline_list, str):
                    cmdline_str = cmdline_list

                proc_entry = {
                    "pid": pid,
                    "ppid": ppid,
                    "name": name,
                    "exe_path": exe_path,
                    "username": username,
                    "cpu_percent": round(cpu_percent, 2),
                    "memory_percent": round(memory_percent, 2),
                    "start_time": started_at_str,
                    "started_at": started_at_str,
                    "cmdline": cmdline_str
                }
                processes.append(proc_entry)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                logger.debug(f"Error reading process info: {e}")
                continue

        return processes

    def send_processes(self, backend_url: str, device_id: str, timeout: int = 10) -> bool:
        """
        Sends gathered process inventory payload to backend endpoint.
        """
        processes = self.collect()
        endpoint = f"{backend_url.rstrip('/')}/api/v1/devices/{device_id}/processes"
        payload = {"processes": processes}

        try:
            resp = requests.post(endpoint, json=payload, timeout=timeout)
            if resp.status_code in (200, 201):
                logger.info(f"Successfully posted {len(processes)} processes to backend for device {device_id}")
                return True
            else:
                logger.warning(f"Failed to post process inventory. Status: {resp.status_code}, Body: {resp.text}")
                return False
        except Exception as e:
            logger.error(f"Error transmitting process inventory to backend: {e}")
            return False


def collect_process_inventory() -> List[Dict[str, Any]]:
    """Utility function to collect process inventory list."""
    return ProcessCollector().collect()
