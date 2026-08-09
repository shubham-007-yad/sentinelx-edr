import logging
import threading
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Callable
import psutil
import requests
from collectors.process_collector import ProcessCollector

logger = logging.getLogger("SentinelXAgent.LiveProcessMonitor")

DEFAULT_PROCESS_POLICY: Dict[str, Any] = {
    "monitor_powershell": True,
    "monitor_lolbins": True,
    "cpu_threshold_percent": 80.0,
    "memory_threshold_mb": 500.0,
    "allowed_processes": [],
    "blocklisted_processes": ["mimikatz.exe", "psexec.exe", "nc.exe", "ncat.exe"],
    "auto_kill_blocklisted": False,
    "parent_child_rules_enabled": True
}

POWERSHELL_NAMES = {"powershell.exe", "pwsh.exe", "powershell", "pwsh"}
LOLBIN_NAMES = {"certutil.exe", "bitsadmin.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe", "cscript.exe", "wscript.exe"}


class ProcessMonitor:
    """
    Live Process Monitor for continuous real-time process monitoring with Dynamic Security Policy Enforcement.
    Periodically collects process inventory and enforces:
    - PowerShell and LOLBin monitoring toggles
    - CPU and Memory resource consumption alerts
    - Allowed / Blocklisted process checking
    - Auto-termination of blocklisted executables when auto_kill_blocklisted is enabled
    """

    def __init__(
        self,
        interval: float = 5.0,
        long_running_threshold: float = 60.0,
        backend_url: Optional[str] = None,
        policy: Optional[Dict[str, Any]] = None
    ):
        self.interval = interval
        self.long_running_threshold = long_running_threshold
        self.backend_url = backend_url
        self.collector = ProcessCollector()
        self._previous_processes: Dict[int, Dict[str, Any]] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None

        self.policy: Dict[str, Any] = dict(DEFAULT_PROCESS_POLICY)
        if policy:
            self.policy.update(policy)

    def update_policy(self, new_policy: Dict[str, Any]):
        """Dynamically updates active Process Security Policy."""
        logger.info("[LiveProcessMonitor] Applying updated Process security policy configuration.")
        self.policy.update(new_policy)

    def _get_current_process_map(self) -> Dict[int, Dict[str, Any]]:
        """
        Collects running processes and maps them by PID with memory and CPU evaluations.
        """
        procs_map: Dict[int, Dict[str, Any]] = {}
        now = time.time()

        cpu_limit = self.policy.get("cpu_threshold_percent", 80.0)
        mem_limit_mb = self.policy.get("memory_threshold_mb", 500.0)

        for proc in psutil.process_iter(
            ['pid', 'ppid', 'name', 'exe', 'username', 'cpu_percent', 'memory_info', 'memory_percent', 'create_time', 'cmdline']
        ):
            try:
                info = proc.info
                pid = info.get('pid')
                if not pid:
                    continue

                name = info.get('name') or "unknown"
                create_time = info.get('create_time') or now
                duration = max(0.0, now - create_time)

                started_at_str = None
                if create_time:
                    try:
                        started_at_str = datetime.fromtimestamp(create_time, tz=timezone.utc).isoformat()
                    except Exception:
                        started_at_str = str(create_time)

                cmdline_list = info.get('cmdline')
                cmdline_str = " ".join(cmdline_list) if isinstance(cmdline_list, list) else (cmdline_list or None)

                cpu_pct = round(info.get('cpu_percent') or 0.0, 2)
                mem_info = info.get('memory_info')
                mem_mb = round((mem_info.rss / (1024 * 1024)), 2) if mem_info else 0.0

                exceeds_cpu = cpu_pct >= cpu_limit
                exceeds_mem = mem_mb >= mem_limit_mb

                procs_map[pid] = {
                    "pid": pid,
                    "ppid": info.get('ppid'),
                    "name": name,
                    "exe_path": info.get('exe'),
                    "username": info.get('username'),
                    "cpu_percent": cpu_pct,
                    "memory_mb": mem_mb,
                    "memory_percent": round(info.get('memory_percent') or 0.0, 2),
                    "exceeds_cpu_threshold": exceeds_cpu,
                    "exceeds_memory_threshold": exceeds_mem,
                    "create_time_epoch": create_time,
                    "duration_seconds": round(duration, 2),
                    "start_time": started_at_str,
                    "started_at": started_at_str,
                    "cmdline": cmdline_str
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                logger.debug(f"Process inspection skipped for PID {proc.pid}: {e}")
                continue

        return procs_map

    def collect_and_diff(self) -> Dict[str, Any]:
        """
        Performs a single diff cycle comparing current process map with previous snapshot,
        applying process blocklist, auto-kill, and monitoring toggles.
        """
        current_map = self._get_current_process_map()

        created: List[Dict[str, Any]] = []
        terminated: List[Dict[str, Any]] = []
        long_running: List[Dict[str, Any]] = []
        blocklist_hits: List[Dict[str, Any]] = []

        blocklist_set = set(p.lower() for p in self.policy.get("blocklisted_processes", []))
        auto_kill = self.policy.get("auto_kill_blocklisted", False)
        monitor_ps = self.policy.get("monitor_powershell", True)
        monitor_lol = self.policy.get("monitor_lolbins", True)

        # Detect newly created processes
        for pid, proc in current_map.items():
            proc_name_lower = proc["name"].lower()

            if not monitor_ps and proc_name_lower in POWERSHELL_NAMES:
                continue
            if not monitor_lol and proc_name_lower in LOLBIN_NAMES:
                continue

            if pid not in self._previous_processes:
                # Check blocklist
                if proc_name_lower in blocklist_set:
                    proc["is_blocklisted"] = True
                    blocklist_hits.append(proc)
                    logger.warning(f"⚠️ [Process Blocklist Hit] Blocklisted process '{proc['name']}' (PID {pid}) detected.")

                    if auto_kill:
                        try:
                            psutil.Process(pid).kill()
                            proc["auto_killed"] = True
                            logger.info(f"🛡️ [Auto Kill Policy] Terminated blocklisted process '{proc['name']}' (PID {pid}).")
                        except Exception as kill_err:
                            logger.error(f"Failed to auto-kill blocklisted process PID {pid}: {kill_err}")
                            proc["auto_killed"] = False

                created.append(proc)

            if proc["duration_seconds"] >= self.long_running_threshold:
                long_running.append(proc)

        # Detect terminated processes
        for pid, prev_proc in self._previous_processes.items():
            if pid not in current_map:
                terminated.append(prev_proc)

        # Update cached previous process state
        self._previous_processes = current_map

        diff_result = {
            "created": created,
            "terminated": terminated,
            "long_running": long_running,
            "blocklist_hits": blocklist_hits,
            "total_active": len(current_map),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        return diff_result

    def start_monitoring(
        self,
        device_id: str,
        callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ):
        """Starts real-time process monitoring in a background thread."""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._monitoring_loop,
            args=(device_id, callback),
            daemon=True
        )
        self._thread.start()
        logger.info(f"⚡ [LiveProcessMonitor] Started live process monitoring thread for device '{device_id}' (interval: {self.interval}s).")

    def stop_monitoring(self):
        """Stops real-time process monitoring thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
            logger.info("🛑 [LiveProcessMonitor] Live process monitor thread stopped.")

    def _monitoring_loop(
        self,
        device_id: str,
        callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ):
        while self._running:
            try:
                diff = self.collect_and_diff()

                if callback:
                    try:
                        callback(diff)
                    except Exception as cb_err:
                        logger.error(f"Error in LiveProcessMonitor callback: {cb_err}")

                if self.backend_url:
                    self._post_process_events(device_id, diff)

            except Exception as e:
                logger.error(f"Error during live process monitoring cycle: {e}")

            time.sleep(self.interval)

    def _post_process_events(self, device_id: str, diff: Dict[str, Any]):
        if not self.backend_url:
            return

        endpoint = f"{self.backend_url.rstrip('/')}/api/v1/devices/{device_id}/processes/events"
        try:
            resp = requests.post(endpoint, json=diff, timeout=5)
            if resp.status_code in (200, 201):
                logger.debug(f"Posted process events to backend. Created: {len(diff['created'])}, Terminated: {len(diff['terminated'])}")
            else:
                logger.warning(f"Failed posting process events to backend: HTTP {resp.status_code}")
        except Exception as e:
            logger.error(f"Error transmitting live process events to backend: {e}")
