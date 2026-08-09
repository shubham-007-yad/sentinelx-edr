from datetime import datetime, timezone
import logging
import socket
import threading
import time
from typing import List, Dict, Any, Optional, Callable
import psutil
import requests

logger = logging.getLogger("SentinelXAgent.NetworkCollector")


class NetworkCollector:
    """
    Collects active network connection inventory from endpoint using psutil.
    Gathers socket metadata: PID, process_name, executable_path, local_ip, local_port,
    remote_ip, remote_port, protocol (TCP/UDP), connection state, bytes sent/received, and timestamp.
    """

    def collect(self) -> List[Dict[str, Any]]:
        connections: List[Dict[str, Any]] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        # Cache process names and exe paths by PID for efficiency during collection
        proc_cache: Dict[int, Dict[str, Optional[str]]] = {}

        try:
            net_conns = psutil.net_connections(kind='inet')
        except Exception as e:
            logger.warning(f"Failed to fetch net_connections with kind='inet': {e}. Retrying with 'all'...")
            try:
                net_conns = psutil.net_connections(kind='all')
            except Exception as ex:
                logger.error(f"Error getting network connections from psutil: {ex}")
                return connections

        for conn in net_conns:
            try:
                pid = conn.pid
                proc_name: Optional[str] = None
                exe_path: Optional[str] = None

                if pid:
                    if pid in proc_cache:
                        proc_name = proc_cache[pid]["name"]
                        exe_path = proc_cache[pid]["exe"]
                    else:
                        try:
                            proc = psutil.Process(pid)
                            proc_name = proc.name()
                            exe_path = proc.exe()
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                            proc_name = "unknown"
                            exe_path = None
                        except Exception:
                            proc_name = "unknown"
                            exe_path = None
                        proc_cache[pid] = {"name": proc_name, "exe": exe_path}

                # Local binding info
                local_ip = conn.laddr.ip if conn.laddr else None
                local_port = conn.laddr.port if conn.laddr else None

                # Remote binding info
                remote_ip = conn.raddr.ip if conn.raddr else None
                remote_port = conn.raddr.port if conn.raddr else None

                # Protocol determination
                protocol_str = "TCP"
                if conn.type == socket.SOCK_DGRAM:
                    protocol_str = "UDP"
                elif conn.type == socket.SOCK_STREAM:
                    protocol_str = "TCP"
                else:
                    protocol_str = str(conn.type)

                # State determination
                state_str = conn.status if conn.status else "NONE"

                conn_entry = {
                    "pid": pid,
                    "process_name": proc_name,
                    "executable_path": exe_path,
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "protocol": protocol_str.upper(),
                    "state": state_str.upper(),
                    "bytes_sent": 0,
                    "bytes_received": 0,
                    "timestamp": now_iso
                }
                connections.append(conn_entry)

            except Exception as e:
                logger.debug(f"Skipping socket entry due to collection error: {e}")
                continue

        return connections

    def send_network_connections(self, backend_url: str, device_id: str, timeout: int = 10) -> bool:
        """
        Sends gathered network connection inventory payload to backend endpoint.
        """
        connections = self.collect()
        endpoint = f"{backend_url.rstrip('/')}/api/v1/devices/{device_id}/network"
        payload = {"connections": connections}

        try:
            resp = requests.post(endpoint, json=payload, timeout=timeout)
            if resp.status_code in (200, 201):
                logger.info(f"Successfully posted {len(connections)} network connections to backend for device {device_id}")
                return True
            else:
                logger.warning(f"Failed to post network connections. Status: {resp.status_code}, Body: {resp.text}")
                return False
        except Exception as e:
            logger.error(f"Error transmitting network connections to backend: {e}")
            return False


def collect_network_connections() -> List[Dict[str, Any]]:
    """Utility function to collect active network connections list."""
    return NetworkCollector().collect()


DEFAULT_NETWORK_POLICY: Dict[str, Any] = {
    "allowed_ports": [80, 443, 53, 22, 123],
    "blocked_ports": [4444, 1337, 6667, 31337],
    "allowlisted_ips": [],
    "blocklisted_ips": ["198.51.100.99", "203.0.113.5"],
    "monitor_external_connections": True,
    "beacon_interval_threshold_seconds": 60.0,
    "beacon_jitter_percent": 20.0,
    "auto_block_c2_connections": False
}


class NetworkMonitor:
    """
    Background worker daemon for continuous real-time network connection monitoring with Dynamic Network Policy Enforcement.
    Maintains an in-memory cache to calculate connection diffs between polling cycles:
    - CONNECTED (new connection opened)
    - DISCONNECTED (connection closed)
    - STATE_CHANGED (socket state transition)
    - LONG_RUNNING (long-lived sessions)
    - POLICY_VIOLATIONS (blocked ports, C2 IPs, external connection flags)
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
        self.collector = NetworkCollector()
        self._previous_connections: Dict[tuple, Dict[str, Any]] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None

        self.policy: Dict[str, Any] = dict(DEFAULT_NETWORK_POLICY)
        if policy:
            self.policy.update(policy)

    def update_policy(self, new_policy: Dict[str, Any]):
        """Dynamically updates active Network Security Policy."""
        logger.info("[NetworkMonitor] Applying updated Network security policy configuration.")
        self.policy.update(new_policy)

    def _make_conn_key(self, conn: Dict[str, Any]) -> tuple:
        return (
            conn.get("protocol"),
            conn.get("local_ip"),
            conn.get("local_port"),
            conn.get("remote_ip"),
            conn.get("remote_port"),
            conn.get("pid")
        )

    def is_private_ip(self, ip: Optional[str]) -> bool:
        if not ip or ip in ("127.0.0.1", "0.0.0.0", "::1"):
            return True
        return ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.") or ip.startswith("172.17.") or ip.startswith("172.18.") or ip.startswith("172.19.") or ip.startswith("172.20.") or ip.startswith("172.30.") or ip.startswith("172.31.")

    def collect_and_diff(self) -> Dict[str, Any]:
        """
        Performs a diff cycle comparing current network connections snapshot with previous cached snapshot.
        Categorizes live connection events and evaluates against Network Policy rules.
        """
        raw_conns = self.collector.collect()
        now_epoch = time.time()

        blocked_ports = set(self.policy.get("blocked_ports", []))
        blocklisted_ips = set(self.policy.get("blocklisted_ips", []))
        monitor_external = self.policy.get("monitor_external_connections", True)
        auto_block = self.policy.get("auto_block_c2_connections", False)

        current_map: Dict[tuple, Dict[str, Any]] = {}
        for conn in raw_conns:
            key = self._make_conn_key(conn)

            # Preserve first_seen_epoch for duration tracking
            if key in self._previous_connections:
                first_seen = self._previous_connections[key].get("first_seen_epoch", now_epoch)
            else:
                first_seen = now_epoch

            conn["first_seen_epoch"] = first_seen
            conn["duration_seconds"] = round(max(0.0, now_epoch - first_seen), 2)

            r_port = conn.get("remote_port")
            r_ip = conn.get("remote_ip")

            conn["is_blocked_port"] = bool(r_port and r_port in blocked_ports)
            conn["is_blocklisted_ip"] = bool(r_ip and r_ip in blocklisted_ips)
            conn["is_external"] = bool(monitor_external and r_ip and not self.is_private_ip(r_ip))

            current_map[key] = conn

        connected: List[Dict[str, Any]] = []
        disconnected: List[Dict[str, Any]] = []
        state_changed: List[Dict[str, Any]] = []
        long_running: List[Dict[str, Any]] = []
        policy_violations: List[Dict[str, Any]] = []

        # 1. Detect CONNECTED, STATE_CHANGED, LONG_RUNNING, and POLICY_VIOLATIONS
        for key, conn in current_map.items():
            if conn["is_blocked_port"] or conn["is_blocklisted_ip"]:
                conn["violates_policy"] = True
                policy_violations.append(conn)
                logger.warning(f"⚠️ [Network Policy Violation] Socket to {conn.get('remote_ip')}:{conn.get('remote_port')} violates network policy.")

                if auto_block and conn.get("pid"):
                    try:
                        psutil.Process(conn["pid"]).kill()
                        conn["auto_severed"] = True
                        logger.info(f"🛡️ [Auto Sever Policy] Terminated process PID {conn['pid']} connecting to blocked target {conn.get('remote_ip')}.")
                    except Exception as kill_err:
                        logger.error(f"Failed to auto-sever process PID {conn.get('pid')}: {kill_err}")
                        conn["auto_severed"] = False

            if key not in self._previous_connections:
                connected.append(conn)
            else:
                prev_conn = self._previous_connections[key]
                prev_state = prev_conn.get("state")
                curr_state = conn.get("state")
                if prev_state != curr_state:
                    state_changed.append({
                        "connection": conn,
                        "old_state": prev_state or "NONE",
                        "new_state": curr_state or "NONE"
                    })

            if conn["duration_seconds"] >= self.long_running_threshold:
                long_running.append(conn)

        # 2. Detect DISCONNECTED
        for key, prev_conn in self._previous_connections.items():
            if key not in current_map:
                disconnected.append(prev_conn)

        # Update cached previous state
        self._previous_connections = current_map

        diff_result = {
            "connected": connected,
            "disconnected": disconnected,
            "state_changed": state_changed,
            "long_running": long_running,
            "policy_violations": policy_violations,
            "total_active": len(current_map),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        return diff_result


    def start_monitoring(
        self,
        device_id: str,
        callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ):
        """Starts background network connection collector thread."""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._monitoring_loop,
            args=(device_id, callback),
            daemon=True
        )
        self._thread.start()
        logger.info(f"⚡ [NetworkMonitor] Started live network monitoring thread for device '{device_id}' (interval: {self.interval}s).")

    def stop_monitoring(self):
        """Stops background network monitoring thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
            logger.info("🛑 [NetworkMonitor] Network monitor thread stopped.")

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
                        logger.error(f"Error in NetworkMonitor callback: {cb_err}")

                if self.backend_url:
                    self._post_network_events(device_id, diff)
            except Exception as e:
                logger.error(f"Error during network monitoring loop: {e}")

            time.sleep(self.interval)

    def _post_network_events(self, device_id: str, diff: Dict[str, Any]):
        if not self.backend_url:
            return

        endpoint = f"{self.backend_url.rstrip('/')}/api/v1/devices/{device_id}/network/events"
        try:
            resp = requests.post(endpoint, json=diff, timeout=5)
            if resp.status_code in (200, 201):
                logger.debug(f"Posted live network events to backend. Connected: {len(diff['connected'])}, Disconnected: {len(diff['disconnected'])}")
            else:
                logger.warning(f"Failed posting network events to backend: HTTP {resp.status_code}")
        except Exception as e:
            logger.error(f"Error transmitting live network events to backend: {e}")
