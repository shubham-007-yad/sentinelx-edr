from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, Set


class IPReputationProvider(ABC):
    """Abstract interface for IP Reputation Providers (AbuseIPDB, OTX, VirusTotal, MISP, Local)."""

    @abstractmethod
    def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Checks if an IP address is malicious or blacklisted.
        Returns dict with threat details if flagged, otherwise None.
        """
        pass


class LocalIPReputationProvider(IPReputationProvider):
    """
    Local IP Reputation Provider MVP using a configurable blacklist set.
    """

    DEFAULT_BLACKLIST: Set[str] = {
        "185.220.101.5",   # Tor exit node / C2 test IP
        "192.42.116.16",   # Known scanner IP
        "45.154.255.71",   # Malicious C2 server
        "10.0.0.5",        # Internal test blacklisted IP
        "198.51.100.1",    # Test documentation IP
    }

    def __init__(self, blacklisted_ips: Optional[Set[str]] = None):
        self.blacklisted_ips = set(blacklisted_ips) if blacklisted_ips is not None else set(self.DEFAULT_BLACKLIST)

    def add_blacklisted_ip(self, ip: str):
        self.blacklisted_ips.add(ip)

    def remove_blacklisted_ip(self, ip: str):
        self.blacklisted_ips.discard(ip)

    def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        if not ip:
            return None
        if ip in self.blacklisted_ips:
            return {
                "ip": ip,
                "is_malicious": True,
                "provider": "LocalBlacklist",
                "category": "Command & Control / Malicious IP",
                "confidence": 95.0
            }
        return None
