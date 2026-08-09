from datetime import datetime
from typing import Dict, Any, Optional, List
from uuid import UUID
from pydantic import BaseModel, Field, ConfigDict
from app.models.security_policy import PolicyCategory


class FIMPolicyConfigSchema(BaseModel):
    protected_folders: List[str] = Field(
        default_factory=lambda: ["Desktop", "Downloads", "Documents", "Startup"],
        description="List of target folders/directories to continuously monitor for integrity changes"
    )
    excluded_folders: List[str] = Field(
        default_factory=lambda: [".git", "node_modules", "tmp", "Cache", "AppData/Local/Temp"],
        description="List of path patterns or subfolders to exclude from integrity monitoring"
    )
    hash_algorithm: str = Field("SHA-256", description="Cryptographic hashing algorithm (SHA-256, SHA-1, MD5)")
    ransomware_modification_threshold: int = Field(20, description="Max allowed file modifications per minute before triggering Ransomware alert")
    ransomware_entropy_threshold: float = Field(7.2, description="File Shannon entropy threshold (0.0 to 8.0) indicating high encryption risk")
    ignore_temporary_files: bool = Field(True, description="Automatically ignore temporary system and editor files (.tmp, .swp, ~$)")
    auto_quarantine_ransomware: bool = Field(True, description="Automatically quarantine process/file upon ransomware threshold breach")


class NetworkPolicyConfigSchema(BaseModel):

    allowed_ports: List[int] = Field(default_factory=lambda: [80, 443, 53, 22, 123], description="List of explicitly permitted destination/listening ports")
    blocked_ports: List[int] = Field(default_factory=lambda: [4444, 1337, 6667, 31337], description="List of strictly unauthorized/prohibited ports")
    allowlisted_ips: List[str] = Field(default_factory=list, description="List of trusted remote IP addresses / CIDR ranges")
    blocklisted_ips: List[str] = Field(default_factory=lambda: ["198.51.100.99", "203.0.113.5"], description="List of malicious / C2 remote IP addresses")
    monitor_external_connections: bool = Field(True, description="Monitor non-RFC1918 public IP connections")
    beacon_interval_threshold_seconds: float = Field(60.0, description="Beaconing timing threshold in seconds")
    beacon_jitter_percent: float = Field(20.0, description="Beaconing timing variance tolerance percentage")
    auto_block_c2_connections: bool = Field(False, description="Automatically sever or isolate connections matching C2/blocklist criteria")


class ProcessPolicyConfigSchema(BaseModel):

    monitor_powershell: bool = Field(True, description="Enable monitoring and detection rules for PowerShell processes")
    monitor_lolbins: bool = Field(True, description="Enable monitoring of Living-off-the-Land Binaries (LOLBins)")
    cpu_threshold_percent: float = Field(80.0, description="CPU usage percentage threshold to trigger resource alert")
    memory_threshold_mb: float = Field(500.0, description="Memory consumption threshold in MB to trigger resource alert")
    allowed_processes: List[str] = Field(default_factory=list, description="Allowlist of approved process names/paths")
    blocklisted_processes: List[str] = Field(
        default_factory=lambda: ["mimikatz.exe", "psexec.exe", "nc.exe", "ncat.exe"],
        description="Blocklist of unauthorized process names"
    )
    auto_kill_blocklisted: bool = Field(False, description="Automatically terminate processes matching the blocklist")
    parent_child_rules_enabled: bool = Field(True, description="Enable parent-child process lineage anomaly detection")


class USBPolicyConfigSchema(BaseModel):


    enable_usb_monitoring: bool = Field(True, description="Enable monitoring of USB insertion/removal events")
    enable_auto_scanning: bool = Field(True, description="Automatically initiate file scan on USB insertion")
    scan_removable_only: bool = Field(True, description="Limit automatic scanning strictly to removable drives")
    max_file_size_mb: int = Field(50, description="Maximum file size in MB to inspect/hash during scan")
    ignored_extensions: List[str] = Field(default_factory=lambda: [".tmp", ".log", ".bak", ".sys"], description="File extensions to ignore during scan")
    enable_sha256_hashing: bool = Field(True, description="Compute SHA-256 hashes during file scanning")
    block_unauthorized_usbs: bool = Field(False, description="Block unauthorized USB storage devices")
    auto_quarantine_suspicious: bool = Field(False, description="Automatically move suspicious files to quarantine vault")
    allowed_vendor_ids: List[str] = Field(default_factory=list, description="List of authorized USB Vendor IDs (VIDs)")
    read_only_mode: bool = Field(False, description="Enforce read-only access on connected USB storage")


class SecurityPolicyBase(BaseModel):
    policy_name: str = Field(..., description="Unique name of the security policy")
    category: PolicyCategory = Field(..., description="Policy category: USB, PROCESS, NETWORK, FIM, RANSOMWARE")
    version: int = Field(1, description="Incremental policy version number")
    enabled: bool = Field(True, description="Whether policy is active and enforced")
    priority: int = Field(10, description="Priority weight (higher priority overrides lower)")
    configuration: Dict[str, Any] = Field(default_factory=dict, description="Policy rules and setting parameters in JSON format")
    created_by: str = Field("Admin", description="Creator or managing administrator")


class SecurityPolicyCreate(SecurityPolicyBase):
    pass


class SecurityPolicyUpdate(BaseModel):
    policy_name: Optional[str] = None
    category: Optional[PolicyCategory] = None
    version: Optional[int] = None
    enabled: Optional[bool] = None
    priority: Optional[int] = None
    configuration: Optional[Dict[str, Any]] = None
    created_by: Optional[str] = None


class SecurityPolicyOut(SecurityPolicyBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    created_at: datetime
    updated_at: datetime


class UnifiedSecurityPolicySyncResponse(BaseModel):
    version: int = Field(..., description="Global policy version sequence number")
    timestamp: datetime = Field(..., description="Sync response generation timestamp")
    usb: USBPolicyConfigSchema
    process: ProcessPolicyConfigSchema
    network: NetworkPolicyConfigSchema
    fim: FIMPolicyConfigSchema


