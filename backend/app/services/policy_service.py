from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from app.models.security_policy import SecurityPolicy, PolicyCategory
from app.schemas.security_policy import (
    SecurityPolicyCreate, SecurityPolicyUpdate,
    USBPolicyConfigSchema, ProcessPolicyConfigSchema, NetworkPolicyConfigSchema,
    FIMPolicyConfigSchema
)


DEFAULT_USB_CONFIG: Dict[str, Any] = {
    "enable_usb_monitoring": True,
    "enable_auto_scanning": True,
    "scan_removable_only": True,
    "max_file_size_mb": 50,
    "ignored_extensions": [".tmp", ".log", ".bak", ".sys"],
    "enable_sha256_hashing": True,
    "block_unauthorized_usbs": False,
    "auto_quarantine_suspicious": False,
    "allowed_vendor_ids": [],
    "read_only_mode": False
}

DEFAULT_PROCESS_CONFIG: Dict[str, Any] = {
    "monitor_powershell": True,
    "monitor_lolbins": True,
    "cpu_threshold_percent": 80.0,
    "memory_threshold_mb": 500.0,
    "allowed_processes": [],
    "blocklisted_processes": ["mimikatz.exe", "psexec.exe", "nc.exe", "ncat.exe"],
    "auto_kill_blocklisted": False,
    "parent_child_rules_enabled": True
}

DEFAULT_NETWORK_CONFIG: Dict[str, Any] = {
    "allowed_ports": [80, 443, 53, 22, 123],
    "blocked_ports": [4444, 1337, 6667, 31337],
    "allowlisted_ips": [],
    "blocklisted_ips": ["198.51.100.99", "203.0.113.5"],
    "monitor_external_connections": True,
    "beacon_interval_threshold_seconds": 60.0,
    "beacon_jitter_percent": 20.0,
    "auto_block_c2_connections": False
}

DEFAULT_FIM_CONFIG: Dict[str, Any] = {
    "protected_folders": ["Desktop", "Downloads", "Documents", "Startup"],
    "excluded_folders": [".git", "node_modules", "tmp", "Cache", "AppData/Local/Temp"],
    "hash_algorithm": "SHA-256",
    "ransomware_modification_threshold": 20,
    "ransomware_entropy_threshold": 7.2,
    "ignore_temporary_files": True,
    "auto_quarantine_ransomware": True
}


class PolicyService:
    @staticmethod
    def get_policy(db: Session, policy_id: str) -> Optional[SecurityPolicy]:
        return db.query(SecurityPolicy).filter(SecurityPolicy.id == policy_id).first()

    @staticmethod
    def get_policies(
        db: Session,
        category: Optional[PolicyCategory] = None,
        enabled_only: bool = False
    ) -> List[SecurityPolicy]:
        query = db.query(SecurityPolicy)
        if category:
            query = query.filter(SecurityPolicy.category == category)
        if enabled_only:
            query = query.filter(SecurityPolicy.enabled.is_(True))
        return query.order_by(SecurityPolicy.priority.desc(), SecurityPolicy.created_at.desc()).all()

    @staticmethod
    def get_active_usb_policy(db: Session) -> Dict[str, Any]:
        active_policy = db.query(SecurityPolicy).filter(
            SecurityPolicy.category == PolicyCategory.USB,
            SecurityPolicy.enabled.is_(True)
        ).order_by(SecurityPolicy.priority.desc(), SecurityPolicy.version.desc()).first()

        if not active_policy or not active_policy.configuration:
            return dict(DEFAULT_USB_CONFIG)

        merged_config = dict(DEFAULT_USB_CONFIG)
        merged_config.update(active_policy.configuration)
        return merged_config

    @staticmethod
    def get_active_process_policy(db: Session) -> Dict[str, Any]:
        active_policy = db.query(SecurityPolicy).filter(
            SecurityPolicy.category == PolicyCategory.PROCESS,
            SecurityPolicy.enabled.is_(True)
        ).order_by(SecurityPolicy.priority.desc(), SecurityPolicy.version.desc()).first()

        if not active_policy or not active_policy.configuration:
            return dict(DEFAULT_PROCESS_CONFIG)

        merged_config = dict(DEFAULT_PROCESS_CONFIG)
        merged_config.update(active_policy.configuration)
        return merged_config

    @staticmethod
    def get_active_network_policy(db: Session) -> Dict[str, Any]:
        active_policy = db.query(SecurityPolicy).filter(
            SecurityPolicy.category == PolicyCategory.NETWORK,
            SecurityPolicy.enabled.is_(True)
        ).order_by(SecurityPolicy.priority.desc(), SecurityPolicy.version.desc()).first()

        if not active_policy or not active_policy.configuration:
            return dict(DEFAULT_NETWORK_CONFIG)

        merged_config = dict(DEFAULT_NETWORK_CONFIG)
        merged_config.update(active_policy.configuration)
        return merged_config

    @staticmethod
    def get_active_fim_policy(db: Session) -> Dict[str, Any]:
        active_policy = db.query(SecurityPolicy).filter(
            SecurityPolicy.category.in_([PolicyCategory.FIM, PolicyCategory.RANSOMWARE]),
            SecurityPolicy.enabled.is_(True)
        ).order_by(SecurityPolicy.priority.desc(), SecurityPolicy.version.desc()).first()

        if not active_policy or not active_policy.configuration:
            return dict(DEFAULT_FIM_CONFIG)

        merged_config = dict(DEFAULT_FIM_CONFIG)

        merged_config.update(active_policy.configuration)
        return merged_config

    @staticmethod
    def get_unified_active_policy(db: Session) -> Dict[str, Any]:
        """
        Retrieves aggregated unified active security policy across all categories
        (USB, Process, Network, FIM) with a global version checksum.
        """
        usb_cfg = PolicyService.get_active_usb_policy(db)
        proc_cfg = PolicyService.get_active_process_policy(db)
        net_cfg = PolicyService.get_active_network_policy(db)
        fim_cfg = PolicyService.get_active_fim_policy(db)

        active_policies = db.query(SecurityPolicy).filter(SecurityPolicy.enabled.is_(True)).all()
        global_version = sum(p.version for p in active_policies) if active_policies else 1

        return {
            "version": global_version,
            "timestamp": datetime.now(timezone.utc),
            "usb": usb_cfg,
            "process": proc_cfg,
            "network": net_cfg,
            "fim": fim_cfg
        }


    @staticmethod
    def create_policy(db: Session, payload: SecurityPolicyCreate) -> SecurityPolicy:
        config = payload.configuration
        if payload.category == PolicyCategory.USB:
            validated_schema = USBPolicyConfigSchema(**(config or {}))
            config = validated_schema.model_dump()
        elif payload.category == PolicyCategory.PROCESS:
            validated_schema = ProcessPolicyConfigSchema(**(config or {}))
            config = validated_schema.model_dump()
        elif payload.category == PolicyCategory.NETWORK:
            validated_schema = NetworkPolicyConfigSchema(**(config or {}))
            config = validated_schema.model_dump()
        elif payload.category in (PolicyCategory.FIM, PolicyCategory.RANSOMWARE):
            validated_schema = FIMPolicyConfigSchema(**(config or {}))
            config = validated_schema.model_dump()

        policy = SecurityPolicy(
            policy_name=payload.policy_name,
            category=payload.category,
            version=payload.version,
            enabled=payload.enabled,
            priority=payload.priority,
            configuration=config,
            created_by=payload.created_by
        )
        db.add(policy)
        db.commit()
        db.refresh(policy)
        return policy

    @staticmethod
    def update_policy(db: Session, policy_id: str, payload: SecurityPolicyUpdate) -> Optional[SecurityPolicy]:
        existing = db.query(SecurityPolicy).filter(SecurityPolicy.id == policy_id).first()
        if not existing:
            return None

        data = payload.model_dump(exclude_unset=True)
        cat = data.get("category") or existing.category
        new_config = data.get("configuration")

        if new_config is not None:
            if cat == PolicyCategory.USB:
                merged = dict(DEFAULT_USB_CONFIG)
                if existing.configuration:
                    merged.update(existing.configuration)
                merged.update(new_config)
                validated = USBPolicyConfigSchema(**merged)
                new_config = validated.model_dump()
            elif cat == PolicyCategory.PROCESS:
                merged = dict(DEFAULT_PROCESS_CONFIG)
                if existing.configuration:
                    merged.update(existing.configuration)
                merged.update(new_config)
                validated = ProcessPolicyConfigSchema(**merged)
                new_config = validated.model_dump()
            elif cat == PolicyCategory.NETWORK:
                merged = dict(DEFAULT_NETWORK_CONFIG)
                if existing.configuration:
                    merged.update(existing.configuration)
                merged.update(new_config)
                validated = NetworkPolicyConfigSchema(**merged)
                new_config = validated.model_dump()
            elif cat in (PolicyCategory.FIM, PolicyCategory.RANSOMWARE):
                merged = dict(DEFAULT_FIM_CONFIG)
                if existing.configuration:
                    merged.update(existing.configuration)
                merged.update(new_config)
                validated = FIMPolicyConfigSchema(**merged)
                new_config = validated.model_dump()
        else:
            new_config = dict(existing.configuration or {})

        # Compute next version across category
        highest_ver_policy = db.query(SecurityPolicy).filter(
            SecurityPolicy.category == cat
        ).order_by(SecurityPolicy.version.desc()).first()

        next_version = (highest_ver_policy.version + 1) if highest_ver_policy else (existing.version + 1)

        # Deactivate old policy records in this category
        db.query(SecurityPolicy).filter(SecurityPolicy.category == cat).update({"enabled": False})

        # Create new immutable policy snapshot
        new_policy = SecurityPolicy(
            policy_name=data.get("policy_name") or existing.policy_name,
            category=cat,
            version=next_version,
            enabled=data.get("enabled", True),
            priority=data.get("priority") or existing.priority or 10,
            configuration=new_config,
            created_by=data.get("created_by") or existing.created_by or "Admin"
        )
        db.add(new_policy)
        db.commit()
        db.refresh(new_policy)
        return new_policy


    @staticmethod
    def delete_policy(db: Session, policy_id: str) -> bool:
        policy = db.query(SecurityPolicy).filter(SecurityPolicy.id == policy_id).first()
        if not policy:
            return False
        db.delete(policy)
        db.commit()
        return True

    @staticmethod
    def toggle_policy(db: Session, policy_id: str, enabled: bool) -> Optional[SecurityPolicy]:
        p_uuid = uuid.UUID(str(policy_id)) if isinstance(policy_id, str) else policy_id
        policy = db.query(SecurityPolicy).filter(SecurityPolicy.id == p_uuid).first()
        if not policy:
            return None
        policy.enabled = enabled
        policy.version += 1
        db.commit()
        db.refresh(policy)
        return policy

    @staticmethod
    def clone_policy(db: Session, policy_id: str) -> Optional[SecurityPolicy]:
        p_uuid = uuid.UUID(str(policy_id)) if isinstance(policy_id, str) else policy_id
        target = db.query(SecurityPolicy).filter(SecurityPolicy.id == p_uuid).first()
        if not target:
            return None

        max_ver = db.query(SecurityPolicy).filter(SecurityPolicy.category == target.category).count()

        cloned = SecurityPolicy(
            policy_name=f"{target.policy_name} (Copy)",
            category=target.category,
            version=max_ver + 1,
            enabled=False,
            priority=target.priority,
            configuration=dict(target.configuration or {}),
            created_by="Admin"
        )
        db.add(cloned)
        db.commit()
        db.refresh(cloned)
        return cloned

    @staticmethod
    def rollback_policy(db: Session, policy_id: str) -> Optional[SecurityPolicy]:
        target = db.query(SecurityPolicy).filter(SecurityPolicy.id == policy_id).first()
        if not target:
            return None

        same_cat_policies = db.query(SecurityPolicy).filter(SecurityPolicy.category == target.category).all()
        for p in same_cat_policies:
            p.enabled = (p.id == target.id)
            if p.id == target.id:
                p.priority = 999
                p.version += 1

        db.commit()
        db.refresh(target)
        return target

