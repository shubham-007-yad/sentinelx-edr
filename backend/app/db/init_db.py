from sqlalchemy.orm import Session
from app.models.user import User, UserRole
from app.schemas.user import UserCreate, UserUpdate
from app.services import user_service

from sqlalchemy import text

def init_db(db: Session) -> None:
    """
    Seed initial database data, ensuring at least one Admin account exists with known credentials.
    """
    try:
        connection = db.connection().execution_options(isolation_level="AUTOCOMMIT")
        new_values = [
            'SUSPICIOUS_POWERSHELL', 'SUSPICIOUS_CMD', 'LOLBIN_ABUSE', 'SUSPICIOUS_PROCESS_BEHAVIOR',
            'SUSPICIOUS_NETWORK_PORT', 'BLACK_LISTED_IP', 'EXCESSIVE_CONNECTIONS', 'UNEXPECTED_INTERNET_ACCESS', 'C2_BEACONING',
            'FIM_EXECUTABLE_IN_DOWNLOADS', 'FIM_DOUBLE_EXTENSION_MASQUERADE', 'FIM_STARTUP_MODIFICATION', 'FIM_MASS_FILE_MODIFICATION',
            'BRUTE_FORCE_AUTHENTICATION', 'PRIVILEGE_ESCALATION', 'UNAUTHORIZED_ACCOUNT_CREATION', 'DEFENSE_EVASION_LOG_CLEARING',
            'SUSPICIOUS_RDP_LOGON', 'PERSISTENCE_SERVICE_CREATION', 'AGENT_HEALTH_ISSUE'
        ]
        for val in new_values:
            try:
                connection.execute(text(f"ALTER TYPE threattype ADD VALUE IF NOT EXISTS '{val}';"))
            except Exception:
                pass

        resp_values = [
            'TERMINATE_PROCESS', 'SUSPEND_PROCESS', 'MARK_TRUSTED', 'ADD_ALLOWLIST', 'BLOCK_IP',
            'INVESTIGATE', 'RESTORE_BASELINE', 'RECALCULATE_BASELINE', 'IGNORE_CHANGE',
            'DISABLE_USER', 'FORCE_LOGOUT', 'ALLOWLIST_EVENT'
        ]
        for val in resp_values:
            try:
                connection.execute(text(f"ALTER TYPE responseactiontype ADD VALUE IF NOT EXISTS '{val}';"))
            except Exception:
                pass

        cat_values = ['IOC_INTELLIGENCE', 'RANSOMWARE']
        for val in cat_values:
            try:
                connection.execute(text(f"ALTER TYPE telemetrycategoryenum ADD VALUE IF NOT EXISTS '{val}';"))
            except Exception:
                pass

        try:
            connection.execute(text("ALTER TABLE threats ALTER COLUMN scan_result_id DROP NOT NULL;"))
            connection.execute(text("ALTER TABLE network_connections ADD COLUMN IF NOT EXISTS threat_id UUID REFERENCES threats(id) ON DELETE SET NULL;"))
            connection.execute(text("ALTER TABLE network_connections ADD COLUMN IF NOT EXISTS alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL;"))
            connection.execute(text("ALTER TABLE telemetry_logs ADD COLUMN IF NOT EXISTS correlation_id UUID;"))
            connection.execute(text("ALTER TABLE telemetry_logs ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(100) DEFAULT 'default_tenant';"))
            connection.execute(text("ALTER TABLE investigation_cases ADD COLUMN IF NOT EXISTS linked_alert_ids JSONB DEFAULT '[]'::jsonb;"))
            connection.execute(text("ALTER TABLE investigation_cases ADD COLUMN IF NOT EXISTS linked_telemetry_ids JSONB DEFAULT '[]'::jsonb;"))
        except Exception:
            pass
    except Exception:
        pass


    import os
    admin_pass = os.getenv("INITIAL_ADMIN_PASSWORD", "AdminPassword123!")
    analyst_pass = os.getenv("INITIAL_ANALYST_PASSWORD", "AnalystPassword123!")

    admin_user = user_service.get_user_by_username(db, username="admin")
    if not admin_user:
        admin_in = UserCreate(
            email=os.getenv("INITIAL_ADMIN_EMAIL", "admin@sentinelx.io"),
            username="admin",
            password=admin_pass,
            role=UserRole.ADMIN,
            is_active=True
        )
        user_service.create_user(db, user_in=admin_in)

    analyst_user = user_service.get_user_by_username(db, username="analyst")
    if not analyst_user:
        analyst_in = UserCreate(
            email=os.getenv("INITIAL_ANALYST_EMAIL", "analyst@sentinelx.io"),
            username="analyst",
            password=analyst_pass,
            role=UserRole.ANALYST,
            is_active=True
        )
        user_service.create_user(db, user_in=analyst_in)
