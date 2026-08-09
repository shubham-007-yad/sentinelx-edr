"""
Scheduled Report Service Layer
Handles creation, updates, execution, and next run calculations for recurring report configurations.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta, timezone
from uuid import UUID
from sqlalchemy.orm import Session

from app.models.scheduled_report_config import (
    ScheduledReportConfig,
    ReportTypeEnum,
    ReportFrequencyEnum,
    ReportExportFormatEnum,
)
from app.schemas.scheduled_report import ScheduledReportCreate, ScheduledReportUpdate
from app.analytics.engine import AnalyticsEngine


def calculate_next_run(frequency: ReportFrequencyEnum, from_time: Optional[datetime] = None) -> datetime:
    base = from_time if from_time else datetime.now(timezone.utc)
    if frequency == ReportFrequencyEnum.DAILY:
        return base + timedelta(days=1)
    elif frequency == ReportFrequencyEnum.WEEKLY:
        return base + timedelta(days=7)
    elif frequency == ReportFrequencyEnum.MONTHLY:
        return base + timedelta(days=30)
    return base + timedelta(days=7)


def create_scheduled_report(
    db: Session, report_in: ScheduledReportCreate, created_by: str = "admin"
) -> ScheduledReportConfig:
    next_run = calculate_next_run(report_in.frequency)
    db_config = ScheduledReportConfig(
        title=report_in.title,
        report_type=report_in.report_type,
        frequency=report_in.frequency,
        timeframe_days=report_in.timeframe_days,
        export_format=report_in.export_format,
        recipients=report_in.recipients,
        is_enabled=report_in.is_enabled,
        next_run_at=next_run,
        created_by=created_by
    )
    db.add(db_config)
    db.commit()
    db.refresh(db_config)
    return db_config


def get_scheduled_reports(db: Session, enabled_only: bool = False) -> List[ScheduledReportConfig]:
    query = db.query(ScheduledReportConfig)
    if enabled_only:
        query = query.filter(ScheduledReportConfig.is_enabled.is_(True))
    return query.order_by(ScheduledReportConfig.created_at.desc()).all()


def get_scheduled_report_by_id(db: Session, config_id: UUID) -> Optional[ScheduledReportConfig]:
    return db.query(ScheduledReportConfig).filter(ScheduledReportConfig.id == config_id).first()


def update_scheduled_report(
    db: Session, db_config: ScheduledReportConfig, report_in: ScheduledReportUpdate
) -> ScheduledReportConfig:
    update_data = report_in.model_dump(exclude_unset=True)
    for field, val in update_data.items():
        setattr(db_config, field, val)

    if "frequency" in update_data:
        db_config.next_run_at = calculate_next_run(db_config.frequency)

    db.commit()
    db.refresh(db_config)
    return db_config


def delete_scheduled_report(db: Session, config_id: UUID) -> bool:
    db_config = get_scheduled_report_by_id(db, config_id)
    if not db_config:
        return False
    db.delete(db_config)
    db.commit()
    return True


def execute_scheduled_report(db: Session, config_id: UUID) -> Dict[str, Any]:
    """
    Executes a scheduled report configuration on demand, returning generated report payload
    and updating last_run_at / next_run_at timestamps.
    """
    db_config = get_scheduled_report_by_id(db, config_id)
    if not db_config:
        raise ValueError("Scheduled report configuration not found")

    engine = AnalyticsEngine(db)
    now = datetime.now(timezone.utc)

    # Generate payload based on format & type
    if db_config.export_format == ReportExportFormatEnum.PDF:
        r_type = "executive" if db_config.report_type == ReportTypeEnum.EXECUTIVE else "technical"
        content = engine.export_report_pdf(report_type=r_type, timeframe_days=db_config.timeframe_days)
        content_type = "application/pdf"
    elif db_config.export_format == ReportExportFormatEnum.CSV:
        ds = "incidents" if db_config.report_type == ReportTypeEnum.EXECUTIVE else "technical_iocs"
        content = engine.export_analytics_csv(dataset_type=ds, timeframe_days=db_config.timeframe_days)
        content_type = "text/csv"
    else:  # JSON
        if db_config.report_type == ReportTypeEnum.TECHNICAL:
            content = engine.generate_technical_report(timeframe_days=db_config.timeframe_days)
        else:
            content = engine.generate_executive_report(timeframe_days=db_config.timeframe_days)
        content_type = "application/json"

    # Update execution timestamps
    db_config.last_run_at = now
    db_config.next_run_at = calculate_next_run(db_config.frequency, from_time=now)
    db.commit()
    db.refresh(db_config)

    return {
        "config_id": str(db_config.id),
        "title": db_config.title,
        "report_type": db_config.report_type,
        "frequency": db_config.frequency,
        "export_format": db_config.export_format,
        "content_type": content_type,
        "recipients": db_config.recipients,
        "executed_at": now.isoformat(),
        "next_run_at": db_config.next_run_at.isoformat() if db_config.next_run_at else None,
        "payload": content if isinstance(content, (dict, str)) else f"Binary PDF Data ({len(content)} bytes)"
    }
