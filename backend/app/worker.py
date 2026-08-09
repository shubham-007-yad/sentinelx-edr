import time
import sys
import traceback
from app.core.logging import setup_logging, logger
from app.core.job_queue import pop_next_job, update_job_status, JobStatus
from app.db.database import SessionLocal
from app.services import (
    scheduled_report_service,
    agent_command_service,
    policy_service,
    telemetry_service,
)
from app.analytics.engine import AnalyticsEngine

setup_logging()

QUEUES_TO_LISTEN = ["reports", "fleet", "policies", "telemetry", "analytics"]

def handle_job(job: dict):
    job_id = job["job_id"]
    task_name = job["task_name"]
    payload = job.get("payload", {})

    logger.info(f"[Worker] Starting execution of job {job_id} ({task_name})")
    update_job_status(job_id, JobStatus.PROCESSING)

    db = SessionLocal()
    try:
        result = None

        if task_name == "generate_report":
            config_id = payload.get("config_id")
            if config_id:
                result = scheduled_report_service.execute_scheduled_report(db, config_id=config_id)
            else:
                engine = AnalyticsEngine(db)
                r_type = payload.get("report_type", "executive")
                tf_days = int(payload.get("timeframe_days", 7))
                fmt = payload.get("export_format", "JSON").upper()
                if fmt == "PDF":
                    res = engine.export_report_pdf(report_type=r_type, timeframe_days=tf_days)
                    result = {"format": "PDF", "bytes": len(res), "status": "generated"}
                elif fmt == "CSV":
                    res = engine.export_analytics_csv(dataset_type="incidents", timeframe_days=tf_days)
                    result = {"format": "CSV", "data": res[:200] + "...(truncated)"}
                else:
                    res = engine.generate_executive_report(timeframe_days=tf_days)
                    result = {"format": "JSON", "payload": res}

        elif task_name == "bulk_fleet_command":
            target_scope = payload.get("target_scope", "all")
            command_type = payload.get("command_type", "HEALTH_CHECK")
            cmd_params = payload.get("parameters", {})
            issued_by = payload.get("issued_by", "system")

            # Dispatch fleet commands to devices
            dispatched = agent_command_service.queue_agent_command(
                db,
                device_id=payload.get("device_id"),
                command_type=command_type,
                command_payload=cmd_params,
                issued_by=issued_by
            )
            result = {"status": "dispatched", "command": str(dispatched.id)}

        elif task_name == "bulk_policy_distribution":
            policy_id = payload.get("policy_id")
            device_ids = payload.get("device_ids", [])
            dispatched_count = 0
            if policy_id:
                policy = policy_service.get_policy_by_id(db, policy_id=policy_id)
                if policy:
                    # In a real environment, policy rules are pushed via WebSocket to target agents
                    dispatched_count = len(device_ids) if device_ids else 1
            result = {"policy_id": str(policy_id), "target_devices_notified": dispatched_count}

        elif task_name == "process_telemetry_batch":
            logs = payload.get("telemetry_logs", [])
            processed = 0
            for log_item in logs:
                telemetry_service.process_telemetry_event(db, log_item)
                processed += 1
            result = {"processed_count": processed, "status": "success"}

        elif task_name == "scheduled_analytics":
            engine = AnalyticsEngine(db)
            tf_days = int(payload.get("timeframe_days", 30))
            metrics = engine.generate_executive_report(timeframe_days=tf_days)
            result = {"timeframe_days": tf_days, "summary": metrics.get("summary")}

        else:
            raise ValueError(f"Unknown background task: '{task_name}'")

        update_job_status(job_id, JobStatus.COMPLETED, result=result)
        logger.info(f"[Worker] Job {job_id} ({task_name}) completed successfully.")

    except Exception as e:
        err_msg = f"{type(e).__name__}: {str(e)}"
        logger.error(f"[Worker] Job {job_id} failed: {err_msg}\n{traceback.format_exc()}")
        update_job_status(job_id, JobStatus.FAILED, error=err_msg)
    finally:
        db.close()

def run_worker():
    logger.info(f"[Worker] SentinelX Background Worker started listening on queues: {QUEUES_TO_LISTEN}")
    while True:
        try:
            job = pop_next_job(QUEUES_TO_LISTEN, timeout=3)
            if job:
                handle_job(job)
        except KeyboardInterrupt:
            logger.info("[Worker] Worker shutting down gracefully.")
            sys.exit(0)
        except Exception as e:
            logger.warning(f"[Worker] Error in job worker loop: {e}")
            time.sleep(2)

if __name__ == "__main__":
    run_worker()
