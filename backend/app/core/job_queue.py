import json
import uuid
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
import redis

from app.core.config import settings
from app.core.logging import logger

JOB_KEY_PREFIX = "sentinelx:job:"
QUEUE_PREFIX = "sentinelx:queue:"
JOBS_INDEX_KEY = "sentinelx:jobs_index"
JOB_TTL_SECONDS = 86400 * 7  # 7 days retention

def get_redis_client() -> redis.Redis:
    return redis.Redis.from_url(
        settings.REDIS_URL,
        decode_responses=True,
        socket_timeout=5,
        socket_connect_timeout=5
    )

class JobStatus:
    PENDING = "PENDING"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

def enqueue_job(queue_name: str, task_name: str, payload: Dict[str, Any], created_by: str = "system") -> Dict[str, Any]:
    """
    Enqueues a background job into Redis and returns job metadata.
    """
    client = get_redis_client()
    job_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    job_data = {
        "job_id": job_id,
        "task_name": task_name,
        "queue_name": queue_name,
        "status": JobStatus.PENDING,
        "created_by": created_by,
        "created_at": now_iso,
        "started_at": None,
        "completed_at": None,
        "payload": payload,
        "result": None,
        "error": None
    }

    job_key = f"{JOB_KEY_PREFIX}{job_id}"
    raw_json = json.dumps(job_data)

    client.setex(job_key, JOB_TTL_SECONDS, raw_json)
    client.lpush(JOBS_INDEX_KEY, job_id)
    client.ltrim(JOBS_INDEX_KEY, 0, 499)  # Keep last 500 job references

    queue_key = f"{QUEUE_PREFIX}{queue_name}"
    client.rpush(queue_key, job_id)

    logger.info(f"[JobQueue] Enqueued job {job_id} ({task_name}) to queue '{queue_name}'")
    return job_data

def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    client = get_redis_client()
    job_key = f"{JOB_KEY_PREFIX}{job_id}"
    raw_json = client.get(job_key)
    if not raw_json:
        return None
    try:
        return json.loads(raw_json)
    except Exception:
        return None

def update_job_status(
    job_id: str,
    status: str,
    result: Optional[Any] = None,
    error: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    client = get_redis_client()
    job = get_job(job_id)
    if not job:
        return None

    now_iso = datetime.now(timezone.utc).isoformat()
    job["status"] = status

    if status == JobStatus.PROCESSING:
        job["started_at"] = now_iso
    elif status in (JobStatus.COMPLETED, JobStatus.FAILED):
        job["completed_at"] = now_iso
        job["result"] = result
        job["error"] = error

    job_key = f"{JOB_KEY_PREFIX}{job_id}"
    client.setex(job_key, JOB_TTL_SECONDS, json.dumps(job))
    logger.info(f"[JobQueue] Updated job {job_id} -> {status}")
    return job

def pop_next_job(queue_names: List[str], timeout: int = 5) -> Optional[Dict[str, Any]]:
    """
    Blocks waiting for the next job in specified queue names.
    Returns job metadata dict or None if timeout expires.
    """
    client = get_redis_client()
    keys = [f"{QUEUE_PREFIX}{q}" for q in queue_names]
    res = client.blpop(keys, timeout=timeout)
    if not res:
        return None

    queue_key, job_id = res
    job = get_job(job_id)
    return job

def list_recent_jobs(limit: int = 50) -> List[Dict[str, Any]]:
    client = get_redis_client()
    job_ids = client.lrange(JOBS_INDEX_KEY, 0, limit - 1)
    jobs = []
    for jid in job_ids:
        j = get_job(jid)
        if j:
            jobs.append(j)
    return jobs
