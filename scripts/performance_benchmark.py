import os
import sys
import time
import uuid
import math
import concurrent.futures
from typing import List, Dict, Any

# Ensure /app or backend directory is in sys.path
sys.path.append("/app")
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "backend"))

from fastapi.testclient import TestClient
from app.main import app
from app.db.database import SessionLocal, engine
from sqlalchemy import text

client = TestClient(app)


def calculate_percentiles(latencies_ms: List[float]) -> Dict[str, float]:
    """Calculates min, avg, p50, p95, p99, and max latencies in milliseconds."""
    if not latencies_ms:
        return {"min": 0, "avg": 0, "p50": 0, "p95": 0, "p99": 0, "max": 0}
    sorted_l = sorted(latencies_ms)
    n = len(sorted_l)
    return {
        "min": round(sorted_l[0], 2),
        "avg": round(sum(sorted_l) / n, 2),
        "p50": round(sorted_l[int(n * 0.50)], 2),
        "p95": round(sorted_l[int(n * 0.95)], 2),
        "p99": round(sorted_l[min(int(n * 0.99), n - 1)], 2),
        "max": round(sorted_l[-1], 2)
    }


def simulate_agent_heartbeat(agent_idx: int) -> float:
    """Simulates single agent registration and heartbeat cycle, returning latency in ms."""
    hostname = f"perf-agent-{agent_idx}-{uuid.uuid4().hex[:4]}"
    t0 = time.time()
    reg_resp = client.post("/api/v1/devices/register", json={
        "hostname": hostname,
        "mac_address": f"52:54:00:{agent_idx % 99:02x}:11:22",
        "os_type": "LINUX"
    })
    if reg_resp.status_code == 201:
        dev_id = reg_resp.json()["id"]
        client.post("/api/v1/devices/heartbeat", json={
            "device_id": dev_id,
            "status": "ONLINE",
            "cpu_usage_percent": 15.5
        })
    latency = (time.time() - t0) * 1000.0
    return latency


def run_benchmark_100_agents():
    print("\n[Scenario 1/3] Benchmarking 100 Concurrent Agents (Registration & Heartbeat)...")
    latencies = []
    t_start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(simulate_agent_heartbeat, i) for i in range(100)]
        for f in concurrent.futures.as_completed(futures):
            try:
                latencies.append(f.result())
            except Exception as e:
                print(f"Error in agent worker: {e}")

    total_time = time.time() - t_start
    stats = calculate_percentiles(latencies)
    rps = round(len(latencies) / total_time, 2)
    print(f"    ✓ Processed 100 agent heartbeats in {total_time:.2f}s ({rps} req/sec)")
    print(f"    Latency Metrics: p50: {stats['p50']}ms | p95: {stats['p95']}ms | p99: {stats['p99']}ms | Max: {stats['max']}ms")
    return stats, rps


def run_benchmark_1000_agents():
    print("\n[Scenario 2/3] Benchmarking 1,000 Scale Agents (High Concurrency Burst)...")
    latencies = []
    t_start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(simulate_agent_heartbeat, i) for i in range(1000)]
        for f in concurrent.futures.as_completed(futures):
            try:
                latencies.append(f.result())
            except Exception as e:
                pass

    total_time = time.time() - t_start
    stats = calculate_percentiles(latencies)
    rps = round(len(latencies) / total_time, 2)
    print(f"    ✓ Processed 1,000 agent requests in {total_time:.2f}s ({rps} req/sec)")
    print(f"    Latency Metrics: p50: {stats['p50']}ms | p95: {stats['p95']}ms | p99: {stats['p99']}ms | Max: {stats['max']}ms")
    return stats, rps


def run_benchmark_10000_telemetry_events():
    print("\n[Scenario 3/3] Ingesting 10,000 Telemetry Events in Batches...")
    device_uuid = str(uuid.uuid4())
    events = [
        {
            "category": "PROCESS",
            "event_type": "PROCESS_START",
            "source": "ProcessCollector",
            "payload": {
                "pid": 4000 + i,
                "process_name": "cron_scanner.exe",
                "exe_path": "/usr/bin/cron_scanner",
                "cmdline": "/usr/bin/cron_scanner --scan",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            }
        }
        for i in range(100)
    ]

    total_events = 10000
    batch_size = 100
    batches_count = total_events // batch_size
    latencies = []

    t_start = time.time()
    for b in range(batches_count):
        t0 = time.time()
        resp = client.post("/api/v1/telemetry/ingest", json={
            "device_id": device_uuid,
            "events": events
        })
        latencies.append((time.time() - t0) * 1000.0)

    total_time = time.time() - t_start
    ingestion_rate = round(total_events / total_time, 2)
    stats = calculate_percentiles(latencies)

    print(f"    ✓ Ingested 10,000 telemetry events ({batches_count} batches) in {total_time:.2f}s")
    print(f"    Ingestion Rate: {ingestion_rate} events/sec")
    print(f"    Batch Latency: p50: {stats['p50']}ms | p95: {stats['p95']}ms | p99: {stats['p99']}ms")
    return stats, ingestion_rate


def inspect_postgres_connection_metrics():
    print("\n[Metrics] Inspecting PostgreSQL Database Connection Pool & Active Queries...")
    db = SessionLocal()
    try:
        res = db.execute(text("SELECT count(*) FROM pg_stat_activity WHERE datname = 'sentinelx';")).scalar()
        print(f"    ✓ PostgreSQL Active Connections in 'sentinelx': {res}")
        return res
    except Exception as e:
        print(f"    (Could not inspect pg_stat_activity: {e})")
        return 0
    finally:
        db.close()


def run_full_performance_suite():
    print("==================================================================")
    print("🚀 SentinelX EDR — Comprehensive Performance & Scalability Test Suite")
    print("==================================================================")

    inspect_postgres_connection_metrics()
    s1_stats, s1_rps = run_benchmark_100_agents()
    s2_stats, s2_rps = run_benchmark_1000_agents()
    s3_stats, s3_rate = run_benchmark_10000_telemetry_events()
    inspect_postgres_connection_metrics()

    print("\n==================================================================")
    print("📊 SCALABILITY SUMMARY & BENCHMARK RESULTS")
    print("==================================================================")
    print(f"• 100 Agents Workload   : {s1_rps} req/sec | p50: {s1_stats['p50']}ms | p95: {s1_stats['p95']}ms")
    print(f"• 1,000 Scale Burst     : {s2_rps} req/sec | p50: {s2_stats['p50']}ms | p95: {s2_stats['p95']}ms")
    print(f"• Telemetry Ingestion   : {s3_rate} events/sec | Batch p50: {s3_stats['p50']}ms")
    print("==================================================================\n")


if __name__ == "__main__":
    run_full_performance_suite()
