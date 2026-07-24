import time
import sys
from config import config
from logger import logger
from collectors import collect_system_info, get_system_info_json
from api import APIClient


def run_heartbeat_cycle(client: APIClient, sys_info: dict):
    """Executes a single heartbeat cycle."""
    return client.send_heartbeat(ip_address=sys_info.get("ip_address"))


def main(once: bool = False):
    logger.info("==================================================")
    logger.info(f" Starting SentinelX EDR Agent v{config.AGENT_VERSION}")
    logger.info("==================================================")

    # 1. Verify and display configuration loading
    logger.info("Loading configuration settings...")
    for key, value in config.display().items():
        logger.info(f" - Config: {key} = {value}")

    # 2. Collect local system information
    logger.info("Collecting local system diagnostics...")
    sys_info = collect_system_info()
    json_output = get_system_info_json()
    logger.info("System Diagnostics JSON Payload:")
    for line in json_output.splitlines():
        logger.info(f"  {line}")

    # 3. Initialize API client and perform backend registration
    logger.info(f"Initializing API client for backend: {config.BACKEND_URL}")
    client = APIClient()
    registration_result = client.register_device(sys_info)

    if registration_result:
        logger.info("SentinelX EDR Agent initialized and registered successfully!")
    else:
        logger.warning("Agent started, but backend registration pending connection.")

    # 4. Heartbeat execution
    logger.info(f"Executing heartbeat worker (Interval: {config.HEARTBEAT_INTERVAL}s)...")
    run_heartbeat_cycle(client, sys_info)

    if once or "--once" in sys.argv:
        logger.info("Single-pass execution complete.")
        return

    try:
        while True:
            time.sleep(config.HEARTBEAT_INTERVAL)
            logger.info("Executing heartbeat cycle...")
            run_heartbeat_cycle(client, sys_info)
    except KeyboardInterrupt:
        logger.info("SentinelX EDR Agent stopped by signal.")


if __name__ == "__main__":
    main()
