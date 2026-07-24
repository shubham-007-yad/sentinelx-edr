import sys
from config import config
from logger import logger
from collectors import collect_system_info
from api import APIClient


def main():
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
    for key, value in sys_info.items():
        logger.info(f" - System Info: {key} = {value}")

    # 3. Initialize API client and perform backend registration
    logger.info(f"Initializing API client for backend: {config.BACKEND_URL}")
    client = APIClient()
    registration_result = client.register_device(sys_info)

    if registration_result:
        logger.info("SentinelX EDR Agent initialized and registered successfully!")
    else:
        logger.warning("Agent started, but backend registration pending connection.")

    logger.info("SentinelX EDR Agent foundation runner completed initial startup cycle.")


if __name__ == "__main__":
    main()
