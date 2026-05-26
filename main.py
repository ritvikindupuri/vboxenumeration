import logging
import os
import sys

from dotenv import load_dotenv

from core.claude_client import ClaudeClient
from core.engine import AuditEngine
from dashboard.app import start_dashboard

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("main")


def main():
    load_dotenv()

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        logger.error("ANTHROPIC_API_KEY not set in .env")
        sys.exit(1)

    model = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
    claude = ClaudeClient(api_key=api_key, model=model)
    engine = AuditEngine(claude)

    host = os.getenv("DASHBOARD_HOST", "0.0.0.0")
    port = os.getenv("DASHBOARD_PORT", "8080")

    logger.info("=" * 60)
    logger.info("VBoxAuditor — Attack Surface Enumeration Tool")
    logger.info("=" * 60)
    logger.info(f"Dashboard: http://localhost:{port}")
    logger.info("Open in browser and click 'Execute Audit' to begin")
    logger.info("=" * 60)

    try:
        start_dashboard(engine)
    except KeyboardInterrupt:
        logger.info("Shutting down...")


if __name__ == "__main__":
    main()
