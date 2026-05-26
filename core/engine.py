import json
import logging
import threading
from queue import Queue
from typing import Callable

from agents.analyzer_agent import AnalyzerAgent
from agents.enumerator_agent import EnumeratorAgent
from agents.exploiter_agent import ExploiterAgent
from agents.remediator_agent import RemediatorAgent
from agents.reporter_agent import ReporterAgent
from core.claude_client import ClaudeClient

logger = logging.getLogger(__name__)


class AuditEngine:
    def __init__(self, claude: ClaudeClient):
        self.claude = claude
        self.enumerator = EnumeratorAgent()
        self.analyzer = AnalyzerAgent(claude)
        self.exploiter = ExploiterAgent()
        self.reporter = ReporterAgent()
        self.remediator = RemediatorAgent(claude)
        self.event_queue: Queue = Queue()
        self._running = False

        for agent in [self.enumerator, self.analyzer, self.exploiter, self.reporter]:
            agent.on_event(self._handle_event)

    def _handle_event(self, agent_name: str, event_type: str, data: dict):
        self.event_queue.put({
            "agent": agent_name,
            "type": event_type,
            "data": data,
        })
        logger.info(f"[{agent_name}] {event_type}: {json.dumps(data)[:200]}")

    def on_event(self, handler: Callable):
        self.event_queue.put = lambda item, _orig=self.event_queue.put: (
            handler(item) or _orig(item)
        )

    def run_audit(self) -> dict:
        self._running = True
        context = {}

        try:
            logger.info("=== Phase 1: Enumeration ===")
            enum_result = self.enumerator.run(context)
            context["enumeration"] = enum_result

            logger.info("=== Phase 2: Analysis ===")
            analysis_result = self.analyzer.run(context)
            context["findings"] = analysis_result.get("findings", [])
            context["summary"] = analysis_result.get("summary", {})
            context["executive_summary"] = analysis_result.get("executive_summary", "")

            logger.info("=== Phase 3: Active Exploitation ===")
            exploit_result = self.exploiter.run(context)
            context["exploitation"] = exploit_result

            logger.info("=== Phase 4: Report Generation ===")
            report_result = self.reporter.run(context)
            context["report"] = report_result

            logger.info("=== Audit Complete ===")
            return context

        finally:
            self._running = False

    def run_remediation(self, finding: dict, event_handler: Callable) -> dict:
        self.remediator._handlers = []
        self.remediator.on_event(event_handler)
        result = self.remediator.remediate(finding)
        return result

    def get_events(self, block=True, timeout=None) -> dict | None:
        try:
            return self.event_queue.get(block=block, timeout=timeout)
        except Exception:
            return None
