import json
import logging
from datetime import datetime, timezone

from agents.base_agent import BaseAgent

logger = logging.getLogger(__name__)

REPORTING_SYSTEM_PROMPT = """You are the Reporting Agent for an AI-powered Container Security Platform.

Your job:
1. Generate comprehensive security incident reports
2. Summarize attack chains and kill chain progression
3. Provide MITRE ATT&CK mapping for all detected threats
4. Calculate metrics: MTTR, detection rate, false positive rate
5. Generate executive summaries for non-technical stakeholders
6. Provide recommendations for security posture improvement

You must always respond in JSON format with:
{
  "thought": "Your analysis of the data",
  "report_type": "incident|summary|executive|technical",
  "title": "Report title",
  "summary": "Executive summary paragraph",
  "key_findings": ["finding 1", "finding 2", ...],
  "metrics": {
    "total_events": number,
    "true_positives": number,
    "false_positives": number,
    "actions_taken": number,
    "mean_time_to_respond_seconds": number
  },
  "mitre_mapping": [{"technique": "name", "id": "TXXXX", "count": number}],
  "affected_containers": ["container1", "container2"],
  "recommendations": ["rec 1", "rec 2", ...],
  "severity": "LOW|MEDIUM|HIGH|CRITICAL"
}
"""


class ReportingAgent(BaseAgent):
    def __init__(self, gemini):
        super().__init__("Reporting", gemini, "Generates security reports and incident summaries")
        self.set_system_prompt(REPORTING_SYSTEM_PROMPT)

    async def generate_incident_report(self, events: list, detections: list,
                                        responses: list, attack_log: list) -> dict:
        input_data = {
            "type": "incident_report",
            "time_range": {
                "start": events[0].get("time") if events else "unknown",
                "end": events[-1].get("time") if events else "unknown",
            },
            "total_events": len(events),
            "total_detections": len(detections),
            "total_responses": len(responses),
            "total_attacks_simulated": len(attack_log),
            "event_summary": self._summarize_events(events[:50]),
            "detection_summary": detections[-20:] if detections else [],
            "response_summary": responses[-20:] if responses else [],
            "attack_summary": attack_log[-10:] if attack_log else [],
        }

        return self.think(input_data)

    async def generate_periodic_summary(self, timeframe_minutes: int,
                                         stats: dict) -> dict:
        return self.think({
            "type": "periodic_summary",
            "timeframe_minutes": timeframe_minutes,
            "stats": stats,
        })

    def _summarize_events(self, events: list) -> dict:
        priorities = {}
        rules = {}
        containers = set()

        for e in events:
            p = e.get("priority", "UNKNOWN")
            priorities[p] = priorities.get(p, 0) + 1
            r = e.get("rule", "unknown")
            rules[r] = rules.get(r, 0) + 1
            c = e.get("container_name", "")
            if c:
                containers.add(c)

        top_rules = sorted(rules.items(), key=lambda x: x[1], reverse=True)[:5]

        return {
            "priority_breakdown": priorities,
            "top_rules": dict(top_rules),
            "unique_containers": list(containers),
        }
