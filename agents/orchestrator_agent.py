import json
import logging
from datetime import datetime, timezone

from agents.base_agent import BaseAgent

logger = logging.getLogger(__name__)

ORCHESTRATOR_SYSTEM_PROMPT = """You are the Orchestrator Agent for an AI-powered Container Security Platform (FalcoShield SOC).

Your responsibilities:
1. Coordinate all other agents (Detection, Response, Attack, Reporting)
2. Make high-level decisions about security posture
3. Manage the operational cycle: MONITOR → DETECT → ANALYZE → RESPOND → REPORT
4. Decide when to deploy honeypot containers for threat intelligence
5. Evaluate the overall security state of the system at any time

Available agents:
- detection_agent: Analyzes Falco events and classifies threats
- response_agent: Decides on actions (kill/block/isolate/alert) for threats
- attack_agent: Simulates attacks on honeypot containers (red team)
- reporting_agent: Generates incident reports and summaries

You must always respond in JSON format with:
{
  "thought": "Your reasoning about the current state",
  "decision": "One of: CONTINUE_MONITORING, INVESTIGATE, RESPOND, RUN_ATTACK_SIM, DEPLOY_HONEYPOT, GENERATE_REPORT, SHUTDOWN",
  "reasoning": "Explanation of your decision",
  "next_agent": "Which agent should act next or null",
  "priority": "LOW|MEDIUM|HIGH|CRITICAL",
  "context": { "any relevant data to pass to next agent" }
}
"""


class OrchestratorAgent(BaseAgent):
    def __init__(self, gemini):
        super().__init__("Orchestrator", gemini, "Coordinates all security operations")
        self.set_system_prompt(ORCHESTRATOR_SYSTEM_PROMPT)
        self.cycle_state = "MONITOR"

    async def evaluate_state(self, falco_status: dict, recent_events: list,
                             detected_threats: list, response_actions: list) -> dict:
        input_data = {
            "cycle_state": self.cycle_state,
            "falco_status": falco_status,
            "recent_events_count": len(recent_events),
            "detected_threats_count": len(detected_threats),
            "response_actions_count": len(response_actions),
            "recent_events": recent_events[-10:] if recent_events else [],
            "detected_threats": detected_threats[-5:] if detected_threats else [],
            "response_actions": response_actions[-5:] if response_actions else [],
        }

        decision = self.think(input_data)
        if "decision" in decision:
            self.cycle_state = decision["decision"]
        return decision

    async def should_deploy_honeypot(self) -> bool:
        if self.iteration > 0 and self.iteration % 5 == 0:
            return True
        return False

    def get_cycle_state(self) -> str:
        return self.cycle_state
