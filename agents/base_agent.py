import json
import logging
from datetime import datetime, timezone

from core.gemini_client import GeminiClient

logger = logging.getLogger(__name__)

AGENT_COLORS = {
    "Orchestrator": "#8b5cf6",
    "Detection": "#ef4444",
    "Response": "#f97316",
    "AttackAgent": "#dc2626",
    "Reporting": "#3b82f6",
}

AGENT_ICONS = {
    "Orchestrator": "\u2699\ufe0f",
    "Detection": "\ud83d\udd0d",
    "Response": "\ud83d\udee1\ufe0f",
    "AttackAgent": "\ud83d\udd25",
    "Reporting": "\ud83d\udcca",
}


class BaseAgent:
    def __init__(self, name: str, gemini: GeminiClient, description: str = ""):
        self.name = name
        self.gemini = gemini
        self.description = description
        self.log: list[dict] = []
        self.iteration = 0
        self.emit_callback = None
        self.color = AGENT_COLORS.get(name, "#888888")
        self.icon = AGENT_ICONS.get(name, "\u2753")

    def set_emit_callback(self, callback):
        self.emit_callback = callback

    def _emit(self, action_type: str, data: dict):
        if self.emit_callback:
            try:
                self.emit_callback({
                    "type": "agent_action",
                    "agent": self.name,
                    "color": self.color,
                    "icon": self.icon,
                    "action_type": action_type,
                    "iteration": self.iteration,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    **data,
                })
            except Exception as e:
                logger.warning(f"Emit callback error: {e}")

    def think(self, input_data: dict) -> dict:
        self.iteration += 1
        message = json.dumps(input_data, indent=2, default=str)

        self._emit("thinking", {
            "thought": f"Analyzing input: {list(input_data.keys()) if isinstance(input_data, dict) else 'data'}",
            "input_summary": str(input_data)[:500],
        })

        try:
            raw = self.gemini.chat(message, json_mode=True)
            result = json.loads(raw) if isinstance(raw, str) else raw
        except json.JSONDecodeError:
            result = {"raw_response": raw, "parse_error": True}
        except Exception as e:
            result = {"error": str(e)}

        self._emit("analysis_complete", {
            "thought": result.get("thought", result.get("explanation", str(result)[:300])),
            "result": result,
            "decision": result.get("decision") or result.get("recommended_action") or result.get("action"),
            "confidence": result.get("confidence", 0),
            "risk_score": result.get("risk_score", 0),
        })

        self._log(input_data, result)
        return result

    def think_structured(self, input_data: dict, schema: dict) -> dict:
        self.iteration += 1
        message = json.dumps(input_data, indent=2, default=str)

        self._emit("thinking", {
            "thought": f"Structured analysis: {list(input_data.keys()) if isinstance(input_data, dict) else 'data'}",
            "input_summary": str(input_data)[:500],
        })

        result = self.gemini.chat_structured(message, schema)

        self._emit("analysis_complete", {
            "thought": result.get("thought", result.get("explanation", str(result)[:300])),
            "result": result,
        })

        self._log(input_data, result)
        return result

    def emit_command(self, command: str, exit_code: int = None, output: str = ""):
        self._emit("executing_command", {
            "command": command,
            "exit_code": exit_code,
            "command_output": output[:2000],
        })

    def emit_decision(self, decision: str, reasoning: str, details: dict = None):
        self._emit("decision_made", {
            "decision": decision,
            "reasoning": reasoning,
            "details": details or {},
        })

    def emit_error(self, error: str):
        self._emit("error", {
            "error": error,
        })

    def _log(self, input_data: dict, output: dict):
        entry = {
            "agent": self.name,
            "iteration": self.iteration,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "input": input_data,
            "output": output,
        }
        self.log.append(entry)
        logger.debug(f"[{self.name}] Iteration {self.iteration} complete")

    def get_recent_logs(self, n: int = 5) -> list:
        return self.log[-n:]

    def get_stats(self) -> dict:
        return {
            "name": self.name,
            "iterations": self.iteration,
            "description": self.description,
        }
