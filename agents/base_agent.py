import json
import logging
from datetime import datetime, timezone

from core.gemini_client import GeminiClient

logger = logging.getLogger(__name__)


class BaseAgent:
    def __init__(self, name: str, gemini: GeminiClient, description: str = ""):
        self.name = name
        self.gemini = gemini
        self.description = description
        self.log: list[dict] = []
        self.iteration = 0

    def set_system_prompt(self, prompt: str):
        self.gemini.set_system_prompt(prompt)

    def think(self, input_data: dict) -> dict:
        self.iteration += 1
        message = json.dumps(input_data, indent=2, default=str)

        try:
            raw = self.gemini.chat(message, json_mode=True)
            result = json.loads(raw) if isinstance(raw, str) else raw
        except json.JSONDecodeError:
            result = {"raw_response": raw, "parse_error": True}
        except Exception as e:
            result = {"error": str(e)}

        self._log(input_data, result)
        return result

    def think_structured(self, input_data: dict, schema: dict) -> dict:
        self.iteration += 1
        message = json.dumps(input_data, indent=2, default=str)
        result = self.gemini.chat_structured(message, schema)
        self._log(input_data, result)
        return result

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
