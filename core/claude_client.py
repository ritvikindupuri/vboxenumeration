import json
import logging

import anthropic

logger = logging.getLogger(__name__)


class ClaudeClient:
    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514"):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model
        self.system_prompt = ""

    def set_system_prompt(self, prompt: str):
        self.system_prompt = prompt

    def chat(self, message: str, json_mode: bool = True, temperature: float = 0.2, max_tokens: int = 4096) -> str:
        if json_mode:
            message += "\n\nYou must respond with valid JSON only. No other text, no markdown formatting."

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=temperature,
                system=[{"type": "text", "text": self.system_prompt}] if self.system_prompt else None,
                messages=[{"role": "user", "content": message}],
            )
            text = response.content[0].text.strip()
            if text.startswith("```"):
                text = text.strip("`").replace("json\n", "").replace("json", "").strip()
            return text
        except Exception as e:
            logger.error(f"Claude API error: {e}")
            return json.dumps({"error": str(e), "fallback": True})

    def chat_structured(self, message: str, schema: dict = None, temperature: float = 0.2, max_tokens: int = 4096) -> dict:
        message += "\n\nYou must respond with valid JSON only. No other text, no markdown formatting."

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=temperature,
                system=[{"type": "text", "text": self.system_prompt}] if self.system_prompt else None,
                messages=[{"role": "user", "content": message}],
            )
            text = response.content[0].text.strip()
            if text.startswith("```"):
                text = text.strip("`").replace("json\n", "").replace("json", "").strip()
            return json.loads(text)
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}, raw: {text}")
            return {"error": str(e), "fallback": True}
        except Exception as e:
            logger.error(f"Claude API error: {e}")
            return {"error": str(e), "fallback": True}
