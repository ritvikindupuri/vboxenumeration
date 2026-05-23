import json
import logging
from typing import Optional

import google.generativeai as genai

logger = logging.getLogger(__name__)


class GeminiClient:
    def __init__(self, api_key: str, model: str = "gemini-2.0-flash"):
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(model)
        self.system_prompt = ""

    def set_system_prompt(self, prompt: str):
        self.system_prompt = prompt

    def chat(self, message: str, json_mode: bool = True, temperature: float = 0.2) -> str:
        full_prompt = self.system_prompt + "\n\n" + message if self.system_prompt else message

        generation_config = {
            "temperature": temperature,
            "top_p": 0.95,
            "top_k": 40,
        }

        if json_mode:
            generation_config["response_mime_type"] = "application/json"

        try:
            response = self.model.generate_content(
                full_prompt,
                generation_config=generation_config,
            )
            text = response.text.strip()
            if text.startswith("```"):
                text = text.strip("`").replace("json\n", "").replace("json", "").strip()
            return text
        except Exception as e:
            logger.error(f"Gemini API error: {e}")
            return json.dumps({"error": str(e), "fallback": True})

    def chat_structured(self, message: str, schema: dict, temperature: float = 0.2) -> dict:
        full_prompt = self.system_prompt + "\n\n" + message if self.system_prompt else message

        try:
            response = self.model.generate_content(
                full_prompt,
                generation_config={
                    "temperature": temperature,
                    "response_mime_type": "application/json",
                    "response_schema": schema,
                },
            )
            text = response.text.strip()
            if text.startswith("```"):
                text = text.strip("`").replace("json\n", "").replace("json", "").strip()
            return json.loads(text)
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}, raw: {text}")
            return {"error": str(e), "fallback": True}
        except Exception as e:
            logger.error(f"Gemini API error: {e}")
            return {"error": str(e), "fallback": True}
