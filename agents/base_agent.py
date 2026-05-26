import logging
from typing import Callable


class BaseAgent:
    def __init__(self, name: str):
        self.name = name
        self.logger = logging.getLogger(f"agent.{name}")
        self._handlers: list[Callable] = []

    def on_event(self, handler: Callable):
        self._handlers.append(handler)

    def emit(self, event_type: str, data: dict):
        for handler in self._handlers:
            handler(self.name, event_type, data)

    def emit_thinking(self, message: str):
        self.emit("thinking", {"message": message})

    def emit_command(self, command: str):
        self.emit("command", {"command": command})

    def emit_output(self, output: str):
        self.emit("output", {"output": output})

    def emit_result(self, result: dict):
        self.emit("result", result)

    def run(self, context: dict) -> dict:
        raise NotImplementedError
