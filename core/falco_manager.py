import json
import logging
import time
import urllib.request
from datetime import datetime, timezone
from typing import Optional

from core.docker_controller import DockerController

logger = logging.getLogger(__name__)


class FalcoManager:
    FALCO_IMAGE = "falcosecurity/falco:latest"
    FALCO_CONTAINER_NAME = "falco-soc-agent"

    def __init__(self, docker: DockerController):
        self.docker = docker
        self.container_id = None

    def deploy(self) -> bool:
        existing = self.docker.get_container(self.FALCO_CONTAINER_NAME)
        if existing:
            logger.info("Falco container already running")
            self.container_id = existing.id
            return True

        container = self.docker.run_container(
            image=self.FALCO_IMAGE,
            name=self.FALCO_CONTAINER_NAME,
            privileged=True,
            detach=True,
            ports={"5060/tcp": 5060},
        )
        if container:
            self.container_id = container.id
            time.sleep(5)
            return True
        return False

    def is_running(self) -> bool:
        if not self.container_id:
            return False
        c = self.docker.get_container(self.container_id)
        return c is not None and c.status == "running"

    def get_status(self) -> dict:
        if not self.container_id:
            return {"status": "not_deployed"}
        c = self.docker.get_container(self.container_id)
        if not c:
            return {"status": "not_found"}
        return {
            "status": c.status,
            "id": c.short_id,
            "name": c.name,
            "image": c.image.tags[0] if c.image.tags else "unknown",
            "created": c.attrs.get("Created", ""),
        }

    def check_grpc_ready(self, host: str = "localhost", port: int = 5060, timeout: int = 30) -> bool:
        start = time.time()
        while time.time() - start < timeout:
            try:
                req = urllib.request.Request(f"http://{host}:{port}/health")
                urllib.request.urlopen(req, timeout=2)
                return True
            except Exception:
                time.sleep(2)
        return False

    def get_recent_logs(self, tail: int = 50) -> list:
        if not self.container_id:
            return []
        logs = self.docker.get_container_logs(self.container_id, tail=tail)
        entries = []
        for line in logs.strip().split("\n"):
            if line.strip():
                try:
                    parsed = json.loads(line)
                    entries.append(parsed)
                except json.JSONDecodeError:
                    entries.append({"raw": line})
        return entries

    def shutdown(self):
        if self.container_id:
            self.docker.stop_container(self.container_id)
            logger.info("Falco container stopped")
