import logging
import time
from typing import Optional

import docker

logger = logging.getLogger(__name__)


class DockerController:
    def __init__(self):
        self.client = docker.from_env()

    def list_containers(self, all=False):
        return self.client.containers.list(all=all)

    def get_container(self, container_id: str):
        try:
            return self.client.containers.get(container_id)
        except docker.errors.NotFound:
            return None

    def run_container(self, image: str, name: str, command: str = None,
                      ports: dict = None, privileged: bool = False,
                      environment: dict = None, labels: dict = None,
                      detach: bool = True) -> Optional[docker.models.containers.Container]:
        try:
            container = self.client.containers.run(
                image=image,
                name=name,
                command=command,
                ports=ports,
                privileged=privileged,
                environment=environment,
                labels=labels,
                detach=detach,
                remove=False,
            )
            logger.info(f"Started container: {name} ({container.short_id})")
            return container
        except docker.errors.ImageNotFound:
            logger.info(f"Pulling image: {image}")
            self.client.images.pull(image)
            return self.run_container(image, name, command, ports, privileged, environment, labels, detach)
        except Exception as e:
            logger.error(f"Failed to start container {name}: {e}")
            return None

    def kill_container(self, container_id: str, force: bool = True) -> bool:
        try:
            c = self.client.containers.get(container_id)
            c.kill()
            if force:
                c.remove(force=True)
            logger.info(f"Killed container: {container_id[:12]}")
            return True
        except docker.errors.NotFound:
            logger.warning(f"Container {container_id[:12]} not found")
            return False
        except Exception as e:
            logger.error(f"Failed to kill container: {e}")
            return False

    def stop_container(self, container_id: str) -> bool:
        try:
            c = self.client.containers.get(container_id)
            c.stop()
            logger.info(f"Stopped container: {container_id[:12]}")
            return True
        except Exception as e:
            logger.error(f"Failed to stop container: {e}")
            return False

    def disconnect_network(self, container_id: str) -> bool:
        try:
            c = self.client.containers.get(container_id)
            networks = list(c.attrs["NetworkSettings"]["Networks"].keys())
            for net in networks:
                if net != "none":
                    try:
                        docker_net = self.client.networks.get(net)
                        docker_net.disconnect(c, force=True)
                    except Exception:
                        pass
            logger.info(f"Isolated container network: {container_id[:12]}")
            return True
        except Exception as e:
            logger.error(f"Failed to isolate network: {e}")
            return False

    def exec_command(self, container_id: str, command: str) -> tuple:
        try:
            c = self.client.containers.get(container_id)
            exit_code, output = c.exec_run(command)
            return exit_code, output.decode("utf-8", errors="replace") if isinstance(output, bytes) else str(output)
        except Exception as e:
            return -1, str(e)

    def get_container_logs(self, container_id: str, tail: int = 100) -> str:
        try:
            c = self.client.containers.get(container_id)
            return c.logs(tail=tail).decode("utf-8", errors="replace")
        except Exception:
            return ""

    def wait_for_container(self, container_id: str, timeout: int = 30) -> bool:
        start = time.time()
        while time.time() - start < timeout:
            c = self.get_container(container_id)
            if c and c.status == "running":
                return True
            time.sleep(1)
        return False
