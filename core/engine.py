import asyncio
import json
import logging
import signal
from datetime import datetime, timezone

from config.settings import settings
from core.gemini_client import GeminiClient
from core.elastic_client import ElasticClient
from core.docker_controller import DockerController
from core.falco_manager import FalcoManager
from agents.orchestrator_agent import OrchestratorAgent
from agents.detection_agent import DetectionAgent
from agents.response_agent import ResponseAgent
from agents.attack_agent import AttackAgent
from agents.reporting_agent import ReportingAgent
from dashboard.app import SOCDashboard

logger = logging.getLogger(__name__)


class AISOC:
    def __init__(self):
        self.gemini = GeminiClient(settings.GEMINI_API_KEY, settings.GEMINI_MODEL)
        self.elastic = ElasticClient()
        self.docker = DockerController()
        self.falco = FalcoManager(self.docker)
        self.dashboard = SOCDashboard(self)

        self.orchestrator = OrchestratorAgent(self.gemini)
        self.detection = DetectionAgent(self.gemini)
        self.response_agent = ResponseAgent(self.gemini)
        self.attack = AttackAgent(self.gemini)
        self.reporting = ReportingAgent(self.gemini)

        q = self.agent_event_queue
        for agent in [self.orchestrator, self.detection, self.response_agent, self.attack, self.reporting]:
            agent.set_emit_callback(lambda ev: q.put_nowait(ev))

        self.agent_event_queue: asyncio.Queue = asyncio.Queue()
        self.events: list = []
        self.detections: list = []
        self.responses: list = []
        self.attack_log: list = []
        self.honeypot_containers: list = []
        self._running = False

    async def start(self):
        self._running = True
        logger.info("=" * 60)
        logger.info("  Argus AI-SOC - Multi-Agent Security Platform")
        logger.info(f"  Gemini Model: {settings.GEMINI_MODEL}")
        logger.info(f"  Elasticsearch: {'Connected' if self.elastic.available else 'Not available'}")
        logger.info(f"  Auto-block: {settings.AUTO_BLOCK_ENABLED}")
        logger.info("=" * 60)

        logger.info("[1/5] Deploying Falco...")
        falco_ok = self.falco.deploy()
        if not falco_ok:
            logger.warning("Falco deployment failed, running in standalone mode")

        logger.info("[2/5] Deploying honeypot containers...")
        await self._deploy_honeypots()

        logger.info("[3/5] Starting dashboard...")
        await self.dashboard.start()

        logger.info("[3.5/5] Starting agent event stream...")
        asyncio.create_task(self._agent_event_loop())

        logger.info("[4/5] Starting AI orchestration loop...")
        await self._orchestration_loop()

    async def _agent_event_loop(self):
        while self._running:
            try:
                event = await asyncio.wait_for(self.agent_event_queue.get(), timeout=1.0)
                await self.dashboard.broadcast(event)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Agent event stream error: {e}")

    async def _deploy_honeypots(self):
        targets = [
            ("nginx:alpine", "honeypot-web", {"80/tcp": 8081}),
            ("redis:7-alpine", "honeypot-redis", {"6379/tcp": 6379}),
            ("python:3.12-alpine", "honeypot-python", None),
        ]
        for image, name, ports in targets:
            c = self.docker.run_container(
                image=image,
                name=name,
                ports=ports,
                labels={"argus": "honeypot", "managed-by": "ai-soc"},
            )
            if c:
                self.honeypot_containers.append({"id": c.id, "name": name, "image": image})
                logger.info(f"  Deployed: {name}")
            else:
                logger.warning(f"  Failed to deploy: {name}")

    async def _orchestration_loop(self):
        cycle_count = 0
        last_report_time = datetime.now(timezone.utc)

        while self._running:
            cycle_count += 1
            logger.info(f"\n--- Cycle {cycle_count} ---")

            try:
                falco_status = self.falco.get_status() if self.falco else {"status": "not_available"}
                recent_events = self.falco.get_recent_logs(tail=20) if self.falco else []

                for raw_event in recent_events:
                    event = self._normalize_event(raw_event)

                    if not any(e.get("time") == event.get("time") and e.get("rule") == event.get("rule") for e in self.events[-50:]):
                        self.events.append(event)
                        self.elastic.index_event("falco-event", event)

                        detection = await self.detection.analyze_event(event)
                        self.detections.append(detection)
                        self.elastic.index_event("detection", {"event": event, "detection": detection})

                        if detection.get("is_threat", False):
                            response = await self.response_agent.decide_action(event, detection)
                            self.responses.append({**response, "container": event.get("container_name", "")})

                            if response.get("action") in ("KILL", "BLOCK", "ISOLATE"):
                                await self._execute_response(event, response)

                            self.elastic.index_event("response", {
                                "event": event,
                                "detection": detection,
                                "response": response,
                            })

                            await self.dashboard.broadcast_event(event, detection, response)

                if cycle_count % 3 == 0:
                    orchestrator_decision = await self.orchestrator.evaluate_state(
                        falco_status, self.events, self.detections, self.responses
                    )
                    logger.info(f"Orchestrator: {orchestrator_decision.get('decision', 'unknown')}")
                    self.elastic.index_event("orchestrator-decision", orchestrator_decision)

                    if orchestrator_decision.get("decision") == "RUN_ATTACK_SIM":
                        await self._run_attack_simulation()

                if cycle_count % 10 == 0:
                    await self._generate_report()

                await self.dashboard.broadcast_stats()
                await asyncio.sleep(5)

            except Exception as e:
                logger.error(f"Orchestration error: {e}", exc_info=True)
                await asyncio.sleep(5)

    def _normalize_event(self, raw: dict) -> dict:
        if isinstance(raw, dict):
            return {
                "time": datetime.now(timezone.utc).isoformat(),
                "rule": raw.get("rule", "unknown"),
                "priority": raw.get("priority", "NOTICE"),
                "output": raw.get("output", json.dumps(raw)),
                "container_name": raw.get("container.name") or raw.get("container_name", ""),
                "container_id": raw.get("container.id") or raw.get("container_id", ""),
                "container_image": raw.get("container.image") or raw.get("container_image", ""),
                "process_name": raw.get("proc.name") or raw.get("process_name", ""),
                "evt_type": raw.get("evt.type") or raw.get("evt_type", ""),
                "fd_name": raw.get("fd.name") or raw.get("fd_name", ""),
                "user_name": raw.get("user.name") or raw.get("user_name", ""),
            }
        return {"time": datetime.now(timezone.utc).isoformat(), "raw": str(raw)}

    async def _execute_response(self, event: dict, response: dict):
        action = response.get("action")
        container_id = event.get("container_id", "")
        container_name = event.get("container_name", "")

        if not container_id:
            logger.warning(f"No container ID to act on for {container_name}")
            return

        self.response_agent.emit_decision(action, response.get("reasoning", ""), {
            "container": container_name,
            "rule": event.get("rule", ""),
            "confidence": response.get("action_confidence", 0),
        })

        if action == "KILL":
            cmd = f"docker kill {container_name}"
            self.response_agent.emit_command(cmd)
            exit_code = self.docker.kill_container(container_id)
            self.response_agent.emit_command(cmd, exit_code=0 if exit_code else 1, output="Container killed")
            logger.critical(f"[KILL] {container_name}: {response.get('reasoning', '')}")
        elif action == "BLOCK":
            cmd = f"docker kill {container_name}"
            self.response_agent.emit_command(cmd)
            exit_code = self.docker.kill_container(container_id)
            self.response_agent.emit_command(cmd, exit_code=0 if exit_code else 1, output="Process blocked")
            logger.critical(f"[BLOCK] {container_name}: {response.get('reasoning', '')}")
        elif action == "ISOLATE":
            cmd_net = f"docker network disconnect {container_name}"
            self.response_agent.emit_command(cmd_net)
            self.docker.disconnect_network(container_id)
            self.response_agent.emit_command(cmd_net, exit_code=0, output="Network disconnected")
            cmd_stop = f"docker stop {container_name}"
            self.response_agent.emit_command(cmd_stop)
            self.docker.stop_container(container_id)
            self.response_agent.emit_command(cmd_stop, exit_code=0, output="Container stopped")
            logger.warning(f"[ISOLATE] {container_name}: {response.get('reasoning', '')}")
        elif action == "ALERT":
            logger.warning(f"[ALERT] {container_name}: {response.get('reasoning', '')}")

    async def _run_attack_simulation(self):
        target_names = [c["name"] for c in self.honeypot_containers if c.get("name")]
        if not target_names:
            logger.warning("No honeypot containers to attack")
            return

        attack_plan = await self.attack.plan_attack(target_names, self.attack_log)
        logger.info(f"Attack Agent: Planning {attack_plan.get('attack_name', 'unknown')}")

        self.attack.emit_decision(
            "EXECUTE_ATTACK",
            f"Running {attack_plan.get('attack_name', 'unknown')} on {attack_plan.get('target_container', 'unknown')}",
            attack_plan,
        )

        for cmd in attack_plan.get("commands", []):
            self.attack.emit_command(cmd)
            exit_code, output = self.docker.exec_command(attack_plan["target_container"], cmd)
            self.attack.emit_command(cmd, exit_code=exit_code, output=output[:2000])

        result = await self.attack.execute_attack(self.docker, attack_plan)
        self.attack_log.append(result)
        self.elastic.index_event("attack-simulation", result)
        logger.info(f"Attack executed: {attack_plan.get('attack_name', 'unknown')} on {attack_plan.get('target_container', 'unknown')}")

    async def _generate_report(self):
        report = await self.reporting.generate_incident_report(
            self.events, self.detections, self.responses, self.attack_log
        )
        self.elastic.index_event("report", report)
        logger.info(f"Report generated: {report.get('title', 'Incident Report')}")
        await self.dashboard.broadcast_report(report)

    def stop(self):
        logger.info("Shutting down AI-SOC...")
        self._running = False
        self.falco.shutdown()
        for c in self.honeypot_containers:
            self.docker.kill_container(c["id"])
        logger.info("AI-SOC stopped")


async def main():
    soc = AISOC()

    def shutdown():
        soc.stop()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, shutdown)
        except NotImplementedError:
            pass

    try:
        await soc.start()
    except KeyboardInterrupt:
        pass
    finally:
        soc.stop()


def run():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    run()
