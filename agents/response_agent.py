import json
import logging

from agents.base_agent import BaseAgent

logger = logging.getLogger(__name__)

RESPONSE_SYSTEM_PROMPT = """You are the Response Agent for an AI-powered Container Security Platform.

Your responsibilities:
1. Decide the appropriate action for detected threats
2. Consider the context: container criticality, attack severity, blast radius
3. Determine if isolation, killing, blocking, or alerting is appropriate
4. Consider defense evasion techniques that might be in use (eBPF rootkits, LD_PRELOAD, seccomp bypass)
5. Consider the attack type and whether it's a kernel exploit, memory injection, or network attack
6. Provide detailed rationale for each decision

Available actions:
- KILL: Immediately terminate and remove the container (for critical threats)
- BLOCK: Kill the offending process within the container
- ISOLATE: Disconnect the container from all networks and stop it
- ALERT: Log and notify without taking action (for low-severity)
- IGNORE: No action needed (false positive)

Attack type response guidelines:
- KERNEL_ESCAPE (cgroup, nsenter, runc FD leak, overlayfs): KILL immediately
- MEMORY_INJECTION (ptrace, /proc/self/mem, LD_PRELOAD, eBPF): KILL or BLOCK
- CAPABILITY_ABUSE (SYS_ADMIN, NET_RAW, SYS_PTRACE): KILL
- FILESYSTEM_ATTACK (symlink, TOCTOU, side-channel): ISOLATE + KILL
- EVASION (seccomp bypass, timer delay, immutable files): BLOCK
- NETWORK_ATTACK (ARP spoof, ICMP, DNS tunnel): ISOLATE
- SUPPLY_CHAIN (image mining, cgroup exhaustion): ISOLATE

You must always respond in JSON format with:
{
  "thought": "Your decision-making reasoning",
  "action": "KILL|BLOCK|ISOLATE|ALERT|IGNORE",
  "action_confidence": 0.0-1.0,
  "reasoning": "Detailed explanation of why this action was chosen",
  "containment_strategy": "immediate|gradual|monitor_only",
  "should_notify": true/false,
  "notes": "Any additional considerations",
  "alternatives": ["alternative action 1", "alternative action 2"]
}
"""


class ResponseAgent(BaseAgent):
    def __init__(self, gemini):
        super().__init__("Response", gemini, "Decides and executes security responses")
        self.set_system_prompt(RESPONSE_SYSTEM_PROMPT)

    async def decide_action(self, event: dict, detection_result: dict) -> dict:
        input_data = {
            "type": "response_decision",
            "event": {
                "rule": event.get("rule", "unknown"),
                "priority": event.get("priority", "NOTICE"),
                "container_name": event.get("container_name", ""),
                "container_image": event.get("container_image", ""),
                "process_name": event.get("process_name", ""),
            },
            "detection_analysis": detection_result,
        }

        self.emit_decision("EVALUATING", f"Deciding action for {event.get('rule', 'unknown')} (risk: {detection_result.get('risk_score', 0)})", {
            "detected_attack": detection_result.get("attack_type", ""),
            "mitre_id": detection_result.get("mitre_id", ""),
            "confidence": detection_result.get("confidence", 0),
        })

        decision = self.think(input_data)
        action = decision.get("action", "ALERT")

        category = detection_result.get("attack_category", "GENERIC")
        risk = detection_result.get("risk_score", 0)
        attack_type = detection_result.get("attack_type", "")

        category_map = {
            "KERNEL_ESCAPE": ("KILL", 0.98),
            "MEMORY_INJECTION": ("KILL" if risk >= 90 else "BLOCK", 0.95),
            "CAPABILITY_ABUSE": ("KILL", 0.92),
            "FILESYSTEM_ATTACK": ("ISOLATE", 0.85),
            "EVASION": ("BLOCK", 0.80),
            "NETWORK_ATTACK": ("ISOLATE", 0.82),
            "SUPPLY_CHAIN": ("ISOLATE", 0.75),
        }

        if category in category_map:
            preferred, conf = category_map[category]
        elif detection_result.get("risk_score", 0) >= 95:
            preferred = "KILL"
            conf = detection_result.get("confidence", 0.9)
        elif detection_result.get("risk_score", 0) >= 80:
            preferred = "BLOCK" if attack_type != "container_escape" and attack_type != "cgroup_escape" else "KILL"
            conf = detection_result.get("confidence", 0.8)
        elif detection_result.get("risk_score", 0) >= 60:
            preferred = "ISOLATE"
            conf = detection_result.get("confidence", 0.6)
        else:
            preferred = "ALERT"
            conf = 0.3

        if decision.get("action_confidence", 0) < confidence:
            decision["action"] = preferred
            decision["action_confidence"] = confidence
            decision["reasoning"] = f"Overridden by risk-based policy (risk={detection_result.get('risk_score', 0)})"

        self.emit_decision(decision.get("action"), decision.get("reasoning", ""), {
            "confidence": decision.get("action_confidence", 0),
            "containment": decision.get("containment_strategy", "immediate"),
        })

        return decision

    def get_response_summary(self, actions: list) -> dict:
        killed = sum(1 for a in actions if a.get("action") == "KILL")
        blocked = sum(1 for a in actions if a.get("action") == "BLOCK")
        isolated = sum(1 for a in actions if a.get("action") == "ISOLATE")
        alerted = sum(1 for a in actions if a.get("action") == "ALERT")

        return {
            "total_responses": len(actions),
            "killed": killed,
            "blocked": blocked,
            "isolated": isolated,
            "alerted": alerted,
        }
