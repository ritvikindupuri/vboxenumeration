import json
import logging
import re

from agents.base_agent import BaseAgent

logger = logging.getLogger(__name__)

DETECTION_SYSTEM_PROMPT = """You are the Detection Agent for an AI-powered Container Security Platform.

Your job:
1. Analyze Falco security events and classify them according to MITRE ATT&CK
2. Assign confidence scores and risk levels
3. Determine if the event represents a real attack or false positive
4. Provide detailed contextual analysis

For each event, evaluate:
- What MITRE technique does this map to?
- What is the kill chain stage?
- Is this a known attack pattern or anomalous behavior?
- What is the confidence level (0-1)?
- What is the risk score (0-100)?

You must always respond in JSON format with:
{
  "thought": "Your analysis reasoning",
  "is_threat": true/false,
  "attack_type": "mitre_technique_id or description",
  "kill_chain_stage": "initial_access|execution|persistence|privilege_escalation|defense_evasion|credential_access|discovery|lateral_movement|collection|command_and_control|exfiltration|impact",
  "mitre_id": "TXXXX.XXX",
  "confidence": 0.0-1.0,
  "risk_score": 0-100,
  "severity": "LOW|MEDIUM|HIGH|CRITICAL",
  "false_positive_likelihood": 0.0-1.0,
  "explanation": "Detailed explanation of the analysis",
  "recommended_action": "KILL|BLOCK|ISOLATE|ALERT|IGNORE"
}
"""


class DetectionAgent(BaseAgent):
    def __init__(self, gemini):
        super().__init__("Detection", gemini, "Analyzes Falco events and classifies threats")
        self.set_system_prompt(DETECTION_SYSTEM_PROMPT)

    async def analyze_event(self, event: dict) -> dict:
        analysis_fields = {
            "rule": event.get("rule", "unknown"),
            "priority": event.get("priority", "NOTICE"),
            "output": event.get("output", ""),
            "container_name": event.get("container_name", ""),
            "container_image": event.get("container_image", ""),
            "process_name": event.get("process_name", ""),
            "evt_type": event.get("evt_type", ""),
            "fd_name": event.get("fd_name", ""),
            "user_name": event.get("user_name", ""),
        }

        result = self.think({
            "type": "falco_event_analysis",
            "event": analysis_fields,
        })

        risk_score = result.get("risk_score", 50)
        severity_map = {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 50, "LOW": 20}
        event_priority = event.get("priority", "MEDIUM")
        base_risk = severity_map.get(event_priority, 50)

        if result.get("is_threat", False):
            risk_score = max(risk_score, base_risk)
        else:
            risk_score = min(risk_score, base_risk)

        result["final_risk_score"] = risk_score
        result["original_priority"] = event_priority
        return result

    def _local_fallback(self, event: dict) -> dict:
        output = event.get("output", "").lower()
        proc = event.get("process_name", "").lower()
        fd = event.get("fd_name", "").lower()
        evt = event.get("evt_type", "").lower()

        patterns = [
            (r"(/etc/shadow|/etc/passwd|credential|secret|\.env)", "credential_access", "T1003.001", 95, "CRITICAL"),
            (r"(bash -i|sh -i|nc .* -e|/dev/tcp|/dev/udp)", "reverse_shell", "T1059.004", 98, "CRITICAL"),
            (r"(mount|unshare|pivot_root)", "container_escape", "T1611", 99, "CRITICAL"),
            (r"(xmrig|minerd|cryptonight)", "crypto_mining", "T1496", 90, "HIGH"),
            (r"(ptrace|process_vm_writev)", "process_injection", "T1055", 97, "CRITICAL"),
            (r"(chmod 777|chown root)", "privilege_escalation", "T1548", 85, "HIGH"),
            (r"(nmap|masscan|zmap)", "network_scanning", "T1046", 70, "MEDIUM"),
            (r"(kubectl exec|kubectl run)", "container_breakout", "T1611", 85, "HIGH"),
        ]

        search_text = f"{output} {proc} {fd} {evt}"
        for pattern, attack, mitre, risk, sev in patterns:
            if re.search(pattern, search_text):
                return {
                    "is_threat": True,
                    "attack_type": attack,
                    "mitre_id": mitre,
                    "risk_score": risk,
                    "severity": sev,
                    "confidence": risk / 100.0,
                    "explanation": f"Pattern match: {pattern}",
                    "recommended_action": "KILL" if risk >= 95 else "BLOCK" if risk >= 80 else "ISOLATE",
                }

        return {
            "is_threat": False,
            "attack_type": "benign",
            "risk_score": 10,
            "severity": "LOW",
            "confidence": 0.1,
            "explanation": "No threat patterns detected",
            "recommended_action": "IGNORE",
        }
