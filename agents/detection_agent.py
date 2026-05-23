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
4. Detect advanced attack patterns including kernel escapes, memory injection, and evasion

For each event, evaluate:
- What MITRE technique does this map to?
- What is the kill chain stage?
- Is this a known attack pattern or anomalous behavior?
- What is the confidence level (0-1)?
- What is the risk score (0-100)?
- Could this be part of an advanced attack chain (e.g. recon -> exploit -> persist -> exfil)?

Advanced attack signatures to recognize:
- Cgroup notify_on_release writes: Container escape via cgroup (T1611)
- /proc/self/fd/ traversal: runc FD leak escape (T1611)
- nsenter on host processes: Namespace escape (T1611)
- memfd_create() execution: Fileless malware (T1055)
- ptrace POKE: Process injection (T1055)
- LD_PRELOAD exports: Runtime hooking (T1055.001)
- CAP_SYS_ADMIN usage: Privilege escalation (T1548)
- ARP table manipulation: Network MITM (T1557.002)
- chattr +i on binaries: Defense evasion (T1562.001)
- /sys/kernel/notes reads: KASLR leak (T1592.004)
- ICMP raw socket creation: Covert channel (T1048.003)
- DNS TXT queries to unusual domains: C2 tunnel (T1572)

You must always respond in JSON format with:
{
  "thought": "Your analysis reasoning",
  "is_threat": true/false,
  "attack_type": "mitre_technique_id or description",
  "attack_category": "KERNEL_ESCAPE|MEMORY_INJECTION|CAPABILITY_ABUSE|FILESYSTEM_ATTACK|EVASION|NETWORK_ATTACK|SUPPLY_CHAIN|GENERIC",
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

        self.emit_decision("ANALYZING", f"Examining event: {event.get('rule', 'unknown')} [{event.get('priority', '')}]", {
            "container": event.get("container_name", ""),
            "process": event.get("process_name", ""),
            "syscall": event.get("evt_type", ""),
        })

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

        if result.get("is_threat", False):
            self.emit_decision(
                result.get("recommended_action", "ALERT"),
                f"{result.get('attack_type', 'unknown')} (MITRE: {result.get('mitre_id', 'N/A')}) - {result.get('explanation', '')[:200]}",
                {"risk_score": risk_score, "confidence": result.get("confidence", 0)},
            )

        return result

    def _local_fallback(self, event: dict) -> dict:
        output = event.get("output", "").lower()
        proc = event.get("process_name", "").lower()
        fd = event.get("fd_name", "").lower()
        evt = event.get("evt_type", "").lower()

        patterns = [
            (r"(/etc/shadow|/etc/passwd|credential|secret|\.env)", "credential_access", "T1003.001", "CREDENTIAL_ACCESS", 95, "CRITICAL"),
            (r"(bash -i|sh -i|nc .* -e|/dev/tcp|/dev/udp)", "reverse_shell", "T1059.004", "EXECUTION", 98, "CRITICAL"),
            (r"(mount|unshare|pivot_root|nsenter)", "container_escape", "T1611", "KERNEL_ESCAPE", 99, "CRITICAL"),
            (r"(xmrig|minerd|cryptonight)", "crypto_mining", "T1496", "IMPACT", 90, "HIGH"),
            (r"(ptrace|process_vm_writev|memfd)", "process_injection", "T1055", "MEMORY_INJECTION", 97, "CRITICAL"),
            (r"(chmod 777|chown root|setuid|setgid)", "privilege_escalation", "T1548", "PRIVILEGE_ESCALATION", 85, "HIGH"),
            (r"(nmap|masscan|zmap)", "network_scanning", "T1046", "DISCOVERY", 70, "MEDIUM"),
            (r"(kubectl exec|kubectl run)", "container_breakout", "T1611", "KERNEL_ESCAPE", 85, "HIGH"),
            (r"(ld_preload|dlopen|dlsym)", "runtime_hooking", "T1055.001", "MEMORY_INJECTION", 92, "CRITICAL"),
            (r"(chattr.*\+i|immutable)", "defense_evasion", "T1562.001", "EVASION", 75, "HIGH"),
            (r"(cgroup.*release_agent|notify_on_release)", "cgroup_escape", "T1611", "KERNEL_ESCAPE", 99, "CRITICAL"),
            (r"(arpspoof|arp.*poison|raw.*socket)", "network_mitm", "T1557.002", "NETWORK_ATTACK", 85, "HIGH"),
            (r"(memfd_create|fileless)", "fileless_malware", "T1055", "MEMORY_INJECTION", 95, "CRITICAL"),
            (r"(seccomp|x32|32.*bit.*syscall)", "seccomp_bypass", "T1574.002", "EVASION", 88, "HIGH"),
            (r"(dns.*txt|dns.*tunnel)", "dns_tunneling", "T1572", "NETWORK_ATTACK", 82, "HIGH"),
            (r"(icmp.*exfil|ping.*data|covert.*channel)", "covert_channel", "T1048.003", "NETWORK_ATTACK", 85, "HIGH"),
            (r"(kptr_restrict|kallsyms|kaslr)", "information_disclosure", "T1592.004", "RECONNAISSANCE", 60, "MEDIUM"),
            (r"(docker.*socket|docker.*exec)", "docker_abuse", "T1611", "CAPABILITY_ABUSE", 90, "CRITICAL"),
        ]

        search_text = f"{output} {proc} {fd} {evt}"
        for pattern, attack, mitre, category, risk, sev in patterns:
            if re.search(pattern, search_text):
                return {
                    "is_threat": True,
                    "attack_type": attack,
                    "attack_category": category,
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
            "attack_category": "GENERIC",
            "risk_score": 10,
            "severity": "LOW",
            "confidence": 0.1,
            "explanation": "No threat patterns detected",
            "recommended_action": "IGNORE",
        }
