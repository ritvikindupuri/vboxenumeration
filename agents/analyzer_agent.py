import json
import logging

from agents.base_agent import BaseAgent
from core.claude_client import ClaudeClient

logger = logging.getLogger(__name__)

ANALYSIS_PROMPT = """You are an adversarial security auditor analyzing a VirtualBox attack surface.
Think like a red teamer: every misconfiguration is a potential foothold, every enabled feature is a possible
covert channel, every network setting is a lateral movement path.

Analyze the provided VirtualBox enumeration data from an attacker's perspective.

For each finding, provide:
- title: short, actionable name
- description: what an attacker could actually DO with this (not just what it is)
- severity: CRITICAL / HIGH / MEDIUM / LOW / INFO
- cvss_score: numeric CVSS v3.1 score (0.0-10.0)
- affected_component: specific VM, network, or setting
- remediation: step-by-step hardening instructions
- attack_scenario: 1-2 sentence realistic attack scenario
- references: relevant security references

Return JSON:
{
  "findings": [
    {
      "id": "VBOX-001",
      "title": "VRDE Remote Desktop Exposed on Windows VM",
      "description": "VirtualBox Remote Desktop Extension is enabled...",
      "severity": "HIGH",
      "cvss_score": 8.1,
      "affected_component": "Windows VM",
      "remediation": "1. Disable VRDE...",
      "attack_scenario": "An attacker on the same network...",
      "references": ["https://..."]
    }
  ],
  "summary": {
    "total_findings": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0,
    "overall_risk": "...",
    "primary_attack_vectors": ["..."],
    "highest_risk_component": "..."
  },
  "executive_summary": "3-4 paragraph executive summary from an attacker's perspective"
}
"""


class AnalyzerAgent(BaseAgent):
    def __init__(self, claude: ClaudeClient):
        super().__init__("analyzer")
        self.claude = claude

    def run(self, context: dict) -> dict:
        enum_data = context.get("enumeration", {})

        self.emit_thinking("Preparing enumeration data for adversarial analysis — structuring VM configurations, network topology, and host properties into a format suitable for AI-powered red-team assessment; extracting attacker-relevant fields: VRDE status, clipboard mode, drag-and-drop, USB, encryption, TPM, firmware, guest additions, shared folders, and network interfaces")

        vms = enum_data.get("vm_details", [])
        vm_summaries = []
        for vm in vms:
            p = vm.get("parsed", {})
            vm_summaries.append({
                "name": vm["name"],
                "state": p.get("VMState", "?"),
                "os": p.get("OSType", "?"),
                "ram": p.get("memory", "?"),
                "vram": p.get("vram", "?"),
                "cpus": p.get("cpus", "?"),
                "vrde": p.get("vrde", "?"),
                "clipboard": p.get("clipboard", "?"),
                "draganddrop": p.get("draganddrop", "?"),
                "audio": p.get("audio", "?"),
                "usb": p.get("usb", "?"),
                "accelerate3d": p.get("accelerate3d", "?"),
                "encryption": p.get("encryption", "?"),
                "tpm": p.get("tpm", "?"),
                "firmware": p.get("firmware", "?"),
                "guest_additions": p.get("GuestAdditionsVersion", p.get("guest_additions", "?")),
                "snapshot_count": len(vm.get("snapshots", "")) // 50 if vm.get("snapshots") else 0,
                "shared_folder_count": len(vm.get("shared_folders", "")) // 50 if vm.get("shared_folders") else 0,
                "network_adapters": [k for k in p if k.startswith("nic") and p[k] not in ("none", "")],
            })
            self.emit_thinking(f"Analyzing VM: {vm['name']} — examining {vm_summaries[-1]['os']} ({vm_summaries[-1]['state']}) configuration for attacker-relevant weaknesses: VRDE {'ENABLED' if vm_summaries[-1].get('vrde','') == 'on' else 'disabled'}, clipboard: {vm_summaries[-1].get('clipboard','?')}, USB: {'ENABLED' if vm_summaries[-1].get('usb','') == 'on' else 'disabled'}, encryption: {vm_summaries[-1].get('encryption','?')}, TPM: {vm_summaries[-1].get('tpm','?')}")

        analysis_input = json.dumps({
            "vms": vm_summaries,
            "running": enum_data.get("running_vms", []),
            "network": {
                "host_only": enum_data.get("network", {}).get("hostonly", "")[:500],
                "bridged": enum_data.get("network", {}).get("bridged", "")[:500],
                "natnets": enum_data.get("network", {}).get("natnets", "")[:500],
                "dhcp": enum_data.get("network", {}).get("dhcp", "")[:500],
            },
            "host": {
                "extpacks": enum_data.get("host", {}).get("extension_packs", "")[:300],
                "usb": enum_data.get("host", {}).get("usb_host", "")[:300],
            },
        }, indent=2)

        self.emit_thinking("Engaging Claude AI for adversarial security analysis — transmitting structured enumeration data to Claude with a red-team prompt designed to identify misconfigurations that create realistic attack paths; Claude will evaluate each VM's settings, network exposure, and host-level vulnerabilities from an attacker's perspective")
        self.emit_command(f"Sending {len(analysis_input)} chars to Claude API")

        self.claude.set_system_prompt(ANALYSIS_PROMPT)
        result = self.claude.chat_structured(analysis_input)

        if result.get("fallback"):
            self.emit_output(f"Claude analysis failed: {result.get('error')}")
            return {"findings": [], "summary": {}, "executive_summary": "Analysis failed."}

        findings = result.get("findings", [])
        summary = result.get("summary", {})
        exec_summary = result.get("executive_summary", "")

        self.emit_thinking(f"Claude analysis complete: identified {len(findings)} security findings across the VirtualBox attack surface — findings range from critical remote access exposures to informational observations; each finding includes severity rating, CVSS score, remediation steps, attack scenario, and references for manual verification")

        if summary:
            self.emit("summary_detail", summary)

        for f in (findings or []):
            self.emit("finding", f)

        self.emit_result({
            "status": "complete",
            "finding_count": len(findings),
            "summary": summary,
        })

        return {
            "findings": findings,
            "summary": summary,
            "executive_summary": exec_summary,
        }
