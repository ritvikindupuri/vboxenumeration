import json
import logging

from agents.base_agent import BaseAgent
from core.claude_client import ClaudeClient

logger = logging.getLogger(__name__)

ANALYSIS_PROMPT = """You are an adversarial security auditor conducting a live penetration test against a VirtualBox hypervisor environment.
Think like a red team operator: every misconfiguration is a potential foothold, every enabled feature is a possible
covert channel, every network setting is a lateral movement path, every open port is an exploitation opportunity.

Analyze the provided VirtualBox enumeration data from an active attacker's perspective.
Active network reconnaissance data (live hosts, open ports, service banners) is also provided — incorporate these findings into your analysis.

For EACH finding, you MUST include:
- title: short, actionable name
- description: what an attacker could actually DO with this — describe the real exploitation technique
- severity: CRITICAL / HIGH / MEDIUM / LOW / INFO
- cvss_score: numeric CVSS v3.1 score (0.0-10.0)
- affected_component: specific VM, network, or setting
- remediation: step-by-step hardening instructions
- attack_scenario: detailed 3-4 sentence realistic attack scenario with specific techniques
- cve: relevant CVE identifier if known (e.g., "CVE-2023-21991") or null
- exploit_poc: actual proof-of-concept command or exploit code the attacker would use (e.g., Metasploit command, Python exploit snippet, or VBoxManage manipulation command) — be specific and technical
- metasploit: specific Metasploit module path if applicable (e.g., "exploit/multi/handler") or null
- attack_chain: how this finding connects to other potential attacks (e.g., "Stage 1: Initial Access -> Stage 2: Lateral Movement -> Stage 3: Data Exfiltration")
- references: relevant security references and CVE links

Return ONLY valid JSON:
{
  "findings": [
    {
      "id": "VBOX-001",
      "title": "VRDE Remote Desktop Exposed on Windows VM",
      "description": "The VRDE (VirtualBox Remote Desktop Extension) is enabled on the Windows VM, allowing unauthenticated remote desktop access on port 3389. An attacker on the same network can connect to this VRDP server using any RDP client and potentially gain interactive desktop access to the VM. If VRDP authentication is not configured or uses default credentials, this provides immediate code execution within the guest environment. This is the VirtualBox equivalent of leaving RDP exposed to the internet.",
      "severity": "CRITICAL",
      "cvss_score": 9.8,
      "affected_component": "Windows VM",
      "remediation": "1. Power off the VM\n2. Run: VBoxManage modifyvm \"Windows VM\" --vrde off\n3. If VRDE is required, configure strong authentication: VBoxManage setproperty vrdeauthlibrary \"VBoxAuth\"\n4. Restrict VRDP access via host firewall to trusted IPs only\n5. Use VPN tunnels for remote management instead of direct VRDP",
      "attack_scenario": "An attacker on the same network segment performs an Nmap scan and discovers port 3389 open on the host. Using any RDP client (rdesktop, FreeRDP, xfreerdp), the attacker connects to the VRDP server. If default credentials are in use or no authentication is configured, the attacker gains immediate interactive desktop access to the Windows VM, establishing a foothold for lateral movement and data exfiltration.",
      "cve": "CVE-2023-21991",
      "exploit_poc": "xfreerdp /v:192.168.56.101:3389 /u:Administrator /p:password /cert-ignore\n\n# Or with Metasploit:\n# use auxiliary/scanner/rdp/rdp_scanner\n# set RHOSTS 192.168.56.0/24\n# run",
      "metasploit": "auxiliary/scanner/rdp/rdp_scanner",
      "attack_chain": "Stage 1: Network Reconnaissance (Nmap port scan) -> Stage 2: Initial Access (VRDP/RDP brute force or default creds) -> Stage 3: VM Compromise (interactive desktop) -> Stage 4: Data Exfiltration (shared folders or network transfer)",
      "references": ["https://www.virtualbox.org/manual/ch07.html#vrdp", "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-21991", "https://www.rapid7.com/db/modules/auxiliary/scanner/rdp/rdp_scanner/"]
    }
  ],
  "summary": {
    "total_findings": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0,
    "overall_risk": "CRITICAL / HIGH / MEDIUM / LOW",
    "primary_attack_vectors": ["describe the top attack paths"],
    "highest_risk_component": "most vulnerable VM or component",
    "kill_chain": "Summarize the complete attack chain — from initial recon to full compromise — chaining multiple findings together in a realistic red team scenario"
  },
  "executive_summary": "4-5 paragraph executive summary written as a red team engagement report. Describe the overall security posture, the most critical attack paths identified, the real-world impact of the vulnerabilities, and the recommended remediation priorities. Reference specific findings and how they chain together."
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

        active_scan = enum_data.get("active_scan", {})
        scan_hosts = []
        for h in active_scan.get("hosts", []):
            scan_hosts.append({
                "ip": h.get("ip"),
                "open_ports": [{
                    "port": p["port"],
                    "service": p["service"],
                    "banner": p.get("banner", "")[:150],
                    "version": p.get("version"),
                    "fingerprint": p.get("fingerprint", {}),
                } for p in h.get("open_ports", [])],
            })

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
            "active_network_recon": {
                "subnets_scanned": active_scan.get("subnets", []),
                "live_hosts_discovered": scan_hosts,
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

        if summary:
            sev_counts = {k: summary.get(k, 0) for k in ("critical", "high", "medium", "low", "info")}
            self.emit_thinking(f"Risk distribution — critical: {sev_counts.get('critical',0)}, high: {sev_counts.get('high',0)}, medium: {sev_counts.get('medium',0)}, low: {sev_counts.get('low',0)}, info: {sev_counts.get('info',0)}")
            self.emit_thinking(f"Overall risk rating: {summary.get('overall_risk', 'N/A')} — primary attack vectors: {summary.get('primary_attack_vectors', 'N/A')}")
            self.emit_thinking(f"Highest risk component: {summary.get('highest_risk_component', 'N/A')} — recommended prioritization for remediation")

        self.emit_thinking(f"Claude analysis complete: {len(findings)} security finding(s) identified across the VirtualBox attack surface — findings range from critical remote access exposures to informational observations; each finding includes severity rating, CVSS score, remediation steps, attack scenario, exploitation proof-of-concept, attack chain context, and security references for manual verification")

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
