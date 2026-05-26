import json
import logging
import shlex

from agents.base_agent import BaseAgent
from core.claude_client import ClaudeClient
from core.vbox_controller import VBoxController

logger = logging.getLogger(__name__)

REMEDIATION_PROMPT = """You are a VirtualBox security hardening assistant.
Convert security remediation text into exact VBoxManage commands.

For the given finding, produce the VBoxManage commands needed to fix it.
Only include commands that directly address the finding.

Rules:
- Command must be valid VBoxManage arguments only (NO "VBoxManage" prefix)
- Example GOOD: modifyvm "Windows VM" --vrde off
- Example BAD: VBoxManage modifyvm "Windows VM" --vrde off
- Use exact VM name from affected_component
- Commands should be safe and idempotent
- If no automated fix is possible, return empty steps with a note

Return ONLY valid JSON:
{
  "steps": [
    {
      "description": "Disable VRDE remote desktop",
      "command": "modifyvm \"Windows 10 VM\" --vrde off"
    }
  ]
}"""


class RemediatorAgent(BaseAgent):
    def __init__(self, claude: ClaudeClient):
        super().__init__("remediator")
        self.vbox = VBoxController()
        self.claude = claude

    def remediate(self, finding: dict) -> dict:
        finding_id = finding.get("id", "unknown")
        title = finding.get("title", "Untitled Finding")
        component = finding.get("affected_component", "unknown")

        self.emit_thinking(f"Preparing remediation: {title}")
        self.emit_thinking(f"Target component: {component}")

        prompt_input = json.dumps({
            "finding_id": finding_id,
            "title": title,
            "affected_component": component,
            "remediation": finding.get("remediation", ""),
            "description": finding.get("description", ""),
        }, indent=2)

        self.emit_thinking("Converting remediation to VBoxManage commands...")
        self.claude.set_system_prompt(REMEDIATION_PROMPT)
        result = self.claude.chat_structured(prompt_input)

        steps = result.get("steps", [])

        if not steps:
            note = result.get("note", "No automated remediation available for this finding")
            self.emit_output(f"Remediation note: {note}")
            self.emit_result({"status": "skipped", "finding_id": finding_id, "reason": note})
            return {"finding_id": finding_id, "status": "skipped", "all_success": False, "steps": []}

        self.emit_thinking(f"Executing {len(steps)} remediation step(s)")

        executed_steps = []
        all_ok = True

        for i, step in enumerate(steps):
            desc = step.get("description", f"Step {i+1}")
            cmd = step.get("command", "")

            self.emit_thinking(f"[{i+1}/{len(steps)}] {desc}")
            self.emit_command(cmd)

            try:
                args = shlex.split(cmd)
                if args and args[0].lower() in ("vboxmanage", "vboxmanage.exe"):
                    args = args[1:]
                rc, out = self.vbox.run(*args)
                if out.strip():
                    self.emit_output(out.strip()[:500])
                if rc == 0:
                    self.emit_output(f"✓ {desc}")
                    executed_steps.append({
                        "description": desc, "command": cmd,
                        "success": True, "output": out[:300],
                    })
                else:
                    self.emit_output(f"✗ {desc} (exit {rc})")
                    executed_steps.append({
                        "description": desc, "command": cmd,
                        "success": False, "output": out[:500],
                    })
                    all_ok = False
            except Exception as e:
                self.emit_output(f"✗ {desc}: {e}")
                executed_steps.append({
                    "description": desc, "command": cmd,
                    "success": False, "output": str(e),
                })
                all_ok = False

        status = "completed" if all_ok else "completed_with_errors"
        ok_count = sum(1 for s in executed_steps if s["success"])
        self.emit_result({
            "status": status, "finding_id": finding_id,
            "steps": len(executed_steps), "successful": ok_count,
        })

        return {
            "finding_id": finding_id,
            "status": status,
            "all_success": all_ok,
            "steps": executed_steps,
        }
