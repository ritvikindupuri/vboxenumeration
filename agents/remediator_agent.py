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

    def generate_plan(self, finding: dict) -> dict:
        """Generate remediation steps using Claude without executing them."""
        finding_id = finding.get("id", "unknown")
        title = finding.get("title", "Untitled Finding")
        component = finding.get("affected_component", "unknown")
        severity = finding.get("severity", "unknown")

        self.emit_thinking(f"Beginning remediation planning for finding [{finding_id}]: {title}")
        self.emit_thinking(f"Affected component: {component} (severity: {severity})")
        self.emit_thinking(f"Reviewing finding context — description length: {len(finding.get('description', ''))} chars, remediation guidance: {len(finding.get('remediation', ''))} chars")

        self.emit_thinking("Analyzing the remediation guidance provided by the analyzer to determine the precise VBoxManage commands needed — different findings require different command families: modifyvm for VM settings, setproperty for global config, controlvm for runtime changes, etc.")

        prompt_input = json.dumps({
            "finding_id": finding_id,
            "title": title,
            "affected_component": component,
            "severity": severity,
            "remediation": finding.get("remediation", ""),
            "description": finding.get("description", ""),
            "attack_scenario": finding.get("attack_scenario", ""),
        }, indent=2)

        self.emit_thinking(f"Converting remediation steps to precise VBoxManage commands — transmitting {len(prompt_input)} chars of finding context to Claude with the remediation prompt template; requesting structured JSON output with safe, idempotent, and targeted commands only")
        self.claude.set_system_prompt(REMEDIATION_PROMPT)
        result = self.claude.chat_structured(prompt_input)

        steps = result.get("steps", [])
        note = result.get("note", "")

        if steps:
            self.emit_thinking(f"Claude generated {len(steps)} remediation command(s):")
            for i, s in enumerate(steps):
                self.emit_thinking(f"  Step {i+1}: {s.get('description', '?')} → `{s.get('command', '?')}`")
            self.emit_thinking("All commands reviewed — proceeding to plan presentation; user will review before any commands are executed on the host")
        else:
            self.emit_thinking(f"No automated remediation commands could be generated for this finding — note from Claude: {note or 'No explanation provided'}")
            self.emit_thinking("This may be due to: the finding requiring manual intervention (e.g., installing patches, replacing hardware), the finding being informational only, or remediation requiring steps outside VBoxManage's capabilities")

        return {
            "finding_id": finding_id,
            "steps": steps,
            "note": note,
        }

    def execute_plan(self, plan: dict) -> dict:
        """Execute pre-generated remediation steps step by step."""
        finding_id = plan["finding_id"]
        steps = plan.get("steps", [])

        if not steps:
            note = plan.get("note", "No automated remediation available for this finding")
            self.emit_output(f"Remediation note: {note}")
            self.emit_result({"status": "skipped", "finding_id": finding_id, "reason": note})
            return {"finding_id": finding_id, "status": "skipped", "all_success": False, "steps": []}

        self.emit_thinking(f"Beginning execution of {len(steps)} remediation command(s) for finding {finding_id}")
        self.emit_thinking("Applying hardening measures directly via VBoxManage — each command is executed against the local VirtualBox installation with the VM names and parameters specified in the remediation plan")

        executed_steps = []
        all_ok = True

        for i, step in enumerate(steps):
            desc = step.get("description", f"Step {i+1}")
            cmd = step.get("command", "")

            self.emit_thinking(f"[{i+1}/{len(steps)}] Executing: {desc}")
            self.emit_thinking(f"Command: VBoxManage {cmd}")
            self.emit_command(cmd)

            try:
                args = shlex.split(cmd)
                if args and args[0].lower() in ("vboxmanage", "vboxmanage.exe"):
                    args = args[1:]
                self.emit_thinking(f"Invoking VBoxManage with arguments: {args}")
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
                    self.emit_output(f"✗ {desc} (exit code {rc})")
                    executed_steps.append({
                        "description": desc, "command": cmd,
                        "success": False, "output": out[:500],
                    })
                    all_ok = False
            except Exception as e:
                self.emit_output(f"✗ {desc} failed with exception: {e}")
                executed_steps.append({
                    "description": desc, "command": cmd,
                    "success": False, "output": str(e),
                })
                all_ok = False

        status = "completed" if all_ok else "completed_with_errors"
        ok_count = sum(1 for s in executed_steps if s["success"])
        fail_count = len(executed_steps) - ok_count

        if all_ok:
            self.emit_thinking(f"All {len(steps)} remediation step(s) executed successfully — finding {finding_id} has been addressed")
        else:
            self.emit_thinking(f"Remediation completed with {fail_count} error(s) — {ok_count}/{len(steps)} step(s) succeeded; manual intervention may be required for failed steps")

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

    def remediate(self, finding: dict) -> dict:
        """Full remediate: generate plan then execute (backward compatible)."""
        plan = self.generate_plan(finding)
        return self.execute_plan(plan)
