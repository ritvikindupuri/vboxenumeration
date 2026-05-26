import json, glob, os

reports = glob.glob("data/vboxaudit_*.json")
if not reports:
    print("No reports found")
    exit()

latest = max(reports, key=os.path.getmtime)
print(f"Checking: {latest}")
print()

with open(latest) as f:
    data = json.load(f)

for finding in data["findings"]:
    sev = finding.get("severity", "?")
    title = finding.get("title", "?")
    remed = finding.get("remediation", "MISSING")
    attack = finding.get("attack_scenario", "MISSING")
    print(f"[{sev}] {title}")
    print(f"  Attack Scenario: {attack[:120]}")
    print(f"  Remediation: {remed[:200]}")
    print()
