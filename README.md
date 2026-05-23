# FalcoHive

**Multi-Agent AI Security Operations Center** — powered by Gemini AI agents that orchestrate Docker, Falco, and Elasticsearch for real-time container threat detection and automated response.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                     ORCHESTRATOR AGENT (Gemini)                   │
│       Decides: monitor, investigate, respond, attack, report    │
└──────┬──────────┬──────────┬──────────┬──────────┬──────────────┘
       │          │          │          │          │
       ▼          ▼          ▼          ▼          ▼
   ┌────────┐┌────────┐┌────────┐┌────────┐┌────────────┐
   │  Falco ││Detect ││Response││ Attack ││ Reporting  │
   │Manager ││ Agent ││ Agent  ││ Agent  ││   Agent    │
   └───┬────┘└───┬────┘└───┬────┘└───┬────┘└──────┬─────┘
       │         │         │         │            │
       └─────────┴─────────┴─────────┴────────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │  ELASTICSEARCH   │ ← All events, detections, decisions
                  └────────┬─────────┘
                           │
                  ┌────────▼─────────┐
                  │     KIBANA       │
                  │  (visualization) │
                  └──────────────────┘
```

## 5 Gemini AI Agents

| Agent | Role | Powered By |
|-------|------|-----------|
| **Orchestrator** | Coordinates all agents, decides operational state | Gemini |
| **Detection** | Analyzes Falco events, classifies threats (MITRE ATT&CK) | Gemini |
| **Response** | Decides kill/block/isolate/alert for each threat | Gemini |
| **Attack** | Simulates realistic attacks on honeypot containers (Red Team) | Gemini |
| **Reporting** | Generates incident reports with metrics and recommendations | Gemini |

## What It Does

1. **Deploys Falco** — Real syscall monitoring on all containers
2. **Deploys Honeypots** — Intentionally vulnerable containers to attract attackers
3. **AI Detection** — Every Falco event is analyzed by Gemini-powered Detection Agent
4. **Auto-Response** — Containers are killed, blocked, or isolated automatically
5. **Red Team AI** — Attack Agent periodically simulates real attacks to validate detection
6. **Elasticsearch** — All events, detections, decisions, and attacks stored in ES
7. **Kibana** — Visualize security data, build dashboards, hunt threats
8. **Real-time Dashboard** — WebSocket-powered UI showing live events and agent thoughts

## Detection Coverage (MITRE ATT&CK)

| Attack | MITRE | Response | Risk |
|--------|-------|----------|------|
| Container Escape | T1611 | KILL | CRITICAL |
| Reverse Shell | T1059.004 | KILL | CRITICAL |
| Process Injection | T1055 | KILL | CRITICAL |
| Credential Dump | T1003.001 | BLOCK | CRITICAL |
| Crypto Mining | T1496 | KILL | HIGH |
| Web Shell | T1505.003 | BLOCK | HIGH |
| Privilege Escalation | T1548 | BLOCK | HIGH |
| Network Scan | T1046 | ISOLATE | MEDIUM |
| Cron Persistence | T1053.003 | BLOCK | HIGH |

## One-Command Shutdown
```powershell
.\shutdown.ps1                    # With confirmation prompt
.\shutdown.ps1 -Force             # Skip confirmation
```

## Quick Start

### Prerequisites
- Docker Desktop (with Linux containers)
- Python 3.12+
- Gemini API key (free from [Google AI Studio](https://aistudio.google.com))
- Elasticsearch credentials (cloud or local)

### 1. Setup credentials
```bash
cp .env.example .env
# Edit .env — add GEMINI_API_KEY and ES_* credentials
```

### 2. Run full stack
```bash
docker compose up -d elasticsearch kibana falco    # Start ES + Kibana + Falco
pip install -r requirements.txt                    # Install Python deps
python run.py                                      # Start AI-SOC engine
```

### 3. Open dashboards
- **AI-SOC Dashboard**: http://localhost:8080
- **Kibana**: http://localhost:5601

### 4. Simulate attacks
```powershell
.\tests\simulate-attacks.ps1
```

### Docker Compose (full deployment)
```bash
docker compose up --build
```

## Project Structure
```
container-security-ai-soc/
├── agents/
│   ├── orchestrator_agent.py    # Coordinator AI agent
│   ├── detection_agent.py       # Threat classification AI
│   ├── response_agent.py        # Auto-response AI
│   ├── attack_agent.py          # Red team AI
│   └── reporting_agent.py       # Report generation AI
├── core/
│   ├── gemini_client.py         # Gemini API wrapper
│   ├── elastic_client.py        # Elasticsearch client
│   ├── docker_controller.py     # Docker orchestration
│   ├── falco_manager.py         # Falco lifecycle
│   └── engine.py                # Main SOC engine
├── dashboard/app.py             # Real-time WebSocket dashboard
├── config/settings.py           # Configuration
├── rules/falco_rules.yaml       # Custom Falco detection rules
└── docker-compose.yml           # Full stack deployment
```

## Elasticsearch Indexes
- `falcohive-falco-event-*` — Raw Falco events
- `falcohive-detection-*` — AI detection analysis
- `falcohive-response-*` — Response actions taken
- `falcohive-attack-simulation-*` — Red team attack logs
- `falcohive-report-*` — Generated incident reports
- `falcohive-orchestrator-decision-*` — Orchestrator decisions
