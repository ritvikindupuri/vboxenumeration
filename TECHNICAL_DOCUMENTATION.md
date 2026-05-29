# Technical Documentation — VBoxAuditor

**Date:** May 26, 2026

**By:** Ritvik Indupuri

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Project Overview](#2-project-overview)
3. [Technology Stack](#3-technology-stack)
4. [System Architecture](#4-system-architecture)
   - 4.1 Architecture Diagram
   - 4.2 Component Descriptions
   - 4.3 Data Flow
5. [Installation & Configuration](#5-installation--configuration)
   - 5.1 Prerequisites
   - 5.2 Installation Steps
   - 5.3 Configuration
6. [Dashboard Frontend](#6-dashboard-frontend)
   - 6.1 Layout
   - 6.2 Header
   - 6.3 Main Panel — Tabs
   - 6.4 Sidebar
   - 6.5 Finding Cards
   - 6.6 Event Streaming & Rendering
7. [Agent System](#7-agent-system)
   - 7.1 Base Agent Architecture
   - 7.2 Event Emission System
   - 7.3 Enumerator Agent
   - 7.4 Analyzer Agent
   - 7.5 Exploiter Agent
   - 7.6 Reporter Agent
   - 7.7 Remediator Agent
8. [Exploitation Engine](#8-exploitation-engine)
   - 8.1 CVE Database
   - 8.2 Credential Sprayer
   - 8.3 Post-Exploitation Engine
   - 8.4 External Tool Integration
9. [Network Scanner](#9-network-scanner)
   - 9.1 Subnet Extraction
   - 9.2 Ping Sweep
   - 9.3 Port Scan
   - 9.4 Banner Grabbing
   - 9.5 Version Fingerprinting
10. [WebSocket Event System](#10-websocket-event-system)
    - 10.1 Connection Lifecycle
    - 10.2 Event Queue & Processing
    - 10.3 Event Types
    - 10.4 Event Routing
11. [Report Generation](#11-report-generation)
    - 11.1 JSON Report
    - 11.2 HTML Report
    - 11.3 PDF Report
12. [Remediation System](#12-remediation-system)
    - 12.1 Plan Generation Phase
    - 12.2 Execution Phase
    - 12.3 Remediation Tab UI
13. [Attack Chain & Kill Chain](#13-attack-chain--kill-chain)
    - 13.1 Attack Chain Format
    - 13.2 Kill Chain Visualization
14. [Security Considerations](#14-security-considerations)
15. [Conclusion](#15-conclusion)

---

## 1. Executive Summary

VBoxAuditor is a comprehensive red-team security auditing tool designed specifically for Oracle VM VirtualBox hypervisor environments. It combines automated VirtualBox configuration enumeration, AI-powered vulnerability analysis, active exploitation with real compromise verification, and guided remediation — all delivered through a real-time web dashboard with live event streaming.

The system employs five autonomous AI agents that run sequentially in a background pipeline: **Enumerator** (discovers VMs, networks, and host configuration), **Analyzer** (sends data to Claude AI for structured security analysis), **Exploiter** (executes 8 phases of active attacks including CVE probing, VM escape detection, credential spraying, and SSH post-exploitation), **Reporter** (generates JSON/HTML/PDF reports), and **Remediator** (converts findings into executable VBoxManage fix commands).

The dashboard provides real-time visibility into every agent action through a two-tab interface: the **Agent Activity Log** streams every thinking message, command, raw output, and result with color-coded entries and agent badges, while the **Remediation tab** provides a structured two-phase fix workflow. The sidebar displays executive summary, kill chain visualization, exploitation statistics, expandable finding cards, compromised hosts panel, and report download links.

VBoxAuditor is built with Python 3.12+ (Flask backend), vanilla JavaScript frontend (no frameworks), WebSocket communication via flask-sock, Anthropic Claude AI for analysis, and VBoxManage CLI for VirtualBox control. It targets Windows hosts running Oracle VM VirtualBox.

---

## 2. Project Overview

VBoxAuditor performs the following high-level functions in sequence:

1. **Enumeration** — Discovers all VirtualBox VMs, their configurations, network topology, host properties, and performs active network reconnaissance (ping sweep, port scan, banner grabbing) on VM networks.
2. **Analysis** — Sends all collected data to Anthropic Claude with a red-team security auditor prompt. Claude returns structured findings with severity ratings, CVSS scores, CVE identifiers, exploit proof-of-concept commands, attack chain narratives, and remediation steps.
3. **Exploitation** — Executes 8 phases of active attacks: CVE-based service probing, VM configuration exploitation, VM escape detection, guest addition exploitation, shared folder abuse, network MITM simulation, credential spraying across 11 services, and SSH post-exploitation with live command execution.
4. **Reporting** — Generates JSON, HTML, and PDF reports with clean formatting.
5. **Remediation** — Converts findings into executable VBoxManage fix commands through Claude AI, with a two-phase plan-and-execute workflow.

---

## 3. Technology Stack

| Category | Technology | Purpose |
|----------|-----------|---------|
| **Backend Framework** | Python 3.12+, Flask 3.x | HTTP server and WebSocket host |
| **Real-Time Communication** | flask-sock (WebSocket) | Bidirectional event streaming between server and browser |
| **AI Analysis** | Anthropic Claude API (Claude Sonnet 4) | Security analysis, executive summary generation, remediation plan creation |
| **VirtualBox Control** | VBoxManage.exe CLI (subprocess) | All VirtualBox configuration queries and modifications |
| **CVE Database** | Python dictionary (in-memory) | 25+ service-version to CVE mappings plus 14 VirtualBox escape CVEs |
| **Credential Dictionary** | Python dictionary (in-memory) | 100+ default/weak credential pairs across 11 services |
| **SSH Post-Exploitation** | paramiko | SSH authentication and remote command execution |
| **Network Scanning** | Python socket + subprocess (ping, arp, route) | Ping sweeps, port scans, banner grabbing, ARP/routing analysis |
| **PDF Generation** | fpdf2 | PDF report output |
| **Report Formats** | JSON, HTML, PDF | Three formats for maximum compatibility |
| **External Tool Detection** | shutil.which + common paths | Auto-detection of nmap and hydra for enhanced scanning |
| **Environment Management** | python-dotenv | API key and configuration management |
| **Frontend** | Vanilla HTML/CSS/JavaScript | No frameworks — self-contained single-page application |
| **Styling** | CSS custom properties (variables) | Consistent dark theme with accent colors for different entry types |
| **Target Platform** | Windows | Requires Oracle VM VirtualBox and VBoxManage.exe |

---

## 4. System Architecture

### 4.1 Architecture Diagram

<div align="center">

**Figure 4.1: VBoxAuditor System Architecture — Component Interactions and Data Flow**

```mermaid
flowchart TB
    subgraph User["User Interface Layer"]
        Browser[Web Browser<br/>Dashboard HTML/CSS/JS]
    end

    subgraph Server["Flask Server — localhost:8080"]
        HTML[Single-Page Dashboard<br/>app.py template]
        WS[WebSocket Handler<br/>flask-sock /ws endpoint]
        Bcast[Event Broadcaster<br/>Fan-out to all WS clients]
    end

    subgraph Pipeline["Audit Pipeline — Background Thread"]
        direction LR
        E[1. Enumerator Agent<br/>Discovers VMs, networks, host config]
        NS[NetworkScanner<br/>Ping sweep · Port scan<br/>Banner grab · Version fingerprint]
        Ctx[(Shared Context<br/>Python dict)]
        A[2. Analyzer Agent<br/>AI-powered security analysis<br/>via Claude API]
        X[3. Exploiter Agent<br/>8 phases of active attacks]
        Rp[4. Reporter Agent<br/>JSON / HTML / PDF reports]
    end

    subgraph ExploitEngine["Exploitation Engine — Core Modules"]
        CVE[CVE Database<br/>25+ service→CVE mappings<br/>14 VM escape CVEs]
        Spray[Credential Sprayer<br/>100+ default creds<br/>11 services]
        PE[Post-Exploit Engine<br/>SSH compromise + cmd execution<br/>via paramiko]
        Tools[Tool Integration<br/>nmap / hydra auto-detection<br/>shutil.which + fallback paths]
    end

    subgraph Remediation["Remediation Engine — Background Thread"]
        Rm[Remediator Agent<br/>Converts findings to fix commands<br/>via Claude AI]
    end

    subgraph External["External Services & Resources"]
        VBox[Oracle VM VirtualBox<br/>VBoxManage.exe CLI]
        Claude[Anthropic Claude AI<br/>REST API — Sonnet 4]
        FS[File System<br/>Report files in data/]
    end

    Browser -->|"HTTP GET /"| HTML
    Browser -->|"WebSocket ws://host/ws"| WS
    WS -->|"cmd: start_audit"| E
    E -->|"VBoxManage list/showvminfo"| VBox
    VBox -->|"raw XML/config output"| E
    E -->|"discovered subnets"| NS
    NS -->|"live hosts + ports + banners"| E
    E -->|"store enum data"| Ctx
    Ctx -->|"read enum data"| A
    A -->|"send for AI analysis"| Claude
    Claude -->|"findings + summary JSON"| A
    A -->|"store findings"| Ctx
    Ctx -->|"read enum + findings"| X
    X -->|"CVE match + exploit probe"| CVE
    X -->|"default cred spray"| Spray
    X -->|"SSH login + commands"| PE
    X -->|"nmap -sV -sC / hydra"| Tools
    X -->|"store compromised hosts"| Ctx
    Ctx -->|"read all results"| Rp
    Rp -->|"write report files"| FS
    E -->|"event stream"| Bcast
    A -->|"event stream"| Bcast
    X -->|"event stream"| Bcast
    Rp -->|"event stream"| Bcast
    Bcast -->|"real-time JSON events"| Browser

    Browser -->|"cmd: remediate {finding}"| WS
    WS -->|"finding object"| Rm
    Rm -->|"convert to VBoxManage commands"| Claude
    Claude -->|"command list"| Rm
    Rm -->|"execute fix"| VBox
    VBox -->|"command output"| Rm
    Rm -->|"event stream"| Bcast
```

</div>

### 4.2 Component Descriptions

#### Application Entry Point (`main.py`)
The `main.py` file is the application entry point. It performs the following startup sequence:
1. Loads environment variables from `.env` using `python-dotenv` (`load_dotenv()`).
2. Validates that `ANTHROPIC_API_KEY` is set — exits with an error message if missing.
3. Creates a `ClaudeClient` instance using the API key and optional model override (`ANTHROPIC_MODEL` env var, defaults to `claude-sonnet-4-20250514`).
4. Creates an `AuditEngine` instance, passing in the Claude client.
5. Reads `DASHBOARD_HOST` and `DASHBOARD_PORT` environment variables (defaults: `0.0.0.0:8080`).
6. Logs the dashboard URL and calls `start_dashboard(engine)` which starts the Flask server.
7. Handles `KeyboardInterrupt` for clean shutdown on Ctrl+C.
8. A companion utility script `shutdown.ps1` is provided for terminating the application by process name or port number — useful when the terminal is closed or the process is running in the background.

#### Audit Engine (`core/engine.py`)
The `AuditEngine` class (`core/engine.py`) is the central orchestrator that manages the entire audit pipeline. It:

- **Initialization**: Creates all five agent instances (Enumerator, Analyzer, Exploiter, Reporter, Remediator). Registers event callback handlers on the four pipeline agents (not the Remediator, which uses a fresh handler per remediation run).
- **Event Queue**: Maintains an internal `Queue` that collects all agent events. Each agent emits events via `BaseAgent.emit()`, which calls `_handle_event()` to push `{agent, type, data}` JSON objects into the queue.
- **Event Broadcasting**: An `on_event()` handler is registered by the dashboard to receive events from the queue. The handler intercepts queue puts to broadcast events to WebSocket clients in real time.
- **Pipeline Execution**: `run_audit()` runs the 4-phase pipeline sequentially: Enumeration → Analysis → Exploitation → Reporting. Each phase stores results in a shared `context` dictionary passed between agents. The method is thread-safe and sets `_running = False` in a `finally` block.
- **Remediation Execution**: `run_remediation()` creates a fresh event handler for the Remediator Agent and calls `remediator.remediate(finding)`, allowing independent event streaming for the remediation workflow.

#### VBoxController (`core/vbox_controller.py`)
The `VBoxController` class provides a Python wrapper around the `VBoxManage.exe` command-line interface. It:

- **VBoxManage Discovery**: Automatically locates VBoxManage.exe at startup by checking common installation paths (`C:\Program Files\Oracle\VirtualBox\VBoxManage.exe`, the `VBOX_INSTALL_PATH` environment variable, and the system PATH).
- **Command Execution**: The `run()` method takes a variable-length argument list (e.g., `run("list", "vms")`) and executes it as a subprocess using `subprocess.Popen` with `capture_output=True` and `text=True`.
- **Output Parsing**: Returns raw stdout/stderr as strings. Individual agents are responsible for parsing the output into structured data (e.g., splitting lines, extracting key-value pairs from `showvminfo` output).
- **Error Handling**: Captures non-zero exit codes and returns them alongside output text, allowing agents to handle errors gracefully.

#### ClaudeClient (`core/claude_client.py`)
The `ClaudeClient` class provides a wrapper around the Anthropic Claude REST API. It:

- **Authentication**: Stores the API key and model name from environment configuration.
- **Query Method**: The `query()` method accepts a system prompt and user message, sends them to the Claude API via the `anthropic` Python SDK, and returns the response text.
- **Configuration**: Uses configurable model (defaults to `claude-sonnet-4-20250514`), temperature, and max tokens for response generation.
- **Error Handling**: Wraps API calls in try/except blocks and logs errors for troubleshooting.

#### Flask Server (`dashboard/app.py`)
The Flask server serves the single-page dashboard at `http://localhost:8080` and hosts a WebSocket endpoint at `/ws`. It manages the audit pipeline lifecycle, client connections, and event broadcasting. The server runs with `use_reloader=False` to prevent duplicate background threads.

Key server-side components:
- **WebSocket Handler** — Accepts connections, parses incoming JSON commands (`start_audit`, `plan_remediation`, `execute_remediation`), and manages client list (`_ws_clients`).
- **Event Broadcaster** — Fan-outs agent events to all connected WebSocket clients. Each event is a JSON object with `agent`, `type`, and `data` fields.
- **Audit Engine** — Background thread that runs the 4-agent pipeline sequentially. Each agent's events are captured via callback handlers and broadcast in real time.
- **Report Serving** — Serves generated report files (JSON, HTML, PDF) via Flask routes.

#### Agent Pipeline
Five autonomous agents run in sequence (or on-demand for remediation):

1. **Enumerator Agent** — Discovers the VirtualBox environment configuration.
2. **Analyzer Agent** — Analyzes findings via Claude AI.
3. **Exploiter Agent** — Executes active exploitation attacks.
4. **Reporter Agent** — Generates report files.
5. **Remediator Agent** — Converts findings to executable fix commands (runs on-demand via remediation tab).

Each agent extends `BaseAgent` which provides an event emission system (`emit_thinking`, `emit_command`, `emit_output`, `emit_result`) that routes through callback handlers to the WebSocket broadcaster.

#### Dashboard Frontend
A single HTML page with embedded CSS and JavaScript. The page establishes a WebSocket connection on load and processes incoming events through a queue-based streaming system with 800ms delay between events for readability. The frontend is organized into:

- **Header** — Logo, status indicator, and Execute Audit button.
- **Main Panel** — Two-tab layout (Agent Activity Log and Remediation).
- **Sidebar** — Executive summary, kill chain, exploitation summary, findings, compromised hosts, download links.

### 4.3 Data Flow

1. **User clicks Execute Audit** → Frontend sends `{"cmd": "start_audit"}` via WebSocket.
2. **Server spawns pipeline** → Creates `AuditEngine` instance with callback for events.
3. **Enumerator collects data** → Queries VBoxManage for VM configs, runs network scans, stores results in shared context dict.
4. **Analyzer processes** → Reads context, sends to Claude API, stores returned findings/summary/executive summary.
5. **Exploiter attacks** → Reads context, runs 8 phases of exploitation, stores results, compromised hosts, kill chain.
6. **Reporter finalizes** → Reads entire context, writes JSON/HTML/PDF files to `data/` directory.
7. **All events stream** → Every agent action (thinking, command, output, result, finding, vulnerability, compromise) is broadcast in real time to the dashboard via WebSocket.
8. **Dashboard renders** → Event queue processes each event sequentially with 800ms delay, routing to appropriate renderer functions (addEntry, renderFindings, renderKillChain, etc.).
9. **User remediation** → User clicks Execute Fix in remediation tab → triggers background `plan_remediation` (Claude generates VBoxManage commands) → preview shown → user clicks Apply → `execute_remediation` streams each command's output.

---

## 5. Installation & Configuration

### 5.1 Prerequisites

- Windows machine with administrator access
- Oracle VM VirtualBox installed (VBoxManage.exe must be available)
- Python 3.12 or later
- Anthropic API key (for Claude AI analysis)
- Internet connection (for API calls and package downloads)

### 5.2 Installation Steps

1. **Clone the repository:**
   ```powershell
   git clone https://github.com/ritvikindupuri/vboxenumeration.git
   cd vboxenumeration
   ```

2. **Create and activate a Python virtual environment:**
   ```powershell
   python -m venv venv
   .\venv\Scripts\activate
   ```

3. **Install Python dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```

4. **Configure environment variables:**
   Rename `.env.example` to `.env` and set your Anthropic API key:
   ```powershell
   Rename-Item .env.example .env
   ```
   Edit `.env` and set:
   ```
   ANTHROPIC_API_KEY=sk-ant-your-real-api-key-here
   ```

5. **(Optional) Install nmap** for enhanced version scanning during exploitation. Download from https://nmap.org and run the installer. VBoxAuditor auto-detects nmap at `C:\Program Files (x86)\Nmap\nmap.exe`.

6. **Run the application:**
   ```powershell
   python main.py
   ```
   The dashboard is available at `http://localhost:8080`.

### 5.3 Configuration

The application uses the following environment variables (in `.env`):

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | Yes | — | Anthropic Claude API key for AI analysis and remediation |
| `DASHBOARD_HOST` | No | `0.0.0.0` | Flask server bind address |
| `DASHBOARD_PORT` | No | `8080` | Flask server port |

---

## 6. Dashboard Frontend

The dashboard is a single-page application served by Flask. All HTML, CSS, and JavaScript are contained within `dashboard/app.py` as a multi-line string rendered via `render_template_string()`.

### 6.1 Layout

The dashboard uses a two-column layout with the main panel on the left and sidebar on the right.

```mermaid
flowchart TB
    subgraph Header["Header Layer"]
        H["[Logo] VBoxAuditor &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; [● Status] [Execute Audit]"]
    end

    subgraph Content["Dashboard Content"]
        direction LR
        subgraph Main["Main Panel (left)"]
            direction TB
            Tabs["Tabs: [📋 Agent Activity] | [🔧 Remediation]"]
            Log["Streaming Log Entries<br/>- thinking (gold border)<br/>- command (cyan border)<br/>- output (grouped under cmd)<br/>- result (green)<br/>- finding (green)<br/>- summary_detail (gold)"]
            Tabs --- Log
        end

        subgraph Sidebar["Sidebar (right, 400px)"]
            direction TB
            S1["Executive Summary"]
            S2["Kill Chain"]
            S3["Active Exploitation Stats"]
            S4["Findings Summary (grid)"]
            S5["Findings (expandable cards)"]
            S6["Compromised Hosts"]
            S7["Download Reports"]
            S1 --- S2 --- S3 --- S4 --- S5 --- S6 --- S7
        end

        Main ~~~ Sidebar
    end

    Header --- Content

    style Header fill:#111128,stroke:#1e1e3a,color:#d0d0e0
    style H fill:#0c0c1a,stroke:#1e1e3a,color:#00bcd4
    style Content fill:#07070f,stroke:none,color:#d0d0e0
    style Main fill:#111128,stroke:#1e1e3a,color:#d0d0e0
    style Sidebar fill:#0c0c1a,stroke:#1e1e3a,color:#d0d0e0
    style Log fill:#0c0c1a,stroke:#1e1e3a,color:#d0d0e0,text-align:left
```

### 6.2 Header

The header contains:
- **Logo** — Isometric box SVG icon referencing VirtualBox with the text "VBoxAuditor" in a cyan-to-purple gradient.
- **Status Badge** — A dot indicator with text: Dim gray = Ready, pulsing green = Running, cyan = Complete, red = Error.
- **Execute Audit Button** — Triggers the audit pipeline. Transitions to "Auditing..." (disabled) while running, then back to "Execute Audit" on completion.

### 6.3 Main Panel — Tabs

The main panel has two tabs switched via `switchTab()` function that toggles visibility of `#tab-log` and `#tab-remediation` panels.

#### Agent Activity Log Tab
This is the primary view for monitoring agent activity. It contains:
- **Phase Indicators** — Four phase badges at the top: `01 Enumerate`, `02 Analyze`, `03 Exploit`, `04 Report`. Initially dim, each turns cyan when active and green when complete.
- **Log Stream** — A scrollable container that displays all agent events in real time. Each entry is a `div.entry` with an agent badge header and message body.

#### Remediation Tab
Contains:
- **Findings list** (`#rem-findings-list`) — Each finding has a title, severity badge, and an "Execute Fix" button. Initially shows an empty state message.
- **Output area** (`#rem-output-area`) — Hidden by default. Shown when a fix is being executed. Displays the remediation plan preview and execution output.
- **Empty state** (`#rem-empty-state`) — "No findings yet" message with wrench icon, shown when no findings have been generated.

### 6.4 Sidebar

The sidebar (400px wide, scrollable) contains these sections that appear in order as data becomes available:

#### Executive Summary (`#execSection`)
A formatted display of the executive summary generated by the Analyzer agent. Uses `mdToHtml()` to convert markdown formatting (bold headers, bullet lists, paragraphs) into styled HTML. Below the summary text, it shows:
- **Risk Tag** — Overall risk level badge (critical=red, high=orange, medium=gold, low=cyan).
- **Attack Vectors** — Tag chips for each primary attack vector discovered.

#### Kill Chain (`#killChainSection`)
A visual 5-stage attack path visualization that updates in real time. Each stage is a node with technique name, target, description, and status badge (completed=green, confirmed=red, potential=gold). Stages are connected by arrow dividers.

#### Active Exploitation (`#exploitSummarySection`)
Summary card showing exploitation statistics: targets scanned, services probed, CVE probes executed, confirmed vulnerabilities, credentials discovered, and hosts compromised.

#### Findings Summary (`#summaryGrid`)
A 2×3 grid showing finding counts: Total, Critical, High, Medium, Low, Info. Updates in real time as findings are received.

#### Findings (`#findingsList`)
Expandable cards for each finding. Each card shows:
- **Collapsed:** Severity badge (colored), title, CVSS score, expand chevron.
- **Expanded:** Description, Attack Scenario, Exploit PoC (monospace code block), Attack Chain (numbered steps). No remediation in cards — remediation is in the dedicated Remediation tab.

Finding cards are styled with a colored left border matching severity (red=critical, orange=high, gold=medium, cyan=low, gray=info). Cards are sorted by severity (critical first).

#### Compromised Hosts (`#compromisedSection`)
Appears when the exploiter agent successfully compromises hosts via SSH. Shows each compromised host as a card with:
- IP address and port
- Credentials used (username:password)
- SHELL badge (green)
- Hostname, user, OS info
- Output from reconnaissance commands with `$` prompt styling

#### Download Reports (`#downloadArea`)
Appears after the audit completes. Shows PDF, HTML, and JSON download links.

### 6.5 Finding Cards

Finding cards are created by the `renderFindings()` function when a `findings` event is received. Each finding uses a template with:

- **Severity badge** (`sev-badge`) — Small uppercase label with colored background (critical/red, high/orange, medium/gold, low/cyan, info/gray).
- **CVE badge** (`cve-badge`) — Red badge showing CVE identifier if present.
- **MSF badge** (`msf-badge`) — Cyan badge showing Metasploit availability.
- **Title** — Bold text.
- **CVSS score** and **affected component** — Meta information.
- **Description** — Detailed finding description.
- **Attack Scenario** — Italic orange text describing the attack technique.
- **Exploit PoC** — Preformatted monospace code block with proof-of-concept exploit commands.
- **Attack Chain** — Numbered step circles (①, ②, ③...) with stage labels, formatted by `formatAttackChain()`.
- **Remediation** — (in main log entries only) Bullet-pointed fix steps.

Clicking a card header toggles the `expanded` class, which triggers CSS transitions to show/hide the finding body.

### 6.6 Event Streaming & Rendering

The dashboard uses an event queue system for sequential rendering:

1. **WebSocket message received** → Parsed as JSON, pushed to `eventQueue` array.
2. **`processNext()` function** — Dequeues one event per call, routes it to the appropriate handler, then schedules the next call after `STREAM_DELAY` (800ms).
3. **Handler functions** — Each event type has a dedicated handler:
   - `status` → updates status dot/text
   - `summary` → updates findings summary grid
   - `findings` → renders sidebar finding cards
   - `complete` → shows download links, resets button
   - `executive` → renders executive summary section
   - `kill_chain` → renders kill chain visualization
   - `vulnerability` → adds vulnerability probe entry
   - `exploitation_summary` → renders exploitation stats
   - `compromise` → adds compromised host card
   - `shell_output` → adds shell command output to compromised host card
   - `error` → adds error entry to log
   - `remediation_plan` → displays remediation plan preview
   - `remediation_complete` → finalizes remediation output
   - `thinking`, `command`, `output`, `result`, `finding`, `summary_detail` → routed to `addEntry()` for log display

---

## 7. Agent System

### 7.1 Base Agent Architecture

All agents inherit from `BaseAgent` (`agents/base_agent.py`), which provides:

<div align="center">

**Figure 7.1: Agent Class Inheritance and Event Emission Flow**

```mermaid
classDiagram
    %% Base Agent Definition
    class BaseAgent {
        +name: str
        +on_event(handler: Callable)
        +emit(event_type: str, data: dict)
        +emit_thinking(message)
        +emit_command(command)
        +emit_output(output)
        +emit_result(result)
        +run(context: dict) dict
    }

    %% Child Agents
    class EnumeratorAgent {
        +run(context: dict) dict
    }
    class AnalyzerAgent {
        +run(context: dict) dict
    }
    class ExploiterAgent {
        +run(context: dict) dict
    }
    class ReporterAgent {
        +run(context: dict) dict
    }
    class RemediatorAgent {
        +run(context: dict) dict
    }

    %% Inheritance
    BaseAgent <|-- EnumeratorAgent
    BaseAgent <|-- AnalyzerAgent
    BaseAgent <|-- ExploiterAgent
    BaseAgent <|-- ReporterAgent
    BaseAgent <|-- RemediatorAgent

    %% Event Flow
    class WebSocket_Client {
        <<External>>
    }
    class Flask_Server {
        <<External>>
    }
    class AuditEngine {
        <<External>>
    }

    BaseAgent --> AuditEngine : emit() / emit_*() calls
    AuditEngine --> Flask_Server : Event Queue / Callback
    Flask_Server --> WebSocket_Client : Broadcast JSON
```

</div>



```python
class BaseAgent:
    def __init__(self, name: str):           # Agent identifier
    def on_event(self, handler: Callable):    # Register event callback
    def emit(self, event_type: str, data: dict):  # Emit event to all handlers
    def emit_thinking(message):               # Shorthand for emit("thinking", ...)
    def emit_command(command):                # Shorthand for emit("command", ...)
    def emit_output(output):                  # Shorthand for emit("output", ...)
    def emit_result(result):                  # Shorthand for emit("result", ...)
    def run(self, context: dict) -> dict:     # Main agent logic (overridden)
```

Each agent registers a callback handler during pipeline setup. When an agent calls any `emit_*` method, the handler receives `(agent_name, event_type, data)` and broadcasts it to all WebSocket clients as a JSON object: `{"agent": "enumerator", "type": "thinking", "data": {"message": "..."}}`.

### 7.2 Event Emission System

Agents emit events using these standardized methods:

| Method | Event Type | Data Format | Purpose |
|--------|-----------|-------------|---------|
| `emit_thinking(msg)` | `thinking` | `{"message": "..."}` | Agent reasoning, what it's about to do, why |
| `emit_command(cmd)` | `command` | `{"command": "..."}` | Exact command being executed |
| `emit_output(out)` | `output` | `{"output": "..."}` | Raw command output |
| `emit_result(res)` | `result` | `{...}` | Structured result dict |
| `emit(type, data)` | custom | custom | Any event type (finding, vulnerability, kill_chain, etc.) |

### 7.3 Enumerator Agent

**File:** `agents/enumerator_agent.py`

The Enumerator Agent is responsible for discovering the full VirtualBox environment configuration. It performs both passive (VBoxManage queries) and active (network scanning) reconnaissance.

#### Execution Flow

1. **VM Inventory**: Runs `VBoxManage list vms` and `VBoxManage list runningvms` to get all registered VMs and currently running ones.

2. **Deep VM Configuration**: For each VM, runs `VBoxManage showvminfo "<vmname>"` and parses the output into a structured dictionary. Extracts these fields:
   - `VMState` — Power state (running, powered off, saved)
   - `OSType` — Guest operating system
   - `memory` / `vram` — RAM and video memory allocation
   - `cpus` — CPU count
   - `vrde` — VRDP remote desktop status (on/off)
   - `clipboard` — Clipboard sharing mode (disabled, hosttoguest, guesttohost, bidirectional)
   - `draganddrop` — Drag-and-drop mode (disabled, hosttoguest, bidirectional)
   - `audio` — Audio controller status
   - `usb` — USB controller status
   - `accelerate3d` — 3D acceleration status
   - `encryption` — Disk encryption status
   - `tpm` — TPM presence and version
   - `firmware` — Firmware type (EFI, BIOS)
   - `GuestAdditionsVersion` — Guest Additions version (if installed)
   - `nic*` — Network adapter configurations (type, MAC, attachment)
   - `serial` — Serial port configuration
   - `storage` — Storage controller details

3. **Snapshot Analysis**: Lists snapshots for each VM. Emits thinking detailing snapshot count and potential sensitive data exposure.

4. **Shared Folders**: Lists shared folder configurations for each VM. Shared folders create bidirectional host-guest filesystem bridges.

5. **Guest Properties**: Enumerates guest properties via `VBoxManage guestproperty enumerate`. Guest properties can leak OS details, logged-in users, network configuration, and installed software.

6. **Network Topology Mapping**: Runs multiple VBoxManage commands:
   - `list hostonlyifs` — Host-only network interfaces (the primary VM network type)
   - `list bridgedifs` — Bridged network adapters (direct LAN access)
   - `list natnets` — NAT networks (port forwarding rules)
   - `list dhcpservers` — DHCP server configurations
   - `list intnets` — Internal networks (stealth VM-to-VM channels)

7. **Host Profiling**: Collects host-level information:
   - `list hostinfo` — OS platform, CPU, memory details
   - `list systemproperties` — Default VM behavior, API version
   - `list extpacks` — Installed extension packs (Oracle Extension Pack, etc.)
   - `list usbhost` — Available USB host devices for passthrough
   - Host-only adapter details (IP addresses, netmasks)

8. **Active Network Reconnaissance**: If host-only networks are found, performs live network scanning:
   - Extracts subnet CIDRs from host-only adapter IPs
   - Runs parallel ping sweeps using PowerShell `Test-Connection`
   - TCP port scans live hosts on 30+ common ports (SSH, RDP, HTTP, HTTPS, SMB, MySQL, PostgreSQL, Redis, MongoDB, VNC, Telnet, FTP, SMTP, DNS, DHCP, Kerberos, LDAP, WinRM, MSSQL, Oracle DB, Elasticsearch, Cassandra, Memcached, RabbitMQ, Jenkins, GitLab, Docker, Kubernetes, VRDP, NFS)
   - Grabs service banners using protocol-specific probe techniques
   - Parses banners for version fingerprinting

9. **Summary Emission**: After all enumeration, emits a summary with counts of VMs, running VMs, host-only networks, live hosts, open ports, findings, snapshots, shared folders, and VMs with guest additions.

### 7.4 Analyzer Agent

**File:** `agents/analyzer_agent.py`

The Analyzer Agent sends all enumeration data to Anthropic Claude with a red-team security auditor prompt and processes the structured JSON response.

#### Prompt Structure

The agent uses `ANALYSIS_PROMPT` (a multi-line string constant) that instructs Claude to:

- Act as an adversarial security auditor conducting a live penetration test
- Analyze every finding from an attacker's perspective
- Return all findings as valid JSON with specific fields

Each finding in the response includes:
- `id` — Unique identifier (VBOX-001, VBOX-002, etc.)
- `title` — Short, actionable name
- `description` — What an attacker could actually do, with exploitation technique details
- `severity` — CRITICAL, HIGH, MEDIUM, LOW, or INFO
- `cvss_score` — Numeric CVSS v3.1 score (0.0–10.0)
- `affected_component` — Specific VM, network, or setting
- `remediation` — Step-by-step hardening instructions with commands
- `attack_scenario` — 3–4 sentence realistic red-team scenario with specific techniques
- `cve` — Relevant CVE identifier (e.g., "CVE-2023-21991") or null
- `exploit_poc` — Proof-of-concept command or exploit code (Metasploit, Python, VBoxManage)
- `metasploit` — Specific Metasploit module path or null
- `attack_chain` — How finding connects to other attacks (e.g., "Stage 1: Initial Access -> Stage 2: Lateral Movement -> Stage 3: Data Exfiltration")
- `references` — Relevant security references and CVE links

The response also includes a `summary` object with:
- `total_findings`, `critical`, `high`, `medium`, `low`, `info` — Count breakdowns
- `overall_risk` — CRITICAL / HIGH / MEDIUM / LOW
- `primary_attack_vectors` — List of top attack paths
- `highest_risk_component` — Most vulnerable VM or component
- `kill_chain` — Summary of complete attack chain from recon to compromise

And an `executive_summary` string formatted with markdown:
- `**Attack Surface Overview**` — Overall security posture summary
- `**Key Attack Paths**` — Bullet list of critical exploitation chains
- `**Real-World Impact**` — What a successful attacker could achieve
- `**Remediation Priorities**` — Ordered bullet list of recommended actions

#### Processing Flow

1. Prepares VM summaries from enumeration data (name, state, OS, VRDE, clipboard, drag-and-drop, USB, audio, 3D, encryption, TPM, firmware, guest additions, snapshots, shared folders, network adapters)
2. Compiles network scan data (live hosts, open ports, service banners, version fingerprints)
3. Sends to Claude via `ClaudeClient.query()` with the analysis prompt plus formatted enumeration data
4. Parses Claude's JSON response
5. Emits a `summary_detail` event with the risk distribution breakdown
6. Emits each finding individually as a `finding` event
7. Returns findings list, summary stats, and executive summary text

### 7.5 Exploiter Agent

**File:** `agents/exploiter_agent.py`

The Exploiter Agent performs 8 phases of active security testing against discovered targets. Each phase follows a strict **thinking → command → raw output → result** event format to provide full transparency.

#### Phase 1: CVE-Based Exploit Probing

For each live host discovered during enumeration:

1. If nmap is installed, runs `nmap -sV -sC` on the host's open ports and streams the raw output. If nmap is not available, falls back to banner-based fingerprinting from the initial port scan.
2. For each open port/service, fingerprints the service by extracting version numbers from banners.
3. Cross-references each service+version against a local CVE database of 25+ mappings.
4. For each CVE match, displays the exploit command and runs a live Python socket-based probe.
5. Emits `vulnerability` events for each probe result (confirmed or inconclusive).
6. Emits `finding` events for confirmed vulnerabilities.

#### Phase 2: VM Configuration Exploit Assessment

For each VM discovered during enumeration, analyzes its configuration for attacker-abusable features:

- **VRDP Remote Desktop** (CRITICAL) — If VRDE is enabled, an attacker on the same network can connect using any RDP client and gain interactive desktop access.
- **Clipboard Sharing** (HIGH) — Bidirectional clipboard allows guest-to-host data exfiltration and host-to-guest injection.
- **Drag-and-Drop File Transfer** (HIGH) — Enables file transfer between host and guest, bypassing network monitoring.
- **USB Passthrough** (HIGH) — USB controller enables keystroke injection (BadUSB) and device passthrough attacks.
- **Audio Redirection** (MEDIUM) — Creates covert channel for data exfiltration bypassing network monitoring.
- **3D Acceleration** (MEDIUM) — Exposes GPU paravirtualization interface with history of VM escape CVEs.
- **Serial Port Console** (MEDIUM) — Alternate administrative channel bypassing network security.
- **Guest Additions** (INFO) — Installed Guest Additions expand host-guest attack surface.

Each finding emits an output entry with severity and detailed attack technique description.

#### Phase 3: VM Escape Detection

1. Runs `VBoxManage --version` to get the installed VirtualBox version.
2. Cross-references the version against a database of 14 known guest-to-host escape CVEs spanning versions 5.2.0 through 6.1.50.
3. Each CVE has a version range (e.g., 6.1.0–6.1.50), an identifier, a description, and a CVSS score (typically 8.8–9.9).
4. If the installed version falls within a vulnerable range, emits a confirmed `vulnerability` event.
5. All escape CVEs target the virtualization boundary — successful exploitation grants ring-0 access to the host OS.

The escape CVE database includes notable vulnerabilities:
- CVE-2023-21991 (CVSS 9.8) — E1000 Guest-to-Host Escape
- CVE-2022-21489 (CVSS 9.9) — VRDP Guest-to-Host Escape
- CVE-2022-21303 (CVSS 8.8) — Shared Folders Out-of-Bounds
- CVE-2021-35544 (CVSS 8.8) — USB Passthrough Escape
- CVE-2021-35538 (CVSS 9.9) — E1000 Guest-to-Host Escape
- CVE-2020-14722 (CVSS 8.8) — USB Control Escape

#### Phase 4: Guest Addition Exploitation

For each VM with Guest Additions installed:

1. Runs `VBoxManage guestproperty enumerate "<vmname>"` to enumerate guest properties (OS details, user accounts, network config, logged-in users).
2. Runs `VBoxManage guestcontrol "<vmname>" list` to enumerate guest users and sessions.
3. Attempts `VBoxManage guestcontrol "<vmname>" createsession` to test guest session creation.
4. Emits a detailed output describing post-exploitation capabilities: guest property reading, guest control command execution, shared clipboard, screenshot capture, and file transfer.

#### Phase 5: Shared Folder Exploitation

For each VM with shared folders configured:
1. Runs `VBoxManage sharedfolder list "<vmname>"` to enumerate mount points and paths.
2. Describes the exploitation risk: bidirectional host-guest filesystem access enables malware staging, credential theft, and data exfiltration without network detection.

#### Phase 6: Network MITM Simulation

1. Runs `arp -a` on the host to enumerate ARP table entries, identifying VM MAC addresses and active network neighbors.
2. Runs `route print` to analyze the host routing table, identifying VM network segments and gateway configurations.
3. Runs `Get-NetAdapter | Select-Object Name, Status, MacAddress` via PowerShell to enumerate network adapters.
4. Analyzes host-only network topology and describes realistic MITM attack scenarios:
   - All traffic between VMs on host-only networks passes through the host
   - An attacker with code execution on the host can enable IP forwarding and ARP spoof neighboring VMs
   - Unencrypted protocols (HTTP, FTP, Telnet, SMB) can be intercepted and modified
   - Credentials and session tokens can be captured from unencrypted traffic

#### Phase 7: Credential Spraying

For each live host and service:
1. Retrieves default/weak credential pairs from `DEFAULT_CREDENTIALS` dictionary (100+ pairs across 11 services).
2. Displays each credential pair being tested as a command entry (`$ auth_check(service, ip:port, user:pass)`).
3. Attempts authentication using protocol-level libraries:
   - **SSH** — paramiko (TCP connection + SSH handshake + password auth)
   - **MySQL** — Raw MySQL protocol (handshake packet + auth response)
   - **Redis** — Raw Redis protocol (AUTH command)
   - **SMB** — smbprotocol (session setup)
   - **RDP, PostgreSQL, Elasticsearch, MongoDB, MSSQL, Oracle, Telnet** — Protocol-specific probes
4. For each valid credential found, emits a `finding` event with CRITICAL severity.

Default credential database covers common VirtualBox development and testing credentials (vagrant:vagrant, vagrant:password, root:root, admin:admin, administrator:password, user:user, test:test, ubuntu:ubuntu, kali:kali, etc.).

#### Phase 8: Post-Exploitation SSH

For each valid SSH credential discovered:
1. Attempts SSH connection using paramiko (`try_ssh_compromise()`).
2. If successful, emits a `compromise` event with host details (hostname, username, OS info).
3. Runs reconnaissance commands on the compromised host:
   - `whoami` / `hostname` / `id` — Basic system identification
   - `ipconfig /all` (Windows) or `ip addr` (Linux) — Network configuration
   - `netstat -ano` — Active network connections and listening ports
   - `tasklist` (Windows) or `ps aux` (Linux) — Running processes
4. Each command and its raw output is streamed to the dashboard as `shell_output` events.
5. Emits each compromised host to the `compromise` event for sidebar display.
6. All compromised hosts are added to the exploitation chain for kill chain visualization.

### 7.6 Reporter Agent

**File:** `agents/reporter_agent.py`

The Reporter Agent generates three report formats from the complete audit context. It runs last in the pipeline after all other agents have completed.

#### JSON Report
- Saves the complete audit data (enumeration, analysis, exploitation, compromise) as a structured JSON file.
- File path: `data/vboxaudit_{timestamp}.json`
- Contains: generated_at, tool name, executive summary, summary stats, findings array, environment info.

#### HTML Report
- Generates a standalone HTML file with embedded CSS styling.
- Contains: title header with generation date, executive summary with attack vector tags, findings overview cards (total, critical, high, medium, low, info), detailed findings table with severity badges, attack scenario, remediation, and references.
- File path: `data/vboxaudit_{timestamp}.html`
- Uses the same dark theme color scheme as the dashboard.

#### PDF Report
- Generates a PDF using the fpdf2 library.
- Contains: title page header with generation date, executive summary section, findings overview with severity counts, detailed findings per section (severity badge, title, metadata, description, attack scenario, remediation, references), and a conclusion section.
- File path: `data/vboxaudit_{timestamp}.pdf`
- Conference conclusion text describes the total findings, severity distribution, and remediation recommendations.

### 7.7 Remediator Agent

**File:** `agents/remediator_agent.py`

The Remediator Agent runs as a background thread triggered by user action in the Remediation tab. It uses a two-phase workflow: plan generation and execution.

#### Phase 1: Plan Generation (`generate_plan()`)

1. Receives a finding object with remediation text.
2. Sends the finding's remediation text to Claude with a prompt requesting step-by-step VBoxManage commands.
3. Claude returns a structured plan with command strings and descriptions.
4. Emits a `remediation_plan` event with the command list.
5. The dashboard displays the plan as a preview with each command in a code block.

#### Phase 2: Plan Execution (`execute_plan()`)

1. Receives the confirmed plan (list of commands).
2. For each command step:
   a. Emits `thinking` with the step description and safety checks.
   b. Emits `command` with the exact VBoxManage command.
   c. Executes the command via subprocess.
   d. Emits `output` with the raw command output.
3. After all commands, emits a `remediation_complete` event with success/failure status.
4. Agent checks for orphaned references in the plan and cleans up before execution.

---

## 8. Exploitation Engine

### 8.1 CVE Database

**File:** `core/exploit_engine.py`

The CVE database is a Python dictionary mapping service identifiers to known vulnerabilities. Each entry contains:

- `service` — Service name (OpenSSH, Apache, nginx, MySQL, etc.)
- `version_range` — Vulnerable version range (e.g., `< 7.7` for OpenSSH)
- `cve` — CVE identifier
- `description` — Vulnerability description
- `exploit_command` — Python socket-based exploit probe code
- `metasploit` — Metasploit module path (if available)

The database covers these services:
- **OpenSSH** — CVE-2018-15473 (user enumeration), CVE-2018-15919 (auth bypass)
- **Apache HTTP** — CVE-2021-41773 (path traversal), CVE-2021-42013 (RCE)
- **nginx** — CVE-2017-7529 (integer overflow), CVE-2021-23017 (DNS RCE)
- **MySQL** — CVE-2012-2122 (auth bypass), CVE-2016-6662 (RCE)
- **Samba** — CVE-2017-7494 (RCE/EternalRed), CVE-2020-1472 (Zerologon)
- **Redis** — CVE-2022-0543 (Lua sandbox escape), CVE-2013-7459 (heap overflow)
- **PostgreSQL** — CVE-2018-1058 (RCE via superuser)
- **Docker** — CVE-2019-13139 (RCE), CVE-2024-21626 (escape)
- **VirtualBox VRDP** — CVE-2023-21991 (VM escape)
- **Elasticsearch** — CVE-2014-3120 (RCE), CVE-2015-1427 (RCE)
- **Jenkins** — CVE-2015-8103 (RCE), CVE-2019-1003000 (RCE)
- **Tomcat** — CVE-2017-12617 (RCE), CVE-2017-12615 (RCE)
- **CUPS** — CVE-2024-47176 (RCE)

The `scan_service_vulnerabilities()` function:
1. Takes IP, port, service name, and banner text.
2. Extracts version numbers from banners using regex patterns.
3. Matches version against known vulnerable ranges.
4. If matched, builds an exploit command string and executes a live Python socket probe.
5. Returns vulnerability details including probe result and confirmation status.

The `build_exploit_command()` function generates Python code snippets for each CVE exploit, typically using socket connections to send malicious payloads.

### 8.2 Credential Sprayer

**File:** `core/credential_sprayer.py`

The Credential Sprayer module provides dictionary-based default credential testing across 11 network services. It uses protocol-level authentication to validate credentials.

`DEFAULT_CREDENTIALS` dictionary maps port numbers to lists of `(username, password)` tuples:

| Port | Service | Credential Pairs | Examples |
|------|---------|-----------------|----------|
| 22 | SSH | 18 | vagrant:vagrant, root:root, admin:admin, ubuntu:ubuntu, kali:kali |
| 21 | FTP | 15 | anonymous:anonymous, ftp:ftp, admin:admin |
| 23 | Telnet | 10 | root:root, admin:admin, cisco:cisco |
| 445 | SMB | 12 | vagrant:vagrant, administrator:password, guest:guest |
| 3389 | RDP | 10 | administrator:password, vagrant:vagrant, admin:admin |
| 3306 | MySQL | 10 | root:root, root:password, admin:admin |
| 5432 | PostgreSQL | 8 | postgres:postgres, postgres:password, admin:admin |
| 6379 | Redis | 4 | default:(none), default:redis |
| 9200 | Elasticsearch | 3 | (none),(none), elastic:changeme |
| 27017 | MongoDB | 5 | admin:admin, admin:password, root:root |
| 1433 | MSSQL | 5 | sa:sa, sa:password, sa:admin123 |
| 1521 | Oracle | 5 | scott:tiger, sys:change_on_install, system:manager |

The `spray_credentials()` function:
1. Takes IP, port, and service name.
2. Looks up the credential list for the given port.
3. Attempts authentication using protocol-level clients:
   - paramiko.SSHClient() for SSH
   - smbprotocol.connection.Connection() for SMB
   - mysql.connector.connect() for MySQL
   - psycopg2.connect() for PostgreSQL
   - redis.Redis() for Redis
   - ftplib.FTP() for FTP
   - telnetlib.Telnet() for Telnet
   - pyodbc.connect() for MSSQL
   - pymongo.MongoClient() for MongoDB
   - elasticsearch.Elasticsearch() for Elasticsearch
4. Returns list of validated credentials.

### 8.3 Post-Exploitation Engine

**File:** `core/post_exploit.py`

The Post-Exploitation Engine handles SSH-based compromise and remote command execution.

`try_ssh_compromise()` function:
1. Takes target IP, port, username, and password.
2. Creates a paramiko SSH client with disabled host key checking (non-production).
3. Attempts authentication with the provided credentials.
4. If successful, opens an interactive shell session.
5. Executes a series of reconnaissance commands:
   - `whoami` / `hostname` / `id` — Identity and system name
   - `ip addr` (Linux) or `ipconfig` (Windows) — Network configuration
   - `netstat -tlnp` or `netstat -ano` — Listening services and connections
   - `ps aux` or `tasklist` — Running processes
   - `cat /etc/passwd` or `cat /etc/shadow` — (Linux) User accounts and password hashes
   - `uname -a` — (Linux) Kernel version
   - `cat /etc/os-release` — (Linux) OS release info
6. Captures and stores all command outputs.
7. Returns a structured compromise result with hostname, username, OS info, and command outputs.

### 8.4 External Tool Integration

**File:** `core/tool_integration.py`

The Tool Integration module automatically detects installed security tools on the host system.

`detect_available_tools()` function:
1. Uses `shutil.which()` to search PATH for nmap and hydra.
2. If not found in PATH, checks common installation paths:
   - `C:\Program Files (x86)\Nmap\nmap.exe`
   - `C:\Program Files\Nmap\nmap.exe`
   - `C:\Program Files (x86)\Hydra\hydra.exe`
3. Returns a dictionary with tool availability status and paths.

`run_nmap_version_scan()` function:
1. Takes target IP and list of ports.
2. Runs `nmap -sV -sC -p <ports> <ip>` via subprocess with a 120-second timeout.
3. Captures raw stdout and stderr.
4. Returns the command string and raw output.

If nmap is not installed, the exploiter agent falls back to banner-based fingerprinting using the service banners already collected during the initial port scan (e.g., `SSH-2.0-OpenSSH_7.6p1`, `Apache/2.4.49`) — CVE matching still works but without the deeper NSE script analysis.

---

## 9. Network Scanner

**File:** `core/network_scanner.py`

The Network Scanner performs active network reconnaissance on discovered VirtualBox host-only networks.

### 9.1 Subnet Extraction

Parses `IPAddress` fields from VBoxManage host-only interface configuration. For each IP address, computes the subnet CIDR using the corresponding netmask. If no netmask is available, defaults to `/24`.

### 9.2 Ping Sweep

For each discovered subnet:
1. Generates all possible host IPs in the subnet.
2. Launches 30 parallel threads using `ThreadPoolExecutor`.
3. Each thread runs `powershell Test-Connection <ip> -Count 1 -Quiet` with a 2-second timeout.
4. Collects all responsive hosts.
5. Streams results as thinking events with live/discovered counts.

### 9.3 Port Scan

For each live host:
1. Scans 30+ common ports using TCP socket connections.
2. Uses `socket.connect_ex()` with a 2-second timeout per port.
3. Returns list of open ports with raw socket data.
4. Streams each host's open ports as output events.

### 9.4 Banner Grabbing

For each open port:
1. Establishes a TCP socket connection.
2. Sends protocol-specific probe data:
   - HTTP/HTTPS — Sends `GET / HTTP/1.0\r\n\r\n`
   - SSH — Reads server identification string
   - SMTP — Sends `EHLO probe\r\n`
   - FTP — Reads server banner
   - MySQL — Reads handshake packet
   - Redis — Sends `PING\r\n`
   - Generic — Sends `\r\n` and reads response
3. Captures up to 1024 bytes of response.
4. Streams results as output events.

### 9.5 Version Fingerprinting

Parses captured banners using regex patterns to extract version numbers:
- HTTP `Server` headers: `Server: Apache/2.4.49`
- SSH banners: `SSH-2.0-OpenSSH_7.6p1`
- MySQL handshake: Protocol version + server version string
- Redis: `redis_version:6.0.9`
- SMTP banners: `ESMTP Postfix (Ubuntu)`
- FTP banners: `220 ProFTPD 1.3.5 Server`

Extracted versions are used by both the Analyzer Agent (for risk assessment) and the Exploiter Agent (for CVE matching).

---

## 10. WebSocket Event System

### 10.1 Connection Lifecycle

1. Browser establishes WebSocket connection to `ws://host:8080/ws` on page load.
2. Server accepts connection and adds client to `_ws_clients` list.
3. All subsequent agent events are broadcast to all connected clients.
4. If the server restarts, the browser reconnects on next page load.

### 10.2 Event Queue & Processing

The dashboard maintains an `eventQueue` array that buffers incoming WebSocket messages. The `processNext()` function dequeues and processes one event at a time with `STREAM_DELAY` (800ms) between events. This prevents visual overload and allows users to read each event before the next one arrives.

```javascript
ws.onmessage = (e) => {
    eventQueue.push(JSON.parse(e.data));
    if (!processing) processNext();
};
```

### 10.3 Event Types

| Event Type | Source Agent | Data | Renderer | Description |
|-----------|-------------|------|----------|-------------|
| `status` | system | `{status: "running"/"done"/"error"}` | `updateStatus()` | Connection/audit status |
| `thinking` | all agents | `{message: "..."}` | `addEntry()` | Agent reasoning |
| `command` | all agents | `{command: "..."}` | `addEntry()` | Executed command |
| `output` | all agents | `{output: "..."}` | `addEntry()` | Raw command output |
| `result` | all agents | `{...}` | `addEntry()` | Structured result |
| `error` | all agents | `{message: "..."}` | `addEntry()` | Error message |
| `finding` | analyzer, exploiter | `{id, title, severity, ...}` | `addEntry()` + `renderFindings()` | Security finding |
| `summary_detail` | analyzer | `{critical, high, medium, ...}` | `addEntry()` | Risk distribution |
| `summary` | analyzer | `{total_findings, critical, ...}` | `updateSummary()` | Summary grid stats |
| `findings` | analyzer | `[{finding}, ...]` | `renderFindings()` | Batch findings list |
| `executive` | system | `{executive_summary, overall_risk, ...}` | `renderExecutive()` | Executive summary |
| `vulnerability` | exploiter | `{ip, port, cve, confirmed, ...}` | `addVulnerabilityEntry()` | CVE probe result |
| `exploitation_summary` | exploiter | `{targets_scanned, cve_probes, ...}` | `renderExploitSummary()` | Exploitation stats |
| `compromise` | exploiter | `{ip, hostname, username, ...}` | `addCompromisedHost()` | Compromised host |
| `shell_output` | exploiter | `{ip, cmd, output}` | `addShellOutput()` | Post-exploit command result |
| `kill_chain` | exploiter | `{chain: [{stage, technique, ...}]}` | `renderKillChain()` | Kill chain stages |
| `complete` | system | `{pdf_path, html_path, json_path}` | `onComplete()` | Audit completion |
| `remediation_plan` | remediator | `{finding_id, commands: [{cmd, desc}]}` | `onRemediationPlan()` | Remediation plan preview |
| `remediation_complete` | remediator | `{finding_id, all_success}` | `onRemediationComplete()` | Remediation result |

### 10.4 Event Routing

The `processNext()` function routes events to handlers based on `msg.type`. The routing logic:

1. **Remediator agent events** — If `msg.agent === "remediator"` and type is `thinking`/`command`/`output`/`result`, the event is routed ONLY to the remediation tab (`renderRemediationToCard()`) and NOT to the main activity log. Other remediator event types (`remediation_plan`, `remediation_complete`) fall through to normal handlers.
2. **All other events** — Routed to dedicated handler functions or the generic `addEntry()` function.

The `addEntry()` function handles the rendering of thinking, command, output, result, error, finding, and summary_detail event types. It also implements **command-output grouping**: when an output event immediately follows a command event from the same agent, the output is appended as a child div (.cmd-output) directly inside the command's entry element rather than creating a separate log entry.

---

## 11. Report Generation

Reports are generated by the Reporter Agent after all other agents have completed. Three formats are produced: JSON (machine-readable), HTML (browser-viewable), and PDF (print-ready).

### 11.1 JSON Report

- Format: Standard JSON with structured data.
- Contains: Full audit context including environment info, executive summary, summary statistics, complete findings array (each with all fields), and exploitation results.
- Use case: Programmatic analysis, integration with other tools, data archival.

### 11.2 HTML Report

- Format: Standalone self-contained HTML file with embedded CSS.
- Header: "VBoxAuditor" title with generation date.
- Executive Summary section with formatted text and attack vector tags.
- Findings Overview cards showing severity counts.
- Detailed Findings table with columns: ID, Severity, Title, CVSS, Component, Description, Attack Scenario, Remediation, References.
- Uses the same dark theme color scheme as the real-time dashboard.
- Use case: Sharing with non-technical stakeholders, attaching to email, offline viewing.

### 11.3 PDF Report

- Format: Multi-page PDF generated with fpdf2 library.
- Header: "VBoxAuditor" title with generation date.
- Executive Summary section with formatted text.
- Findings Overview with severity counts and labels.
- Detailed Findings per section with severity badge, title, metadata, description, attack scenario, remediation steps, and references.
- Conclusion section summarizing total findings, severity distribution, and remediation recommendations.
- Use case: Formal reporting, compliance documentation, client deliverables.

---

## 12. Remediation System

The remediation system provides a user-driven workflow for applying security fixes to VirtualBox findings. It runs as a background thread separate from the main audit pipeline.

### 12.1 Plan Generation Phase

Triggered when the user clicks "Execute Fix" on a finding in the Remediation tab:

1. **Frontend**: Sends `{"cmd": "plan_remediation", "finding": {...}}` via WebSocket.
2. **Server**: Starts a background thread calling `RemediatorAgent.generate_plan(finding)`.
3. **Remediator Agent**: Sends the finding's remediation text to Claude with a prompt requesting actionable VBoxManage commands.
4. **Claude Response**: Returns a list of commands with step descriptions.
5. **Event**: Emits `remediation_plan` with `finding_id` and `commands` array (each containing `cmd` and `description`).
6. **Frontend**: Displays the plan as a preview with each command in a code block and an "Apply N Commands" button.

### 12.2 Execution Phase

Triggered when the user clicks "Apply" on a confirmed plan:

1. **Frontend**: Sends `{"cmd": "execute_remediation", "plan": [...]}` via WebSocket.
2. **Server**: Starts a background thread calling `RemediatorAgent.execute_plan(plan)`.
3. **Remediator Agent**: For each command step:
   - Emits `thinking` with step description and validation checks
   - Emits `command` with the exact VBoxManage command text
   - Executes the command via Python subprocess (Popen with pipe)
   - Emits `output` with stdout + stderr captured from the shell
4. After all commands: Emits `remediation_complete` with `finding_id` and `all_success` boolean.
5. **Frontend**: Updates button states (`✓ Fixed` or `✗ Failed`), shows final status, displays "← Back to findings list" link.

### 12.3 Remediation Tab UI

The Remediation tab (`#tab-remediation`) has three views:

1. **Empty State** (`#rem-empty-state`): Shown when no findings exist yet. Displays a wrench icon with "No findings yet" message.

2. **Findings List** (`#rem-findings-list`): Shows each finding with:
   - Severity badge (colored by severity)
   - Finding title
   - Execute Fix button (`.rem-exec-btn`) styled per state:
     - Default: Green with "Execute Fix"
     - Planning: Gold pulsing with "Planning..."
     - Running: Gold pulsing with "Applying..."
     - Success: Green with "✓ Fixed" (disabled)
     - Failed: Red with "✗ Failed" (disabled)

3. **Output Area** (`#rem-output-area`): Shows the remediation plan and execution results:
   - Plan preview with command code blocks
   - Execution progress with thinking, commands, and raw output
   - Each output entry is grouped under its command using `_cardLastCmdEl` tracking (parallel mechanism to `_lastCmdEntry` for the main log)
   - Final status with "← Back to findings list" link

---

## 13. Attack Chain & Kill Chain

### 13.1 Attack Chain Format

Attack chains are rendered as numbered step circles using the `formatAttackChain()` function. The function:

1. Splits the chain string on `->` separators.
2. Creates a vertical list of steps, each with a numbered circle badge and text.
3. Steps are styled with the accent-orange color scheme.
4. Between steps, a subtle separator line is drawn.

Example rendering:
```
① Stage 1: Network Reconnaissance (Nmap port scan)
② Stage 2: Initial Access (VRDP/RDP brute force or default creds)
③ Stage 3: VM Compromise (interactive desktop)
④ Stage 4: Data Exfiltration (shared folders or network transfer)
```

### 13.2 Kill Chain Visualization

The kill chain is rendered by `renderKillChain()` in the sidebar. It visualizes a 5-stage attack path:

- **Stage 1: Reconnaissance** — Network scanning results. Status: `completed` (always).
- **Stage 2: Initial Access** — VRDP exposure, SSH credentials found. Status: `confirmed` when credentials found or VRDP enabled.
- **Stage 3: Lateral Movement** — Cross-VM network access, MITM potential. Status: `confirmed` if MITM scenarios identified, `potential` if multiple hosts exist.
- **Stage 4: Privilege Escalation** — VM escape CVEs, USB passthrough attacks. Status: `confirmed` if escape CVEs or USB attacks found.
- **Stage 5: Data Exfiltration** — Shared folders, clipboard access. Status: `potential` if shared folders or bidirectional clipboard enabled.

Each node displays:
- Stage name (cyan label)
- Technique name (bold white text)
- Description (dim gray detail)
- Status badge: `completed` (green), `confirmed` (red), or `potential` (gold)

Nodes are connected by arrow indicators for visual flow. The visualization updates in real time as the exploiter agent discovers new evidence.

---

## 14. Security Considerations

- **Read-Only Operations**: The enumerator and analyzer agents perform read-only operations. Only the exploiter agent makes active network connections and authentication attempts.
- **Safe Defaults**: Credential spraying uses a dictionary of known default/weak credentials — it does not brute-force.
- **Non-Destructive**: The exploiter agent's CVE probes use Python socket connections to test for vulnerabilities without causing service disruption. No actual exploitation payloads are deployed.
- **VM Escape Detection**: VM escape detection is purely version-based — it cross-references the installed VirtualBox version against known CVEs without attempting actual escape exploits.
- **Post-Exploitation Scope**: SSH post-exploitation only executes reconnaissance commands (whoami, ipconfig, netstat) — no modifications are made to compromised systems.
- **Remediation Commands**: Remediation commands are reviewed by the user in the plan preview before execution. The user must explicitly click "Apply" to execute.
- **API Key Security**: The Anthropic API key is stored in `.env` file and loaded via python-dotenv. It is never exposed in logs or dashboard output.

---

## 15. Conclusion

VBoxAuditor provides a comprehensive, end-to-end security auditing solution for VirtualBox hypervisor environments. Its agent-based architecture enables deep enumeration, AI-powered analysis, active exploitation with real verification, and guided remediation — all delivered through a real-time web dashboard.

The five-agent pipeline (Enumerator → Analyzer → Exploiter → Reporter → Remediator) covers the full security assessment lifecycle from discovery through remediation, with every action transparently streamed to the user. The 8-phase exploitation engine provides thorough coverage of the VirtualBox attack surface, including VM escape detection, guest channel exploitation, credential spraying, and live SSH post-exploitation.

The system is designed for security professionals conducting authorized penetration tests, system administrators hardening their VirtualBox infrastructure, and security researchers studying virtualization attack vectors. All exploitation is non-destructive, and remediation requires explicit user confirmation before execution.

By combining automated VirtualBox configuration auditing, AI-driven analysis via Claude, active exploitation with real compromise proof, and structured remediation workflows, VBoxAuditor offers a complete toolkit for understanding and securing VirtualBox environments against real-world attack scenarios.
