# VBoxAuditor

**VirtualBox Attack Surface Enumeration & Remediation Tool**

VBoxAuditor is a security auditing tool that automatically enumerates, analyzes, and reports on VirtualBox hypervisor misconfigurations from an attacker's perspective. It deploys autonomous AI agents to scan your VirtualBox environment, identify security weaknesses, and guide remediation — all through a real-time web dashboard.

---

## System Architecture

<p align="center">
  <em>Figure 1: VBoxAuditor System Architecture</em>
</p>

```mermaid
flowchart TB
    subgraph User["User Interface"]
        Browser[Web Browser - Dashboard]
    end

    subgraph Server["Flask Server localhost:8080"]
        HTML[HTML/CSS/JS Dashboard]
        WS[WebSocket Handler flask-sock]
        Bcast[Event Broadcaster]
    end

    subgraph Pipeline["Audit Pipeline Background Thread"]
        E[1. Enumerator Agent<br/>Discovers VMs, networks, host config]
        A[2. Analyzer Agent<br/>AI-powered security analysis]
        Rp[3. Reporter Agent<br/>Generates JSON / HTML / PDF reports]
    end

    subgraph Remediation["Remediation Engine Background Thread"]
        Rm[Remediator Agent<br/>Converts findings to fix commands]
    end

    subgraph External["External Services"]
        VBox[Oracle VM VirtualBox<br/>VBoxManage.exe CLI]
        Claude[Anthropic Claude AI<br/>REST API]
        FS[File System<br/>Report files in data/]
    end

    Browser -->|"HTTP GET /"| HTML
    Browser -->|"WebSocket ws://host/ws"| WS
    WS -->|"cmd: start_audit"| E
    E -->|"VBoxManage list/show"| VBox
    VBox -->|"raw XML/config output"| E
    E -->|"structured VM/network/host data"| A
    A -->|"send for AI analysis"| Claude
    Claude -->|"findings + summary JSON"| A
    A -->|"findings array"| Rp
    Rp -->|"write files"| FS
    E -->|"event stream"| Bcast
    A -->|"event stream"| Bcast
    Rp -->|"event stream"| Bcast
    Bcast -->|"real-time JSON events"| Browser

    Browser -->|"cmd: remediate {finding}"| WS
    WS -->|"finding object"| Rm
    Rm -->|"convert remediation to commands"| Claude
    Claude -->|"VBoxManage command list"| Rm
    Rm -->|"execute fix"| VBox
    VBox -->|"command output"| Rm
    Rm -->|"event stream"| Bcast
```

### Flow-by-Flow Explanation

**1. Dashboard Load** — The user opens `http://localhost:8080` in a web browser. The Flask server serves a single-page HTML dashboard with embedded CSS and JavaScript. The browser establishes a WebSocket connection to the server for real-time communication.

**2. Execute Audit** — The user clicks the **Execute Audit** button. The dashboard sends a `start_audit` command over the WebSocket. The server spawns a background daemon thread running the `AuditEngine`, so the WebSocket remains responsive.

**3. Enumeration Phase** — The `EnumeratorAgent` runs a series of `VBoxManage.exe` commands to discover every registered VM (`list vms`), identify running VMs (`list runningvms`), extract detailed VM configurations (`showvminfo`), map network interfaces (host-only, bridged, NAT, DHCP, internal), profile the host (OS info, extension packs, USB devices), and check for mounted media. Each command and its output is streamed as events back to the dashboard in real time.

**4. Analysis Phase** — The `AnalyzerAgent` receives the structured enumeration data and calls the Anthropic Claude API with a red-team security prompt. Claude evaluates each VM's settings, network exposure, and host-level vulnerabilities from an attacker's perspective. It returns structured JSON findings with severity ratings, CVSS scores, remediation steps, and attack scenarios. Each finding is streamed to the dashboard as a richly formatted log entry with a colored severity badge.

**5. Report Generation Phase** — The `ReporterAgent` takes the findings and generates three report formats: JSON (machine-readable), HTML (browser-viewable with styled tables), and PDF (portable document with cover page and conclusion). All reports are saved to the `data/` directory.

**6. Dashboard Results** — The dashboard displays an executive summary, a findings summary grid (severity counts), expandable finding cards with full details, and download links for all three report formats.

**7. Remediation** — For any finding, the user clicks **Execute Fix** (either in the collapsed card header or the expanded body). The dashboard sends a `remediate` command with the full finding object. A `RemediatorAgent` is spawned in a new background thread. It sends the finding's remediation text to Claude, which converts it into concrete `VBoxManage` commands. The agent then executes each command step by step, streaming thinking, commands, raw output, and results to the dashboard in real time. The button updates to show `✓ Fixed` or `✗ Failed` on completion.

---

## Tech Stack

| Category | Technology |
|----------|-----------|
| **Backend Framework** | Python 3.12+, Flask 3.x |
| **Real-Time Communication** | WebSocket via flask-sock |
| **AI Analysis** | Anthropic Claude API (Claude Sonnet 4) |
| **VirtualBox Control** | VBoxManage.exe CLI (subprocess) |
| **PDF Generation** | fpdf2 |
| **Report Formats** | JSON, HTML, PDF |
| **Environment** | python-dotenv |
| **Frontend** | Vanilla HTML/CSS/JavaScript (no frameworks) |
| **Target Platform** | Windows (requires Oracle VM VirtualBox) |

---

## Installation

### Prerequisites

- A Windows machine with **Git** installed
- Internet connection (for downloading Python, VirtualBox, and dependencies)
- An **Anthropic API key** (get one at https://console.anthropic.com)

### Step 1: Install Python

1. Open a web browser and go to https://www.python.org/downloads/
2. Click the yellow **Download Python** button (get Python 3.12 or later)
3. Once downloaded, run the installer
4. **IMPORTANT**: Check the box that says **"Add Python to PATH"** at the bottom of the installer
5. Click **Install Now** and wait for the installation to complete
6. Close the installer

Verify Python is installed:
```powershell
python --version
```
You should see something like `Python 3.12.x`.

### Step 2: Install Oracle VM VirtualBox

1. Open a web browser and go to https://www.virtualbox.org/wiki/Downloads
2. Click **"Windows hosts"** under the "VirtualBox X.X.X platform packages" section
3. Once downloaded, run the installer
4. Click **Next** through all default options (no need to change anything)
5. If prompted about network interfaces, click **Yes** to allow
6. Wait for installation to complete and click **Finish**

Verify VirtualBox is installed:
```powershell
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" --version
```
You should see a version number like `7.0.x`.

### Step 3: Clone the Repository

```powershell
git clone https://github.com/ritvikindupuri/vboxenumeration.git
cd vboxenumeration
```

### Step 4: Set Up a Virtual Environment

Create a virtual environment to isolate dependencies:
```powershell
python -m venv venv
```

Activate the virtual environment:
```powershell
.\venv\Scripts\activate
```
You should see `(venv)` appear at the beginning of your terminal prompt.

### Step 5: Install Dependencies

```powershell
pip install -r requirements.txt
```
Wait for all packages to download and install. This may take a minute.

### Step 6: Configure Your API Key

1. In the project folder (`vboxenumeration`), locate the file named `.env.example`
2. Rename it to `.env`:
   ```powershell
   Rename-Item .env.example .env
   ```
3. Open `.env` in Notepad:
   ```powershell
   notepad .env
   ```
4. Replace `sk-ant-xxxxxxxxxxxx` with your actual Anthropic API key:
   ```
   ANTHROPIC_API_KEY=sk-ant-your-real-api-key-here
   ```
5. Save the file (Ctrl+S) and close Notepad

### Step 7: Run the Application

```powershell
python main.py
```

You should see output like:
```
VBoxAuditor — Attack Surface Enumeration Tool
Dashboard: http://localhost:8080
Open in browser and click 'Execute Audit' to begin
```

---

## How to Use the Dashboard

### Opening the Dashboard

Open your web browser and go to `http://localhost:8080`. You will see the VBoxAuditor dashboard with three main areas:

```
┌──────────────────────────────────────────────────────┐
│  [V] VBoxAuditor              [● Ready] [▲ Execute]  │  ← Header
├──────────────────────────┬───────────────────────────┤
│                          │                           │
│    Agent Activity Log    │     Executive Summary     │
│                          │     (hidden until done)    │
│   [01 Enumerate]         │                           │
│   [02 Analyze]           │     Findings Summary      │
│   [03 Report]            │     ┌───┬───┐             │
│                          │     │Ttl│Cri│             │
│   (streaming entries)    │     ├───┼───┤             │
│                          │     │Hi │Med│             │
│                          │     ├───┼───┤             │
│                          │     │Low│Inf│             │
│                          │     └───┴───┘             │
│                          │                           │
│                          │     Findings & Remediation│
│                          │     ┌──────────────────┐  │
│                          │     │[HIGH] VRDE...▶   │  │
│                          │     ├──────────────────┤  │
│                          │     │[MED] TPM...▶     │  │
│                          │     ├──────────────────┤  │
│                          │     │[LOW] DHCP...▶    │  │
│                          │     └──────────────────┘  │
│                          │                           │
│                          │     Download Reports      │
│                          │     (hidden until done)    │
├──────────────────────────┴───────────────────────────┤
│                                                        │
│              Remediation Activity                      │
│              (appears after first fix)                  │
└────────────────────────────────────────────────────────┘
```

### Header Elements

| Element | Description |
|---------|-------------|
| **Status Dot** | Shows current state: dim gray = Ready, pulsing green = Running, cyan = Complete, red = Error |
| **Status Text** | Text label matching the dot state |
| **Execute Audit** | Starts a full security audit. Disabled while running, shows "■ Running..." during audit |

### Log Panel (Left Side)

The main area shows the **Agent Activity Log** — a real-time, scrollable feed of everything the agents are doing:

- **Phase Indicators** at the top show the current stage: `01 Enumerate`, `02 Analyze`, `03 Report`. Each turns green when complete.
- **Thinking entries** (gold left border, `⟐` prefix) — the agent explaining what it's about to do and why (e.g., "Enumerating host-only networks — these isolated segments can be exploited for covert communication...")
- **Command entries** (cyan left border, `$` prefix in monospace) — the exact VBoxManage command being run. Raw output appears directly below the command in a dark monospace block.
- **Result entries** (green left border, `✓` prefix) — a summary of what was accomplished
- **Error entries** (red left border, `✗` prefix) — any failures or issues encountered
- **Summary Detail entries** (purple left border) — the analysis summary with severity breakdown, attack vectors, and overall risk rating
- **Finding entries** (green left border) — one per finding, showing severity badge, bold title, CVSS score, affected component, description, remediation steps as bullet points, and attack scenario

Agent badges (`🔍 Enumerator`, `🧠 Analyzer`, `📊 Reporter`, `🔧 Remediator`, `⚙️ System`) appear on every entry so you always know which agent produced it.

### Sidebar (Right Side)

#### Executive Summary
Appears after the audit completes. Shows the AI-generated executive summary, overall risk badge (colored: red/orange/amber/blue), and attack vector tags.

#### Findings Summary
A 2×3 grid of severity counts (Total, Critical, High, Medium, Low, Info). Numbers update in real time as analysis completes.

#### Findings & Remediation
This section lists every security finding as a clickable card:

1. **Collapsed view** — Each card shows:
   - **Severity badge** (colored: red/CRITICAL, orange/HIGH, gold/MEDIUM, blue/LOW, gray/INFO)
   - **Finding title** (e.g., "Running Ubuntu VM with USB Passthrough Enabled")
   - **CVSS score**
   - **Execute button** — green button to run the fix immediately
   - **Expand chevron** (▼) — click to expand

2. **Expanded view** — Click a card to reveal full details:
   - **Description** — what the vulnerability is and what an attacker could do
   - **Attack Scenario** — a realistic 1-2 sentence attack narrative (orange italic)
   - **Remediation** — step-by-step hardening instructions (green)
   - **References** — security advisory links
   - **Execute Fix button** — at the bottom of the expanded body

#### Running a Fix

1. Click **Execute** (or **Execute Fix** in the expanded body) on any finding
2. The button immediately changes to amber pulsing **"Running..."** and becomes disabled
3. In the log panel, the `🔧 Remediator` agent streams:
   - Its thinking about what needs to be done
   - The exact VBoxManage commands it derived (from Claude)
   - The raw command output (grouped under each command)
   - A success `✓` or failure `✗` summary per step
4. When complete, the button updates to:
   - **`✓ Fixed`** (green, disabled) — all steps succeeded
   - **`✗ Failed`** (red, disabled) — one or more steps failed
5. A **Remediation Activity** section appears below Downloads in the sidebar, showing a history of all fix attempts with their status

#### Download Reports

After an audit completes, the Download section appears with three report formats:
- **PDF** — Portable document with cover page, executive summary, findings overview, detailed findings, and conclusion
- **HTML** — Browser-viewable report with styled tables and severity badges
- **JSON** — Machine-readable data for integration with other tools

Click any button to download the corresponding report file.

### Starting a New Audit

Click **Execute Audit** again at any time. This clears all previous findings and remediation history, resets the phase indicators, adds a separator in the log, and starts a fresh audit from scratch.

### Tips

- **Scroll through the log** during an audit to watch each agent's reasoning in real time. The detailed thinking messages explain the security rationale behind every check.
- **Expand multiple findings** at once to compare their details side by side.
- **Run fixes one at a time** — each remediation runs in its own thread and the button tracks its individual status.
- **Download reports after audit** — the PDF report has a professional format suitable for sharing with stakeholders.
