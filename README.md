# VBoxAuditor

**VirtualBox Attack Surface Enumeration, Active Exploitation & Remediation Tool**

VBoxAuditor is a red-team security auditing tool that automatically enumerates, analyzes, **actively exploits**, and remediates VirtualBox hypervisor misconfigurations. It deploys autonomous AI agents to scan your VirtualBox environment, identify security weaknesses, **prove compromise via real SSH post-exploitation**, and guide remediation — all through a real-time web dashboard with kill chain visualization.

---

## System Architecture

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
        direction LR
        E[1. Enumerator Agent<br/>Discovers VMs, networks, host config]
        NS[NetworkScanner<br/>Ping sweep · Port scan<br/>Banner grab · Version fingerprint]
        Ctx[(Shared Context)]
        A[2. Analyzer Agent<br/>AI-powered security analysis]
        X[3. Exploiter Agent<br/>8-phase: CVE probes · VM escape<br/>Guest addons · Shared folders · MITM<br/>Cred spray · SSH post-exploitation]
        Rp[4. Reporter Agent<br/>JSON / HTML / PDF reports]
    end

    subgraph ExploitEngine["Exploitation Engine"]
        CVE[CVE Database<br/>25+ service→CVE mappings]
        Spray[Credential Sprayer<br/>100+ default creds, 11 services]
        PE[Post-Exploit Engine<br/>SSH compromise + cmd execution]
        Tools[Tool Integration<br/>nmap / hydra auto-detection]
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
    E -->|"internal: scan subnets"| NS
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
    X -->|"store compromised hosts + kill chain"| Ctx
    Ctx -->|"read all results"| Rp
    Rp -->|"write files"| FS
    E -->|"event stream"| Bcast
    A -->|"event stream"| Bcast
    X -->|"event stream"| Bcast
    Rp -->|"event stream"| Bcast
    Bcast -->|"real-time JSON: thinking, commands,<br/>vuln probes, shell output,<br/>compromise confirmations, kill chain"| Browser

    Browser -->|"cmd: remediate {finding}"| WS
    WS -->|"finding object"| Rm
    Rm -->|"convert remediation to commands"| Claude
    Claude -->|"VBoxManage command list"| Rm
    Rm -->|"execute fix"| VBox
    VBox -->|"command output"| Rm
    Rm -->|"event stream"| Bcast

    %% ── Color styling ──────────────────────────────────────
    style Browser fill:#111128,stroke:#1e1e3a,color:#d0d0e0
    style HTML fill:#111128,stroke:#1e1e3a,color:#d0d0e0
    style WS fill:#111128,stroke:#1e1e3a,color:#d0d0e0
    style Bcast fill:#111128,stroke:#1e1e3a,color:#d0d0e0
    style E fill:#ff6f3c,stroke:#ff6f3c,color:#000
    style NS fill:#ff6f3c,stroke:#ff6f3c,color:#000
    style Ctx fill:#1e1e3a,stroke:#606080,color:#d0d0e0
    style A fill:#00bcd4,stroke:#00bcd4,color:#000
    style X fill:#ff1744,stroke:#ff1744,color:#fff
    style Rp fill:#00e676,stroke:#00e676,color:#000
    style CVE fill:#ff1744,stroke:#ff1744,color:#fff
    style Spray fill:#ff1744,stroke:#ff1744,color:#fff
    style PE fill:#ff1744,stroke:#ff1744,color:#fff
    style Tools fill:#ff1744,stroke:#ff1744,color:#fff
    style Rm fill:#ffd740,stroke:#ffd740,color:#000
    style VBox fill:#1e1e3a,stroke:#1e1e3a,color:#d0d0e0
    style Claude fill:#1e1e3a,stroke:#1e1e3a,color:#d0d0e0
    style FS fill:#1e1e3a,stroke:#1e1e3a,color:#d0d0e0
```

### Flow-by-Flow Explanation

**1. Dashboard Load** — The user opens `http://localhost:8080`. Flask serves a single-page dashboard. The browser establishes a WebSocket connection.

**2. Execute Audit** — The user clicks **Execute Audit**. The server spawns a background `AuditEngine` thread. All 4 agents (Enumerator → Analyzer → Exploiter → Reporter) run sequentially, each streaming events in real time.

**3. Enumeration Phase** — `EnumeratorAgent` runs `VBoxManage.exe` commands: registered VMs (`list vms`), running VMs (`list runningvms`), deep VM configuration (`showvminfo` — VRDE, clipboard, drag-and-drop, USB, encryption, TPM, firmware, audio, 3D acceleration, guest additions, network adapters), snapshot listing, shared folders, guest properties, network topology (host-only, bridged, NAT, DHCP, internal networks), host profiling (OS, extension packs, USB devices, system properties), and mounted media. **Then performs active network reconnaissance** — ping sweeps host-only subnets, TCP port-scans 30+ common ports on every live host, and grabs service banners.

**4. Analysis Phase** — `AnalyzerAgent` sends all enumeration data (VM configs + active scan results + service banners + version fingerprints) to Claude with a red-team prompt. Claude returns structured findings with severity, CVSS, CVE IDs, exploit PoC commands, Metasploit module paths, attack chain narratives, and remediation steps.

**5. Exploitation Phase** — `ExploiterAgent` runs 8 sub-phases (each with proper **thinking → command → raw output → result** streaming):
   - **Phase 1 — CVE Probing** — Fingerprints each discovered service against a local database of 25+ service-version → CVE mappings (OpenSSH, Apache, nginx, MySQL, Samba, Redis, Docker, VirtualBox VRDP, etc.). Executes live Python socket-based exploit probes against each target — the actual Python command is displayed (`$ python -c "import socket; ..."`) followed by its raw socket output. If nmap is installed, runs `nmap -sV -sC` with full raw output displayed. If nmap is not installed, the agent extracts version numbers directly from the service banners already collected during the enumeration phase (the initial port scan already grabbed banners like `SSH-2.0-OpenSSH_7.6p1` or `Apache/2.4.49`), so you still get the same CVE matching — just without the extra detail nmap's NSE scripts would provide.
   - **Phase 2 — VM Config Attacks** — Per-VM audit of VRDP, clipboard, drag-and-drop, USB, audio, 3D acceleration, serial ports, guest additions with detailed attack technique descriptions for each finding.
   - **Phase 3 — VM Escape Detection** — Queries `VBoxManage --version` and cross-references the installed version against 14 known guest-to-host escape CVEs (CVE-2023-21991, CVE-2022-21489, CVE-2022-21303, CVE-2021-35544, etc.) with version range matching. Each match is emitted as a confirmed vulnerability.
   - **Phase 4 — Guest Addition Exploitation** — Runs `VBoxManage guestproperty enumerate` and `guestcontrol list` against VMs with Guest Additions, extracting OS details, user accounts, network config. Describes host-to-guest command execution and screenshot capture capabilities.
   - **Phase 5 — Shared Folder Abuse** — Audits shared folder configurations as bidirectional host-guest filesystem bridges for malware staging and data exfiltration.
   - **Phase 6 — Network MITM Simulation** — Runs `arp -a` and `route print` with raw output, describes ARP spoofing scenarios on host-only networks, identifies VM network segments for traffic interception.
   - **Phase 7 — Credential Spraying** — Tries 100+ default/weak credential pairs across 11 services (SSH, RDP, SMB, MySQL, PostgreSQL, Redis, Elasticsearch, MongoDB, MSSQL, Oracle, Telnet) using protocol-level authentication (paramiko for SSH, raw MySQL/Redis protocol, etc.). Each credential pair is displayed as a command entry, with results per service.
   - **Phase 8 — Post-Exploitation SSH** — For every discovered SSH credential, **actually connects** via paramiko and runs reconnaissance commands (`whoami`, `hostname`, `id`, `ipconfig`, `netstat -ano`, `tasklist`). Shows each command with `$` prefix. Streams every command and its raw output to the dashboard in real time. Emits a `compromise` event for each successful shell.

**6. Report Generation Phase** — `ReporterAgent` generates JSON, HTML, and PDF reports. Reports have a clean header with just the title ("VBoxAuditor") and generation date. The executive summary is rendered as structured markdown with bold section headers and bullet points for readability.

**7. Dashboard Results** — Shows executive summary (formatted with bold headers, bullet lists, and proper spacing), kill chain visualization, exploitation summary (probes, confirmed vulns, creds found, hosts compromised), findings grid with expandable cards, Compromised Hosts panel, and download links.

**8. Remediation** — User clicks **Execute Fix** on any finding. `RemediatorAgent` spawns in a background thread, sends the finding's remediation text to Claude to convert into `VBoxManage` commands, then executes each step while streaming thinking, commands, raw output, and results.

---

## What the Enumerator Checks

The `EnumeratorAgent` performs a comprehensive audit of every VirtualBox configuration surface that an attacker could exploit. Below is the full checklist.

### VM Inventory & State
| Check | VBoxManage Command | What It Looks For |
|-------|-------------------|-------------------|
| Registered VMs | `list vms` | All VM names + UUIDs — attack surface inventory |
| Running VMs | `list runningvms` | Currently active targets (live attack surface) |

### Per-VM Deep Configuration
| Check | What It Looks For | Attacker Relevance |
|-------|-------------------|--------------------|
| **VRDE** | Is remote desktop enabled? | Direct RDP/VRDP access to guest OS |
| **Clipboard** | bidirectional / hosttoguest? | Clipboard hijacking, cross-VM data theft |
| **Drag & Drop** | bidirectional / hosttoguest? | File exfiltration, malware staging |
| **USB** | USB controller enabled? | BadUSB attacks, keystroke injection, device passthrough |
| **Audio** | Audio adapter enabled? | Covert channel, audio exfiltration |
| **3D Acceleration** | 3D enabled? | Potential GPU escape vector |
| **Serial Ports** | Serial port configured? | Serial console access |
| **Disk Encryption** | Encryption enabled? | Data-at-rest exposure if missing |
| **TPM** | TPM present? | Hardware security module detection |
| **Firmware** | EFI or BIOS? Secure boot? | Boot integrity assessment |
| **Guest Additions** | Installed? | Bidirectional host/guest channel |
| **Network Adapters** | Count + types | Expanded network attack surface |
| **Snapshots** | Any snapshots exist? | Contains sensitive data/credentials to extract |
| **Shared Folders** | Host-guest mounts? | Bidirectional file access, exfil path |
| **Guest Properties** | OS, users, network info leaked? | Reconnaissance intelligence |

### Network Topology Mapping
| Check | VBoxManage Command | What It Detects |
|-------|-------------------|-----------------|
| Host-Only Networks | `list hostonlyifs` | Isolated segments — VM-to-VM attack surface |
| Bridged Adapters | `list bridgedifs` | Direct LAN access — bypasses host firewall |
| NAT Networks | `list natnets` | Port forwarding rules — exposed internal services |
| DHCP Servers | `list dhcpservers` | Auto-IP assignment — unauthorized VMs can join |
| Internal Networks | `list intnets` | Stealth VM-to-VM channels invisible to host |

### Host-Level Profiling
| Check | VBoxManage Command | Attacker Relevance |
|-------|-------------------|--------------------|
| OS + Platform Info | `list hostinfo` | Host fingerprinting for escape exploits |
| System Properties | `list systemproperties` | Default VM behavior settings |
| Extension Packs | `list extpacks` | Oracle Extension Pack version — known CVEs |
| USB Host Devices | `list usbhost` | Available passthrough devices |
| Host-Only Adapters | `list hostonlyifs` | Host IP on VM networks — pivot target |

### Active Network Reconnaissance (Real Scanning)
After passive enumeration, the Enumerator performs live network scanning:

| Phase | Technique | What It Discovers |
|-------|-----------|-------------------|
| **Subnet Extraction** | Parses `IPAddress` from host-only config | Target networks (e.g., `192.168.56.0/24`) |
| **Ping Sweep** | `powershell Test-Connection` (ICMP) | Live hosts on each subnet (30-thread parallel) |
| **Port Scan** | TCP `socket.connect()` | 30+ common ports per host (SSH, RDP, HTTP, SMB, VNC, VRDP, databases, containers) |
| **Banner Grab** | Protocol-specific probes | Service versions, HTTP server headers, SSH software, DBMS versions |
| **Deep Fingerprint** | Regex banner parsing | Version numbers, OS detection, HTTP `Server`/`X-Powered-By` headers |

All scan results are streamed to the dashboard in real time alongside the VBoxManage output, and fed to both the Analyzer (for AI risk assessment) and the Exploiter (for CVE matching and credential spraying).

---

## Tech Stack

| Category | Technology |
|----------|-----------|
| **Backend Framework** | Python 3.12+, Flask 3.x |
| **Real-Time Communication** | WebSocket via flask-sock |
| **AI Analysis** | Anthropic Claude API (Claude Sonnet 4) |
| **VirtualBox Control** | VBoxManage.exe CLI (subprocess) |
| **CVE Database** | Local Python dict — 25+ service-version → CVE mappings + 14 VirtualBox escape CVEs |
| **VM Escape Detection** | VBoxManage version cross-referenced against 14 known guest-to-host escape CVEs |
| **Guest Addition Exploitation** | VBoxManage guestproperty enumerate + guestcontrol list — host-to-guest pivot |
| **MITM Simulation** | ARP table + route table analysis — host-only network traffic interception |
| **SSH Post-Exploitation** | paramiko |
| **External Tool Detection** | nmap (`-sV -sC`, auto-detected — falls back to banner-based fingerprinting if absent) |
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
4. Click **Next** through all default options
5. If prompted about network interfaces, click **Yes** to allow
6. Wait for installation to complete and click **Finish**

Verify VirtualBox is installed:
```powershell
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" --version
```
You should see a version number like `7.0.x`.

### Optional: Install nmap

VBoxAuditor auto-detects nmap and uses it for enhanced version scanning (`-sV -sC`) during the exploitation phase — raw nmap output is streamed directly to the dashboard. If nmap is not installed, the agent still gets version numbers from the service banners already collected during the initial port scan (e.g., banners like `SSH-2.0-OpenSSH_7.6p1` or `Apache/2.4.49`), so CVE matching still works — you just won't get the extra detail from nmap's NSE scripts.

**Install nmap:**

1. Open a web browser and go to https://nmap.org/download.html
2. Under **Microsoft Windows**, click the **nmap-7.95-setup.exe** link (or latest version)
3. Once downloaded, run the installer
4. Click **Next** through all default options (agree to the license)
5. On the "Choose Components" screen, leave defaults checked — **Nmap Core** is required
6. On the "Install Npcap" screen, check **"Install Npcap in WinPcap API-compatible Mode"**
7. Click **Install** and wait for installation to complete
8. Click **Finish**

Verify nmap is installed:
```powershell
nmap --version
```
You should see `Nmap version 7.95` (or similar).

**Note:** If nmap is not installed, the exploiter agent still gets version numbers from the service banners already grabbed during the initial port scan (e.g., `SSH-2.0-OpenSSH_7.6p1`, `Apache/2.4.49`) — same CVE matching, just without nmap's deeper NSE script analysis.

### Step 3: Clone the Repository

```powershell
git clone https://github.com/ritvikindupuri/vboxenumeration.git
cd vboxenumeration
```

### Step 4: Set Up a Virtual Environment

```powershell
python -m venv venv
.\venv\Scripts\activate
```
You should see `(venv)` at the beginning of your terminal prompt.

### Step 5: Install Dependencies

```powershell
pip install -r requirements.txt
```

### Step 6: Configure Your API Key

1. Rename `.env.example` to `.env`:
   ```powershell
   Rename-Item .env.example .env
   ```
2. Open `.env` in Notepad:
   ```powershell
   notepad .env
   ```
3. Replace `sk-ant-xxxxxxxxxxxx` with your actual Anthropic API key:
   ```
   ANTHROPIC_API_KEY=sk-ant-your-real-api-key-here
   ```
4. Save and close

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

### Layout

```
┌─────────────────────────────────────────────────────────────┐
│  [◇] VBoxAuditor                     [● Ready] [▲ Execute]  │  ← Header
├──────────────────────────┬──────────────────────────────────┤
│                          │                                  │
│   📋 Agent Activity Log  │                                  │
│   🔧 Remediation         │     Preview Summary               │
│                          │     (hidden until first findings)  │
│   [01 Enumerate]         │                                  │
│   [02 Analyze]           │     Kill Chain                   │
│   [03 Exploit]           │     ▼ Stage 1: Recon ✓          │
│   [04 Report]            │     ▼ Stage 2: Access ✓         │
│                          │     ▼ Stage 3: Movement ◇       │
│   (streaming entries)    │     ▼ Stage 4: PrivEsc ◇       │
│   w/ agent badges,       │     ▼ Stage 5: Exfil ◇         │
│   timestamps, thinking,  │                                  │
│   commands, raw output,  │     Active Exploitation          │
│   results                │     ⚔ 4 Targets · 2 Vulns       │
│                          │     💀 1 Host Compromised        │
│                          │                                  │
│                          │     Findings Summary             │
│                          │     ┌───┬───┐                   │
│                          │     │Ttl│Cri│                   │
│                          │     ├───┼───┤                   │
│                          │     │Hi │Med│                   │
│                          │     ├───┼───┤                   │
│                          │     │Low│Inf│                   │
│                          │     └───┴───┘                   │
│                          │                                  │
│                          │     Findings                     │
│                          │     (click to expand)            │
│                          │     ┌──────────────────┐        │
│                          │     │[HIGH] VRDE...▶   │        │
│                          │     ├──────────────────┤        │
│                          │     │[CRIT] Creds...▶  │        │
│                          │     ├──────────────────┤        │
│                          │     │[MED] TPM...▶     │        │
│                          │     └──────────────────┘        │
│                          │                                  │
│                          │     Compromised Hosts 💀         │
│                          │     ┌──────────────────┐        │
│                          │     │💀 192.168.56.101 │        │
│                          │     │vagrant:vagrant   │SHELL   │
│                          │     │$ whoami vagrant  │        │
│                          │     │$ hostname vm-01  │        │
│                          │     └──────────────────┘        │
│                          │                                  │
│                          │     Download Reports              │
│                          │     (hidden until done)           │
├──────────────────────────┴──────────────────────────────────┤
│            🔧 Remediation Tab (separate tab)                 │
│            Finding list → Execute Fix → Plan preview         │
│            → Apply → Live streaming output → Back            │
└─────────────────────────────────────────────────────────────┘
```

### Header Elements

| Element | Description |
|---------|-------------|
| **Status Dot** | Dim gray = Ready, pulsing green = Running, cyan = Complete, red = Error |
| **Execute Audit** | Starts a full audit. Disabled while running |

### Main Panel — Tabs

The main panel has two tabs:

- **📋 Agent Activity Log** — Real-time streaming feed of everything the agents are doing (thinking, commands, raw VBoxManage output, results, findings, vulnerabilities, compromise events)
- **🔧 Remediation** — Separate tab showing findings list with severity and Execute Fix buttons. Clicking executes a two-phase flow: plan preview (generated by Claude from the finding's remediation text) → Apply button → live streaming of each VBoxManage command with raw output → final result with Back button.

#### Agent Activity Log Entries

Each log entry has an **agent badge** (colored label with icon), a **· separator**, and a **timestamp** header. Entries are color-coded by type:

| Entry Type | Left Border | Background | Icon | Description |
|-----------|-------------|------------|------|-------------|
| **Thinking** | Gold `#ffd740` | Subtle gold tint | `⟐` | Agent explaining what it's about to do and why |
| **Command** | Cyan `#00bcd4` | Subtle cyan tint | `$` | Exact command being run (monospace), raw output grouped directly beneath |
| **Output** | Cyan `#00bcd4` | Subtle cyan tint | — | Raw command output directly under the command, gold monospace text on dark background |
| **Result** | Green `#00e676` | Subtle green tint | `✓` | Structured result or completion summary |
| **Error** | Red `#ff1744` | Subtle red tint | `✗` | Error messages |
| **Finding** | Green `#00e676` | Subtle green tint | — | Security finding with severity badge, CVE, attack chain |
| **Summary Detail** | Gold `#ffd740` | Subtle gold tint | — | Analysis summary with severity breakdown and risk rating |

- **Phase Indicators**: `01 Enumerate` · `02 Analyze` · `03 Exploit` · `04 Report` — each turns green when complete
- **Shell output entries** (green border) — live command results from compromised SSH sessions: `$ whoami` → `vagrant`, `$ hostname` → `vagrant-vm`, `$ ip addr` → network info
- **Compromise entries** — rendered in the sidebar panel with structured card display

Agent badges: `🔍 Enumerator` (orange) · `🧠 Analyzer` (cyan) · `⚔ Exploiter` (red) · `📊 Reporter` (green) · `🔧 Remediator` (gold) · `⚙️ System` (purple)

### Sidebar (Right Side)

#### Kill Chain
A visual 5-stage attack path that updates in real time as the exploiter finds evidence:
- **Stage 1: Reconnaissance** — Network scanning results (always completed)
- **Stage 2: Initial Access** — Turns `confirmed` (red) when SSH credentials or VRDP exposure found, green `SHELL` when post-exploitation succeeds
- **Stage 3: Lateral Movement** — `potential` if multiple hosts found
- **Stage 4: Privilege Escalation** — `potential` if USB passthrough enabled
- **Stage 5: Data Exfiltration** — `potential` if clipboard/drag-and-drop/shared folders enabled
- Each node has a status badge: `completed` (green), `confirmed` (red), or `potential` (gold)

#### Active Exploitation
Summary card showing: Targets scanned, Services probed, CVE probes executed, Confirmed vulnerabilities, Credentials discovered, and Hosts compromised (💀 with green number).

#### Findings Summary
2×3 grid: Total, Critical, High, Medium, Low, Info. Updates in real time.

#### Findings
Expandable cards per finding. Collapsed view: severity badge, title, CVSS, expand chevron. Expanded view: description, attack scenario, exploit PoC, attack chain (formatted as numbered steps). Remediation is in the dedicated **🔧 Remediation** tab.

#### Compromised Hosts 💀
Appears when post-exploitation succeeds. Per host:
- 💀 IP:port + credentials used + **SHELL** badge (green)
- Hostname, user, OS info
- All command outputs with `$` prompt styling

#### Download Reports
PDF / HTML / JSON — appear after audit completes.

### Running a Fix
Switch to the **🔧 Remediation** tab and click **Execute Fix** on any finding. The `🔧 Remediator` agent first generates a plan (sends the finding to Claude to convert to VBoxManage commands) and shows a preview with each command. Click **Apply** to execute — streams thinking → commands → raw output → results in real time. Button updates to `✓ Fixed` or `✗ Failed`. Click `← Back to findings list` to return.

### Tips
- Install nmap and hydra for enhanced scanning (auto-detected)
- Watch the kill chain turn from `potential` → `confirmed` as the exploiter finds evidence
- Compromised Hosts panel proves actual access — you see real `whoami`/`hostname` output
- Run fixes one at a time — each has independent button state tracking
