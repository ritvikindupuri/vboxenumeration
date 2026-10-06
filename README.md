# VBoxAuditor

**VirtualBox Attack Surface Enumeration, Active Exploitation & Remediation Tool**

> **Full technical documentation available at [`TECHNICAL_DOCUMENTATION.md`](TECHNICAL_DOCUMENTATION.md)** — covers system architecture, detailed agent breakdowns, exploitation engine internals, WebSocket event system, report generation, and complete feature documentation.

VBoxAuditor is a red-team security auditing tool that automatically enumerates, analyzes, **actively exploits**, and remediates VirtualBox hypervisor misconfigurations. It deploys autonomous AI agents to scan your VirtualBox environment, identify security weaknesses, **prove compromise via real SSH post-exploitation**, and guide remediation — all through a real-time web dashboard with kill chain visualization.

---

## System Architecture

<div align="center">
  <img src="architecture.png" alt="VBoxAuditor Architecture" width="100%"/>
  <p><em>Figure 1: VBoxAuditor System Architecture — Component Layers &amp; Pipeline Data Flow</em></p>
</div>

### Flow-by-Flow Explanation

1. **User Dashboard ↔ Flask Backend** — The operator interacts with the web interface (`http://localhost:8080`) to launch audits, track real-time kill chain progress, inspect discovered vulnerabilities, or execute automated remediation. Audit commands are dispatched over HTTP, while execution logs and status events stream live to the browser via WebSocket (`flask-sock`).

2. **Flask Backend → Audit Engine** — When an audit is triggered, the Flask server spawns a background worker thread and initializes the sequential 4-stage `AuditEngine` pipeline (`Start Audit`).

3. **Stage 1: Enumeration (EnumeratorAgent ↔ VirtualBox Host)** — The Enumerator queries the local VirtualBox hypervisor using `VBoxManage.exe` commands (`list vms`, `showvminfo`, `list hostonlyifs`, snapshots, shared folders, VRDE settings). It then performs active network reconnaissance across host-only subnets (ping sweeps, TCP port scans, and service banner grabs) to map the complete target attack surface.

4. **Stage 2: AI Analysis (AnalyzerAgent ↔ Claude AI)** — The Analyzer submits the full enumeration dataset (VM configs, network topology, and open service banners) to Claude with a red-team prompt. Claude correlates CVEs, assigns CVSS risk scores, constructs attack chains, and produces a structured executive summary. Analysis results stream back to guide exploitation and update the Flask dashboard.

5. **Stage 3: Active Exploitation (ExploiterAgent ↔ Security Tools)** — The Exploiter executes an 8-phase automated attack cycle against discovered targets, leveraging local security tooling:
   - **Nmap (optional)** — Service version detection and deep NSE vulnerability scans.
   - **Paramiko (SSH)** — Tests 100+ default/weak credentials across 11 services (SSH, RDP, SMB, MySQL, Redis, etc.) and establishes live SSH root shells to prove compromise with real reconnaissance commands.

6. **Stage 4: Reporting (ReporterAgent → Audit Reports)** — The Reporter aggregates all findings, telemetry, and exploit shell evidence from the audit context. It generates three deliverables saved to disk under `data/`:
   - `data/vboxaudit_<timestamp>.json` — Complete raw findings and machine-readable data.
   - `data/vboxaudit_<timestamp>.html` — Interactive dashboard assessment report.
   - `data/vboxaudit_<timestamp>.pdf` — Formatted executive security audit report.

7. **Remediation Planning (Claude AI Integration)** — When an operator clicks **Execute Fix** on a finding in the dashboard, Claude analyzes the vulnerability and synthesizes a step-by-step remediation plan with precise `VBoxManage` hardening commands.

8. **Remediation Execution (RemediatorAgent ↔ VirtualBox Host → Dashboard)** — The Remediator Agent executes the confirmed `VBoxManage` fix commands directly against the VirtualBox environment. It validates execution output, ensures configuration changes take effect, and streams real-time status and logs over WebSocket back through Flask to the User Dashboard.


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

```mermaid
flowchart TB
    subgraph Header["Header Layer"]
        H["[V] VBoxAuditor &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; [● Ready] [▲ Execute]"]
    end

    subgraph Content["Dashboard Layout"]
        direction LR
        subgraph Main["Main Panel (left)"]
            direction TB
            Tabs["📋 Agent Activity Log &nbsp;&nbsp;|&nbsp;&nbsp; 🔧 Remediation"]
            Phases["[01 Enumerate] [02 Analyze] [03 Exploit] [04 Report]"]
            Log["(streaming entries)<br/>w/ agent badges,<br/>timestamps, thinking,<br/>commands, raw output,<br/>results"]
            Rem["<b>Remediation Tab (separate)</b><br/>Finding list → Execute Fix → Plan preview<br/>→ Apply → Live streaming output → Back"]
            Tabs --- Phases --- Log ~~~ Rem
        end

        subgraph Sidebar["Sidebar (right)"]
            direction TB
            S1["Preview Summary<br/>(hidden until first findings)"]
            S2["Kill Chain<br/>▼ Stage 1: Recon ✓<br/>▼ Stage 2: Access ✓<br/>▼ Stage 3: Movement ◇<br/>▼ Stage 4: PrivEsc ◇<br/>▼ Stage 5: Exfil ◇"]
            S3["Active Exploitation<br/>⚔ Targets · Vulns<br/>💀 Host Compromised"]
            S4["Findings Summary Grid<br/>Total | Critical | High | Med | Low | Info"]
            S5["Findings (expandable)<br/>▶ [HIGH] VRDE...<br/>▶ [CRIT] Creds..."]
            S6["Compromised Hosts 💀<br/>IP | user:pass | SHELL<br/>$ whoami ..."]
            S7["Download Reports<br/>(hidden until done)"]
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
    style Rem fill:#0c0c1a,stroke:#1e1e3a,color:#ffd740
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

- **Phase Indicators**: `01 Enumerate` · `02 Analyze` · `03 Exploit` · `04 Report` — each turns green when complete
- **Thinking entries** (gold border, `⟐`) — the agent explaining what it's about to do and why (e.g., "Fingerprinting SSH on 192.168.56.101:22 — extracting version from banner and cross-referencing CVE database")
- **Command entries** (cyan border, `$` monospace) — the exact command being run (VBoxManage, Python exploit probe, nmap, hydra, SSH). Raw output appears directly below in a dark monospace block.
- **Vulnerability entries** (red border) — `CONFIRMED` or `PROBED` badge with CVE ID, target, and probe output
- **Shell output entries** (green border) — live command results from compromised SSH sessions: `$ whoami` → `vagrant`, `$ hostname` → `vagrant-vm`, `$ ip addr` → network info
- **Finding entries** (green border) — severity badge, CVE, exploit PoC, attack chain, remediation
- **Summary entries** (purple border) — analysis summary with severity breakdown, attack vectors, overall risk
- **Compromise entries** — rendered in the sidebar panel with structured card display

Agent badges: `🔍 Enumerator` · `🧠 Analyzer` · `⚔ Exploiter` · `📊 Reporter` · `🔧 Remediator` · `⚙️ System`

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
PDF / HTML / JSON — appear after audit completes. If you want to view a sample report, you can view the [Sample Security Report](#sample-report-virtualbox-attack-surface-audit) section below.

### Running a Fix
Switch to the **🔧 Remediation** tab and click **Execute Fix** on any finding. The `🔧 Remediator` agent first generates a plan (sends the finding to Claude to convert to VBoxManage commands) and shows a preview with each command. Click **Apply** to execute — streams thinking → commands → raw output → results in real time. Button updates to `✓ Fixed` or `✗ Failed`. Click `← Back to findings list` to return.

### Tips
- nmap and hydra are auto-detected — if found, they fire silently when hosts need scanning (you'll see `$ nmap -sV...` commands and output in the log). No "detected at" announcements. If neither is found, CVE matching and credential spraying still work using **built-in Python probes** — `socket`-level service checkers and a local CVE database. The only difference is you won't get nmap's enhanced version fingerprinting or hydra's wordlist brute-forcing.
- Watch the kill chain turn from `potential` → `confirmed` as the exploiter finds evidence
- Compromised Hosts panel proves actual access — you see real `whoami`/`hostname` output
- Run fixes one at a time — each has independent button state tracking

---

## Sample Report: VirtualBox Attack Surface Audit

**VBoxAuditor VirtualBox Attack Surface Audit Report** · Generated: 2026-05-29T11:35:44

### Executive Summary

#### Attack Surface Overview
The VirtualBox environment presents a HIGH risk security posture with 5 significant findings, including 1 high-severity and 2 medium-severity vulnerabilities. The most critical weakness is the complete lack of disk encryption across all VMs, creating a direct path to sensitive data extraction.

#### Key Attack Paths
* **VM Disk Encryption Disabled:** Direct host-level access to unencrypted VM disks allows credential extraction and data theft without VM compromise.
* **USB Device Passthrough Enabled:** Ubuntu VM can access host USB devices, enabling data exfiltration and covert communication channels.
* **Host-Only Network DHCP Server Exposed:** Large DHCP range enables network reconnaissance and man-in-the-middle attacks between VMs.
* **No VM Snapshots:** Absence of recovery snapshots extends attacker dwell time and complicates incident response.

#### Real-World Impact
A successful attacker could extract Windows credentials and sensitive data directly from unencrypted VM disks, establish persistent access across multiple VMs through network-based attacks, and maintain long-term presence due to limited recovery options. The combination of these vulnerabilities creates multiple paths for data exfiltration and lateral movement.

#### Remediation Priorities
* Enable VM disk encryption immediately on all VMs to prevent direct data access.
* Disable USB passthrough on ubuntu VM unless specifically required for business operations.
* Reduce DHCP server IP range and implement network segmentation between VMs.
* Create baseline snapshots for all VMs to enable rapid incident response.
* Implement comprehensive USB device access controls and monitoring.

### Findings Overview

| Severity | Count |
|----------|-------|
| **Critical** | 0 |
| **High** | 1 |
| **Medium** | 2 |
| **Low** | 2 |
| **Info** | 0 |
| **Total** | **5** |

### Detailed Findings

| ID | Severity | Title | CVSS | Component | Description | Attack Scenario | Remediation | References |
|----|----------|-------|------|-----------|-------------|-----------------|-------------|------------|
| **VBOX-001** | HIGH | VM Disk Encryption Disabled on Running VMs | 7.5 | Windows VM, ubuntu VM | Both running VMs (Windows VM and ubuntu) have disk encryption disabled, storing all VM data in plaintext on the host filesystem. An attacker with host access can directly mount and read VM disk files (.vdi/.vmdk) to extract sensitive data, credentials, and configuration without needing VM access. This bypasses all guest OS security controls and provides immediate access to all VM contents including registry hives, password databases, and user files. | An attacker gains access to the VirtualBox host system through phishing or privilege escalation. They navigate to the VM storage directory and locate the .vdi disk files. Using tools like qemu-nbd or VBoxManage, they mount the unencrypted VM disks directly to the host filesystem. The attacker can then extract Windows SAM/SYSTEM hives, Linux shadow files, SSH keys, browser passwords, and application data without ever powering on the VMs or dealing with guest OS authentication. | 1. Power off VMs: `VBoxManage controlvm "Windows VM" poweroff`<br>2. Enable encryption: `VBoxManage encryptmedium "Windows VM" --newpassword="strong_password" --cipher="AES-XTS256-PLAIN64"`<br>3. Repeat for ubuntu VM<br>4. Store encryption passwords in secure key management system<br>5. Implement host-level disk encryption as additional layer | [VirtualBox Manual: Disk Encryption](https://www.virtualbox.org/manual/ch09.html#diskencryption)<br>[MITRE ATT&CK T1005](https://attack.mitre.org/techniques/T1005/)<br>[Impacket secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) |
| **VBOX-002** | MEDIUM | USB Device Passthrough Enabled on Ubuntu VM | 6.5 | ubuntu VM | The ubuntu VM has USB device passthrough enabled, allowing the VM to access host USB devices directly. An attacker who compromises the ubuntu VM can access connected USB devices including storage devices, hardware tokens, and input devices. This creates a bridge between the VM and host hardware that can be exploited for data exfiltration, keylogging, or accessing encrypted storage devices that should be isolated from the VM environment. | An attacker compromises the ubuntu VM through a web application vulnerability or SSH brute force attack. Once inside the VM, they discover USB passthrough is enabled and can see host USB devices via lsusb. The attacker writes a script to monitor for USB storage devices and automatically copies sensitive data when devices are connected. They can also access hardware security tokens or USB-based authentication devices, potentially bypassing multi-factor authentication systems intended to protect the host. | 1. Power off ubuntu VM: `VBoxManage controlvm "ubuntu" poweroff`<br>2. Disable USB controller: `VBoxManage modifyvm "ubuntu" --usb off`<br>3. If USB access is required, use specific device filters instead of blanket access<br>4. Monitor USB device access logs<br>5. Implement USB device whitelisting on host | [VirtualBox Manual: USB Settings](https://www.virtualbox.org/manual/ch03.html#settings-usb)<br>[MITRE ATT&CK T1052](https://attack.mitre.org/techniques/T1052/)<br>[MITRE ATT&CK T1200](https://attack.mitre.org/techniques/T1200/) |
| **VBOX-003** | MEDIUM | Host-Only Network DHCP Server Exposed | 5.8 | VirtualBox Host-Only Network | The VirtualBox host-only network has an active DHCP server running on 192.168.56.100 with a large IP range (192.168.56.101-254). An attacker who gains access to any VM on this network can perform DHCP spoofing attacks, intercept network traffic, or conduct man-in-the-middle attacks against other VMs. The DHCP server also reveals network topology information and can be used to identify and target other VMs on the same host-only network segment. | An attacker compromises one VM on the host-only network and discovers the DHCP server configuration. They set up a rogue DHCP server with a higher priority to intercept DHCP requests from other VMs. When VMs request IP addresses, the attacker's DHCP server responds with malicious DNS servers and gateway configurations. This allows the attacker to intercept all network traffic between VMs, capture credentials, and perform man-in-the-middle attacks on inter-VM communications. | 1. Disable DHCP if not needed: `VBoxManage dhcpserver remove --netname "HostInterfaceNetworking-VirtualBox Host-Only Ethernet Adapter"`<br>2. If DHCP required, reduce IP range: `VBoxManage dhcpserver modify --netname "HostInterfaceNetworking-VirtualBox Host-Only Ethernet Adapter" --lowerip 192.168.56.101 --upperip 192.168.56.110`<br>3. Configure static IPs for VMs instead<br>4. Implement network segmentation between VMs<br>5. Monitor DHCP logs for suspicious activity | [MITRE ATT&CK T1557](https://attack.mitre.org/techniques/T1557/)<br>[VirtualBox Manual: Host-Only Network](https://www.virtualbox.org/manual/ch06.html#network_hostonly)<br>[RFC 2131: DHCP](https://tools.ietf.org/html/rfc2131) |
| **VBOX-004** | LOW | No VM Snapshots for Incident Response | 3.1 | All VMs | All VMs have zero snapshots configured, eliminating the ability to quickly restore to a known-good state after compromise. This significantly increases recovery time and forensic analysis difficulty during security incidents. Without snapshots, any malware persistence, configuration changes, or data corruption requires full VM rebuilds rather than simple rollbacks, extending attacker dwell time and impact. | An attacker successfully compromises the Windows VM and establishes persistence through registry modifications, scheduled tasks, and malware installation. The security team detects the compromise but realizes there are no clean snapshots available for quick restoration. Instead of a 5-minute snapshot rollback, the team must spend hours rebuilding the VM from scratch, during which time the attacker maintains access and continues lateral movement activities. The extended recovery time allows the attacker to achieve their objectives and cover their tracks. | 1. Create baseline snapshots: `VBoxManage snapshot "Windows VM" take "Clean_Baseline" --description "Pre-production clean state"`<br>2. Implement automated snapshot scheduling before major changes<br>3. Create snapshots before software installations or updates<br>4. Establish snapshot retention policy (keep 3-5 recent snapshots)<br>5. Test snapshot restoration procedures regularly<br>6. Document snapshot naming conventions | [VirtualBox Manual: Snapshots](https://www.virtualbox.org/manual/ch01.html#snapshots)<br>[MITRE ATT&CK T1053](https://attack.mitre.org/techniques/T1053/)<br>[SANS Incident Response](https://www.sans.org/white-papers/33901/) |
| **VBOX-005** | LOW | Intel USB Controller Device Exposed to Host | 4.3 | Host USB Controller, ubuntu VM | An Intel USB controller device (VendorId: 0x8087, ProductId: 0x0033) is connected to the host and potentially accessible to VMs with USB passthrough enabled. This Intel wireless/Bluetooth controller could be leveraged by an attacker in a compromised VM to perform wireless attacks, intercept Bluetooth communications, or establish covert communication channels that bypass network monitoring. | An attacker compromises the ubuntu VM which has USB passthrough enabled. They discover the Intel USB controller and realize it's a wireless/Bluetooth adapter. The attacker loads wireless drivers in the VM and uses the adapter to scan for nearby wireless networks, potentially discovering hidden SSIDs or performing evil twin attacks. They could also intercept Bluetooth communications from nearby devices or establish a covert wireless communication channel that bypasses the host's network monitoring and firewall rules. | 1. Disable USB passthrough on all VMs unless specifically required<br>2. Use USB device filters to restrict access to specific devices only<br>3. Monitor USB device access logs<br>4. Physically disconnect unnecessary USB devices<br>5. Implement USB device whitelisting policies<br>6. Consider using USB/IP for controlled remote USB access | [MITRE ATT&CK T1200](https://attack.mitre.org/techniques/T1200/)<br>[VirtualBox Manual: USB Settings](https://www.virtualbox.org/manual/ch03.html#settings-usb) |
