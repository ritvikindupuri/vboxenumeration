import re

from agents.base_agent import BaseAgent
from core.network_scanner import NetworkScanner
from core.vbox_controller import VBoxController


class EnumeratorAgent(BaseAgent):
    def __init__(self):
        super().__init__("enumerator")
        self.vbox = VBoxController()

    def run(self, context: dict) -> dict:
        self.emit_thinking("Initializing attack surface enumeration — scanning VirtualBox environment to identify all potential attacker footholds, including registered VMs, network configurations, host settings, and media attachments")
        data = {}

        data["vms"] = self._enum_vms()
        data["running_vms"] = self._enum_running_vms()
        data["vm_details"] = self._enum_vm_details(data["vms"])
        data["network"] = self._enum_network()
        data["active_scan"] = self._active_network_scan(data.get("network", {}))
        data["host"] = self._enum_host()
        data["media"] = self._enum_media()

        self.emit_result({"status": "complete", "vm_count": len(data["vms"])})
        return data

    def _enum_vms(self):
        self.emit_thinking("Enumerating all VM registrations — discovering every virtual machine registered with VirtualBox, including powered-off VMs that could contain sensitive data, credentials, or be booted as lateral movement targets")
        self.emit_command("VBoxManage list vms")
        vms = self.vbox.list_vms()
        self.emit_output(f"Discovered {len(vms)} VM(s): {', '.join(v['name'] for v in vms)}")
        return vms

    def _enum_running_vms(self):
        self.emit_thinking("Identifying running VMs — these are live, active targets that present immediate attack surface and may have network connectivity, open ports, or active user sessions")
        self.emit_command("VBoxManage list runningvms")
        running = self.vbox.list_running_vms()
        names = [v["name"] for v in running]
        self.emit_output(f"Running ({len(running)}): {', '.join(names) if names else 'none'}")
        return names

    def _enum_vm_details(self, vms):
        self.emit_thinking("Performing deep-dive enumeration of each VM — extracting machine-readable config for automated analysis and human-readable output for manual review of attacker-relevant attributes: VRDE, clipboard, drag-and-drop, USB, audio, encryption, TPM, firmware, serial ports, and 3D acceleration")
        details = []
        for vm in vms:
            name = vm["name"]
            self.emit_thinking(f"Probing VM: {name} — extracting full configuration to identify insecure settings that could serve as attacker footholds or data exfiltration channels")
            self.emit_command(f"VBoxManage showvminfo \"{name}\" --machinereadable")
            raw = self.vbox.show_vm_info(name)
            self.emit_command(f"VBoxManage showvminfo \"{name}\"")
            raw_human = self.vbox.show_vm_info(name, machinereadable=False)

            parsed = self._parse_vm_machine_readable(raw)

            snapshots = self._enum_snapshots(name)
            shared = self._enum_shared_folders(name)
            guestprops = self._enum_guestprops(name)

            vm_data = {
                "name": name,
                "uuid": vm["uuid"],
                "raw_machine_readable": raw,
                "raw_human": raw_human,
                "parsed": parsed,
                "snapshots": snapshots,
                "shared_folders": shared,
                "guest_properties": guestprops,
            }
            details.append(vm_data)
            self._emit_attacker_flags(parsed, name)
        self.emit_output(f"Completed deep enumeration of {len(details)} VM(s)")
        return details

    def _parse_vm_machine_readable(self, raw: str) -> dict:
        parsed = {}
        for line in raw.splitlines():
            if "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"')
            parsed[key] = val
        return parsed

    def _emit_attacker_flags(self, p: dict, name: str):
        flags = []

        if p.get("vrde", "").lower() == "on":
            flags.append(f"[!] VRDE/remote desktop ENABLED — potential RDP attack surface")
        if p.get("clipboard", "").lower() != "disabled":
            flags.append(f"[!] Clipboard mode: {p.get('clipboard','?')} — clipboard hijacking risk")
        if p.get("draganddrop", "").lower() != "disabled":
            flags.append(f"[!] Drag'n'drop mode: {p.get('draganddrop','?')} — file exfiltration vector")
        if p.get("audio", "").lower() == "on":
            flags.append(f"[!] Audio enabled — covert channel / audio exfiltration risk")
        if p.get("usb", "").lower() == "on":
            flags.append(f"[!] USB controller enabled — rubber ducky / BadUSB attack surface")
        if p.get("accelerate3d", "").lower() == "on":
            flags.append(f"[!] 3D acceleration enabled — potential GPU escape vector")
        if p.get("serial", "").lower() != "none":
            flags.append(f"[!] Serial port configured — potential serial console access")
        if p.get("guest_additions", "").lower() not in ("", "none"):
            flags.append(f"[i] Guest Additions installed — bidirectional host/guest channel")
        if p.get("encryption", "").lower() not in ("", "none", "disabled"):
            flags.append(f"[+] Disk encryption: {p.get('encryption','?')}")
        else:
            flags.append(f"[!] Disk NOT encrypted — data at rest exposure risk")
        if p.get("tpm", "").lower() not in ("", "none", "disabled"):
            flags.append(f"[+] TPM detected: {p.get('tpm','?')}")
        if p.get("firmware", "").lower() == "efi":
            flags.append(f"[i] Firmware: EFI (secure boot: {p.get('secureboot','?')})")
        if p.get("nic3", ""):
            flags.append(f"[i] 3+ network adapters — expanded network attack surface")

        if flags:
            self.emit_output(f"VM '{name}' flags:\n  " + "\n  ".join(flags))

    def _enum_snapshots(self, name: str):
        self.emit_thinking(f"Checking snapshots for '{name}' — snapshots can contain sensitive data, credentials, or vulnerable software versions that an attacker could revert to or extract data from")
        self.emit_command(f"VBoxManage snapshot \"{name}\" list --machinereadable")
        raw = self.vbox.list_snapshots(name)
        if raw:
            self.emit_output(f"Snapshots found for {name}")
        return raw

    def _enum_shared_folders(self, name: str):
        self.emit_thinking(f"Checking shared folders on '{name}' — shared folders create bidirectional host-guest filesystem access, which can be exploited for data exfiltration, malware staging, or privilege escalation across the host/guest boundary")
        self.emit_command(f"VBoxManage sharedfolder list \"{name}\"")
        raw = self.vbox.sharedfolder_list(name)
        if raw:
            self.emit_output(f"[!] Shared folder(s) on {name}: {raw[:300]}")
        return raw

    def _enum_guestprops(self, name: str):
        self.emit_thinking(f"Dumping guest properties on '{name}' — guest properties can leak sensitive information about the guest OS, including logged-in users, network configuration, installed software, and last boot time, aiding attacker reconnaissance")
        self.emit_command(f"VBoxManage guestproperty enumerate \"{name}\"")
        raw = self.vbox.enumerate_guestprops(name)
        lines = [l for l in raw.splitlines() if l.strip()]
        if lines:
            self.emit_output(f"Guest properties ({len(lines)} keys) for {name}")
        return raw

    def _enum_network(self):
        self.emit_thinking("Mapping VirtualBox network attack surface — enumerating every network interface type that could expose VMs to unauthorized access, lateral movement, or data exfiltration: host-only, bridged, NAT, DHCP, and internal networks")
        net = {}

        self.emit_thinking("Enumerating host-only networks — these isolated segments can be exploited for covert communication between VMs and the host, bypassing network monitoring tools on the primary interface")
        self.emit_command("VBoxManage list hostonlyifs")
        hostonly = self.vbox.list_hostonlyifs()
        self._check_hostonly_dhcp(hostonly)
        net["hostonly"] = hostonly

        self.emit_thinking("Enumerating bridged adapters — bridged mode places VMs directly on the physical LAN, giving them unrestricted network access that bypasses host firewall controls and exposes them to the same attacks as any physical machine on the network")
        self.emit_command("VBoxManage list bridgedifs")
        bridged = self.vbox.list_bridgedifs()
        if bridged.strip():
            self.emit_output(f"[!] Bridged networking detected — VMs have direct LAN access")
        net["bridged"] = bridged

        self.emit_thinking("Enumerating NAT networks — checking for port forwarding rules that could expose internal VM services to external networks, creating unintended ingress points into the virtualized environment")
        self.emit_command("VBoxManage list natnets")
        natnets = self.vbox.list_natnets()
        self._check_nat_port_forwards(natnets)
        net["natnets"] = natnets

        self.emit_thinking("Enumerating DHCP servers — active DHCP servers on host-only or internal networks can automatically assign IP addresses to unauthorized VMs, enabling unmanaged devices to join the virtual network")
        self.emit_command("VBoxManage list dhcpservers")
        dhcp = self.vbox.list_dhcpservers()
        net["dhcp"] = dhcp

        self.emit_thinking("Enumerating internal networks — these VM-to-VM networks are invisible to host monitoring tools and can provide attackers with a stealthy communication channel between compromised VMs")
        self.emit_command("VBoxManage list intnets")
        intnets = self.vbox.list_intnets()
        net["intnets"] = intnets

        net["all_raw"] = self.vbox.get_network_info()
        return net

    def _check_hostonly_dhcp(self, hostonly: str):
        if "DHCP:" in hostonly:
            for line in hostonly.splitlines():
                if "DHCP" in line and "Disabled" in line:
                    continue
                if "DHCP" in line and "Enabled" in line:
                    self.emit_output(f"[!] Host-only DHCP is enabled — VMs can auto-join")

    def _check_nat_port_forwards(self, natnets: str):
        if "Forwarding" in natnets or "forward" in natnets.lower():
            self.emit_output(f"[!] NAT port forwarding rules detected — exposed host ports")

    def _active_network_scan(self, network_data: dict) -> dict:
        self.emit_thinking("Initiating active network reconnaissance — performing ping sweeps and port scans on discovered VirtualBox networks to identify live hosts, open ports, and running services; this mirrors the initial recon phase of a real adversarial engagement")
        hostonly_output = network_data.get("hostonly", "")
        if not hostonly_output.strip():
            self.emit_output("No host-only networks found — skipping active scan")
            return {"status": "skipped", "hosts": []}

        scanner = NetworkScanner()
        subnets = scanner.extract_subnets(hostonly_output)
        if not subnets:
            self.emit_output("Could not extract subnet from host-only network config")
            return {"status": "skipped", "hosts": []}

        self.emit_thinking(f"Identified target subnet(s): {', '.join(subnets)} — launching ping sweep to discover live hosts")
        self.emit_command(f"powershell Test-Connection -Count 1 (sweeping {', '.join(subnets)})")

        found_hosts = []
        for subnet in subnets:
            self.emit_thinking(f"Scanning {subnet} for live hosts with active ICMP probes and TCP port sweeps")
            hosts = scanner.discover_hosts(subnet)
            if not hosts:
                self.emit_output(f"No live hosts detected on {subnet}")
                continue
            self.emit_output(f"Discovered {len(hosts)} live host(s) on {subnet}: {', '.join(hosts)}")

            for ip in hosts:
                self.emit_thinking(f"Probing {ip} — performing TCP port scan on 30+ common ports (SSH, RDP, HTTP, SMB, VNC, VRDP, databases, containers)")
                self.emit_command(f"socket.connect(({ip}, port)) — scanning 30 ports")
                ports = scanner.port_scan(ip)
                open_count = len(ports)
                if open_count > 0:
                    svc_list = ", ".join([f"{p['port']}/{p['service']}" for p in ports[:6]])
                    if len(ports) > 6:
                        svc_list += f" +{len(ports)-6} more"
                    self.emit_output(f"[!] {ip}: {open_count} open port(s) — {svc_list}")
                    for p in ports:
                        if p["banner"]:
                            self.emit_output(f"    Port {p['port']} ({p['service']}): {p['banner'][:150]}")
                else:
                    self.emit_output(f"{ip}: 0 open ports on common targets")

                found_hosts.append({"ip": ip, "open_ports": ports})

        total_open = sum(len(h["open_ports"]) for h in found_hosts)
        self.emit_thinking(f"Active reconnaissance complete — discovered {len(found_hosts)} live host(s) with {total_open} open service port(s) across {len(subnets)} network(s); this data will be incorporated into the adversarial risk analysis")
        return {"status": "complete", "subnets": subnets, "hosts": found_hosts}

    def _enum_host(self):
        self.emit_thinking("Profiling VirtualBox host attack surface — assessing host-level configuration that affects ALL VMs: OS version, system properties, extension pack versions, and USB device availability for passthrough attacks")
        host = {}

        self.emit_thinking("Extracting host OS and platform information — identifying the host operating system and hardware platform to assess which VM escape exploits or host-level attacks may be applicable")
        self.emit_command("VBoxManage list hostinfo")
        host["info"] = self.vbox.get_host_info()

        self.emit_thinking("Checking system properties — examining global VirtualBox settings that govern default VM behavior, including default networking mode, maximum VM memory, and folder sharing defaults that apply across all VMs")
        self.emit_command("VBoxManage list systemproperties")
        host["system_properties"] = self.vbox.list_systemproperties()

        self.emit_thinking("Checking extension packs — Oracle VM VirtualBox Extension Pack adds support for USB 2.0/3.0, VRDP, disk encryption, and NVMe; outdated extensions may contain known vulnerabilities exploitable for VM escape")
        self.emit_command("VBoxManage list extpacks")
        extpacks = self.vbox.list_extpacks()
        self._check_extpack_version(extpacks)
        host["extension_packs"] = extpacks

        self.emit_thinking("Checking USB host devices — enumerating USB devices attached to the host that could be passed through to VMs, enabling BadUSB attacks, keystroke injection, or data exfiltration via USB storage")
        self.emit_command("VBoxManage list usbhost")
        usb = self.vbox.list_usbhost()
        if usb.strip():
            self.emit_output(f"[!] USB host devices available for passthrough")
        host["usb_host"] = usb

        host["host_only_adapters"] = self.vbox.list_hostonlyifs()
        return host

    def _check_extpack_version(self, extpacks: str):
        for line in extpacks.splitlines():
            if "Version" in line and "Oracle VM VirtualBox Extension Pack" in extpacks:
                self.emit_output(f"[i] Extension pack detected: {line.strip()}")

    def _enum_media(self):
        self.emit_thinking("Enumerating mounted optical and media images — ISO and DVD images attached to VMs can contain bootable operating systems, live environments, or forensic tools that an attacker could use to bypass guest OS security controls")
        self.emit_command("VBoxManage list dvds")
        dvds = self.vbox.list_dvds()
        if dvds.strip():
            self.emit_output(f"Optical media found:\n{dvds[:400]}")
        return {"dvds": dvds}
