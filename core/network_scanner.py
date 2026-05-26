import concurrent.futures
import logging
import re
import socket
import subprocess

logger = logging.getLogger(__name__)

COMMON_PORTS = [
    22, 80, 443, 445, 3389, 5900, 5901, 8080, 8443, 18080, 18083,
    21, 23, 25, 53, 110, 135, 139, 143, 389, 993, 995, 1433, 1521,
    2049, 2375, 2376, 3306, 3388, 5432, 6379, 8081, 9090, 9200, 27017,
]

SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle DB", 2049: "NFS", 2375: "Docker",
    2376: "Docker TLS", 3306: "MySQL", 3389: "RDP", 3388: "RDP-Alt",
    5432: "PostgreSQL", 5900: "VNC", 5901: "VNC-1", 6379: "Redis",
    8080: "HTTP-Proxy", 8081: "HTTP-Alt", 8443: "HTTPS-Alt",
    9090: "HTTP-Alt2", 9200: "Elasticsearch", 18080: "VRDP",
    18083: "VRDP-Alt", 27017: "MongoDB",
}


class NetworkScanner:
    def ping_host(self, ip: str, timeout: int = 3) -> bool:
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"Test-Connection -ComputerName '{ip}' -Count 1 -Quiet -TimeToLive 64"],
                capture_output=True, text=True, timeout=timeout,
            )
            return "True" in r.stdout
        except Exception:
            return False

    def scan_port(self, ip: str, port: int, timeout: float = 1.5) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return s.connect_ex((ip, port)) == 0
        except Exception:
            return False

    def banner_grab(self, ip: str, port: int, timeout: float = 3) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))

                proto = "ssl" if port in (443, 8443, 990, 993, 995, 636) else "plain"
                if proto == "ssl":
                    import ssl
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    s = ctx.wrap_socket(s, server_hostname=ip)

                if port in (80, 8080, 443, 8443, 9090, 18080):
                    s.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: VBoxAuditor/1.0\r\n\r\n".encode())
                    banner = s.recv(2048).decode("utf-8", errors="replace").strip()
                elif port == 22:
                    banner = s.recv(1024).decode("utf-8", errors="replace").strip()
                elif port in (21, 23, 25, 110, 143):
                    banner = s.recv(1024).decode("utf-8", errors="replace").strip()
                elif port in (3306, 5432, 6379, 9200, 27017):
                    banner = s.recv(1024).decode("utf-8", errors="replace").strip()
                else:
                    s.sendall(b"\r\n")
                    banner = s.recv(1024).decode("utf-8", errors="replace").strip()

                return banner[:300]
        except Exception:
            return ""

    def discover_hosts(self, subnet: str) -> list[str]:
        try:
            import ipaddress
            net = ipaddress.IPv4Network(subnet, strict=False)
            hosts = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
                fut_map = {ex.submit(self.ping_host, str(ip)): str(ip) for ip in net.hosts()}
                for fut in concurrent.futures.as_completed(fut_map):
                    ip = fut_map[fut]
                    if fut.result():
                        hosts.append(ip)
            return sorted(hosts)
        except Exception as e:
            logger.warning(f"Host discovery failed for {subnet}: {e}")
            return []

    def port_scan(self, ip: str, ports: list[int] | None = None) -> list[dict]:
        if ports is None:
            ports = COMMON_PORTS
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            fut_map = {ex.submit(self.scan_port, ip, p): p for p in ports}
            for fut in concurrent.futures.as_completed(fut_map):
                p = fut_map[fut]
                if fut.result():
                    banner = self.banner_grab(ip, p)
                    svc = SERVICE_MAP.get(p, "Unknown")
                    fp = self.deep_fingerprint(ip, p, svc, banner)
                    results.append({
                        "port": p,
                        "service": svc,
                        "banner": banner,
                        "version": fp.get("version"),
                        "fingerprint": fp.get("extra", {}),
                        "secure": "HTTPS" in svc or "TLS" in svc or "VRDP" not in svc,
                    })
        return sorted(results, key=lambda x: x["port"])

    def deep_fingerprint(self, ip: str, port: int, service: str, banner: str) -> dict:
        result = {"ip": ip, "port": port, "service": service, "banner": banner, "version": None, "os": None, "extra": {}}

        if service in ("HTTP", "HTTP-Proxy", "HTTP-Alt", "HTTPS", "HTTPS-Alt"):
            import re as _re
            srv_match = _re.search(r"Server:\s*(.+)", banner, _re.IGNORECASE)
            if srv_match:
                result["extra"]["server"] = srv_match.group(1).strip()
            powered = _re.search(r"X-Powered-By:\s*(.+)", banner, _re.IGNORECASE)
            if powered:
                result["extra"]["powered_by"] = powered.group(1).strip()

        elif service == "SSH":
            import re as _re
            ssh_match = _re.match(r"SSH-\d+\.\d+-(.+)", banner)
            if ssh_match:
                result["extra"]["ssh_software"] = ssh_match.group(1)
            ver_match = _re.search(r"OpenSSH_(\d+\.\d+)", banner)
            if ver_match:
                result["version"] = ver_match.group(1)

        elif service in ("MySQL", "MariaDB"):
            import re as _re
            ver_match = _re.search(r"(\d+\.\d+\.\d+)", banner)
            if ver_match:
                result["version"] = ver_match.group(1)

        elif service == "PostgreSQL":
            import re as _re
            ver_match = _re.search(r"(\d+\.\d+)", banner)
            if ver_match:
                result["version"] = ver_match.group(1)

        elif service == "Redis":
            if "redis_version" in banner:
                import re as _re
                ver_match = _re.search(r"redis_version:(\d+\.\d+)", banner)
                if ver_match:
                    result["version"] = ver_match.group(1)

        return result

    def extract_subnets(self, hostonly_output: str) -> list[str]:
        subnets = []
        for m in re.finditer(r"IPAddress:\s*(\d+\.\d+\.\d+\.\d+)", hostonly_output):
            ip = m.group(1)
            parts = ip.split(".")
            subnets.append(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")
        return list(set(subnets))

    def scan_network(self, hostonly_output: str) -> dict:
        subnets = self.extract_subnets(hostonly_output)
        if not subnets:
            return {"status": "no_hostonly_networks", "hosts": []}

        all_hosts = []
        for subnet in subnets:
            hosts = self.discover_hosts(subnet)
            for ip in hosts:
                open_ports = self.port_scan(ip)
                all_hosts.append({"ip": ip, "subnet": subnet, "open_ports": open_ports})

        return {"status": "complete", "subnets": subnets, "hosts": all_hosts}
