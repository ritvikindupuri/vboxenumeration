import logging
import os
import shutil
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)

TOOL_CACHE: dict = {}


def find_tool(name: str) -> Optional[str]:
    if name in TOOL_CACHE:
        return TOOL_CACHE[name]
    path = shutil.which(name)
    if path:
        logger.info(f"Detected external tool: {name} at {path}")
        TOOL_CACHE[name] = path
        return path
    common_paths = {
        "nmap": [r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"],
        "hydra": [r"C:\Program Files\THC-Hydra\hydra.exe", r"C:\Tools\hydra\hydra.exe"],
    }
    for candidate in common_paths.get(name, []):
        if os.path.isfile(candidate):
            logger.info(f"Detected external tool: {name} at {candidate}")
            TOOL_CACHE[name] = candidate
            return candidate
    TOOL_CACHE[name] = None
    return None


def detect_available_tools() -> dict:
    return {
        "nmap": find_tool("nmap") is not None,
        "nmap_path": find_tool("nmap"),
        "hydra": find_tool("hydra") is not None,
        "hydra_path": find_tool("hydra"),
    }


def run_nmap_version_scan(ip: str, ports: list[int]) -> Optional[dict]:
    nmap_path = find_tool("nmap")
    if not nmap_path:
        return None

    port_str = ",".join(str(p) for p in ports)
    cmd = [nmap_path, "-sV", "-sC", "--version-intensity", "5", "-p", port_str, ip]
    logger.info(f"Running nmap: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = result.stdout + result.stderr
        return {
            "tool": "nmap",
            "command": " ".join(cmd),
            "returncode": result.returncode,
            "output": output,
            "truncated": len(output) > 3000,
            "raw": output[:3000],
        }
    except subprocess.TimeoutExpired:
        return {"tool": "nmap", "error": "TIMEOUT after 120s", "raw": ""}
    except Exception as e:
        logger.warning(f"nmap failed: {e}")
        return {"tool": "nmap", "error": str(e)[:200], "raw": ""}


def run_hydra_bruteforce(ip: str, port: int, service: str, username: str, password: str, extra: str = "") -> Optional[dict]:
    hydra_path = find_tool("hydra")
    if not hydra_path:
        return None

    svc_map = {"ssh": "ssh", "rdp": "rdp", "smb": "smb", "mysql": "mysql", "postgresql": "postgresql", "ftp": "ftp", "telnet": "telnet"}
    hydra_svc = svc_map.get(service.lower(), service.lower())

    cmd = [hydra_path, "-l", username, "-p", password, f"{ip}", hydra_svc, "-t", "4", "-w", "5"]
    if extra:
        cmd.extend(extra.split())

    logger.info(f"Running hydra: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout + result.stderr
        return {
            "tool": "hydra",
            "command": " ".join(cmd),
            "returncode": result.returncode,
            "output": output,
            "raw": output[:2000],
        }
    except subprocess.TimeoutExpired:
        return {"tool": "hydra", "error": "TIMEOUT", "raw": ""}
    except Exception as e:
        logger.warning(f"hydra failed: {e}")
        return {"tool": "hydra", "error": str(e)[:200], "raw": ""}


def run_hydra_wordlist(ip: str, port: int, service: str, user: str, wordlist_path: str) -> Optional[dict]:
    hydra_path = find_tool("hydra")
    if not hydra_path:
        return None

    cmd = [hydra_path, "-l", user, "-P", wordlist_path, f"{ip}", service, "-t", "4", "-w", "5"]
    logger.info(f"Running hydra wordlist: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = result.stdout + result.stderr
        return {"tool": "hydra", "command": " ".join(cmd), "returncode": result.returncode, "output": output, "raw": output[:2000]}
    except Exception as e:
        return {"tool": "hydra", "error": str(e)[:200], "raw": ""}
