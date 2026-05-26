import logging
import subprocess
import re
from typing import Optional

logger = logging.getLogger(__name__)

VBOX_EXE = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"


class VBoxController:
    def run(self, *args: str, timeout: int = 30) -> tuple[int, str]:
        try:
            result = subprocess.run(
                [VBOX_EXE, *args],
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding="utf-8",
                errors="replace",
            )
            output = result.stdout + result.stderr
            return result.returncode, output.strip()
        except subprocess.TimeoutExpired:
            return -1, f"TIMEOUT after {timeout}s"
        except FileNotFoundError:
            return -1, f"VBoxManage not found at {VBOX_EXE}"
        except Exception as e:
            return -1, str(e)

    def list_vms(self) -> list[dict]:
        code, out = self.run("list", "vms")
        if code != 0:
            return []
        vms = []
        for line in out.splitlines():
            m = re.match(r'"(.+)"\s+\{(.+)\}', line)
            if m:
                vms.append({"name": m.group(1), "uuid": m.group(2)})
        return vms

    def list_running_vms(self) -> list[dict]:
        code, out = self.run("list", "runningvms")
        if code != 0:
            return []
        vms = []
        for line in out.splitlines():
            m = re.match(r'"(.+)"\s+\{(.+)\}', line)
            if m:
                vms.append({"name": m.group(1), "uuid": m.group(2)})
        return vms

    def show_vm_info(self, vm: str, machinereadable: bool = True) -> str:
        if machinereadable:
            code, out = self.run("showvminfo", vm, "--machinereadable")
        else:
            code, out = self.run("showvminfo", vm)
        return out if code == 0 else ""

    def list_snapshots(self, vm: str) -> str:
        code, out = self.run("snapshot", vm, "list", "--machinereadable")
        return out if code == 0 else ""

    def sharedfolder_list(self, vm: str) -> str:
        code, out = self.run("sharedfolder", "list", vm)
        return out if code == 0 else ""

    def enumerate_guestprops(self, vm: str) -> str:
        code, out = self.run("guestproperty", "enumerate", vm)
        return out if code == 0 else ""

    def list_hostonlyifs(self) -> str:
        code, out = self.run("list", "hostonlyifs")
        return out if code == 0 else ""

    def list_bridgedifs(self) -> str:
        code, out = self.run("list", "bridgedifs")
        return out if code == 0 else ""

    def list_natnets(self) -> str:
        code, out = self.run("list", "natnets")
        return out if code == 0 else ""

    def list_dhcpservers(self) -> str:
        code, out = self.run("list", "dhcpservers")
        return out if code == 0 else ""

    def list_intnets(self) -> str:
        code, out = self.run("list", "intnets")
        return out if code == 0 else ""

    def list_systemproperties(self) -> str:
        code, out = self.run("list", "systemproperties")
        return out if code == 0 else ""

    def list_extpacks(self) -> str:
        code, out = self.run("list", "extpacks")
        return out if code == 0 else ""

    def list_usbhost(self) -> str:
        code, out = self.run("list", "usbhost")
        return out if code == 0 else ""

    def get_host_info(self) -> str:
        code, out = self.run("list", "hostinfo")
        return out if code == 0 else ""

    def list_dvds(self) -> str:
        code, out = self.run("list", "dvds")
        return out if code == 0 else ""

    def get_network_info(self) -> dict:
        return {
            "hostonly": self.list_hostonlyifs(),
            "bridged": self.list_bridgedifs(),
            "natnets": self.list_natnets(),
            "dhcp": self.list_dhcpservers(),
            "intnets": self.list_intnets(),
        }

    def enumerate_all_vms(self, vms: list[dict]) -> list[dict]:
        results = []
        for vm in vms:
            name = vm["name"]
            info = self.show_vm_info(name)
            snapshots = self.list_snapshots(name)
            shared = self.sharedfolder_list(name)
            guestprops = self.enumerate_guestprops(name)
            results.append({
                "name": name,
                "uuid": vm["uuid"],
                "info": info,
                "snapshots": snapshots,
                "shared_folders": shared,
                "guest_properties": guestprops,
            })
        return results
