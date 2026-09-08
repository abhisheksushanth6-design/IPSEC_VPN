"""VirtualBox hypervisor manager for Layer 01.

Provides safe, parameterized execution of VBoxManage commands without using
shell=True. Validates paths and inputs, handles timeouts, and extracts
structured VM, adapter, and state information.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# UUID pattern validation to ensure input safety
UUID_REGEX = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
# Safe VM name regex: alphanumerics, spaces, dashes, underscores, colons
SAFE_VM_NAME_REGEX = re.compile(r"^[\w\s\-:.]+$")


class VBoxManager:
    """Encapsulates safe VBoxManage CLI interactions."""

    def __init__(self, vboxmanage_path: Optional[str] = None) -> None:
        self.vboxmanage_path = self._resolve_vboxmanage(vboxmanage_path)

    @staticmethod
    def _resolve_vboxmanage(configured_path: Optional[str]) -> str:
        """Resolve the executable path to VBoxManage, verifying it exists."""
        if configured_path and os.path.isfile(configured_path):
            return str(Path(configured_path).resolve())
        
        # Check standard installation locations on Windows
        standard_windows_paths = [
            r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
            r"C:\Program Files (x86)\Oracle\VirtualBox\VBoxManage.exe",
        ]
        for p in standard_windows_paths:
            if os.path.isfile(p):
                return str(Path(p).resolve())

        # Check system PATH
        which_path = shutil.which("VBoxManage") or shutil.which("vboxmanage")
        if which_path:
            return str(Path(which_path).resolve())

        return configured_path or r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"

    @property
    def is_available(self) -> bool:
        """Return True if the VBoxManage executable exists on the filesystem."""
        return os.path.isfile(self.vboxmanage_path)

    def _run_command(self, args: list[str], timeout: float = 6.0) -> tuple[int, str, str]:
        """Execute a VBoxManage command safely with strict argument lists.
        
        NEVER uses shell=True. Always uses timeout.
        """
        if not self.is_available:
            return -1, "", f"VBoxManage executable not found at '{self.vboxmanage_path}'"

        full_cmd = [self.vboxmanage_path] + args
        try:
            res = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                shell=False,
                timeout=timeout,
                check=False,
            )
            return res.returncode, res.stdout, res.stderr
        except subprocess.TimeoutExpired:
            logger.warning("VBoxManage command timed out after %.1fs: %s", timeout, args)
            return -2, "", f"Command timed out after {timeout} seconds"
        except Exception as exc:
            logger.exception("Failed to execute VBoxManage: %s", exc)
            return -3, "", str(exc)

    def get_version(self) -> tuple[bool, Optional[str], Optional[str]]:
        """Query VirtualBox version."""
        code, stdout, stderr = self._run_command(["--version"], timeout=4.0)
        if code == 0 and stdout.strip():
            return True, stdout.strip(), None
        return False, None, stderr.strip() or "Failed to query VirtualBox version"

    @staticmethod
    def parse_vm_list(output: str) -> list[dict[str, str]]:
        """Parse `VBoxManage list vms` output: "Name" {UUID}."""
        vms: list[dict[str, str]] = []
        # Pattern: "VM Name" {UUID}
        pattern = re.compile(r'^"(.+?)"\s+\{([0-9a-fA-F\-]+)\}$')
        for line in output.splitlines():
            line = line.strip()
            match = pattern.match(line)
            if match:
                vms.append({"name": match.group(1), "uuid": match.group(2)})
        return vms

    def list_vms(self) -> list[dict[str, str]]:
        """List all registered virtual machines."""
        code, stdout, _ = self._run_command(["list", "vms"], timeout=5.0)
        if code != 0:
            return []
        return self.parse_vm_list(stdout)

    def list_running_vms(self) -> set[str]:
        """Return set of running VM UUIDs and names."""
        code, stdout, _ = self._run_command(["list", "runningvms"], timeout=5.0)
        if code != 0:
            return set()
        running = set()
        for vm in self.parse_vm_list(stdout):
            running.add(vm["uuid"].lower())
            running.add(vm["name"].lower())
        return running

    @staticmethod
    def parse_machine_readable(output: str) -> dict[str, str]:
        """Parse `showvminfo --machinereadable` key-value pairs."""
        data: dict[str, str] = {}
        for line in output.splitlines():
            line = line.strip()
            if not line or "=" not in line:
                continue
            parts = line.split("=", 1)
            key = parts[0].strip().strip('"')
            val = parts[1].strip().strip('"')
            data[key] = val
        return data

    def get_vm_info(self, vm_identifier: str) -> Optional[dict[str, Any]]:
        """Get detailed machine-readable info for a VM by name or UUID."""
        # Validate identifier safety
        if not (UUID_REGEX.match(vm_identifier) or SAFE_VM_NAME_REGEX.match(vm_identifier)):
            logger.warning("Rejected unsafe VM identifier: %r", vm_identifier)
            return None

        code, stdout, _ = self._run_command(["showvminfo", vm_identifier, "--machinereadable"], timeout=6.0)
        if code != 0 or not stdout:
            return None

        raw = self.parse_machine_readable(stdout)
        
        # Extract host-only network adapter details if present
        hostonly_mac = None
        hostonly_adapter = None
        for i in range(1, 9):
            nic_mode = raw.get(f"nic{i}")
            if nic_mode == "hostonly":
                hostonly_mac = raw.get(f"macaddress{i}")
                hostonly_adapter = raw.get(f"hostonlyadapter{i}")
                break

        return {
            "name": raw.get("name", vm_identifier),
            "uuid": raw.get("UUID", ""),
            "state": raw.get("VMState", "unknown").lower(),
            "os_type": raw.get("ostype", ""),
            "memory_mb": int(raw.get("memory", "0")) if raw.get("memory", "").isdigit() else 0,
            "cpus": int(raw.get("cpus", "0")) if raw.get("cpus", "").isdigit() else 0,
            "hostonly_mac": hostonly_mac,
            "hostonly_adapter": hostonly_adapter,
            "raw": raw,
        }

    @staticmethod
    def parse_hostonly_interfaces(output: str) -> list[dict[str, str]]:
        """Parse `VBoxManage list hostonlyifs` output into structured interface dicts."""
        interfaces: list[dict[str, str]] = []
        current: dict[str, str] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                if current and "Name" in current:
                    interfaces.append(current)
                    current = {}
                continue
            if ":" in line:
                key, val = line.split(":", 1)
                current[key.strip()] = val.strip()

        if current and "Name" in current:
            interfaces.append(current)

        return interfaces

    def list_hostonly_interfaces(self) -> list[dict[str, str]]:
        """List all VirtualBox host-only network interfaces."""
        code, stdout, _ = self._run_command(["list", "hostonlyifs"], timeout=5.0)
        if code != 0:
            return []
        return self.parse_hostonly_interfaces(stdout)

    def start_vm(self, vm_identifier: str, headless: bool = True) -> tuple[bool, str]:
        """Start a virtual machine safely."""
        if not (UUID_REGEX.match(vm_identifier) or SAFE_VM_NAME_REGEX.match(vm_identifier)):
            return False, "Invalid VM identifier"

        args = ["startvm", vm_identifier]
        if headless:
            args.extend(["--type", "headless"])

        code, stdout, stderr = self._run_command(args, timeout=12.0)
        if code == 0:
            return True, f"VM '{vm_identifier}' started successfully"
        return False, stderr.strip() or stdout.strip() or "Failed to start VM"

    def stop_vm(self, vm_identifier: str, force: bool = False) -> tuple[bool, str]:
        """Stop a virtual machine safely (ACPI power button or graceful poweroff)."""
        if not (UUID_REGEX.match(vm_identifier) or SAFE_VM_NAME_REGEX.match(vm_identifier)):
            return False, "Invalid VM identifier"

        action = "poweroff" if force else "acpipowerbutton"
        code, stdout, stderr = self._run_command(["controlvm", vm_identifier, action], timeout=10.0)
        if code == 0:
            mode = "forced poweroff" if force else "ACPI shutdown signal"
            return True, f"VM '{vm_identifier}' {mode} delivered successfully"
        return False, stderr.strip() or stdout.strip() or f"Failed to stop VM '{vm_identifier}'"
