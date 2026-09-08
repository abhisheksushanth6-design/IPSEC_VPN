"""StrongSwan and IPsec SA status verification for Layer 01.

Provides safe inspection of StrongSwan daemon and Security Association state.
Uses configurable non-intrusive port probing or optional SSH/guest execution
without hardcoded credentials. Never fabricates green states or invents data.
"""

from __future__ import annotations

import logging
import re
import subprocess
from typing import Any, Optional

from app.layers.layer01_test_environment.network_discovery import NetworkDiscovery

logger = logging.getLogger(__name__)

# Sensitive pattern scrubbers to protect against secret leakage in command logs/evidence
SECRET_SCRUBBER = re.compile(r"(password|psk|secret|key|token)=([^\s&]+)", re.IGNORECASE)


def scrub_secrets(text: str) -> str:
    """Mask any sensitive keywords in output strings."""
    return SECRET_SCRUBBER.sub(r"\1=********", text)


class StrongSwanChecker:
    """Inspects StrongSwan service and IKE / Child SA status on target VMs."""

    def __init__(
        self,
        ssh_user: Optional[str] = None,
        ssh_key_path: Optional[str] = None,
        ssh_password: Optional[str] = None,
    ) -> None:
        self.ssh_user = ssh_user or ""
        self.ssh_key_path = ssh_key_path or ""
        self.ssh_password = ssh_password or ""
        self.network_discovery = NetworkDiscovery()

    @property
    def has_ssh_config(self) -> bool:
        """Return True if SSH credentials are configured for remote guest inspection."""
        return bool(self.ssh_user and (self.ssh_key_path or self.ssh_password))

    def _run_ssh_command(self, ip_address: str, command: str, timeout: float = 4.0) -> tuple[int, str, str]:
        """Execute a command over SSH safely without shell=True."""
        if not self.has_ssh_config:
            return -1, "", "SSH credentials not configured"

        # Construct safe SSH command array
        cmd = [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=NUL",
            "-o", f"ConnectTimeout={int(timeout)}",
        ]
        if self.ssh_key_path:
            cmd.extend(["-i", self.ssh_key_path])

        target = f"{self.ssh_user}@{ip_address}"
        cmd.extend([target, command])

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                shell=False,
                timeout=timeout + 1.0,
                check=False,
            )
            return res.returncode, scrub_secrets(res.stdout), scrub_secrets(res.stderr)
        except subprocess.TimeoutExpired:
            return -2, "", f"SSH command timed out after {timeout}s"
        except Exception as exc:
            return -3, "", f"SSH execution error: {scrub_secrets(str(exc))}"

    @staticmethod
    def parse_ipsec_status(output: str) -> dict[str, Any]:
        """Parse `ipsec statusall` or `swanctl --list-sas` textual output into structured SA state."""
        info: dict[str, Any] = {
            "daemon_status": "UNKNOWN",
            "ike_sa_state": "UNKNOWN",
            "child_sa_state": "NONE",
            "connections": [],
            "established_sas": 0,
            "raw_summary": "",
        }

        if not output or not output.strip():
            return info

        lower = output.lower()

        # Check daemon status
        if "strongswan" in lower or "charon" in lower or "statusall" in lower or "uptime" in lower:
            info["daemon_status"] = "RUNNING"

        # Check IKE SAs
        # Look for e.g. "ESTABLISHED 30 seconds ago" or "[1]: ESTABLISHED"
        if "established" in lower:
            info["ike_sa_state"] = "ESTABLISHED"
            established_matches = re.findall(r"established", lower)
            info["established_sas"] = len(established_matches)
        elif "connecting" in lower:
            info["ike_sa_state"] = "CONNECTING"
        elif "no matching sas found" in lower or "0 established" in lower or "no sas" in lower:
            info["ike_sa_state"] = "NO_SA"

        # Check Child SA (ESP / AH)
        if "installed" in lower or "routed" in lower or "reqid" in lower:
            info["child_sa_state"] = "INSTALLED"

        # Extract proposal / cipher details if mentioned
        ciphers = re.findall(r"(aes[_\-0-9a-z]+|chacha20[_\-poly1305]+|3des[_\-0-9a-z]+)", lower)
        if ciphers:
            info["detected_ciphers"] = list(set(ciphers))

        lines = [line.strip() for line in output.splitlines() if line.strip()][:5]
        info["raw_summary"] = " | ".join(lines)

        return info

    def inspect_vm_ipsec(
        self,
        ip_address: Optional[str],
        vm_power_state: str,
        vm_role: str,
    ) -> dict[str, Any]:
        """Inspect StrongSwan and IPsec status for a specific VM."""
        result: dict[str, Any] = {
            "vm_role": vm_role,
            "ip_address": ip_address,
            "strongswan_status": "UNKNOWN",
            "ipsec_status": "UNKNOWN",
            "ike_sa_state": "UNKNOWN",
            "child_sa_state": "NONE",
            "evidence": "",
            "details": {},
        }

        # If VM is not running, we know StrongSwan cannot be active
        if vm_power_state.lower() != "running":
            result["strongswan_status"] = "NOT FOUND"
            result["ipsec_status"] = "NO SA"
            result["evidence"] = f"VM '{vm_role}' is powered off ({vm_power_state})"
            return result

        if not ip_address:
            result["strongswan_status"] = "UNKNOWN"
            result["ipsec_status"] = "UNKNOWN"
            result["evidence"] = f"No IP address discovered for VM '{vm_role}'"
            return result

        # Check IP reachability first
        reachable, ping_msg, _ = self.network_discovery.ping_host(ip_address, timeout_ms=800)
        if not reachable:
            result["strongswan_status"] = "UNKNOWN"
            result["ipsec_status"] = "UNKNOWN"
            result["evidence"] = f"VM host {ip_address} did not respond to ICMP ping"
            return result

        # Test IPsec ports (UDP 500 ISAKMP / UDP 4500 NAT-T)
        udp500_ok, _ = self.network_discovery.probe_udp_port(ip_address, 500)
        udp4500_ok, _ = self.network_discovery.probe_udp_port(ip_address, 4500)

        # If SSH credentials are provided, attempt active command execution
        if self.has_ssh_config:
            code, stdout, stderr = self._run_ssh_command(
                ip_address,
                "swanctl --list-sas 2>/dev/null || ipsec statusall 2>/dev/null || systemctl status strongswan-starter --no-pager 2>/dev/null",
                timeout=3.5,
            )
            if code == 0 and stdout:
                parsed = self.parse_ipsec_status(stdout)
                result["strongswan_status"] = parsed["daemon_status"]
                result["ike_sa_state"] = parsed["ike_sa_state"]
                result["child_sa_state"] = parsed["child_sa_state"]
                result["ipsec_status"] = parsed["ike_sa_state"]
                result["evidence"] = parsed["raw_summary"] or f"StrongSwan output received from {ip_address}"
                result["details"] = parsed
                return result
            else:
                logger.debug("SSH command failed for %s: %s", ip_address, stderr)

        # Non-intrusive fallback: report port readiness without fabricating internal SA status
        if udp500_ok or udp4500_ok:
            result["strongswan_status"] = "UNKNOWN"
            result["ipsec_status"] = "UNKNOWN"
            result["evidence"] = (
                f"Host {ip_address} is reachable. UDP 500/4500 sockets open. "
                "StrongSwan SA query requires guest SSH credentials to inspect charon daemon."
            )
        else:
            result["strongswan_status"] = "UNKNOWN"
            result["ipsec_status"] = "UNKNOWN"
            result["evidence"] = f"Host {ip_address} reachable via ICMP, but no IPsec ports responding."

        return result
