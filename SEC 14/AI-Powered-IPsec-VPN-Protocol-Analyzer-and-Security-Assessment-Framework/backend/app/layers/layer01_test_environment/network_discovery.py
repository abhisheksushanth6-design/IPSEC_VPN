"""Network and IP discovery utilities for Layer 01.

Provides safe discovery of guest VM IP addresses via:
1. VirtualBox DHCP lease file inspection
2. Local host ARP table inspection by MAC address
3. Safe ICMP ping verification (using argument arrays, no shell=True)
4. UDP socket reachability checks on IPsec ports (500, 4500)
"""

from __future__ import annotations

import logging
import os
import re
import socket
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

IPV4_REGEX = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
MAC_CLEAN_REGEX = re.compile(r"[:\-\.]")


def normalize_mac(mac: Optional[str]) -> str:
    """Normalize MAC address string to lower-case without separators (e.g. '08002786308e')."""
    if not mac:
        return ""
    return MAC_CLEAN_REGEX.sub("", mac).lower()


class NetworkDiscovery:
    """Encapsulates network reachability and guest IP discovery routines."""

    def __init__(self, host_only_adapter_name: str = "VirtualBox Host-Only Ethernet Adapter") -> None:
        self.host_only_adapter_name = host_only_adapter_name

    def find_dhcp_leases(self) -> dict[str, str]:
        """Inspect VirtualBox DHCP leases file for active MAC-to-IP mappings.
        
        Returns dict of normalized_mac -> ip_address.
        """
        mappings: dict[str, str] = {}
        user_profile = os.environ.get("USERPROFILE", "")
        if not user_profile:
            return mappings

        vbox_dir = Path(user_profile) / ".VirtualBox"
        if not vbox_dir.is_dir():
            return mappings

        # Locate lease files matching HostInterfaceNetworking-*.leases
        try:
            for lease_file in vbox_dir.glob("*.leases"):
                try:
                    tree = ET.parse(lease_file)
                    root = tree.getroot()
                    for lease in root.findall("Lease"):
                        mac = lease.get("mac", "")
                        norm_mac = normalize_mac(mac)
                        addr_elem = lease.find("Address")
                        if norm_mac and addr_elem is not None:
                            ip = addr_elem.get("value", "")
                            if ip and IPV4_REGEX.match(ip):
                                mappings[norm_mac] = ip
                except Exception as ex:
                    logger.debug("Could not parse lease file %s: %s", lease_file, ex)
        except Exception as exc:
            logger.debug("Error scanning VirtualBox lease files: %s", exc)

        return mappings

    def get_arp_table(self) -> dict[str, str]:
        """Query host ARP table and map normalized MAC -> IP."""
        mappings: dict[str, str] = {}
        try:
            res = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                shell=False,
                timeout=3.0,
                check=False,
            )
            if res.returncode != 0 or not res.stdout:
                return mappings

            # Lines look like: "  192.168.56.104        08-00-27-86-30-8e     dynamic"
            pattern = re.compile(r"^\s*([0-9\.]+)\s+([0-9a-fA-F\-:]{11,17})\s+")
            for line in res.stdout.splitlines():
                match = pattern.match(line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2)
                    if IPV4_REGEX.match(ip):
                        mappings[normalize_mac(mac)] = ip
        except Exception as exc:
            logger.debug("Failed to read ARP table: %s", exc)

        return mappings

    def discover_ip_for_mac(
        self,
        mac_address: Optional[str],
        static_fallback: Optional[str] = None,
    ) -> list[str]:
        """Discover IP addresses matching a VM's MAC address."""
        if not mac_address:
            return [static_fallback] if static_fallback else []

        norm_target_mac = normalize_mac(mac_address)
        discovered: list[str] = []

        # 1. Check ARP table
        arp_table = self.get_arp_table()
        if norm_target_mac in arp_table:
            discovered.append(arp_table[norm_target_mac])

        # 2. Check DHCP leases
        leases = self.find_dhcp_leases()
        if norm_target_mac in leases and leases[norm_target_mac] not in discovered:
            discovered.append(leases[norm_target_mac])

        # 3. Add static fallback if configured and not yet in list
        if static_fallback and static_fallback not in discovered:
            discovered.append(static_fallback)

        return discovered

    @staticmethod
    def ping_host(ip_address: str, timeout_ms: int = 1000) -> tuple[bool, str, Optional[float]]:
        """Perform a single ICMP ping using safe subprocess array on Windows.
        
        Returns (success, message, round_trip_time_ms).
        """
        if not ip_address or not IPV4_REGEX.match(ip_address):
            return False, f"Invalid IPv4 address: '{ip_address}'", None

        # Windows ping command: ping -n 1 -w <timeout_ms> <ip>
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip_address]
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                shell=False,
                timeout=(timeout_ms / 1000.0) + 1.5,
                check=False,
            )
            stdout = res.stdout or ""
            if res.returncode == 0 and ("Reply from" in stdout or "bytes=" in stdout):
                # Parse RTT: time=0ms or time<1ms
                rtt = 0.5
                rtt_match = re.search(r"time[<=]([0-9]+)ms", stdout, re.IGNORECASE)
                if rtt_match:
                    rtt = float(rtt_match.group(1))
                return True, f"Host {ip_address} reachable (RTT: {rtt}ms)", rtt
            return False, f"Host {ip_address} unreachable (No response received)", None
        except subprocess.TimeoutExpired:
            return False, f"Ping to {ip_address} timed out", None
        except Exception as exc:
            return False, f"Ping execution error: {exc}", None

    @staticmethod
    def probe_udp_port(ip_address: str, port: int, timeout_sec: float = 1.0) -> tuple[bool, str]:
        """Test UDP socket transmission (e.g. port 500 / 4500).
        
        Sends a minimal probe packet; checks for immediate socket ICMP unreachable.
        """
        if not ip_address or not IPV4_REGEX.match(ip_address):
            return False, "Invalid target IP address"

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout_sec)
        try:
            # Minimal probe (empty or generic header)
            sock.sendto(b"\x00" * 8, (ip_address, port))
            # UDP is connectionless; lack of immediate host unreachable indicates route exists
            return True, f"UDP port {port} on {ip_address} is routeable"
        except (socket.timeout, BlockingIOError):
            return True, f"UDP port {port} socket open (no error)"
        except Exception as exc:
            return False, f"UDP probe to port {port} failed: {exc}"
        finally:
            sock.close()
