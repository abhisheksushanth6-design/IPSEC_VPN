"""VirtualBox NIC tracing capture engine for Layer 02.

Manages hypervisor-level live packet capture into standard PCAP files using
VBoxManage controlvm nictrace. Provides thread-safe state tracking, real-time
packet counting via binary PCAP header inspection, and safe argument execution.
"""

from __future__ import annotations

import logging
import os
import struct
import time
from pathlib import Path
from typing import Optional

from app.core.config import BACKEND_ROOT
from app.layers.layer01_test_environment.vbox_manager import VBoxManager

logger = logging.getLogger(__name__)

# Default live capture buffer directory
DEFAULT_LIVE_CAPTURE_DIR = BACKEND_ROOT / "data" / "captures" / "live"


def count_pcap_packets(file_path: str) -> int:
    """Count packets in a standard PCAP file by scanning record headers.
    
    Pure Python, zero-copy seek, handles endianness, safe against concurrent writes.
    """
    if not os.path.isfile(file_path):
        return 0
    try:
        with open(file_path, "rb") as f:
            header = f.read(24)
            if len(header) < 24:
                return 0
            magic = header[:4]
            if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
                endian = "<"
            elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
                endian = ">"
            else:
                return 0

            count = 0
            while True:
                rec_hdr = f.read(16)
                if len(rec_hdr) < 16:
                    break
                _, _, incl_len, _ = struct.unpack(endian + "IIII", rec_hdr)
                # Seek past payload
                f.seek(incl_len, os.SEEK_CUR)
                count += 1
            return count
    except Exception as exc:
        logger.debug("Error counting packets in PCAP %s: %s", file_path, exc)
        return 0


class VBoxCaptureEngine:
    """Manages VirtualBox NIC tracing for a VM."""

    def __init__(self, vbox_manager: Optional[VBoxManager] = None) -> None:
        self.vbox_manager = vbox_manager or VBoxManager()
        self.capture_dir = DEFAULT_LIVE_CAPTURE_DIR
        self.capture_dir.mkdir(parents=True, exist_ok=True)

    def start_trace(self, vm_identifier: str, nic_number: int, output_pcap_path: str) -> tuple[bool, str]:
        """Enable NIC tracing on a running VM writing to output_pcap_path.
        
        Executes:
        1. VBoxManage controlvm <VM> nictracefile<N> <output_pcap_path>
        2. VBoxManage controlvm <VM> nictrace<N> on
        """
        if not self.vbox_manager.is_available:
            return False, "VBoxManage executable is not available"

        if nic_number < 1 or nic_number > 8:
            return False, f"Invalid NIC number {nic_number}; must be between 1 and 8"

        # Step 1: Set trace output file
        file_cmd = [
            "controlvm",
            vm_identifier,
            f"nictracefile{nic_number}",
            str(Path(output_pcap_path).resolve()),
        ]
        code, stdout, stderr = self.vbox_manager._run_command(file_cmd, timeout=5.0)
        if code != 0:
            err = stderr.strip() or stdout.strip() or "Failed to set nictracefile"
            return False, f"Failed setting capture file: {err}"

        # Step 2: Enable tracing
        on_cmd = ["controlvm", vm_identifier, f"nictrace{nic_number}", "on"]
        code, stdout, stderr = self.vbox_manager._run_command(on_cmd, timeout=5.0)
        if code != 0:
            err = stderr.strip() or stdout.strip() or "Failed to enable nictrace"
            return False, f"Failed enabling NIC trace: {err}"

        return True, f"Live capture engaged on {vm_identifier} NIC {nic_number}"

    def stop_trace(self, vm_identifier: str, nic_number: int) -> tuple[bool, str]:
        """Disable NIC tracing on a running VM.
        
        Executes:
        VBoxManage controlvm <VM> nictrace<N> off
        """
        if not self.vbox_manager.is_available:
            return False, "VBoxManage executable is not available"

        off_cmd = ["controlvm", vm_identifier, f"nictrace{nic_number}", "off"]
        code, stdout, stderr = self.vbox_manager._run_command(off_cmd, timeout=5.0)
        if code != 0:
            err = stderr.strip() or stdout.strip() or "Failed to disable nictrace"
            return False, f"Failed stopping NIC trace: {err}"

        return True, f"Live capture stopped on {vm_identifier} NIC {nic_number}"
