import sys
import time
from pathlib import Path

scratch_dir = Path(r"C:\Users\abhis\.gemini\antigravity-ide\brain\e0b7be5f-6d1e-4036-8496-045fa224aff3\scratch")
sys.path.insert(0, str(scratch_dir))

from vm_controller import send_ctrl_c, type_cmd, capture_screen

vm_name = "Name: IPsec-Analyzer"

print("1. Ensuring clean prompt...")
send_ctrl_c(vm_name)
time.sleep(0.5)

print("Checking which python...")
type_cmd(vm_name, "clear && which python && which pip && pwd")
time.sleep(1.5)

png = capture_screen(vm_name, "sync_stage2_extract")
print(f"Captured screen to {png}")
