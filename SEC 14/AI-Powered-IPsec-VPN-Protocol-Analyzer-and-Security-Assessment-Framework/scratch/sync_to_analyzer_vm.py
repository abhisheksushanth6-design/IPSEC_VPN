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

print("2. Downloading sec14_production.tar.gz from Windows host (192.168.56.1)...")
cmd_dl = "curl -s -f http://192.168.56.1:8888/sec14_production.tar.gz -o /home/analyzer/sec14_production.tar.gz && ls -lh /home/analyzer/sec14_production.tar.gz"
type_cmd(vm_name, cmd_dl)
time.sleep(3.0)

png = capture_screen(vm_name, "sync_stage1_download")
print(f"Captured screen to {png}")
