import sys
import os
sys.path.insert(0, os.path.abspath("."))
import time
import subprocess
from app.layers.layer02_packet_capture.capture_engine import count_pcap_packets

pcap_path = r"C:\Users\abhis\OneDrive\Desktop\SIH-Project\SEC 14\AI-Powered-IPsec-VPN-Protocol-Analyzer-and-Security-Assessment-Framework\backend\data\captures\live\test_live_check.pcap"
vbox = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"

# 1. Set file and turn on trace
print("Setting nictracefile...")
subprocess.run([vbox, "controlvm", "IPsec-Client", "nictracefile1", pcap_path], check=True)
subprocess.run([vbox, "controlvm", "IPsec-Client", "nictrace1", "on"], check=True)

try:
    for i in range(3):
        time.sleep(1)
        cnt = count_pcap_packets(pcap_path)
        size = os.path.getsize(pcap_path) if os.path.exists(pcap_path) else 0
        print(f"Check {i+1}: size={size} bytes, packets={cnt}")
finally:
    subprocess.run([vbox, "controlvm", "IPsec-Client", "nictrace1", "off"], check=True)
    print("Trace stopped.")
