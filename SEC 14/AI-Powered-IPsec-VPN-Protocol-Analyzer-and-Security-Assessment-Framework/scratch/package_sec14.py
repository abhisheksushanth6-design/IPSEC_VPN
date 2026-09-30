import os
import tarfile
import sys
from pathlib import Path

source_dir = Path(r"c:\Users\abhis\OneDrive\Desktop\SIH-Project\SEC 14\AI-Powered-IPsec-VPN-Protocol-Analyzer-and-Security-Assessment-Framework")
output_tar = Path(r"c:\Users\abhis\.gemini\antigravity-ide\brain\e0b7be5f-6d1e-4036-8496-045fa224aff3\scratch\sec14_production.tar.gz")

exclude_dirs = {"__pycache__", "node_modules", ".pytest_cache", ".git", ".venv", ".venv-ai"}
exclude_extensions = {".pyc", ".pyo", ".db-wal", ".db-shm"}

def filter_tar(tarinfo):
    name = tarinfo.name
    parts = Path(name).parts
    for p in parts:
        if p in exclude_dirs:
            return None
    for ext in exclude_extensions:
        if name.endswith(ext):
            return None
    return tarinfo

print(f"Creating {output_tar} from {source_dir}...")
with tarfile.open(output_tar, "w:gz") as tar:
    tar.add(source_dir, arcname="AI-Powered-IPsec-VPN-Protocol-Analyzer-and-Security-Assessment-Framework", filter=filter_tar)

size_mb = output_tar.stat().st_size / (1024 * 1024)
print(f"Done! Archive size: {size_mb:.2f} MB")
