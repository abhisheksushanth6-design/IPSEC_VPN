#!/usr/bin/env python3
"""
Layer 13 Verification Runner — Frontend Dashboard / React Visualization Layer
AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework

Executes the standalone Layer 13 verification suite (frontend/scripts/verify_layer13.cjs)
and verifies frontend build, tests, TypeScript typechecks, and Layer 12 API alignment.
"""

import sys
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FRONTEND_DIR = REPO_ROOT / "frontend"
VERIFY_SCRIPT = FRONTEND_DIR / "scripts" / "verify_layer13.cjs"

def main():
    print("=" * 80)
    print("  LAYER 13 PYTHON VERIFICATION RUNNER")
    print("  AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework")
    print("=" * 80)
    print(f"Repository Root: {REPO_ROOT}")
    print(f"Frontend Root:   {FRONTEND_DIR}")
    print(f"Script Path:     {VERIFY_SCRIPT}\n")

    if not VERIFY_SCRIPT.exists():
        print(f"❌ Verification script not found at {VERIFY_SCRIPT}")
        sys.exit(1)

    cmd = ["node", str(VERIFY_SCRIPT)]
    print(f"Executing: {' '.join(cmd)}\n")

    result = subprocess.run(cmd, cwd=str(REPO_ROOT))
    sys.exit(result.returncode)

if __name__ == "__main__":
    main()
