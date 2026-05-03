#!/usr/bin/env python3
"""QClaw CLI entry point."""
import sys
import os

# Add workspace to path
WORKSPACE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if WORKSPACE not in sys.path:
    sys.path.insert(0, WORKSPACE)

from qclaw_cli.cli import main

if __name__ == "__main__":
    main()
