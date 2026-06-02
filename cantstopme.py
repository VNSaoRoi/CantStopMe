#!/usr/bin/env python3
"""
CantStopMe — entry point at project root.

Usage (from this directory):
  python cantstopme.py -c "cat /etc/passwd" -b examples/php_ping_filter.txt --ping --url-encode -n 10
  python cantstopme.py --pool -v
  python cantstopme.py --explain -c "whoami"

After `pip install -e .` you can also run: cantstopme ...
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running without install: python cantstopme.py
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from cantstopme.cli.main import main

if __name__ == "__main__":
    raise SystemExit(main())
