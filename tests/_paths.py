"""Make next/addons importable (works under `python3 -I`, which drops the script directory)."""
import os
import sys

ADDONS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "addons")
if ADDONS not in sys.path:
    sys.path.insert(0, ADDONS)
