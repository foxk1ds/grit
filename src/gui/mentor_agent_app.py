#!/usr/bin/env python3
"""
Grit — Socratic Mentor Agent Application Entrypoint.
Delegates to the modernized GNOME HIG workstation interface in app.py.
"""
import sys
from pathlib import Path

# Ensure local gui module path is accessible
gui_dir = Path(__file__).resolve().parent
if str(gui_dir) not in sys.path:
    sys.path.insert(0, str(gui_dir))

from app import main

if __name__ == "__main__":
    sys.exit(main())
