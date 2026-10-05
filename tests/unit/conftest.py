import sys
from pathlib import Path

# The scripts under tests/ import each other as top-level modules (they run as
# `python tests/<script>.py`), so make that folder importable for pytest too.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
