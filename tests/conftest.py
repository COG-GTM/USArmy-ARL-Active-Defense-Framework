import os
import sys

# Make the in-tree ``adf`` package importable without installing.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src", "python")
if SRC not in sys.path:
    sys.path.insert(0, SRC)
