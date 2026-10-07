"""Run every evaluation script in order.   python evaluation/run_all.py"""
import runpy
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
for script in sorted(HERE.glob("0*.py")):
    print(f"\n{'=' * 70}\n{script.name}\n{'=' * 70}")
    runpy.run_path(str(script), run_name="__main__")
