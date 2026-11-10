"""Run pure browser-model regressions without adding a frontend dependency."""
from pathlib import Path
import shutil
import subprocess
import pytest


def test_soc_rows():
    if not shutil.which('node'):
        pytest.skip('Node unavailable')
    root = Path(__file__).resolve().parents[2]
    subprocess.run(['node', str(root/'tests/js/soc_dashboard.test.js')], cwd=root, check=True)
