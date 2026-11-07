"""Required G01 entry, explicitly reserved by the executor; missing assets fail."""
import os
from pathlib import Path
import subprocess
import sys


def test_short_three_tasks_cold_once_warm_twice_with_native_budget():
    binary = Path(os.environ['AZ_LLAMA_SERVER'])
    model = Path(os.environ['AZ_GGUF_DIR']) / 'qwen2.5-1.5b-instruct-q4_k_m.gguf'
    output = Path(os.environ['W4_RECEIPT_DIR']) / 'g01'
    root = Path('/tmp/weekend-g01')
    env = {**os.environ, 'AZAZEL_ROOT': str(root)}
    child = subprocess.run([sys.executable, '-B', '-m', 'azazel_nexus_lab.weekend_generation',
        '--binary', str(binary), '--model', str(model), '--root', str(root), '--output', str(output)],
        env=env, capture_output=True, text=True, timeout=300)
    assert child.returncode == 0, child.stderr[-4000:]
    assert (output / 'g01.json').is_file()
