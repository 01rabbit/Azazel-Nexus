"""Opt-in process isolation: AZAZEL_ROOT must precede runtime imports."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def real_assets():
    binary = os.environ.get("AZ_LLAMA_SERVER")
    directory = os.environ.get("AZ_GGUF_DIR")
    if not binary or not directory:
        pytest.skip("set AZ_LLAMA_SERVER and AZ_GGUF_DIR for real local inference")
    binary = Path(binary).resolve()
    directory = Path(directory).resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        pytest.skip("AZ_LLAMA_SERVER is not an executable file")
    candidates = ("qwen2.5-1.5b-instruct-q4_k_m.gguf",
                  "hf.co_XpressAI_shisa-v2.1-llama3.2-3b-GGUF_Q4_K_M.gguf",
                  "Phi-3.5-mini-instruct-Q4_K_M.gguf")
    models = sorted((directory / name for name in candidates if (directory / name).is_file()),
                    key=lambda p: (p.stat().st_size, p.name))
    if not models:
        pytest.skip("AZ_GGUF_DIR contains no supported candidate GGUF files")
    # Functional evidence uses the smallest model; the separate bench covers
    # the model matrix. Never download a model or invoke a substitute server.
    return binary, models[0]


@pytest.fixture
def run_real(real_assets):
    binary, model = real_assets
    repo = Path(__file__).resolve().parents[2]

    def run(scenario, privacy="P0-public"):
        # Short paths also work with macOS's 104-byte sockaddr_un ceiling.
        with tempfile.TemporaryDirectory(prefix="azlc-", dir="/tmp") as temporary:
            env = {
                **os.environ,
                "AZAZEL_ROOT": temporary,
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPATH": os.pathsep.join((str(repo / "src"), str(repo / "runtime/src"))),
            }
            with subprocess.Popen(
                [sys.executable, str(Path(__file__).with_name("harness.py")),
                 scenario, privacy, str(binary), str(model)],
                env=env, cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True,
            ) as child:
                try:
                    stdout, stderr = child.communicate(timeout=300)
                except subprocess.TimeoutExpired:
                    child.terminate()
                    try:
                        child.communicate(timeout=15)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.communicate()
                    pytest.fail(f"real inference scenario {scenario} exceeded 300s")
            assert child.returncode == 0, (
                f"real inference scenario {scenario}/{privacy} failed\n"
                f"stdout:\n{stdout[-12000:]}\n"
                f"stderr:\n{stderr[-12000:]}"
            )
            return stdout

    return run
