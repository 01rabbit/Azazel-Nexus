"""Run explicitly requested model × load × concurrency cells, outside production."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from .load import EdgeLoad, LoadConfig
from .metrics import ProcessMeter, distribution, memory_limit
from .transport import stream

SCHEMA = "azazel-nexus/mio-bench/1"
FRAMES = Path(__file__).with_name("frames.json")


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return "sha256:" + value.hexdigest()


@dataclass(frozen=True)
class Condition:
    concurrency: int
    background_load: bool
    requests: int = 20
    deadline_s: float = 120
    max_tokens: int = 256

    def __post_init__(self):
        if self.concurrency not in (1, 2) or not 20 <= self.requests <= 10000:
            raise ValueError("concurrency must be 1/2 and requests 20..10000")
        if not 0 < self.deadline_s <= 600 or not 1 <= self.max_tokens <= 4096:
            raise ValueError("deadline must be <=600s and max_tokens 1..4096")


def run_cell(server, condition, frames, *, prompt_builder, advisory_reader,
             observer=stream, clock=time.monotonic):
    """server has start/stop/health/infer per LocalServer; observer adds TTFT.

    Each cell uses a fresh server. No warm-up is excluded: the first request
    is retained, while cold startup is measured separately. Failed requests
    count against validity; latency distributions contain successful streams.
    Exceptions are recorded by type only, never including model output.
    """
    rows = []
    cold = None
    error = None
    try:
        started = clock()
        server.start()
        if not server.health():
            raise RuntimeError("server unhealthy")
        cold = (clock() - started) * 1000

        def request(index):
            frame = frames[index % len(frames)]
            began = clock()
            row = {"index": index, "frame_id": frame["request_id"],
                   "valid_advisory": False, "error": None}
            try:
                result = observer(server.socket_path, prompt_builder(frame),
                                  max_tokens=condition.max_tokens,
                                  deadline_s=condition.deadline_s)
                row.update({key: value for key, value in asdict(result).items() if key != "text"})
                try:
                    from azazel_nexus.advisory_response import Advisory
                    row["valid_advisory"] = isinstance(advisory_reader(result.text), Advisory)
                except Exception as exc:  # noqa: BLE001 - record failure type, never untrusted text
                    row["error"] = type(exc).__name__
            except Exception as exc:  # noqa: BLE001 - record failure type, never untrusted text
                row.update(error=type(exc).__name__, elapsed_ms=(clock() - began) * 1000)
            return row

        with ThreadPoolExecutor(max_workers=condition.concurrency) as pool:
            # executor.map retains fixed frame ordering in the record.
            rows = list(pool.map(request, range(condition.requests)))
    except Exception as exc:  # noqa: BLE001 - record failure type, never untrusted text
        error = type(exc).__name__
    finally:
        try:
            server.stop()
        except Exception as exc:  # noqa: BLE001 - preserve the measured rows if cleanup fails
            error = error or type(exc).__name__
    successful = [row for row in rows if "total_ms" in row]
    rates = [row["tokens_out"] / (row["total_ms"] / 1000)
             for row in successful if row.get("tokens_out") is not None and row["total_ms"] > 0]
    generation_rates = [row["tokens_out"] / (row["generation_ms"] / 1000)
             for row in successful if row.get("tokens_out") is not None
             and row.get("generation_ms", 0) and row["generation_ms"] > 0]
    return {"condition": asdict(condition), "cold_start_ms": cold, "error": error,
            "attempted": len(rows), "stream_completed": len(successful),
            "valid_advisory_rate": sum(row["valid_advisory"] for row in rows) / condition.requests,
            "ttft_ms": distribution([row["ttft_ms"] for row in successful
                                      if row["ttft_ms"] is not None]),
            "total_ms": distribution([row["total_ms"] for row in successful]),
            "tokens_per_s": distribution(rates),
            "generation_tokens_per_s": distribution(generation_rates), "requests": rows}


def runtime_server(binary, model, socket_path, *, threads, context, max_tokens, start_deadline_s):
    # Lane B's public builder/lifecycle; imports deferred for fake-only tests.
    from azazel_nexus_runtime.mio_serve import LocalServer

    from azazel_nexus.model_runtime import RuntimeBinary, llama_server_record

    executable = str(Path(binary).absolute())
    binary_record = RuntimeBinary(
        runtime_id="bench-llama-b11716", executable=executable,
        version="b11716", digest=digest(binary), argv=(executable,),
    )
    record = llama_server_record(binary_record, model_path=Path(model).resolve(),
                                 socket_path=socket_path, ctx=context, threads=threads,
                                 max_tokens=max_tokens)
    # Bench-only fixed options: CPU execution and two server slots in every
    # cell, so the concurrency comparison changes only client concurrency.
    record = replace(record, argv=(*record.argv, "-ngl", "0", "--parallel", "2"))
    return LocalServer(record, root=Path("/"), socket_path=socket_path,
                       start_deadline_s=start_deadline_s)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, action="append", required=True)
    parser.add_argument("--binary", type=Path, default=Path("/usr/libexec/azazel/llama-server"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--requests", type=int, default=20)
    parser.add_argument("--deadline-s", type=float, default=120)
    parser.add_argument("--start-deadline-s", type=float, default=120)
    parser.add_argument("--max-tokens", type=int, default=256)
    parser.add_argument("--threads", type=int, default=2)
    parser.add_argument("--context", type=int, default=2048)
    parser.add_argument("--load-workers", type=int, default=1)
    parser.add_argument("--load-cpu", type=float, default=0.25)
    parser.add_argument("--load-memory-mib", type=int, default=256)
    args = parser.parse_args(argv)
    conditions = [Condition(c, load, args.requests, args.deadline_s, args.max_tokens)
                  for load in (False, True) for c in (1, 2)]
    if not 1 <= args.threads <= 4 or not 512 <= args.context <= 8192:
        parser.error("threads must be 1..4 and context 512..8192")
    if not 0 < args.start_deadline_s <= 300 or len(args.model) > 16:
        parser.error("start deadline must be <=300s and at most 16 models")
    # Bound load lifetime to the longest possible cell (including startup).
    duration = args.start_deadline_s + args.requests * args.deadline_s + 10
    if duration > 21600:
        parser.error("worst-case cell duration must be <=21600s")
    load_config = LoadConfig(args.load_workers, args.load_cpu, args.load_memory_mib, duration)
    from azazel_nexus.local_advisory import build_prompt, read_local_advisory

    frames = json.loads(FRAMES.read_text())
    environment = {"arch": platform.machine(), "cpu_count": os.cpu_count(),
                   "cpu_affinity_count": len(os.sched_getaffinity(0))
                   if hasattr(os, "sched_getaffinity") else None,
                   "memory_limit_bytes": memory_limit(), "llama_cpp_version": "b11716",
                   "binary_digest": digest(args.binary), "platform": platform.platform()}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as output:
        for model in args.model:
            model_info = {"name": model.name, "digest": digest(model)}
            for condition in conditions:
                with tempfile.TemporaryDirectory(prefix="mb-", dir="/tmp") as directory:
                    sock = Path(directory) / "s.sock"
                    server = runtime_server(args.binary, model, sock, threads=args.threads,
                                            context=args.context, max_tokens=args.max_tokens,
                                            start_deadline_s=args.start_deadline_s)
                    with (
                        EdgeLoad(load_config) if condition.background_load else nullcontext(),
                        ProcessMeter(sock) as meter,
                    ):
                        result = run_cell(server, condition, frames,
                                          prompt_builder=build_prompt,
                                          advisory_reader=read_local_advisory)
                    result.update(schema=SCHEMA, provenance="bench", not_hg05=True,
                                  environment=environment, model=model_info,
                                  frames_digest=digest(FRAMES), load=asdict(load_config),
                                  runtime_options={"threads": args.threads, "context": args.context,
                                                   "parallel": 2, "gpu_layers": 0},
                                  resources=meter.record())
                    output.write(json.dumps(result, ensure_ascii=False, allow_nan=False) + "\n")
                    output.flush()


if __name__ == "__main__":
    main()
