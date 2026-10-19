"""Reproducible software measurements on the lab stack, never HIL evidence."""
from __future__ import annotations

import hashlib
import io
import json
import math
import platform
import statistics
import time
from contextlib import redirect_stdout
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from azazel_nexus.audit import AuditChainBroken

from . import services
from .artifacts import BANNER
from .inprocess import DATA, load_frame, reference
from .safe_files import lab_file

SCHEMA = "azazel-nexus-lab/bench/v1"
LABEL = "仮想マシン・ソフトウェア性能（実機の根拠ではない）"
SCENARIO = Path(__file__).parent / "scenarios/ssh-brute-force.json"


def build_identity():
    packages = {}
    for name in ("azazel-nexus", "azazel-nexus-runtime", "azazel-nexus-lab"):
        try:
            packages[name] = version(name)
        except PackageNotFoundError:
            packages[name] = "uninstalled source tree"
    return {"packages": packages, "python": platform.python_version(),
            "kernel": platform.release(), "machine": platform.machine(),
            "baseline_sha256": hashlib.sha256(DATA.read_bytes()).hexdigest(),
            "scenario_sha256": hashlib.sha256(SCENARIO.read_bytes()).hexdigest()}


def distribution(values):
    ordered = sorted(values)
    return {"n": len(ordered), "p50_ms": statistics.median(ordered),
            "p95_ms": ordered[max(0, math.ceil(len(ordered) * .95) - 1)]}


def process_memory(pid):
    try:
        rows = Path(f"/proc/{int(pid)}/status").read_text().splitlines()
        return {name + "_kib": int(next(row.split()[1] for row in rows
                                        if row.startswith(name + ":")))
                for name in ("VmRSS", "VmHWM")}
    except (OSError, ValueError, StopIteration):
        return {"unavailable": "/proc process memory unavailable"}


def service_memory(root):
    result = {}
    for name in services.UNITS:
        unit = services.prefix(root) + name + ".service"
        row = services.show(unit, ("MainPID", "ControlGroup", "ActiveState"))
        memory = process_memory(row.get("MainPID", "0"))
        group = row.get("ControlGroup", "")
        path = Path("/sys/fs/cgroup") / group.lstrip("/") / "memory.peak"
        try:
            if not group.startswith("/") or ".." in path.parts:
                raise ValueError("invalid cgroup")
            memory["cgroup_memory_peak_bytes"] = int(path.read_text())
        except (OSError, ValueError):
            memory["cgroup_memory_peak_bytes"] = None
        result[name] = {**memory, "active_state": row.get("ActiveState"), "pid": row.get("MainPID")}
    return result


def roundtrips(root, count, concurrency):
    from .cli import worker

    result = worker(root, "roundtrips", SCENARIO, count, concurrency)
    if result["exit_code"]:
        raise ValueError("entryd benchmark worker failed")
    rows = json.loads(result["stdout"])
    if len(rows) != count:
        raise ValueError("incomplete entryd benchmark")
    return {**distribution([row["ms"] for row in rows]), "samples": rows,
            "concurrency": concurrency}


def recoveries(root, *, timeout=15):
    from .cli import audit, break_target, worker

    results = []
    for target, relative in (
        ("knowledge-trust", "var/lib/azazel/lite-trust/trust.json"),
        ("locald", None), ("audit-tamper", "var/lib/azazel/state/mio/route.jsonl"),
    ):
        # Stop writers before capturing a ledger that will later be restored.
        services.stop(root)
        path = root / relative if relative else None
        saved = None
        if path is not None:
            with lab_file(root, target) as stream:
                saved = stream.read()
        services.start(root, services.prepare(root))
        try:
            began = time.monotonic()
            with redirect_stdout(io.StringIO()) as snapshot:
                break_target(root, target)
            previous, stable = None, 0
            observations = []
            reading = {"state": "transport_failure"}
            while time.monotonic() - began < timeout:
                if target == "audit-tamper":
                    try:
                        audit(root)
                        reading = {"state": "answered"}
                    except (AuditChainBroken, ValueError, KeyError):
                        reading = {"state": "refused"}
                else:
                    reply = worker(root, "knowledge-status") if target == "knowledge-trust" else worker(root, "ask", SCENARIO)
                    reading = {"exit_code": reply["exit_code"], "stdout": reply["stdout"], "state": "transport_failure"}
                    if reply["exit_code"] == 0:
                        body = json.loads(reply["stdout"])
                        if target == "knowledge-trust":
                            reading["state"] = "answered" if body.get("state") in {"available", "stale"} else "refused"
                        else:
                            reading["state"] = "answered" if body.get("outcome") == "answered" else "handoff_or_refusal"
                        # The route ledger position advances on every request by
                        # design; identical replies differ only in ledger_seq.
                        reading["reply"] = {key: value for key, value in body.items()
                                            if key != "ledger_seq"}
                observations.append(reading)
                compared = {key: value for key, value in reading.items() if key != "stdout"}
                stable = stable + 1 if compared == previous else 1
                previous = compared
                # Stable replies/refusals are observed three times, 100 ms apart.
                if stable >= 3 and reading["state"] != "transport_failure":
                    break
                time.sleep(.1)
            results.append({"target": target, "elapsed_ms": (time.monotonic() - began) * 1000,
                            "state": "stable_" + reading["state"] if stable >= 3 and reading["state"] != "transport_failure" else "timeout",
                            "observations": observations, "authority_snapshot": json.loads(snapshot.getvalue()),
                            "memory": service_memory(root)})
        finally:
            services.stop(root)
            try:
                if path is not None:
                    with lab_file(root, target, write=True) as stream:
                        stream.write(saved)
                        stream.truncate()
            finally:
                # A refused restore must not also leave the lab stopped.
                services.start(root, services.prepare(root))
    return results


def summary(document):
    lines = [BANNER, LABEL, "測定 | 件数 | p50 (ms) | p95 (ms)", "--- | ---: | ---: | ---:"]
    for name, row in [("entryd 並列 " + str(r["concurrency"]), r) for r in document["entryd"]] + [
        ("LAB-INPROCESS keyword", document["keyword"])]:
        lines.append(f'{name} | {row["n"]} | {row["p50_ms"]:.3f} | {row["p95_ms"]:.3f}')
    embedding = document["embedding"]
    if embedding.get("latency"):
        row = embedding["latency"]
        lines.append(f'LAB-INPROCESS embedding | {row["n"]} | {row["p50_ms"]:.3f} | {row["p95_ms"]:.3f}')
    else:
        lines.append("embedding | " + embedding["state"] + " | — | —")
    if embedding.get("banner"):
        lines.append(embedding["banner"])
    for row in document["startup"]:
        lines.append(f'{row["unit"]} 起動 | active {row["active_ms"]:.3f} ms | socket {row["socket_ready_ms"]:.3f} ms | —')
    for row in document["recovery"]:
        lines.append(f'{row["target"]} 安定応答/拒否 | {row["state"]} | {row["elapsed_ms"]:.3f} | —')
    lines.append("持続測定 RSS/latency drift: " + json.dumps(document["sustained"]["drift"], ensure_ascii=False))
    lines.append("サービス VmHWM / cgroup memory.peak: " + json.dumps(document["memory_after"], ensure_ascii=False))
    return "\n".join(lines) + "\n"


def run_bench(root, args):
    if getattr(args, "embedding", False):
        from .embedding import refuse_embedding

        refuse_embedding()
    if not 1 <= args.requests <= 10000 or not 0 < args.duration <= 86400 or not .1 <= args.interval <= 60:
        raise ValueError("requests 1..10000, duration (0,86400], interval .1..60 required")
    # No caller-supplied destination and no writes into evidence directories.
    destination = root / "bench"
    if destination.is_symlink():
        raise ValueError("symlink bench directory refused")
    destination.mkdir(mode=0o700, exist_ok=True)
    services.stop(root)
    startup = services.start(root, services.prepare(root))
    frame = load_frame(SCENARIO)
    document = {"schema": SCHEMA, "lab": True, "not_hardware_evidence": True,
                "banner": BANNER, "performance_label": LABEL,
                "started_at": datetime.now(UTC).isoformat(), "platform": platform.platform(),
                "build_identity": build_identity(),
                "parameters": vars(args) | {"model": str(args.model) if args.model else None},
                "startup": startup, "memory_before": service_memory(root)}
    document["entryd"] = [roundtrips(root, args.requests, c) for c in (1, 2, 4)]
    document["keyword"] = distribution([reference(frame)["latency_ms"] for _ in range(args.requests)])
    document["embedding"] = {"state": "not_requested"}
    sustained = sustained_run(root, frame, args, None)
    document["sustained"] = sustained
    document["memory_after"] = service_memory(root)
    document["recovery"] = recoveries(root)
    stem = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f")
    json_path, text_path = destination / (stem + ".json"), destination / (stem + ".txt")
    text = summary(document)
    with json_path.open("x") as stream:
        json.dump(document, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.write("\n")
    with text_path.open("x") as stream:
        stream.write(text)
    # main() has already printed the banner; the saved summary keeps its own.
    print(text.removeprefix(BANNER + "\n"), end="")
    return {**document, "saved_json": str(json_path), "saved_summary": str(text_path)}


def sustained_run(root, frame, args, engine):
    samples = []
    began = time.monotonic()
    while True:
        samples.append({"elapsed_s": time.monotonic() - began,
                        "entryd": roundtrips(root, args.requests, 1),
                        "reference": reference(frame, retriever=engine), "memory": service_memory(root),
                        "embedding_memory": engine.server.memory() if engine is not None else None})
        remaining = args.duration - (time.monotonic() - began)
        if remaining <= 0:
            break
        time.sleep(min(args.interval, remaining))
    first, last = samples[0], samples[-1]
    drift = {"entryd_p50_ms": last["entryd"]["p50_ms"] - first["entryd"]["p50_ms"],
             "reference_ms": last["reference"]["latency_ms"] - first["reference"]["latency_ms"],
             "rss_kib": {name: last["memory"][name].get("VmRSS_kib", 0) - row["VmRSS_kib"]
                         for name, row in first["memory"].items() if "VmRSS_kib" in row
                         and "VmRSS_kib" in last["memory"][name]}}
    if first["embedding_memory"] and last["embedding_memory"] and all(
            "VmRSS_kib" in sample["embedding_memory"] for sample in (first, last)):
        drift["embedding_rss_kib"] = last["embedding_memory"]["VmRSS_kib"] - first["embedding_memory"]["VmRSS_kib"]
    return {"actual_duration_s": time.monotonic() - began, "samples": samples, "drift": drift}
