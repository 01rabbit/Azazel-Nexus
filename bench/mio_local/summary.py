"""Generate Markdown from mio-bench/1 JSONL; never write route evidence."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .runner import SCHEMA


def _number(value):
    return "n/a" if value is None else f"{value:.2f}"


def _label(value):
    return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def summarize(records):
    lines = ["# M.I.O. local benchmark", "",
             "provenance=bench; not_hg05=true. No admission or route evidence.", "",
             "Nearest-rank p50/p95 require n≥20 per metric; n/a means insufficient or unavailable data.",
             "CPU uses one core = 100%; RSS is server-only. Cold start includes readiness.", "",
             "| Model | Load | Concurrent | Completed/attempted | Valid/all | Cold ms | TTFT p50/p95 ms (n) | Total p50/p95 ms (n) | End-to-end tok/s p50/p95 (n) | Peak RSS MiB | CPU % | Error |",
             "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for row in records:
        if (row.get("schema") != SCHEMA or row.get("provenance") != "bench"
                or row.get("not_hg05") is not True):
            raise ValueError("not mio-bench/1 bench-only evidence")
        condition = row["condition"]
        metrics = []
        for key in ("ttft_ms", "total_ms", "tokens_per_s"):
            metric = row[key]
            metrics.append(f"{_number(metric['p50'])}/{_number(metric['p95'])} ({metric['n']})")
        rss = row["resources"]["peak_rss_bytes"]
        values = [row["model"]["name"], "yes" if condition["background_load"] else "no",
                  condition["concurrency"], f"{row['stream_completed']}/{row['attempted']}",
                  f"{row['valid_advisory_rate']:.1%}/{condition['requests']}",
                  _number(row["cold_start_ms"]), *metrics,
                  _number(rss / 1024 ** 2 if rss is not None else None),
                  _number(row["resources"]["cpu_percent_one_core"]), row["error"] or ""]
        lines.append("| " + " | ".join(_label(value) for value in values) + " |")
    lines.extend(["", "Model/binary/frame digests, environment, load settings, resource sample counts,",
                  "and per-request failures are retained in the source JSONL. Validity measures",
                  "acceptance by read_local_advisory, not factual correctness or security efficacy.", ""])
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    records = [json.loads(line) for line in args.input.read_text().splitlines() if line.strip()]
    result = summarize(records)
    with args.output.open("x", encoding="utf-8") as output:
        output.write(result)


if __name__ == "__main__":
    main()
