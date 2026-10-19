"""Explicitly non-production reference composition; never selects a Mission Pack."""
from __future__ import annotations

import json
import time
from pathlib import Path

from azazel_nexus_runtime.mio_supervisor import SupervisorRefused

from azazel_nexus.local_advisory import (
    MAX_FRAME_BYTES,
    build_options,
    delivered_document,
    gate_frame,
    read_delivered,
    read_frame,
    retrieval_decision,
)
from azazel_nexus.model_paths import bounded_read
from azazel_nexus.model_runtime import RuntimeRefused
from azazel_nexus.reasoning_playbook import match, read_library

HEADER = ("LAB-INPROCESS — 受け入れ外・サービス経路外\n"
          "LAB-INPROCESS — NOT admission / OUTSIDE service path")
DATA = Path(__file__).parent / "data/azazel-baseline.json"


def load_frame(path):
    document = json.loads(bounded_read(path, MAX_FRAME_BYTES))
    if document.get("schema") == "azazel-nexus-lab/scenario/1":
        document = document["frame"]
    return read_frame(document)


def reference(frame, *, retriever=None):
    began = time.perf_counter()
    library = read_library(DATA.read_bytes())
    books, scores, method = match(frame, library), (), "keyword"
    fallback = None
    if retriever is not None:
        try:
            books, scores = retriever.retrieve(frame, library, end=time.monotonic() + 120)
            method = "embedding"
        except (OSError, ValueError, RuntimeError, TimeoutError, RuntimeRefused, SupervisorRefused) as error:
            fallback = type(error).__name__
    gated = gate_frame(frame, scores[0] if scores else -1)
    if gated:
        document = gated
    else:
        options = build_options(frame, books)
        candidate, state, benign, record = retrieval_decision(frame, books, scores)
        if method == "keyword":
            state = "split" if books else "none"
        document = read_delivered(delivered_document(
            frame, books, options, candidate, options, None,
            "bge-m3" if method == "embedding" else "deterministic",
            similarities=scores, state=state, retrieval=method,
            benign_evidence=benign, system_record=record, provenance=method,
        ))
    return {"header": HEADER, "document": document, "retrieval": method,
            "fallback": fallback, "latency_ms": (time.perf_counter() - began) * 1000}


def render(result):
    document = result["document"]
    lines = [HEADER]
    if result.get("fallback"):
        lines.append("埋め込み利用不可・keyword にフォールバック / embedding unavailable; keyword fallback")
    lines.append(document.get("advice", ""))
    lines.extend(f"{name}: {value}" for name, value in document.get("fields", {}).items())
    return "\n".join(lines)
