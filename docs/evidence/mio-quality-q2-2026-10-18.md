# M.I.O. local advice — false-refusal reduction, 2026-10-18

`provenance=bench`. Not HG-05 evidence and not a production admission claim.

## Setup
Same harness and models as `mio-quality-1b-2026-10-18.md` (14 frames, llama.cpp b11716,
aarch64 4 CPU / 8 GiB, `--network none`, baseline playbooks). New: grounding across every field
with deterministic `cited_facts`, label-advice recovery, generation caps 200/160 with
`max_tokens` 1024, a short "adapt, do not copy" prompt line, prose-shape filtering, `degenerate`
refusal, and cap-fragment trimming. The last three were added after the model run, so the stored
raw outputs were re-read offline with the final reader (the model output does not depend on the
reader).

## Accepted advice (of 12 non-gated frames)

| Condition | 1b | final |
|---|---|---|
| Qwen2.5-1.5B + playbooks | 8 | 10 (1 `ungrounded_facts`, 1 `degenerate`) |
| Llama 3.2 3B + playbooks | 7 | 9 (3 `ungrounded_facts`) |

Remaining `ungrounded_facts` are genuine: invented quantities (`10GB`, 「過去1ヶ月」), a
truncated IP (`192.0`), an unstated count ("1 successful login"). The `degenerate` case is a
Qwen answer repeating one phrase until the cap.

## Graded quality (independent Sonnet reviewer, 1–5)
Graded on the stored outputs before prose filtering / degenerate / trimming were added:

| Condition | 正確性 | 文脈 | 実行可能性 | 安全性 | 言語 | 合計平均 |
|---|---|---|---|---|---|---|
| qwen-pb (1b) | 3.00 | 2.71 | 2.71 | 4.93 | 4.29 | 3.53 |
| qwen-pb (new) | 3.00 | 2.93 | 2.57 | 4.57 | 4.36 | 3.49 |
| llama-pb (new) | 3.00 | 3.00 | 2.71 | 4.64 | 4.29 | 3.53 |

The same 1b outputs scored 3.43 in the earlier grading run, so grader variance is about ±0.1.
Averages are flat: fewer false refusals, but some newly delivered answers are weak (q10 Qwen
calls a 40-POST + injection log "usually fine"; q13 Qwen contradicts the available patch; q08
Llama misreads shadow-copy deletion). Lexical validators cannot catch fluent wrong claims; the
trusted playbook `first_response` attached to every matched answer remains the quality floor.
