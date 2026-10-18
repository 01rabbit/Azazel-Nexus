# M.I.O. local benchmark

provenance=bench; not_hg05=true. No admission or route evidence.

Nearest-rank p50/p95 require n≥20 per metric; n/a means insufficient or unavailable data.
CPU uses one core = 100%; RSS is server-only. Cold start includes readiness.

| Model | Load | Concurrent | Completed/attempted | Valid/all | Cold ms | TTFT p50/p95 ms (n) | Total p50/p95 ms (n) | End-to-end tok/s p50/p95 (n) | Peak RSS MiB | CPU % | Error |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| qwen2.5-1.5b-instruct-q4_k_m.gguf | no | 1 | 20/20 | 100.0%/20 | 584.90 | 3609.06/4523.41 (20) | 6909.27/8606.86 (20) | 11.52/18.96 (20) | 1256.89 | 198.82 |  |
| qwen2.5-1.5b-instruct-q4_k_m.gguf | no | 2 | 20/20 | 100.0%/20 | 498.13 | 4133.82/8128.54 (20) | 12760.34/20115.61 (20) | 7.37/8.07 (20) | 1274.96 | 198.95 |  |
| qwen2.5-1.5b-instruct-q4_k_m.gguf | yes | 1 | 20/20 | 100.0%/20 | 506.99 | 3703.94/4671.39 (20) | 6970.95/8657.10 (20) | 11.11/18.73 (20) | 1261.60 | 198.86 |  |
| qwen2.5-1.5b-instruct-q4_k_m.gguf | yes | 2 | 20/20 | 100.0%/20 | 526.71 | 4285.49/4898.58 (20) | 14226.72/21597.76 (20) | 7.00/7.82 (20) | 1261.82 | 198.82 |  |
| hf.co_XpressAI_shisa-v2.1-llama3.2-3b-GGUF_Q4_K_M.gguf | no | 1 | 20/20 | 100.0%/20 | 888.41 | 9510.21/11020.17 (20) | 21537.72/38908.95 (20) | 8.00/11.92 (20) | 2445.93 | 198.03 |  |
| hf.co_XpressAI_shisa-v2.1-llama3.2-3b-GGUF_Q4_K_M.gguf | no | 2 | 20/20 | 95.0%/20 | 1255.68 | 10258.99/19308.13 (20) | 46676.33/90058.39 (20) | 5.39/5.80 (20) | 2452.04 | 199.40 |  |
| hf.co_XpressAI_shisa-v2.1-llama3.2-3b-GGUF_Q4_K_M.gguf | yes | 1 | 20/20 | 100.0%/20 | 1181.58 | 10514.30/12447.92 (20) | 25855.48/43746.95 (20) | 7.70/11.26 (20) | 2446.04 | 198.11 |  |
| hf.co_XpressAI_shisa-v2.1-llama3.2-3b-GGUF_Q4_K_M.gguf | yes | 2 | 20/20 | 95.0%/20 | 1401.71 | 10322.78/19548.17 (20) | 47379.42/91582.88 (20) | 5.38/5.72 (20) | 2452.50 | 199.45 |  |

Model/binary/frame digests, environment, load settings, resource sample counts,
and per-request failures are retained in the source JSONL. Validity measures
acceptance by read_local_advisory, not factual correctness or security efficacy.
