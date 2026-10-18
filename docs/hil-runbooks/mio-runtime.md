# Local retrieval runtime — hardware measurement (superseded)

## 概要（日本語）

この手順は [M.I.O. 埋め込み admission ランブック](mio-admission.md) に統合された。
実機計測・証跡・承認はすべてそちらに従う。生成（explanation）モデルの計測は
admission の入力にならず、生成 admission は将来作業である。

Status: **not run; hardware-unverified**.

The executable procedure for measuring the local embedding runtime on target
hardware, together with the HG-05 reserve, is now
[mio-admission.md](mio-admission.md). It produces the single attested
`azazel-nexus/hil-mio-campaign/v1` record that the admission loader requires.
Do not run a separate runtime campaign from this page.

What remains true here:

- Only the embedding role (bge-m3 Q8_0 on `llama-cpp-b11716`) can be admitted.
  A generative (Qwen2.5-1.5B-Instruct Q4_K_M) exercise, if separately approved
  under [#100](https://github.com/01rabbit/Azazel-Nexus/issues/100), is a
  diagnostic measurement only; it is never an admission input and authorizes
  nothing. Container RSS figures are never sizing or admission evidence.
- Fault exercises (crash/restart budget, wrong or missing binary, wrong model,
  timeout, memory pressure, keyword fallback, no non-AF_UNIX sockets, no Edge
  authority widening) belong to the [#100 behaviours](../hil-campaign.md#admission-and-the-six-100-behaviours)
  after admission, not to the measurement campaign.
- No VM/container latency or RSS qualifies target hardware, another
  architecture or another memory class. Keep failures and repeat after any
  image, runtime, model or workload change. This page supplies no approval or
  admission bypass.
