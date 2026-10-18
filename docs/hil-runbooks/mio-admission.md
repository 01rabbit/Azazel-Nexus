# M.I.O. embedding admission — HIL campaign runbook

## 概要（日本語）

実機（rugged x86_64、8 GiB クラス、仮想化なし）で HG-05 Core reserve と
M.I.O. 埋め込みランタイム（llama.cpp b11716 + bge-m3）を計測し、
コードが要求する唯一の証跡 `azazel-nexus/hil-mio-campaign/v1` を作成・
証明（attester 鍵）し、別の鍵（approver）で承認ペイロードにオフホスト署名するまでの
実行手順である。承認後も `LOCAL_MODEL_ADMISSION_ENABLED = False` のため
`verify` は `ADMISSION_DISABLED` を返す。有効化はレビュー済みのコード変更でのみ行う。
VM でのリハーサル結果は**決して証跡にならない**（§17）。

Status: **not run; hardware-unverified**. No campaign, approval, key or
measured record exists in this repository. Owner issues:
[#100](https://github.com/01rabbit/Azazel-Nexus/issues/100) (admission),
[#115](https://github.com/01rabbit/Azazel-Nexus/issues/115) (8 GiB pilot),
[#4](https://github.com/01rabbit/Azazel-Nexus/issues/4) (campaign parent).

This is the single executable procedure for local embedding admission. It
uses the [campaign prerequisites and stop conditions](../hil-campaign.md), the
[evidence lifecycle](../hil-evidence-records.md), the
[HG-05 reserve procedure](../core-reserve-measurement.md#5-the-procedure) and the
[admission contract](../local-model-admission.md). Where this runbook and the
code disagree, the code wins and this runbook is defective:
`tests/unit/test_runbook_references.py` checks that every command, flag, schema
name and refusal symbol named here exists in the code.

## 0. Scope

- Role: **embedding only** (`bge-m3` Q8_0 through `llama-cpp-b11716`).
  Explanation/generative admission does not exist; nothing here measures,
  approves or starts a generative server.
- Admission is advisory. It grants no Edge authority, no lease and no
  enforcement. `az-activated` still supplies no lease and no health evidence.
- The admission loader never reads the legacy
  `/var/lib/azazel/run/core-reserve.json`. Do not create or promote it.
- Never set `AZAZEL_ROOT`, never patch admission code, never unmask units by hand
  and never start `azazel-mio-locald.service` to collect numbers.

## 1. Roles, keys and custody

| Role | Who | Key | Where the key is used |
| --- | --- | --- | --- |
| DUT root operator (R) | runs install, probe, measurement, request, placement | none | DUT console only |
| Attester (A) | bundles and attests the campaign | enrolled operator key **A**, as a 32-byte seed in lowercase hex | `python -m tools.hil_evidence sign` on A's own workstation only |
| Approver (P) | signs the admission payload | enrolled operator key **P**, Ed25519 PEM | OpenSSL 3 on an offline signing workstation only |
| Independent reviewer (V) | performs the §10 checklist with P, witnesses §11 | none | — |

- A and P must be **different enrolled, non-revoked operators** in
  `/etc/azazel/operator-trust/operators.json`. Equal keys refuse with
  `ATTESTER_IS_APPROVER`; a revoked or unenrolled attester refuses with
  `RESERVE_UNATTESTED`; a revoked approver refuses with `SIGNATURE_REFUSED`.
  Use different people for A and P; V must not be P.
- Enroll each public key with the existing root-only
  `python -m azazel_nexus.operator_enrollment enroll LABEL` procedure
  ([explicit administrator enrollment](../debian-live-install.md#explicit-administrator-enrollment)),
  confirming the fingerprint (SHA-256 over the raw 32-byte public key) through a
  separate channel.
- `tools/hil_evidence.py sign` reads a seed file. Run it **only on the attester's
  own workstation**, never on the DUT, never in this repository's CI and never
  with a key stored in any checkout. No private key, seed or signature tool ever
  touches the DUT. Neither package contains a signer.
- Keep P's private key encrypted at rest on the offline workstation (or a
  hardware token), with a recorded custodian. Never transmit it, paste it into
  a ticket, or copy it to removable media used for the DUT.

## 2. Equipment and preconditions

- Deployment-candidate **rugged x86_64** Linux PC, Debian 13 / amd64, LUKS2
  storage, **8 GiB usable-memory class** (`MemTotal` 7168–15359 MiB selects
  `8GiB`/`core`). Another class needs its own campaign.
- Physical machine only: BIOS/UEFI virtualization features unused, no
  hypervisor, container or VM layer. Firmware/BIOS settings recorded in the
  protected commissioning record.
- Stable power (UPS or bench supply) and declared thermal conditions; record
  ambient temperature and any throttling observed. Unplanned power loss or
  thermal throttling during a run voids that run.
- Local console recovery, the approved image, a protected HIL archive outside
  every Git checkout, and an independent reviewer.
- Completed [preflight](../hil-preflight.md) A/B, commissioning key initialized
  on the device ([procedure](../core-reserve-measurement.md#commissioning-key-initialization-root-only)),
  and the Edge Core subsystems installed through the approved deployment path.
- An offline signing workstation with OpenSSL 3 for P; A's workstation with a
  checkout of the same reviewed commit and PyNaCl.

## 3. Install on the DUT

1. Obtain the reviewed amd64 `llama-server` built by `tools/build_llama_runtime.sh`
   ([pinned build](../mio-local-runtime.md#pinned-runtime-build-and-offline-installation)).
   Its SHA-256 must equal the x86_64 pin in `model_runtime.LLAMA_RUNTIME_DIGESTS`:
   `sha256:e1671cd4167b39b29fe34bb906f62d610b289aed19301445c4844764467fb701`.
2. Provision the full source commit of the installed build in the root-owned
   `/usr/share/azazel/build-commit`.
3. Install as root, offline:

   ```sh
   sudo packaging/install.sh --llama-runtime /media/approved/llama-server
   ```

   The installer refuses before mutation on a digest mismatch. Then check:

   ```sh
   sha256sum /usr/libexec/azazel/llama-server
   stat -c '%U:%G %a %h' /usr/libexec/azazel/llama-server
   stat -c '%U:%G %a' /etc/azazel/model-admission /etc/azazel/model-admission/evidence /etc/azazel/model-admission/evidence/artifacts
   ```

   Expect the pin above, `root:root 755 1`, and `root:azmio 750` for each
   admission directory. `azazel-mio-locald.service` stays masked.
4. Run `az-hil-readiness` and record its JSON. Not ready blocks the campaign.

## 4. Model import, promotion and declarations

1. The commissioned signed catalog (`/var/lib/azazel/models/trust/catalog.signed`,
   schema `azazel-nexus/model-catalog/3`) and `trust/trust.json` must already
   carry the embedding entry: `role` `embedding`, `format` `gguf`,
   `runtime_abi` `llama.cpp/1`, `context_limit` at least 2048, the bge-m3 Q8_0
   digest and size from the [model catalog](../model-catalog.md#embedding-retrieval-development-artifact),
   and a reviewed `declared_min_ram_mib`.
2. The protected `/etc/azazel/mission-pack.json`
   (`azazel-nexus/mission-pack-config/1`) supplies host facts (architecture
   `x86_64`, `profile` `core`, `security_epoch`), an embedding-role tested tuple
   for that digest, the `commissioning_digest`, and the model asset with its
   `memory_need_mib`. The asset value is set **after** §5 (see §6.3) through
   the reviewed Mission Pack process. `/etc/azazel/node.yaml` must be the
   commissioned node declaration.
3. Import offline as root: copy the verified GGUF from approved media to
   `/var/lib/azazel/fetch/ready/<64-hex digest>.gguf`, then

   ```sh
   sudo azazel-nexus model-import-fetched MODEL_ID --acknowledge-license
   ```

   (omit `--acknowledge-license` when the catalog entry does not require it).
   Expect `promoted`. Confirm `/var/lib/azazel/models/state/current` and that
   `sha256sum /var/lib/azazel/models/store/<64-hex digest>.gguf` equals the catalog digest.
4. Compute the exact argv and its digest from a reviewed checkout (runs nothing):

   ```sh
   PYTHONPATH=src python3 -m tools.mio_admission_helper argv --model-digest sha256:<64-hex model digest>
   ```

   Retain `argv`, `argv_digest` and `runtime_binary_digest`. The settings are
   fixed in code (`EMBEDDING_CTX` 2048, `EMBEDDING_THREADS` 2,
   `EMBEDDING_MAX_TOKENS` 256, embedding flags from `llama_server_record`).

## 5. Measurement campaign

Run **at least three boots** of the same DUT, class, image, build commit and
kernel. Allocate a run ID per boot. Never change the harness, binary, model or
workload within the campaign. Keep every failure.

### 5.1 Per boot

1. Cold boot. Do not start the model yet. Confirm `az-hil-readiness` is ready,
   locald is masked/inactive and `/var/lib/azazel/mio/embedding.sock` is absent.
2. Apply the declared Core workload (audit writing, evidence capture, lease
   journal) and keep it applied through steps 3–4.
3. **HG-05 reserve:** run `az-core-reserve-probe` (60 samples at 10-second
   intervals, harness `core-reserve-probe/3`). It refuses, writing nothing, on
   any inactive subsystem, unreadable sample, class change, identity change or
   observed virtualization (`refused: RESERVE_VIRTUALIZATION_OBSERVED`). On
   success it publishes `/var/lib/azazel/run/core-reserve-run-<8-digit sequence>.json`
   (schema `azazel-nexus/core-reserve/3`). The model must not run during the probe.
4. **Embedding runtime**, immediately after the probe, still under load (§5.2).
5. Copy the probe run file and the raw embedding tables to the protected
   campaign archive. Record ambient temperature, power state and any anomaly.

### 5.2 Embedding runtime measurement (root, on the DUT)

Run the pinned binary directly, as `azmio`, with **exactly** the argv from §4.4
and the locald resource limits. Do not use locald.

```sh
SOCK=/var/lib/azazel/mio/embedding.sock
MODEL=/var/lib/azazel/models/store/<64-hex model digest>.gguf
test ! -e "$SOCK"
START=$(date +%s%N)
# The full azazel-mio-locald hardening set, so the measurement runs under the
# same sandbox the admitted server will get (seccomp, MDWE, namespaces, limits).
systemd-run --unit=az-hil-embedding --uid=azmio --gid=azmio \
  -p MemoryMax=4G -p MemorySwapMax=0 -p CPUQuota=40% -p TasksMax=64 \
  -p LimitFSIZE=16777216 -p UMask=0027 \
  -p PrivateNetwork=yes -p IPAddressDeny=any -p RestrictAddressFamilies=AF_UNIX \
  -p NoNewPrivileges=yes -p ProtectSystem=strict -p ProtectHome=yes -p PrivateTmp=yes \
  -p PrivateDevices=yes -p ProtectKernelTunables=yes -p ProtectKernelModules=yes \
  -p ProtectControlGroups=yes -p RestrictNamespaces=yes -p RestrictSUIDSGID=yes \
  -p LockPersonality=yes -p MemoryDenyWriteExecute=yes -p SystemCallArchitectures=native \
  -p SystemCallFilter=@system-service -p CapabilityBoundingSet= -p AmbientCapabilities= \
  -p ReadWritePaths=/var/lib/azazel/mio -p ReadOnlyPaths=/var/lib/azazel/models \
  /usr/libexec/azazel/llama-server -m "$MODEL" --host "$SOCK" -c 2048 -t 2 --no-webui \
  -n 256 --embedding --pooling cls -ub 2048 -b 2048 -ngl 0
# Debian minimal has no curl: a stdlib AF_UNIX HTTP client measures health and latency.
python3 - "$SOCK" "$START" queries.txt > retrieval-latency.txt <<'PY'
import json, socket, sys, time
sock, start_ns, queries = sys.argv[1], int(sys.argv[2]), sys.argv[3]
def call(method, path, body=b""):
    s = socket.socket(socket.AF_UNIX); s.settimeout(30); s.connect(sock)
    head = (f"{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
    s.sendall(head + body); data = b""
    while chunk := s.recv(65536):
        data += chunk
    s.close(); return int(data.split(b" ", 2)[1]), data
while True:
    try:
        if call("GET", "/health")[0] == 200:
            break
    except OSError:
        pass
    if time.time_ns() - start_ns > 120_000_000_000:
        print("startup-timeout", file=sys.stderr); sys.exit(1)
    time.sleep(0.05)
print("startup_ms", -(-(time.time_ns() - start_ns) // 1_000_000), file=sys.stderr)
for query in open(queries, encoding="utf-8").read().splitlines():
    t = time.perf_counter()
    code, _ = call("POST", "/v1/embeddings", json.dumps({"input": [query]}).encode())
    print(code, f"{time.perf_counter() - t:.6f}")
PY
PID=$(systemctl show -p MainPID --value az-hil-embedding.service)
grep VmHWM "/proc/$PID/status"
cat /sys/fs/cgroup/system.slice/az-hil-embedding.service/memory.peak
grep -E '^(oom|oom_kill) ' /sys/fs/cgroup/system.slice/az-hil-embedding.service/memory.events
systemctl stop az-hil-embedding.service
rm -f "$SOCK"
```

- `queries.txt`: a fixed, sanitized corpus of at least 100 non-sensitive
  retrieval queries, one per line, identical on every boot. Record its SHA-256
  in block B. Never use operational prompts or identifiers.
- A run **fails** on `startup-timeout` (locald's 120-second startup bound), any
  response code other than `200`, any nonzero `oom`/`oom_kill`, a unit result
  other than success, or a mismatch of `sha256sum` of the binary or model.
- Measure on a cold page cache: run 5.2 first after each boot, before anything
  else reads the model (or `sync; echo 3 > /proc/sys/vm/drop_caches` as root
  immediately before). With a warm cache the cgroup `memory.peak` under-counts
  the mapped model (observed 143 MiB warm vs 759 MiB cold in a container
  rehearsal), and §6.3 takes the larger of `VmHWM` and `memory.peak`.
- Installed console scripts live in the venv (e.g.
  `/opt/azazel-nexus/venv/bin/az-nexus-model-admission`); `sudo` does not search
  it, so call them by full path.
- What is measured: `startup_ms` is exec to first healthy `/health` over AF_UNIX;
  retrieval latency is the client-observed query-embedding request
  (`POST /v1/embeddings`) over AF_UNIX. Library cosine ranking is not included
  because locald is not used. Peak RSS is `VmHWM` of the server process.

### 5.3 Pass criteria for the campaign

- At least three successful probe runs with distinct boot fingerprints, distinct
  positive run sequences, identical build commit, kernel release and harness,
  and non-identical measurement payloads; each run validates
  (`MIN_SAMPLES` 30, `MIN_DURATION_SECONDS` 300, all five required subsystems).
- All runs carry identical virtualization observations with
  `virtualization_not_observed` true.
- Every embedding run passed §5.2; no swap, OOM or thermal event.
- `reserve_mib` (maximum of per-run maxima) + `memory_need_mib` + 256 is at most
  the observed `MemTotal` in MiB, and `memory_need_mib` is at most 3840.

Anything else is a `failed` or `not-run` campaign. Retain it; do not attest it
as input to admission.

## 6. The campaign record (exact schema)

### 6.1 Fields

One aggregate record, schema `azazel-nexus/hil-mio-campaign/v1`, validated by
`azazel_nexus.hil_records.validate_record`. Top-level fields:

| Field | Value |
| --- | --- |
| `schema` | `azazel-nexus/hil-mio-campaign/v1` |
| `class` | `hardware-only` |
| `synthetic` / `physical_hardware` | `false` / `true` |
| `platform` | `rugged-x86_64-linux` |
| `provenance` | `measured` |
| `dut_fingerprint` | the probe runs' `host_digest` (`hmac-sha256:` + 64 hex) |
| `dut_id` | `dut-` + the first 32 hex digits of that HMAC |
| `hardware_class` | `8GiB` |
| `harness_version` | `core-reserve-probe/3` |
| `capture_method`, `workload_notes` | nonempty, sanitized descriptions |
| `operator_attestation_ref` | `hil-evidence:<RUN_ID>` of the bundle (§7) |
| `virtualization_not_observed` | `true` |
| `virtualization_observations` | the runs' map of `hypervisor_type`, `cpu_hypervisor`, `systemd_container`, `dockerenv`, `dmi_vendor`, `dmi_product`, `init_cgroup` |
| `embedding_runtime` | exactly the seven keys below |
| `runs` | at least three run envelopes |

`embedding_runtime` keys: `peak_rss_mib`, `startup_ms`, `retrieval_p50_ms`,
`retrieval_p95_ms` (positive integers, p50 at most p95) and
`runtime_binary_digest`, `model_digest`, `argv_digest` (`sha256:` + 64 hex).

Each run envelope repeats `class`, `synthetic`, `physical_hardware`,
`platform`, `provenance`, `dut_id`, `dut_fingerprint`, `hardware_class`,
`harness_version`, `capture_method`, `operator_attestation_ref` and
`workload_notes`, adds `boot_fingerprint` (copied from the probe document) and
embeds the probe document **unchanged** under `measurement`.

### 6.2 Aggregation (all whole numbers, rounded up)

- `peak_rss_mib`: maximum over runs of ceil(`VmHWM` kB / 1024).
- `startup_ms`: maximum over runs.
- `retrieval_p50_ms` / `retrieval_p95_ms`: nearest-rank percentiles over the
  pooled samples of all runs (sorted ascending, index ceil(p/100 × n) − 1),
  converted to milliseconds and rounded up; minimum 1.
- `runtime_binary_digest`, `model_digest`, `argv_digest`: from §4.4, equal to
  the `sha256sum` results observed on every run.
- The reserve is not written into the record; `validate_record` derives it as
  the maximum of per-run maxima.

### 6.3 Memory need

Commission the model asset `memory_need_mib` as at least the larger of
`peak_rss_mib` and ceil(`memory.peak` / 1 MiB) observed on any run, and at most
3840. The request (§9) must state exactly that value; the loader refuses
`RESOURCE_FIT` otherwise.

### 6.4 Assembling canonical artifacts

Write `envelope.json` with every top-level field above except `runs`, then
embed the probe documents unchanged and write canonical bytes (sorted keys,
no whitespace, no trailing newline):

```sh
PYTHONPATH=/path/to/reviewed/checkout/src python3 - envelope.json run-a.json run-b.json run-c.json <<'PY'
import json, sys
from pathlib import Path
from azazel_nexus.audit import canonical_event_bytes
envelope = json.loads(Path(sys.argv[1]).read_text())
common = ("class", "synthetic", "physical_hardware", "platform", "provenance", "dut_id",
          "dut_fingerprint", "hardware_class", "harness_version", "capture_method",
          "operator_attestation_ref", "workload_notes")
runs = []
for index, name in enumerate(sys.argv[2:], 1):
    measurement = json.loads(Path(name).read_text())
    run = {key: envelope[key] for key in common}
    run.update(boot_fingerprint=measurement["boot_fingerprint"], measurement=measurement)
    Path(f"run-{index}.json").write_bytes(canonical_event_bytes(run))
    runs.append(run)
Path("campaign.json").write_bytes(canonical_event_bytes({**envelope, "runs": runs}))
PY
```

This is a field mapping, not a record generator; it invents no value.

## 7. Bundle and attestation (attester workstation)

Choose `RUN_ID` (letters, digits, `-`, `_`; avoid dots) before §6.4 so that
`operator_attestation_ref` is `hil-evidence:<RUN_ID>`. `B.json` holds operator
declarations (workload, corpus SHA-256, approval references, roles); no key
material and no field whose name ends in `fingerprint`.

```sh
python -m tools.hil_evidence bundle BUNDLE --run-id RUN_ID --gate-id HG-05 --dut-id DUT_ID \
  --artifact campaign.json=campaign.json --artifact run-1.json=run-1.json \
  --artifact run-2.json=run-2.json --artifact run-3.json=run-3.json \
  --artifact retrieval-latency.csv=retrieval-latency.csv --operator-input B.json
python -m tools.hil_evidence lint BUNDLE
python -m tools.hil_evidence sign BUNDLE --key-file /path/outside/any/checkout/attester.seed
python -m tools.hil_evidence verify BUNDLE --operator-key attester.pub
```

Expect `{"status": "attested"}`. `attester.pub` holds A's 64-hex public key.
The signature covers `azazel-nexus/hil-evidence/v1\0` + canonical manifest; it
can never be confused with an operator approval, whose prefix differs (§11).
Exactly one artifact may carry the campaign schema. Then validate:

```sh
PYTHONPATH=src python3 - BUNDLE attester.pub <<'PY'
import json, sys
from pathlib import Path
from azazel_nexus.hil_records import validate_record
root = Path(sys.argv[1])
campaign = json.loads((root / "artifacts/campaign.json").read_bytes())
print(validate_record(campaign, bundle_directory=root, operator_key=Path(sys.argv[2])))
PY
```

Expect `status=<Status.ATTESTED: 'attested'>`, `reasons=()` and the
`reserve_mib`. A lint refusal is a confidentiality finding: fix the source
observation, never redact silently. Produce the sanitized HIL report (all
values of §6, raw tables, workload, B, manifest SHA-256, campaign SHA-256)
for P and V.

## 8. Placement on the DUT (root)

The admission evidence directory must contain only this bundle:

```sh
find /etc/azazel/model-admission/evidence -type f
cd BUNDLE
install -o root -g azmio -m 0640 manifest.json manifest.sig /etc/azazel/model-admission/evidence/
install -o root -g azmio -m 0640 artifacts/* /etc/azazel/model-admission/evidence/artifacts/
```

The first command must print nothing. Then write the policy (canonical, no
trailing newline; operators lists P's label; `max_seconds` at most 604800,
prefer 259200 or less):

```sh
printf '%s' '{"max_seconds":259200,"operators":["approver-label"],"roles":["embedding"],"schema":"azazel-nexus/model-admission-policy/v1"}' > policy.json
install -o root -g azmio -m 0640 policy.json /etc/azazel/model-admission/policy.json
```

Every file is root:azmio 0640 with one link; every directory root:azmio 0750;
no symlinks. Anything else refuses `EVIDENCE_UNPROTECTED`.

## 9. Approval request (root, on the DUT)

```sh
printf '%s\n' '{"envelope_floor_mib":FLOOR,"expires_at":"2026-11-03T09:00:00Z","issued_at":"2026-11-02T09:00:00Z","memory_need_mib":NEED,"operator":"approver-label"}' \
  | sudo az-nexus-model-admission request --role embedding > request.out
```

The stdin line is canonical JSON with exactly `envelope_floor_mib` (the
catalog `declared_min_ram_mib`), `expires_at`, `issued_at` (whole-second UTC,
`Z`), `memory_need_mib` (the Mission Pack asset value) and `operator`, then a
newline. The window must not exceed `max_seconds`. Output, in order: the
payload line; `payload SHA-256: sha256:…`; `message SHA-256: sha256:…`;
`domain/purpose: azazel-nexus/operator-approval/v1\0local-model-admission\0`;
the Japanese/English review summary (model, license, runtime, argv, Core
reserve MiB, peak RSS MiB, `virtualization_not_observed: true`, validity,
node); `signs nothing, authorizes nothing / 署名・認可は行いません`; and
`feature disabled / 機能無効`. A failure prints
`embedding -> refused:<SYMBOL>` and exits 2.

Each run generates a new `approval_id`, so sign only the payload from the one
`request.out` that P and V review. Move `request.out` to the signing workstation
on dedicated removable media.

## 10. Independent pre-signing checklist (P and V)

Compare against the attested HIL report and records **obtained independently
of the DUT**; a value displayed by the requesting node is not evidence.

1. `head -n 1 request.out | tr -d '\n' > payload.json`; `sha256sum payload.json`
   equals the printed payload SHA-256.
2. Decode `payload.json` and check every field:
   - `schema` `azazel-nexus/local-model-admission/v1`; `purpose`
     `local-model-admission`; `operator` is P's label; `approval_id` is a UUIDv4.
   - `approval_key.fingerprint` equals SHA-256 over P's raw public key, computed
     by P from P's own key; `security_epoch` equals the commissioned epoch.
   - `node`: `dut_fingerprint` and `hardware_class` equal the campaign;
     `profile` `core`; `node_digest` equals the retained SHA-256 of the
     commissioned node declaration; `commissioning_digest` equals commissioning.
   - `catalog` and `model`: catalog digest/version/signer equal the released
     catalog; model id, digest, size, `gguf`, `llama.cpp/1`, `embedding`, license.
   - `generation`: number and ids equal the import audit record.
   - `runtime`: `llama-cpp-b11716`, `b11716`, `x86_64`,
     `/usr/libexec/azazel/llama-server`, and the x86_64 pin of §3.
   - `settings.argv_digest` equals §4.4 and the campaign `argv_digest`; the
     printed argv equals §4.4 exactly.
   - `reserve`: `campaign_record_digest` equals SHA-256 of `artifacts/campaign.json`;
     `manifest_digest` equals SHA-256 of `manifest.json`; `run_id` and
     `attestation_ref` equal the manifest; `attestation_key_fingerprint` is A's
     enrolled fingerprint and differs from `approval_key.fingerprint`;
     `reserve_mib` equals the `validate_record` result; `harness_version`
     `core-reserve-probe/3`.
   - `runtime_evidence.peak_rss_mib` equals the campaign; `resources`:
     `memory_need_mib` at least the peak, at most 3840 and equal to §6.3;
     `envelope_floor_mib` equals the catalog.
   - `issued_at`/`expires_at` are the agreed ceremony window, within policy.
3. The summary lines (virtualization not observed, reserve, peak RSS, node,
   validity) agree with the report. Any mismatch, doubt or missing record: **stop
   and do not sign**.

## 11. Off-host signing ceremony

Present: P (operates the key) and V (reads each value aloud and confirms the
checklist). A may observe but never handles P's key. Record date, roles,
workstation, OpenSSL version and checklist sign-off in the ceremony record.
On the offline workstation with OpenSSL 3:

```sh
openssl version
{ printf 'azazel-nexus/operator-approval/v1\000local-model-admission\000'; cat payload.json; } > message.bin
head -c 56 message.bin | od -An -tx1 | tr -d ' \n'; echo
openssl dgst -sha256 message.bin
openssl pkeyutl -sign -inkey approver.pem -rawin -in message.bin -out approval.sig
openssl pkeyutl -verify -pubin -inkey approver.pub.pem -rawin -in message.bin -sigfile approval.sig
printf '{"payload_b64":"%s","schema":"azazel-nexus/local-model-admission-file/v1","signature_hex":"%s"}' \
  "$(base64 < payload.json | tr -d '\n')" "$(od -An -tx1 -v approval.sig | tr -d ' \n')" > embedding.approval
PYTHONPATH=src python3 -m tools.mio_admission_helper check-wrapper embedding.approval --public-key APPROVER_PUBLIC_HEX
```

- The 56-byte prefix must print exactly
  `617a617a656c2d6e657875732f6f70657261746f722d617070726f76616c2f7631006c6f63616c2d6d6f64656c2d61646d697373696f6e00`
  (`operator_trust.approval_message`: domain, NUL, purpose, NUL).
- `openssl dgst` must equal the printed message SHA-256;
  `Signature Verified Successfully`; `check-wrapper` prints the same payload and
  message SHA-256 and `"signature": "verified"`.
- `APPROVER_PUBLIC_HEX` is P's enrolled key:
  `openssl pkey -pubin -in approver.pub.pem -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \n'`.
- The wrapper has no trailing newline. Only `embedding.approval` leaves the
  workstation; payload, message and signature copies are retained in the
  ceremony record.

## 12. Atomic placement (root, on the DUT)

```sh
install -o root -g azmio -m 0640 embedding.approval /etc/azazel/model-admission/.embedding.approval.new
sync /etc/azazel/model-admission/.embedding.approval.new
mv -T /etc/azazel/model-admission/.embedding.approval.new /etc/azazel/model-admission/embedding.approval
sync /etc/azazel/model-admission
```

Never write the approval in place or as separate payload/signature files.

## 13. Verification

```sh
sudo az-nexus-model-admission verify --role embedding
```

While the kill switch is off this prints `embedding -> refused:ADMISSION_DISABLED`;
that is the expected result and proves nothing about the approval. Re-run §9
with the same stdin values and confirm exit 0 (all evidence still collects;
discard that new payload). On the DUT checkout, re-run `check-wrapper` against
the placed file. After a reviewed enablement (§14) the expected output is
`embedding -> admitted`; anything else is a refusal from the table below.

| Symbol | Meaning (first failing check) |
| --- | --- |
| `ADMISSION_DISABLED` | kill switch off; nothing else was read |
| `ROOT_REQUIRED` | the CLI was not run as root |
| `EVIDENCE_UNPROTECTED` | owner, mode, group, link count, symlink or missing `azmio` group |
| `EVIDENCE_CHANGED` | a file changed while being read or after verification |
| `EVIDENCE_REFUSED` | the CLI hit an unreadable or missing input (e.g. no policy) |
| `POLICY_REFUSED` | policy malformed, or operator not listed/enrolled |
| `MALFORMED` | wrapper or payload not canonical |
| `SIGNATURE_REFUSED` | signature invalid, or approver revoked/unenrolled |
| `ROLE_MISMATCH` | payload role is not `embedding` |
| `NOT_YET_VALID` / `EXPIRED` / `VALIDITY_EXCEEDS_POLICY` | time window |
| `PROCFS_REQUIRED` | no Linux procfs; descriptor execution impossible |
| `NODE_MISMATCH` | Mission Pack, commissioning, node or DUT HMAC differs |
| `WRONG_ARCHITECTURE` | `os.uname().machine` or host facts not `x86_64` |
| `NODE_IDENTITY_UNAVAILABLE` | commissioning HMAC identity not observable |
| `RESERVE_VIRTUALIZATION_OBSERVED` | a virtualization/container signal was observed |
| `CATALOG_MISMATCH` | catalog signature, version, digest or lineage differs |
| `GENERATION_MISMATCH` | installed generation differs from the approval |
| `TUPLE_MISMATCH` | no embedding tested tuple for this host |
| `SETTINGS_MISMATCH` | catalog limits, argv, binary or model digest differ from the campaign |
| `RESERVE_UNATTESTED` | bundle missing, unsigned, or attester not enrolled |
| `ATTESTER_IS_APPROVER` | the same key attested and approved |
| `RUNTIME_EVIDENCE_MISSING` | no single campaign record, or embedding measurements invalid |
| `RESERVE_FIXTURE` | fixture/synthetic markers in the evidence |
| `RESERVE_MISMATCH` | reserve profile or binding differs |
| `RESOURCE_FIT` | need, peak, floor, class or envelope do not fit |
| `RUNTIME_MISMATCH` | installed binary differs from the pin |
| `ARTIFACT_REFUSED` | model file fails verification |
| `KEY_ROTATED` / `EPOCH_MISMATCH` | approver key or security epoch changed |
| `PRECONDITIONS_REFUSED` / `READINESS_REFUSED` | locald/activation audit only: the shared decision's later gates refused |

`embedding -> absent` means no approval file is installed.

## 14. Enablement criteria for `LOCAL_MODEL_ADMISSION_ENABLED`

Enabling is a reviewed code change to `src/azazel_nexus/model_admission.py`,
never a node configuration. The pull request must attach, sanitized:

1. The HIL report of §7, `tools.hil_evidence verify` output, the
   `validate_record` output, the manifest SHA-256 and campaign record SHA-256.
2. A's and P's enrolled fingerprints (different), the policy file and the
   operator-trust revocation state at ceremony time.
3. `request.out`, the ceremony record with the §10 checklist sign-off by P and V,
   the OpenSSL verification line and `check-wrapper` output.
4. The DUT `verify` output (`embedding -> refused:ADMISSION_DISABLED`).
5. Evidence that `azazel-mio-locald` (user `azmio`) can read every loader input:
   `stat -c '%U:%G %a' /etc/azazel/operator-trust /etc/azazel/operator-trust/operators.json`
   shows `root:azmission-read 750` / `640` (enrollment writes these modes and the
   installer migrates older 0700/0600 stores), and the locald audit after a
   restart reports the same per-role symbol as the root `verify` output.
6. Confirmation that no measured record, key or approval is committed.

After merge and installation on the DUT, `verify` must print
`embedding -> admitted`; otherwise revert. The switch is global: nodes without
an approval report `embedding -> absent`. Production activation still grants
nothing without its separate lease/health producers.

## 15. Revocation, rollback and withdrawal

- Withdraw one node: `rm /etc/azazel/model-admission/embedding.approval` →
  `embedding -> absent`; locald stops the embedding child on the next request
  or 1.0-second poll and falls back to keyword retrieval.
- Revoke a signer: `python -m azazel_nexus.operator_enrollment revoke LABEL`
  (approver → `SIGNATURE_REFUSED`; attester → `RESERVE_UNATTESTED`).
- Bump `security_epoch` in the Mission Pack → `EPOCH_MISMATCH` everywhere.
- Global: revert the kill switch in a reviewed change → `ADMISSION_DISABLED`.
- Model rollback or new generation → `GENERATION_MISMATCH`; restoring the exact
  approved generation may reuse an unexpired approval. Expiry → `EXPIRED`;
  renewal is a new request and ceremony. New evidence (re-measurement) needs a
  new approval. There is no payload revocation list.

## 16. Stop conditions

Stop and record `failed`/`not-run` on: any refusal in §5, digest mismatch,
lint refusal, `validate_record` not attested, identity/class/kernel/build
drift, observed virtualization, OOM/swap/thermal/power event, unexpected
network traffic, Core interruption, a checklist mismatch, key custody doubt,
a revoked or rotated key, or any pressure to patch, unmask or set environment
overrides. Never repair evidence in place; a new campaign starts over.

## 17. VM rehearsal (never evidence)

A VM may rehearse **mechanics only**. Its outputs are never HIL evidence, never
attested with an enrolled key, never copied to a DUT and never attached to an
enablement PR as evidence. Use throwaway keys generated on the VM and destroy
them; never enroll them on a DUT. Label everything `rehearsal`.

What may be rehearsed on an x86_64 VM:

- `packaging/install.sh --llama-runtime` with the pinned amd64 binary
  (an aarch64 VM refuses the amd64 digest).
- The identity pre-start: with a VM-only commissioning key and a root-owned
  `/usr/share/azazel/build-commit` (§3.2),
  `sudo /usr/libexec/azazel/az-mio-identity` writes
  `/run/azazel-mio-identity/node-identity` (root:azmio 0640). Without either it
  exits 0 and writes nothing while the kill switch is off.
- `az-nexus-model-admission verify --role embedding` →
  `embedding -> refused:ADMISSION_DISABLED`.
- `az-nexus-model-admission request --role embedding` refusals in check order:
  `EVIDENCE_REFUSED` without a policy, a missing operator-trust store or a missing
  Mission Pack file, `POLICY_REFUSED` for an unlisted or
  unenrolled operator, `WRONG_ARCHITECTURE`, `NODE_IDENTITY_UNAVAILABLE`
  without a commissioning key, then `RESERVE_VIRTUALIZATION_OBSERVED`.
- `az-core-reserve-probe` refusing (missing subsystems, or
  `refused: RESERVE_VIRTUALIZATION_OBSERVED`).
- `tools.hil_evidence` bundle/lint/sign/verify, the §11 OpenSSL commands and
  `check-wrapper` with throwaway keys and dummy payloads.

The same mechanics can be rehearsed without a VM in a privileged Debian trixie
container running systemd as PID 1 (aarch64 on Apple Silicon): there the loader
stops at `WRONG_ARCHITECTURE`, and only with the admitted architecture changed in
a throwaway installed copy does it reach `NODE_IDENTITY_UNAVAILABLE` and then
`RESERVE_VIRTUALIZATION_OBSERVED`. Never change the architecture or the kill
switch in the repository for a rehearsal.

Rehearsing the operator path (entryd `mio.advise`) shows `deterministic handoff`
/ `refused` for every frame while admission is closed; that is the documented
behaviour (see [M.I.O. runtime](../mio-runtime.md#what-an-operator-receives-today)),
not a rehearsal failure.

A VM that happens to report no virtualization signal is still a VM:
`virtualization_not_observed` is a negative filter, not proof of hardware.
