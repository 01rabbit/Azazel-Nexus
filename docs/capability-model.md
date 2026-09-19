# Effective Capability Model

Status: **target contract**. Nothing in this document is implemented or
verified in this repository.

Related: [Contract ownership](contract-ownership.md) ·
[Commissioning and activation](commissioning.md) ·
[Field operations](operations.md)

## 1. The rule

Effective capability is the **intersection** of four records that are
determined independently:

```text
effective capability = resource profile
                     ∩ topology profile
                     ∩ verified asset set
                     ∩ current trust/health state
```

`ResourceProfile`, `TopologyProfile`, `InterfaceAssignment`, and
`CommissioningRecord` are assigned to Azazel-Fabric `provisioning_contracts`,
which is **not released yet**; the verified-asset set and the trust/health
evaluation are Nexus-local. See [contract ownership](contract-ownership.md)
§3.4.

No single dimension enables a capability. In particular:

> **RAM capacity never enables NIC roles, capture, enforcement, or Deception.**

A dimension can only *remove* capability from the intersection. There is no
path by which a larger resource envelope grants a topology, asset, or trust
property it does not have.

`CORE`, `LITE`, and `FULL` are **capability states, not authority levels**.
Azazel-Edge's deterministic arbiter holds the same and only decision and
enforcement authority in every state. Degrading from `FULL` to `CORE` removes
optional capacity; it never removes, transfers, or expands authority.

## 2. Resource profile

The resource profile records measured capacity only: CPU cores and features,
usable RAM, storage, and thermal/power budget. It says nothing about the
network.

Usable RAM is measured in **MiB after firmware reservation**, not nominal
module size, and the measured Core reserve is subtracted before selection. One
product-local selector produces exactly one of four values:

| Usable RAM (MiB, after firmware reservation) | Resource profile | Resource envelope permitted |
| --- | --- | --- |
| `< 8192` | `diagnostic` | diagnostics and inventory only; no policy activation |
| `8192` – `16383` | `core` | evidence, evaluators, arbiter, audit, UI, deterministic voice |
| `16384` – `32767` | `lite` | `core` capacity plus Knowledge Lite, Deception Lite, and local M.I.O. **capacity** |
| `>= 32768` | `standard` | `lite` capacity plus concurrent analysis, wider local models, and module-link capacity |

The words "capacity" and "envelope" are load-bearing. A `lite` resource profile
means the host has room for Deception Lite. It does **not** mean Deception Lite
is eligible; that requires the topology, asset, and trust dimensions to agree.

CPU cores and storage are recorded and may independently reduce the envelope,
but they never raise it above the RAM-selected value.

Performance and retention targets are measured and recorded separately for the
8, 16, 32, and 64 GB classes. A 64 GB host selects `standard`; there is no
separate `extended` selector output.

`lite` and `standard` name the **envelope**; "Lite-capable" and "Full-capable"
name what that envelope permits once the other three dimensions agree. They are
not separate tiers. [M.I.O. runtime control plane](mio-runtime.md) §2 holds the
mapping, including Edge's "Full-eligible" wording.

> **Retired:** the earlier four-tier scheme (`core` / `lite` / `standard` /
> `extended`, each stated with a NIC count) is retired. It conflated resource
> capacity with network topology, which SR-02 identified as unsafe. Its
> successor is this section plus §3. The 64 GB class survives as a performance
> measurement class, not as a selector output.

## 3. Topology profile

The topology profile records what the network actually permits, determined by
[commissioning](commissioning.md) and never by RAM:

- commissioned interfaces and their operator-confirmed logical roles;
- capture support proven on the interface assigned the observation role;
- management reachability over a path independent of the enforced path;
- proven isolation properties for a decoy zone.

A capability whose topology precondition is unproven is **unavailable**,
regardless of resource headroom:

| Capability | Topology precondition |
| --- | --- |
| capture / observation | an interface commissioned to the observation role with proven zero-transmit behavior |
| enforcement | a commissioned protected-zone path, plus an independent management path or physical console for the two-stage commit |
| Deception Lite | a dedicated decoy bridge with proven deny to protected, management, control-plane, and Internet zones |
| external AZ-04 / AZ-06 links | a commissioned module/egress zone reaching only provisioned peers |
| remote M.I.O. | a commissioned egress path plus a valid sanitizer decision |

## 4. Verified asset set

The verified asset set records which signed artifacts passed the full admission
sequence in [contract ownership](contract-ownership.md) §4: authenticity, an
exact tested compatibility tuple, semantic content policy, resource/topology
admission, approval, and staged activation.

A missing or rejected asset removes its capability and nothing else. Model
download or verification failure MUST leave a working Core environment.

## 5. Trust and health state

The trust/health state records current, revocable facts: policy signature
validity, audit chain continuity and anchor availability, clock trust, security
epoch, peer identity and manifest freshness, isolation attestation, and service
health.

This dimension is continuous, not a one-time gate. Isolation drift, a failed
anchor receipt, an expired peer manifest, or an untrusted clock withdraws the
affected capability while the node is running.

Audit assurance is reported as one of:

- `ROLLBACK_ANCHORED` — an independent anchor receipt is available;
- `LOCAL_CONTINUITY_ONLY` — no independent anchor. This state forbids live
  Deception, disruptive actions, and any claim of rollback-verified finalized
  evidence, unless a named emergency policy records explicit operator
  acceptance. Exports are labeled locally consistent and **not** rollback
  verified.

## 6. Worked examples

These examples show the intersection producing a *lower* capability than any
single dimension would suggest.

### 6.1 High memory, unsuitable network — observe-only

A 32 GB rugged PC with a single usable NIC and no independent management path.

| Dimension | Value |
| --- | --- |
| resource | `standard` (32768 MiB or more) |
| topology | one interface; no second commissioned role; no independent management path; no decoy bridge |
| verified assets | Edge package and local model both verified |
| trust/health | nominal |

Effective capability:

| Capability | State | Reason |
| --- | --- | --- |
| evidence, evaluators, arbiter, audit, UI, voice | available | resource and topology both permit |
| local M.I.O. | available | resource `standard`; no topology precondition |
| Knowledge Lite | available | read-only cache; no topology precondition |
| capture | **unavailable** | no interface commissioned to the observation role |
| enforcement | **unavailable** | no independent management path for the two-stage commit |
| Deception Lite | **unavailable** | no dedicated decoy bridge with proven deny |
| remote M.I.O. | **unavailable** | no commissioned egress path |

The node reports `CORE` with local cognition and is **observe-only**. Its 32 GB
of RAM changed nothing about what it is permitted to do to the network. This is
the intended outcome, not a defect.

### 6.2 Adequate network, missing assets

A 16 GB host, fully commissioned with observation, protected, management, and
decoy roles, but whose local model asset fails signature verification.

Effective capability: `CORE` plus Knowledge Lite and Deception Lite, with
M.I.O. reported as `CORE ONLY`. Enforcement and capture are available because
topology and trust permit them. The failed model asset removes only the local
cognition capability.

### 6.3 Trust withdrawal during operation

A fully commissioned `standard` node in `FULL` loses its independent audit
anchor.

Audit assurance drops to `LOCAL_CONTINUITY_ONLY`. Live Deception and new
disruptive actions are fenced; observation, evaluation, and audit continue;
existing leases run to their predeclared safe expiry. The node reports a
visible custody exception. Resource and topology did not change.

## 7. Degradation

The expected degradation path is `FULL -> LITE -> CORE`. It is driven by the
loss of an optional component, never by a change in authority.

| Loss | Result |
| --- | --- |
| AZ-04 external node | extended knowledge removed; Knowledge Lite continues from last verified content |
| AZ-06 external node | new full-host redirects stop; eligible redirects select a Lite destination if topology still permits |
| Knowledge Lite or Deception Lite | source-specific impairment; the other Lite service and Core continue |
| local model | M.I.O. reports `CORE ONLY`; deterministic explanations and voice continue |
| remote cognition | M.I.O. returns to `LOCAL`; no queued sensitive data |
| independent management path | enforcement eligibility withdrawn; observation continues |
| isolation attestation | decoy route withdrawn within the declared bound, then runtime cleanup |

Restoration above `CORE` requires a passing health window, revalidation of
signatures and segmentation, and an audited transition. Restoring a module
route or a failed enforcement adapter additionally requires operator
acknowledgement. A restart alone never restores a capability.

Optional-component failure MUST NOT block the deterministic control path and
MUST NOT grant a new authority.
