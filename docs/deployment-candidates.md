# Deployment candidates — what a machine has to be, and why none is named

**No machine is named here, and none is named anywhere in this project.** That
is the designed state, not a gap: `CONTRIBUTING.md` forbids naming a rugged PC
as supported, qualified **or a candidate**, and
[support matrix](support-matrix.md) §6 says why — *naming a candidate before a
test program exists creates the same expectation an empty table is meant to
prevent.*

A search of this repository, the other Azazel repositories and every open
issue found no product model, vendor or box named as a Nexus target, pilot
unit or past experiment. **Selecting the first pilot machine is an open owner
decision.** This document is what that decision has to satisfy.

Related: [support matrix](support-matrix.md) ·
[hardware gates](hardware-gates.md) ·
[HIL preflight](hil-preflight.md) ·
[Core reserve measurement](core-reserve-measurement.md) ·
[capability model](capability-model.md) ·
[Nexus #115](https://github.com/01rabbit/Azazel-Nexus/issues/115)

## 1. The three states an entry could be in

So that a machine, once there is one, is described as what it is rather than
as what somebody hopes.

| state | what it means | what it does **not** mean |
| --- | --- | --- |
| `evaluation candidate` | a machine under consideration. **No HIL has been run on it** | not tested, not supported, not recommended |
| `8 GiB pilot target` | the machine chosen for the first campaign ([#115](https://github.com/01rabbit/Azazel-Nexus/issues/115)) | the campaign has not produced a result by being chosen |
| `hardware-verified` | a hardware gate has passed on it, with a linked evidence record | valid for **that** entry only: a machine whose firmware version differs is a different entry until tested ([support matrix](support-matrix.md) §5) |

An entry reaches any of these only with **owner ratification and a linked
evidence record**. A name in a document is not an entry.

| System | State | RAM class | Evidence |
| --- | --- | --- | --- |
| — | — | — | — |

*(empty — see above)*

## 2. What the product says the machine must be

Every row is quoted from where it already stands; none of it is new here.

| requirement | source |
| --- | --- |
| a **generic rugged x86_64 Linux PC, at the resource class actually deployed** — not a named model and not any particular vendor's box | [hardware gates](hardware-gates.md) |
| architecture `x86_64`; other values are rejected by product admission | [support matrix](support-matrix.md) §3 |
| systemd, with nftables, `tc`, cgroup v2, TPM 2.0 tools and LUKS2 available. **No distribution, release or kernel series is named anywhere** | [support matrix](support-matrix.md) §3, §7 |
| a headless console MUST be supported; a touchscreen is an optional presentation device | [support matrix](support-matrix.md) §3 |
| UEFI Secure Boot where supported, TPM 2.0 measured boot, LUKS2-encrypted system and data volumes. With no TPM: a boot-time operator secret, and measured-boot evidence **labeled unavailable** | [support matrix](support-matrix.md) §3 |
| serviceable storage, battery power, touchscreen or external display support, and controllable network interfaces | [README](../README.md) |
| two or more labeled network adapters, and a passive tap or approved capture method | [operations](operations.md) |
| an interface layout **unknown until inventory** — roles are confirmed by an operator, never inferred | [commissioning](commissioning.md) |
| a Raspberry-Pi-class device, a laptop or a workstation may exercise the harness; **a record from one is not admissible** | [Core reserve measurement](core-reserve-measurement.md) §5 |

### The resource class, as the selector reads it

Usable RAM in MiB **after firmware reservation**, never nominal size.

| usable MiB | class |
| --- | --- |
| `< 7168` | `diagnostic` |
| `7168` – `15359` | `core` — **this is the 8 GiB class** |
| `15360` – `31743` | `lite` |
| `>= 31744` | `standard` |

The thresholds are nominal minus a 1024 MiB firmware-reservation allowance
([capability model](capability-model.md) §2). The profile names a hardware
class and not a capability.

## 3. What the 8 GiB pilot requires

The first campaign is fixed to **one 8 GiB-class rugged x86_64 Linux PC**
([#115](https://github.com/01rabbit/Azazel-Nexus/issues/115)). Its evidence is
valid for the 8 GiB class only: **one class's record says nothing about
another's.**

Before a campaign may begin, the target itself establishes `A-1`…`A-11`
(read-only inventory) and the operator settles `B-1`…`B-9` (explicit
decisions and approvals). Both lists, and what may be printed about them, are
[the HIL preflight](hil-preflight.md) — which is run on the target as

```
azazel-nexus hil-preflight
```

and answers `HIL_PREFLIGHT_READY` or `HIL_PREFLIGHT_BLOCKED`.

The measurement conditions are [the procedure](core-reserve-measurement.md)
§5–§7 and are not restated as numbers here, because a second copy of a
threshold is the copy that goes stale.

## 4. What must not be written here

- a machine name, before owner ratification and a linked evidence record
- any claim that a machine is "supported", "recommended", "field-proven" or
  suited to any particular duty, from its name alone
- raw identity of any machine — permanent MACs, serials, TPM identity, asset
  IDs. Those live in the encrypted commissioning record and nowhere else
  ([inventory confidentiality](inventory-confidentiality.md)). An entry
  identifies a machine by the composite identity of
  [support matrix](support-matrix.md) §5, recorded where that document says
