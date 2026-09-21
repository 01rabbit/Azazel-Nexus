# HIL preflight — may the 8 GiB campaign start on this node?

Status: **implemented, and it authorises nothing.** `azazel-nexus
hil-preflight` answers one question with one of two words. It takes no
sample, reboots nothing, activates no unit, admits no provider, runs no model
and reaches no network.

Related: [Core reserve measurement](core-reserve-measurement.md) ·
[Inventory confidentiality](inventory-confidentiality.md) ·
[Commissioning and Activation](commissioning.md) ·
[hardware gates](hardware-gates.md) ·
[Nexus #115](https://github.com/01rabbit/Azazel-Nexus/issues/115)

## 1. What it replaces

Starting a campaign used to mean a person transcribing twenty facts about a
machine into a conversation. Every transcription is a copy of an identifier
somewhere it does not belong, and a mistyped one is a fact nobody can check.
The node holds all twenty. It answers for itself, and the operator runs one
command.

## 2. Two answers

`HIL_PREFLIGHT_READY` or `HIL_PREFLIGHT_BLOCKED`. There is no `PARTIAL`, no
`READY_WITH_WARNINGS` and no `PROBABLY` — **a preflight with a middle value
is a preflight somebody proceeds from.** The absence is structural:
`hil_preflight.OUTCOMES` has two entries and a result carrying anything else
cannot be constructed.

## 3. What it establishes, and who establishes it

| | established by | items |
| --- | --- | --- |
| `A-1` … `A-11` | the node, read-only | memory class, architecture, distribution, kernel, capacity, free space, LUKS, TPM, wired and wireless inventory, connectivity |
| `B-1` … `B-9` | the operator, explicitly | management and observation interfaces, every remaining interface left unassigned, whether external communication is forbidden, who, when, the asset or anonymous host ID, approval for reboots, administrative rights |

**No role is inferred.** An interface with no answer is *unanswered*, which
blocks; it is not *unassigned*, which is something an operator chose.
`docs/commissioning.md` §4 forbids resolving a role from an interface name, a
carrier, a link state or a route, and the preflight holds no role-to-interface
mapping to get wrong.

Connectivity (`A-11`) is read from the kernel's own view and is **never handed
to the role path**. It is a fact about the node, not about which port does
what.

## 4. What a reader is shown

| blocked | ready |
| --- | --- |
| the classification of each missing item — `A-4`, `B-2` | the anonymous host ID |
| | the record generation |
| | the key-protected HMAC fingerprint |
| | the classification of the approved roles, and how many interfaces were left unassigned |
| | that the node is the 8 GiB class |
| | the runbook ID |

**No value from the inventory appears on either path.** A blocked answer names
what is missing, because the name is what the operator needs; the value of the
facts that are present is not.

## 5. Where raw identity goes

Exactly where [inventory confidentiality](inventory-confidentiality.md) §3
says: the permanent MACs, the serials, the TPM identity, the asset ID and the
detailed interface inventory are written to the **commissioning record on
encrypted storage** and to nowhere else. Not the terminal, not the journal,
not the audit, not a report.

The audit receives the closed list of §4 of that document: the anonymous host
ID, the record generation, the transitions, the approval ID, the HMAC
fingerprint, and the outcome with the classification of what blocked it.

**The record is the existing one.** `commissioning.CommissioningRecord`, the
format the wizard already produces, stored as the document its own digest
covers. A second format would be a second identity policy.

## 6. A refusal writes nothing

If the encrypted-storage prerequisite does not hold — no LUKS-backed device
under the record directory, or no protection key — the raw inventory has
nowhere it may go, **so it goes nowhere**: the record is not written at all,
and the answer is `HIL_PREFLIGHT_BLOCKED` against `A-7` and `A-8`.

A preflight that wrote the record and then complained about the storage would
have already done the thing it was refusing. The refusal lives in the one
function that writes raw identity, so the next caller cannot route around it.

## 7. How the node reads itself

Every source is a file or a `stat`. Nothing is executed.

| fact | source |
| --- | --- |
| LUKS | `dm/uuid` under `/sys/dev/block/<major>:<minor>`, which device-mapper sets to `CRYPT-LUKS…` |
| TPM | the presence of a device under `/sys/class/tpm` — presence only; the TPM's identity is raw identity and is not read |
| memory class | `/proc/meminfo`, through `resource_profile`, which already owns that reading |
| interfaces | `azazel_nexus.inventory`, which already owns that reading |

A LUKS check that shelled out to `cryptsetup` would report "not encrypted" on
a host where the tool is merely absent — the wrong answer in the one direction
that matters.

## 8. What it still does not decide

A ready preflight says a campaign **may begin**. It is not a measurement, not
a reserve, not an admission and not an approval. `HG-05` is closed by the run
in [the measurement procedure](core-reserve-measurement.md) §5, and what that
run produces is refused or admitted by the gates named there — none of which
this command touches.
