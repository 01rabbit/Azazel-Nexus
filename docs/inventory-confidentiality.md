# Node inventory confidentiality — what is collected, where it is kept, what may leave

Status: **rule, not procedure.** This document fixes how node inventory is
classified, where each class may be stored, and what may be shared outside the
node. It contains **no value from any machine** — no MAC address, no serial,
no asset ID, no TPM identity, no interface name — and
`tests/unit/test_inventory_confidentiality_doc.py` refuses it if one appears.

It applies to every commissioning and hardware-in-the-loop campaign this
product runs, not to one target. A runbook written for a specific machine
inherits these rules; it does not restate them differently.

Related: [Commissioning and Activation](commissioning.md) ·
[Core reserve measurement](core-reserve-measurement.md) ·
[hardware gates](hardware-gates.md) ·
[Nexus #115](https://github.com/01rabbit/Azazel-Nexus/issues/115)

## 1. Three questions that are not one question

| question | answered by |
| --- | --- |
| may it be **collected**? | the campaign needs it to classify the node |
| where may it be **stored**? | §3 |
| may it leave the node? | §5 |

Collecting a value is not permission to store it anywhere, and storing it is
not permission to share it. A record that answers the three together answers
none of them: it is the shape in which an identifier ends up in a report
because it was already in the file the report was written from.

## 2. The classes

| class | what it holds |
| --- | --- |
| **raw identity** | MAC address, serial, TPM identity, detailed NIC inventory, kernel inventory as read, asset ID |
| **derived identity** | the anonymous host ID, and the key-protected HMAC fingerprint of §4 |
| **class facts** | the memory class, the architecture, capacities, whether a capability is present — facts that describe a class of machine rather than one machine |

Raw identity is collected because the node cannot be classified or
commissioned without reading it. That is the whole of its licence.

## 3. Where each class may be stored

| destination | raw identity | derived identity | class facts |
| --- | --- | --- | --- |
| the node's **encrypted commissioning record** | **yes — only here** | yes | yes |
| the **append-only audit** | **no** | yes | yes |
| the ordinary **journal** | no | yes | yes |
| an **external report** | no | approved only (§5) | yes |

### Why the append-only audit is not a place for raw identity

The audit exists for **traceability**. Append-only means nobody can erase what
is written; it does not mean nobody can read it. The property that makes the
audit trustworthy — that a record cannot be taken back — is exactly what makes
it the worst destination for a value that should not have been written:
**writing a secret somewhere unerasable makes the disclosure permanent.**

A store is a confidentiality boundary when it restricts who can read it. The
audit restricts who can *change* it. Those are different guarantees, and
treating one as the other is how an identifier reaches a reader nobody
intended.

## 4. What the audit may hold

A closed list. **Anything not named here does not go in the audit.**

| admissible in the audit |
| --- |
| the anonymous host ID |
| the record generation |
| the transitions: inventory captured, inventory verified, node commissioned |
| the approval ID of the responsible operator |
| a key-protected HMAC fingerprint |
| the time, the outcome, and the **classification** of a refusal reason |

A refusal's classification is admissible; the refusing value is not. "The
interface was not the one the operator selected" is a classification. Naming
the interface is the raw identity the classification exists to avoid.

## 5. The fingerprint is an HMAC, and a bare hash is not one

A fingerprint that appears in the audit or in an external report is an **HMAC
bound to the TPM or to the commissioning secret**.

**A bare hash of a MAC address is not an anonymisation.** A MAC is 48 bits,
and with a known OUI the search space is smaller still; an unkeyed digest of
one is recovered by enumeration in negligible time. An unkeyed digest is an
*encoding* of the identifier, and publishing an encoding publishes the
identifier to anyone willing to enumerate.

**The key material never leaves the node.** It does not appear in the audit,
in the journal, in an issue, in a pull request, or in chat — and neither does
anything derived from it that would let it be reconstructed. A fingerprint
scheme whose key is in the same record as the fingerprint protects nothing.

## 6. What may be shared outside the node

| may be shared | condition |
| --- | --- |
| the anonymous host ID | **approved by the responsible operator.** An ID nobody approved is not an approved ID |
| a key-protected HMAC fingerprint | only where the report needs to correlate two records |
| class facts | — |

**The default is closed.** A value that is not named above is not shared, and
an item whose class is unclear is treated as raw identity until the
responsible operator classifies it. "Probably fine to publish" is how the
first identifier gets out, and it does not come back.

This covers every outward destination, named so none is overlooked by being
unlisted: issues, pull request bodies, shared chat, public audit output, and
support bundles.

## 7. What this document does not do

- It does not authorise a measurement, a commissioning, or a connection.
- It does not select an interface role. Interface roles are the operator's
  explicit decision, per [commissioning](commissioning.md) §1 — never inferred
  by this product.
- It does not record any machine's values, and a campaign's values do not
  belong in it. A rule that accumulates examples becomes the file the examples
  leak from.
