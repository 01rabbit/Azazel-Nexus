"""`az-activation`: operator tooling for the observe-baseline activation (#206 P3).

`docs/activation-observe-baseline.md` §3.1, §3.2, §3.5 and §7. Three commands,
none of which grants anything:

* ``generation-publish`` (root, interactive) measures the installed unit files
  of the activation policy's scope, the Edge pin and -- exactly when
  edge-core is in scope -- the installed Edge package digest and the digests
  of the extracted binary and redirect policy it runs (refusing any
  unit override or drop-in, `activation_unit_files`), builds the
  observe-baseline tree, binds it to verified commissioning evidence and,
  after the digest is re-entered and ``PUBLISH`` typed, publishes it as an
  ordinary generation. Publishing is not admission.
* ``request`` (read-only) collects the independent context the node verifier
  will use and writes the canonical unsigned v2 payload to a create-only
  ``--out`` file (without it, only a summary is printed). It never signs and
  never writes an approval file.
* ``install`` (root) re-collects that context, verifies a signed approval
  against the activation policy and the current high-water floors, places
  ``approval.json`` and ``approval.sig`` and raises (or, on a node without any
  floor history, initializes) the high water. Replacing an installed approval
  and the §7 high-water recovery each need a separate typed confirmation.

`az-activated` does not import this module; its pass still composes
``lease=None`` until phase P4. No key is created or read for signing, no
environment variable or path override is accepted, and nothing here starts,
enables or unmasks a unit. Refusals print fixed labels only: no file content,
raw inventory, evidence binding or exception text.
"""

from __future__ import annotations

import argparse
import fcntl
import os
import re
import stat
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

from azazel_nexus.activation_approval_v2 import (
    ActivationApprovalPolicy,
    ObserveBaselineContext,
    observe_baseline_payload,
    verify_observe_baseline_approval,
)
from azazel_nexus.activation_policy import ActivationPolicy, load_activation_policy
from azazel_nexus.audit import AuditLedger
from azazel_nexus.bootstrap_approval import parse_bootstrap_time
from azazel_nexus.bootstrap_deployment import declared_node_binding
from azazel_nexus.bootstrap_deployment_store import load_bootstrap_deployment
from azazel_nexus.edge_package import installed_package_components
from azazel_nexus.generation import (
    GenerationCommitUncertain,
    GenerationRefused,
    GenerationStore,
    tree_digest,
)
from azazel_nexus.observe_baseline import (
    EDGE_CORE_UNIT,
    build_observe_baseline,
    evidence_commissioning_digest,
    verify_observe_baseline,
)
from azazel_nexus.operator_store import load_operator_trust
from azazel_nexus.operator_trust import MAX_APPROVAL_BYTES, ApprovalRefused

from . import activation_high_water as high_water
from .activation_high_water import (
    HighWater,
    HighWaterCommitUncertain,
    decode_high_water,
    initialize_high_water,
    raise_high_water,
    read_high_water,
)
from .activation_unit_files import (
    UnitContentRefused,
    UnitFilesRefused,
    UnitOverrideRefused,
    measure_scoped_unit_files,
)
from .commissioning_input import load_commissioning_evidence
from .node_config import load_declared_node

__all__ = ["FLOOR_EVENTS", "main"]

_APPROVAL_DIRECTORY = ("etc", "azazel", "activation")
_GENERATIONS = ("var", "lib", "azazel", "generations")
_STATE = ("var", "lib", "azazel", "state")
_EDGE_PACKAGE = ("opt", "azazel", "edge-core")
_LEDGER = "activation.jsonl"
_APPROVAL_FILES = ("approval.json", "approval.sig")
#: Private test seams: the root every fixed path is resolved under and the
#: owner every protected component must have. Production is `/` and root.
_ROOT = Path("/")
_OWNER = 0

_ACTOR = "az-activation"
_SIGNATURE_BYTES = 64
_LEDGER_LIMIT = 64 << 20
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_RETAINED = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")

#: Activation-ledger events that mean a high-water floor existed (§3.5, §7):
#: the install and recovery records written here, and a unit grant (only a
#: pass that verified an approval against a floor can grant). A ledger that
#: holds any of them is "history": a missing high-water file is then never
#: initialized from zero, only recovered through §7. The pass's own
#: `activation.inputs_incomplete` records and generation publications are
#: not floors. Phase P4's pass records `activation.high_water_raised`.
FLOOR_EVENTS = frozenset({
    "activation.approval_installed",
    "activation.high_water_recovered",
    "activation.unit_granted",
    "activation.high_water_raised",
})


class Refused(Exception):
    """A fixed operator-facing label; never file content or exception text."""


# -- independent readers (private seams; each has its own protected tests) --


def _load_policy() -> ActivationPolicy:
    return load_activation_policy()


def _load_declaration():
    return load_bootstrap_deployment()


def _load_node():
    return load_declared_node()


def _load_evidence():
    return load_commissioning_evidence()


def _load_trust():
    return load_operator_trust()


def _now() -> str:
    # The OS clock. Not trusted time: §3.5 bounds it by the persisted floor.
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_root() -> bool:
    return os.geteuid() == 0


def _step(label: str, operation, *args, **kwargs):
    """Run one reader; any failure becomes `label` and nothing else."""
    try:
        return operation(*args, **kwargs)
    except Refused:
        raise
    except Exception:  # noqa: BLE001 - redacted: labels only, never details
        raise Refused(label) from None


# -- protected file access ---------------------------------------------------


def _directory_ok(fd: int, *, private: bool) -> None:
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != _OWNER
            or info.st_mode & (0o077 if private else 0o022)):
        raise Refused("protected directory refused")


def _open_directory(components, *, private: bool = False) -> int:
    """Walk fixed components from the root without following any link."""
    fd = os.open(_ROOT, _DIR)
    try:
        for component in components:
            _directory_ok(fd, private=False)
            child = os.open(component, _DIR, dir_fd=fd)
            os.close(fd)
            fd = child
        _directory_ok(fd, private=private)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_regular(fd: int, *, limit: int, owner: int | None, private: bool = False) -> bytes:
    """Bounded read of one open regular single-link file that did not change."""
    before = os.fstat(fd)
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or not 0 < before.st_size <= limit
            or (owner is not None and (before.st_uid != owner
                                       or before.st_mode & (0o077 if private else 0o022)))):
        raise Refused("file protection refused")
    data = bytearray()
    while len(data) <= limit:
        part = os.read(fd, min(65536, limit + 1 - len(data)))
        if not part:
            break
        data.extend(part)
    if _stamp(os.fstat(fd)) != _stamp(before) or len(data) != before.st_size:
        raise Refused("file changed while reading")
    return bytes(data)


def _read_protected_at(directory_fd: int, name: str, *, limit: int,
                       private: bool = False) -> bytes:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                 dir_fd=directory_fd)
    try:
        return _read_regular(fd, limit=limit, owner=_OWNER, private=private)
    finally:
        os.close(fd)


def _read_operator_file(path: Path, *, limit: int) -> bytes:
    """An operator-supplied input: a regular single-link file, never a link."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        return _read_regular(fd, limit=limit, owner=None)
    finally:
        os.close(fd)


def _measure_unit_files(units) -> dict[str, bytes]:
    """The vendor unit file bytes, refused when any override or drop-in exists."""
    try:
        return measure_scoped_unit_files(units)
    except UnitOverrideRefused:
        raise Refused("a scoped unit has an override, a non-mask unit file elsewhere "
                      "or a drop-in") from None
    except UnitContentRefused:
        raise Refused("a scoped unit file lacks its grant-marker lines or changed a "
                      "start condition") from None
    except UnitFilesRefused:
        raise Refused("installed unit files unavailable or not protected") from None


def _package_digest(units):
    """`(archive digest, extracted component digests)` when edge-core is in scope.

    `installed_package_components`: the package checks pass, and the
    extracted binary and redirect policy equal both the manifest's component
    digests and the archive's members (#206 P5).
    """
    if EDGE_CORE_UNIT not in units:
        return None
    return installed_package_components(package_root=_ROOT.joinpath(*_EDGE_PACKAGE),
                                        owner_uid=_OWNER)


def _pin_arguments(package) -> dict:
    if package is None:
        return {"package_digest": None, "package_components": None}
    digest, components = package
    return {"package_digest": digest, "package_components": components}


def _store() -> GenerationStore:
    return GenerationStore(_ROOT.joinpath(*_GENERATIONS))


def _ledger_path() -> Path:
    return _ROOT.joinpath(*_STATE, _LEDGER)


def _append(event: dict) -> None:
    AuditLedger(_ledger_path(), private=True).append(event)


# -- measured baseline and independent context --------------------------------


@dataclass(frozen=True)
class _Baseline:
    """What `generation-publish` measured; compared again before publishing."""

    policy: ActivationPolicy
    commissioning_digest: str
    binding: str = field(repr=False)
    tree: dict = field(repr=False)
    package: tuple | None = None

    @property
    def package_digest(self) -> str | None:
        return None if self.package is None else self.package[0]


def _measure_baseline() -> _Baseline:
    policy = _step("activation policy unavailable or refused", _load_policy)
    evidence = _step("verified commissioning evidence unavailable", _load_evidence)
    units = list(policy.units)
    unit_files = _step("installed unit files unavailable or not protected",
                       _measure_unit_files, units)
    package = _step("installed Edge package checks did not pass", _package_digest, units)
    tree = _step("observe-baseline tree refused", build_observe_baseline,
                 units=units, unit_files=unit_files, **_pin_arguments(package))
    return _Baseline(policy, _step("verified commissioning evidence unavailable",
                                   evidence_commissioning_digest, evidence),
                     evidence.binding, tree, package)


@dataclass(frozen=True)
class _Collected:
    policy: ActivationPolicy
    context: ObserveBaselineContext

    @property
    def approval_policy(self) -> ActivationApprovalPolicy:
        return ActivationApprovalPolicy(
            authorized_operators=frozenset(self.policy.operators),
            max_lease_seconds=self.policy.max_lease_seconds,
            unit_scope=frozenset(self.policy.units),
        )


def _current_baseline(policy, unit_files, package, commissioning_digest, binding):
    store = _store()
    current = store.current()
    if current is None:
        raise Refused("no generation is published")
    generation = store.verify(current.number)
    verify_observe_baseline(generation=generation, files=store.read_tree(generation.number),
                            units=list(policy.units), unit_files=unit_files,
                            **_pin_arguments(package))
    if (generation.commissioning_digest != commissioning_digest
            or generation.commissioning_evidence_binding != binding):
        raise Refused("current generation is bound to other commissioning evidence")
    return generation


def _collect_context() -> _Collected:
    """Independent expected context; nothing is taken from an approval."""
    policy = _step("activation policy unavailable or refused", _load_policy)
    declaration = _step("administrator deployment declaration unavailable or refused",
                        _load_declaration)
    node = _step("declared node unavailable or refused", _load_node)
    # The same function the activation pass uses (`activation_pass`).
    node_digest = _step("declared node differs from the deployment declaration",
                        declared_node_binding, declaration, node.node_id)
    evidence = _step("verified commissioning evidence unavailable", _load_evidence)
    commissioning = _step("verified commissioning evidence unavailable",
                          evidence_commissioning_digest, evidence)
    units = list(policy.units)
    unit_files = _step("installed unit files unavailable or not protected",
                       _measure_unit_files, units)
    package = _step("installed Edge package checks did not pass", _package_digest, units)
    generation = _step("current generation is not a verified observe baseline",
                       _current_baseline, policy, unit_files, package, commissioning,
                       evidence.binding)
    context = _step("activation context refused", ObserveBaselineContext,
                    node_digest=node_digest, generation=generation.number,
                    generation_digest=generation.digest, commissioning_digest=commissioning,
                    commissioning_evidence_binding=evidence.binding,
                    policy_digest=policy.policy_digest,
                    security_epoch=declaration.security_epoch)
    return _Collected(policy, context)


# -- terminal confirmation ---------------------------------------------------


def _terminal_line(source, out, prompt: str, limit: int) -> str:
    """One bounded, complete line from an interactive terminal."""
    if not source.isatty():
        raise Refused("interactive terminal confirmation required")
    print(prompt, file=out, flush=True)
    raw = source.buffer.readline(limit + 2)
    if not raw.endswith(b"\n") or len(raw) > limit + 1:
        raise Refused("bounded complete input line required")
    try:
        return raw[:-1].decode("ascii")
    except UnicodeDecodeError:
        raise Refused("confirmation must be ASCII") from None


def _confirm_word(source, out, word: str, what: str) -> None:
    if _terminal_line(source, out, f"Type {word} to confirm {what}:", 16) != word:
        raise Refused("operation not confirmed")


# -- generation-publish ------------------------------------------------------


def run_generation_publish(*, source, out) -> int:
    """Measure, show, confirm twice, re-measure, publish, read back, record."""
    try:
        if not _is_root():
            raise Refused("generation-publish requires root")
        if not source.isatty():
            raise Refused("interactive terminal confirmation required")
        measured = _measure_baseline()
        store = _store()
        latest = _step("generation store unreadable", store.current)
        digest = tree_digest(measured.tree)
        if latest is not None:
            try:
                same = (store.verify(latest.number).digest == digest
                        and store.read_tree(latest.number) == measured.tree
                        and latest.commissioning_digest == measured.commissioning_digest
                        and latest.commissioning_evidence_binding == measured.binding)
            except Exception:  # noqa: BLE001 - unreadable is "not this baseline"
                same = False
            if same:
                print(f"Generation {latest.number} already is this observe baseline "
                      f"({digest}); nothing published.", file=out)
                return 0
        number = 1 if latest is None else latest.number + 1
        print("Observe-baseline generation (azazel-nexus/observe-baseline-generation/v1)",
              file=out)
        print("Units: " + ",".join(measured.policy.units), file=out)
        if measured.package_digest is not None:
            print("Edge package digest: " + measured.package_digest, file=out)
            for name, component in measured.package[1].items():
                print(f"Edge component {name}: {component}", file=out)
        print(f"Next generation number: {number}", file=out)
        print("Generation digest: " + digest, file=out)
        print("Publishing is NOT admission: only an operator's signature over this "
              "digest, installed with `az-activation install`, can name it.", file=out)
        if _terminal_line(source, out, "Re-enter the generation digest (sha256:...):",
                          71) != digest:
            raise Refused("generation digest confirmation differs")
        _confirm_word(source, out, "PUBLISH", "this generation publication")
        if _measure_baseline() != measured:
            raise Refused("measured inputs changed during confirmation")
        try:
            generation = store.create(
                measured.tree, created_at=_now(),
                commissioning_digest=measured.commissioning_digest,
                commissioning_evidence_binding=measured.binding,
                expected_latest_generation=None if latest is None else latest.number,
            )
        except GenerationRefused as error:
            if isinstance(error, GenerationCommitUncertain):
                print("Generation may be published; durability UNCONFIRMED. Inspect the "
                      "store; do not retry automatically. Nothing admitted.", file=out)
                return 2
            raise Refused("generation publication refused; inspect the store") from None
        except Exception:  # noqa: BLE001 - unknown outcome: it may be visible
            print("Generation publication interrupted; it may be published. Inspect the "
                  "store; do not retry automatically. Nothing admitted.", file=out)
            return 2
    except Refused as error:
        print(f"Generation publication refused: {error}. Nothing published.", file=out)
        return 1
    except Exception:  # noqa: BLE001 - before publication; labels only
        print("Generation publication refused. Nothing published.", file=out)
        return 1
    return _after_publication(generation, measured, store, out)


def _after_publication(generation, measured: _Baseline, store, out) -> int:
    """Read back and record a generation that is already published.

    Nothing here may claim "nothing published": every failure exits 2 and
    names the number. The record is appended whether or not the read-back
    verified, with `verified` saying which.
    """
    try:
        current = store.current()
        if current is None or current.number != generation.number:
            raise Refused("another generation became current")
        _current_baseline(measured.policy, _measure_unit_files(list(measured.policy.units)),
                          measured.package, measured.commissioning_digest,
                          measured.binding)
        verified = True
    except Exception:  # noqa: BLE001 - published but not verified; labels only
        verified = False
    try:
        _append({
            "event_type": "activation.generation_published",
            "generation": generation.number,
            "digest": generation.digest,
            "units": list(measured.policy.units),
            "policy_digest": measured.policy.policy_digest,
            "verified": verified,
            "occurred_at": generation.created_at,
            "actor": _ACTOR,
        })
        recorded = True
    except Exception:  # noqa: BLE001 - published, but the record is missing
        recorded = False
    if not verified:
        print(f"Generation {generation.number} published, NOT verified on read-back"
              + ("" if recorded else "; the activation ledger did not record it")
              + ". Inspect the store before any request. Nothing admitted.", file=out)
        return 2
    if not recorded:
        print(f"Generation {generation.number} published, but the activation ledger "
              "did not record it. Inspect the ledger before continuing.", file=out)
        return 2
    print(f"Generation {generation.number} published ({generation.digest}); NOT admitted "
          "and no unit enabled.", file=out)
    return 0


# -- request -----------------------------------------------------------------


def _units_argument(text, policy: ActivationPolicy) -> tuple[str, ...]:
    if text is None:
        return policy.units
    names = text.split(",")
    if (not names or any(not name for name in names) or len(set(names)) != len(names)
            or not set(names) <= set(policy.units)):
        raise Refused("requested units must be a subset of the activation policy scope")
    return tuple(sorted(names))


def _open_output_parent(path: Path) -> tuple[int, str]:
    """The output's parent, walked from `/` without following any link.

    The parent must not be writable by group or others (a shared directory
    such as `/tmp` is refused), so nobody else can swap the name.
    """
    absolute = Path(os.path.abspath(path))
    if absolute.name in {"", ".", ".."}:
        raise Refused("output file name refused")
    fd = os.open("/", _DIR)
    try:
        for component in absolute.parent.parts[1:]:
            child = os.open(component, _DIR, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if info.st_mode & 0o022 or info.st_uid not in {0, os.geteuid()}:
            raise Refused("output directory is shared or foreign")
        return fd, absolute.name
    except BaseException:
        os.close(fd)
        raise


def _write_create_only(path: Path, data: bytes) -> None:
    parent, name = _open_output_parent(path)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                     | os.O_CLOEXEC, 0o600, dir_fd=parent)
        try:
            os.fchmod(fd, 0o600)
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        except BaseException:
            os.close(fd)
            os.unlink(name, dir_fd=parent)
            raise
        os.close(fd)
    finally:
        os.close(parent)


def _summary(payload: bytes, *, operator, approval_id, seq, units, context, granted, expires):
    # The evidence binding and the commissioning digest are not printed.
    return [
        "schema: azazel-nexus/activation-approval/v2",
        f"approval_id: {approval_id}",
        f"operator: {operator}",
        "units: " + ",".join(units),
        f"generation: {context.generation}",
        f"generation_digest: {context.generation_digest}",
        f"node_digest: {context.node_digest}",
        f"policy_digest: {context.policy_digest}",
        f"security_epoch: {context.security_epoch}",
        f"approval_seq: {seq}",
        f"granted_at: {granted}",
        f"expires_at: {expires}",
        f"payload_sha256: {sha256(payload).hexdigest()}",
    ]


def run_request(*, operator, approval_id, seq, valid_for, units, out_path, stderr) -> int:
    """Write the canonical unsigned v2 payload; sign nothing, place nothing."""
    try:
        if type(seq) is not int or seq < 0:
            raise Refused("approval sequence must be a non-negative integer")
        collected = _collect_context()
        policy = collected.policy
        scope = _units_argument(units, policy)
        if type(valid_for) is not int or not 0 < valid_for <= policy.max_lease_seconds:
            raise Refused("validity must be positive and within the policy lease cap")
        if operator not in policy.operators:
            raise Refused("operator is not authorized by the activation policy")
        trust = _step("operator trust unavailable or refused", _load_trust)
        if operator not in trust.public_keys or operator in trust.revoked:
            raise Refused("operator has no active enrolled key")
        granted = _now()
        expires = (parse_bootstrap_time(granted) + timedelta(seconds=valid_for)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        payload = _step("approval payload refused", observe_baseline_payload,
                        context=collected.context, approval_id=approval_id, operator=operator,
                        approval_seq=seq, units=scope, granted_at=granted, expires_at=expires)
        if out_path is not None:
            _step("output file refused (it must not exist)", _write_create_only,
                  Path(out_path), payload)
    except Refused as error:
        print(f"Activation request refused: {error}. Nothing written.", file=stderr)
        return 1
    except Exception:  # noqa: BLE001 - labels only, never exception text
        print("Activation request refused. Nothing written.", file=stderr)
        return 1
    for line in _summary(payload, operator=operator, approval_id=approval_id, seq=seq,
                         units=scope, context=collected.context, granted=granted,
                         expires=expires):
        print(line, file=stderr)
    if out_path is None:
        # #251 L-4: the payload carries the commissioning evidence binding,
        # so it never goes to a terminal or a redirect; only to --out.
        print("Summary only; the payload was NOT written. Rerun with --out FILE (a "
              "create-only 0600 file) to write it; its payload_sha256 will differ, since "
              "granted_at is taken again. Nothing was signed, placed or admitted.",
              file=stderr)
        return 1
    print("Unsigned. Sign it off-host with tools/operator_sign.py --purpose activation and "
          "the payload_sha256 above; install it with az-activation install. Nothing was "
          "signed, placed or admitted.", file=stderr)
    return 0


# -- install -----------------------------------------------------------------


def _ledger_entry():
    try:
        info = os.lstat(_ledger_path())
    except FileNotFoundError:
        return None
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != _OWNER or info.st_nlink != 1
            or info.st_mode & 0o022 or info.st_size > _LEDGER_LIMIT):
        raise Refused("activation ledger protection refused")
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _ledger_history() -> tuple[bool, tuple[int, int, int]]:
    """Whether the activation ledger records a floor, and the highest it records.

    Read-only: protection, one chain verification, unchanged identity. An
    unreadable or broken ledger refuses; it never reads as "no history".
    """
    before = _ledger_entry()
    if before is None:
        return False, (0, 0, 0)
    ledger = AuditLedger(_ledger_path())
    ledger.verify()
    entries = list(ledger)
    if _ledger_entry() != before:
        raise Refused("activation ledger changed while reading")
    history, floors = False, [0, 0, 0]
    for entry in entries:
        if entry.event.get("event_type") not in FLOOR_EVENTS:
            continue
        history = True
        recorded = entry.event.get("high_water")
        if recorded is None:
            continue
        if type(recorded) is not dict:
            raise Refused("activation ledger floor record malformed")
        for index, name in enumerate(("security_epoch", "approval_seq", "generation")):
            value = recorded.get(name)
            if type(value) is not int or value < 0:
                raise Refused("activation ledger floor record malformed")
            floors[index] = max(floors[index], value)
    return history, tuple(floors)


def _read_retained(name: str) -> HighWater:
    """The moved-aside floor, inside the root-only high-water directory (§7 step 3)."""
    if (type(name) is not str or not _RETAINED.fullmatch(name)
            or name in {"high-water.json", ".high-water.json.partial"}):
        raise Refused("retained high-water name refused")
    with high_water._state_directory() as state_fd:
        leaf = high_water._open_leaf(state_fd, create=False)
        if leaf is None:
            raise Refused("retained high-water file unavailable")
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=leaf)
            try:
                high_water._protected(fd, owner=high_water._OWNER, directory=False,
                                      private=True)
                raw = _read_regular(fd, limit=4096, owner=high_water._OWNER)
            finally:
                os.close(fd)
        finally:
            os.close(leaf)
    return decode_high_water(raw)


def _existing_approval(directory_fd: int) -> bool:
    present = []
    for name in _APPROVAL_FILES:
        try:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(info.st_mode):
            raise Refused("installed approval entry is not a regular file")
        present.append(name)
    return bool(present)


def _approval_present() -> bool:
    fd = _open_directory(_APPROVAL_DIRECTORY, private=True)
    try:
        return _existing_approval(fd)
    finally:
        os.close(fd)


class _PlacementUncertain(Exception):
    pass


def _pair_at(directory_fd: int, payload: bytes, signature: bytes) -> bool:
    """Whether the installed pair is byte-for-byte this payload and signature."""
    try:
        return (_read_protected_at(directory_fd, "approval.json", limit=MAX_APPROVAL_BYTES,
                                   private=True) == payload
                and _read_protected_at(directory_fd, "approval.sig", limit=_SIGNATURE_BYTES,
                                       private=True) == signature)
    except FileNotFoundError:
        return False


def _installed_pair_is(payload: bytes, signature: bytes) -> bool:
    fd = _open_directory(_APPROVAL_DIRECTORY, private=True)
    try:
        return _pair_at(fd, payload, signature)
    finally:
        os.close(fd)


def _place_approval(payload: bytes, signature: bytes, *, expect_present: bool,
                    expect_same: bool = False) -> None:
    """Private temporary files, fsync, rename, directory fsync, protected read-back.

    The pair is renamed one after the other; a crash between the renames
    leaves a pair whose signature does not verify, which every reader refuses.
    """
    fd = _open_directory(_APPROVAL_DIRECTORY, private=True)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise Refused("activation approval store is busy") from None
        # Under the exclusive lock: what is installed now must be what the
        # operator confirmed (REPLACE only covers a pair that was shown).
        if _existing_approval(fd) != expect_present:
            raise Refused("installed approval changed after confirmation")
        # A sequence at the floor was accepted only as this exact pair again.
        if expect_same and not _pair_at(fd, payload, signature):
            raise Refused("installed approval changed after confirmation")
        for name, data in zip(_APPROVAL_FILES, (payload, signature)):
            partial = f".{name}.partial"
            try:
                stale = os.stat(partial, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                stale = None
            if stale is not None:
                if not stat.S_ISREG(stale.st_mode):
                    raise Refused("approval partial entry is not a regular file")
                os.unlink(partial, dir_fd=fd)
            out = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                          | os.O_CLOEXEC, 0o600, dir_fd=fd)
            try:
                os.fchmod(out, 0o600)
                view = memoryview(data)
                while view:
                    view = view[os.write(out, view):]
                os.fsync(out)
            finally:
                os.close(out)
        for name in _APPROVAL_FILES:
            os.replace(f".{name}.partial", name, src_dir_fd=fd, dst_dir_fd=fd)
        try:
            os.fsync(fd)
            if (_read_protected_at(fd, "approval.json", limit=MAX_APPROVAL_BYTES,
                                   private=True) != payload
                    or _read_protected_at(fd, "approval.sig", limit=_SIGNATURE_BYTES,
                                          private=True) != signature):
                raise Refused("installed approval read-back differs")
        except Exception:  # noqa: BLE001 - renamed; durability or read-back unconfirmed
            raise _PlacementUncertain() from None
    finally:
        os.close(fd)


def _floor_values(value: HighWater) -> dict:
    return {"security_epoch": value.security_epoch, "approval_seq": value.approval_seq,
            "generation": value.generation, "time_floor": value.time_floor}


def run_install(*, payload_path, signature_path, confirm_sha256, replace, recover,
                source, out) -> int:
    """Verify against fresh context and floors, then place and record (§3.1, §3.5, §7)."""
    stage = "nothing changed"
    try:
        if not _is_root():
            raise Refused("install requires root")
        if type(confirm_sha256) is not str or not _HEX.fullmatch(confirm_sha256):
            raise Refused("--confirm-sha256 must be 64 lowercase hex characters")
        payload = _step("approval payload file refused", _read_operator_file,
                        Path(payload_path), limit=MAX_APPROVAL_BYTES)
        signature = _step("approval signature file refused", _read_operator_file,
                          Path(signature_path), limit=_SIGNATURE_BYTES)
        if len(signature) != _SIGNATURE_BYTES:
            raise Refused("approval signature must be 64 raw bytes")
        if sha256(payload).hexdigest() != confirm_sha256:
            raise Refused("payload SHA-256 differs from --confirm-sha256")

        collected = _collect_context()
        trust = _step("operator trust unavailable or refused", _load_trust)
        now = _now()
        skew = collected.policy.max_clock_skew_seconds
        current = _step("high-water store unavailable or refused", read_high_water)
        retained = None
        if current is not None:
            if recover is not None:
                raise Refused("high-water recovery applies only while high-water.json is absent")
            if (parse_bootstrap_time(now) + timedelta(seconds=skew)
                    < parse_bootstrap_time(current.time_floor)):
                raise Refused("OS clock is behind the high-water time floor")
            floors = (current.security_epoch, current.approval_seq, current.generation)
            mode = "raised"
        else:
            history, archived = _step("activation ledger unreadable or refused",
                                      _ledger_history)
            if recover is None:
                if history:
                    raise Refused("high water absent on a node with activation history; "
                                  "follow the recovery procedure (docs §7)")
                floors, mode = (0, 0, 0), "initialized"
            else:
                retained = _step("retained high-water file refused", _read_retained, recover)
                floors = tuple(max(a, b) for a, b in zip(archived, (
                    retained.security_epoch, retained.approval_seq, retained.generation)))
                mode = "recovered"
        try:
            approved = verify_observe_baseline_approval(
                trust=trust, expected=collected.context, policy=collected.approval_policy,
                payload=payload, signature=signature, now=now,
                security_epoch_floor=floors[0], approval_seq_floor=floors[1])
        except ApprovalRefused as error:
            # The verifier's messages are fixed, redacted labels.
            raise Refused(str(error)) from None
        if collected.context.generation < floors[2]:
            raise Refused("approved generation below the high-water floor")
        # #251 L-3: once a floor exists, a sequence at the floor is already
        # spent. Only the exact installed pair may be placed again (idempotent);
        # any other approval needs a sequence above the floor. The pass's own
        # check (`seq < floor` refuses) is unchanged, so the installed
        # approval, whose sequence the floor now equals, still verifies.
        reinstall = False
        if (current is not None or retained is not None) and approved.approval_seq <= floors[1]:
            reinstall = _step("activation approval directory unavailable or not private",
                              _installed_pair_is, payload, signature)
            if not reinstall:
                raise Refused("approval sequence not above the high-water floor; only the "
                              "installed approval may be installed again")
        time_floor = now
        if current is not None and parse_bootstrap_time(current.time_floor) > parse_bootstrap_time(now):
            time_floor = current.time_floor
        new_floor = HighWater(
            security_epoch=max(floors[0], approved.security_epoch),
            approval_seq=max(floors[1], approved.approval_seq),
            generation=max(floors[2], collected.context.generation),
            time_floor=time_floor,
        )
        present = _step("activation approval directory unavailable or not private",
                        _approval_present)
        if present and not replace:
            raise Refused("an approval is already installed; use --replace")
        lease = approved.lease
        print("Verified observe-baseline approval (signature, policy, context, floors):",
              file=out)
        print(f"approval_id: {approved.approval_id}", file=out)
        print(f"operator: {lease.granted_by}", file=out)
        print("units: " + ",".join(sorted(lease.units)), file=out)
        print(f"generation: {lease.generation_number} ({lease.generation_digest})", file=out)
        print(f"security_epoch: {approved.security_epoch}  approval_seq: "
              f"{approved.approval_seq}", file=out)
        print(f"valid: {lease.granted_at} .. {lease.expires_at}", file=out)
        print(f"high water ({mode}): epoch {new_floor.security_epoch}, seq "
              f"{new_floor.approval_seq}, generation {new_floor.generation}, time floor "
              f"{new_floor.time_floor}", file=out)
        if present:
            print("An approval is already installed and would be REPLACED.", file=out)
            _confirm_word(source, out, "REPLACE", "replacing the installed approval")
        if retained is not None:
            print("HIGH-WATER RECOVERY (docs/activation-observe-baseline.md §7). Retained "
                  f"floor: epoch {retained.security_epoch}, seq {retained.approval_seq}, "
                  f"generation {retained.generation}, time floor {retained.time_floor}.",
                  file=out)
            print(f"New time floor from this node's clock: {now}. Confirm it against an "
                  "independent time source first; counters never go below the retained "
                  "file or the ledger.", file=out)
            _confirm_word(source, out, "RECOVER", "re-initializing the high water")

        # Nothing was written yet. Re-collect and compare before touching state.
        if (_collect_context() != collected or _step(
                "operator trust unavailable or refused", _load_trust) != trust
                or _step("high-water store unavailable or refused", read_high_water) != current
                or _step("activation approval directory unavailable or not private",
                         _approval_present) != present):
            raise Refused("node context changed during confirmation")
        if retained is not None:
            stage = "recovery recorded; high water not yet written"
            _step("activation ledger refused the recovery record", _append, {
                "event_type": "activation.high_water_recovered",
                "retained": _floor_values(retained),
                "ledger_floors": dict(zip(("security_epoch", "approval_seq", "generation"),
                                          archived)),
                "high_water": _floor_values(new_floor),
                "occurred_at": now,
                "actor": _ACTOR,
            })
        stage = "high water may be written; approval not placed"
        if current is None:
            initialize_high_water(new_floor, now=now, skew_seconds=skew)
        else:
            raise_high_water(new_floor, now=now, skew_seconds=skew)
        stage = "high water written; approval placement unconfirmed"
        _place_approval(payload, signature, expect_present=present, expect_same=reinstall)
        stage = "approval placed; activation ledger record missing"
        _step("activation ledger refused the install record", _append, {
            "event_type": "activation.approval_installed",
            "approval_id": approved.approval_id,
            "operator": lease.granted_by,
            "units": sorted(lease.units),
            "generation": lease.generation_number,
            "generation_digest": lease.generation_digest,
            "security_epoch": approved.security_epoch,
            "approval_seq": approved.approval_seq,
            "granted_at": lease.granted_at,
            "expires_at": lease.expires_at,
            "payload_sha256": "sha256:" + confirm_sha256,
            "replaced": present,
            "high_water": {"mode": mode, **_floor_values(new_floor)},
            "occurred_at": now,
            "actor": _ACTOR,
        })
    except (HighWaterCommitUncertain, _PlacementUncertain):
        print(f"Install interrupted with durability UNCONFIRMED ({stage}). Inspect "
              "/etc/azazel/activation and the high water; do not retry automatically. "
              "Nothing admitted.", file=out)
        return 2
    except Refused as error:
        if stage != "nothing changed":
            print(f"Install stopped: {error} ({stage}). Inspect before retrying. "
                  "Nothing admitted.", file=out)
            return 2
        print(f"Approval install refused: {error}. Nothing changed.", file=out)
        return 1
    except Exception:  # noqa: BLE001 - e.g. a high-water refusal; labels only
        if stage != "nothing changed":
            print(f"Install stopped ({stage}). Inspect before retrying. Nothing admitted.",
                  file=out)
            return 2
        print("Approval install refused. Nothing changed.", file=out)
        return 1
    print("Approval installed. This is NOT a grant: the activation pass verifies it again "
          "on every boot, with health and its own gates.", file=out)
    return 0


# -- entry point -------------------------------------------------------------


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="az-activation",
        description="Observe-baseline activation tooling; publishes, requests or installs, "
                    "never grants.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("generation-publish",
                        help="publish the observe-baseline generation (root, interactive)")
    request = commands.add_parser("request", help="write the unsigned v2 approval payload")
    request.add_argument("--operator", required=True)
    request.add_argument("--approval-id", required=True)
    request.add_argument("--seq", required=True, type=int)
    request.add_argument("--valid-for", required=True, type=int, metavar="SECONDS")
    request.add_argument("--units", help="comma-separated subset of the policy scope")
    request.add_argument("--out", help="create-only 0600 file for the payload; without it "
                         "only a summary is printed and nothing is written")
    install = commands.add_parser("install", help="verify and place a signed approval (root)")
    install.add_argument("--payload", required=True)
    install.add_argument("--signature", required=True)
    install.add_argument("--confirm-sha256", required=True)
    install.add_argument("--replace", action="store_true")
    install.add_argument("--recover-high-water", metavar="RETAINED_NAME",
                         help="docs §7: name of the moved-aside high-water file")
    args = parser.parse_args(argv)
    if args.command == "generation-publish":
        return run_generation_publish(source=sys.stdin, out=sys.stdout)
    if args.command == "request":
        return run_request(operator=args.operator, approval_id=args.approval_id,
                           seq=args.seq, valid_for=args.valid_for, units=args.units,
                           out_path=args.out, stderr=sys.stderr)
    return run_install(payload_path=args.payload, signature_path=args.signature,
                       confirm_sha256=args.confirm_sha256, replace=args.replace,
                       recover=args.recover_high_water, source=sys.stdin, out=sys.stdout)


if __name__ == "__main__":
    raise SystemExit(main())
