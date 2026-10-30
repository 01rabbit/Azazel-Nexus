"""Local commissioning challenges; no trust-store mutation lives here.

The only input name is a fixed leaf in the commissioning directory. A
confirmation consumes its challenge even when it fails. The operation receives
an immutable copy of the bytes whose fingerprint the operator confirmed.

Interactive confirmation guards human intent against accidental/non-root use,
not against a malicious root process. A ROOT caller receives both the nonce
and confirmation words and can confirm without the CLI or a TTY. The shipped
CLI (`lite_trust_ops.run_repin`) drives this class in its own narrowed
process; `az-commissiond` serves the same two verbs on its socket.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from .principal import Principal, PrincipalClass
from .protocol import Refusal, RequestRefused

ANCHOR_FILENAME = "repin-anchor.json"
REASONS = ("rotation", "recovery", "compromise")
CHALLENGE_SECONDS = 60.0
MAX_ANCHOR_BYTES = 64 * 1024
MAX_CHALLENGES = 32


@dataclass(frozen=True)
class RepinRequestLike:
    new_anchor_path: Path
    reason: str
    principal: str


@dataclass(frozen=True)
class ConfirmationLike:
    nonce: str
    confirmed_at: str


class OutcomeLike(Protocol):
    promoted: bool
    generation: int


@dataclass(frozen=True)
class _Challenge:
    principal: Principal
    reason: str
    digest: str
    echo: str
    expires: float


def _refuse() -> None:
    # Never return an exception, file content, reason, path or library outcome
    # as a refusal detail: the shared transport may record that detail.
    raise RequestRefused(Refusal.ARGUMENT_RANGE, "repin_confirmation")


def production_repin(request: RepinRequestLike, confirmation: ConfirmationLike) -> OutcomeLike:
    """Adapt confirmed runtime evidence to the library's fixed production store."""
    from azazel_nexus.audit import AuditLedger
    from azazel_nexus.lite_trust import RepinConfirmation as LibraryConfirmation
    from azazel_nexus.lite_trust import RepinRequest, TrustStore

    from .runtime_paths import commission_ledger_path, lite_trust_root

    return TrustStore(lite_trust_root()).repin(
        RepinRequest(request.new_anchor_path, request.reason, request.principal),
        confirmation=LibraryConfirmation(confirmation.nonce, confirmation.confirmed_at),
        ledger=AuditLedger(commission_ledger_path()),
        now=confirmation.confirmed_at,
    )


class RepinConfirmation:
    def __init__(
        self,
        *,
        commissioning_dir: Path,
        snapshot_dir: Path,
        repin: Callable[[RepinRequestLike, ConfirmationLike], OutcomeLike] = production_repin,
        clock: Callable[[], float] = time.monotonic,
        now: Callable[[], str] = lambda: datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    ) -> None:
        self.commissioning_dir = commissioning_dir
        self.snapshot_dir = snapshot_dir
        self.repin = repin
        self.clock = clock
        self.now = now
        # Not thread-safe: relies on single-threaded serve_forever dispatch.
        self._pending: dict[str, _Challenge] = {}

    @staticmethod
    def _root(principal: Principal) -> None:
        # None means credentials were not checked, never an admitted root.
        if (type(principal) is not Principal or principal.uid != 0
                or PrincipalClass.ROOT not in principal.classes):
            raise RequestRefused(Refusal.PRINCIPAL_DENIED)

    def _read_anchor(self) -> bytes:
        directory = os.open(self.commissioning_dir,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            fd = os.open(ANCHOR_FILENAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                         | os.O_CLOEXEC, dir_fd=directory)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ANCHOR_BYTES:
                    _refuse()
                content = stream.read(MAX_ANCHOR_BYTES + 1)
                if not content or len(content) > MAX_ANCHOR_BYTES:
                    _refuse()
                return content
        finally:
            os.close(directory)

    def challenge(self, principal: Principal, reason: str, new_anchor_file: str) -> dict:
        self._root(principal)
        if reason not in REASONS or new_anchor_file != ANCHOR_FILENAME:
            _refuse()
        try:
            digest = "sha256:" + hashlib.sha256(self._read_anchor()).hexdigest()
            now = self.clock()
            self._pending = {key: value for key, value in self._pending.items()
                             if value.expires > now}
            if len(self._pending) >= MAX_CHALLENGES:
                _refuse()
            nonce = "sha256:" + secrets.token_hex(32)
            # IDENTIFIER grammar, human-readable words plus fresh random text.
            echo = "REPIN-TRUST-" + secrets.token_hex(8)
            self._pending[nonce] = _Challenge(principal, reason, digest, echo,
                                              now + CHALLENGE_SECONDS)
            return {"nonce": nonce, "reason": reason, "new_fingerprint": digest,
                    "confirmation_words": echo, "expires_in": CHALLENGE_SECONDS}
        except (OSError, ValueError):
            _refuse()

    def confirm(self, principal: Principal, nonce: str, echo: str) -> dict:
        self._root(principal)
        pending = self._pending.pop(nonce, None)
        if (pending is None or self.clock() >= pending.expires
                or principal != pending.principal
                or not hmac.compare_digest(echo, pending.echo)):
            _refuse()
        snapshot = None
        result = None
        try:
            content = self._read_anchor()
            digest = "sha256:" + hashlib.sha256(content).hexdigest()
            if not hmac.compare_digest(digest, pending.digest):
                _refuse()
            # Separate daemon-owned state directory. O_EXCL/0600 prevents a
            # second local principal from replacing the confirmed file before
            # the library opens it. The fixed input file is never passed on.
            directory = os.open(self.snapshot_dir, os.O_RDONLY | os.O_DIRECTORY
                                | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                info = os.fstat(directory)
                if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                    _refuse()
                leaf = ".repin-" + secrets.token_hex(16)
                fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
                snapshot = self.snapshot_dir / leaf
            finally:
                os.close(directory)
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            outcome = self.repin(
                RepinRequestLike(snapshot, pending.reason, "root"),
                ConfirmationLike(nonce, self.now()),
            )
            # Library reason strings, fingerprints and exception text are not
            # response fields. Only typed outcome values cross this boundary;
            # cleanup below may add a fixed boolean.
            if (type(outcome.promoted) is not bool or type(outcome.generation) is not int
                    or outcome.generation < 0):
                _refuse()
            result = {"promoted": outcome.promoted, "generation": outcome.generation}
        except Exception as error:
            # Library refusals can include file contents or key parser text.
            # Keep them out of replies, refusal sinks and journal tracebacks.
            raise RequestRefused(Refusal.ARGUMENT_RANGE, "repin_confirmation") from error
        finally:
            if snapshot is not None:
                try:
                    snapshot.unlink(missing_ok=True)
                except OSError:
                    # Cleanup cannot undo a committed promotion or mask an
                    # in-flight exception. Expose only a fixed boolean on a
                    # completed operation; never return paths/error text.
                    if result is not None:
                        result["cleanup_failed"] = True
        return result
