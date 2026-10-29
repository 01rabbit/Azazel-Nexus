"""ROOT-only acceptance of a signed Knowledge Lite revocation list (assess-c P4).

`az-commissiond` already owns the Knowledge Lite trust root
(`/var/lib/azazel/lite-trust`, its only writer) and its ROOT-only trust verb
(`trust.repin.*`). Accepting a cumulative revocation list is the same kind of
change to the same root, so it is a second verb of the same daemon, admitted
for ROOT only, with no new account, socket, path argument or approval.

* **The statement is the authority.** It must verify under the commissioned
  revocation policy (`RevocationStore.accept`: threshold of distinct
  revocation-signing keys, payload generation, a sequence above the one in
  force, nothing re-enabled, no self-revocation). Root chooses *when*, never
  *what* is trusted.
* **One fixed input.** The only input name is a fixed leaf in the
  commissioning directory, read without following links and bounded, as the
  repin anchor is. A caller cannot name a path.
* **Audit first.** `knowledge.lite.revocation_requested` is appended to
  `az-auditd` before the store is touched; if that fails nothing is written.
  The outcome (`..._accepted` / `..._refused`) follows; if that append fails
  the acceptance stands (more revocation only closes) and the reply says the
  audit is incomplete.
* **Readable by the reader.** The written files take `trust.json`'s owner,
  group and mode (`RevocationStore._metadata`), so `knowledge-lited` reads
  `revoked` rather than `unverified` (F3 of the 2026-10-28 rehearsal).
"""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path

from .principal import Principal, PrincipalClass
from .protocol import Refusal, RequestRefused

__all__ = [
    "MAX_REVOCATION_BYTES",
    "REVOCATION_INPUT",
    "RevocationAcceptance",
    "production_revocation_accept",
]

#: The fixed leaf in the commissioning directory root installs a list into.
REVOCATION_INPUT = "lite-revocations.signed"
#: About four thousand revoked digests; a list is cumulative, never unbounded.
MAX_REVOCATION_BYTES = 256 * 1024


def production_revocation_accept(blob: bytes):
    """Accept into the fixed production trust root."""

    from azazel_nexus.lite_import import CommissionedTrust

    from .runtime_paths import lite_trust_root

    return CommissionedTrust(lite_trust_root()).accept_revocation(blob)


def _refuse() -> None:
    # Fixed detail: file contents, key parser output and library text never
    # reach a reply or the shared refusal sink.
    raise RequestRefused(Refusal.ARGUMENT_RANGE, "revocation")


def _code(error: Exception) -> str:
    """A fixed word for why a statement was not accepted."""

    from azazel_nexus.lite_import import TrustUnusable

    if isinstance(error, TrustUnusable):
        return "trust_unreadable"
    text = str(error)
    if "replay refused" in text:
        return "replay"
    if "cannot be re-enabled" in text:
        return "re_enable"
    return "unverified"


class RevocationAcceptance:
    def __init__(
        self,
        *,
        commissioning_dir: Path,
        accept: Callable[[bytes], object] = production_revocation_accept,
        append: Callable[[Mapping], None] | None = None,
        now: Callable[[], str] = lambda: datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    ) -> None:
        if append is None:
            from .lite_audit import append_event as append
        self.commissioning_dir = commissioning_dir
        self.accept_statement = accept
        self.append = append
        self.now = now

    @staticmethod
    def _root(principal: Principal) -> None:
        if (type(principal) is not Principal or principal.uid != 0
                or PrincipalClass.ROOT not in principal.classes):
            raise RequestRefused(Refusal.PRINCIPAL_DENIED)

    def _read_input(self) -> bytes:
        directory = os.open(self.commissioning_dir,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            fd = os.open(REVOCATION_INPUT, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                         | os.O_CLOEXEC, dir_fd=directory)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REVOCATION_BYTES:
                    _refuse()
                content = stream.read(MAX_REVOCATION_BYTES + 1)
        finally:
            os.close(directory)
        if not content or len(content) > MAX_REVOCATION_BYTES:
            _refuse()
        return content

    def accept(self, principal: Principal, revocation_file: str) -> dict:
        from azazel_nexus.lite_import import TrustUnusable
        from azazel_nexus.revocation import RevocationRefused, parse_signed

        self._root(principal)
        if revocation_file != REVOCATION_INPUT:
            _refuse()
        try:
            blob = self._read_input()
        except OSError:
            _refuse()
        digest = "sha256:" + hashlib.sha256(blob).hexdigest()
        now = self.now()
        try:
            self.append({"event_type": "knowledge.lite.revocation_requested",
                         "statement_digest": digest, "occurred_at": now})
        except Exception:  # noqa: BLE001 - no record, no change
            return {"accepted": False, "code": "audit_unavailable", "sequence": None,
                    "audit_complete": False}
        try:
            parse_signed(blob)
        except RevocationRefused:
            return self._refused(digest, now, "malformed")
        try:
            accepted = self.accept_statement(blob)
        except (RevocationRefused, TrustUnusable) as error:
            return self._refused(digest, now, _code(error))
        except Exception:  # noqa: BLE001 - never a library text or traceback
            return self._refused(digest, now, "unverified")
        result = {"accepted": True, "code": None, "sequence": accepted.sequence,
                  "audit_complete": True}
        try:
            self.append({
                "event_type": "knowledge.lite.revocation_accepted",
                "statement_digest": digest, "sequence": accepted.sequence,
                "generation": accepted.generation,
                "revoked_digests": len(accepted.revoked_digests),
                "revoked_generations": len(accepted.revoked_generations),
                "revoked_keys": len(accepted.revoked_keys),
                "occurred_at": now,
            })
        except Exception:  # noqa: BLE001 - the acceptance stands
            result["audit_complete"] = False
        return result

    def _refused(self, digest: str, now: str, code: str) -> dict:
        result = {"accepted": False, "code": code, "sequence": None, "audit_complete": True}
        try:
            self.append({"event_type": "knowledge.lite.revocation_refused",
                         "statement_digest": digest, "code": code, "occurred_at": now})
        except Exception:  # noqa: BLE001 - nothing changed either way
            result["audit_complete"] = False
        return result
