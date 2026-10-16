"""Held-file withdrawal binding; no production opener or grant authority."""

import os
import uuid
from hashlib import sha256
from pathlib import Path

from azazel_nexus.bootstrap_grant_transaction import GrantTransaction
from azazel_nexus.bootstrap_lock import BootstrapTransactionGuard
from azazel_nexus.bootstrap_overlay_journal import (
    OverlayIntent,
    OverlayJournal,
    advance_overlay,
    encode_overlay_journal,
)
from azazel_nexus.operator_trust import ApprovalRefused

from .bootstrap_overlay_files import _closing_candidate, _present
from .bootstrap_restore_files import BootstrapRestoredOverlayFiles
from .bootstrap_withdraw_files import _withdraw_candidates_at, _withdraw_paths
from .units import UNIT_NAMES, UnitKey
from .bootstrap_directory_paths import bind_directory_path


class BootstrapWithdrawalFiles:
    """Borrowed protected descriptors and lock, retained through restoration.

    Only trusted composition constructs this object. Binding a transaction
    selects existing ownership; it does not authenticate caller authorization.
    Missing journals refuse, including before any grant; no ownership guessed.
    """

    def __init__(self, *, overlay_fd, masks_fd, higher_priority_fd, transient_fd,
                 generator_early_fd, overlay_path, masks_path, higher_priority_path,
                 transient_path, generator_early_path, journal_store, guard, owner_uid):
        if type(guard) is not BootstrapTransactionGuard:
            raise ApprovalRefused("held withdrawal guard required")
        self._args = dict(overlay_fd=overlay_fd, masks_fd=masks_fd,
                          higher_priority_fd=higher_priority_fd, transient_fd=transient_fd,
                          generator_early_fd=generator_early_fd, owner_uid=owner_uid)
        self._path_args = dict(overlay_path=overlay_path, masks_path=masks_path,
                               higher_priority_path=higher_priority_path,
                               transient_path=transient_path, generator_early_path=generator_early_path)
        self._store, self._guard = journal_store, guard
        self._intent = None
        self._owned = None
        self._stamps = None
        self._selected_transaction = None

    def bind(self, transaction):
        self._selected_transaction = None
        if type(transaction) is not GrantTransaction:
            raise ApprovalRefused("exact grant transaction required")
        expected = OverlayIntent(
            boot_id=transaction.boot_id, context_digest=transaction.context_digest[7:],
            grant_id=transaction.grant_id, payload_digests=transaction.unit_payload_digests,
        )
        self._bind_intent(expected)
        self._selected_transaction = transaction

    def _bind_intent(self, expected):
        self._guard()
        current = self._store.load()
        if (type(current) is not OverlayJournal or current.intent != expected
                or current.phase not in {"closing", "withdrawing", "closed"}):
            raise ApprovalRefused("withdrawal does not own retained overlay intent")
        self._intent = expected
        self._owned = current.owned_files
        self._stamps = _withdraw_paths(**self._args)
        self.check()

    def resume_closure(self):
        """Select retained narrowing state, not authority to remove a grant.

        A fresh controller may re-establish a masked fence from the protected
        journal. Actual unlink still requires bind(transaction) and its match.
        """
        self._selected_transaction = None
        self._guard()
        current = self._store.load_optional()
        if current is None:
            if self._intent is not None:
                raise ApprovalRefused("retained withdrawal journal disappeared")
            return False
        if type(current) is not OverlayJournal:
            raise ApprovalRefused("retained closure journal required")
        if current.phase not in {"withdrawing", "closed"}:
            return False
        self._bind_intent(current.intent)
        return True

    def retire_prior_boot(self, expected, current_boot_id, record_retirement):
        """Remove a journal that provably belongs to a finished earlier boot.

        Grants no authority: it only deletes a moot record. The caller must
        pass the kernel boot id (canonical lowercase UUID); injection is for
        tests. `record_retirement` is a required audit step called with one
        summary mapping (event "retiring", phase, boot_id, grant_id,
        context_digest, journal_sha256; no payload) before any mutation; it
        must return normally or the journal is left untouched. The record
        announces an attempt, not completion: a later failure or retry may
        produce repeated records, which callers must treat as idempotent.
        """
        self._guard()
        if (type(expected) is not OverlayJournal or not callable(record_retirement)):
            raise ApprovalRefused("prior boot journal retirement arguments refused")
        try:
            if (type(current_boot_id) is not str
                    or str(uuid.UUID(current_boot_id)) != current_boot_id):
                raise ValueError
        except (ValueError, AttributeError, TypeError):
            raise ApprovalRefused("prior boot journal current boot id refused") from None
        current = self._store.load()
        if current != expected:
            raise ApprovalRefused("prior boot journal differs from expected")
        if current.intent.boot_id == current_boot_id:
            raise ApprovalRefused("prior boot journal belongs to current boot")
        stamps = _withdraw_paths(**self._args)
        if self._stamps is not None and stamps != self._stamps:
            raise ApprovalRefused("prior boot journal retirement masks changed")
        if current.phase not in {"closed", "published", "closing", "withdrawing"}:
            raise ApprovalRefused("prior boot journal phase refused")

        def pair_absent():
            if any(_present(self._args["overlay_fd"], UNIT_NAMES[key])
                   for key in (UnitKey.AUDITD, UnitKey.COMMISSIOND)):
                raise ApprovalRefused("prior boot journal retirement pair entry present")

        def stable(journal):
            self._guard()
            pair_absent()
            if self._store.load() != journal:
                raise ApprovalRefused("prior boot journal changed during retirement")
            if _withdraw_paths(**self._args) != stamps:
                raise ApprovalRefused("prior boot journal retirement masks changed")

        stable(expected)
        try:
            record_retirement({
                "event": "retiring",
                "phase": current.phase,
                "boot_id": current.intent.boot_id,
                "grant_id": current.intent.grant_id,
                "context_digest": current.intent.context_digest,
                "journal_sha256": sha256(encode_overlay_journal(current)).hexdigest(),
            })
        except Exception:
            raise ApprovalRefused("prior boot journal audit record refused") from None
        stable(expected)
        closed = current
        try:
            if current.phase != "closed":
                closed = advance_overlay(current, "reboot-reset")
                self._store.replace(current, closed)
                self._guard()
                if self._store.load() != closed:
                    raise ApprovalRefused("prior boot journal reset not confirmed")
            stable(closed)
            self._store.remove(closed)
        finally:
            # Once mutation began no bound ownership may outlive the journal.
            self._intent = None
            self._owned = None
            self._stamps = None
            self._selected_transaction = None

    def close(self):
        # No truncation or ownership transition: all present entries must
        # already be owned empty masks and all missing ones persistently masked.
        self.check()
        if self._store.load().phase not in {"withdrawing", "closed"}:
            raise ApprovalRefused("resumed closure phase refused")

    def check(self):
        self._guard()
        if self._intent is None:
            raise ApprovalRefused("withdrawal transaction not bound")
        for name in ("overlay", "masks", "higher_priority", "transient", "generator_early"):
            path = Path(self._path_args[name + "_path"])
            bind_directory_path(path, self._args[name + "_fd"])
        current = self._store.load()
        if (current.intent != self._intent or current.phase not in {"closing", "withdrawing", "closed"}
                or (current.phase != "closed" and current.owned_files != self._owned)
                or _withdraw_paths(**self._args) != self._stamps):
            raise ApprovalRefused("withdrawal identity or paths changed")
        owned = {unit: (dev, ino, digest) for unit, dev, ino, digest in current.owned_files}
        fragments = []
        for key in (UnitKey.AUDITD, UnitKey.COMMISSIOND):
            unit = UNIT_NAMES[key]
            present = _present(self._args["overlay_fd"], unit)
            if present:
                if unit not in owned:
                    raise ApprovalRefused("unowned withdrawal entry")
                dev, ino, digest = owned[unit]
                with _closing_candidate(self._args["overlay_fd"], unit, (dev, ino), digest,
                                        owner_uid=self._args["owner_uid"], allow_empty=True) as fd:
                    if os.fstat(fd).st_size != 0:
                        raise ApprovalRefused("withdrawal mask not empty")
            elif unit in owned and current.phase == "closing":
                raise ApprovalRefused("withdrawal entry missing before intent")
            path = self._path_args["overlay_path" if present else "masks_path"]
            fragments.append((key, str(Path(path) / unit)))
        self._guard()
        if self._store.load() != current or _withdraw_paths(**self._args) != self._stamps:
            raise ApprovalRefused("withdrawal observation changed")
        return tuple(fragments)

    def withdraw(self, check_contained):
        if type(self._selected_transaction) is not GrantTransaction:
            raise ApprovalRefused("withdrawal requires explicit grant selection")
        self.check()
        if self._store.load().phase != "closed":
            _withdraw_candidates_at(**self._args, journal_store=self._store,
                                    guard=self._guard, check_contained=check_contained)
        self.check()
        return BootstrapRestoredOverlayFiles(
            **self._args, **self._path_args, journal_store=self._store, guard=self._guard,
        )
