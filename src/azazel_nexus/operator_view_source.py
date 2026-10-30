"""The read adapter that connects `operator_view` to the status read model (S-04).

`operator_view.build_view` is a pure function of facts; until now nothing in
the product called it, so the catalog, the import stages, the admission
gates and the operator's next confirmations reached neither `status` nor the
UI. This module is the one place that gathers those facts for `status`:

    read adapter (here) -> versioned status section (`operator_view`)
                        -> UI projection (`ui_model`)

What it reads, each read-only and each through an existing reader:

* the model store (`/var/lib/azazel/models`, `0750 root:azmio`): its trust
  descriptor, its signed catalog, the inbox listing, the installed
  generation record -- through `gather_facts` over `_RecordedState`, whose
  `reading_for` never opens or hashes an artifact (an installed model is
  "recorded at promotion, not re-verified here", never `present`). A
  catalog that is refused (unsigned, invalid, unreadable) keeps its fixed
  code and is never shown as not presented;
* the Core reserve record (`core_reserve.load_reserve`, HG-05);
* the M.I.O. entry service's operator snapshot, already read for the status
  view (its recorded ceiling and the local route's admission reason);
* the build switch `model_admission.LOCAL_MODEL_ADMISSION_ENABLED`.

**It never writes, imports, admits, hashes an artifact or calls a daemon.**
A source the reading account may not open is said so: the section names the
access word for each input (`readable`, `absent`, `permission_denied`,
`refused`, `not_read`), and `operator_view` turns an unread input into a row
that says *not read* -- never into `absent`, `empty` or zero. The UI's
account `azui` reads none of the model store, the reserve record or the
remote consent, so on a node the UI shows those rows as not read, while the
admission gates it can read (the build switch, entryd's record through the
UI copy of its snapshot) are shown as they are.

The remote consent record is the entry service's (root-only state); this
adapter does not read it, and the consent row says not read.

**Versioning (M23).** The section carries its own schema,
`azazel-nexus/status-view/operator-view/1`, inside `status-view/1`. A field
added to it is additive (readers copy by allowlist and ignore what they do
not list); a field removed or a word whose meaning changes is a new
`/2`, which the UI refuses rather than misreads.
"""

from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path
from typing import Optional

__all__ = ["SCHEMA", "MAX_MODELS", "ACCESS_WORDS", "read_section"]

SCHEMA = "azazel-nexus/status-view/operator-view/1"

#: At most this many catalog entries are shown; the rest are counted.
MAX_MODELS = 16

#: What reading each input came to.
ACCESS_WORDS = frozenset({"readable", "absent", "permission_denied", "refused", "not_read",
                          "stale", "not_recorded", "unsigned", "invalid", "unreadable"})

#: The inputs whose state decides what the section can say. The remote
#: consent is the entry service's own state, which this adapter never reads;
#: its row says so, and it does not make the section partial.
DECISIVE_INPUTS = ("model_store", "core_reserve", "mio_entry_record")

#: entryd's recorded local-route reasons (`mio_capability.HealthReason`, the
#: closed set `mio_status.HEALTH_REASONS`) that name a refusing gate.
_LOCAL_REASONS = frozenset({"not_admitted", "no_admission_evidence", "unavailable"})

#: entryd's recorded ceiling (CapabilityState) -> the profile it came from
#: (`mio_capability.read_capability`'s own table, read backwards).
_CEILING_PROFILE = {"CORE": "core", "LITE": "local-only", "FULL": "fastest-permitted"}


def _root(root) -> Path:
    return Path(os.environ.get("AZAZEL_ROOT", "/")) if root is None else Path(root)


def _access_of(exc: BaseException) -> str:
    if isinstance(exc, PermissionError):
        return "permission_denied"
    if isinstance(exc, FileNotFoundError):
        return "absent"
    cause = exc.__cause__ or exc.__context__
    if isinstance(cause, PermissionError):
        return "permission_denied"
    return "refused"


def _readable_directory(path: Path) -> str:
    try:
        os.stat(path)
    except PermissionError:
        return "permission_denied"
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "refused"
    return "readable" if os.access(path, os.R_OK | os.X_OK) else "permission_denied"


def _catalog(models: Path) -> dict:
    """What reading the model store came to. Never raises.

    `access` is the word for the store; `service` (read verbs only) is set
    when the catalog may be shown; `empty` says a trusted catalog offered
    nothing (which is not absent).
    """

    from .model_catalog import CatalogRefused
    from .model_import import CommissionedModels, ModelImport
    from .model_paths import load_model_trust

    result = {"access": _readable_directory(models), "service": None, "model_ids": (),
              "omitted": 0, "quarantined": 0, "empty": False}
    if result["access"] == "absent":
        # No model store is a node never set up for models: the catalog is
        # absent, which is an answer, not an unread input.
        result["access"] = "readable"
        return result
    if result["access"] != "readable":
        return result
    try:
        keys, digest, _ = load_model_trust(models / "trust/trust.json")
    except Exception as exc:  # noqa: BLE001 - a fixed word, never the text
        access = _access_of(exc)
        # No trust descriptor is a node never commissioned for models: the
        # catalog is absent, which is an answer. Any other failure is not.
        result["access"] = "readable" if access == "absent" else access
        return result
    commissioned = CommissionedModels(models, keys, digest)
    for directory in (commissioned.inbox, commissioned.root / "state", commissioned.quarantine):
        word = _readable_directory(directory)
        if word not in ("readable", "absent"):
            result["access"] = word
            return result
    try:
        catalog = commissioned.catalog()
        entries = catalog.entries
    except CatalogRefused as refused:
        word = _catalog_refusal(refused)
        if word != "not_presented":
            # A refused catalog is never shown as absent (R389-06): the fixed
            # code says why, and nothing else is listed from it.
            result["access"] = word
            return result
        catalog, entries = None, None
    except Exception as exc:  # noqa: BLE001
        result["access"] = _access_of(exc)
        return result
    ids = sorted(entry.model_id for entry in entries or ())
    try:
        quarantined = (sum(1 for _ in os.scandir(commissioned.quarantine))
                       if commissioned.quarantine.is_dir() else 0)
    except OSError:
        result["access"] = "refused"
        return result
    result.update(service=_RecordedState(ModelImport(commissioned), catalog),
                  model_ids=tuple(ids[:MAX_MODELS]),
                  omitted=max(0, len(ids) - MAX_MODELS), quarantined=quarantined,
                  empty=entries is not None and not entries)
    return result


def _catalog_refusal(refused) -> str:
    """A fixed word for why the catalog was refused (R389-06)."""

    from .model_catalog import Refusal

    text = str(refused)
    if isinstance(refused.__cause__, PermissionError):
        return "permission_denied"
    if text.startswith(Refusal.CATALOG_ABSENT.value):
        return "not_presented"
    if isinstance(refused.__cause__, OSError):
        return "unreadable"
    if text.startswith(Refusal.CATALOG_UNSIGNED.value):
        return "unsigned"
    return "invalid"


class _RecordedState:
    """`ModelImport`'s read verbs, with `reading_for` from records only (R389-04).

    `ModelImport.reading_for` re-hashes the installed artifact, which can be
    gigabytes; a status screen must not do that on every refresh. Here a model
    is described from the signed catalog and the current generation record:
    installed, with the digest that was checked when it was promoted. It is
    never called `present` (verified now): integrity is re-verified only by
    an explicit operation, and the row says so. No artifact is opened.
    """

    def __init__(self, service, catalog):
        self._service = service
        self._catalog = catalog

    def current_generation(self):
        return self._service.current_generation()

    def list_inbox(self):
        return self._service.list_inbox()

    def reading_for(self, model_id):
        from .model_catalog import CatalogState, ModelReading, Refusal, absent_reading

        if self._catalog is None:
            return absent_reading()
        entry = self._catalog.entry(model_id)
        if entry is None:
            return ModelReading(model_id=model_id, state=CatalogState.EMPTY,
                                refused_by=Refusal.UNKNOWN_MODEL,
                                reason=f"{Refusal.UNKNOWN_MODEL.value}: the catalog does not name it")
        generation = self._service.current_generation()
        installed = generation.installed.get(model_id) if generation is not None else None
        if installed is None:
            return ModelReading(model_id=model_id, state=CatalogState.DECLARED,
                                refused_by=Refusal.ARTIFACT_ABSENT,
                                reason=(f"{Refusal.ARTIFACT_ABSENT.value}. The catalog offers it; "
                                        "no generation installs it"))
        if installed != entry.digest:
            return ModelReading(model_id=model_id, state=CatalogState.DECLARED,
                                refused_by=Refusal.DIGEST_MISMATCH,
                                reason=("the generation record names a digest other than the "
                                        "catalog's; not shown as present"))
        if entry.license_acknowledgement_required:
            return ModelReading(model_id=model_id, state=CatalogState.DECLARED,
                                refused_by=Refusal.LICENSE_NOT_ACKNOWLEDGED,
                                reason=Refusal.LICENSE_NOT_ACKNOWLEDGED.value)
        return ModelReading(model_id=model_id, state=CatalogState.DECLARED, refused_by=None,
                            reason=INSTALLED_NOT_REVERIFIED.format(number=generation.number))


#: What an installed model's row says: recorded, not re-verified here.
INSTALLED_NOT_REVERIFIED = (
    "installed in generation {number}; its digest was checked when it was promoted. "
    "This screen does not re-hash it, so integrity is not re-verified here")


def _reserve(path: Path):
    """`(access, measured)`; `measured` is `None` unless the record was read."""

    from .core_reserve import load_reserve

    try:
        return ("readable", load_reserve(path) is not None)
    except Exception as exc:  # noqa: BLE001 - a fixed word, never the text
        access = _access_of(exc)
        if access == "absent":
            return "absent", False
        return access, None


def _entryd(mio_status_section) -> tuple[str, Optional[str], Optional[str]]:
    """`(access, profile, local)` from entryd's snapshot section, as read."""

    if not isinstance(mio_status_section, dict):
        return "not_read", None, None
    snapshot = mio_status_section.get("snapshot")
    if snapshot is None:
        return "absent", None, None
    if mio_status_section.get("freshness") != "fresh":
        return "stale", None, None
    if not snapshot.get("recorded") or snapshot.get("record_uncertain") is not False:
        return "not_recorded", None, None
    health = (snapshot.get("reasons") or {}).get("health") or {}
    local = health.get("local") if health.get("local") in _LOCAL_REASONS else "invalid_observation"
    return "readable", _CEILING_PROFILE.get(snapshot.get("ceiling")), local


def _disk(storage_section):
    """`(total MiB, free MiB)` of the model store's filesystem, as status measured it.

    Taken from the storage section (`operator_snapshots.read_storage`), so the
    screen and the storage table never show two measurements of one disk.
    """
    locations = {entry.get("label"): entry for entry in
                 (storage_section or {}).get("locations") or () if isinstance(entry, dict)}
    for label in ("models", "state_root"):
        entry = locations.get(label) or {}
        total, free = entry.get("total_bytes"), entry.get("available_bytes")
        if entry.get("status") == "measured" and type(total) is int and type(free) is int:
            return total // (1024 * 1024), free // (1024 * 1024)
    return None, None


def read_section(*, usable_mib: Optional[int], mio_status_section=None, storage_section=None,
                 root=None, models_root: Optional[Path] = None,
                 reserve_path: Optional[Path] = None) -> dict:
    """The `operator_view` status section. Reads only; never raises."""

    try:
        return _read_section(usable_mib=usable_mib, mio_status_section=mio_status_section,
                             storage_section=storage_section, root=root,
                             models_root=models_root, reserve_path=reserve_path)
    except Exception:  # noqa: BLE001 - presentation only; status continues
        return {"schema": SCHEMA, "status": "unavailable", "reason_code": "internal_error"}


def _read_section(*, usable_mib, mio_status_section, storage_section, root, models_root,
                  reserve_path) -> dict:
    from .mio_profile import MioProfile
    from .model_admission import LOCAL_MODEL_ADMISSION_ENABLED
    from .model_catalog import CatalogState
    from .operator_view import AdmissionFacts, NodeResources, ViewFacts, build_view, gather_facts

    base = _root(root)
    models = models_root if models_root is not None else base / "var/lib/azazel/models"
    reserve_file = (reserve_path if reserve_path is not None
                    else base / "var/lib/azazel/run/core-reserve.json")
    catalog = _catalog(models)
    catalog_access, service = catalog["access"], catalog["service"]
    reserve_access, reserve_measured = _reserve(reserve_file)
    entryd_access, profile_word, local = _entryd(mio_status_section)
    total, free = _disk(storage_section)
    resources = NodeResources(usable_mib=usable_mib, disk_total_mib=total, disk_free_mib=free)
    profile = MioProfile(profile_word) if profile_word is not None else None
    admission = AdmissionFacts(build_enabled=bool(LOCAL_MODEL_ADMISSION_ENABLED), local=local)
    if service is not None:
        facts = gather_facts(service, profile=profile, opt_in=None,
                             reserve_measured=reserve_measured, resources=resources,
                             model_ids=catalog["model_ids"], quarantined=catalog["quarantined"])
        # A trusted catalog that offers nothing is `empty`, not `absent`.
        facts = replace(facts, admission=admission, **(
            {"catalog_state": CatalogState.EMPTY} if catalog["empty"] else {}))
    else:
        facts = ViewFacts(profile=profile, opt_in=None, reserve_measured=reserve_measured,
                          resources=resources, catalog_state=CatalogState.ABSENT, readings=(),
                          inbox=(), quarantined=0, installed={}, rollback_target=None,
                          catalog_access=("read" if catalog_access == "readable"
                                          else catalog_access),
                          admission=admission)
    document = build_view(facts).as_document()
    json.dumps(document, allow_nan=False)
    inputs = {"model_store": catalog_access, "core_reserve": reserve_access,
              "mio_entry_record": entryd_access, "remote_consent": "not_read"}
    unread = sorted(name for name in DECISIVE_INPUTS if inputs[name] != "readable"
                    and not (name == "core_reserve" and inputs[name] == "absent"))
    cognition = next(s for s in document["sections"] if s["key"] == "cognition")
    provider = next(r for r in cognition["rows"] if r["axis"] == "provider_state")
    return {
        "schema": SCHEMA,
        # `read` only when every input was read; otherwise `partial`, which
        # the UI shows as unknown with the inputs it could not read.
        "status": "read" if not unread else "partial",
        "reason_code": None if not unread else "inputs_not_all_read",
        "inputs": inputs,
        "unread_inputs": unread,
        "provider": {"state": provider["value"], "reason_codes": provider["reason_codes"]},
        "admission_build_switch": "on" if LOCAL_MODEL_ADMISSION_ENABLED else "off",
        "models_omitted": catalog["omitted"],
        "status_sentence": document["status_sentence"],
        "sections": document["sections"],
        "operations": document["operations"],
        "source": {"kind": "read_adapter", "reader": "operator_view_source.read_section",
                   "writes": "none"},
    }
