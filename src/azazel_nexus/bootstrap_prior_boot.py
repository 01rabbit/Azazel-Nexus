"""Move a prior-boot administrator record aside inside an owner-confirmed write.

Only the owner's own confirmed initialize/install operations call this, under
their exclusive directory lock; no reader, startup path or daemon does. It is
not renewal, repair or a new authority: a record of the current boot, a pending
publication, a record that is not canonical, or a record whose retirement cannot
be durably recorded first is left untouched and the operation refuses.
"""

from hashlib import sha256
import os

from .operator_trust import ApprovalRefused

EVENT_TYPE = "activation.bootstrap_prior_boot_record_retiring"


def retired_name(prior_boot: str, name: str) -> str:
    """Fixed archive name next to the record; never reused or overwritten."""
    return "retired-" + prior_boot + "-" + name


def _exists(fd, name):
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def retire_prior_boot_records(fd, *, kind, names, limits, pending, owner, read_file,
                              boot_of, current_boot, record):
    """Record, then link each record to its archive name and unlink the original.

    The caller holds the directory's exclusive lock and has already confirmed the
    operation. ``boot_of`` decodes the exact retained bytes canonically and returns
    their boot id (any failure refuses). ``record`` is a trusted composition
    callback that durably records ``event`` and returns exactly True; it runs
    before anything is moved. Readers refuse a record with two links, so the
    window between link and unlink fails closed.
    """
    if record is None or not callable(record):
        raise ApprovalRefused("existing record cannot be replaced")
    if any(_exists(fd, name) for name in pending):
        raise ApprovalRefused("pending publication requires administrator review")
    raws = tuple(read_file(fd, name, owner=owner, limit=limit)
                 for name, limit in zip(names, limits, strict=True))
    prior = boot_of(raws)
    if type(prior) is not str or type(current_boot) is not str or prior == current_boot:
        raise ApprovalRefused("record of the current boot cannot be replaced")
    archives = tuple(retired_name(prior, name) for name in names)
    if any(_exists(fd, name) for name in archives):
        raise ApprovalRefused("retired record name already present")
    event = {
        "event_type": EVENT_TYPE,
        "record": kind,
        "boot_id": prior,
        "current_boot_id": current_boot,
        "files": {name: {"sha256": "sha256:" + sha256(raw).hexdigest(), "retired_as": archive}
                  for name, raw, archive in zip(names, raws, archives)},
    }
    if record(event) is not True:
        raise ApprovalRefused("prior boot record retirement unrecorded")
    if tuple(read_file(fd, name, owner=owner, limit=limit)
             for name, limit in zip(names, limits)) != raws:
        raise ApprovalRefused("prior boot record changed during retirement")
    for name, archive in zip(names, archives):
        os.link(name, archive, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
    os.fsync(fd)
    for name in names:
        os.unlink(name, dir_fd=fd)
    os.fsync(fd)
