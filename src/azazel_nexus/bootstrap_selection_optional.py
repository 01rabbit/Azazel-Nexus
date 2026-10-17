"""Optional protected routing for installations with no bootstrap selection."""

from . import bootstrap_store
from . import bootstrap_selection_store
from .operator_trust import ApprovalRefused


def load_optional_bootstrap_selection():
    """Return None only when the protected selection records are absent.

    Present selection decoding, pending-state refusal, deployment/boot binding,
    and stable-byte checks remain delegated to the strict current reader.
    This function never creates the directory or treats other errors as absence.
    """
    try:
        with bootstrap_store._optional_bootstrap_directory() as initial:
            directory_fd, parent_identity, directory_identity = initial
            if directory_fd is None:
                with bootstrap_store._optional_bootstrap_directory() as current:
                    if current != (None, parent_identity, None):
                        raise ApprovalRefused("bootstrap selection absence changed")
                return None
            try:
                bootstrap_selection_store._read_at(directory_fd, owner=0)
            except FileNotFoundError:
                missing_selection = True
            else:
                missing_selection = False

        if missing_selection:
            with bootstrap_store._optional_bootstrap_directory() as current:
                fresh_fd, fresh_parent, fresh_directory = current
                if (fresh_fd is None or fresh_parent != parent_identity
                        or fresh_directory != directory_identity):
                    raise ApprovalRefused("bootstrap selection directory changed")
                try:
                    bootstrap_selection_store._read_at(fresh_fd, owner=0)
                except FileNotFoundError:
                    return None
                raise ApprovalRefused("bootstrap selection appeared during observation")

        selection = bootstrap_selection_store.load_bootstrap_selection()
        with bootstrap_store._optional_bootstrap_directory() as current:
            fresh_fd, fresh_parent, fresh_directory = current
            if (fresh_fd is None or fresh_parent != parent_identity
                    or fresh_directory != directory_identity):
                raise ApprovalRefused("bootstrap selection directory changed")
        return selection
    except Exception:
        raise ApprovalRefused("optional protected bootstrap selection refused") from None
