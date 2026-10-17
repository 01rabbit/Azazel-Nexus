"""Root's local copy-and-verify handoff from fetchd to the #95 importer."""

import os
import stat
import tempfile

from .model_catalog import artifact_filename
from .model_import import CommissionedModels, ModelImport, entry_id_for
from .model_paths import fetch_ready_dir, load_model_trust, models_root


def import_fetched(model_id, *, license_acknowledged, now, out):
    if os.geteuid() != 0:
        print("refused: root_required", file=out)
        return 1
    temporary = None
    try:
        root = models_root()
        keys, digest, _ = load_model_trust(root / "trust/trust.json")
        models = CommissionedModels(root, keys, digest)
        entry = models.catalog().entry(model_id)
        if entry is None:
            print("refused: unknown_model", file=out)
            return 1
        name = artifact_filename(entry)
        ready = fetch_ready_dir() / name
        try:
            descriptor = os.open(ready, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            print("refused: ready_absent", file=out)
            return 1
        with os.fdopen(descriptor, "rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise ValueError("regular file required")
            models.inbox.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=models.inbox, delete=False) as target:
                temporary = target.name
                remaining = entry.size_bytes + 1
                while remaining:
                    chunk = source.read(min(remaining, 1024 * 1024))
                    if not chunk:
                        break
                    target.write(chunk)
                    remaining -= len(chunk)
                target.flush()
                os.fsync(target.fileno())
        os.replace(temporary, models.inbox / name)
        temporary = None
        directory = os.open(models.inbox, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        size = (models.inbox / name).stat().st_size
        outcome = ModelImport(models).import_entry(
            entry_id_for(display_name=name, size=size), model_id,
            now=now, actor="root", license_acknowledged=license_acknowledged,
        )
        if outcome.promoted:
            try:
                ready.unlink()
            except OSError:
                print("promoted; ready_cleanup_failed", file=out)
                return 0
            print("promoted", file=out)
            return 0
        reason = (outcome.reading.refused_by.name.lower() if outcome.reading.refused_by
                  else outcome.refused_by.value if outcome.refused_by else "import_refused")
        print("refused: " + reason, file=out)
        return 1
    except Exception:  # noqa: BLE001 - a refusal, never a traceback or exception text
        print("refused: local_state_invalid", file=out)
        return 1
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass
