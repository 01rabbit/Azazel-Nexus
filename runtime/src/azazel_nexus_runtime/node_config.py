"""Protected declared node label, not attestation or disclosure permission.

Fixed /etc/azazel/node.yaml; no enrollment, file creation or identity fallback.
Other configuration fields never become authorization or measured evidence.
"""

from dataclasses import dataclass
import os
import stat

_MAX_BYTES = 65536


class NodeConfigUnavailable(Exception):
    """Redacted failure; parser diagnostics and node labels must stay private."""


@dataclass(frozen=True, repr=False)
class DeclaredNode:
    node_id: str


def _mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if type(key) is not str or key == "<<" or key in result:
            raise NodeConfigUnavailable("ambiguous node configuration")
        result[key] = loader.construct_object(value_node)
    return result


def _decode(raw: bytes) -> DeclaredNode:
    # A missing optional diagnostic parser must not stop az-activated before
    # its mandatory narrowing pass. Import only inside the guarded reader.
    try:
        import yaml
    except ImportError:
        raise NodeConfigUnavailable("node configuration parser unavailable") from None

    class Loader(yaml.SafeLoader):
        pass

    Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= _MAX_BYTES:
            raise ValueError
        text = raw.decode("utf-8")
        depth = 0
        for count, event in enumerate(yaml.parse(text), start=1):
            if (count > 8192 or isinstance(event, yaml.AliasEvent)
                    or getattr(event, "anchor", None) is not None
                    or getattr(event, "tag", None) is not None):
                raise ValueError
            if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                depth += 1
                if depth > 32:
                    raise ValueError
            elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                depth -= 1
        document = yaml.load(text, Loader=Loader)
        if type(document) is not dict:
            raise ValueError
        label = document["node_id"]
        if (type(label) is not str or not 0 < len(label) <= 128
                or not label.isascii() or any(char.isspace() or ord(char) < 33 or ord(char) == 127 for char in label)):
            raise ValueError
        return DeclaredNode(label)
    except (yaml.YAMLError, ValueError, TypeError, KeyError, RecursionError):
        raise NodeConfigUnavailable("node configuration refused") from None


def _protected(fd, *, owner, directory):
    info = os.fstat(fd)
    correct = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not correct or info.st_uid != owner or info.st_mode & 0o022:
        raise NodeConfigUnavailable("node configuration storage refused")
    if not directory and (info.st_nlink != 1 or not 0 < info.st_size <= _MAX_BYTES):
        raise NodeConfigUnavailable("node configuration file refused")
    return info


def _read_at(directory_fd, *, owner):
    _protected(directory_fd, owner=owner, directory=True)
    fd = os.open("node.yaml", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                 dir_fd=directory_fd)
    try:
        before = _protected(fd, owner=owner, directory=False)
        result = bytearray()
        while len(result) <= _MAX_BYTES:
            chunk = os.read(fd, min(8192, _MAX_BYTES + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
        after = _protected(fd, owner=owner, directory=False)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ) or len(result) != before.st_size:
            raise NodeConfigUnavailable("node configuration changed during read")
        return _decode(bytes(result))
    finally:
        os.close(fd)


def load_declared_node() -> DeclaredNode:
    """Read root-owned protected ancestry; never expose the label in errors."""
    fd = None
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open("/", flags)
        for component in ("etc", "azazel"):
            _protected(fd, owner=0, directory=True)
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return _read_at(fd, owner=0)
    except (OSError, AttributeError):
        raise NodeConfigUnavailable("protected node configuration unavailable") from None
    finally:
        if fd is not None:
            os.close(fd)
