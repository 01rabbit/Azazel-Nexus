"""The Deception Lite network's names and addresses, and nothing else (#196 §13).

A leaf: it imports nothing and runs nothing, so the unit renderer
(`hardening.py`) can take the decoy subnet from here without loading the
module that starts processes (`decoy_network.py`). The decoy's end of the
veth pair is `decoy_netns.DECOY_VETH`, kept with the decoy's own check.
Fixed in code until the commissioned bridge prefix reaches the units (§7 Q9).
"""

from __future__ import annotations

__all__ = [
    "BRIDGE",
    "BRIDGE_ADDRESS",
    "DECOY_ADDRESS",
    "DECOY_PORTS",
    "DECOY_SUBNET",
    "HOST_VETH",
    "NAMESPACE",
    "NFT_TABLE",
    "PREFIX_LENGTH",
]

#: The namespace name; its handle is `decoy_netns.DECOY_NAMESPACE_PATH`.
NAMESPACE = "azazel-decoy"

#: The bridge the decoy lives on (`azazel_nexus.decoy.DECOY_BRIDGE`).
BRIDGE = "az-decoy0"

#: The host's end of the veth pair. At most 15 bytes (`IFNAMSIZ`).
HOST_VETH = "az-decoy-host0"

#: The decoy network: a /30, the bridge (host) and the decoy, nothing else.
DECOY_SUBNET = "10.255.196.0/30"
BRIDGE_ADDRESS = "10.255.196.1"
DECOY_ADDRESS = "10.255.196.2"
PREFIX_LENGTH = "30"

#: The decoy's ports (`decoyd.SERVED`; a test keeps them equal).
DECOY_PORTS: tuple[int, ...] = (2222, 2323, 8080)

#: The host's nftables table, created and deleted whole.
NFT_TABLE = "azazel_decoy"
