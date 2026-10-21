"""Turn a decoy's observation into the event it reports (#196 P2).

The decoy daemon (`decoyd.py`, §12) calls `interaction_from_observation` once
per reach and sends `DecoyInteraction.line` to the intake's decoy socket
(`decoy_sender.DECOY_INTAKE_SOCKET`), one line per connection, as
Edge does on its own socket. Nothing is read back: the intake answers nothing,
and nothing it holds flows to the decoy or to Edge.

The observation (`decoy_loopback.Observation`) has no payload and no peer
field, so neither can reach the event. Its responder and byte count are held
to this build's responder table and read ceiling before the library's closed
shape is applied (`azazel_nexus.decoy_interaction`). Its generation digest is
not sent: the intake could not check it against anything in this build, and
an unchecked digest is 256 bits the sender chooses.
"""

from __future__ import annotations

from collections.abc import Callable

from azazel_nexus.decoy_interaction import (
    LOCAL_NODE_ID,
    DecoyEventRefused,
    DecoyInteraction,
    build_interaction,
    new_event_id,
)

from .decoy_loopback import MAX_READ_BYTES, RESPONDERS, Observation

__all__ = ["interaction_from_observation", "new_event_id"]


def interaction_from_observation(
    observation: Observation,
    *,
    node_id: str = LOCAL_NODE_ID,
    event_id: Callable[[], str] = new_event_id,
) -> DecoyInteraction:
    """The closed `EnvironmentEvent` for one observation; refused otherwise.

    `observation.at` must be whole seconds in UTC (`...T12:00:00Z`).
    """

    if type(observation) is not Observation:
        raise DecoyEventRefused("DECOY_TYPE")
    if observation.responder not in RESPONDERS:
        raise DecoyEventRefused("DECOY_RANGE")
    if type(observation.bytes_received) is not int or not (
            0 <= observation.bytes_received <= MAX_READ_BYTES):
        raise DecoyEventRefused("DECOY_RANGE")
    return build_interaction(
        event_id=event_id(),
        decoy_name=observation.decoy_name,
        node_id=node_id,
        observed_at=observation.at,
        bytes_received=observation.bytes_received,
        truncated=observation.truncated,
        responder=observation.responder,
    )
