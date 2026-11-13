"""The Knowledge mTLS egress boundary; no caller URLs, redirects or retries.

Reuses inference_egress's commissioned mTLS context and SPKI pin verifier.
Numeric signed addresses avoid an unbounded resolver call. The one deadline
covers connect, both handshakes, negotiation and query; queue capacity is zero.
"""

from __future__ import annotations

import math
import secrets
import socket
import ssl
import threading
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime

from azazel_nexus.knowledge_peer import (
    SCHEMA,
    KnowledgeRefused,
    KnowledgeRegistry,
    PeerContext,
    canonical,
    negotiate,
    prepare_query,
    read_context,
)
from azazel_nexus.knowledge_context_adapter import (
    KnowledgeContextRefused,
    make_request,
    read_signed_response,
)
from azazel_nexus.fabric_boundary import (
    KnowledgeContextInvalid,
    KnowledgeContextUnavailable,
    canonical_knowledge_context_request,
)
from azazel_nexus.lite_service import KnowledgeReading, LiteReading, knowledge_context
from azazel_nexus.sanitizer import PrivacyClass, SanitizerPolicy

from .inference_egress import InferenceRefused, spki_pin, tls_context

_KNOWLEDGE_CONTEXT_PATH = "/v1/knowledge-context"
_MAX_KNOWLEDGE_CONTEXT_REQUEST_BYTES = 64 * 1024


def _staged(exc: Exception, stage: str) -> Exception:
    """Tag a refusal with the fixed request section it came from.

    The tag is one of refused_before_send / transport / verification; the broker
    reads it instead of parsing any message text.
    """
    exc.stage = stage
    return exc


def egress_address(peer) -> str:
    """The one address the client connects to; the renderer's allowance uses it too.

    The registry loader accepts exactly one address; a peer that does not carry
    exactly one is refused here as well, never reduced to its first element.
    """
    if len(peer.addresses) != 1:
        raise ValueError("peer must carry exactly one address")
    return peer.addresses[0]


class KnowledgeClient:
    """Constructed only from commissioned registry and identity material.

    No CLI, daemon, environment URL, caller endpoint or implicit commissioning.
    Construct once per service: its semaphore bounds concurrent requests across
    calls. Failure details are fixed codes, never exception strings or frames.
    """

    def __init__(
        self,
        *,
        registry: KnowledgeRegistry | None,
        peer_id: str,
        ca_certificate: str,
        identities: Mapping[str, tuple[str, str]],
        knowledge_context_enabled: bool = False,
        knowledge_context_max_ttl_seconds: int | None = None,
        utc_now: Callable[[], str] | None = None,
    ):
        if type(knowledge_context_enabled) is not bool:
            raise ValueError("Knowledge Context enablement must be an explicit boolean")
        if knowledge_context_max_ttl_seconds is not None and (
            type(knowledge_context_max_ttl_seconds) is not int
            or knowledge_context_max_ttl_seconds < 1
        ):
            raise ValueError("Knowledge Context maximum TTL must be a positive integer")
        if knowledge_context_enabled and knowledge_context_max_ttl_seconds is None:
            raise ValueError("enabled Knowledge Context requires an explicit maximum TTL")
        self.registry = registry
        self.peer_id = peer_id
        self.knowledge_context_enabled = knowledge_context_enabled
        self.knowledge_context_max_ttl_seconds = knowledge_context_max_ttl_seconds
        self.utc_now = utc_now or (lambda: datetime.now(UTC).isoformat())
        self.context = None
        self.slots = threading.BoundedSemaphore(1)
        if registry is not None:
            peer = registry.resolve(peer_id, now=self.utc_now())
            pair = identities.get(peer.endpoint.client_identity)
            if pair is None:
                raise KnowledgeRefused("commissioned client identity unavailable")
            self.context = tls_context(
                ca_certificate=ca_certificate,
                client_certificate=pair[0],
                client_key=pair[1],
            )
            self.slots = threading.BoundedSemaphore(peer.max_inflight)

    def retrieve(
        self,
        *,
        local: LiteReading,
        frame: Mapping,
        privacy_class: PrivacyClass,
        policy: SanitizerPolicy,
        mission: str,
        alias_key: bytes,
        deeper: bool = False,
    ) -> KnowledgeReading:
        correlation = secrets.token_hex(16)
        # Local-first: a usable cache answers without even capability traffic.
        if local.sources_capability and local.served and not deeper:
            return knowledge_context(local, correlation=correlation)
        if self.registry is None:
            return knowledge_context(
                local,
                correlation=correlation,
                reason="no module endpoint is configured on this node",
            )
        if not self.slots.acquire(blocking=False):
            return knowledge_context(
                local, correlation=correlation, reason="knowledge queue full"
            )
        try:
            peer = self.registry.resolve(self.peer_id, now=self.utc_now())
            body = prepare_query(
                peer,
                frame=frame,
                privacy_class=privacy_class,
                policy=policy,
                mission=mission,
                alias_key=alias_key,
                correlation=correlation,
            )
            deadline = time.monotonic() + peer.endpoint.deadline_seconds
            hello = canonical({"schema": SCHEMA, "correlation": correlation})
            capabilities = self._post(peer, "/capabilities", hello, deadline)
            negotiate(
                capabilities, peer=peer, correlation=correlation, now=self.utc_now()
            )
            # Recheck registry expiry before any sanitized context is sent.
            self.registry.resolve(self.peer_id, now=self.utc_now())
            raw = self._post(peer, "/query", body, deadline)
            context: PeerContext = read_context(
                raw, peer=peer, correlation=correlation, now=self.utc_now()
            )
            if time.monotonic() >= deadline:
                raise KnowledgeRefused("knowledge deadline exceeded")
            return knowledge_context(local, peer=context, correlation=correlation)
        except (KnowledgeRefused, InferenceRefused, OSError, ValueError):
            return knowledge_context(
                local,
                correlation=correlation,
                reason="knowledge peer refused or unavailable",
            )
        finally:
            self.slots.release()

    def _post(self, peer, suffix: str, body: bytes, deadline: float) -> bytes:
        return self._post_path(peer, f"{peer.endpoint.path_for()}{suffix}", body, deadline)

    def request_context(
        self,
        *,
        frame: Mapping,
        privacy_class: PrivacyClass,
        policy: SanitizerPolicy,
        mission: str,
        alias_key: bytes,
        deadline_s: float | None = None,
    ):
        """Query the Fabric v1 endpoint only when local configuration opts in.

        This operation remains outside MIO's pure core and shares the commissioned
        peer registry, mTLS identity, SPKI pin, deadline and concurrency budget.
        `knowledge_context_enabled` is a local caller-supplied opt-in, not a
        capability asserted by the signed peer registry. The deployed service
        must source it only from reviewed local commissioning configuration.
        It returns a Fabric-validated advisory response or one fixed refusal.
        """
        if self.knowledge_context_enabled is not True:
            raise _staged(KnowledgeContextRefused("full-node Knowledge Context is disabled"), "refused_before_send")
        if self.registry is None or self.context is None:
            raise _staged(KnowledgeContextRefused("commissioned Knowledge peer is unavailable"), "refused_before_send")
        caller_deadline = None
        if deadline_s is not None:
            try:
                valid_deadline = (type(deadline_s) in (int, float)
                                  and math.isfinite(deadline_s) and deadline_s > 0)
            except OverflowError:
                valid_deadline = False
            if not valid_deadline:
                raise _staged(KnowledgeContextRefused("Knowledge Context deadline is invalid"), "refused_before_send")
            caller_deadline = time.monotonic() + float(deadline_s)
        max_ttl_seconds = self.knowledge_context_max_ttl_seconds
        if type(max_ttl_seconds) is not int or max_ttl_seconds < 1:
            raise _staged(KnowledgeContextRefused("Knowledge Context TTL is not commissioned"), "refused_before_send")
        if not self.slots.acquire(blocking=False):
            raise _staged(KnowledgeContextRefused("Knowledge peer queue is full"), "refused_before_send")
        stage = "refused_before_send"
        try:
            peer = self.registry.resolve(self.peer_id, now=self.utc_now())
            if PrivacyClass.P0_PUBLIC not in peer.endpoint.allowed_privacy_classes:
                raise KnowledgeContextRefused(
                    "commissioned peer does not allow P0-public context"
                )
            request = make_request(
                frame,
                privacy_class=privacy_class,
                policy=policy,
                mission=mission,
                alias_key=alias_key,
                requested_at=self.utc_now(),
            )
            body = canonical_knowledge_context_request(request)
            limit = min(
                peer.endpoint.max_request_bytes,
                _MAX_KNOWLEDGE_CONTEXT_REQUEST_BYTES,
            )
            if len(body) > limit:
                raise _staged(KnowledgeContextRefused("Knowledge Context request is too large"), "refused_before_send")
            deadline = time.monotonic() + peer.endpoint.deadline_seconds
            if caller_deadline is not None:
                deadline = min(deadline, caller_deadline)
            if time.monotonic() >= deadline:
                raise _staged(KnowledgeContextRefused("Knowledge Context deadline exceeded"), "refused_before_send")
            stage = "transport"
            raw = self._post_path(peer, _KNOWLEDGE_CONTEXT_PATH, body, deadline)
            stage = "verification"
            # Refuse a response if commissioning was revoked or expired in flight.
            self.registry.resolve(self.peer_id, now=self.utc_now())
            return read_signed_response(
                raw,
                request=request,
                registry=self.registry,
                peer_id=self.peer_id,
                now=self.utc_now(),
                max_ttl_seconds=max_ttl_seconds,
            )
        except (
            KnowledgeRefused,
            KnowledgeContextRefused,
            KnowledgeContextInvalid,
            KnowledgeContextUnavailable,
            InferenceRefused,
            OSError,
            ValueError,
        ) as exc:
            raise _staged(KnowledgeContextRefused(
                "Knowledge Context peer refused or unavailable"
            ), stage) from exc
        finally:
            self.slots.release()

    def _post_path(self, peer, path: str, body: bytes, deadline: float) -> bytes:
        endpoint = peer.endpoint
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or any(char in path for char in "\r\n?#")
        ):
            raise KnowledgeRefused("invalid Knowledge path")
        if len(body) > endpoint.max_request_bytes:
            raise KnowledgeRefused("request size exceeded")

        def remaining():
            value = deadline - time.monotonic()
            if value <= 0:
                raise KnowledgeRefused("knowledge deadline exceeded")
            return value

        # One signed address and one attempt. No retry can multiply the budget.
        address = egress_address(peer)
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as raw:
            raw.settimeout(remaining())
            raw.connect((address, endpoint.port))
            raw.settimeout(remaining())
            with self.context.wrap_socket(raw, server_hostname=endpoint.host) as stream:
                if (
                    self.context.verify_mode != ssl.CERT_REQUIRED
                    or not self.context.check_hostname
                    or spki_pin(stream.getpeercert(binary_form=True) or b"")
                    != endpoint.certificate_pin
                ):
                    raise KnowledgeRefused("TLS identity refused")
                request = (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {endpoint.host}\r\nContent-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                ).encode("ascii")
                stream.settimeout(remaining())
                stream.sendall(request + body)
                buffer = b""
                while b"\r\n\r\n" not in buffer:
                    stream.settimeout(remaining())
                    chunk = stream.recv(1024)
                    if not chunk:
                        raise KnowledgeRefused("truncated headers")
                    buffer += chunk
                    if len(buffer.split(b"\r\n\r\n", 1)[0]) > 8192:
                        raise KnowledgeRefused("headers too large")
                head, response = buffer.split(b"\r\n\r\n", 1)
                lines = head.split(b"\r\n")
                # Knowledge's one-request-per-connection mTLS listener uses
                # HTTP/1.0 with an explicit Content-Length and Connection: close.
                # Keep the accepted status exact while supporting that bounded
                # producer response alongside ordinary HTTP/1.1 peers.
                if lines[0] not in (b"HTTP/1.1 200 OK", b"HTTP/1.0 200 OK"):
                    raise KnowledgeRefused("HTTP status refused")
                headers = {}
                for line in lines[1:]:
                    name, sep, value = line.partition(b":")
                    name = name.lower()
                    if not sep or name in headers:
                        raise KnowledgeRefused("malformed headers")
                    headers[name] = value.strip()
                if b"transfer-encoding" in headers:
                    raise KnowledgeRefused("unsupported framing")
                length = int(headers.get(b"content-length", b"-1"))
                if not 64 < length <= endpoint.max_response_bytes:
                    raise KnowledgeRefused("response size exceeded")
                while len(response) < length:
                    stream.settimeout(remaining())
                    chunk = stream.recv(min(8192, length + 1 - len(response)))
                    if not chunk:
                        raise KnowledgeRefused("truncated response")
                    response += chunk
                if len(response) != length:
                    raise KnowledgeRefused("response framing mismatch")
                remaining()
                return response
