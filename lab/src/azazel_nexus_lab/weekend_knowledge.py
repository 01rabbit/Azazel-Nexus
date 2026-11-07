"""Synthetic complete producer seam; partial uses the unchanged Knowledge route.

Complete is a LAB claim over a closed synthetic dataset. It is projected before
signing, using the existing test server signer, actual query handler and adapter.
No production object, class, constant, issuer or signed response is patched.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import ssl
import threading
from datetime import timedelta


def complete_response(request, body, peer_id):
    from fastapi import HTTPException, Response
    from azazel_fabric.knowledge_context import canonical_knowledge_context_bytes
    from azazel_knowledge.api.app import AuthContext
    from azazel_knowledge.api.knowledge_context_adapter import (
        from_knowledge_context_request, to_knowledge_context_response)
    from azazel_knowledge.api.routers.context import post_context
    from azazel_knowledge.api.routers.knowledge_context import _canonical, _ENVELOPE_DOMAIN
    from azazel_knowledge.core.clock import parse_rfc3339, to_rfc3339
    from azazel_knowledge.security.auth import Scope
    config = request.app.state.settings.knowledge_context_transport
    if body.source_product != 'azazel_nexus':
        raise HTTPException(status_code=403, detail={'error': 'peer_profile_mismatch'})
    response = post_context(request, from_knowledge_context_request(body),
        raw_body=body.model_dump_json().encode(),
        auth=AuthContext(key_id=f'mtls:{peer_id}', scopes=frozenset({Scope.QUERY})))
    instant = parse_rfc3339(response._knowledge_snapshot_as_of)
    expires = instant + timedelta(seconds=config.max_ttl_seconds)
    semantic = to_knowledge_context_response(response, body, provider_id='azazel-knowledge',
        snapshot_ref=response._knowledge_snapshot_ref, snapshot_state='complete',
        snapshot_as_of=response._knowledge_snapshot_as_of, generated_at=instant,
        expires_at=expires, limitations=(
            'LAB ONLY: completeness is scoped to the closed synthetic fixture dataset; no operational freshness claim.',))
    envelope = _canonical(dict(schema='azazel-nexus/knowledge-context-envelope/1',
        key_id=config.signer.key_id, issued_at=to_rfc3339(instant), expires_at=to_rfc3339(expires),
        payload=json.loads(canonical_knowledge_context_bytes(semantic))))
    signature = config.signer.sign(_ENVELOPE_DOMAIN + envelope)
    from nacl.signing import VerifyKey
    VerifyKey(config.signer.public_key).verify(_ENVELOPE_DOMAIN + envelope, signature)
    return Response(content=signature + envelope, media_type='application/octet-stream',
                    headers={'Cache-Control': 'no-store'})


def configure_complete(app):
    from fastapi import Depends, Request
    from azazel_knowledge.api.routers.knowledge_context import (
        _authenticated_peer, _bounded_envelope, _parse_envelope)

    # A new lab app instance has one explicit endpoint. Production route globals
    # and the source file remain intact. Both authentication gates still run.
    def endpoint(request: Request, peer_id=Depends(_authenticated_peer),
                 raw_body=Depends(_bounded_envelope)):
        return complete_response(request, _parse_envelope(request, raw_body), peer_id)
    # Request is locally imported; give FastAPI the concrete annotation.
    endpoint.__annotations__['request'] = Request
    # First-match routing also works with FastAPI's included-router wrapper.
    # The underlying production router is kept intact and remains reusable.
    from fastapi.routing import APIRoute
    app.router.routes.insert(0, APIRoute('/v1/knowledge-context', endpoint, methods=['POST']))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--pki', type=Path, required=True)
    parser.add_argument('--snapshot', choices=('complete', 'partial'), required=True)
    parser.add_argument('--ingress', type=Path, required=True)
    args = parser.parse_args(argv)
    from azazel_nexus_lab.weekend_process import require_container
    require_container()
    from _knowledge_context_mtls_server import _Signer
    from _api_support import build_app
    from azazel_knowledge.core.clock import SystemClock
    from azazel_knowledge.api.knowledge_context_mtls import (
        KnowledgeContextMtlsListener, MtlsListenerConfig, PinnedCertificatePeerAuthenticator)
    from azazel_knowledge.api.knowledge_context_transport import KnowledgeContextTransportConfig
    app, settings, _, _ = build_app(args.root)
    settings.clock = SystemClock()
    app.state.clock = settings.clock
    signer = _Signer()
    pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert((args.pki / 'nexus.pem').read_text())).hexdigest()
    settings.knowledge_context_transport = KnowledgeContextTransportConfig(
        peer_authenticator=PinnedCertificatePeerAuthenticator(peer_id='nexus-lab',
            cert_sha256=pin, is_revoked=lambda fp: False), signer=signer, max_ttl_seconds=30,
        expected_peer_id='nexus-lab', enabled=True)
    if args.snapshot == 'complete':
        configure_complete(app)

    class CountIngress:
        def __init__(self, app):
            self.app = app
        async def __call__(self, scope, receive, send):
            if scope['type'] == 'http' and scope.get('path') == '/v1/knowledge-context':
                with args.ingress.open('a') as log:
                    log.write(json.dumps({'path': scope['path'], 'method': scope['method']}) + '\n')
            await self.app(scope, receive, send)

    app.add_middleware(CountIngress)
    listener = KnowledgeContextMtlsListener(app, MtlsListenerConfig(
        bind_host='127.0.0.1', bind_port=0, server_cert_file=args.pki / 'server.pem',
        server_key_file=args.pki / 'server.key', client_ca_file=args.pki / 'ca.pem'))
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    listener.start()
    try:
        host, port = listener.address
        print(json.dumps(dict(ready=True, pid=os.getpid(), host=host, port=port,
            public_key=signer.public_key.hex(), snapshot=args.snapshot)), flush=True)
        stop.wait()
    finally:
        listener.stop()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
