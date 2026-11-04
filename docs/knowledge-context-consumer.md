# Nexus Knowledge Context consumer candidate (#395)

The semantic request/response belongs to Fabric's `knowledge-context/v1`
profile. Nexus imports it only through `fabric_boundary`, where the import is
deferred so CORE remains usable without the optional Fabric package. The
currently supported product pin remains Fabric `v0.9.0rc5`; that tag does not
contain this profile. Until a released Fabric pin provides it, the new adapter
returns unavailable and the existing Lite/no-context behavior remains in use.

The Nexus envelope is separate from the Fabric payload. It binds `key_id`,
`issued_at`, `expires_at`, and the canonical response bytes under the
`azazel-nexus/knowledge-context-envelope/v1` Ed25519 domain. Verification
resolves the provider key through Nexus's existing commissioning-bound signed
Knowledge registry and requires `key_id` to equal that key's SHA-256
fingerprint. A maximum TTL has no default and must be explicitly supplied.
Fabric validates the semantic request and response, including exact
request/correlation/source binding and the advisory-only fact/inference model.

The adapter accepts P0-public queries only, even if local policy allows a
wider class. It does not open a socket, load a key, read an endpoint, install a
trust anchor, alter service startup, or enable full-node lookup. No commissioning
state is added. The response is a bounded advisory object; it cannot grant
authority or alter Edge's deterministic decision path.

Before an actual client is composed or a connection is enabled, the service
owners still need to record and test:

- the endpoint/CA/client-certificate provision owner and accepted trust anchor;
- the signing-key registry owner and key identifier assignment;
- certificate and signing-key validity, rotation approver and overlap period;
- the numeric maximum response TTL;
- the revocation authority and notification route; and
- the disable and recovery procedure.

The Draft-only CI job tests this code against Fabric source commit
`50494cf769978abdbad21626a130d6525c83135d`. That is compatibility evidence for
the candidate contract, not a production dependency pin or an authorization to
connect. Product packaging continues to use the exact accepted Fabric tag
until the usual version and offline-wheelhouse review updates it.
