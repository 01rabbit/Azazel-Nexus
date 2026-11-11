# Knowledge Context commissioning examples (test-only)

Test-only, not for production. Every value here is a placeholder; addresses are
documentation addresses (192.0.2.0/24) and the names are invented. Nothing in
this directory enables, grants or connects anything, and no key, certificate or
signed registry is included.

The files show the shape of what an owner has to supply for
`/etc/azazel/knowledge-context/commissioning/` (see
[the consumer boundary](../../knowledge-context-consumer.md)). Use
`tools/check_knowledge_context_bundle.py` to check a real bundle read-only.
Run it as the service account and its group, never as root, because the
loader's checks depend on the caller:
`sudo -u azknowledgeegress -g azknowledgeegress python3 tools/check_knowledge_context_bundle.py`.
The group is the daemon's primary group `azknowledgeegress`, not the socket
group `azknowledge-context-client`; with the wrong group the pre-check reports
`commissioned` but the daemon refuses with `perm_unsafe`.
This directory deliberately has no network allowance example; the endpoint
allowlist is not designed here.

- `manifest.json`: the bundle manifest. `enabled` is `false` here on purpose;
  the loader refuses it (`enabled_not_true`).
- `registry.skeleton.json`: the structure inside `registry.signed`. The real
  file is a 64-byte signature followed by canonical JSON, signed by a registry
  key that must differ from Knowledge's response-signing key.
- `observation-query.json`: the optional rule file, kept outside the bundle.

Points that are easy to get wrong:

- Knowledge fixes `provider_id` to `azazel-knowledge` (not configurable); set
  the manifest `peer_id` and the registry `provider_id` to that value. Nexus
  rejects a mismatch (`src/azazel_nexus/knowledge_context_adapter.py`).
- Nexus pins the server certificate's SubjectPublicKeyInfo (`sha256:<hex>`);
  Knowledge pins the whole client certificate (DER SHA-256, hex). Run
  `tools/check_knowledge_context_bundle.py --pin <cert>` to print both.
- `max_ttl_seconds` on the Nexus side must be at least Knowledge's value.
