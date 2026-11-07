"""Container-only P01/P02/P03/P04 controller; never starts host services."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

REPO = Path(__file__).resolve().parents[3]


def require_container(*, root=True):
    if not (sys.platform.startswith('linux') and Path('/.dockerenv').is_file()
            and (not root or os.geteuid() == 0)):
        raise RuntimeError('requires the disposable Linux root container; host execution forbidden')
    interfaces = {p.name for p in Path('/sys/class/net').iterdir()}
    if interfaces != {'lo'}:
        raise RuntimeError('requires --network=none; only loopback may exist')


def _count(path):
    return len(path.read_text().splitlines()) if path.exists() else 0


def edge_input():
    # Existing producer-shaped fixture -> real parser -> real intake tracker ->
    # explainer frame. The actual daemon path below uses the same fixture bytes.
    from test_edge_intake import edge_event
    return edge_event()


def _digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def published_incidents(paths, records):
    """Ledger durability precedes the daemon's throttled operator/UI copies."""
    from azazel_nexus.edge_loop_status import read_snapshot
    from azazel_nexus.incident_explain import RECENT_BYTES, explanation_summary, read_recent_incidents
    snapshots = {}
    for reader, path in paths.items():
        value = read_snapshot(path, read_recent_incidents, RECENT_BYTES)
        if value is None:
            return None
        rows = {row['incident_id']: row for row in value['incidents']}
        for record in records:
            row = rows.get(record['incident_id'])
            if row is None or any(row['explanation'].get(k) != v
                                  for k, v in explanation_summary(record).items()):
                return None
        snapshots[reader] = value
    return snapshots


def verify_handoff(parent, incident_id):
    """The ordinary CLI creates ONE package below its private output parent."""
    entries = list(parent.iterdir())
    assert len(entries) == 1, 'expected one ordinary handoff package'
    package = entries[0]
    assert not package.is_symlink() and package.is_dir(), 'handoff package is not a directory'
    files = list(package.iterdir())
    assert {p.name for p in files} == {'manifest.json', 'handoff.json', 'handoff.ja.md'}
    assert all(not p.is_symlink() and p.is_file() for p in files)
    manifest = json.loads((package / 'manifest.json').read_text())
    assert manifest['schema'] == 'azazel-nexus/handoff-manifest/1'
    assert manifest['incident_id'] == incident_id
    assert [e['name'] for e in manifest['files']] == ['handoff.json', 'handoff.ja.md']
    for entry in manifest['files']:
        path = package / entry['name']
        assert _digest(path) == entry['sha256'], 'handoff digest mismatch'
        assert path.stat().st_size == entry['bytes'], 'handoff size mismatch'
    document = json.loads((package / 'handoff.json').read_text())
    assert document['incident']['incident_id'] == incident_id
    assert incident_id in (package / 'handoff.ja.md').read_text()
    return dict(directory=str(package.relative_to(parent.parent)),
                files={p.name: _digest(p) for p in files})


def noc_event():
    """Authored service report in a synthetic Edge-shaped envelope, not telemetry."""
    from azazel_nexus_lab.weekend_ui import NOC_QUESTION, NOC_CONTEXT
    event = edge_input()
    event['normalized'].update(src_ip='192.0.2.18', sid=990001, target_port=22,
        attack_type=NOC_QUESTION + ' ' + NOC_CONTEXT, category='Misc activity',
        severity=4, technique_ids=[])
    event['defense'].update(action='observe', reason='synthetic service report only',
        policy_reason='baseline_observe_only', target='192.0.2.18')
    event['enforcement'].update(selected_action='observe', target='192.0.2.18',
        policy_reason='baseline_observe_only', command_plan=[], rollback_plan=[])
    return event


def run_pair(output: Path, *, snapshot='complete'):
    require_container()
    import grp
    import pwd
    import pytest
    import test_knowledge_lited as lite
    from test_knowledge_lookup import _producer_manifest, admit_rows
    from test_knowledge_context_process_interop import _pki, _ready, _wait_socket
    from test_mio_process_integration import _credentials, _owned_dir, _own_tree, _send_edge_alert
    from azazel_nexus.incident_explain import read_record
    from azazel_nexus.spki import spki_pin
    import ssl

    output.mkdir(parents=True, exist_ok=False)
    root = Path(tempfile.mkdtemp(prefix='weekend-', dir='/tmp'))
    root.chmod(0o755)
    children = []
    roles = {}
    readiness = {}
    receipt = dict(schema='weekend-paired/v1', synthetic=True, snapshot=snapshot,
        production_constants_unchanged=True, network='none', cases={}, processes=[],
        input_classification='P0 is authored synthetic public text; P3 is the Edge producer frame',
        recipe_sha256=_digest(Path(__file__)), model_sends=0)
    receipt['model_send_scope'] = 'no model process or provider configured; actual slow replies must remain closed'

    def launch(role, argv, user=None, groups=(), env=None):
        child = subprocess.Popen(argv, cwd=REPO, env=env or runtime_env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            preexec_fn=_credentials(user, groups) if user else None)
        children.append(child)
        roles[child.pid] = role
        # /proc start identity distinguishes PID reuse in this owned namespace.
        stat = Path(f'/proc/{child.pid}/stat').read_text().rsplit(')', 1)[1].split()
        receipt['processes'].append(dict(role=role, pid=child.pid, start_ticks=stat[19],
            uid=pwd.getpwnam(user).pw_uid if user else os.getuid()))
        return child

    def ready(child):
        value = _ready(child)
        readiness[child.pid] = json.dumps(value) + '\n'
        (output / f'{roles[child.pid]}.ready.json').write_text(json.dumps(value) + '\n')
        return value

    try:
        with pytest.MonkeyPatch.context() as env_patch:
            _, store, trust, _ = lite.node.__wrapped__(root, env_patch)
            manifest, rows = _producer_manifest()
            admit_rows((None, store, trust, None), rows, profile=manifest['profile'])
        users = {n: pwd.getpwnam(n) for n in ('azknowledge', 'azmio', 'azmioentry',
                 'azknowledgeegress', 'azintake', 'azexplain')}
        gid = lambda n: grp.getgrnam(n).gr_gid
        az = root / 'var/lib/azazel'
        for p, mode in ((root / 'var', 0o755), (root / 'var/lib', 0o755),
                        (az, 0o711), (az / 'run', 0o711), (az / 'run/ui-read', 0o711),
                        (az / 'state', 0o711)):
            _owned_dir(p, 0, 0, mode)
        leaves = [
            ('run/knowledge', 'azknowledge', 'azazel-operator', 0o2710),
            ('run/knowledge-read', 'azknowledge', 'azknowledge-read', 0o2710),
            ('run/knowledge-status', 'azknowledge', 'azazel-operator', 0o2750),
            ('run/knowledge-context', 'azknowledgeegress', 'azknowledge-context-client', 0o2710),
            ('run/mio', 'azmio', 'azazel-operator', 0o2710),
            ('run/mio-entry', 'azmioentry', 'azazel-operator', 0o2710),
            ('run/mio-advise', 'azmioentry', 'azmio-advise', 0o2710),
            ('run/mio-status', 'azmioentry', 'azazel-operator', 0o2750),
            ('run/ui-read/mio', 'azmioentry', None, 0o2750),
            ('run/ui-read/knowledge', 'azknowledge', None, 0o2750),
            ('run/edge-intake', 'azintake', 'azedge', 0o2710),
            ('run/edge-intake-status', 'azintake', 'azazel-operator', 0o2750),
            ('run/incident-explain-status', 'azexplain', 'azazel-operator', 0o2750),
            ('run/ui-read/edge-intake', 'azintake', None, 0o2750),
            ('run/ui-read/incident-explain', 'azexplain', None, 0o2750),
            ('state/knowledge', 'azknowledge', None, 0o700),
            ('state/mio', 'azmioentry', None, 0o700),
            ('state/knowledge-context', 'azknowledgeegress', None, 0o700),
            ('mio', 'azmio', None, 0o750),
            ('edge-intake', 'azintake', None, 0o700),
            ('edge-incidents', 'azintake', 'azincident-read', 0o2750),
            ('incident-explain', 'azexplain', None, 0o700),
        ]
        for leaf, user, group, mode in leaves:
            _owned_dir(az / leaf, users[user].pw_uid, gid(group) if group else 0, mode)
        _own_tree(store, users['azknowledge'].pw_uid, gid('azazel-operator'))
        _own_tree(trust, users['azknowledge'].pw_uid, users['azknowledge'].pw_gid)
        pki = _pki(root / 'pki')
        ingress = root / 'knowledge-ingress.jsonl'
        runtime_env = {**os.environ, 'AZAZEL_ROOT': str(root)}
        server = launch('knowledge', [sys.executable, '-B', '-m', 'azazel_nexus_lab.weekend_knowledge',
            '--root', str(root / 'knowledge-root'), '--pki', str(pki), '--snapshot', snapshot,
            '--ingress', str(ingress)])
        knowledge_ready = ready(server)
        assert knowledge_ready['host'] == '127.0.0.1' and knowledge_ready['pid'] == server.pid
        pki.chmod(0o750)
        os.chown(pki, 0, users['azknowledgeegress'].pw_gid)
        for name in ('ca.pem', 'nexus.pem', 'nexus.key'):
            path = pki / name
            path.chmod(0o640 if name.endswith('.key') else 0o644)
            os.chown(path, 0, users['azknowledgeegress'].pw_gid)
        broker_log = root / 'broker-ingress.jsonl'
        broker_log.touch(mode=0o600)
        os.chown(broker_log, users['azknowledgeegress'].pw_uid, users['azknowledgeegress'].pw_gid)
        # The broker writes only its own ingress counter under an owned leaf.
        broker_log_target = az / 'state/knowledge-context/broker-ingress.jsonl'
        broker_log.rename(broker_log_target)
        broker_args = [sys.executable, '-B', '-m', 'azazel_nexus_lab.weekend_broker', str(root),
            str(pki), str(knowledge_ready['port']), knowledge_ready['public_key'],
            spki_pin(ssl.PEM_cert_to_DER_cert((pki / 'server.pem').read_text()))]
        broker = launch('broker', broker_args, 'azknowledgeegress')
        assert ready(broker)['ready']
        for role, user, groups, module, opts in (
            ('lite', 'azknowledge', ('azazel-operator',), 'azazel_nexus_runtime.knowledge_lited', []),
            ('locald', 'azmio', ('azknowledge-read', 'azknowledge-context-client', 'azmission-read'),
             'azazel_nexus_lab.weekend_locald', ['--lite'] if snapshot == 'complete' else []),
            ('entryd', 'azmioentry', ('azazel-operator',), 'azazel_nexus_runtime.mio_entryd', []),
        ):
            launch(role, [sys.executable, '-B', '-m', module, *opts], user, tuple(map(gid, groups)))
        for leaf in ('knowledge-read', 'mio', 'mio-advise'):
            _wait_socket(az / f'run/{leaf}/{leaf}.sock', children[-1])

        def request(frame):
            code = ('import json,sys; from azazel_nexus_runtime.mio_socket_client import _exchange; '
                    'print(json.dumps(_exchange("mio-entry","azmioentry","mio.advise",'
                    '{"deadline_ms":5000},payload=json.loads(sys.stdin.read()),deadline_s=5.25)))')
            value = subprocess.run([sys.executable, '-B', '-c', code], input=json.dumps(frame),
                cwd=REPO, env=runtime_env, capture_output=True, text=True, timeout=8,
                preexec_fn=_credentials('azoperator', (gid('azazel-operator'),)))
            index = len(list(output.glob('operator-*.exit')))
            for suffix, text in (('stdout', value.stdout), ('stderr', value.stderr),
                                 ('exit', str(value.returncode) + '\n')):
                (output / f'operator-{index}.{suffix}').write_text(text)
            assert value.returncode == 0, 'operator entry request failed'
            return json.loads(value.stdout)

        from azazel_nexus_lab.weekend_ui import noc_frame
        p0 = request(noc_frame())
        fast = p0['fast_assistance']
        assert fast['full_node_context_status'] == 'received'
        advisory = fast['fabric_knowledge_context_advisory']
        assert advisory['snapshot_state'] == snapshot
        assert advisory['authority'] == 'advisory_only'
        assert advisory['trust'] == 'unverified_advisory_only'
        assert advisory['claim_status'] == 'source_reported_unverified'
        assert bool(fast['knowledge']) == (snapshot == 'complete')
        assert fast['trace_id']
        if snapshot == 'partial':
            assert 'KNOWLEDGE_CONTEXT_PARTIAL' in fast['unknowns']
        assert p0['slow_analysis']['state'] == 'closed'
        receipt['cases']['P01' if snapshot == 'complete' else 'P02'] = p0
        before = (_count(broker_log_target), _count(ingress))
        assert min(before) > 0

        for role, user, groups, module in (
            ('intake', 'azintake', ('azincident-read',), 'azazel_nexus_runtime.edge_intaked'),
            ('explainer', 'azexplain', ('azincident-read', 'azknowledge-read', 'azmio-advise'),
             'azazel_nexus_runtime.incident_explaind')):
            launch(role, [sys.executable, '-B', '-m', module], user, tuple(map(gid, groups)))
        _wait_socket(az / 'run/edge-intake/edge-intake.sock', children[-2])
        until = time.monotonic() + 10
        while not (az / 'run/incident-explain-status/status.json').exists():
            assert children[-1].poll() is None and time.monotonic() < until, 'explainer not ready'
            time.sleep(.025)
        _send_edge_alert(runtime_env, az / 'run/edge-intake/edge-intake.sock', (gid('azedge'),))
        until = time.monotonic() + 12
        record = None
        while time.monotonic() < until:
            assert all(c.poll() is None for c in children)
            files = sorted((az / 'incident-explain/explanations').glob('*.jsonl'))
            lines = [line for p in files for line in p.read_bytes().splitlines()]
            if lines:
                record = read_record(json.loads(lines[0]))
                break
            time.sleep(.05)
        assert record is not None, 'no actual intake/explainer record'
        p3 = record['mio']['fast_assistance']
        assert p3['full_node_context_status'] == 'not_queried'
        assert p3['generation_method'] == 'static_reference'
        assert p3['unknowns'] and p3['next_checks']
        assert p3['handoff']['current_action'] is None
        assert p3['trace_id'] == f"mio-{record['incident_id'][4:]}-{record['incident_sequence']}"
        after = (_count(broker_log_target), _count(ingress))
        assert after == before, 'P3 caused full context egress'
        receipt['cases']['P04'] = dict(record=record, broker_ingress=after[0]-before[0],
            knowledge_ingress=after[1]-before[1], generated_sends=0)
        # A distinct NOC incident through the SAME actual intake/explainer chain.
        # The authored report remains P3 in this envelope; P01's public operator
        # request above is separate and is never relabelled as incident evidence.
        from azazel_nexus.edge_intake import EvidenceRecord, IncidentTracker, parse_edge_event
        event = noc_event()
        raw = json.dumps(event).encode()
        expected_incident = IncidentTracker(lambda: 0).add(
            EvidenceRecord.receive(parse_edge_event(raw), lambda: 0))[0]['incident_id']
        assert expected_incident != record['incident_id']
        (output / 'noc-input.json').write_bytes(raw + b'\n')
        sent = subprocess.run([sys.executable, '-B', '-c',
            'import socket,sys; s=socket.socket(socket.AF_UNIX); s.settimeout(2); '
            's.connect(sys.argv[1]); s.sendall(sys.stdin.buffer.read()); s.close()',
            str(az / 'run/edge-intake/edge-intake.sock')], input=raw + b'\n',
            cwd=REPO, env=runtime_env, capture_output=True, timeout=4,
            preexec_fn=_credentials('azedge', (gid('azedge'),)))
        assert sent.returncode == 0, 'NOC synthetic intake failed'
        until = time.monotonic() + 12
        publication_started = time.monotonic()
        noc_record = None
        published = None
        from azazel_nexus.runtime_paths import incident_recent_path
        recent_paths = {reader: incident_recent_path(root, reader=reader)
                        for reader in ('operator', 'ui')}
        while time.monotonic() < until:
            assert all(c.poll() is None for c in children)
            for path in sorted((az / 'incident-explain/explanations').glob('*.jsonl')):
                for line in path.read_bytes().splitlines():
                    candidate = read_record(json.loads(line))
                    if candidate['incident_id'] == expected_incident:
                        noc_record = candidate
            if noc_record is not None:
                # Use the SAME existing 12 s deadline for ledger + publication.
                # recent_status() publishes at most once per 5 s; a durable
                # explanation alone does not make the read model ready.
                published = published_incidents(recent_paths, (record, noc_record))
                if published is not None:
                    break
            time.sleep(.05)
        assert noc_record is not None, 'no NOC incident explanation'
        assert published is not None, 'NOC/SOC explanations not published to operator/UI within existing deadline'
        receipt['read_model_publication'] = dict(deadline_s=12,
            elapsed_s=time.monotonic() - publication_started,
            written_at={reader: value['written_at'] for reader, value in published.items()})
        for reader, value in published.items():
            (output / f'recent-{reader}.json').write_text(json.dumps(value, indent=2) + '\n')
        noc_fast = noc_record['mio']['fast_assistance']
        assert noc_fast['full_node_context_status'] == 'not_queried'
        assert noc_fast['generation_method'] == 'static_reference'
        assert noc_fast['unknowns'] and noc_fast['next_checks']
        assert noc_fast['handoff']['current_action'] is None
        assert noc_fast['trace_id'] == f"mio-{expected_incident[4:]}-{noc_record['incident_sequence']}"
        assert (_count(broker_log_target), _count(ingress)) == after
        receipt['noc_incident'] = dict(record=noc_record, input_sha256=_digest(output / 'noc-input.json'),
            input_kind='authored_synthetic_report_in_edge_envelope_not_measured_outage',
            broker_ingress=0, knowledge_ingress=0, generated_sends=0)
        # Same live producer/broker: prove actual unavailable then recovery.
        broker.terminate()
        broker.wait(timeout=5)
        unavailable = request(noc_frame('weekend-recovery-down'))
        assert unavailable['fast_assistance']['full_node_context_status'] == 'unavailable'
        broker = launch('broker-recovery', broker_args, 'azknowledgeegress')
        assert ready(broker)['ready']
        recovered = request(noc_frame('weekend-recovery-up'))
        assert recovered['fast_assistance']['full_node_context_status'] == 'received'
        receipt['cases']['P03'] = dict(down=unavailable, recovered=recovered)
        receipt['counters'] = dict(broker_ingress=_count(broker_log_target), knowledge_ingress=_count(ingress))
        from azazel_nexus_lab.weekend_fixture import fixture_lane, production_control
        from azazel_nexus_runtime.mio_fast_assistance import _frame
        fixture, cap = fixture_lane(REPO, None)
        assert fixture._authorized(cap.generation_id) is True
        receipt['same_cap_control'] = production_control(cap, None, _frame(noc_frame()))
        # Preserve the actual status read model for the later real browser.
        status = subprocess.run([sys.executable, '-B', '-m', 'azazel_nexus.cli',
            'status', '--json'], cwd=REPO, env=runtime_env, capture_output=True, text=True, timeout=15)
        (output / 'status.stdout').write_text(status.stdout)
        (output / 'status.stderr').write_text(status.stderr)
        (output / 'status.exit').write_text(str(status.returncode) + '\n')
        assert status.returncode == 0, 'status read model export failed'
        view = json.loads(status.stdout)
        assert view['schema'] == 'azazel-nexus/status-view/1'
        visible = {row['incident_id'] for row in
                   view['sections']['edge_loop']['recent']['snapshot']['incidents']}
        assert {record['incident_id'], noc_record['incident_id']} <= visible
        (output / 'status-view.json').write_text(json.dumps(view, ensure_ascii=False, indent=2) + '\n')
        receipt['handoffs'] = {}
        for case, incident in (('SOC1', record), ('NOC1', noc_record)):
            label = 'handoff' if case == 'SOC1' else 'noc-handoff'
            handoff = output / label
            handoff.mkdir(mode=0o700)
            exported = subprocess.run([sys.executable, '-B', '-m', 'azazel_nexus.cli', 'handoff',
                'export', '--incident', incident['incident_id'], '--output-dir', str(handoff)],
                cwd=REPO, env=runtime_env, capture_output=True, text=True, timeout=15)
            for suffix, text in (('stdout', exported.stdout), ('stderr', exported.stderr),
                                 ('exit', str(exported.returncode) + '\n')):
                (output / f'{label}.{suffix}').write_text(text)
            assert exported.returncode == 0, 'ordinary handoff export failed'
            receipt['handoffs'][case] = {**verify_handoff(handoff, incident['incident_id']),
                'incident_id': incident['incident_id'],
                'trace_id': incident['mio']['fast_assistance']['trace_id']}
        receipt['handoff_files'] = receipt['handoffs']['SOC1']['files']
        (output / 'paired.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n')
        return receipt
    finally:
        (output / 'paired-attempt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n')
        # Preserve only public snapshots and synthetic ledger outputs, never PKI,
        # private state or trust. Take these before graceful stop changes status.
        capture_error = None
        try:
            for leaf in ('run/edge-intake-status', 'run/incident-explain-status',
                         'run/ui-read/edge-intake', 'run/ui-read/incident-explain',
                         'edge-incidents', 'incident-explain/explanations',
                         'incident-explain/generation-results'):
                source = root / 'var/lib/azazel' / leaf
                if source.is_dir():
                    for path in source.iterdir():
                        if not path.is_symlink() and path.is_file() and path.suffix in {'.json', '.jsonl'}:
                            target = output / 'process-artifacts' / leaf / path.name
                            target.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copyfile(path, target)
            for name, path in (('broker-ingress.jsonl', root / 'var/lib/azazel/state/knowledge-context/broker-ingress.jsonl'),
                               ('knowledge-ingress.jsonl', root / 'knowledge-ingress.jsonl')):
                if path.is_file():
                    shutil.copyfile(path, output / name)
        except Exception as exc:  # cleanup still owns and stops every child
            capture_error = exc
        cleanup = []
        cleanup_ok = True
        for child in reversed(children):
            if child.poll() is None:
                child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cleanup_ok = False
                child.kill()
                child.wait(timeout=5)
            role = roles[child.pid]
            cleanup.append(dict(role=role, pid=child.pid, exit=child.returncode))
            stdout, stderr = child.communicate(timeout=5)
            (output / f'{role}.stdout').write_text(readiness.get(child.pid, '') + stdout)
            (output / f'{role}.stderr').write_text(stderr)
            (output / f'{role}.exit').write_text(str(child.returncode) + '\n')
        (output / 'cleanup.json').write_text(json.dumps(dict(clean=cleanup_ok, processes=cleanup)) + '\n')
        shutil.rmtree(root)
        if not cleanup_ok:
            raise AssertionError('owned daemon did not stop within the cleanup deadline')
        if capture_error is not None:
            raise AssertionError('process artifact capture failed') from capture_error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--snapshot', choices=('complete', 'partial'), default='complete')
    args = parser.parse_args(argv)
    run_pair(args.output, snapshot=args.snapshot)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
