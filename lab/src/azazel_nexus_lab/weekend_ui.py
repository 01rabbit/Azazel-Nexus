"""Lab-only trace/NOC supplement to the actual read-only UI and login boundary."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import threading

NOC_QUESTION = ('Synthetic service monitor reports intermittent SSH reachability after an approved '
                'maintenance window. T1110 is a caller-supplied tag. What can be checked safely?')
NOC_CONTEXT = 'No packet capture, signed availability measurement, or approved change record was supplied.'


def noc_frame(request_id='weekend-noc1'):
    return dict(request_id=request_id, privacy_class='P0-public', question=NOC_QUESTION,
                context=[dict(kind='operator_report', text=NOC_CONTEXT)])


def panels(receipt):
    """Allowlisted projection from the SAME paired receipt; no raw frame/body."""
    from azazel_nexus.incident_explain import read_record
    records = [('NOC1', read_record(receipt['noc_incident']['record'])),
               ('SOC1', read_record(receipt['cases']['P04']['record']))]
    if records[0][1]['incident_id'] == records[1][1]['incident_id']:
        raise ValueError('lab UI requires distinct NOC and SOC incidents')
    rows = []
    for name, record in records:
        fast = record['mio']['fast_assistance']
        expected = f"mio-{record['incident_id'][4:]}-{record['incident_sequence']}"
        if fast['trace_id'] != expected or fast['frame_id'] != expected + ':frame':
            raise ValueError('lab UI requires incident-bound trace')
        assert fast['generation_method'] == 'static_reference'
        assert fast['unknowns'] and fast['next_checks'] and fast['handoff']['current_action'] is None
        rows.append(dict(case=name, incident_id=record['incident_id'], trace_id=fast['trace_id'],
            frame_id=fast['frame_id'], method=fast['generation_method'],
            evidence=('Validated intake of an authored synthetic service report in an Edge-shaped envelope; '
                      'outage and maintenance remain unverified. T1110 is a caller tag, not a measured cause.' if name == 'NOC1' else
                      'Validated intake transition; refs remain in the incident evidence plane.'),
            unknowns=list(fast['unknowns']), next_checks=list(fast['next_checks']),
            handoff=dict(current_action=None, frame_id=fast['handoff']['frame_id']),
            association='incident_bound',
            # Context-specific operator checks are predeclared lab guidance,
            # visually separate from actual MIO next_checks above.
            lab_guidance=('Read authorized service reachability records, trusted timestamps, maintenance '
                          'approval and affected scope; cause and actual outage remain unknown.' if name == 'NOC1'
                          else 'Compare authentication times/counts with approved automation and change records; '
                               'hostile and benign explanations remain unresolved.')))
    return dict(schema='weekend-ui/v1', synthetic=True, rows=rows,
        clock_notice='Snapshot and browser clocks are distinct; unknown/stale is not healthy.',
        deception='shadow replay only; execution_results=not_accepted; no decoy or redirect is started',
        semantic_acceptance='human_review_required; lab guidance is not generated MIO output')


SCRIPT = '''"use strict";
async function weekendRefresh() {
  const response = await fetch('/api/view', {credentials:'same-origin', cache:'no-store'});
  const box = document.getElementById('weekend-receipt');
  box.replaceChildren();
  if (!response.ok) { box.hidden = true; return; }
  const data = (await response.json()).weekend_lab;
  if (!data) { box.hidden = true; return; }
  box.hidden = false;
  function line(parent, tag, text, cls) {
    const e = document.createElement(tag); e.textContent = text;
    if (cls) e.className = cls; parent.appendChild(e); return e;
  }
  line(box, 'h2', '隔離 lab: NOC / SOC / trace (synthetic・読取専用)');
  line(box, 'p', data.clock_notice, 'weekend-clock');
  line(box, 'p', data.deception, 'weekend-shadow');
  line(box, 'p', data.semantic_acceptance);
  data.rows.forEach(row => {
    const article = line(box, 'article', '', 'weekend-case'); article.id = row.case;
    line(article, 'h3', row.case);
    ['incident_id','trace_id','frame_id','method','association'].forEach(k => line(article,'p', k+': '+row[k], k));
    line(article,'p', '根拠: '+row.evidence, 'weekend-evidence');
    line(article,'p', '不明: '+row.unknowns.join(' / '), 'weekend-unknowns');
    line(article,'p', 'MIOの次確認: '+row.next_checks.join(' / '), 'weekend-checks');
    line(article,'p', '事前固定lab手順: '+row.lab_guidance, 'weekend-guidance');
    line(article,'p', '引継ぎ: '+row.handoff.frame_id+'; current_action=null', 'weekend-handoff');
  });
}
weekendRefresh(); setInterval(weekendRefresh, 2000);
'''.encode('utf-8')


def supplement(app, receipt):
    data = panels(receipt)
    # Change only this lab app instance's static asset copies.
    for route in ('/', '/index.html'):
        body, kind = app.static[route]
        body = body.replace(b'</body>', b'<section id="weekend-receipt" hidden></section>'
            b'<script src="/static/weekend.js" defer></script></body>')
        app.static[route] = body, kind
    app.static['/static/weekend.js'] = SCRIPT, 'text/javascript; charset=utf-8'
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--login-file', type=Path, required=True)
    args = parser.parse_args(argv)
    from azazel_nexus.ui_model import browser_json
    from azazel_nexus_runtime import ui_serve as ui
    listener = ui.adopt_listener(__import__('os').environ, __import__('os').getpid())

    class LabUiApp(ui.UiApp):
        def view_document(self):
            value = json.loads(super().view_document())
            value['weekend_lab'] = self.weekend_data
            return browser_json(value)

    app = LabUiApp(source=ui.FixtureSource(args.fixture),
        codes=ui.LoginCodes(ui.publish_to(args.login_file), f'http://127.0.0.1:{listener.getsockname()[1]}/'),
        port=listener.getsockname()[1])
    app.weekend_data = supplement(app, json.loads(args.receipt.read_text()))
    app.codes.tick(app.clock())
    stop = threading.Event()
    threading.Thread(target=ui._rotate, args=(app, stop), daemon=True).start()
    server = ui.AdoptedServer(listener, ui.UiHandler, app)
    try:
        server.serve_forever(poll_interval=.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        server.server_close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
