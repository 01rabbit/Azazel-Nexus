"""Real MIO source/receipt contract with a controlled provider; no model process."""
from dataclasses import replace
import json
import time

from test_budget_api import ControlledServer, FixtureLane, inputs


def test_real_mio_unknown_origin_survives_restart_without_model_body(tmp_path):
    class MissingEvidenceServer(ControlledServer):
        def infer(self, request, deadline_s, **kw):
            result = super().infer(request, deadline_s, **kw)
            value = json.loads(result.text)
            if 'hypotheses' in value:
                value['hypotheses'][0]['missing_evidence'] = ['MODEL-PRIVATE-SENTINEL']
                result = replace(result, text=json.dumps(value))
            return result
    frame, cap = inputs()
    server = MissingEvidenceServer()
    lane = FixtureLane(capability=cap,server=server,deadline_s=5,budget_enabled=True,
                       journal_dir=tmp_path/'journal')
    source = {'request_id':'api-restart'}
    receipt = lane.submit(source,frame,'api-fixture',upstream_coverage='intact',caller_epoch='epoch-before')
    end = time.monotonic()+2
    while time.monotonic() < end:
        value = lane.poll(receipt['result_handle'],'api-fixture',frame.trace_id,caller_epoch='epoch-before')
        if value['state'] != 'queued':
            break
        time.sleep(.002)
    assert value['state'] == 'complete', value
    worker = lane._worker
    if worker:
        worker.join(2)
        assert not worker.is_alive()
    private = lane._receipts[receipt['result_handle']]
    assert private['frame_unknowns']['um:1'] == 'MODEL-PRIVATE-SENTINEL'
    assert private['unknown_origins']['um:1'] == 'model_authored'
    payload = next((tmp_path/'journal').glob('*.json')).read_text()
    assert 'MODEL-PRIVATE-SENTINEL' not in payload and 'possible' not in payload
    resumed = FixtureLane(capability=cap,server=ControlledServer(),budget_enabled=True,
                          journal_dir=tmp_path/'journal')
    result = resumed.poll(receipt['result_handle'],'api-fixture',frame.trace_id,caller_epoch='epoch-after')
    assert result['state'] == 'degraded' and 'assistance' not in result
    unknown = next(u for u in resumed.private_observation('api-restart')['unknowns'] if u['id']=='um:1')
    assert unknown == dict(id='um:1',origin='model_asserted',category='model_unknown',status='unavailable_after_restart')
    assert resumed.submit(source,frame,'api-fixture')['state'] == 'degraded'
    assert not resumed.server.requests
