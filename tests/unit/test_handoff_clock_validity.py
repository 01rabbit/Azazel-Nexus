"""時計契約の公開digestだけを閉じた保存fieldで許可。ネットワークなし。"""
import copy
from datetime import datetime,timedelta
import pytest
from azazel_nexus import handoff
from azazel_fabric.knowledge_context_clocklab import ClockContract
from azazel_nexus.technique_knowledge import project_technique_response
from _technique_fixture import make_response

def record():
 c=ClockContract(skew_budget_us=5000);r=make_response(['T1110']);x=r['expires_at'];e=datetime.fromisoformat(x.replace('Z','+00:00'));r.update(schema_version='knowledge-context-response/v2',contract_id=c.contract_id)
 v={'schema':'azazel-knowledge-clock-validity/1','contract_id':c.contract_id,'signed_expires_at':x,'semantic_expires_at':x,'effective_expires_at':(e-timedelta(milliseconds=5)).isoformat().replace('+00:00','Z'),'adopted_at':(e-timedelta(seconds=1)).isoformat().replace('+00:00','Z'),'skew_budget_us':5000,'health_generation':['n','k',1,0]}
 return project_technique_response({'response':r,'validity':v},['T1110'])
def package(tk=None):return {'knowledge':{'full_node_context':{'technique_knowledge':tk or record()}}}
def test_closed_v2_digest_exports():
 p=package();assert handoff.scan_package(p)==[]
 assert handoff._clock_contract_digest(p)==ClockContract(skew_budget_us=5000).contract_id
@pytest.mark.parametrize('path',[('contract_id',),('other','contract_id'),('knowledge','full_node_context','contract_id')])
def test_wrong_path_still_refuses(path):
 p={};q=p
 for k in path[:-1]:q=q.setdefault(k,{})
 q[path[-1]]=ClockContract(skew_budget_us=5000).contract_id
 assert 'hex_value' in handoff.scan_package(p)
@pytest.mark.parametrize('field,value',[('contract_id','sha256:'+'a'*63),('contract_id','sha256:'+'A'*64),('contract_id','a'*64),('skew_budget_us',True),('effective_expires_at','2026-11-13T00:01:10Z'),('semantic_expires_at','2026-11-13T00:02:10Z'),('health_generation',['n','k',1.0,0])])
def test_invalid_binding_refuses(field,value):
 p=package();p['knowledge']['full_node_context']['technique_knowledge']['validity'][field]=value
 assert 'hex_value' in handoff.scan_package(p)
def test_free_secret_hex_not_widened():
 p=package();p['free_text']='a'*64
 assert 'hex_value' in handoff.scan_package(p)
def test_extra_projection_field_refuses():
 p=package();p['knowledge']['full_node_context']['technique_knowledge']['extra']='code'
 assert 'hex_value' in handoff.scan_package(p)
def test_v1_without_contract_unchanged():
 r=make_response(['T1110']);p=package(project_technique_response(r,['T1110']))
 assert handoff.scan_package(p)==[]

@pytest.mark.parametrize('expired',[False,True])
def test_complete_ui_package_encodes_current_and_expired(tmp_path,monkeypatch,expired):
 from test_handoff_full_context_ui import _fn
 from azazel_nexus.technique_knowledge import display_projection
 fn,p=_fn(tmp_path,monkeypatch,'clock-export',None)
 tk=record();e=datetime.fromisoformat(tk['expires_at'].replace('Z','+00:00'))
 fn['technique_knowledge']=display_projection(tk,(e+timedelta(seconds=1) if expired else e-timedelta(seconds=1)).timestamp(),health_check=lambda **kw:True)
 files=handoff.encode_files(p)
 assert len(files)==3 and b'sha256:' in files[handoff.JSON_NAME]
 assert fn['technique_knowledge']['server_validity']['usable'] is (not expired)


def test_old_contract_past_reference_exports_without_becoming_usable(tmp_path,monkeypatch):
 from test_handoff_full_context_ui import _fn
 from azazel_nexus.technique_knowledge import display_projection
 fn,p=_fn(tmp_path,monkeypatch,'old-clock-export',None)
 tk=record();tk['validity']['contract_id']='sha256:cf12b6f9e68bdde9d8ab9f99218d18d2ea61d15b45e94ca7acf9123595598df6'
 e=datetime.fromisoformat(tk['expires_at'].replace('Z','+00:00'))
 def closed_health(**kw):raise ValueError('past policy is not current authority')
 fn['technique_knowledge']=display_projection(tk,(e+timedelta(seconds=1)).timestamp(),health_check=closed_health)
 assert fn['technique_knowledge']['server_validity']['usable'] is False
 assert len(handoff.encode_files(p))==3


@pytest.mark.parametrize('reason,label',[('clock_unknown','時刻未確認'),('clock_health_unavailable','時刻監視未確認'),('clock_rollback','時計逆行')])
def test_closed_clock_reason_markdown_is_not_windows_path(tmp_path,monkeypatch,reason,label):
 from test_handoff_full_context_ui import _fn
 from azazel_nexus.technique_knowledge import display_projection
 fn,p=_fn(tmp_path,monkeypatch,'clock-reason-export',None)
 tk=record();e=datetime.fromisoformat(tk['expires_at'].replace('Z','+00:00'))
 fn['technique_knowledge']=display_projection(tk,(e-timedelta(seconds=1)).timestamp(),health_check=lambda **kw:True)
 fn['technique_knowledge']['server_validity'].update(usable=False,reason=reason)
 files=handoff.encode_files(p)
 assert label in files[handoff.MARKDOWN_NAME].decode()
 assert reason in files[handoff.JSON_NAME].decode()
 assert handoff.scan_markdown(files[handoff.MARKDOWN_NAME].decode())==[]
