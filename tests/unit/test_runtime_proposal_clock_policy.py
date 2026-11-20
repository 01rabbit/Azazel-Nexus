"""Explicit formal v4 export and adversarial file/prompt boundaries; no admission."""
import json,os,stat
from types import SimpleNamespace
import pytest

# The lab clock contract exists only in the unpublished candidate Fabric (ADR-0011);
# against the pinned tag these modules are not applicable.
pytest.importorskip("azazel_fabric.knowledge_context_clocklab")
from azazel_fabric.knowledge_context_clocklab import ClockContract
from azazel_nexus import commissioning_draft
from azazel_nexus.commissioning_approval import verify_commissioning_proposal
from azazel_nexus.fabric_boundary import restore_commissioning_inputs
from azazel_nexus.operator_trust import ApprovalPurpose,ApprovalRefused,approval_message
from azazel_nexus_runtime import commission_cli,proposal_export
from test_runtime_proposal_export import export_scope,_set_interactive
POLICY=ClockContract(skew_budget_us=5000).as_dict()

@pytest.fixture
def policy_file(tmp_path,monkeypatch):
 p=tmp_path/'clock-policy.json';p.write_text(json.dumps(POLICY));p.chmod(0o600)
 original=proposal_export._policy_stat
 # The sandbox's own ancestors (a Linux CI /tmp is 1777) are outside the test's
 # control; only they are masked. The policy file and the directory holding it
 # keep every real mode check, so the writable-parent refusals stay exercised.
 outside=set()
 for ancestor in p.parent.parents:
  info=ancestor.stat();outside.add((info.st_dev,info.st_ino))
 def host_owner(info,*,directory=False):
  # Host fixture has no root privilege; retain all real mode/type/inode checks.
  info=SimpleNamespace(**{name:getattr(info,name) for name in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')})
  info.st_uid=0
  if directory and (info.st_dev,info.st_ino) in outside:info.st_mode&=~(stat.S_ISVTX|stat.S_IWGRP|stat.S_IWOTH)
  return original(info,directory=directory)
 monkeypatch.setattr(proposal_export,'_policy_stat',host_owner)
 return p

def invoke(export_scope,monkeypatch,p,profile='FULL',on_confirm=None):
 _set_interactive(monkeypatch)
 def answer(prompt):
  if 'ceiling' in prompt:return profile
  if on_confirm:on_confirm()
  return 'EXPORT'
 monkeypatch.setattr('builtins.input',answer)
 return commission_cli.main(['proposal-export','--operator','operator-a','--clock-policy',str(p)])

def test_formal_cli_v4_protected_bytes_and_full_signature(export_scope,monkeypatch,policy_file,tmp_path):
 protected=tmp_path/'protected';protected.mkdir(mode=0o700)
 monkeypatch.setattr(commissioning_draft,'COMMISSIONING_DIR',protected)
 monkeypatch.setattr(commissioning_draft,'luks_backed',lambda *a,**k:True)
 monkeypatch.setattr(commissioning_draft,'read_protection_key',lambda p:b'fixture-protection-key')
 monkeypatch.setattr(proposal_export,'retain_proposal_context',commissioning_draft.retain_proposal_context)
 assert invoke(export_scope,monkeypatch,policy_file)==0
 payload=(protected/'commissioning-proposal.json').read_bytes()
 assert payload==(protected/'commissioning-proposal.expected.json').read_bytes()
 doc=json.loads(payload);assert doc['schema']=='azazel-nexus/commissioning-proposal/v4' and doc['clock_policy']==POLICY
 signature=export_scope.key.sign(approval_message(ApprovalPurpose.COMMISSIONING_PROPOSAL,payload)).signature
 context=restore_commissioning_inputs(doc)
 verify_commissioning_proposal(trust=export_scope.trust,payload=payload,signature=signature,**context)
 changed=json.dumps({**doc,'clock_policy':ClockContract().as_dict()},sort_keys=True,separators=(',',':')).encode()
 with pytest.raises((ApprovalRefused,ValueError)):verify_commissioning_proposal(trust=export_scope.trust,payload=changed,signature=signature,**context)

@pytest.mark.parametrize('profile',['CORE','LITE'])
def test_policy_needs_full_before_export(export_scope,monkeypatch,policy_file,profile):
 assert invoke(export_scope,monkeypatch,policy_file,profile)==1;assert export_scope.writes==[]

@pytest.mark.parametrize('change',['bytes','identity','mode','parent_identity','unlink'])
def test_confirmation_rereads_raw_bytes_and_path_identity(export_scope,monkeypatch,policy_file,change):
 def alter():
  if change=='bytes':policy_file.write_text(json.dumps(POLICY,indent=2))
  elif change=='identity':
   replacement=policy_file.with_suffix('.new');replacement.write_bytes(policy_file.read_bytes());replacement.chmod(0o600);replacement.replace(policy_file)
  elif change=='mode':policy_file.chmod(0o640)
  elif change=='parent_identity':
   parent=policy_file.parent;old=parent.with_name(parent.name+'-old');parent.rename(old);parent.mkdir(mode=0o700);(parent/policy_file.name).write_bytes((old/policy_file.name).read_bytes())
  else:policy_file.unlink()
 assert invoke(export_scope,monkeypatch,policy_file,on_confirm=alter)==1;assert export_scope.writes==[]

@pytest.mark.parametrize('bad',[b'{"schema":1,"schema":2}',b'[]',b'null',b'{"a":NaN}',b'\xff',b'x'*4097])
def test_invalid_policy_never_retained(export_scope,monkeypatch,policy_file,bad):
 policy_file.write_bytes(bad);assert invoke(export_scope,monkeypatch,policy_file)==1;assert export_scope.writes==[]

@pytest.mark.parametrize('patch',[{'skew_budget_us':True},{'skew_budget_us':5001},{'skew_budget_us':0},{'max_observation_age_ms':4999},{'contract_id':'sha256:'+'f'*64},{'extra':1}])
def test_strict_finite_contract(export_scope,monkeypatch,policy_file,patch):
 policy_file.write_text(json.dumps({**POLICY,**patch}));assert invoke(export_scope,monkeypatch,policy_file)==1;assert export_scope.writes==[]

def test_symlink_and_hardlink_policy_refused(policy_file):
 link=policy_file.with_suffix('.link');link.symlink_to(policy_file)
 with pytest.raises(commissioning_draft.DraftRefused):proposal_export._clock_policy_input(str(link))
 link.unlink();os.link(policy_file,link)
 with pytest.raises(commissioning_draft.DraftRefused):proposal_export._clock_policy_input(str(policy_file))

def test_symlink_ancestor_and_writable_ancestor_refused(policy_file):
 parent=policy_file.parent;link=parent.parent/(parent.name+'-symlink');link.symlink_to(parent,target_is_directory=True)
 with pytest.raises(commissioning_draft.DraftRefused):proposal_export._clock_policy_input(str(link/policy_file.name))
 parent.chmod(0o777)
 try:
  with pytest.raises(commissioning_draft.DraftRefused):proposal_export._clock_policy_input(str(policy_file))
 finally:parent.chmod(0o700)

@pytest.mark.parametrize('path',['relative.json','/tmp/../etc/policy','/tmp/./policy','/tmp//policy'])
def test_ambiguous_path_refused(path):
 with pytest.raises(commissioning_draft.DraftRefused):proposal_export._clock_policy_input(path)

@pytest.mark.parametrize('patch,directory',[({'st_uid':1},False),({'st_uid':1},True),({'st_mode':stat.S_IFREG|0o622},False),({'st_mode':stat.S_IFDIR|0o775},True),({'st_nlink':2},False),({'st_size':4097},False)])
def test_production_owner_and_metadata_checks(tmp_path,patch,directory):
 p=tmp_path/'file';p.write_bytes(b'a');s=p.stat();d={n:getattr(s,n) for n in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')};d.update(st_uid=0,st_mode=(stat.S_IFDIR|0o755) if directory else (stat.S_IFREG|0o644));d.update(patch)
 with pytest.raises(commissioning_draft.DraftRefused):proposal_export._policy_stat(SimpleNamespace(**d),directory=directory)

def test_duplicate_otherwise_valid_policy_refused(policy_file):
 raw=json.dumps(POLICY);policy_file.write_text(raw[:-1]+',"skew_budget_us":5000}')
 with pytest.raises(commissioning_draft.DraftRefused):proposal_export._clock_policy_input(str(policy_file))

def test_valid_zero_contract_not_an_opt_in(policy_file):
 policy_file.write_text(json.dumps(ClockContract().as_dict()))
 with pytest.raises(commissioning_draft.DraftRefused):proposal_export._clock_policy_input(str(policy_file))

def test_changed_during_read_refused(policy_file,monkeypatch):
 original=os.read
 def read_then_change(fd,size):
  raw=original(fd,size);policy_file.write_bytes(raw+b' ');return raw
 monkeypatch.setattr(proposal_export.os,'read',read_then_change)
 with pytest.raises(commissioning_draft.DraftRefused):proposal_export._clock_policy_input(str(policy_file))

@pytest.mark.parametrize('args',[['proposal-export','--operator','operator-a','--clock-policy'],['proposal-export','--operator','operator-a','--clock-policy','/p','--clock-policy','/q'],['proposal-export','--operator','operator-a','--policy','/p']])
def test_invalid_opt_in_argv_never_collects(monkeypatch,args):
 monkeypatch.setattr(commission_cli,'read_links',lambda:pytest.fail('unexpected observation'))
 assert commission_cli.main(args)==2
