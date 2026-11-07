"""Explicit container entries; no host skip can turn required process evidence green."""
import os
from pathlib import Path

from azazel_nexus_lab.weekend_process import run_pair


def test_p01_complete_lite_p04_edge_zero_egress_and_p03_recovery_share_manifest():
    root = Path(os.environ['W4_RECEIPT_DIR'])
    value = run_pair(root / 'paired-complete', snapshot='complete')
    assert set(value['cases']) == {'P01', 'P03', 'P04'}
    assert value['cases']['P04']['knowledge_ingress'] == 0
    assert set(value['handoffs']) == {'NOC1', 'SOC1'}
    noc = value['noc_incident']['record']
    assert noc['incident_id'] != value['cases']['P04']['record']['incident_id']
    assert value['handoffs']['NOC1']['incident_id'] == noc['incident_id']
    assert value['handoffs']['NOC1']['trace_id'] == noc['mio']['fast_assistance']['trace_id']
    assert value['noc_incident']['knowledge_ingress'] == 0


def test_p02_partial_without_lite_preserves_warning():
    root = Path(os.environ['W4_RECEIPT_DIR'])
    value = run_pair(root / 'paired-partial', snapshot='partial')
    assert value['cases']['P02']['fast_assistance']['knowledge'] == []
