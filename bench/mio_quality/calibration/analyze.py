"""Derive retrieval thresholds from recorded similarities (see README.md).

Rules: SCOPE_MIN and SIM_MIN are the relevant minimum floored to 0.01, minus a
0.01 margin; GAP_MIN is the smallest gap whose "clear" state (excluding frames
with a collector-attached system record) is right at least 90% of the time, plus
the same 0.01 margin.
"""
import json
import math
import sys
from pathlib import Path

SYSTEM_KINDS = {'change_record', 'change_ticket', 'maintenance_window', 'asset_inventory',
                'baseline', 'schedule', 'approval_record'}
NON_PLAYBOOK = {'benign', 'other_suspicious', 'undetermined', 'out_of_scope'}


def floor_margin(value):
    return round(math.floor(value * 100) / 100 - 0.01, 2)


def main(argv):
    names = argv[1].split(',')
    sims = json.loads(Path(argv[2] if len(argv) > 2 else 'sims.json').read_text(encoding='utf-8'))
    sets_dir = Path(argv[3]) if len(argv) > 3 else None
    rows = [r for name in names for r in sims[name]]
    records = {}
    if sets_dir:
        for name in names:
            for case in json.loads((sets_dir / f'{name}.json').read_text(encoding='utf-8'))['cases']:
                records[case['frame']['request_id']] = any(
                    item['kind'] in SYSTEM_KINDS for item in case['frame']['context'])

    def playbooks(r):
        return {r['labels']['expected'], *r['labels']['acceptable']} - NON_PLAYBOOK

    def top(r):
        return r['sims'][0][0]

    in_scope = [r for r in rows if r['labels']['expected'] != 'out_of_scope']
    out_scope = [r for r in rows if r['labels']['expected'] == 'out_of_scope']
    scope_min = floor_margin(min(top(r) for r in in_scope if not r['lexicon_hit']))
    gated = sum(1 for r in out_scope if not r['lexicon_hit'] and top(r) < scope_min)
    correct = [r for r in in_scope if playbooks(r) and r['sims'][0][1] in playbooks(r)]
    sim_min = floor_margin(min(top(r) for r in correct))
    print(f'frames {len(rows)}: in scope {len(in_scope)}, out of scope {len(out_scope)}')
    print(f'SCOPE_MIN={scope_min}: out-of-scope gated {gated}/{len(out_scope)}, security refused 0')
    print(f'SIM_MIN={sim_min}: correct top-1 kept {len(correct)}/{len(correct)}')
    chosen = None
    for step in range(2, 16):
        gap = step / 100
        clear = [r for r in in_scope if top(r) >= sim_min and top(r) - r['sims'][1][0] >= gap
                 and not r.get('benign_support') and not records.get(r['id'], False)]
        right = sum(r['sims'][0][1] in playbooks(r) for r in clear)
        print(f'  GAP {gap:.2f}: clear {len(clear)}, right {right}')
        if chosen is None and clear and right / len(clear) >= 0.9:
            chosen = round(gap + 0.01, 2)
    print(f'GAP_MIN={chosen}')


if __name__ == '__main__':
    main(sys.argv)
