"""Record full similarity lists per frame with the production text formulas."""
import json
import math
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path[:0] = ['/src/src', '/src/runtime/src']
from azazel_nexus import local_advisory as la
from azazel_nexus import reasoning_playbook as rp
from azazel_nexus_runtime.mio_embedding import document_text

lib = rp.compose(rp.read_library(Path('/src/playbooks/baseline/azazel-baseline.json').read_bytes()))
srv = subprocess.Popen([shutil.which('llama-server'), '-m', '/models/bge-m3-Q8_0.gguf', '--embedding', '--pooling', 'cls',
                        '--host', '127.0.0.1', '--port', '8099', '-t', '4', '-c', '4096', '-ub', '4096', '-b', '4096'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
def post(texts):
    req = urllib.request.Request('http://127.0.0.1:8099/v1/embeddings', json.dumps({'input': texts}).encode(),
                                 {'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=600) as response:
        return [d['embedding'] for d in json.load(response)['data']]
for _ in range(120):
    try:
        with urllib.request.urlopen('http://127.0.0.1:8099/health', timeout=2):
            break
    except (urllib.error.URLError, OSError):
        time.sleep(1)
def norm(v): n = math.sqrt(sum(x*x for x in v)); return [x/n for x in v]
D = []
for i in range(0, len(lib.entries), 16):
    D += [norm(v) for v in post([document_text(e) for e in lib.entries[i:i+16]])]
out = {}
for name in sys.argv[1:]:
    cases = json.loads(Path(f'/sets/{name}.json').read_text(encoding='utf-8'))['cases']
    rows = []
    for c in cases:
        f = c['frame']; ck = la.read_frame(f)
        q = norm(post([f['question'] + '\n' + '\n'.join(i['text'] for i in f['context'])])[0])
        sims = sorted(((sum(a*b for a, b in zip(q, d)), e.id) for d, e in zip(D, lib.entries)), key=lambda t: (-t[0], t[1]))
        texts = ' '.join([ck['question'], *(i['text'] for i in ck['context'])])
        rows.append({'id': f['request_id'], 'labels': c['labels'], 'lexicon_hit': bool(la._SCOPE.search(texts)),
                     'insufficient_shape': (not ck['context'] and not la._TARGET.search(ck['question'])),
                     'benign_support': la.benign_supported(ck) if hasattr(la, 'benign_supported') else None,
                     'sims': [[round(s, 4), i] for s, i in sims[:10]]})
    out[name] = rows
Path('/out/sims.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf-8')
srv.terminate()
print('ok', {k: len(v) for k, v in out.items()})
