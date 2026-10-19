"""Offline comparison of CRS detection/blocking levels on the existing corpus."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.scripts.bench_waf import build_attacks, load_benign
from sentinel.core.config import Config
from sentinel.waf.engines.modsecurity import ModSecurityEngine
from sentinel.waf.parser import parse_request


def run(repeats=3):
    attacks, _ = build_attacks(4096, 'GoTestWAF')
    benign, texts = load_benign()
    if not attacks or not texts or repeats < 1:
        raise ValueError('GoTestWAF fixtures and positive repeat count required')
    corpus = [('attack', a.raw) for a in attacks] + [('benign', b) for b in benign]
    digest = hashlib.sha256()
    for label, raw in corpus:
        digest.update(label.encode() + len(raw).to_bytes(8, 'big') + raw)
    rows = []
    for blocking, detection in ((1, 1), (4, 4), (1, 4), (2, 4)):
        cfg = Config()
        cfg.waf.paranoia_level, cfg.waf.detection_paranoia_level = blocking, detection
        driver = ModSecurityEngine(cfg)
        engine, runs, traces = driver.engine, [], []
        for repeat in range(repeats):
            counts = Counter()
            for index, (label, raw) in enumerate(corpus):
                verdict = engine.inspect(parse_request(raw))
                high = {h.rule_id for h in verdict.hits if any(
                    f'paranoia-level/{level}' in h.tags for level in range(blocking + 1, detection + 1))}
                counts[label + '_total'] += 1
                counts[label + '_blocked'] += int(verdict.blocked)
                counts[label + '_logged_above_blocking_pl'] += int(bool(high) and not verdict.blocked)
                if repeat == 0 and label == 'benign':
                    traces.append({'id': index - len(attacks), 'blocked': verdict.blocked,
                                   'high_pl_ids': sorted(high),
                                   'hits': [{'rule_id': h.rule_id, 'message': h.message,
                                             'targets': h.targets} for h in verdict.hits]})
            runs.append(dict(counts))
        rows.append({'blocking_paranoia_level': blocking, 'detection_paranoia_level': detection,
                     'runs': runs, 'stable_counts': all(r == runs[0] for r in runs),
                     'benign_traces': traces, 'engine_errors': engine.stats['errors']})
    return {'scope': 'Offline only; same GoTestWAF+project-benign corpus, new explicit policies',
            'corpus_sha256': digest.hexdigest(), 'repeats': repeats, 'rows': rows,
            'limitations': ['Higher detection PL is observation, not higher blocking protection',
                            'Rule matches are not proof of exploitation; no HTTP requests sent',
                            'Defaults and historic equal-PL benchmarks are unchanged']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = run(args.repeats)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps([{k: row[k] for k in ('blocking_paranoia_level', 'detection_paranoia_level', 'runs', 'engine_errors')}
                      for row in result['rows']]))


if __name__ == '__main__':
    main()
