"""Offline, fixed-partition WAF tradeoff acceptance; never sends requests."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import statistics
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from benchmarks.scripts.bench_waf import build_attacks, load_benign
from sentinel.core.config import Config
from sentinel.waf.engines.modsecurity import ModSecurityEngine
from sentinel.waf.parser import parse_request


def summarize(rows, min_recall=.85, max_fpr=.10):
    if (not math.isfinite(min_recall) or not 0 < min_recall <= 1
            or not math.isfinite(max_fpr) or not 0 < max_fpr <= 1):
        raise ValueError('Acceptance thresholds must be finite fractions in (0, 1]')
    counts, categories = Counter(), {}
    for row in rows:
        label = row['label']
        counts[label + '_total'] += 1
        counts[label + '_blocked'] += row['blocked']
        if label == 'attack':
            category = categories.setdefault(row['category'], Counter())
            category['total'] += 1
            category['blocked'] += row['blocked']
    if not counts['attack_total'] or not counts['benign_total']:
        raise ValueError('Acceptance requires both positive and benign samples')
    recall = counts['attack_blocked'] / counts['attack_total']
    fpr = counts['benign_blocked'] / counts['benign_total']
    macro = statistics.mean(c['blocked'] / c['total'] for c in categories.values())
    return {'counts': counts, 'recall': recall, 'false_positive_rate': fpr,
            'category_macro_recall': macro, 'by_category': categories,
            'meets_micro_gate': recall >= min_recall and fpr < max_fpr,
            'meets_macro_gate': macro >= min_recall and fpr < max_fpr}


def run(manifest_path, repeats, min_recall=.85, max_fpr=.10):
    if repeats < 1:
        raise ValueError('repeats must be positive')
    manifest = json.loads(manifest_path.read_text())
    attacks, _ = build_attacks(4096, 'GoTestWAF')
    benign, text_count = load_benign()
    if not attacks or not text_count:
        raise ValueError('Missing public fixtures')
    inputs, groups, identities = [], {}, set()
    for row in manifest['cases']:
        label, index = row['label'], row['index']
        if label not in ('attack', 'benign') or row['split'] not in ('calibration', 'validation'):
            raise ValueError('Unknown acceptance label or partition')
        if (label, index) in identities:
            raise ValueError('Duplicate acceptance identity')
        identities.add((label, index))
        previous = groups.setdefault(row['group'], row['split'])
        if previous != row['split']:
            raise ValueError('Payload identity crosses partitions')
        raw = attacks[index].raw if label == 'attack' else benign[index]
        if hashlib.sha256(raw).hexdigest() != row['raw_sha256']:
            raise ValueError('Corpus changed after partition freeze')
        if label == 'attack' and row['category'] != attacks[index].category:
            raise ValueError('Category changed after partition freeze')
        inputs.append((row, parse_request(raw)))
    if identities != ({('attack', i) for i in range(len(attacks))}
                      | {('benign', i) for i in range(len(benign))}):
        raise ValueError('Acceptance manifest omits collected samples')
    configurations = []
    for profile, level in [('standard', 1), ('standard', 4), ('balanced', 4)]:
        config = Config()
        config.waf.crs_profile, config.waf.paranoia_level = profile, level
        config.waf.detection_paranoia_level = level
        driver = ModSecurityEngine(config)
        runs, detail = [], []
        for repeat in range(repeats):
            rows = []
            for metadata, request in inputs:
                verdict = driver.inspect(request)
                rows.append({**metadata, 'blocked': verdict.blocked,
                             'score': verdict.anomaly_score, 'rules': verdict.matched_rules})
            runs.append({split: summarize([r for r in rows if split == 'all' or r['split'] == split],
                                          min_recall, max_fpr)
                         for split in ('calibration', 'validation', 'all')})
            if repeat == 0:
                detail = rows
        configurations.append({'profile': profile, 'paranoia_level': level,
                               'anomaly_threshold': config.waf.anomaly_threshold,
                               'runs': runs, 'stable_counts': all(r == runs[0] for r in runs),
                               'cases': detail, 'engine_errors': driver.engine.stats['errors'],
                               'health': driver.health()})
    return {'scope': 'Offline decision evaluation only; no target or application execution',
            'acceptance': {'min_recall': min_recall, 'max_fpr_exclusive': max_fpr},
            'split_manifest_sha256': hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            'repeats': repeats, 'configurations': configurations,
            'limitations': manifest['limitations'] + [
                'After the first validation failure these partitions were used for development; subsequent runs are regression evidence, not blind validation',
                'Rates describe these fixtures, not production traffic or exploitation success',
                'Content-type and protocol-policy rejections count as blocks, not semantic exploit confirmation',
                'Macro averages weight observed categories equally; partitions can contain different categories',
                'Correlated placements are grouped for partitioning but still counted as individual requests']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--min-recall', type=float, default=.85)
    parser.add_argument('--max-fpr', type=float, default=.10)
    args = parser.parse_args()
    result = run(args.manifest, args.repeats, args.min_recall, args.max_fpr)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n')
    for config in result['configurations']:
        print(json.dumps({'profile': config['profile'], 'pl': config['paranoia_level'],
                          'all': config['runs'][0]['all'], 'validation': config['runs'][0]['validation'],
                          'stable': config['stable_counts'], 'errors': config['engine_errors']}))
