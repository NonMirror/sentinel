"""Offline fixed sample of public CSIC normal requests; no HTTP is sent."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from sentinel.core.config import Config
from sentinel.waf.engines.modsecurity import ModSecurityEngine
from sentinel.waf.parser import parse_request

SOURCE_SHA256 = 'd3344377d4721b03b906ca232ab44bfd81b9c1356f967ec9d348532ec420f000'


def records(blob):
    starts = list(re.finditer(rb'(?m)^(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) [^\r\n]+ HTTP/1\.[01]\r?$', blob))
    if not starts or starts[0].start() != 0:
        raise ValueError('Missing CSIC request framing')
    result = []
    for index, start in enumerate(starts):
        part = blob[start.start():starts[index + 1].start() if index + 1 < len(starts) else len(blob)]
        head, sep, rest = part.partition(b'\r\n\r\n')
        if not sep:
            raise ValueError('Missing header terminator')
        sizes = re.findall(rb'(?im)^Content-Length: ([0-9]+)\r?$', head)
        if len(sizes) > 1:
            raise ValueError('Ambiguous Content-Length')
        size = int(sizes[0]) if sizes else 0
        if len(rest) < size or rest[size:].strip(b'\r\n'):
            raise ValueError('Body size or record separator mismatch')
        raw = head + sep + rest[:size]
        result.append((hashlib.sha256(raw).hexdigest(), index, raw))
    return result


def select_records(corpus, sample_size, offset=0):
    unique = {digest: (index, raw) for digest, index, raw in corpus}
    if offset < 0 or sample_size < 1 or offset + sample_size > len(unique):
        raise ValueError('Invalid sample size or offset')
    return unique, sorted(unique.items())[offset:offset + sample_size]


def run(path, sample_size, offset=0):
    blob = path.read_bytes()
    if hashlib.sha256(blob).hexdigest() != SOURCE_SHA256:
        raise ValueError('Public corpus digest differs from pinned source')
    corpus = records(blob)
    # Stable selection before classification; repeated identical requests count once.
    unique, selected = select_records(corpus, sample_size, offset)
    configurations = []
    for profile, level in [('standard', 1), ('standard', 4), ('balanced', 4)]:
        config = Config()
        config.waf.paranoia_level, config.waf.crs_profile = level, profile
        driver = ModSecurityEngine(config)
        rows, methods = [], Counter()
        for digest, (index, raw) in selected:
            request = parse_request(raw)
            methods[request.method] += 1
            verdict = driver.inspect(request)
            rows.append({'index': index, 'sha256': digest, 'blocked': verdict.blocked,
                         'score': verdict.anomaly_score, 'rules': verdict.matched_rules})
        blocked = sum(r['blocked'] for r in rows)
        configurations.append({'profile': profile, 'pl': level, 'total': len(rows),
                               'false_positives': blocked, 'false_positive_rate': blocked / len(rows),
                               'methods': methods, 'engine_errors': driver.engine.stats['errors'], 'cases': rows})
    return {'source': 'https://doi.org/10.60895/redata/RWUUSV', 'file_id': 389,
            'source_sha256': SOURCE_SHA256, 'collected': len(corpus), 'unique': len(unique),
            'selected': sample_size, 'offset': offset,
            'selection': 'SHA256-sorted complete unique requests, fixed offset and size before classification',
            'configurations': configurations,
            'limitations': ['Historical synthetic e-commerce normal traffic, not production prevalence',
                            'Normal subset only: no attack recall measurement',
                            'Original absolute-form targets, headers, body and declared lengths preserved',
                            'Only dataset separators removed; no request transmission or native CSIC app execution']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--normal-file', type=Path, required=True)
    parser.add_argument('--sample-size', type=int, default=2000)
    parser.add_argument('--offset', type=int, default=0)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = run(args.normal_file, args.sample_size, args.offset)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps([{k: v for k, v in row.items() if k != 'cases'} for row in result['configurations']]))
