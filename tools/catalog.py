"""Compile reviewable check specifications. This does not evaluate an environment."""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ['number', 'title', 'condition', 'evidence', 'remediation', 'limitation',
          'attack', 'nist', 'nist_rationale', 'sources', 'severity']
ASSISTED = {'ST.CORR.RECOVERY.004', 'ST.CORR.RECOVERY.005', 'ST.CORR.RECOVERY.007',
            'ST.POST.OPERATIONS.002', 'ST.POST.OPERATIONS.004', 'ST.POST.OPERATIONS.008'}

def read_json(path: Path):
    return json.loads(path.read_text(encoding='utf-8'))

def load_catalog(root: Path = ROOT) -> dict:
    meta = read_json(root / 'catalog/metadata.json')
    areas = read_json(root / 'catalog/areas.json')
    sources = read_json(root / 'catalog/sources.json')['sources']
    routes = read_json(root / 'config/collection-routes.json')
    providers = {p['id'] for p in read_json(root / 'config/providers.json')['providers']}
    checks, seen, fingerprints = [], set(), {}
    paths = sorted((root / 'catalog').glob('*/*.psv'))
    keys = {p.relative_to(root / 'catalog').with_suffix('').as_posix() for p in paths}
    if keys != set(areas) or keys != set(routes):
        raise ValueError('Area, route and source-file inventories differ')
    for path in paths:
        key = path.relative_to(root / 'catalog').with_suffix('').as_posix()
        area, route = areas[key], routes[key]
        if not route['providers'] or set(route['providers']) - providers:
            raise ValueError(f'Unknown or empty provider route: {key}')
        if area['kind'] not in ('correlation', 'posture') or not area['scope'] or not area['join']:
            raise ValueError(f'Invalid area contract: {key}')
        fingerprints[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        with path.open(encoding='utf-8', newline='') as stream:
            reader = csv.DictReader(stream, delimiter='|')
            if reader.fieldnames != FIELDS:
                raise ValueError(f'Unexpected columns: {path.name}')
            for row in reader:
                if None in row or any(row.get(f) is None for f in FIELDS):
                    raise ValueError(f'Malformed row: {path.name}')
                if any(not row[f].strip() for f in FIELDS if f != 'sources'):
                    raise ValueError(f'Missing required value: {path.name}')
                if not re.fullmatch(r'\d{3}', row['number']):
                    raise ValueError('Check suffix must be three digits')
                kind = 'CORR' if area['kind'] == 'correlation' else 'POST'
                ident = f"ST.{kind}.{area['code']}.{row['number']}"
                if ident in seen:
                    raise ValueError(f'Duplicate check ID: {ident}')
                seen.add(ident)
                attack, nist = row['attack'].split(';'), row['nist'].split(';')
                if any(not re.fullmatch(r'T\d{4}(?:\.\d{3})?', x) for x in attack):
                    raise ValueError(f'Invalid ATT&CK identifier: {ident}')
                if any(not re.fullmatch(r'[A-Z]{2}-\d+(?:\(\d+\))?', x) for x in nist):
                    raise ValueError(f'Invalid NIST identifier: {ident}')
                if row['severity'] not in ('Low', 'Medium', 'High', 'Critical'):
                    raise ValueError(f'Invalid severity: {ident}')
                refs = sorted(set(area['source_ids'] + [s for s in row['sources'].split(';') if s]))
                if not refs or set(refs) - set(sources):
                    raise ValueError(f'Unresolved source: {ident}')
                relationship = ('visibility-gap' if area['code'] == 'VISIBILITY' else
                                'recovery-impact' if area['code'] == 'RECOVERY' else 'potential-behavior')
                check = dict(row, id=ident, kind=area['kind'], area=area['label'],
                             applicability=area['scope'], identity_join=area['join'],
                             implementation='specified', mapping_status='project-proposed',
                             measurement='assisted' if ident in ASSISTED else 'configuration-and-evidence',
                             source_ids=refs, providers=route['providers'],
                             collection_gap=route['gap'], attack_ids=attack, nist_ids=nist,
                             attack_relationship=relationship, nist_relationship='partial-control-support',
                             cis_mapping='not-mapped: exact licensed version/profile review required')
                check['required_tests'] = {
                    'positive': row['condition'], 'limiting_case': row['limitation'],
                    'missing': 'Remove each required input in turn; do not infer absence from incomplete collection.',
                    'boundary': 'Use duplicate labels in different tenants/forests; no implicit merge.',
                    'freshness': 'Supply stale or contradictory required evidence; report Unknown.',
                    'version': 'Supply an unsupported producer schema; reject rather than guess.'}
                checks.append(check)
    if len(checks) != meta['expected_checks']:
        raise ValueError('Check count differs from the versioned catalog scope')
    return dict(meta, checks=checks, source_file_sha256=fingerprints)

def csv_safe(value: object) -> str:
    text = str(value)
    return "'" + text if text.lstrip().startswith(('=', '+', '-', '@', '\t', '\r')) else text

def build(root: Path = ROOT, out: Path | None = None) -> dict:
    data = load_catalog(root)
    out = out or root / '.build/catalog'
    out.mkdir(parents=True, exist_ok=True)
    (out / 'checks.json').write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
    columns = ['id', 'kind', 'area', 'title', 'severity', 'condition', 'evidence',
               'limitation', 'remediation', 'attack', 'nist', 'nist_rationale', 'implementation']
    with (out / 'checks.csv').open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        for check in data['checks']:
            writer.writerow({k: csv_safe(check[k]) for k in columns})
    lines = ['# ScubaTank check catalog', '',
             'Rule specifications, not live assessment results. All mappings are project-proposed.', '']
    sources = read_json(root / 'catalog/sources.json')['sources']
    for c in data['checks']:
        lines += [f"## {c['id']}: {c['title']}", '', f"**Flag when:** {c['condition']}", '',
                  f"**Evidence:** {c['evidence']}", '', f"**Applicability:** {c['applicability']}", '',
                  f"**Identity join:** {c['identity_join']}", '', f"**Limit:** {c['limitation']}", '',
                  f"**Fix:** {c['remediation']}", '', f"**ATT&CK ({c['attack_relationship']}):** {c['attack']}", '',
                  f"**NIST (partial support):** {c['nist']}. {c['nist_rationale']}", '',
                  f"**Preferred providers:** {', '.join(c['providers'])}. {c['collection_gap']}", '',
                  '**Sources:** ' + '; '.join(f"[{s}]({sources[s]['url']})" for s in c['source_ids']), '',
                  '**Validation required:** positive predicate; each missing input; the limiting case; '
                  'wrong tenant/forest; stale or contradictory evidence; unsupported producer version.', '']
    (out / 'checks.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return data

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    result = build(out=args.out)
    print(f"Compiled {len(result['checks'])} specifications; no environment was assessed.")
