"""Catalog integrity tests, not security-detector validation."""
import csv
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from tools.catalog import ROOT, build, csv_safe, load_catalog

class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        for folder in ('catalog', 'config'):
            shutil.copytree(ROOT / folder, self.root / folder)
    def tearDown(self):
        self.tmp.cleanup()
    def edit_row(self, field, value):
        path = self.root / 'catalog/correlation/identity.psv'
        with path.open(newline='', encoding='utf-8') as stream:
            rows = list(csv.DictReader(stream, delimiter='|'))
        rows[0][field] = value
        with path.open('w', newline='', encoding='utf-8') as stream:
            writer = csv.DictWriter(stream, fieldnames=rows[0].keys(), delimiter='|')
            writer.writeheader(); writer.writerows(rows)
    def test_counts_and_unique_ids(self):
        checks = load_catalog(self.root)['checks']
        self.assertEqual(len(checks), 132)
        self.assertEqual(sum(c['kind'] == 'correlation' for c in checks), 100)
        self.assertEqual(len({c['id'] for c in checks}), 132)
    def test_specs_are_not_implemented(self):
        self.assertEqual({c['implementation'] for c in load_catalog(self.root)['checks']}, {'specified'})
    def test_every_check_has_mappings_and_evidence(self):
        for c in load_catalog(self.root)['checks']:
            for key in ('evidence', 'limitation', 'remediation', 'nist_rationale', 'attack_ids', 'nist_ids', 'source_ids'):
                self.assertTrue(c[key], (c['id'], key))
    def test_every_check_has_a_reuse_route(self):
        for c in load_catalog(self.root)['checks']:
            self.assertTrue(c['providers']); self.assertTrue(c['collection_gap'])
    def test_missing_evidence_rejected(self):
        self.edit_row('evidence', '')
        with self.assertRaises(ValueError): load_catalog(self.root)
    def test_unknown_source_rejected(self):
        self.edit_row('sources', 'NO-SUCH-SOURCE')
        with self.assertRaises(ValueError): load_catalog(self.root)
    def test_malformed_attack_id_rejected(self):
        self.edit_row('attack', 'T1558.x')
        with self.assertRaises(ValueError): load_catalog(self.root)
    def test_malformed_nist_id_rejected(self):
        self.edit_row('nist', 'NIST-THING')
        with self.assertRaises(ValueError): load_catalog(self.root)
    def test_duplicate_id_rejected(self):
        path = self.root / 'catalog/correlation/identity.psv'
        text = path.read_text(); path.write_text(text + text.splitlines()[1] + '\n')
        with self.assertRaises(ValueError): load_catalog(self.root)
    def test_missing_area_file_rejected(self):
        (self.root / 'catalog/correlation/identity.psv').unlink()
        with self.assertRaises(ValueError): load_catalog(self.root)
    def test_unknown_provider_rejected(self):
        path = self.root / 'config/collection-routes.json'
        routes = json.loads(path.read_text()); routes['correlation/identity']['providers'] = ['unreviewed-scanner']
        path.write_text(json.dumps(routes))
        with self.assertRaises(ValueError): load_catalog(self.root)
    def test_build_is_deterministic(self):
        out = self.root / 'out'; build(self.root, out)
        first = {p.name: p.read_bytes() for p in out.iterdir()}
        build(self.root, out)
        self.assertEqual(first, {p.name: p.read_bytes() for p in out.iterdir()})
    def test_all_test_contracts_present(self):
        for c in load_catalog(self.root)['checks']:
            self.assertEqual(set(c['required_tests']), {'positive','limiting_case','missing','boundary','freshness','version'})
    def test_formula_export(self):
        self.assertEqual(csv_safe('=1+1'), "'=1+1")
        self.assertEqual(csv_safe('  @SUM(1)'), "'  @SUM(1)")
        self.assertEqual(csv_safe('Normal text'), 'Normal text')
    def test_no_provider_can_execute(self):
        for p in json.loads((self.root / 'config/providers.json').read_text())['providers']:
            self.assertFalse(p['execution_enabled'])
    def test_implemented_import_routes_have_explicit_format_validation(self):
        providers={p['id']:p for p in json.loads((self.root / 'config/providers.json').read_text())['providers']}
        for name,version in (('scubagear','1.8.0'),('bloodhound','9.7.1'),('operator-attestation','1.0.0')):
            self.assertEqual(providers[name]['adapter_status'],'implemented-offline')
            self.assertEqual(providers[name]['validated_versions'],[version])
            self.assertFalse(providers[name]['live_validation'])

if __name__ == '__main__': unittest.main()
