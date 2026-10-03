"""Offline adapter and evidence integrity tests using synthetic producer-shaped data."""
import copy
import hashlib
import json
import shutil
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from scubatank.evidence import EvidenceError, read_json, validate_bundle
from scubatank.importers import import_manifest

ROOT = Path(__file__).resolve().parents[1]


class ImporterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / '.build')
        self.root = Path(self.temp.name)
        shutil.copytree(ROOT / 'fixtures/demo', self.root, dirs_exist_ok=True)

    def tearDown(self):
        self.temp.cleanup()

    def change(self, name, mutate):
        path = self.root / name
        document = json.loads(path.read_text(encoding='utf-8'))
        mutate(document)
        path.write_text(json.dumps(document), encoding='utf-8')

    def load(self):
        return import_manifest(self.root / 'manifest.json')

    def test_producer_shaped_demo_imports_deterministically(self):
        first = self.load()
        self.assertEqual(first, self.load())
        validate_bundle(first)
        self.assertTrue(first['synthetic'])
        self.assertEqual({s['producer_version'] for s in first['sources']}, {'1.8.0', '9.7.1', '1.0.0'})
        self.assertTrue(any(e['type'] == 'ForceChangePassword' for e in first['edges']))
        self.assertTrue(any(f['predicate'] == 'active_privileged_role' for f in first['facts']))

    def test_pinned_public_scubagear_contract_excerpt_imports(self):
        excerpt = json.loads((self.root / 'scubagear-public-contract-excerpt.json').read_text(encoding='utf-8'))
        manifest = {'schema_version': '1.0.0', 'synthetic': True, 'sources': [{
            'source_id': 'public-example', 'producer': 'scubagear', 'producer_version': '1.8.0',
            'producer_schema': 'scubagear-consolidated-1.8.0', 'path': 'scubagear-public-contract-excerpt.json',
            'scope': {'tenant_id': excerpt['MetaData']['TenantId']},
            'completeness': {'complete': False, 'capabilities': ['public-contract-example']}}]}
        (self.root / 'public-manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
        bundle = import_manifest(self.root / 'public-manifest.json')
        self.assertEqual(bundle['sources'][0]['producer_version'], '1.8.0')
        self.assertEqual(bundle['upstream_findings'][0]['policy_id'], 'MS.AAD.1.1v1')
        self.assertEqual(len(bundle['upstream_findings']), 1)
        self.assertEqual(len(bundle['entities']), 1)
        self.assertEqual(bundle['facts'], [])

    def test_secret_bearing_keys_rejected_before_retention(self):
        self.change('scubagear.json', lambda d: d['Raw'].update(access_token='synthetic-forbidden-value'))
        with self.assertRaisesRegex(EvidenceError, 'secret'):
            self.load()

    def test_nested_secret_bearing_keys_rejected(self):
        self.change('bloodhound.json', lambda d: d['data']['nodes']['1']['properties'].update(nested={'PrivateKey': 'synthetic-forbidden-value'}))
        with self.assertRaisesRegex(EvidenceError, 'secret'):
            self.load()

    def test_every_ref_resolves_and_is_hash_backed(self):
        bundle = self.load()
        for source in bundle['sources']:
            self.assertEqual(source['sha256'], hashlib.sha256((self.root / source['path']).read_bytes()).hexdigest())
        for group in ('entities', 'edges', 'facts', 'identity_links', 'upstream_findings'):
            for record in bundle[group]:
                self.assertTrue(record['evidence_refs'], (group, record))

    def test_snapshot_hashes_the_exact_parsed_bytes(self):
        path = self.root / 'scubagear.json'
        expected = hashlib.sha256(path.read_bytes()).hexdigest()
        original = Path.read_bytes
        reads = []
        def changing_file(candidate):
            if candidate == path:
                reads.append(candidate)
                if len(reads) > 1:
                    return b'{}'
            return original(candidate)
        with patch.object(Path, 'read_bytes', changing_file):
            bundle = self.load()
        self.assertEqual(next(s for s in bundle['sources'] if s['source_id'] == 'scuba')['sha256'], expected)
        self.assertEqual(len(reads), 1)

    def test_native_group_sid_conflict_marks_identity_unknown(self):
        self.change('bloodhound.json', lambda d: d['data']['nodes']['110']['properties'].update(onpremisessecurityidentifier='S-1-5-21-1-2-3-999'))
        bundle = self.load()
        group_link = next(l for l in bundle['identity_links'] if l['id'].endswith('group-link'))
        self.assertTrue(group_link['conflict'])
        self.assertTrue(any(i['code'] == 'IdentityConflict' for i in bundle['issues']))

    def test_native_user_anchor_conflict_marks_identity_unknown(self):
        def mutate(d):
            first = next(iter(d['Raw']['privileged_users'].values()))
            first['OnPremisesImmutableId'] = 'conflicting-native-anchor'
        self.change('scubagear.json', mutate)
        bundle = self.load()
        self.assertTrue(any(l['conflict'] for l in bundle['identity_links']))

    def test_unknown_manifest_version_rejected(self):
        self.change('manifest.json', lambda d: d.update(schema_version='99'))
        with self.assertRaises(EvidenceError):
            self.load()

    def test_unknown_producer_version_rejected(self):
        self.change('manifest.json', lambda d: d['sources'][0].update(producer_version='99'))
        with self.assertRaisesRegex(EvidenceError, 'UnsupportedVersion'):
            self.load()

    def test_native_version_conflict_rejected(self):
        self.change('scubagear.json', lambda d: d['MetaData'].update(ToolVersion='1.7.0'))
        with self.assertRaisesRegex(EvidenceError, 'version'):
            self.load()

    def test_relative_parent_path_rejected(self):
        self.change('manifest.json', lambda d: d['sources'][0].update(path='../outside.json'))
        with self.assertRaisesRegex(EvidenceError, 'path'):
            self.load()

    def test_windows_absolute_path_rejected(self):
        self.change('manifest.json', lambda d: d['sources'][0].update(path='C:\\outside.json'))
        with self.assertRaises(EvidenceError):
            self.load()

    def test_unexpected_manifest_claim_rejected(self):
        self.change('manifest.json', lambda d: d.update(facts=[]))
        with self.assertRaises(EvidenceError):
            self.load()

    def test_hash_mismatch_rejected(self):
        self.change('manifest.json', lambda d: d['sources'][0].update(sha256='0' * 64))
        with self.assertRaisesRegex(EvidenceError, 'hash'):
            self.load()

    def test_duplicate_json_keys_rejected(self):
        path = self.root / 'bad.json'
        path.write_text('{"a": 1, "a": 2}', encoding='utf-8')
        with self.assertRaisesRegex(EvidenceError, 'duplicate'):
            read_json(path)

    def test_nonfinite_json_rejected(self):
        path = self.root / 'bad.json'
        path.write_text('{"a": NaN}', encoding='utf-8')
        with self.assertRaises(EvidenceError):
            read_json(path)

    def test_json_depth_bounded(self):
        path = self.root / 'bad.json'
        path.write_text('[' * 70 + '0' + ']' * 70, encoding='utf-8')
        with self.assertRaisesRegex(EvidenceError, 'depth'):
            read_json(path)

    def test_json_record_count_bounded(self):
        path = self.root / 'bad.json'
        path.write_text('[' + ','.join(['0'] * 200_001) + ']', encoding='utf-8')
        with self.assertRaisesRegex(EvidenceError, 'record'):
            read_json(path)

    def test_file_size_bounded(self):
        path = self.root / 'bad.json'
        path.write_text('"' + ('a' * 100) + '"', encoding='utf-8')
        with self.assertRaisesRegex(EvidenceError, 'size'):
            read_json(path, max_bytes=50)

    def test_unc_input_rejected_without_network_access(self):
        with self.assertRaisesRegex(EvidenceError, 'local'):
            read_json('\\\\untrusted.example\\share\\export.json')

    def test_uri_input_rejected_without_network_access(self):
        with self.assertRaisesRegex(EvidenceError, 'local'):
            read_json('https://untrusted.example/export.json')

    def test_controller_inventory_requires_stable_imported_ids(self):
        self.change('supplemental.json', lambda d: d['facts'][0].update(value=['Alex Admin']))
        with self.assertRaisesRegex(EvidenceError, 'controller'):
            self.load()

    def test_incomplete_controller_inventory_cannot_assert_absence(self):
        self.change('manifest.json', lambda d: d['sources'][2]['completeness'].update(complete=False))
        bundle = self.load()
        self.assertTrue(any(i['code'] == 'IncompleteControllerInventory' for i in bundle['issues']))

    def test_invalid_graph_endpoint_rejected(self):
        self.change('bloodhound.json', lambda d: d['data']['edges'][0].update(target='missing'))
        with self.assertRaisesRegex(EvidenceError, 'endpoint'):
            self.load()

    def test_duplicate_graph_object_identity_rejected(self):
        self.change('bloodhound.json', lambda d: d['data']['nodes'].update(duplicate=copy.deepcopy(next(iter(d['data']['nodes'].values())))))
        with self.assertRaisesRegex(EvidenceError, 'duplicate'):
            self.load()

    def test_missing_scubagear_raw_remains_incomplete(self):
        self.change('scubagear.json', lambda d: d.pop('Raw'))
        bundle = self.load()
        self.assertTrue(any(i['code'] == 'MissingRaw' for i in bundle['issues']))
        self.assertFalse(any(f['predicate'] == 'active_privileged_role' and f['evidence_refs'][0].startswith('scuba#') for f in bundle['facts']))

    def test_missing_role_schedule_boundary_does_not_prove_active_role(self):
        self.change('scubagear.json', lambda d: [a.pop('EndDateTime') for a in d['Raw']['privileged_roles'][0]['Assignments']])
        bundle = self.load()
        self.assertFalse(any(f['predicate'] == 'active_privileged_role' for f in bundle['facts']))
        self.assertTrue(any(i['code'] == 'IncompleteRoleSchedule' for i in bundle['issues']))

    def test_eligible_role_is_not_active_assignment(self):
        self.change('scubagear.json', lambda d: [a.update(AssignmentType='Eligible') for a in d['Raw']['privileged_roles'][0]['Assignments']])
        self.assertFalse(any(f['predicate'] == 'active_privileged_role' for f in self.load()['facts']))

    def test_expired_role_is_not_active_assignment(self):
        self.change('scubagear.json', lambda d: [a.update(EndDateTime='/Date(946684800000)/') for a in d['Raw']['privileged_roles'][0]['Assignments']])
        self.assertFalse(any(f['predicate'] == 'active_privileged_role' for f in self.load()['facts']))

    def test_microsoft_role_schedule_preserves_finite_validity_bounds(self):
        def mutate(d):
            assignment = d['Raw']['privileged_roles'][0]['Assignments'][0]
            assignment.update(StartDateTime='/Date(1790920800000)/', EndDateTime='/Date(1790926200000)/')
        self.change('scubagear.json', mutate)
        fact = next(f for f in self.load()['facts'] if f['predicate'] == 'active_privileged_role')
        self.assertEqual(fact['valid_from'], '2026-10-02T06:00:00Z')
        self.assertEqual(fact['valid_until'], '2026-10-02T07:30:00Z')
        self.assertEqual(fact['evidence_refs'], ['scuba#/Raw/privileged_roles/0/Assignments/0'])

    def test_iso_role_schedule_preserves_finite_validity_bounds(self):
        def mutate(d):
            assignment = d['Raw']['privileged_roles'][0]['Assignments'][0]
            assignment.update(StartDateTime='2026-10-02T08:00:00+02:00', EndDateTime='2026-10-02T09:30:00+02:00')
        self.change('scubagear.json', mutate)
        fact = next(f for f in self.load()['facts'] if f['predicate'] == 'active_privileged_role')
        self.assertEqual(fact['valid_from'], '2026-10-02T06:00:00Z')
        self.assertEqual(fact['valid_until'], '2026-10-02T07:30:00Z')

    def test_multiple_role_schedules_remain_separate_facts(self):
        def mutate(d):
            assignments = d['Raw']['privileged_roles'][0]['Assignments']
            first = assignments[0]
            first.update(StartDateTime='2026-10-02T06:00:00Z', EndDateTime='2026-10-02T07:30:00Z')
            assignments.append(dict(first, Id='another-supported-assignment', EndDateTime='2026-10-02T10:00:00Z'))
        self.change('scubagear.json', mutate)
        facts = [f for f in self.load()['facts'] if f['predicate'] == 'active_privileged_role' and f['subject_id'].endswith('000000000002')]
        self.assertEqual(len(facts), 2)
        self.assertEqual({f['valid_until'] for f in facts}, {'2026-10-02T07:30:00Z', '2026-10-02T10:00:00Z'})
        self.assertEqual(len({f['id'] for f in facts}), 2)
        self.assertEqual(len({f['evidence_refs'][0] for f in facts}), 2)

    def test_open_ended_role_has_no_invented_validity_bounds(self):
        facts = [f for f in self.load()['facts'] if f['predicate'] == 'active_privileged_role']
        self.assertTrue(facts)
        self.assertTrue(all('valid_from' not in f and 'valid_until' not in f for f in facts))

    def test_native_raw_timestamp_conflict_rejected(self):
        self.change('scubagear.json', lambda d: d['Raw'].update(timestamp_zulu='2000-01-01T00:00:00Z'))
        with self.assertRaisesRegex(EvidenceError, 'timestamp'):
            self.load()

    def test_inconsistent_observation_rejected(self):
        bundle = self.load()
        bundle['observations'][1]['value'] = {'tampered': True}
        with self.assertRaisesRegex(EvidenceError, 'reference'):
            validate_bundle(bundle)

    def test_wrong_tenant_rejected(self):
        self.change('scubagear.json', lambda d: d['MetaData'].update(TenantId='22222222-2222-4222-8222-222222222222'))
        with self.assertRaisesRegex(EvidenceError, 'scope'):
            self.load()

    def test_malformed_ref_rejected_by_bundle_validation(self):
        bundle = self.load()
        bundle['facts'][0]['evidence_refs'] = ['scuba#/Raw/~2illegal']
        with self.assertRaisesRegex(EvidenceError, 'reference'):
            validate_bundle(bundle)

    def test_nonexistent_ref_rejected_by_bundle_validation(self):
        bundle = self.load()
        bundle['facts'][0]['evidence_refs'] = ['scuba#/Raw/no-such-record']
        with self.assertRaisesRegex(EvidenceError, 'reference'):
            validate_bundle(bundle)

    def test_conflicting_facts_surface_issue(self):
        self.change('supplemental.json', lambda d: d['facts'].append(dict(d['facts'][1], id='conflict', value='cloud')))
        bundle = self.load()
        self.assertTrue(any(i['code'] == 'FactConflict' for i in bundle['issues']))

    def test_same_labels_do_not_link_identities(self):
        bundle = self.load()
        self.assertTrue(all(l['method'] == 'established_id_link' for l in bundle['identity_links']))
        self.assertGreater(len({e['id'] for e in bundle['entities'] if e['label'] == 'Alex Admin'}), 1)

    def test_conflicting_identity_link_is_flagged(self):
        def mutate(d):
            link = dict(d['identity_links'][0], id='conflicting-link', ad_entity_id=d['identity_links'][1]['ad_entity_id'])
            d['identity_links'].append(link)
        self.change('supplemental.json', mutate)
        bundle = self.load()
        self.assertTrue(any(l['conflict'] for l in bundle['identity_links']))
        self.assertTrue(any(i['code'] == 'IdentityConflict' for i in bundle['issues']))

    def test_unsupported_graph_edge_preserved_without_authority(self):
        self.change('bloodhound.json', lambda d: d['data']['edges'][0].update(kind='UnreviewedEdge'))
        bundle = self.load()
        edge = next(e for e in bundle['edges'] if e['type'] == 'UnreviewedEdge')
        self.assertEqual(edge['semantics'], 'unsupported')
        self.assertTrue(any(i['code'] == 'UnsupportedRelationship' for i in bundle['issues']))

    def test_schema_rejects_extra_bundle_claims(self):
        bundle = self.load()
        bundle['guaranteed_secure'] = True
        with self.assertRaises(EvidenceError):
            validate_bundle(bundle)

    def test_collection_time_and_completeness_preserved(self):
        self.change('manifest.json', lambda d: d['sources'][1].update(collected_at='2000-01-01T00:00:00Z', observation_window={'oldest_at': '2000-01-01T00:00:00Z', 'newest_at': '2000-01-01T00:00:00Z'}, completeness={'complete': False, 'capabilities': ['graph']}))
        source = next(s for s in self.load()['sources'] if s['source_id'] == 'bloodhound')
        self.assertEqual(source['collected_at'], '2000-01-01T00:00:00Z')
        self.assertFalse(source['completeness']['complete'])

    def test_missing_graph_collection_window_remains_incomplete(self):
        self.change('manifest.json', lambda d: d['sources'][1].pop('observation_window'))
        bundle = self.load()
        self.assertTrue(any(i['code'] == 'MissingCollectionWindow' for i in bundle['issues']))
        self.assertFalse(next(s for s in bundle['sources'] if s['source_id'] == 'bloodhound')['completeness']['complete'])

    def test_graph_collection_window_and_collectors_preserved(self):
        source = next(s for s in self.load()['sources'] if s['source_id'] == 'bloodhound')
        self.assertEqual(source['observation_window']['oldest_at'], '2026-10-02T07:00:00Z')
        self.assertEqual(source['collector_versions']['SharpHound'], 'synthetic-not-executed')

    def test_reversed_collection_window_rejected(self):
        self.change('manifest.json', lambda d: d['sources'][1]['observation_window'].update(oldest_at='2030-01-01T00:00:00Z'))
        with self.assertRaisesRegex(EvidenceError, 'window'):
            self.load()


if __name__ == '__main__':
    unittest.main()
