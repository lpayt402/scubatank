"""Pinned, offline adapters. Native tools retain ownership of permission semantics."""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .evidence import (EvidenceError, confined_path, make_ref, pointer_escape,
                       read_json_with_hash, validate_bundle, validate_schema)

ADAPTER_VERSION = '1.0.0'
SUPPORTED = {
    'scubagear': ('1.8.0', 'scubagear-consolidated-1.8.0'),
    'bloodhound-ce': ('9.7.1', 'bloodhound-cypher-9.7.1'),
    'operator-evidence': ('1.0.0', 'operator-evidence-1.0.0'),
}
NODE_KINDS = {'User': 'ADUser', 'Group': 'ADGroup', 'Computer': 'ADComputer',
              'Domain': 'ADDomain', 'OU': 'ADOU', 'GPO': 'ADGPO',
              'AZUser': 'CloudUser', 'AZGroup': 'CloudGroup',
              'AZApp': 'CloudApplication', 'AZServicePrincipal': 'CloudServicePrincipal',
              'AZTenant': 'CloudTenant'}
# The evaluator must still apply the edge-specific limiting cases and prerequisites.
SUPPORTED_EDGES = {'MemberOf', 'ForceChangePassword', 'GenericAll', 'GenericWrite',
                   'WriteDacl', 'WriteOwner', 'AddMember', 'AddSelf', 'AdminTo',
                   'AZMemberOf', 'AZAddMembers', 'AZAddSecret', 'AZOwns', 'AZOwner',
                   'AZContributor', 'AZGlobalAdmin', 'AZPrivilegedRoleAdmin'}
BOOL_FACTS = {'enabled', 'active_privileged_role', 'password_flow_applicable',
              'tier_separation_required', 'ad_control_plane', 'sync_host_confirmed',
              'sensitive_grant_effective', 'membership_add_supported',
              'usable_credential_addition', 'sensitive_application_permissions'}
FACTS = BOOL_FACTS | {'approved_controllers', 'password_authority', 'sync_tenant_id',
                      'ca_scenario', 'service_principal_id'}
# Only these stable role templates are needed by this bounded adapter milestone.
PRIVILEGED_ROLE_TEMPLATES = {'62e90394-69f5-4237-9190-012177145e10',
                             'e8611ab8-c189-46e8-94e1-60213ab1f814'}
SECRET_FIELDS = {'password', 'passwordhash', 'ntlmhash', 'nthash', 'unicodepwd',
                 'privatekey', 'access_token', 'accesstoken', 'refreshtoken',
                 'bearertoken', 'clientsecret', 'secrettext', 'managedpassword',
                 'msdsmanagedpassword', 'authenticationtoken'}


def _reject_secret_fields(document):
    """Reject explicit credential-bearing fields before retaining any source observation."""
    pending = [document]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            for key, child in value.items():
                normalized = re.sub(r'[^a-z0-9]', '', key.lower())
                if normalized in SECRET_FIELDS:
                    raise EvidenceError('InvalidInput: secret-bearing field is forbidden; supply an authorized credential-free export')
                pending.append(child)
        elif isinstance(value, list):
            pending.extend(value)


def _object(value, description):
    if not isinstance(value, dict):
        raise EvidenceError(f'InvalidInput: {description} must be an object')
    return value


def _list(value, description):
    if not isinstance(value, list):
        raise EvidenceError(f'InvalidInput: {description} must be an array')
    return value


def _string(value, description):
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise EvidenceError(f'InvalidInput: {description} must be a bounded nonempty string')
    return value


def _uuid(value, description):
    try:
        return str(uuid.UUID(_string(value, description)))
    except (ValueError, AttributeError) as exc:
        raise EvidenceError(f'InvalidInput: {description} must be a stable UUID') from exc


def _time(value):
    if not isinstance(value, str):
        raise EvidenceError('InvalidInput: collection time must be an explicit timestamp')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            raise ValueError('timezone missing')
        return parsed.astimezone(timezone.utc)
    except ValueError as exc:
        raise EvidenceError('InvalidInput: malformed or timezone-free collection time') from exc


def _schedule_time(value):
    if value is None:
        return None
    match = re.fullmatch(r'/Date\((-?\d+)(?:[+-]\d{4})?\)/', value) if isinstance(value, str) else None
    try:
        return datetime.fromtimestamp(int(match.group(1)) / 1000, timezone.utc) if match else _time(value)
    except (OverflowError, OSError, ValueError) as exc:
        raise EvidenceError('InvalidInput: malformed role schedule timestamp') from exc


def entity_id(kind, boundary, native):
    """Namespace stable identifiers; names, email and UPN are display information."""
    if kind.startswith('Cloud'):
        return f'cloud:{_uuid(boundary, "tenant boundary")}:{_uuid(native, "cloud object ID")}'
    boundary = _string(boundary, 'forest boundary').lower()
    native = _string(native, 'AD object ID')
    if re.fullmatch(r'S-1-(?:\d+-)+\d+', native, re.IGNORECASE):
        native = native.upper()
    else:
        native = _uuid(native, 'AD SID/object GUID')
    return f'ad:{boundary}:{native}'


class _Bundle:
    def __init__(self, synthetic):
        self.data = {'schema_version': '1.0.0', 'run_id': str(uuid.UUID(int=0)),
                     'synthetic': synthetic, 'sources': [], 'entities': [], 'edges': [],
                     'facts': [], 'identity_links': [], 'upstream_findings': [],
                     'issues': [], 'coverage': [], 'observations': []}
        self.entities = {}
        self.facts = {}
        self.observed = set()

    def observe(self, source, pointer, value):
        ref = make_ref(source['source_id'], pointer)
        if ref not in self.observed:
            self.observed.add(ref)
            self.data['observations'].append({'ref': ref, 'value': value})
        return ref

    def issue(self, code, message, *, source=None, entities=None, refs=None):
        issue = {'code': code, 'message': message, 'entity_ids': entities or [], 'evidence_refs': refs or []}
        if source:
            issue['source_id'] = source['source_id']
        self.data['issues'].append(issue)

    def entity(self, kind, boundary, native, label, properties, ref):
        identifier = entity_id(kind, boundary, native)
        record = {'id': identifier, 'kind': kind, 'boundary_id': boundary.lower(),
                  'native_id': identifier.rsplit(':', 1)[1], 'label': label,
                  'properties': properties, 'evidence_refs': [ref]}
        previous = self.entities.get(identifier)
        if previous:
            shared = previous['properties'].keys() & properties.keys()
            if previous['kind'] != kind or any(previous['properties'][key] != properties[key] for key in shared):
                self.issue('EntityConflict', 'Source records disagree about a stable entity.',
                           entities=[identifier], refs=previous['evidence_refs'] + [ref])
            previous['evidence_refs'] = sorted(set(previous['evidence_refs'] + [ref]))
            for key, value in properties.items():
                previous['properties'].setdefault(key, value)
        else:
            self.entities[identifier] = record
            self.data['entities'].append(record)
        return identifier

    def fact(self, source, subject, predicate, value, ref, semantics='observed', identifier=None,
             *, valid_from=None, valid_until=None):
        key = (subject, predicate)
        for previous in self.facts.get(key, []):
            if previous['value'] != value:
                self.issue('FactConflict', f'Source records disagree about {predicate}.', source=source,
                           entities=[subject], refs=previous['evidence_refs'] + [ref])
        record = {'id': identifier or f"{source['source_id']}:fact:{len(self.data['facts'])}",
                  'subject_id': subject, 'predicate': predicate, 'value': value,
                  'semantics': semantics, 'evidence_refs': [ref]}
        if valid_from is not None:
            record['valid_from'] = valid_from.isoformat().replace('+00:00', 'Z')
        if valid_until is not None:
            record['valid_until'] = valid_until.isoformat().replace('+00:00', 'Z')
        self.facts.setdefault(key, []).append(record)
        self.data['facts'].append(record)


def _scuba(bundle, source, document):
    metadata = _object(document.get('MetaData'), 'ScubaGear MetaData')
    if metadata.get('Tool') != 'ScubaGear' or metadata.get('ToolVersion') != '1.8.0':
        raise EvidenceError('UnsupportedVersion: ScubaGear native tool/version disagrees with manifest')
    tenant = _uuid(metadata.get('TenantId'), 'ScubaGear TenantId')
    if tenant != source['scope'].get('tenant_id'):
        raise EvidenceError('InvalidInput: ScubaGear tenant scope disagrees with manifest')
    native_time = metadata.get('TimestampZulu')
    _time(native_time)
    if source.get('collected_at') and _time(source['collected_at']) != _time(native_time):
        raise EvidenceError('InvalidInput: ScubaGear collection timestamp disagrees with manifest')
    source['collected_at'] = native_time
    _uuid(metadata.get('ReportUUID'), 'ScubaGear report UUID')
    _list(metadata.get('ProductsAssessed'), 'ScubaGear assessed products')
    _object(metadata.get('ProductAbbreviationMapping'), 'ScubaGear product mapping')
    results = _object(document.get('Results'), 'ScubaGear Results')
    seen_policies = set()
    for product, groups in results.items():
        _list(groups, f'ScubaGear {product} groups')
        for gi, group in enumerate(groups):
            _object(group, 'ScubaGear result group')
            for ci, control in enumerate(_list(group.get('Controls'), 'ScubaGear controls')):
                _object(control, 'ScubaGear control')
                policy = _string(control.get('Control ID'), 'ScubaGear control ID')
                if policy in seen_policies:
                    raise EvidenceError('InvalidInput: duplicate ScubaGear policy ID')
                seen_policies.add(policy)
                for key in ('Requirement', 'Result', 'Criticality', 'Details'):
                    if not isinstance(control.get(key), str):
                        raise EvidenceError(f'InvalidInput: ScubaGear control {key} must be a string')
                pointer = f'/Results/{pointer_escape(product)}/{gi}/Controls/{ci}'
                ref = bundle.observe(source, pointer, control)
                annotations = {key: value for key, value in control.items()
                               if key not in ('Control ID', 'Requirement', 'Result', 'Criticality', 'Details')}
                annotations['Requirement'] = control['Requirement']
                if policy in document.get('AnnotatedFailedPolicies', {}):
                    annotations['AnnotatedFailedPolicy'] = document['AnnotatedFailedPolicies'][policy]
                bundle.data['upstream_findings'].append({
                    'id': f"{source['source_id']}:{policy}", 'source_id': source['source_id'],
                    'policy_id': policy, 'product': product, 'result': control['Result'],
                    'criticality': control['Criticality'], 'details': control['Details'],
                    'annotations': annotations, 'evidence_refs': [ref]})
    raw = document.get('Raw')
    if raw is None:
        source['completeness']['complete'] = False
        bundle.issue('MissingRaw', 'ScubaGear raw configuration is absent; subject-specific role and policy evidence is unavailable.', source=source,
                     refs=[make_ref(source['source_id'])])
        return
    _object(raw, 'ScubaGear Raw')
    if raw.get('module_version', '1.8.0') != '1.8.0':
        raise EvidenceError('UnsupportedVersion: ScubaGear Raw module version disagrees')
    if 'timestamp_zulu' in raw and _time(raw['timestamp_zulu']) != _time(native_time):
        raise EvidenceError('InvalidInput: ScubaGear Raw timestamp disagrees with metadata')
    if 'report_uuid' in raw and _uuid(raw['report_uuid'], 'ScubaGear Raw report UUID') != _uuid(metadata['ReportUUID'], 'ScubaGear report UUID'):
        raise EvidenceError('InvalidInput: ScubaGear Raw report identity disagrees with metadata')
    for key, value in raw.items():
        if key.endswith('_unsuccessful_commands'):
            _list(value, key)
            source['collection_errors'].extend(value)
    if source['collection_errors']:
        source['completeness']['complete'] = False
        bundle.issue('CollectionErrors', 'Upstream collection reported errors; coverage remains incomplete.', source=source,
                     refs=[make_ref(source['source_id'], '/Raw')])
    users = _object(raw.get('privileged_users', {}), 'ScubaGear privileged_users')
    for native, user in users.items():
        _object(user, 'ScubaGear privileged user')
        ref = bundle.observe(source, f'/Raw/privileged_users/{pointer_escape(native)}', user)
        bundle.entity('CloudUser', tenant, native, user.get('DisplayName', native), dict(user), ref)
    service_principals = _object(raw.get('privileged_service_principals', {}), 'ScubaGear privileged_service_principals')
    for native, principal in service_principals.items():
        _object(principal, 'ScubaGear privileged service principal')
        if principal.get('ServicePrincipalId', native).lower() != native.lower():
            raise EvidenceError('InvalidInput: ScubaGear service principal identity conflict')
        ref = bundle.observe(source, f'/Raw/privileged_service_principals/{pointer_escape(native)}', principal)
        bundle.entity('CloudServicePrincipal', tenant, native, principal.get('DisplayName', native), dict(principal), ref)
    now = _time(native_time)
    for ri, role in enumerate(_list(raw.get('privileged_roles', []), 'ScubaGear privileged_roles')):
        _object(role, 'ScubaGear privileged role')
        if str(role.get('RoleTemplateId', '')).lower() not in PRIVILEGED_ROLE_TEMPLATES:
            continue
        for ai, assignment in enumerate(_list(role.get('Assignments'), 'ScubaGear role assignments')):
            _object(assignment, 'ScubaGear role assignment')
            # Eligible and group-mediated schedules are not direct active user assignments.
            if assignment.get('MemberType') != 'Direct' or assignment.get('AssignmentType') not in ('Assigned', 'Activated'):
                continue
            if assignment.get('DirectoryScopeId') != '/':
                continue
            if not {'PrincipalId', 'StartDateTime', 'EndDateTime'}.issubset(assignment):
                ref = bundle.observe(source, f'/Raw/privileged_roles/{ri}/Assignments/{ai}', assignment)
                bundle.issue('IncompleteRoleSchedule', 'Role schedule boundaries are missing; active authority is unknown.', source=source, refs=[ref])
                continue
            principal = _uuid(assignment.get('PrincipalId'), 'ScubaGear role principal')
            user_id = entity_id('CloudUser', tenant, principal)
            if user_id not in bundle.entities or bundle.entities[user_id]['kind'] != 'CloudUser':
                continue
            start = _schedule_time(assignment.get('StartDateTime'))
            end = _schedule_time(assignment.get('EndDateTime'))
            if (start is None or start <= now) and (end is None or now < end):
                ref = bundle.observe(source, f'/Raw/privileged_roles/{ri}/Assignments/{ai}', assignment)
                bundle.fact(source, user_id, 'active_privileged_role', True, ref, 'upstream-derived',
                            valid_from=start, valid_until=end)


def _bloodhound(bundle, source, document):
    if 'collected_at' not in source:
        raise EvidenceError('InvalidInput: BloodHound collection timestamp must be supplied; export lastSeen is not collection time')
    window = source.get('observation_window')
    if not window:
        source['completeness']['complete'] = False
        bundle.issue('MissingCollectionWindow', 'Graph export time does not establish original observation freshness; supply the oldest/newest source collection times.',
                     source=source, refs=[make_ref(source['source_id'])])
    elif not _time(window['oldest_at']) <= _time(window['newest_at']) <= _time(source['collected_at']):
        raise EvidenceError('InvalidInput: graph collection window is reversed or newer than the export')
    if not source.get('collector_versions'):
        source['completeness']['complete'] = False
        bundle.issue('MissingCollectorVersions', 'Graph engine version is pinned, but contributing collector versions were not recorded.',
                     source=source, refs=[make_ref(source['source_id'])])
    graph = _object(document.get('data'), 'BloodHound Cypher response data')
    nodes = _object(graph.get('nodes'), 'BloodHound graph nodes')
    edges = _list(graph.get('edges'), 'BloodHound graph edges')
    db_ids, identities = {}, set()
    for db_id, node in nodes.items():
        _string(db_id, 'BloodHound DB node ID')
        _object(node, 'BloodHound node')
        native = _string(node.get('objectId'), 'BloodHound stable objectId')
        native_kind = _string(node.get('kind'), 'BloodHound node kind')
        kind = NODE_KINDS.get(native_kind)
        if not kind:
            raise EvidenceError(f'UnsupportedVersion: BloodHound node kind {native_kind} is outside this adapter')
        cloud = kind.startswith('Cloud')
        boundary = source['scope'].get('tenant_id' if cloud else 'forest_id')
        if not boundary:
            raise EvidenceError('InvalidInput: BloodHound node lacks an explicit tenant/forest scope')
        properties = _object(node.get('properties', {}), 'BloodHound node properties')
        if cloud and properties.get('tenantid') and str(properties['tenantid']).lower() != boundary.lower():
            raise EvidenceError('InvalidInput: BloodHound node tenant scope disagrees with manifest')
        canonical = entity_id(kind, boundary, native)
        if canonical in identities:
            raise EvidenceError('InvalidInput: duplicate BloodHound stable object identity')
        identities.add(canonical)
        ref = bundle.observe(source, f'/data/nodes/{pointer_escape(db_id)}', node)
        props = dict(properties)
        props.update({'bloodhound_kinds': node.get('kinds', [native_kind]),
                      'bloodhound_last_seen': node.get('lastSeen'),
                      'bloodhound_is_tier_zero': node.get('isTierZero')})
        db_ids[db_id] = bundle.entity(kind, boundary, native, node.get('label', native), props, ref)
        if 'enabled' in properties:
            if not isinstance(properties['enabled'], bool):
                raise EvidenceError('InvalidInput: BloodHound enabled property must be boolean')
            bundle.fact(source, canonical, 'enabled', properties['enabled'], ref)
    edge_ids = set()
    for ei, edge in enumerate(edges):
        _object(edge, 'BloodHound edge')
        edge_id = _string(edge.get('id'), 'BloodHound edge ID')
        if edge_id in edge_ids:
            raise EvidenceError('InvalidInput: duplicate BloodHound edge ID')
        edge_ids.add(edge_id)
        if edge.get('source') not in db_ids or edge.get('target') not in db_ids:
            raise EvidenceError('InvalidInput: BloodHound graph endpoint is absent from exported nodes')
        edge_type = _string(edge.get('kind'), 'BloodHound edge kind')
        ref = bundle.observe(source, f'/data/edges/{ei}', edge)
        semantics = 'upstream-derived' if edge_type in SUPPORTED_EDGES else 'unsupported'
        bundle.data['edges'].append({'id': f"{source['source_id']}:{edge_id}",
            'source_id': db_ids[edge['source']], 'target_id': db_ids[edge['target']],
            'type': edge_type, 'semantics': semantics, 'semantics_version': 'bloodhound-ce/9.7.1',
            'properties': dict(_object(edge.get('properties', {}), 'BloodHound edge properties')),
            'evidence_refs': [ref]})
        if semantics == 'unsupported':
            bundle.issue('UnsupportedRelationship', f'{edge_type} is retained as context without authority semantics.',
                         source=source, entities=[db_ids[edge['source']], db_ids[edge['target']]], refs=[ref])


def _supplemental(bundle, source, document):
    if document.get('schema_version') != '1.0.0':
        raise EvidenceError('UnsupportedVersion: operator evidence schema must be 1.0.0')
    allowed = {'schema_version', 'entities', 'facts', 'identity_links', 'description'}
    if set(document) - allowed:
        raise EvidenceError('InvalidSchema: unexpected operator evidence property')
    for ei, entity in enumerate(_list(document.get('entities', []), 'operator entities')):
        _object(entity, 'operator entity')
        if set(entity) != {'kind', 'boundary_id', 'native_id', 'label', 'properties'}:
            raise EvidenceError('InvalidSchema: operator entity fields do not match contract')
        kind = entity['kind']
        if kind not in set(NODE_KINDS.values()):
            raise EvidenceError('InvalidInput: unsupported operator entity kind')
        boundary = source['scope'].get('tenant_id' if kind.startswith('Cloud') else 'forest_id')
        if boundary != entity['boundary_id']:
            raise EvidenceError('InvalidInput: operator entity boundary disagrees with source scope')
        ref = bundle.observe(source, f'/entities/{ei}', entity)
        bundle.entity(kind, boundary, entity['native_id'], entity['label'],
                      _object(entity['properties'], 'operator entity properties'), ref)
    facts_seen = set()
    for fi, fact in enumerate(_list(document.get('facts', []), 'operator facts')):
        _object(fact, 'operator fact')
        if set(fact) != {'id', 'subject_id', 'predicate', 'value'}:
            raise EvidenceError('InvalidSchema: operator fact fields do not match contract')
        if fact['id'] in facts_seen:
            raise EvidenceError('InvalidInput: duplicate operator fact ID')
        facts_seen.add(fact['id'])
        predicate, value = fact['predicate'], fact['value']
        if predicate not in FACTS:
            raise EvidenceError(f'InvalidInput: unsupported operator predicate {predicate}')
        if predicate in BOOL_FACTS and not isinstance(value, bool):
            raise EvidenceError(f'InvalidSchema: {predicate} must be boolean')
        if predicate == 'password_authority' and value not in ('ad', 'cloud'):
            raise EvidenceError('InvalidSchema: password_authority must be ad or cloud')
        if predicate == 'approved_controllers' and (not isinstance(value, list) or not all(isinstance(v, str) for v in value)):
            raise EvidenceError('InvalidSchema: approved_controllers must be an explicit ID array')
        if predicate in ('sync_tenant_id', 'service_principal_id') and not isinstance(value, str):
            raise EvidenceError(f'InvalidSchema: {predicate} must be a stable ID string')
        if predicate == 'ca_scenario':
            _object(value, 'conditional access scenario')
            required = {'complete', 'enforced_exclusion', 'other_policy_restores', 'user_id', 'resource_id', 'scope',
                        'group_id', 'evaluated_policy_ids', 'evaluation_method', 'sign_in_conditions',
                        'required_protection', 'prospective_membership', 'owner', 'evaluated_at'}
            if set(value) != required or not all(isinstance(value[k], bool) for k in ('complete', 'enforced_exclusion', 'other_policy_restores', 'prospective_membership')):
                raise EvidenceError('InvalidSchema: conditional access scenario lacks explicit effective scenario evidence')
            if value['scope'] != source['scope']:
                raise EvidenceError('InvalidInput: conditional access scenario scope disagrees with source')
            if value['evaluation_method'] != 'operator-reviewed-combined-policy-scenario':
                raise EvidenceError('UnsupportedVersion: only explicit reviewed scenario attestations are admitted; no platform scenario adapter has been validated')
            _string(value['owner'], 'scenario review owner')
            _time(value['evaluated_at'])
            if not isinstance(value['evaluated_policy_ids'], list) or not all(isinstance(v, str) and v for v in value['evaluated_policy_ids']):
                raise EvidenceError('InvalidSchema: evaluated policy set must be an explicit array')
            _object(value['sign_in_conditions'], 'scenario sign-in conditions')
        subject = fact['subject_id']
        if subject not in bundle.entities:
            raise EvidenceError('InvalidInput: operator fact subject is not an imported stable entity')
        entity = bundle.entities[subject]
        scope_boundary = source['scope'].get('tenant_id' if entity['kind'].startswith('Cloud') else 'forest_id')
        if entity['boundary_id'] != scope_boundary:
            raise EvidenceError('InvalidInput: operator fact subject is outside source scope')
        ref = bundle.observe(source, f'/facts/{fi}', fact)
        if predicate == 'approved_controllers':
            for controller in value:
                record = bundle.entities.get(controller)
                if not record or record['boundary_id'] != entity['boundary_id'] or record['kind'] not in ('ADUser', 'ADGroup', 'CloudUser', 'CloudGroup'):
                    raise EvidenceError('InvalidInput: approved controller inventory requires imported stable IDs in the target boundary')
            if source['completeness']['complete'] is not True:
                bundle.issue('IncompleteControllerInventory', 'An incomplete inventory cannot establish that a controller is unapproved.',
                             source=source, entities=[subject], refs=[ref])
                continue
        bundle.fact(source, subject, predicate, value, ref, 'operator-attested', f"{source['source_id']}:{fact['id']}")
    links_seen = set()
    for li, link in enumerate(_list(document.get('identity_links', []), 'operator identity links')):
        _object(link, 'operator identity link')
        if set(link) != {'id', 'ad_entity_id', 'cloud_entity_id', 'method', 'anchor_evidence'}:
            raise EvidenceError('InvalidSchema: identity link fields do not match contract')
        if link['id'] in links_seen:
            raise EvidenceError('InvalidInput: duplicate identity link ID')
        links_seen.add(link['id'])
        if link['method'] not in ('verified-source-anchor', 'verified-onpremises-sid'):
            raise EvidenceError('InvalidInput: identity linking requires a verified source anchor; names/UPNs are unsupported')
        anchor = _object(link['anchor_evidence'], 'verified source anchor evidence')
        value_key = 'cloud_immutable_id' if link['method'] == 'verified-source-anchor' else 'cloud_sid'
        if set(anchor) != {'attribute', 'ad_value', value_key, 'verified'} or anchor['verified'] is not True:
            raise EvidenceError('InvalidInput: source anchor verification is missing')
        supported_attributes = ('objectGUID', 'mS-DS-ConsistencyGuid') if link['method'] == 'verified-source-anchor' else ('objectSid',)
        if anchor['attribute'] not in supported_attributes or anchor['ad_value'] != anchor[value_key]:
            raise EvidenceError('InvalidInput: source anchor values conflict or attribute is unsupported')
        if not isinstance(anchor['ad_value'], str) or not anchor['ad_value']:
            raise EvidenceError('InvalidInput: source anchor value is missing')
        ad, cloud = bundle.entities.get(link['ad_entity_id']), bundle.entities.get(link['cloud_entity_id'])
        expected_kinds = ('ADUser', 'CloudUser') if link['method'] == 'verified-source-anchor' else ('ADGroup', 'CloudGroup')
        if not ad or not cloud or (ad['kind'], cloud['kind']) != expected_kinds:
            raise EvidenceError('InvalidInput: identity link endpoints must be imported corresponding AD and cloud types')
        if link['method'] == 'verified-onpremises-sid' and anchor['ad_value'] != ad['native_id']:
            raise EvidenceError('InvalidInput: group SID link does not match native AD object SID')
        if ad['boundary_id'] != source['scope'].get('forest_id') or cloud['boundary_id'] != source['scope'].get('tenant_id'):
            raise EvidenceError('InvalidInput: identity link endpoints are outside source scope')
        ref = bundle.observe(source, f'/identity_links/{li}', link)
        native_conflict = False
        if link['method'] == 'verified-source-anchor':
            if 'OnPremisesImmutableId' in cloud['properties'] and cloud['properties']['OnPremisesImmutableId'] != anchor['cloud_immutable_id']:
                native_conflict = True
            if 'source_anchor' in ad['properties'] and ad['properties']['source_anchor'] != anchor['ad_value']:
                native_conflict = True
        elif 'onpremisessecurityidentifier' in cloud['properties'] and cloud['properties']['onpremisessecurityidentifier'] != anchor['cloud_sid']:
            native_conflict = True
        if native_conflict:
            bundle.issue('IdentityConflict', 'Identity verification disagrees with retained native identifiers.', source=source,
                         entities=[ad['id'], cloud['id']], refs=ad['evidence_refs'] + cloud['evidence_refs'] + [ref])
        bundle.data['identity_links'].append({
            'id': f"{source['source_id']}:{link['id']}", 'ad_entity_id': ad['id'],
            'cloud_entity_id': cloud['id'], 'method': 'established_id_link', 'conflict': native_conflict, 'evidence_refs': [ref]})


def _identity_conflicts(bundle):
    links = bundle.data['identity_links']
    for index, link in enumerate(links):
        for other in links[index + 1:]:
            same_ad = link['ad_entity_id'] == other['ad_entity_id']
            same_cloud = link['cloud_entity_id'] == other['cloud_entity_id']
            if same_ad != same_cloud:
                cloud_one = bundle.entities[link['cloud_entity_id']]
                cloud_two = bundle.entities[other['cloud_entity_id']]
                if same_ad and cloud_one['boundary_id'] != cloud_two['boundary_id']:
                    continue
                link['conflict'] = other['conflict'] = True
                bundle.issue('IdentityConflict', 'Verified identity claims disagree within the same boundary.',
                             entities=sorted({link['ad_entity_id'], other['ad_entity_id'], link['cloud_entity_id'], other['cloud_entity_id']}),
                             refs=link['evidence_refs'] + other['evidence_refs'])


def import_manifest(manifest_path: str | Path) -> dict:
    """Import only supported, hash-backed files confined to the manifest directory."""
    manifest_path = Path(manifest_path)
    manifest, manifest_digest = read_json_with_hash(manifest_path)
    validate_schema(manifest, 'import-manifest.schema.json')
    bundle = _Bundle(manifest['synthetic'])
    bundle.data['manifest'] = {'path': manifest_path.name, 'sha256': manifest_digest}
    source_ids, source_paths = set(), set()
    imported = []
    for definition in manifest['sources']:
        source = json.loads(json.dumps(definition))
        source_id = source['source_id']
        if source_id in source_ids:
            raise EvidenceError('InvalidInput: duplicate manifest source ID')
        source_ids.add(source_id)
        expected_version, expected_schema = SUPPORTED[source['producer']]
        if source['producer_version'] != expected_version or source['producer_schema'] != expected_schema:
            raise EvidenceError(f'UnsupportedVersion: {source["producer"]} requires {expected_version} / {expected_schema}')
        path = confined_path(manifest_path.parent, source['path'])
        if path in source_paths:
            raise EvidenceError('InvalidInput: duplicate manifest evidence path')
        source_paths.add(path)
        document, digest = read_json_with_hash(path)
        _object(document, 'evidence document')
        _reject_secret_fields(document)
        if source.get('sha256', digest) != digest:
            raise EvidenceError('InvalidInput: evidence hash does not match manifest')
        source.update(sha256=digest, adapter_version=ADAPTER_VERSION)
        source.setdefault('collection_errors', [])
        source.setdefault('exclusions', [])
        if 'tenant_id' in source['scope']:
            source['scope']['tenant_id'] = _uuid(source['scope']['tenant_id'], 'tenant scope')
        if 'forest_id' in source['scope']:
            source['scope']['forest_id'] = source['scope']['forest_id'].lower()
        bundle.observe(source, '', document)
        imported.append((source, document))
        bundle.data['sources'].append(source)
    # Supplementals can reference stable entities imported from either native producer.
    for source, document in sorted(imported, key=lambda pair: pair[0]['producer'] == 'operator-evidence'):
        {'scubagear': _scuba, 'bloodhound-ce': _bloodhound, 'operator-evidence': _supplemental}[source['producer']](bundle, source, document)
        _time(source.get('collected_at'))
        for capability in source['completeness']['capabilities']:
            bundle.data['coverage'].append({'source_id': source['source_id'], 'capability': capability,
                'complete': source['completeness']['complete'],
                'reason': 'Operator-declared source scope; absence from a query is not evidence of absence.' if source['producer'] == 'bloodhound-ce'
                else 'Source completeness and upstream errors preserved.'})
    _identity_conflicts(bundle)
    fingerprint = json.dumps({'manifest': manifest, 'hashes': [s['sha256'] for s in bundle.data['sources']]}, sort_keys=True)
    bundle.data['run_id'] = str(uuid.uuid5(uuid.NAMESPACE_URL, fingerprint))
    validate_bundle(bundle.data)
    return bundle.data
