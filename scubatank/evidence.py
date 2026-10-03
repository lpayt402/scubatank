"""Bounded offline JSON reading and versioned evidence validation."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PureWindowsPath
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 16 * 1024 * 1024
MAX_DEPTH = 64
MAX_VALUES = 200_000


class EvidenceError(ValueError):
    """Untrusted evidence cannot satisfy the declared input contract."""


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f'InvalidInput: duplicate JSON key {key!r}')
        result[key] = value
    return result


def _invalid_constant(value):
    raise EvidenceError(f'InvalidInput: nonfinite JSON value {value}')


def local_path(path: str | Path) -> Path:
    """Reject UNC and URI paths before any filesystem operation can contact a host."""
    text = str(path)
    windows = PureWindowsPath(text)
    if text.startswith(('\\\\', '//')) or windows.drive.startswith('\\\\'):
        raise EvidenceError('InvalidInput: evidence paths must use a local filesystem; UNC paths are forbidden')
    scheme = re.match(r'^([A-Za-z][A-Za-z0-9+.-]*):', text)
    if scheme and len(scheme.group(1)) != 1:
        raise EvidenceError('InvalidInput: evidence paths must use a local filesystem; URIs are forbidden')
    return Path(path)


def read_json_with_hash(path: str | Path, *, max_bytes: int = MAX_BYTES) -> tuple[Any, str]:
    """Parse and hash one bounded byte snapshot, avoiding a second mutable file read."""
    path = local_path(path)
    try:
        if not path.is_file() or path.stat().st_size > max_bytes:
            raise EvidenceError(f'InvalidInput: file missing or exceeds size limit: {path.name}')
        raw = path.read_bytes()
        if len(raw) > max_bytes:
            raise EvidenceError('InvalidInput: file exceeds size limit')
        value = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=_pairs, parse_constant=_invalid_constant)
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise EvidenceError(f'InvalidInput: invalid JSON in {path.name}: {exc}') from exc
    pending = [(value, 0)]
    count = 0
    while pending:
        current, depth = pending.pop()
        count += 1
        if depth > MAX_DEPTH:
            raise EvidenceError('InvalidInput: JSON depth limit exceeded')
        if count > MAX_VALUES:
            raise EvidenceError('InvalidInput: JSON value/record limit exceeded')
        if isinstance(current, dict):
            pending.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            pending.extend((child, depth + 1) for child in current)
    return value, hashlib.sha256(raw).hexdigest()


def read_json(path: str | Path, *, max_bytes: int = MAX_BYTES) -> Any:
    """Read UTF-8 JSON with limits; never follow URLs or execute imported text."""
    return read_json_with_hash(path, max_bytes=max_bytes)[0]


def confined_path(root: Path, relative: str) -> Path:
    """Resolve a manifest path inside its evidence directory, including symlinks."""
    if not isinstance(relative, str) or not relative or '\x00' in relative:
        raise EvidenceError('InvalidInput: invalid evidence path')
    windows = PureWindowsPath(relative)
    if windows.is_absolute() or windows.drive or relative.startswith(('/', '\\')) or ':' in relative:
        raise EvidenceError('InvalidInput: absolute evidence path is forbidden')
    parts = relative.replace('\\', '/').split('/')
    if any(part in ('', '.', '..') for part in parts):
        raise EvidenceError('InvalidInput: evidence path traversal is forbidden')
    root = local_path(root).resolve()
    path = root.joinpath(*parts).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise EvidenceError('InvalidInput: evidence path is outside the root or missing')
    return path


def validate_schema(value: Any, name: str) -> None:
    schema = read_json(ROOT / 'schemas' / name)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(value), key=lambda e: str(list(e.path)))
    if errors:
        error = errors[0]
        raise EvidenceError(f'InvalidSchema: {name} at {list(error.path)}: {error.message}')


def make_ref(source_id: str, pointer: str = '') -> str:
    return f'{source_id}#{pointer}'


def pointer_escape(value: str) -> str:
    return value.replace('~', '~0').replace('/', '~1')


def resolve_pointer(document: Any, pointer: str) -> Any:
    if pointer == '':
        return document
    if not pointer.startswith('/'):
        raise EvidenceError('InvalidInput: malformed evidence reference pointer')
    current = document
    for encoded in pointer[1:].split('/'):
        if re.search(r'~(?![01])', encoded):
            raise EvidenceError('InvalidInput: malformed evidence reference escape')
        token = encoded.replace('~1', '/').replace('~0', '~')
        try:
            if isinstance(current, list):
                if not re.fullmatch(r'0|[1-9][0-9]*', token):
                    raise EvidenceError('InvalidInput: malformed evidence reference index')
                current = current[int(token)]
            elif isinstance(current, dict):
                current = current[token]
            else:
                raise EvidenceError('InvalidInput: evidence reference traverses a scalar')
        except (KeyError, IndexError) as exc:
            raise EvidenceError('InvalidInput: evidence reference does not exist') from exc
    return current


def validate_bundle(bundle: dict) -> None:
    """Validate the envelope, IDs, endpoints, and every retained evidence pointer."""
    validate_schema(bundle, 'assessment-evidence.schema.json')
    source_ids = {s['source_id'] for s in bundle['sources']}
    if len(source_ids) != len(bundle['sources']):
        raise EvidenceError('InvalidInput: duplicate source identity')
    observations = {}
    for observation in bundle['observations']:
        ref = observation['ref']
        if ref in observations:
            raise EvidenceError('InvalidInput: duplicate observation reference')
        observations[ref] = observation['value']
    roots = {}
    for source_id in source_ids:
        ref = make_ref(source_id)
        if ref not in observations:
            raise EvidenceError('InvalidInput: source lacks a root evidence reference')
        roots[source_id] = observations[ref]
    for ref, value in observations.items():
        source_id, _, pointer = ref.partition('#')
        if source_id not in roots or '#' not in ref or resolve_pointer(roots[source_id], pointer) != value:
            raise EvidenceError('InvalidInput: inconsistent observation reference')
    entity_ids = {e['id'] for e in bundle['entities']}
    for group in ('entities', 'edges', 'facts', 'identity_links', 'upstream_findings'):
        ids = set()
        for record in bundle[group]:
            if record['id'] in ids:
                raise EvidenceError(f'InvalidInput: duplicate {group} identity')
            ids.add(record['id'])
            for ref in record['evidence_refs']:
                source_id, separator, pointer = ref.partition('#')
                if not separator or source_id not in roots:
                    raise EvidenceError('InvalidInput: evidence reference has unknown source')
                resolve_pointer(roots[source_id], pointer)
            if group == 'edges' and {record['source_id'], record['target_id']} - entity_ids:
                raise EvidenceError('InvalidInput: graph endpoint does not exist')
            if group == 'facts' and record['subject_id'] not in entity_ids:
                raise EvidenceError('InvalidInput: fact subject does not exist')
            if group == 'identity_links' and {record['ad_entity_id'], record['cloud_entity_id']} - entity_ids:
                raise EvidenceError('InvalidInput: identity link endpoint does not exist')
