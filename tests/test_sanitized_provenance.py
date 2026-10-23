"""Tamper and historical-identity checks for explicit sanitized public copies."""
import difflib
import pytest
from test_source_adaptations import adaptation, report
from test_source_trace import trace
from _source_adaptations import git_blob


def sanitized_fixture(root):
    inputs, manifest = adaptation(root)
    item = manifest['files'][0]
    retained = root / item['original_path']
    clean = retained.read_bytes() + b'# Attribution removed in public copy\n'
    retained.write_bytes(clean)
    actual = (root / item['path']).read_bytes()
    patch = ''.join(difflib.unified_diff(clean.decode().splitlines(keepends=True),
                                       actual.decode().splitlines(keepends=True),
                                       fromfile='a/'+item['source_path'],
                                       tofile='b/'+item['source_path'])).encode()
    (root/manifest['patch_path']).write_bytes(patch)
    manifest['patch_sha256'] = trace.sha(patch)
    manifest['schema'] = 'reference/explicit-source-adaptations/v2'
    manifest['sanitization'] = {
        'kind': 'attribution-only-public-derivative',
        'baseline_archive_sha256': 'a'*64,
        'baseline_manifest_sha256': 'b'*64,
        'baseline_patch_sha256': 'c'*64,
        'upstream_byte_identity_verified_by_this_manifest': False,
        'scope': 'Synthetic transformation; upstream identity is not established by public copy verification.',
    }
    item['retained_original'] = {'kind': 'attribution-sanitized-copy',
                                 'sha256': trace.sha(clean), 'git_blob': git_blob(clean)}
    return inputs, manifest


def test_public_copy_does_not_claim_upstream_byte_identity(tmp_path):
    inputs, manifest = sanitized_fixture(tmp_path)
    result = report(tmp_path, inputs, manifest)
    info = result['explicit_adaptation_manifest']
    assert info['sanitized_retained_copies'] is True
    assert info['upstream_byte_identity_verified'] is False
    assert info['approval_verified'] is False
    row = next(r for r in result['files'] if r['path'] == 'src/factory/policy.py')
    assert row['sha256'] == manifest['files'][0]['original_sha256']
    assert row['sha256'] != manifest['files'][0]['retained_original']['sha256']
    assert row['byte_identity'] is False
    assert row['direct_rows'] == ['A03']
    assert result['engineering_complete'] is False


@pytest.mark.parametrize('path,message', [
    ('originals/policy.py', 'Sanitized original bytes'),
    ('src/factory/policy.py', 'Adapted source bytes'),
    ('proposal.patch', 'patch hash'),
])
def test_public_copy_tampering_is_rejected(tmp_path, path, message):
    inputs, manifest = sanitized_fixture(tmp_path)
    with (tmp_path/path).open('ab') as f: f.write(b'# tampered\n')
    with pytest.raises(ValueError, match=message): report(tmp_path, inputs, manifest)


def test_legacy_schema_cannot_silently_accept_sanitized_copy(tmp_path):
    inputs, manifest = sanitized_fixture(tmp_path)
    manifest['schema'] = 'reference/explicit-source-adaptations/v1'
    del manifest['sanitization']
    with pytest.raises(ValueError, match='explicit v2 classification'):
        report(tmp_path, inputs, manifest)


def test_sanitized_copy_cannot_rewrite_historical_anchor(tmp_path):
    inputs, manifest = sanitized_fixture(tmp_path)
    manifest['files'][0]['original_git_blob'] = 'f'*40
    with pytest.raises(ValueError, match='pinned recovered provenance'):
        report(tmp_path, inputs, manifest)


def test_rehashed_patch_still_must_reconstruct_public_copies(tmp_path):
    inputs, manifest = sanitized_fixture(tmp_path)
    patch = b'unrelated patch\n'
    (tmp_path/'proposal.patch').write_bytes(patch)
    manifest['patch_sha256'] = trace.sha(patch)
    with pytest.raises(ValueError, match='reconstruct the exact pinned patch'):
        report(tmp_path, inputs, manifest)


@pytest.mark.parametrize('field,value', [
    ('upstream_byte_identity_verified_by_this_manifest', True),
    ('baseline_archive_sha256', ''),
    ('baseline_manifest_sha256', 'invalid'),
    ('baseline_patch_sha256', 'z'*64),
])
def test_sanitized_history_requires_pins_and_explicit_limit(tmp_path, field, value):
    inputs, manifest = sanitized_fixture(tmp_path)
    manifest['sanitization'][field] = value
    with pytest.raises(ValueError, match='historical pins and limits'):
        report(tmp_path, inputs, manifest)
