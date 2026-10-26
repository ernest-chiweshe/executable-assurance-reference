"""Validate retained installed-package CI evidence; exits nonzero on any gap."""
import argparse
from collections import Counter
import json
from pathlib import Path
import xml.etree.ElementTree as ET


def verify(manifest, selection, junit, database):
    def require(condition, message):
        if not condition:
            raise ValueError(message)
    expected = [row['nodeid'] for row in manifest['tests'] if row['scope'] == 'public']
    require(len(expected) == manifest['public_tests'] and len(set(expected)) == len(expected), 'invalid public manifest')
    require(not selection.get('collection_failed'), 'collection failed')
    require(selection.get('exitstatus') == 0, 'pytest did not succeed')
    require(selection.get('selected') == len(expected), 'selection count differs')
    require(Counter(selection.get('selected_nodes', [])) == Counter(expected), 'selected identities differ')
    require(selection.get('private_excluded') == manifest['private_tests'], 'private denominator differs')
    require(selection.get('unapproved_noninstalled_modules') == [], 'unapproved installed-runtime imports')
    require(bool(selection.get('module_origins')) and bool(selection.get('site_packages')), 'installed-runtime evidence missing')
    cases = junit.findall('.//testcase')
    identities = [case.attrib['classname'].replace('.', '/') + '.py::' + case.attrib['name'] for case in cases]
    require(Counter(identities) == Counter(expected), 'JUnit identities differ or duplicate')
    require(not any(case.find(kind) is not None for case in cases for kind in ('failure', 'error', 'skipped')), 'JUnit has failure/error/skip')
    require(database.get('started') is True and database.get('stopped') is True, 'isolated database cleanup unconfirmed')
    require(database.get('validation_exit_code') == 0, 'database runner did not succeed')
    return {'status': 'PASS', 'public_passed': len(expected), 'private_excluded': manifest['private_tests'], 'failures': 0, 'errors': 0, 'skipped': 0, 'exact_node_identities': True, 'installed_origins_checked': True, 'isolated_database_stopped': True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--results', type=Path, required=True)
    args = parser.parse_args()
    def load(path):
        return json.loads(path.read_text(encoding='utf-8-sig'))
    result = verify(load(args.manifest), load(args.results / 'PUBLIC-RESULT.json'), ET.parse(args.results / 'pytest.xml').getroot(), load(args.results / 'pg' / 'RESULT.json'))
    (args.results / 'ACCEPTANCE.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
