"""Build an audited dictionary from an upstream snapshot and reviewed Chinese."""
import argparse
import json
from pathlib import Path

from engine import Catalog, fingerprint


def build(directory, source_path=None):
    """Require complete field and placeholder coverage of the source snapshot."""
    source_path = source_path or directory / 'sources/4.5.2.json'
    source = json.loads(source_path.read_text('utf-8'))
    translated = json.loads(
        (directory / 'translations.zh-CN.json').read_text('utf-8'))
    data = {'schema_version': 1, 'locale': 'zh-CN',
            'tested_versions': [source['version']], 'rules': {}}
    for domain in ('code', 'manifest'):
        assert set(source[domain]) == set(translated[domain]), domain
        data['rules'][domain] = {}
        for rule, fields in source[domain].items():
            assert set(fields) == set(translated[domain][rule]), rule
            data['rules'][domain][rule] = {
                field: dict(translated[domain][rule][field],
                            source=text, sha256=fingerprint(text))
                for field, text in fields.items()}
    catalog = Catalog(data, {d: source[d] for d in ('code', 'manifest')})
    expected = sum(len(f) for d in data['rules'].values() for f in d.values())
    assert len(catalog.entries) == expected, 'Invalid placeholders or source hash'
    return json.dumps(data, ensure_ascii=False, indent=2) + '\n'


def main():
    """Generate the catalog or verify that the checked-in artifact is current."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--source', type=Path,
                        help='Reviewed upstream source snapshot for a new version')
    args = parser.parse_args()
    directory = Path(__file__).resolve().parent
    result = build(directory, args.source)
    destination = directory / 'catalog.zh-CN.json'
    if args.check:
        if destination.read_text('utf-8') != result:
            raise SystemExit('Catalog out of date: run build_catalog.py')
    else:
        destination.write_text(result, encoding='utf-8')
    print('Catalog verified')


if __name__ == '__main__':
    main()
