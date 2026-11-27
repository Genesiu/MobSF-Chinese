"""Scorecard regression checks: source drift, dynamic evidence, and no mutation."""
import copy
import json
import unittest
from pathlib import Path

from engine import split_source

from scorecard import ScorecardCatalog


DATA = json.loads((Path(__file__).resolve().parent
                   / 'scorecard.zh-CN.json').read_text('utf-8'))


class ScorecardTests(unittest.TestCase):
    """Cover reviewed iOS findings and shared scorecard summaries."""

    def setUp(self):
        self.catalog = ScorecardCatalog(DATA, DATA['origins'])

    def test_all_patterns_preserve_evidence(self):
        self.assertEqual(len(self.catalog.entries), 58)
        before = copy.deepcopy(DATA)
        for entry in self.catalog.entries:
            count = len(split_source(entry['source'])) - 1
            arguments = tuple(f'<evidence-{i}>' for i in range(count))
            original = entry['source'] % arguments if count else entry['source']
            item = {'section': entry['section'], entry['field']: original}
            snapshot = item.copy()
            translated = self.catalog.translate(item, entry['field'])
            self.assertNotEqual(original, translated)
            for argument in arguments:
                self.assertIn(argument, translated)
            self.assertEqual(item, snapshot)
            self.assertEqual(type(translated), str)
        self.assertEqual(DATA, before)

    def test_new_wording_or_changed_source_stays_original(self):
        item = {'section': 'binary',
                'title': 'Binary makes use of insecure API(s)'}
        hashes = dict(DATA['origins'], ipa='changed')
        catalog = ScorecardCatalog(DATA, hashes)
        self.assertEqual(catalog.translate(item, 'title'), item['title'])
        item['title'] += ' (new wording)'
        self.assertEqual(self.catalog.translate(item, 'title'), item['title'])

    def test_geolocation_preserves_values_and_escapes_later(self):
        payload = '<img src=x onerror=alert(1)>'
        item = {'section': 'domains',
                'description': repr({'country_long': payload, 'latitude': 7.5})}
        translated = self.catalog.translate(item, 'description')
        self.assertIn('国家/地区：' + payload, translated)
        self.assertIn('纬度：7.5', translated)
        item['description'] = "{'x': ['unexpected nested value']}"
        self.assertEqual(self.catalog.translate(item, 'description'),
                         item['description'])

    def test_permission_reason_remains_original(self):
        reason = '<svg onload=alert(1)> app-authored reason'
        item = {'section': 'permissions', 'description': (
            'Ensure that these permissions are required by the application.\n\n'
            'NSCameraUsageDescription (dangerous): Access the Camera. - ' + reason)}
        translated = self.catalog.translate(item, 'description')
        self.assertIn('访问相机。', translated)
        self.assertIn('应用用途声明：' + reason, translated)
        self.assertIn('NSCameraUsageDescription', translated)

    def test_large_raw_evidence_keeps_every_byte(self):
        evidence = 'untrusted <evidence>\n' * 10000
        item = {'section': 'secrets', 'description': (
            'The following secrets were identified from the app. '
            'Ensure that these are not secrets or private information.\n'
            + evidence)}
        translated = self.catalog.translate(item, 'description')
        self.assertTrue(translated.startswith('从应用中识别出'))
        self.assertTrue(translated.endswith(evidence))


if __name__ == '__main__':
    unittest.main()
