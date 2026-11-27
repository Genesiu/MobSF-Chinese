"""Scorecard regression checks: source drift, dynamic evidence, and no mutation."""
import copy
import json
import unittest
from pathlib import Path

from engine import Catalog, split_source

from scorecard import ScorecardCatalog, android_permission_scorecard, manifest_scorecard
from scorecard import code_scorecard, network_scorecard


DATA = json.loads((Path(__file__).resolve().parent
                   / 'scorecard.zh-CN.json').read_text('utf-8'))
ROOT = Path(__file__).resolve().parent


def reviewed_reports():
    """Load the reviewed report strings as if their source hashes matched."""
    report = json.loads((ROOT / 'report.zh-CN.json').read_text('utf-8'))
    hashes = {key: value['sha256'] for key, value in report['origins'].items()}
    return ScorecardCatalog(dict(report, origins=hashes), hashes)


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

    def test_android_manifest_matches_title_and_details_together(self):
        reviewed = json.loads((ROOT / 'catalog.zh-CN.json').read_text('utf-8'))
        source = json.loads((ROOT / 'sources/4.5.2.json').read_text('utf-8'))
        catalog = Catalog(reviewed, {'manifest': source['manifest']})
        rule = source['manifest']['task_hijacking2']
        finding = {'title': rule['title'] % 'example.MainActivity',
                   'description': rule['description'] % 26}
        title, details = manifest_scorecard(catalog, finding)
        self.assertIn('example.MainActivity', title)
        self.assertIn('任务劫持风险', title)
        self.assertIn('26', details)
        finding['description'] += ' New meaning.'
        self.assertEqual(manifest_scorecard(catalog, finding),
                         (finding['title'], finding['description']))

    def test_android_manifest_preserves_relocated_permission_evidence(self):
        reviewed = json.loads((ROOT / 'catalog.zh-CN.json').read_text('utf-8'))
        source = json.loads((ROOT / 'sources/4.5.2.json').read_text('utf-8'))
        catalog = Catalog(reviewed, {'manifest': source['manifest']})
        rule = source['manifest']['exported_protected_permission_signature']
        evidence = ' example.permission.SIGNED'
        raw = rule['title'] % (
            'Activity', 'example.MainActivity', '<br>' + evidence)
        title, moved = raw.split('<br>', 1)
        finding = {'title': title,
                   'description': '\n'.join((moved, rule['description']))}
        heading, details = manifest_scorecard(catalog, finding)
        self.assertIn('受权限保护', heading)
        self.assertIn(evidence, details)
        self.assertIn('[android:exported=true]', details)

    def test_android_permission_does_not_translate_custom_identifier(self):
        catalog = reviewed_reports()
        original = ('android.permission.RECORD_AUDIO (dangerous): record audio - '
                    'Allows application to access the audio record path.')
        self.assertIn('录制音频', android_permission_scorecard(catalog, original))
        custom = original.replace('android.permission', 'example.permission')
        self.assertEqual(android_permission_scorecard(catalog, custom), custom)

    def test_android_network_preserves_scope_and_all_arguments(self):
        catalog = reviewed_reports()
        for entry in catalog.entries:
            if entry['section'] != 'network':
                continue
            source = entry['source']
            slots = tuple(f'example{i}' for i in range(
                len(split_source(source)) - 1))
            original = source % slots if slots else source
            heading, _, remainder = original.partition('.')
            scope = 'Scope:\nexample.org\n\n'
            result = network_scorecard(catalog, {
                'title': heading, 'description': scope + remainder.strip()})
            self.assertNotEqual(result[0], heading, source)
            self.assertIn('适用范围：\nexample.org', result[1])
            for argument in slots:
                self.assertIn(argument, ''.join(result))

    def test_ios_ats_keeps_domain_list(self):
        domains = 'example.org, assets.example.org'
        title, details = network_scorecard(reviewed_reports(), {
            'title': 'NSExceptionDomains', 'description': domains})
        self.assertIn('例外域名', title)
        self.assertEqual(details, '例外域名：' + domains)

    def test_code_scorecard_translates_shared_rules_and_file_labels(self):
        reviewed = json.loads((ROOT / 'catalog.zh-CN.json').read_text('utf-8'))
        source = json.loads((ROOT / 'sources/4.5.2.json').read_text('utf-8'))
        rules = Catalog(reviewed, {'code': source['code']})
        original = ('The App logs information. '
                    'Sensitive information should never be logged.')
        title, details = code_scorecard(rules, reviewed_reports(), {
            'title': original,
            'description': original + '\n\n\nFiles:\nexample.java, line(s) 14'})
        self.assertIn('日志', title)
        self.assertIn('相关文件：\nexample.java，行号 14', details)


if __name__ == '__main__':
    unittest.main()
