"""Regression tests for rule drift, scan-data escaping, and safe patch scope."""
import copy
import json
import re
import tempfile
import unittest
from pathlib import Path

from engine import Catalog, extract_slots, split_source

from overlay import MARKER, TEMPLATES, apply, patch_scorecard, patch_template, restore

from report_templates import REPORT_TEMPLATES, patch_report


DIRECTORY = Path(__file__).resolve().parent
DATA = json.loads((DIRECTORY / 'catalog.zh-CN.json').read_text('utf-8'))
SOURCE = json.loads((DIRECTORY / 'sources/4.5.2.json').read_text('utf-8'))
SOURCES = {d: SOURCE[d] for d in ('code', 'manifest')}


class CatalogTests(unittest.TestCase):
    """Verify reviewed translations without altering findings or HTML trust."""

    def setUp(self):
        self.catalog = Catalog(DATA, SOURCES)

    def test_all_reviewed_fields(self):
        self.assertEqual(len(self.catalog.entries), 158)
        for (domain, rule, field), entry in self.catalog.entries.items():
            source = entry['source']
            count = len(split_source(source)) - 1
            values = tuple(7 if p == '%d' else f'arg{i}' for i, p in enumerate(
                re.findall(r'%(?:s|d)', source)))
            original = source % values if count else source
            translated = self.catalog.translate(domain, rule, field, original)
            self.assertNotEqual(original, translated, (rule, field))
            for i, argument in enumerate(values):
                if i not in entry.get('ignored_slots', []):
                    self.assertIn(str(argument), translated, (rule, field))

    def test_rule_drift_and_unknown_fall_back(self):
        sources = copy.deepcopy(SOURCES)
        rule = 'android_logging'
        original = sources['code'][rule]['description']
        sources['code'][rule]['description'] += ' Changed upstream.'
        catalog = Catalog(DATA, sources)
        self.assertIn(('code', rule, 'description'), catalog.changed)
        self.assertEqual(catalog.translate('code', rule, 'description', original),
                         original)
        self.assertEqual(self.catalog.translate('code', 'new_rule',
                                                'description', original), original)
        self.assertEqual(self.catalog.translate('code', rule, 'description',
                                                'different historical message'),
                         'different historical message')

    def test_dynamic_values_stay_plain_text(self):
        payload = '<img src=x onerror=alert(1)>'
        rule = 'explicitly_exported'
        source = SOURCES['manifest'][rule]['title']
        original = source % ('Activity', payload)
        before = copy.deepcopy(DATA)
        result = self.catalog.translate('manifest', rule, 'title', original)
        self.assertIn(payload, result)
        self.assertEqual(type(result), str)
        self.assertEqual(DATA, before)
        self.assertEqual(extract_slots('x' * 65537, '%s'), None)

    def test_bad_dictionary_falls_back(self):
        self.assertEqual(Catalog([], SOURCES).entries, {})
        bad = copy.deepcopy(DATA)
        bad['rules']['code']['android_logging']['description']['text'] = 7
        self.assertNotIn(('code', 'android_logging', 'description'),
                         Catalog(bad, SOURCES).entries)

    def test_undefined_permission_preserves_uncertainty(self):
        for rule, fields in SOURCES['manifest'].items():
            if 'not defined' in fields['description']:
                text = DATA['rules']['manifest'][rule]['description']['text']
                self.assertIn('未在被分析应用中定义', text)
                self.assertIn('若为 normal 或 dangerous', text)


class TemplateTests(unittest.TestCase):
    """Ensure all adapters stay scoped and upgrades fail closed."""

    def fixture(self):
        return """{% load static %}
{% for item in manifest_analysis.manifest_findings %}
{{item|key:"title"}} {{item|key:"description"}}
<button data-rule="{{item.rule}}">{{item.title|escapejs}}</button>
{% endfor %}
{% for rule, details in code_analysis.findings.items %}
{{ details.metadata.description }} {{ details.metadata.description }}
{% endfor %}
{% for rule, details in behaviour.items %}
{{ details.metadata.description }}
{% endfor %}<th>ISSUE</th><th>DESCRIPTION</th>"""

    def test_scope_idempotence_and_suppression(self):
        result = patch_template(self.fixture())
        self.assertEqual(result.count('|zh_code:rule'), 2)
        self.assertIn('{{ details.metadata.description }}', result)
        self.assertIn('{{item.title|escapejs}}', result)
        self.assertIn('{{item.rule}}', result)
        self.assertEqual(result.count(MARKER), 1)
        self.assertEqual(patch_template(result), result)

    def test_changed_template_rejected(self):
        with self.assertRaises(ValueError):
            patch_template(self.fixture().replace('code_analysis.findings.items',
                                                  'new_api.findings.items'))

    def scorecard_fixture(self):
        labels = ('MobSF Application Security Scorecard generated for',
                  'MobSF Application Security Scorecard',
                  'Severity Distribution (%)', 'User/Device Trackers',
                  'Security Score', 'Risk Rating', 'Privacy Risk',
                  'Not Scanned', 'Findings', 'Grade', 'Need to Investigate',
                  'Hotspot', 'need to investigate', 'Critical Risk',
                  'High Risk', 'Medium Risk', 'Low Risk')
        text = '{% load static %}\n' + '\n'.join(labels)
        for group in ('high', 'warning', 'info', 'secure', 'hotspot'):
            text += ('{% for item in ' + group + ' %} {{item.title}}'
                     ' {{ item.description}} {{ item.section | upper }}'
                     '{% endfor %}')
        return text + '\nconst high = {{ high|length }};'

    def test_scorecard_keeps_data_identifiers(self):
        source = self.scorecard_fixture()
        result = patch_scorecard(source)
        self.assertEqual(result.count('|zh_score_description'), 5)
        self.assertIn('for item in hotspot', result)
        self.assertIn('const high = {{ high|length }};', result)
        self.assertEqual(patch_scorecard(result), result)
        with self.assertRaises(ValueError):
            patch_scorecard(source.replace('{{item.title}}', '', 1))

    def test_backup_and_rollback(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'app'
            originals = {}
            for name in TEMPLATES + REPORT_TEMPLATES:
                target = root / 'mobsf/templates' / name
                target.parent.mkdir(parents=True, exist_ok=True)
                original = (self.scorecard_fixture()
                            if name.endswith('appsec_dashboard.html')
                            else self.fixture() + self.report_fixture())
                target.write_text(original, encoding='utf-8')
                originals[target] = original
            backup = apply(root, Path(temp) / 'backup')
            self.assertIsNone(apply(root, Path(temp) / 'backup'))
            installed = target.read_bytes()
            target.write_text('later user edit', encoding='utf-8')
            with self.assertRaises(ValueError):
                restore(root, Path(backup))
            target.write_bytes(installed)
            restore(root, Path(backup))
            for path, text in originals.items():
                self.assertEqual(path.read_text('utf-8'), text)

    def report_fixture(self):
        return """
{% for item in network_security.network_findings %}{{ item.description }}{% endfor %}
{% for find in certificate_analysis.certificate_findings %}{{ find.2 }}{% endfor %}
{% for findings in ats_analysis.ats_findings %}{{ findings.issue }}{% endfor %}
{% for find in firebase_urls %}{{ find.description }}{% endfor %}
{% for result in binary_analysis %}{{ result.desc }}{% endfor %}
{% if behaviour %}{% endif %}
{% for issue, details in binary_analysis.findings.items %}
{{ issue }}<a onclick="suppress('{{issue | escapejs }}')">
Suppress the rule <b>{{ issue }}</b></a>
{% endfor %}
"""

    def test_ios_binary_keeps_suppression_identifiers(self):
        source = self.fixture() + self.report_fixture()
        result = patch_report(
            source, 'static_analysis/ios_binary_analysis.html')
        self.assertEqual(result.count('issue|zh_report:"ipa-title"'), 1)
        self.assertIn("suppress('{{issue | escapejs }}')", result)
        self.assertIn('Suppress the rule <b>{{ issue }}</b>', result)
        self.assertIn(
            'details.metadata.description|zh_report_rule:rule', result)

    def test_report_labels_keep_actions_and_script_intact(self):
        template = 'static_analysis/android_binary_analysis.html'
        source = self.fixture() + self.report_fixture() + """
<p><i class="icon"></i> Scan Options </p>
<a href="#file" data-kind="Static Analyzer">Print Report</a>
<script>const markup = '<p>Scan Options</p>';</script>
{% for rule, details in android_api.items %}
{{ details.metadata.description }}<a href="{{ details.metadata.ref }}">API</a>
{% endfor %}
"""
        result = patch_report(source, template)
        self.assertIn('扫描选项', result)
        self.assertIn('>打印报告</a>', result)
        self.assertIn('data-kind="Static Analyzer"', result)
        self.assertIn("const markup = '<p>Scan Options</p>';", result)
        self.assertIn(
            'details.metadata.description|zh_android_api:rule', result)
        self.assertEqual(patch_report(result, template), result)


if __name__ == '__main__':
    unittest.main()
