"""Django filters for the optional MobSF Chinese risk overlay."""
import ast
import json
import logging
import os
from functools import lru_cache
from pathlib import Path

import yaml

from django import template

from .mobsf_zh_engine import Catalog
from .mobsf_zh_scorecard import SECTIONS, ScorecardCatalog, load_catalog, report_catalog
from .mobsf_zh_scorecard import android_permission_scorecard, manifest_scorecard


register = template.Library()
logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def get_catalog():
    """Read fixed, administrator-installed sources once per worker."""
    try:
        directory = Path(__file__).resolve().parent
        data = json.loads(
            (directory / 'mobsf_zh_catalog.json').read_text('utf-8'))
        root = directory.parent / 'views' / 'android'
        code = yaml.safe_load(
            (root / 'rules' / 'android_rules.yaml').read_text('utf-8'))
        tree = ast.parse(
            (root / 'kb' / 'android_manifest_desc.py').read_text('utf-8'))
        node = next(n for n in tree.body if isinstance(n, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == 'MANIFEST_DESC'
                            for t in n.targets))
        manifest = ast.literal_eval(node.value)
        sources = {
            'code': {r['id']: {'description': r['message']} for r in code},
            'manifest': {k: {f: v[f] for f in ('title', 'description')}
                         for k, v in manifest.items()},
        }
        return Catalog(data, sources)
    except (OSError, ValueError, TypeError, KeyError, StopIteration,
            SyntaxError, AttributeError, yaml.YAMLError):
        logger.warning('Chinese risk catalog unavailable; using original text')
        return Catalog({}, {})


def translate(domain, rule, field, original):
    """Keep the escape state explicit: translated values are never marked safe."""
    if os.environ.get('MOBSF_RISK_LOCALE', 'zh-CN') != 'zh-CN':
        return original
    return get_catalog().translate(domain, rule, field, original)


@register.filter
def zh_code(value, rule):
    """Translate the description of a code finding by its original rule ID."""
    return translate('code', rule, 'description', value)


@register.filter
def zh_manifest_title(item):
    """Translate a manifest title without changing its suppression identifier."""
    if not isinstance(item, dict):
        return ''
    return translate('manifest', item.get('rule'), 'title', item.get('title', ''))


@register.filter
def zh_manifest_description(item):
    """Translate a manifest explanation, retaining dynamic arguments as text."""
    if not isinstance(item, dict):
        return ''
    return translate('manifest', item.get('rule'), 'description',
                     item.get('description', ''))


@lru_cache(maxsize=1)
def get_scorecard_catalog():
    """Cache the version-checked scorecard dictionary separately from rules."""
    directory = Path(__file__).resolve().parent
    return load_catalog(directory, directory.parents[2])


def scorecard_text(item, field):
    """Localize only presentation fields; API findings remain untouched."""
    if not isinstance(item, dict):
        return ''
    original = item.get(field, '')
    if os.environ.get('MOBSF_RISK_LOCALE', 'zh-CN') != 'zh-CN':
        return original
    catalog = get_scorecard_catalog()
    section = item.get('section')
    if 'appsec' in catalog.active and section == 'manifest':
        title, description = manifest_scorecard(get_catalog(), item)
        return title if field == 'title' else description
    result = catalog.translate(item, field)
    if 'appsec' in catalog.active:
        if section == 'permissions' and field == 'description':
            return android_permission_scorecard(get_report_catalog(), result)
        if section in ('certificate', 'firebase') and result == original:
            return zh_report(original, 'cert' if section == 'certificate' else section)
    return result


@register.filter
def zh_score_title(item):
    """Translate reviewed scorecard finding titles."""
    return scorecard_text(item, 'title')


@register.filter
def zh_score_description(item):
    """Translate explanations, preserving filenames, symbols, and raw evidence."""
    return scorecard_text(item, 'description')


@register.filter
def zh_section(value):
    """Translate fixed section identifiers without changing their stored value."""
    return SECTIONS.get(value, value)


@lru_cache(maxsize=1)
def get_report_catalog():
    """Load independently reviewed report text once per worker."""
    directory = Path(__file__).resolve().parent
    try:
        data = json.loads(
            (directory / 'mobsf_zh_report.json').read_text('utf-8'))
        return report_catalog(data, directory.parents[2])
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        logger.warning(
            'Chinese report catalog unavailable; using original text')
        return ScorecardCatalog({}, {})


@register.filter
def zh_report(value, section):
    """Localize known report words while letting Django escape all evidence."""
    if os.environ.get('MOBSF_RISK_LOCALE', 'zh-CN') != 'zh-CN':
        return value
    if section == 'status':
        return {'Insecure': '不安全', 'Secure': '安全', 'Info': '提示'}.get(value, value)
    if section.startswith('ipa-'):
        field = section[4:]
        return scorecard_text({'section': 'binary', field: value}, field)
    if section == 'macho':
        translated = scorecard_text({'section': 'macho', 'description': value},
                                    'description')
        if translated != value:
            return translated
        section = 'elf'
    return get_report_catalog().translate({'section': section, 'value': value}, 'value')


@register.filter
def zh_report_rule(value, rule):
    """Match both a reviewed iOS rule identifier and its display wording."""
    if os.environ.get('MOBSF_RISK_LOCALE', 'zh-CN') != 'zh-CN':
        return value
    section = 'ios-api' if str(rule).startswith('api_') else 'ios-code'
    return get_report_catalog().translate(
        {'section': section, 'rule': rule, 'value': value}, 'value')


@register.filter
def zh_android_api(value, rule):
    """Match the Android API rule's identifier and original message."""
    if os.environ.get('MOBSF_RISK_LOCALE', 'zh-CN') != 'zh-CN':
        return value
    return get_report_catalog().translate(
        {'section': 'android-api', 'rule': rule, 'value': value}, 'value')


@register.filter
def zh_android_permission(value, permission):
    """Translate stock descriptions while preserving each Android permission ID."""
    if os.environ.get('MOBSF_RISK_LOCALE', 'zh-CN') != 'zh-CN':
        return value
    if value in ('Unknown permission', 'Unknown permission from android reference'):
        return '未知权限' if value == 'Unknown permission' else '系统权限参考中未找到该权限。'
    rule = str(permission)
    if rule.startswith(('android.', 'com.google.')):
        rule = rule.rsplit('.', 1)[-1]
    return get_report_catalog().translate(
        {'section': 'android-permission', 'rule': rule, 'value': value}, 'value')


@register.filter
def zh_ios_permission(value, rule):
    """Localize MobSF's permission metadata and keep app-authored reasons intact."""
    if os.environ.get('MOBSF_RISK_LOCALE', 'zh-CN') != 'zh-CN':
        return value
    entry = get_scorecard_catalog().permission_info.get(rule, {})
    return entry['text'] if entry.get('source') == value else value
