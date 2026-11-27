"""Localize scorecard display text, with exact sources and upgrade fallback."""
import ast
import hashlib
import json
import re

if __package__:
    from .mobsf_zh_engine import MAX_TEXT, ZH_SLOTS, extract_slots, split_source
else:
    from engine import MAX_TEXT, ZH_SLOTS, extract_slots, split_source


ORIGINS = {
    'appsec': 'mobsf/StaticAnalyzer/views/common/appsec.py',
    'macho': 'mobsf/StaticAnalyzer/views/common/binary/macho.py',
    'ipa': 'mobsf/StaticAnalyzer/views/ios/rules/ipa_rules.py',
    'permissions': 'mobsf/StaticAnalyzer/views/ios/kb/permission_analysis.py',
}
SECTIONS = {
    'binary': '二进制安全分析', 'macho': 'Mach-O 安全防护',
    'network': '网络安全', 'certificate': '证书安全',
    'manifest': '清单安全分析', 'code': '代码安全分析',
    'permissions': '权限检查', 'files': '文件检查',
    'domains': '域名与服务器位置', 'firebase': 'Firebase 配置',
    'trackers': '隐私追踪', 'secrets': '疑似硬编码密钥',
}
GEO_LABELS = {
    'country_short': '国家/地区代码', 'country_long': '国家/地区',
    'country_name': '国家/地区', 'region': '地区', 'region_name': '地区',
    'city': '城市', 'latitude': '纬度', 'longitude': '经度',
    'zipcode': '邮政编码', 'zip_code': '邮政编码', 'time_zone': '时区',
    'timezone': '时区', 'ip': 'IP 地址', 'ip_address': 'IP 地址',
    'isp': '网络服务提供商', 'domain': '域名', 'netspeed': '连接类型',
    'idd_code': '国际拨号代码', 'area_code': '区号',
    'weather_station_code': '气象站代码', 'weather_station_name': '气象站名称',
    'weather_code': '气象站代码', 'weather_name': '气象站名称',
    'mcc': '移动国家码', 'mnc': '移动网络码', 'mobile_brand': '移动运营商',
    'elevation': '海拔', 'usage_type': '网络用途', 'address_type': '地址类型',
    'category': '类别', 'district': '区县', 'asn': '自治系统编号',
    'as_name': '自治系统名称', 'as': '自治系统名称',
    'as_domain': '自治系统域名', 'as_usagetype': '自治系统用途',
    'as_cidr': '自治系统 CIDR 网段',
}
GEO_UNAVAILABLE = (
    'This parameter is unavailable in selected .BIN data file. '
    'Please upgrade data file.'
)
ANDROID_PERMISSION = re.compile(
    r'^((?:android|com\.google)\.[\w.]+) \(dangerous\): ([^\n]*?) - ([^\n]*)$',
    re.MULTILINE,
)


def manifest_scorecard(catalog, item):
    """Recover a reviewed manifest rule from the scorecard's displayed fields."""
    title, description = item.get('title', ''), item.get('description', '')
    if not isinstance(title, str) or not isinstance(description, str):
        return title, description
    candidates = [(title, description)]
    prefix, newline, body = description.partition('\n')
    if newline:
        # MobSF moves the portion after the first <br> from the title to the body.
        candidates.append((title + '<br>' + prefix, body))
    for heading, body in candidates:
        matches = set()
        for domain, rule, field in catalog.entries:
            if domain != 'manifest' or field != 'title':
                continue
            translated = catalog.translate(domain, rule, 'title', heading)
            if translated == heading:
                continue
            details = catalog.translate(domain, rule, 'description', body)
            if details == body:
                continue
            summary, breaks, evidence = translated.partition('<br>')
            if breaks:
                details = evidence.replace('<br>', '') + '\n' + details
            matches.add((summary, details))
        if matches:
            return matches.pop() if len(matches) == 1 else (title, description)
    return title, description


def android_permission_scorecard(catalog, text):
    """Translate both stock Android permission fields using their permission ID."""
    if not isinstance(text, str) or len(text) > MAX_TEXT:
        return text

    def translate(match):
        name, info, description = match.groups()
        item = {'section': 'android-permission',
                'rule': name.rsplit('.', 1)[-1]}
        labels = [catalog.translate(dict(item, value=value), 'value')
                  for value in (info, description)]
        if labels == [info, description]:
            return match[0]
        return f'{name}（高敏感权限）：{labels[0]} — {labels[1]}'

    return ANDROID_PERMISSION.sub(translate, text)


def code_scorecard(risks, reports, item):
    """Localize a reviewed code finding and its file and line labels."""
    title, description = item.get('title', ''), item.get('description', '')
    if not isinstance(title, str) or not isinstance(description, str):
        return title, description
    translations = {
        entry['text'] for (section, _, field), entry in risks.entries.items()
        if section == 'code' and field == 'description' and entry['source'] == title
    }
    translations.update(entry['text'] for entry in reports.entries
                        if entry['section'] == 'ios-code' and entry['source'] == title)
    if len(translations) != 1:
        return title, description
    chinese = translations.pop()
    if description == title:
        return chinese, chinese
    if not description.startswith(title + '\n'):
        return chinese, description
    reference, marker, files = description[len(
        title):].partition('\n\nFiles:\n')
    if not marker:
        return chinese, chinese + reference
    lines = []
    for record in files.split('\n'):
        path, marker, positions = record.rpartition(', line(s) ')
        lines.append(f'{path}，行号 {positions}' if marker else record)
    return chinese, chinese + reference + '\n\n相关文件：\n' + '\n'.join(lines)


def network_scorecard(catalog, item):
    """Translate an Android scoped finding or an iOS ATS finding."""
    title, description = item.get('title', ''), item.get('description', '')
    if not isinstance(title, str) or not isinstance(description, str):
        return title, description

    def translate(value, section):
        return catalog.translate({'section': section, 'value': value}, 'value')

    if not description.startswith('Scope:\n'):
        heading = translate(title, 'ats')
        if title == 'NSExceptionDomains' and heading != title:
            return heading, '例外域名：' + description
        return heading, translate(description, 'ats')

    scope, separator, details = description[len('Scope:\n'):].partition('\n\n')
    if not separator:
        return title, description
    candidates = (title + '. ' + details, title + '.' + details) if details else (
        title + '.', title)
    translations = set()
    for candidate in candidates:
        translated = translate(candidate, 'network')
        if translated != candidate:
            translations.add(translated)
    if len(translations) != 1:
        return title, description
    translated = translations.pop()
    if not details:
        return translated, '适用范围：\n' + scope
    summary, stop, remainder = translated.partition('。')
    if stop and remainder:
        return summary, f'适用范围：\n{scope}\n\n{remainder}'
    return translated, '适用范围：\n' + scope


def source_hashes(root, origins=None):
    """Read only fixed installed source files, rejecting links outside the app."""
    root = root.resolve()
    result = {}
    for name, relative in (ORIGINS if origins is None else origins).items():
        path = root / relative
        path.resolve().relative_to(root.resolve())
        if any(p.is_symlink() for p in (path, *path.parents) if p != root):
            raise ValueError('Symbolic link in scorecard source')
        if path.is_file():
            result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


class ScorecardCatalog:
    """Translate a reviewed field only when its upstream source is unchanged."""

    def __init__(self, data, current_hashes):
        self.entries = []
        self.permission_info = {}
        self.active = set()
        if not isinstance(data, dict) or data.get('schema_version') != 1:
            return
        self.active = {name for name, value in current_hashes.items()
                       if value == data.get('origins', {}).get(name)}
        for entry in data.get('translations', []):
            if entry.get('origin') not in self.active:
                continue
            source, text = entry.get('source'), entry.get('text')
            if not isinstance(source, str) or not isinstance(text, str):
                continue
            references = {int(n) for n in ZH_SLOTS.findall(text)}
            if references != set(range(len(split_source(source)) - 1)):
                continue
            self.entries.append(entry)
        if 'permissions' in self.active:
            self.permission_info = data.get('permission_info', {})

    def translate(self, item, field):
        """Keep parameters and unknown findings verbatim; never return safe HTML."""
        original = item.get(field, '')
        section = item.get('section')
        if not isinstance(original, str):
            return original
        if len(original) > MAX_TEXT:
            # Large raw evidence needs only its fixed introductory text changed.
            # Do not scan or parse the evidence itself to localize that heading.
            for entry in self.entries:
                if entry['section'] != section or entry['field'] != field:
                    continue
                parts = split_source(entry['source'])
                if (len(parts) == 2 and parts[0] and parts[1] == ''
                        and original.startswith(parts[0])):
                    return entry['text'].replace('{0}', original[len(parts[0]):])
            return original
        if section == 'domains' and field == 'description':
            return self.geo_details(original)
        for entry in self.entries:
            if entry['section'] != section or entry['field'] != field:
                continue
            if 'rule' in entry and entry['rule'] != item.get('rule'):
                continue
            values = extract_slots(original, entry['source'])
            if values is not None:
                text = ZH_SLOTS.sub(
                    lambda m, args=values: args[int(m[1])], entry['text'])
                if section == 'permissions' and field == 'description':
                    text = self.permissions(text)
                return text
        return original

    def permissions(self, text):
        """Translate built-in permission labels, preserving app-authored reasons."""
        for permission, entry in self.permission_info.items():
            prefix = permission + ' (dangerous): ' + entry['source'] + ' - '
            translated = (permission + '（高敏感权限）：' + entry['text']
                          + ' — 应用用途声明：')
            text = re.sub(r'(?m)^' + re.escape(prefix),
                          lambda match, value=translated: value, text)
        return text

    def geo_details(self, original):
        """Format scalar geolocation data as escaped text with Chinese labels."""
        if 'appsec' not in self.active or len(original) > 8192:
            return original
        if original in ('None', '{}', ''):
            return '未找到地理位置数据。'
        try:
            data = ast.literal_eval(original)
        except (ValueError, TypeError, SyntaxError, RecursionError, MemoryError):
            return original
        if (not isinstance(data, dict) or len(data) > 50
                or not all(isinstance(k, str)
                           and isinstance(v, (str, int, float, type(None)))
                           for k, v in data.items())):
            return original
        lines = []
        for key, value in data.items():
            if key in GEO_LABELS and value == GEO_UNAVAILABLE:
                value = '当前地理位置数据库未提供此字段。'
            lines.append(f'{GEO_LABELS.get(key, key)}：{value}')
        return '\n'.join(lines)


def load_catalog(directory, root):
    """Load an administrator-installed dictionary; corrupt files fail closed."""
    try:
        data = json.loads(
            (directory / 'mobsf_zh_scorecard.json').read_text('utf-8'))
        return ScorecardCatalog(data, source_hashes(root))
    except (OSError, ValueError, TypeError, AttributeError, KeyError):
        return ScorecardCatalog({}, {})


def report_catalog(data, root):
    """Use the same exact-match catalog for reviewed static report wording."""
    origins = data['origins']
    hashes = source_hashes(
        root, {name: item['path'] for name, item in origins.items()})
    catalog_data = dict(data, origins={name: item['sha256']
                                       for name, item in origins.items()})
    return ScorecardCatalog(catalog_data, hashes)
