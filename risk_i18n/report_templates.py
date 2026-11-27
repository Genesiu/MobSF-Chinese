"""Adapt only risk display slots of the upstream report templates."""
import re

from report_labels import translate_labels


REPORT_TEMPLATES = (
    'static_analysis/ios_binary_analysis.html',
    'static_analysis/ios_source_analysis.html',
    'pdf/ios_report.html',
    'static_analysis/windows_binary_analysis.html',
    'pdf/windows_report.html',
)
MARKER = '{# mobsf-zh-report-overlay:1 #}'
NETWORK = 'for item in network_security.network_findings'
CERT = 'for find in certificate_analysis.certificate_findings'
ATS = 'for findings in ats_analysis.ats_findings'
IOS_BINARY = 'for issue, details in binary_analysis.findings.items'
CODE = 'for rule, details in code_analysis.findings.items'
FIREBASE = 'for find in firebase_urls'
FILE = 'for item in file_analysis'
WINDOWS = ('for result in binary_analysis', 'for warn in binary_warnings')

SLOTS = {
    NETWORK: {'item.description': 'network'},
    CERT: {'find.1': 'cert', 'find.2': 'cert'},
    ATS: {'findings.issue': 'ats', 'findings.description': 'ats'},
    IOS_BINARY: {'issue': 'ipa-title',
                 'details|key:"detailed_desc"': 'ipa-description'},
    FIREBASE: {'find.title': 'firebase', 'find.description': 'firebase'},
    FILE: {'item.issue': 'file', 'item|key:"finding"': 'file'},
    WINDOWS[0]: {'result.rule_id': 'windows', 'result.desc': 'windows',
                 'result.status': 'status'},
    WINDOWS[1]: {'warn.rule_id': 'windows', 'warn.desc': 'windows',
                 'warn.status': 'status'},
}
LABELS = {
    'ISSUE': '风险漏洞项', 'DESCRIPTION': '风险描述与详情',
    'SEVERITY': '风险等级', 'TITLE': '风险漏洞项', 'OPTIONS': '操作',
    'NO': '序号', 'SCOPE': '适用范围', 'FILES': '相关文件',
    'STANDARDS': '安全标准', 'STATUS': '状态', 'INFO': '附加信息',
    'CHECK': '检查项', 'RESULT': '检查结果',
    'NETWORK SECURITY': '网络安全', 'CERTIFICATE ANALYSIS': '证书安全分析',
    'FILE ANALYSIS': '文件分析', 'CODE ANALYSIS': '代码安全分析',
    'MANIFEST ANALYSIS': '清单安全分析',
    'APP TRANSPORT SECURITY (ATS)': '应用传输安全（ATS）',
    'BINARY CODE ANALYSIS': '二进制代码分析',
    'IPA BINARY ANALYSIS': 'IPA 二进制安全分析',
    'APPX BINARY ANALYSIS': 'APPX 二进制安全分析',
    'SHARED LIBRARY BINARY ANALYSIS': '共享库安全分析',
    'DYNAMIC LIBRARY & FRAMEWORK BINARY ANALYSIS': '动态库与框架安全分析',
    'STATIC LIBRARY BINARY ANALYSIS': '静态库安全分析',
    'FIREBASE ANALYSIS': 'Firebase 配置分析', 'APPLICATION PERMISSIONS': '应用权限',
    'high': '高危', 'warning': '警告', 'info': '提示',
    'secure': '安全', 'good': '安全',
}
ANDROID_PDF_FILES = """
{% if app_type not in 'so' and file_analysis %}
<h2>文件安全分析</h2>
<table class="basic">
<thead><tr><th>风险漏洞项</th><th>风险描述与详情</th></tr></thead>
<tbody>
{% for item in file_analysis %}
{% if item.finding %}
<tr><td>{{ item.finding|zh_report:"file" }}</td>
<td>{% for path in item.files %}{{ path }}<br/>{% endfor %}</td></tr>
{% endif %}
{% endfor %}
</tbody>
</table>
{% endif %}
"""


def pdf_display(text, template):
    """Keep translated PDF risk tables legible at print widths."""
    if not template.startswith('pdf/'):
        return text
    for source, target in {
        'MobSF Static Analysis Report': 'MobSF 静态分析报告',
        'ANDROID STATIC ANALYSIS REPORT': 'Android 静态分析报告',
        'IOS STATIC ANALYSIS REPORT': 'iOS 静态分析报告',
        'IPA STATIC ANALYSIS REPORT': 'iOS 静态分析报告',
        'WINDOWS STATIC ANALYSIS REPORT': 'Windows 静态分析报告',
        'PERMISSIONS': '权限', 'PERMISSION': '权限',
        'REASON IN MANIFEST': '应用声明的用途', 'PROTECTION': '防护项',
        'SHARED OBJECT': '共享库', 'STACK CANARY': '栈保护',
        'SYMBOLS STRIPPED': '符号剥离',
    }.items():
        text = re.sub(r'(?<=>)(\s*)' + re.escape(source) + r'(\s*)(?=<)',
                      lambda m, zh=target: m[1] + zh + m[2], text)
    text = text.replace('{% endif %}BINARY CODE ANALYSIS</h2>',
                        '{% endif %}二进制代码分析</h2>')
    if template == 'pdf/android_report.html':
        anchor = '共享库安全分析</h2>'
        start, separator, after = text.partition(anchor)
        if separator and 'data-mobsf-zh-elf' not in after:
            layout = ('<table class="basic" data-mobsf-zh-elf="1" '
                      'style="width:100%;table-layout:fixed;word-wrap:break-word">'
                      '<colgroup><col style="width:4%"><col style="width:12%">'
                      '<col span="8" style="width:10.5%"></colgroup>')
            after = after.replace('<table class="basic">', layout, 1)
            after = after.replace('<td width="20%">{{so.name | relative_path}}',
                                  '<td>{{so.name | relative_path}}', 1)
            text = start + separator + after
    return text


def find_filter(expression, loop, ios):
    """Recognize a finding field by its template loop or known object shape."""
    normalized = re.sub(r'\s*\|\s*', '|', expression)
    if ios and normalized == 'details.metadata.description':
        if loop == CODE:
            return '|zh_report_rule:rule'
        if loop == 'for rule, details in ios_api.items':
            return '|zh_report_rule:rule'
    if (not ios and loop == 'for rule, details in android_api.items'
            and normalized == 'details.metadata.description'):
        return '|zh_android_api:rule'
    if re.fullmatch(r'(macho_analysis|dy|frm|so)\.\w+\.description', normalized):
        section = 'elf' if normalized.startswith('so.') else 'macho'
        return '|zh_report:"' + section + '"'
    if loop == 'for perm, desc in permissions.items':
        if ios and normalized == 'desc.info':
            return '|zh_ios_permission:perm'
        if not ios and normalized in ('desc.info', 'desc.description'):
            return '|zh_android_permission:perm'
    section = SLOTS.get(loop, {}).get(normalized)
    return '|zh_report:"' + section + '"' if section else ''


def patch_report(text, template):
    """Apply scoped display filters while preserving actions and evidence links."""
    if MARKER in text:
        # Revisit unpatched slots when expanding an existing overlay.
        result, _ = patch_fields(text, template)
        return pdf_display(translate_labels(result), template)
    result, changed = patch_fields(text, template)
    ios = '/ios_' in template
    windows = '/windows_' in template
    required = {ATS, FIREBASE} if ios else {
        WINDOWS[0]} if windows else {NETWORK}
    if 'android_source' not in template and not ios and not windows:
        required.add(CERT)
    if not required.issubset(changed):
        raise ValueError(
            f'Unsupported report structure: {template}, {required - changed}')
    if template == 'pdf/android_report.html':
        anchor = '{% if behaviour %}'
        if anchor not in result:
            raise ValueError(
                'Android PDF is missing the file analysis insertion anchor')
        result = result.replace(anchor, ANDROID_PDF_FILES + anchor, 1)
    # Restrict labels to complete text nodes. Do not alter IDs, conditions, or JS.
    for source, target in LABELS.items():
        result = re.sub(r'(?<=>)(\s*)' + re.escape(source) + r'(\s*)(?=<)',
                        lambda m, zh=target: m[1] + zh + m[2], result)
    result = pdf_display(translate_labels(result), template)
    if '{% load mobsf_zh %}' in result:
        return result.replace('{% load mobsf_zh %}',
                              '{% load mobsf_zh %}\n' + MARKER, 1)
    anchor = '{% load static %}'
    if anchor not in result:
        raise ValueError(f'Missing report template library anchor: {template}')
    return result.replace(anchor, anchor + '\n{% load mobsf_zh %}\n' + MARKER, 1)


def patch_fields(text, template):
    """Replace recognized expressions only in their finding display scope."""
    parts = re.split(r'({#.*?#}|{%.*?%}|{{.*?}})', text, flags=re.S)
    loops = []
    changed = set()
    ios = '/ios_' in template
    for index, token in enumerate(parts):
        if token.startswith('{%'):
            command = re.sub(r',\s*', ', ', ' '.join(token[2:-2].split()))
            if command.startswith('for '):
                loops.append(command)
            elif command == 'endfor' and loops:
                loops.pop()
        elif token.startswith('{{'):
            expression = token[2:-2].strip()
            loop = loops[-1] if loops else ''
            suffix = find_filter(expression, loop, ios)
            # The repeated issue in the suppression control is its existing identifier.
            if expression == 'issue' and 'Suppress the rule' in parts[index - 1]:
                continue
            if suffix:
                parts[index] = '{{ ' + expression + suffix + ' }}'
                changed.add(loop)
    return ''.join(parts), changed
