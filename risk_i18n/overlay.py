"""Check, install, or roll back the optional presentation-only risk overlay."""
import argparse
import ast
import hashlib
import json
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml

from engine import Catalog

from report_templates import REPORT_TEMPLATES, patch_report

from scorecard import ScorecardCatalog, report_catalog, source_hashes


TEMPLATES = (
    'static_analysis/android_binary_analysis.html',
    'static_analysis/android_source_analysis.html',
    'pdf/android_report.html',
    'static_analysis/appsec_dashboard.html',
)
MARKER = '{# mobsf-zh-risk-overlay:1 #}'
BUNDLE = Path(__file__).resolve().parent
MODULES = {
    'mobsf_zh.py': 'mobsf_zh.py',
    'mobsf_zh_engine.py': 'engine.py',
    'mobsf_zh_catalog.json': 'catalog.zh-CN.json',
    'mobsf_zh_scorecard.py': 'scorecard.py',
    'mobsf_zh_scorecard.json': 'scorecard.zh-CN.json',
    'mobsf_zh_report.json': 'report.zh-CN.json',
}


def patch_scorecard(text):
    """Adapt the upstream scorecard while preserving all calculations and IDs."""
    marker = '{# mobsf-zh-scorecard-overlay:1 #}'
    if marker in text:
        if (text.count('|zh_score_title') != 5
                or text.count('|zh_score_description') != 5
                or text.count('|zh_section') != 5):
            raise ValueError('Incomplete scorecard overlay')
        return text
    counts = {}
    for field, replacement in (
        ('title', '{{ item|zh_score_title }}'),
        ('description', '{{ item|zh_score_description }}'),
        ('section', '{{ item.section|zh_section }}'),
    ):
        suffix = r'\s*\|\s*upper' if field == 'section' else ''
        pattern = r'{{\s*item\.' + field + suffix + r'\s*}}'
        text, counts[field] = re.subn(pattern, replacement, text)
    if counts != {'title': 5, 'description': 5, 'section': 5}:
        raise ValueError(f'Unsupported scorecard template structure: {counts}')
    labels = {
        'MobSF Application Security Scorecard generated for': 'MobSF 应用安全计分卡，分析对象：',
        'MobSF Application Security Scorecard': 'MobSF 应用安全计分卡',
        'Severity Distribution (%)': '风险等级分布（%）',
        'User/Device Trackers': '用户与设备追踪组件',
        'Security Score': '安全评分', 'Risk Rating': '风险评级',
        'Privacy Risk': '隐私风险', 'Not Scanned': '未扫描',
        'Findings': '安全检查结果', 'Grade': '安全等级',
        'Need to Investigate': '需要进一步核查', 'Hotspot': '待核查项',
        'need to investigate': '需要进一步核查',
        'Critical Risk': '严重风险', 'High Risk': '高风险',
        'Medium Risk': '中风险', 'Low Risk': '低风险',
    }
    # These exact literals are reviewed template/UI strings, never scan values.
    for source, translated in labels.items():
        if source not in text:
            raise ValueError(f'Missing scorecard label: {source}')
        text = text.replace(source, translated)
    text = text.replace('{% else %}hotspot{% endif %}',
                        '{% else %}待核查项{% endif %}')
    for source, translated in (('High', '高危'), ('Medium', '中危'),
                               ('Info', '提示'), ('Secure', '安全'),
                               ('high', '高危'), ('medium', '中危'),
                               ('info', '提示'), ('secure', '安全')):
        text = text.replace('>' + source + '<', '>' + translated + '<')
        text = text.replace('`' + source + '`', '`' + translated + '`')
    anchor = '{% load static %}'
    if anchor not in text:
        raise ValueError('Missing scorecard template library anchor')
    script_anchor = '    function dynamic_loader(){'
    if script_anchor in text:
        text = text.replace(
            script_anchor,
            "    document.title = '应用安全计分卡';\n"
            "    document.documentElement.lang = 'zh-CN';\n" + script_anchor, 1)
    return text.replace(anchor, anchor + '\n{% load mobsf_zh %}\n' + marker, 1)


def digest(value):
    """Hash installed bytes for conflict detection and safe rollback."""
    return hashlib.sha256(value).hexdigest()


def safe_path(root, relative):
    """Reject symbolic links and paths outside the administrator-selected root."""
    path = root / relative
    path.resolve().relative_to(root.resolve())
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError(f'Refusing symbolic link: {part}')
        if part == root:
            break
    return path


def patch_template(text):
    """Change display expressions only within the two reviewed finding loops."""
    if MARKER in text:
        if ('|zh_code:rule' not in text
                or '|zh_manifest_title' not in text
                or '|zh_manifest_description' not in text):
            raise ValueError(
                'Incomplete existing overlay; restore before applying')
        return text
    stack = []
    counts = {'code': 0, 'title': 0, 'description': 0}
    pieces = re.split(r'({%.*?%}|{{.*?}})', text, flags=re.S)
    for index, token in enumerate(pieces):
        if token.startswith('{%'):
            command = token[2:-2].strip()
            if command.startswith('for '):
                stack.append(command)
            elif command == 'endfor':
                if not stack:
                    raise ValueError('Unbalanced template loop')
                stack.pop()
        elif token.startswith('{{') and stack:
            expression = token[2:-2].strip()
            if ('for rule, details in code_analysis.findings.items' in stack
                    and expression == 'details.metadata.description'):
                pieces[index] = '{{ details.metadata.description|zh_code:rule }}'
                counts['code'] += 1
            if 'for item in manifest_analysis.manifest_findings' in stack:
                for field in ('title', 'description'):
                    if expression in (f'item.{field}', f'item|key:"{field}"'):
                        pieces[index] = '{{ item|zh_manifest_' + field + ' }}'
                        counts[field] += 1
    if stack or counts != {'code': 2, 'title': 1, 'description': 1}:
        raise ValueError(f'Unsupported template structure: {counts}')
    result = ''.join(pieces)
    static = re.search(r'{%\s*load static\s*%}', result)
    if not static:
        raise ValueError('Missing static load anchor')
    result = (result[:static.end()] + '\n{% load mobsf_zh %}\n' + MARKER
              + result[static.end():])
    # Exact text nodes only: no JavaScript, IDs, URLs, or scan data replacements.
    labels = {
        'ISSUE': '风险漏洞项', 'DESCRIPTION': '风险描述与详情',
        'SEVERITY': '风险等级', 'OPTIONS': '操作', 'NO': '序号',
        'MANIFEST ANALYSIS': '清单安全分析', 'CODE ANALYSIS': '代码安全分析',
    }
    for english, chinese in labels.items():
        result = re.sub(r'(?<=>)(\s*)' + re.escape(english) + r'(\s*)(?=<)',
                        lambda m, label=chinese: m[1] + label + m[2], result)
    return result


def literal_assignment(path, name):
    """Read static upstream dictionaries without importing application startup."""
    tree = ast.parse(path.read_text('utf-8'))
    for node in tree.body:
        if (isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == name
                        for t in node.targets)):
            return ast.literal_eval(node.value)
    raise ValueError(f'Missing upstream assignment: {name}')


def compatibility(root):
    """Gate translations by exact current rule text, rather than version alone."""
    android = root / 'mobsf/StaticAnalyzer/views/android'
    code = yaml.safe_load(
        (android / 'rules/android_rules.yaml').read_text('utf-8'))
    manifest = literal_assignment(android / 'kb/android_manifest_desc.py',
                                  'MANIFEST_DESC')
    sources = {
        'code': {r['id']: {'description': r['message']} for r in code},
        'manifest': {k: {f: v[f] for f in ('title', 'description')}
                     for k, v in manifest.items()},
    }
    data = json.loads((BUNDLE / 'catalog.zh-CN.json').read_text('utf-8'))
    catalog = Catalog(data, sources)
    version = literal_assignment(root / 'mobsf/MobSF/init.py', 'VERSION')
    score_data = json.loads(
        (BUNDLE / 'scorecard.zh-CN.json').read_text('utf-8'))
    score = ScorecardCatalog(score_data, source_hashes(root))
    report_data = json.loads((BUNDLE / 'report.zh-CN.json').read_text('utf-8'))
    reports = report_catalog(report_data, root)
    return {'version': version, 'tested_version': version in data['tested_versions'],
            'enabled_fields': len(catalog.entries),
            'missing_rules': catalog.missing, 'changed_fields': catalog.changed,
            'scorecard_enabled_patterns': len(score.entries),
            'report_enabled_patterns': len(reports.entries),
            'report_changed_origins': sorted(
                set(report_data['origins']) - reports.active),
            'scorecard_changed_origins': sorted(
                set(score_data['origins']) - score.active)}


def planned_files(root):
    """Preflight every adapter before writing any application file."""
    files = {}
    for template in TEMPLATES + REPORT_TEMPLATES:
        relative = 'mobsf/templates/' + template
        path = safe_path(root, relative)
        contents = path.read_text('utf-8')
        if template.endswith('appsec_dashboard.html'):
            contents = patch_scorecard(contents)
        else:
            if template in TEMPLATES:
                contents = patch_template(contents)
            contents = patch_report(contents, template)
        files[relative] = contents.encode('utf-8')
    prefix = 'mobsf/StaticAnalyzer/templatetags/'
    initializer = safe_path(root, prefix + '__init__.py')
    if not initializer.exists():
        files[prefix + '__init__.py'] = b'"""MobSF optional template libraries."""\n'
    for destination, source in MODULES.items():
        relative = prefix + destination
        safe_path(root, relative)
        files[relative] = (BUNDLE / source).read_bytes()
    return files


def atomic_write(path, content):
    """Replace one file atomically, keeping existing permissions and ownership."""
    path.parent.mkdir(parents=True, exist_ok=True)
    previous = path.stat() if path.exists() else None
    handle, name = tempfile.mkstemp(dir=path.parent, prefix='.mobsf-zh-')
    try:
        with os.fdopen(handle, 'wb') as output:
            output.write(content)
        os.chmod(name, previous.st_mode & 0o777 if previous else 0o644)
        if previous and os.geteuid() == 0:
            os.chown(name, previous.st_uid, previous.st_gid)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def restore(root, backup, check=True):
    """Restore only files still matching this install; preserve later edits."""
    manifest = json.loads((backup / 'manifest.json').read_text('utf-8'))
    for relative, entry in manifest.items():
        target = safe_path(root, relative)
        if (check and (not target.exists()
                       or digest(target.read_bytes()) != entry['installed'])):
            raise ValueError(f'File changed after install: {relative}')
    for relative, entry in manifest.items():
        target = safe_path(root, relative)
        if entry['existed']:
            atomic_write(target, safe_path(backup, relative).read_bytes())
        else:
            if target.exists():
                target.unlink()


def apply(root, backup_parent):
    """Back up all files, then roll back the complete write set on failure."""
    files = planned_files(root)
    changes = {r: value for r, value in files.items()
               if not (root / r).exists() or (root / r).read_bytes() != value}
    if not changes:
        return None
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    backup = backup_parent / stamp
    backup.mkdir(parents=True, exist_ok=False)
    manifest = {}
    for relative, value in changes.items():
        target = safe_path(root, relative)
        existed = target.exists()
        manifest[relative] = {'existed': existed, 'installed': digest(value)}
        if existed:
            destination = safe_path(backup, relative)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, destination)
    (backup / 'manifest.json').write_text(
        json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    try:
        for relative, value in changes.items():
            atomic_write(safe_path(root, relative), value)
    except Exception:
        restore(root, backup, check=False)
        raise
    return str(backup)


def main():
    """Expose read-only checks plus explicit apply and rollback operations."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'apply', 'rollback'))
    parser.add_argument('--app-root', type=Path, default=Path.cwd())
    parser.add_argument('--backup-dir', type=Path,
                        default=Path('/tmp/mobsf-risk-i18n-backups'))
    parser.add_argument('--backup', type=Path)
    parser.add_argument('--expect-version',
                        help='Refuse to apply if the installed MobSF version differs')
    args = parser.parse_args()
    root = args.app_root.resolve()
    if args.action == 'rollback':
        if not args.backup:
            parser.error('rollback requires --backup')
        restore(root, args.backup.resolve())
        print(json.dumps({'restored': str(args.backup)}))
        return
    report = compatibility(root)
    if args.expect_version is not None and args.expect_version != report['version']:
        parser.error(
            f'Expected MobSF {args.expect_version}; found {report["version"]}')
    planned_files(root)
    report['templates_compatible'] = True
    if args.action == 'apply':
        report['backup'] = apply(root, args.backup_dir.resolve())
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
