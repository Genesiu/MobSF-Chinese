"""Translate reviewed rule text without changing findings or trusting HTML."""
import hashlib
import re


MAX_TEXT = 65536
ZH_SLOTS = re.compile(r'\{([0-9]+)\}')


def fingerprint(value):
    """Fingerprint exact upstream wording, including its placeholders."""
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def split_source(source):
    """Split printf placeholders; escaped percent signs stay literal."""
    literals = ['']
    for part in re.split(r'(%s|%d|%%)', source):
        if part in ('%s', '%d'):
            literals.append('')
        else:
            literals[-1] += '%' if part == '%%' else part
    return literals


def extract_slots(value, source):
    """Match a rendered template with a forward-only, bounded scan."""
    literals = split_source(source)
    if len(value) > MAX_TEXT or not value.startswith(literals[0]):
        return None
    if len(literals) == 1:
        return [] if value == literals[0] else None
    position = len(literals[0])
    values = []
    for index, delimiter in enumerate(literals[1:], 1):
        if index == len(literals) - 1:
            if delimiter and not value.endswith(delimiter):
                return None
            end = len(value) - len(delimiter)
            if end < position:
                return None
        else:
            if not delimiter:
                return None
            end = value.find(delimiter, position)
            if end < 0:
                return None
        values.append(value[position:end])
        position = end + len(delimiter)
    reconstructed = literals[0] + ''.join(
        argument + literal for argument, literal in zip(values, literals[1:]))
    return values if reconstructed == value else None


class Catalog:
    """Enable only reviewed fields whose current upstream source still matches."""

    def __init__(self, data, current_sources):
        self.entries = {}
        self.missing = []
        self.changed = []
        if not isinstance(data, dict) or data.get('schema_version') != 1:
            return
        for domain, rules in current_sources.items():
            for rule, fields in rules.items():
                reviewed = data.get('rules', {}).get(domain, {}).get(rule, {})
                if not reviewed:
                    self.missing.append((domain, rule))
                for field, source in fields.items():
                    entry = reviewed.get(field)
                    if not isinstance(source, str) or not isinstance(entry, dict):
                        continue
                    if (entry.get('source') != source
                            or entry.get('sha256') != fingerprint(source)):
                        self.changed.append((domain, rule, field))
                        continue
                    text = entry.get('text')
                    if not isinstance(text, str):
                        continue
                    slots = len(split_source(source)) - 1
                    references = {int(n) for n in ZH_SLOTS.findall(text or '')}
                    ignored = set(entry.get('ignored_slots', []))
                    allowed_ignored = {0} if source.startswith(
                        'A%s %s') else set()
                    if (not ignored.issubset(allowed_ignored)
                            or references & ignored
                            or references | ignored != set(range(slots))):
                        continue
                    self.entries[domain, rule, field] = entry

    def translate(self, domain, rule, field, original):
        """Return plain text. Unknown, altered, or malformed input stays English."""
        if not isinstance(original, str):
            return original
        entry = self.entries.get((domain, rule, field))
        if entry is None:
            return original
        values = extract_slots(original, entry['source'])
        if values is None:
            return original
        return ZH_SLOTS.sub(lambda m: values[int(m.group(1))], entry['text'])
