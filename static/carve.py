"""Carve structure out of a raw dump (process memory, .so, or any blob).

Pairs with host/memdump.py: when a hook did not cover something, scan the raw
bytes offline for ASCII/UTF-16 strings, secret-looking literals, and embedded
executables (PE/ELF/DEX) that can be extracted and analysed separately.

  python static/carve.py dump.bin --min-len 6 --secrets --out carved
  python static/carve.py segments/*.bin --extract --out carved
"""
import argparse
import hashlib
import json
import re
from pathlib import Path
import sys

SECRET_PAT = re.compile(
    rb"(https?://[^\s\"']{4,}|api[_-]?key|secret|token|password|passwd|"
    rb"access[_-]?key|private[_-]?key|BEGIN [A-Z ]*PRIVATE KEY|bearer|authorization|"
    rb"AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,})", re.I)

# name, magic, how to find the end (None = carve a bounded window only).
MAGICS = [
    ('pe', b'MZ', None),
    ('elf', b'\x7fELF', None),
    ('dex', b'dex\n', None),
    ('zip', b'PK\x03\x04', None),
]


def ascii_strings(data, min_len):
    for match in re.finditer(rb'[\x20-\x7e]{%d,}' % min_len, data):
        yield match.start(), match.group().decode('latin-1')


def utf16_strings(data, min_len):
    pattern = rb'(?:[\x20-\x7e]\x00){%d,}' % min_len
    for match in re.finditer(pattern, data):
        yield match.start(), match.group().decode('utf-16-le', 'replace')


def find_embedded(data):
    hits = []
    for name, magic, _ in MAGICS:
        start = 0
        while True:
            idx = data.find(magic, start)
            if idx < 0:
                break
            # A PE's "MZ" must have a plausible e_lfanew pointing at "PE\0\0".
            if name == 'pe':
                if idx + 0x40 <= len(data):
                    off = int.from_bytes(data[idx + 0x3c:idx + 0x40], 'little')
                    if not (0 < off < 0x1000 and data[idx + off:idx + off + 4] == b'PE\x00\x00'):
                        start = idx + 1
                        continue
                else:
                    break
            hits.append({'type': name, 'offset': hex(idx)})
            start = idx + 1
    return hits


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('inputs', nargs='+', type=Path, help='Dump file(s) to carve')
    parser.add_argument('--min-len', type=int, default=6)
    parser.add_argument('--secrets', action='store_true', help='Only keep secret-looking strings')
    parser.add_argument('--grep', help='Keep strings matching this regex (case-insensitive)')
    parser.add_argument('--extract', action='store_true', help='Write embedded PE/ELF/DEX/ZIP to disk')
    parser.add_argument('--extract-max', type=lambda v: int(v, 0), default=64 * 1024 * 1024,
                        help='Max bytes to carve per embedded image when --extract')
    parser.add_argument('--out', type=Path, required=True, help='Output directory')
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    grep = re.compile(args.grep.encode(), re.I) if args.grep else None
    report = {'inputs': [], 'strings': [], 'embedded': []}

    for path in args.inputs:
        if not path.is_file():
            print('[skip] not a file:', path)
            continue
        data = path.read_bytes()
        report['inputs'].append({'path': str(path.resolve()), 'size': len(data),
                                 'sha256': hashlib.sha256(data).hexdigest()})
        found = []
        for offset, text in list(ascii_strings(data, args.min_len)) + list(utf16_strings(data, args.min_len)):
            raw = text.encode('latin-1', 'replace')
            if args.secrets and not SECRET_PAT.search(raw):
                continue
            if grep and not grep.search(raw):
                continue
            found.append({'file': path.name, 'offset': hex(offset), 'text': text[:400]})
        report['strings'].extend(found)
        for hit in find_embedded(data):
            hit['file'] = path.name
            if args.extract:
                start = int(hit['offset'], 0)
                blob = data[start:start + args.extract_max]
                name = '%s_%s_%s.bin' % (path.stem, hit['type'], hit['offset'])
                (args.out / name).write_bytes(blob)
                hit['extracted'] = name
            report['embedded'].append(hit)

    report['counts'] = {'strings': len(report['strings']), 'embedded': len(report['embedded'])}
    (args.out / 'carve-report.json').write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(json.dumps(report['counts']))
    for hit in report['embedded'][:40]:
        print('  embedded %-4s @ %s in %s%s'
              % (hit['type'], hit['offset'], hit['file'],
                 ' -> ' + hit['extracted'] if hit.get('extracted') else ''))
    print('Report:', args.out / 'carve-report.json')
    return 0


if __name__ == '__main__':
    sys.exit(main())
