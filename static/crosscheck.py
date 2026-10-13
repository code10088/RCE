"""Compare runtime method RVAs with Il2CppDumper ScriptMethod addresses."""
import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path


def load(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def fingerprint(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return {'path': str(path.resolve()), 'sha256': h.hexdigest()}


def compare(static, dynamic, image_base=0):
    index = defaultdict(list)
    for method in static.get('ScriptMethod', []):
        index[int(method['Address']) - image_base].append(method['Name'])
    results = []
    for method in dynamic.get('methods', []):
        raw = method.get('rva')
        try:
            rva = int(str(raw), 0)
        except (ValueError, TypeError):
            results.append({'name': method.get('name'), 'rva': raw, 'status': 'invalid'})
            continue
        results.append({'name': method.get('name'), 'rva': hex(rva),
                        'status': 'address_match' if rva in index else 'unmatched',
                        'static_names': index.get(rva, [])})
    counts = {state: sum(row['status'] == state for row in results)
              for state in ('address_match', 'unmatched', 'invalid')}
    return {'counts': counts, 'methods': results,
            'limitations': 'Address matches are evidence only: shared code and generic methods may have multiple names. Input build identity must be checked separately.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--static', required=True, type=Path)
    parser.add_argument('--dynamic', required=True, type=Path)
    parser.add_argument('--image-base', default='0x0', help='Subtract only if static Address is a VA')
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    report = compare(load(args.static), load(args.dynamic), int(args.image_base, 0))
    report['inputs'] = [fingerprint(args.static), fingerprint(args.dynamic)]
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report['counts']))
    print('Report:', args.out)


if __name__ == '__main__':
    main()
