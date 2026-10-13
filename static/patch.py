"""Patch bytes in an extracted libil2cpp.so (never in place).

A more thorough alternative to external hooks: bake changes (added logging
stubs, NOP'd anti-debug checks, flipped branch conditions) directly into the
runtime library, then repackage the APK and reinstall. Use it only on builds
you own or are authorized to modify.

Each patch is `LOCATION=NEWBYTES` or `LOCATION=OLDBYTES:NEWBYTES`. LOCATION is
`rva:0x1A2B3C` (virtual address, mapped through ELF program headers) or
`off:0x1234` (raw file offset). When OLDBYTES is given it is verified first, so
a stale RVA cannot silently corrupt the file.

  python static/patch.py --binary libil2cpp.so --out libil2cpp.patched.so \
      --patch rva:0x1A2B3C=1f2003d5           # arm64 NOP
  python static/patch.py --binary libil2cpp.so --out patched.so \
      --patch "off:0x9F0=00008052:200080d2"   # verify-then-write
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

import _elf


def resolve_offset(info, location):
    kind, _, value = location.partition(':')
    number = int(value, 0)
    if kind == 'off':
        return number
    if kind == 'rva':
        return _elf.rva_to_offset(info, number)
    raise ValueError('location must start with rva: or off:, got %r' % location)


def parse_patch(spec):
    location, _, byte_spec = spec.partition('=')
    if not byte_spec:
        raise ValueError('patch %r missing =NEWBYTES' % spec)
    if ':' in byte_spec and byte_spec.count(':') == 1 and not byte_spec.startswith(('0x',)):
        old_hex, new_hex = byte_spec.split(':')
    else:
        old_hex, new_hex = None, byte_spec
    clean = lambda h: bytes.fromhex(h.lower().replace('0x', '').replace(' ', ''))
    return location, (clean(old_hex) if old_hex else None), clean(new_hex)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path, help='New file; refuses to overwrite')
    parser.add_argument('--patch', action='append', required=True,
                        help='LOCATION=NEWBYTES or LOCATION=OLDBYTES:NEWBYTES')
    args = parser.parse_args()

    if not args.binary.is_file():
        parser.error('Binary not found: %s' % args.binary)
    if args.out.exists():
        parser.error('Output exists; choose a new --out path to keep the original intact')
    data = bytearray(args.binary.read_bytes())
    info = None
    manifest = {'binary': str(args.binary.resolve()), 'out': str(args.out.resolve()),
                'original_sha256': hashlib.sha256(data).hexdigest(), 'patches': []}
    try:
        for spec in args.patch:
            location, old, new = parse_patch(spec)
            if location.startswith('rva:') and info is None:
                info = _elf.load_segments(bytes(data))
            offset = resolve_offset(info, location) if location.startswith('rva:') \
                else resolve_offset(None, location)
            current = bytes(data[offset:offset + len(new)])
            if old is not None and current != old:
                parser.error('Verify failed at %s: file has %s, expected %s'
                             % (location, current.hex(), old.hex()))
            data[offset:offset + len(new)] = new
            manifest['patches'].append({'location': location, 'file_offset': hex(offset),
                                        'before': current.hex(), 'after': new.hex(),
                                        'verified': old is not None})
    except (ValueError, _elf.ElfError) as exc:
        parser.error(str(exc))

    args.out.write_bytes(data)
    manifest['patched_sha256'] = hashlib.sha256(data).hexdigest()
    report = args.out.with_suffix(args.out.suffix + '.patch.json')
    report.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    for entry in manifest['patches']:
        print('patched %s @ %s: %s -> %s' % (entry['location'], entry['file_offset'],
                                             entry['before'], entry['after']))
    print('Output:', args.out)
    print('Manifest:', report)
    print('Next: repackage the APK with the patched .so, re-sign, reinstall.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
