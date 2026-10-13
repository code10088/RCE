#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dump live process memory ranges with Frida, for offline carving.

A forensic backstop for whatever the IL2CPP/hook paths did not cover: snapshot
readable memory (optionally just one module, or ranges above a size), then run
static/carve.py over the segments to recover strings and embedded images.

  python host/memdump.py --attach 12345 --out out/memdump
  python host/memdump.py --pkg com.your.game --module libil2cpp.so --out out/dump
  # then:  python tool.py carve out/dump/segments/*.bin --extract --out out/carved
"""
import argparse
import datetime
import hashlib
import json
import os
import sys

try:
    import frida
except ImportError:
    print('[!] 缺少 frida：pip install frida frida-tools')
    sys.exit(1)

AGENT = r"""
rpc.exports = {
  ranges: function (prot, moduleName) {
    var all = moduleName
      ? Process.getModuleByName(moduleName).enumerateRanges(prot)
      : Process.enumerateRanges(prot);
    return all.map(function (r) {
      return { base: r.base.toString(), size: r.size,
               prot: r.protection, file: r.file ? r.file.path : '' };
    });
  },
  read: function (addrStr, size) {
    try { return Memory.readByteArray(ptr(addrStr), size); }
    catch (e) { return null; }
  }
};
"""


def get_device(device_id):
    if device_id:
        return frida.get_device(device_id)
    try:
        return frida.get_usb_device(timeout=5)
    except Exception:
        return frida.get_local_device()


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--pkg', help='Spawn this package')
    parser.add_argument('--attach', type=int, help='Attach to a running pid')
    parser.add_argument('--device', help='Frida device id')
    parser.add_argument('--module', help='Only dump ranges of this module (e.g. libil2cpp.so)')
    parser.add_argument('--prot', default='r--', help="Minimum protection, e.g. 'r--' or 'rw-'")
    parser.add_argument('--min-size', type=lambda v: int(v, 0), default=0)
    parser.add_argument('--max-size', type=lambda v: int(v, 0), default=256 * 1024 * 1024)
    parser.add_argument('--max-total', type=lambda v: int(v, 0), default=1024 * 1024 * 1024)
    parser.add_argument('--chunk', type=lambda v: int(v, 0), default=4 * 1024 * 1024)
    parser.add_argument('--out', required=True, help='Output directory')
    args = parser.parse_args()
    if not args.pkg and not args.attach:
        parser.error('need --pkg or --attach')

    segments_dir = os.path.join(args.out, 'segments')
    os.makedirs(segments_dir, exist_ok=True)
    device = get_device(args.device)
    if args.attach:
        pid, session = args.attach, device.attach(args.attach)
    else:
        pid = device.spawn([args.pkg])
        session = device.attach(pid)
    script = session.create_script(AGENT)
    script.load()
    if args.pkg and not args.attach:
        device.resume(pid)
    api = script.exports_sync if hasattr(script, 'exports_sync') else script.exports

    ranges = api.ranges(args.prot, args.module)
    manifest = {'pid': pid, 'package': args.pkg or '', 'module': args.module or '',
                'prot': args.prot, 'captured': datetime.datetime.now().astimezone().isoformat(),
                'segments': []}
    total = 0
    for item in ranges:
        size = int(item['size'])
        if size < args.min_size or size > args.max_size:
            continue
        if total >= args.max_total:
            print('[*] reached --max-total, stopping')
            break
        base = int(item['base'], 16)
        name = 'seg_%012x_%d.bin' % (base, size)
        path = os.path.join(segments_dir, name)
        digest = hashlib.sha256()
        written = 0
        with open(path, 'wb') as stream:
            offset = 0
            while offset < size and total < args.max_total:
                want = min(args.chunk, size - offset, args.max_total - total)
                blob = api.read(hex(base + offset), want)
                if not blob:
                    break
                stream.write(blob)
                digest.update(blob)
                written += len(blob)
                offset += want
                total += len(blob)
        if written:
            manifest['segments'].append({'base': item['base'], 'size': size, 'written': written,
                                         'prot': item['prot'], 'file': 'segments/' + name,
                                         'backing': item['file'], 'sha256': digest.hexdigest()})
            print('[+] %s  %#x  %d bytes  %s' % (item['prot'], base, written, item['file'] or ''))
        else:
            os.remove(path)

    manifest['total_bytes'] = total
    with open(os.path.join(args.out, 'memdump-manifest.json'), 'w', encoding='utf-8') as stream:
        json.dump(manifest, stream, indent=2, ensure_ascii=False)
        stream.write('\n')
    try:
        session.detach()
    except Exception:
        pass
    print('[*] %d segments, %d bytes. Output: %s' % (len(manifest['segments']), total, args.out))
    print('[*] Next: python tool.py carve %s --extract --out <dir>' % os.path.join(segments_dir, '*.bin'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
