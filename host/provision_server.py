#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Download a frida-server matching the installed frida and push it to a device.

Automates README section 1.2: pick the frida-server whose version equals the
local frida Python package (they must match), fetch the right ABI build from
GitHub releases, push it, chmod, and optionally rename + start it on a custom
port to dodge the most naive frida detection.

  python host/provision_server.py --device 127.0.0.1:7555
  python host/provision_server.py --device DEVICE --name vendor_thermal --port 47000 --start
"""
import argparse
import lzma
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ABI_MAP = {'arm64-v8a': 'arm64', 'armeabi-v7a': 'arm', 'x86_64': 'x86_64', 'x86': 'x86'}


def frida_version():
    import importlib.metadata
    return importlib.metadata.version('frida')


def adb(serial, args, **kw):
    base = ['adb'] + (['-s', serial] if serial else [])
    return subprocess.run(base + args, **kw)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--device', help='ADB serial')
    parser.add_argument('--version', help='frida-server version (default: installed frida package)')
    parser.add_argument('--abi', help='Device ABI (default: auto-detect via getprop)')
    parser.add_argument('--name', default='frida-server', help='Remote file name (rename to evade scans)')
    parser.add_argument('--port', type=int, help='Custom port for -D start (evade default 27042)')
    parser.add_argument('--remote-dir', default='/data/local/tmp')
    parser.add_argument('--start', action='store_true', help='Start it with su after pushing')
    parser.add_argument('--setenforce0', action='store_true', help='setenforce 0 before starting (some ROMs)')
    args = parser.parse_args()

    if not shutil.which('adb'):
        parser.error('adb not found on PATH')
    try:
        version = args.version or frida_version()
    except Exception:
        parser.error('frida not installed; pip install frida, or pass --version')

    abi = args.abi
    if not abi:
        result = adb(args.device, ['shell', 'getprop', 'ro.product.cpu.abi'],
                     capture_output=True, text=True, encoding='utf-8', errors='replace')
        abi = (result.stdout or '').strip()
    arch = ABI_MAP.get(abi)
    if not arch:
        parser.error('Unknown/undetected ABI %r; pass --abi arm64-v8a|armeabi-v7a|x86_64|x86' % abi)

    asset = 'frida-server-%s-android-%s' % (version, arch)
    url = 'https://github.com/frida/frida/releases/download/%s/%s.xz' % (version, asset)
    cache = ROOT / 'tools' / 'frida-server'
    cache.mkdir(parents=True, exist_ok=True)
    xz_path, bin_path = cache / (asset + '.xz'), cache / asset
    if not bin_path.is_file():
        print('Downloading:', url, flush=True)
        try:
            urllib.request.urlretrieve(url, xz_path)
        except Exception as exc:
            parser.error('Download failed (%s). Check that frida-server %s exists for %s.'
                         % (exc, version, arch))
        with lzma.open(xz_path) as src, open(bin_path, 'wb') as dst:
            shutil.copyfileobj(src, dst)
    print('Local binary:', bin_path)

    remote = '%s/%s' % (args.remote_dir.rstrip('/'), args.name)
    if adb(args.device, ['push', str(bin_path), remote]).returncode:
        parser.error('adb push failed')
    adb(args.device, ['shell', 'chmod', '755', remote])
    print('Pushed to', remote)

    if args.setenforce0:
        adb(args.device, ['shell', 'su', '-c', 'setenforce 0'])
    if args.start:
        cmd = remote + (' -l 0.0.0.0:%d' % args.port if args.port else '') + ' -D &'
        adb(args.device, ['shell', 'su', '-c', cmd])
        print('Started %s%s' % (remote, ' on port %d' % args.port if args.port else ''))
    else:
        hint = remote + (' -l 0.0.0.0:%d' % args.port if args.port else '') + ' -D &'
        print('Start it manually:  adb shell "su -c \'%s\'"' % hint)
    print('Verify:  frida-ps -U   (or -H 127.0.0.1:%d after adb forward)' % (args.port or 27042))
    return 0


if __name__ == '__main__':
    sys.exit(main())
