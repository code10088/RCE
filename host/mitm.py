#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Point an Android device at a host MITM proxy (mitmproxy / Burp) over ADB.

Complementary to the in-process SSL hook in agent/60-nettrace.js: the hook is
better against certificate pinning and needs no CA install, while a proxy gives
a full, replayable protocol log for traffic that is not pinned. This helper only
sets, clears, or shows the device HTTP proxy; it does not install CA certs or
bypass pinning, and it does not launch the proxy itself.

  python host/mitm.py set --device 127.0.0.1:7555 --host 127.0.0.1 --port 8080 --reverse
  python host/mitm.py status --device 127.0.0.1:7555
  python host/mitm.py clear --device 127.0.0.1:7555
"""
import argparse
import shutil
import subprocess
import sys


def adb(args, device, extra):
    base = [args.adb]
    if device:
        base += ['-s', device]
    return subprocess.run(base + extra, capture_output=True, text=True,
                          encoding='utf-8', errors='replace')


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('action', choices=['set', 'clear', 'status'])
    parser.add_argument('--device', help='ADB serial')
    parser.add_argument('--host', default='127.0.0.1', help='Proxy host as seen by the device')
    parser.add_argument('--port', type=int, default=8080)
    parser.add_argument('--reverse', action='store_true',
                        help="adb reverse so the device's 127.0.0.1:port reaches the host proxy")
    parser.add_argument('--adb', default=shutil.which('adb') or 'adb')
    args = parser.parse_args()
    if not shutil.which(args.adb):
        parser.error('adb not found on PATH; pass --adb <path>')

    if args.action == 'status':
        result = adb(args, args.device, ['shell', 'settings', 'get', 'global', 'http_proxy'])
        print('device http_proxy =', (result.stdout.strip() or '(unset)'))
        return 0

    if args.action == 'clear':
        adb(args, args.device, ['shell', 'settings', 'put', 'global', 'http_proxy', ':0'])
        if args.reverse:
            adb(args, args.device, ['reverse', '--remove', 'tcp:%d' % args.port])
        print('[*] proxy cleared. Remember to stop mitmproxy/Burp and remove the CA if installed.')
        return 0

    # set
    if args.reverse:
        result = adb(args, args.device, ['reverse', 'tcp:%d' % args.port, 'tcp:%d' % args.port])
        if result.returncode:
            print('[!] adb reverse failed:', result.stderr.strip())
            return 2
        print('[*] adb reverse tcp:%d -> host tcp:%d' % (args.port, args.port))
    proxy = '%s:%d' % (args.host, args.port)
    result = adb(args, args.device, ['shell', 'settings', 'put', 'global', 'http_proxy', proxy])
    if result.returncode:
        print('[!] failed to set proxy:', result.stderr.strip())
        return 2
    print('[*] device http_proxy =', proxy)
    print('[*] Start the proxy on the host (e.g. mitmdump -p %d) and, for HTTPS,' % args.port)
    print('    install its CA on the device. Pinned apps still need the SSL hook')
    print('    (python tool.py dynamic --pkg <pkg> --mode net).')
    return 0


if __name__ == '__main__':
    sys.exit(main())
