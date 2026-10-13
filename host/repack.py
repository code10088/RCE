#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Rebuild, modify, and sign an APK (closes the patch / gadget workflows).

Use only on builds you own or are authorized to modify. Typical uses:

  # Swap in a libil2cpp.so produced by `tool.py patch`, then sign.
  python host/repack.py --apk game.apk --out game.patched.apk \
      --replace lib/arm64-v8a/libil2cpp.so=libil2cpp.patched.so

  # No-root injection: drop frida-gadget + config into the APK.
  python host/repack.py --apk game.apk --out game.gadget.apk \
      --gadget libfrida-gadget.so --abi arm64-v8a

Needs apktool, zipalign, apksigner, and keytool on PATH (Android SDK build-tools
+ apktool). Smali injection of the gadget loader is best-effort; the tool warns
when it cannot confirm the launcher activity.
"""
import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GADGET_CONFIG = ('{ "interaction": { "type": "listen", "address": "127.0.0.1", '
                 '"port": 27042, "on_load": "wait" } }\n')


def need(tool):
    path = shutil.which(tool)
    if not path:
        raise SystemExit('[!] required tool not found on PATH: %s' % tool)
    return path


def launcher_activity(manifest_text):
    """Find the component declared with the MAIN/LAUNCHER intent-filter."""
    for match in re.finditer(r'<activity[^>]*android:name="([^"]+)"[^>]*>(.*?)</activity>',
                             manifest_text, re.S):
        name, body = match.group(1), match.group(2)
        if 'android.intent.action.MAIN' in body and 'android.intent.category.LAUNCHER' in body:
            return name
    alias = re.search(r'<activity-alias[^>]*android:targetActivity="([^"]+)"', manifest_text)
    return alias.group(1) if alias else None


def inject_loadlibrary(decoded, package, lib_name):
    """Best-effort: add System.loadLibrary(lib_name) to the launcher onCreate."""
    manifest = (decoded / 'AndroidManifest.xml').read_text(encoding='utf-8', errors='replace')
    activity = launcher_activity(manifest)
    if not activity:
        return False, 'launcher activity not found in manifest'
    if activity.startswith('.'):
        activity = package + activity
    elif '.' not in activity:
        activity = package + '.' + activity
    rel = activity.replace('.', '/') + '.smali'
    candidates = list(decoded.glob('smali*/' + rel))
    if not candidates:
        return False, 'smali not found for %s' % activity
    smali = candidates[0]
    text = smali.read_text(encoding='utf-8', errors='replace')
    inject = ('    const-string v0, "%s"\n'
              '    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n' % lib_name)
    match = re.search(r'(\.method[^\n]*\bonCreate\(.*?\n(?:\s*\.locals[^\n]*\n|\s*\.registers[^\n]*\n)?)',
                      text)
    if not match:
        return False, 'onCreate not found in %s' % smali.name
    patched = text[:match.end()] + inject + text[match.end():]
    smali.write_text(patched, encoding='utf-8')
    return True, 'injected into %s' % smali.name


def ensure_keystore(args):
    if args.keystore:
        return args.keystore, args.ks_pass, args.ks_alias, args.key_pass
    store = ROOT / 'tools' / 'harness-debug.keystore'
    alias, password = 'harness', 'harness123'
    if not store.is_file():
        store.parent.mkdir(parents=True, exist_ok=True)
        print('[*] generating debug keystore:', store)
        subprocess.run([need('keytool'), '-genkeypair', '-v', '-keystore', str(store),
                        '-alias', alias, '-keyalg', 'RSA', '-keysize', '2048', '-validity', '10000',
                        '-storepass', password, '-keypass', password,
                        '-dname', 'CN=il2cpp-harness'], check=True)
    return str(store), password, alias, password


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--apk', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--replace', action='append', default=[],
                        help='PATH_IN_APK=LOCAL_FILE, e.g. lib/arm64-v8a/libil2cpp.so=patched.so')
    parser.add_argument('--gadget', type=Path, help='frida-gadget .so to inject (no-root path)')
    parser.add_argument('--abi', default='arm64-v8a', help='lib ABI dir for --gadget')
    parser.add_argument('--package', help='App package (for smali injection; else read from manifest)')
    parser.add_argument('--no-inject', action='store_true', help='Place gadget files but skip smali edit')
    parser.add_argument('--keystore', help='Signing keystore (default: generated debug keystore)')
    parser.add_argument('--ks-pass', default='harness123')
    parser.add_argument('--ks-alias', default='harness')
    parser.add_argument('--key-pass', default='harness123')
    parser.add_argument('--work', type=Path, help='Work dir for apktool decode (default: temp beside --out)')
    args = parser.parse_args()

    if not args.apk.is_file():
        parser.error('APK not found: %s' % args.apk)
    if args.out.exists():
        parser.error('Output exists; choose a new --out path')
    apktool, zipalign, apksigner = need('apktool'), need('zipalign'), need('apksigner')

    work = args.work or args.out.with_suffix('.decoded')
    if work.exists():
        shutil.rmtree(work)
    print('[*] apktool d ...', flush=True)
    if subprocess.run([apktool, 'd', '-f', '-o', str(work), str(args.apk)]).returncode:
        parser.error('apktool decode failed')

    for spec in args.replace:
        rel, _, local = spec.partition('=')
        if not local:
            parser.error('--replace expects PATH_IN_APK=LOCAL_FILE')
        target = work / rel
        if not target.parent.exists():
            parser.error('path not present in APK: %s' % rel)
        shutil.copyfile(local, target)
        print('[*] replaced', rel)

    if args.gadget:
        lib_dir = work / 'lib' / args.abi
        lib_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(args.gadget, lib_dir / 'libfrida-gadget.so')
        (lib_dir / 'libfrida-gadget.config.so').write_text(GADGET_CONFIG, encoding='utf-8')
        print('[*] placed gadget + config in', lib_dir)
        if not args.no_inject:
            manifest = (work / 'AndroidManifest.xml').read_text(encoding='utf-8', errors='replace')
            package = args.package or (re.search(r'package="([^"]+)"', manifest) or [None, ''])[1]
            ok, detail = inject_loadlibrary(work, package, 'frida-gadget')
            print(('[*] ' if ok else '[!] ') + 'smali injection: ' + detail)
            if not ok:
                print('    add manually to the launcher onCreate: System.loadLibrary("frida-gadget")')

    print('[*] apktool b ...', flush=True)
    built = work / 'dist' / 'rebuilt.apk'
    if subprocess.run([apktool, 'b', '-o', str(built), str(work)]).returncode:
        parser.error('apktool build failed')

    aligned = args.out.with_suffix('.aligned.apk')
    if subprocess.run([zipalign, '-f', '-p', '4', str(built), str(aligned)]).returncode:
        parser.error('zipalign failed')

    keystore, ks_pass, alias, key_pass = ensure_keystore(args)
    sign = subprocess.run([apksigner, 'sign', '--ks', keystore, '--ks-pass', 'pass:' + ks_pass,
                           '--ks-key-alias', alias, '--key-pass', 'pass:' + key_pass,
                           '--out', str(args.out), str(aligned)])
    aligned.unlink(missing_ok=True)
    if sign.returncode:
        parser.error('apksigner failed')
    subprocess.run([apksigner, 'verify', '--print-certs', str(args.out)])
    print('[*] signed APK:', args.out)
    print('[*] install:  adb install -r', args.out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
