"""Unified local APK/IL2CPP analysis entry point (Python 3.9+, Windows)."""
import argparse
import datetime
import importlib.metadata
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def run(command):
    print('[run]', subprocess.list2cmdline([str(x) for x in command]), flush=True)
    return subprocess.run([str(x) for x in command], cwd=ROOT).returncode


def doctor():
    print('Python:', sys.version.split()[0], sys.executable)
    for name, note in [('frida', 'dynamic mode'), ('frida-tools', 'dynamic mode'),
                       ('unicorn', 'emulate'), ('capstone', 'emulate --trace')]:
        try:
            print(name + ':', importlib.metadata.version(name))
        except importlib.metadata.PackageNotFoundError:
            print(name + ': not installed (only required for %s)' % note)
    for name in ('powershell', 'adb', 'dotnet', 'java'):
        print(name + ':', shutil.which(name) or 'not on PATH')
    # Optional external engines / repackaging tools, discovered on PATH.
    for name in ('idat64', 'idat', 'apktool', 'zipalign', 'apksigner', 'keytool'):
        print(name + ':', shutil.which(name) or 'not on PATH (optional)')
    for name, pattern in [('Ghidra', 'ghidra/*/support/analyzeHeadless.bat'),
                          ('Portable JDK', 'jdk21/*/bin/javac.exe'),
                          ('Il2CppDumper', 'Il2CppDumper-*/Il2CppDumper.dll'),
                          ('Il2CppInspector', 'il2cppinspector/**/Il2CppInspector.exe'),
                          ('ILSpyCmd', 'ilspycmd/ilspycmd.*')]:
        print(name + ':', ', '.join(str(p) for p in (ROOT / 'tools').glob(pattern)) or 'not cached')
    if shutil.which('adb'):
        return run(['adb', 'devices', '-l'])
    return 0


def static_workflow(args):
    if args.apk and not args.apk.is_file():
        raise ValueError('APK not found: ' + str(args.apk))
    if args.package and not args.device:
        raise ValueError('--package requires --device')
    if args.decompile and not args.recover:
        raise ValueError('--decompile requires --recover')
    if args.limit < 1 or args.timeout < 1:
        raise ValueError('--limit and --timeout must be positive')
    re.compile(args.filter)
    needs_dotnet = args.recover and not (args.runtime_fallback and args.package and not args.decompile)
    for dependency in ['powershell'] + (['adb'] if args.package else []) + (['dotnet'] if needs_dotnet else []):
        if not shutil.which(dependency):
            raise ValueError('Required executable not found: ' + dependency)
    label = args.apk.stem if args.apk else args.package
    label = re.sub(r'[^A-Za-z0-9_.-]', '_', label)[:100] or 'apk'
    output = args.out or ROOT / 'out' / 'static' / (label + '-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    output = output.resolve()
    # Keep independent runs independent; stale files must not be reported as new output.
    if output.exists() and any(output.iterdir()):
        raise ValueError('Output is not empty; choose a new --out directory')
    output.mkdir(parents=True, exist_ok=True)
    status = {'started': datetime.datetime.now().isoformat(), 'output': str(output),
              'abi': args.abi, 'stages': [], 'completed': False}
    code = 2
    runtime_recovered = False
    def stage(name, command):
        result = run(command)
        status['stages'].append({'stage': name, 'exit_code': result})
        return result
    try:
        command = ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ROOT / 'static/analyze.ps1', '-Output', output]
        if args.apk:
            command += ['-ApkPath', args.apk.resolve()]
        else:
            command += ['-Device', args.device, '-Package', args.package, '-PullFromDevice']
        code = stage('audit', command)
        if code:
            return code
        if args.recover:
            code = stage('recover', [sys.executable, ROOT / 'static/recover.py', '--input', output / 'extracted',
                                    '--output', output / 'recovered', '--abi', args.abi])
            if code:
                if not (args.runtime_fallback and args.package):
                    return code
                print('[info] static recovery failed; trying runtime dumpcs fallback', flush=True)
                code = stage('runtime_dumpcs_fallback', [sys.executable, '-u', ROOT / 'host/run.py',
                                                        '--pkg', args.package, '--device', args.device,
                                                        '--out', output / 'runtime', '--mode', 'dumpcs'])
                if code:
                    return code
                runtime_dumps = sorted((output / 'runtime').glob('**/dump.cs'))
                if not runtime_dumps or runtime_dumps[-1].stat().st_size == 0:
                    status['stages'][-1]['validation'] = 'dump.cs missing or empty'
                    return 2
                runtime_recovered = True
        if args.decompile:
            if runtime_recovered:
                status['stages'].append({'stage': 'decompile', 'exit_code': 2,
                                         'reason': 'runtime dumpcs has no native script.json input'})
                print('[error] --decompile requires a successful static recovery; runtime dumpcs fallback only restored managed structure', file=sys.stderr)
                return 2
            decompile_command = [sys.executable, ROOT / 'static/decompile_native.py',
                                 '--binary', output / 'extracted/lib' / args.abi / 'libil2cpp.so',
                                 '--symbols', output / 'recovered/script.json',
                                 '--output', output / 'native-decompiled', '--filter', args.filter,
                                 '--limit', args.limit, '--timeout', args.timeout, '--engine', args.engine]
            if args.engine == 'ida' and args.ida_path:
                decompile_command += ['--ida-path', args.ida_path]
            code = stage('decompile', decompile_command)
            if code:
                return code
        status['completed'] = True
        return 0
    finally:
        status['finished'] = datetime.datetime.now().isoformat()
        (output / 'workflow.json').write_text(json.dumps(status, indent=2, ensure_ascii=False), encoding='utf-8')
        print('Results:', output, flush=True)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    # Preserve all existing dynamic flags; no Frida imports in static/doctor modes.
    if argv and argv[0] == 'dynamic':
        options = argv[1:]
        if options and options[0] == '--':
            options.pop(0)
        return run([sys.executable, '-u', ROOT / 'host/run.py'] + (options or ['--help']))
    if argv and argv[0] == 'analyze':
        options = argv[1:]
        return run([sys.executable, ROOT / 'host/analyze.py'] + (options or ['--help']))
    if argv and argv[0] == 'diff':
        options = argv[1:]
        return run([sys.executable, ROOT / 'static/diff.py'] + (options or ['--help']))
    if argv and argv[0] == 'crosscheck':
        options = argv[1:]
        return run([sys.executable, ROOT / 'static/crosscheck.py'] + (options or ['--help']))
    if argv and argv[0] == 'emulate':
        options = argv[1:]
        return run([sys.executable, ROOT / 'static/emulate.py'] + (options or ['--help']))
    if argv and argv[0] == 'patch':
        options = argv[1:]
        return run([sys.executable, ROOT / 'static/patch.py'] + (options or ['--help']))
    if argv and argv[0] == 'carve':
        options = argv[1:]
        return run([sys.executable, ROOT / 'static/carve.py'] + (options or ['--help']))
    if argv and argv[0] == 'memdump':
        options = argv[1:]
        return run([sys.executable, '-u', ROOT / 'host/memdump.py'] + (options or ['--help']))
    if argv and argv[0] == 'mitm':
        options = argv[1:]
        return run([sys.executable, ROOT / 'host/mitm.py'] + (options or ['--help']))
    if argv and argv[0] == 'provision-server':
        options = argv[1:]
        return run([sys.executable, '-u', ROOT / 'host/provision_server.py'] + (options or ['--help']))
    if argv and argv[0] == 'repack':
        options = argv[1:]
        return run([sys.executable, ROOT / 'host/repack.py'] + (options or ['--help']))
    if argv and argv[0] == 'selftest':
        return run([sys.executable, '-m', 'unittest', 'discover', '-s', ROOT / 'tests'] + argv[1:])
    if argv and argv[0] == 'collect':
        options = argv[1:]
        return run([sys.executable, ROOT / 'static/collect.py'] + (options or ['--help']))
    if argv and argv[0] == 'calibrate':
        options = argv[1:]
        return run([sys.executable, ROOT / 'static/calibrate.py'] + (options or ['--help']))
    if argv and argv[0] == 'backfill':
        options = argv[1:]
        return run([sys.executable, ROOT / 'static/backfill.py'] + (options or ['--help']))
    if argv and argv[0] == 'decompile-managed':
        options = argv[1:]
        return run([sys.executable, ROOT / 'static/decompile_managed.py'] + (options or ['--help']))
    if argv and argv[0] == 'workflow':
        options = argv[1:]
        return run([sys.executable, ROOT / 'workflow.py'] + (options or ['--help']))
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest='command', required=True)
    subs.add_parser('doctor', help='Check host tools and ADB devices; does not attach to an app')
    subs.add_parser('dynamic', help='Forward flags to host/run.py; see dynamic --help')
    subs.add_parser('analyze', help='Analyze existing JSON/JSONL output offline; never attaches to an app')
    subs.add_parser('diff', help='Compare two classes.json artifacts offline')
    subs.add_parser('crosscheck', help='Cross-verify runtime RVAs against Il2CppDumper ScriptMethod addresses')
    subs.add_parser('emulate', help='Emulate one native function offline with Unicorn')
    subs.add_parser('patch', help='Patch bytes in an extracted libil2cpp.so (writes a new file)')
    subs.add_parser('carve', help='Carve strings and embedded images from a raw dump')
    subs.add_parser('memdump', help='Dump live process memory ranges with Frida for carving')
    subs.add_parser('mitm', help='Point a device at a host MITM proxy over ADB')
    subs.add_parser('provision-server', help='Download and push a matching frida-server to a device')
    subs.add_parser('repack', help='Rebuild/sign an APK, replace files, or inject frida-gadget')
    subs.add_parser('selftest', help='Run the offline unit-test suite')
    subs.add_parser('collect', help='Collect split APK/APKS/XAPK/OBB inputs and hashes')
    subs.add_parser('calibrate', help='Convert static RVAs to runtime addresses')
    subs.add_parser('backfill', help='Create evidence bundle and Ghidra/IDA annotation scripts')
    subs.add_parser('decompile-managed', help='Decompile a captured managed DLL with ILSpyCmd')
    subs.add_parser('workflow', help='Create and verify reproducible analysis cases')
    static = subs.add_parser('static', help='Audit APK, optionally recover types and decompile selected native methods')
    source = static.add_mutually_exclusive_group(required=True)
    source.add_argument('--apk', type=Path, help='Local APK')
    source.add_argument('--package', help='Installed package to pull using ADB')
    static.add_argument('--device', help='ADB serial (required with --package)')
    static.add_argument('--out', type=Path, help='New or empty output directory; otherwise a timestamped run is created')
    static.add_argument('--abi', default='arm64-v8a', choices=['arm64-v8a', 'armeabi-v7a', 'x86_64', 'x86'])
    static.add_argument('--recover', action='store_true', help='Recover type/signature structures using Il2CppDumper')
    static.add_argument('--runtime-fallback', action='store_true',
                        help='If static recovery fails for an installed package, try runtime dumpcs')
    static.add_argument('--decompile', action='store_true', help='Export selected native pseudo-C (requires --recover)')
    static.add_argument('--engine', default='ghidra', choices=['ghidra', 'ida'],
                        help='Native decompiler engine for --decompile')
    static.add_argument('--ida-path', type=Path, help='Path to idat64/idat when --engine ida')
    static.add_argument('--filter', default=r'^(GameUtility|ConfigProxy|FarmMockConfigAsset)\$\$', help='Native method-name regex')
    static.add_argument('--limit', type=int, default=20)
    static.add_argument('--timeout', type=int, default=15, help='Decompiler timeout per function')
    args = parser.parse_args(argv)
    try:
        return doctor() if args.command == 'doctor' else static_workflow(args)
    except (ValueError, OSError, re.error) as exc:
        print('[error]', exc, file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
