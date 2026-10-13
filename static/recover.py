"""Run the official Il2CppDumper release against extracted local files."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = '6.7.46'
ASSET = f'Il2CppDumper-net6-v{VERSION}.zip'
URL = f'https://github.com/Perfare/Il2CppDumper/releases/download/v{VERSION}/{ASSET}'


def run_il2cppinspector(args, parser, binary, metadata):
    """Alternative engine: cross-check Il2CppDumper with Il2CppInspector.

    Not bundled or auto-downloaded by default. Pass --inspector-cli pointing at
    Il2CppInspector.exe (or its .dll, run via dotnet), or --inspector-url to a
    release zip. Some Unity versions and metadata layouts parse more reliably
    here; use it to corroborate, not replace, the primary engine.
    """
    cli = args.inspector_cli
    if cli is None and args.inspector_url:
        import urllib.request
        import zipfile
        dest = ROOT / 'tools' / 'il2cppinspector'
        dest.mkdir(parents=True, exist_ok=True)
        archive = dest / 'download.zip'
        if not archive.is_file():
            print('Downloading Il2CppInspector:', args.inspector_url, flush=True)
            urllib.request.urlretrieve(args.inspector_url, archive)
            with zipfile.ZipFile(archive) as z:
                for entry in z.infolist():
                    if not (dest / entry.filename).resolve().is_relative_to(dest.resolve()):
                        raise ValueError('Unsafe archive member')
                z.extractall(dest)
        found = list(dest.rglob('Il2CppInspector.exe')) or list(dest.rglob('Il2CppInspector.dll'))
        if not found:
            parser.error('Il2CppInspector executable not found in the downloaded archive')
        cli = found[0]
    if cli is None:
        parser.error('--engine il2cppinspector needs --inspector-cli PATH or --inspector-url URL')
    args.output.mkdir(parents=True, exist_ok=True)
    if (args.output / 'dump.cs').exists():
        parser.error('Output already contains dump.cs; choose a new --output directory.')
    launch = ['dotnet', str(cli)] if str(cli).lower().endswith('.dll') else [str(cli)]
    command = launch + ['-i', str(binary.resolve()), '-m', str(metadata.resolve()),
                        '--cs-out', str((args.output / 'dump.cs').resolve()),
                        '--py-out', str((args.output / 'ida.py').resolve())]
    command += list(args.inspector_args or [])
    try:
        result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8',
                                errors='replace', timeout=120)
        log, code = result.stdout + result.stderr, result.returncode
    except subprocess.TimeoutExpired as exc:
        log = 'Il2CppInspector timed out.\n' + str(exc)
        code = 2
    except FileNotFoundError as exc:
        parser.error('Failed to launch Il2CppInspector: %s' % exc)
    (args.output / 'parser.log').write_text(log, encoding='utf-8')
    dump = args.output / 'dump.cs'
    success = code == 0 and dump.is_file() and dump.stat().st_size > 0
    status = dict(engine='il2cppinspector', cli=str(cli), exit_code=code, recovered=success,
                  binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  metadata_sha256=hashlib.sha256(metadata.read_bytes()).hexdigest(),
                  limitations='Type/signature reconstruction only; cross-check addresses against the primary engine.')
    (args.output / 'recovery-status.json').write_text(json.dumps(status, indent=2), encoding='utf-8')
    print(log)
    print('Recovery verified:', success)
    print('Output:', args.output)
    return 0 if success else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=ROOT / 'out/static/mumu-current/extracted')
    parser.add_argument('--output', type=Path, default=ROOT / 'out/static/mumu-current/recovered')
    parser.add_argument('--abi', default='arm64-v8a', choices=['arm64-v8a', 'armeabi-v7a', 'x86_64', 'x86'])
    parser.add_argument('--engine', default='il2cppdumper', choices=['il2cppdumper', 'il2cppinspector'],
                        help='Primary engine (default) or the Il2CppInspector cross-check engine')
    parser.add_argument('--inspector-cli', type=Path, help='Path to Il2CppInspector.exe or .dll')
    parser.add_argument('--inspector-url', help='Release zip URL to download Il2CppInspector from')
    parser.add_argument('--inspector-args', nargs=argparse.REMAINDER,
                        help='Extra args passed verbatim to Il2CppInspector (must come last)')
    args = parser.parse_args()
    binary = args.input / 'lib' / args.abi / 'libil2cpp.so'
    metadata = args.input / 'assets/bin/Data/Managed/Metadata/global-metadata.dat'
    for path in (binary, metadata):
        if not path.is_file():
            parser.error(f'Missing input: {path}')
    if args.engine == 'il2cppinspector':
        return run_il2cppinspector(args, parser, binary, metadata)
    tool = ROOT / 'tools' / f'Il2CppDumper-{VERSION}'
    tool.mkdir(parents=True, exist_ok=True)
    archive = tool / ASSET
    executable = tool / 'Il2CppDumper.dll'
    if not executable.exists():
        print(f'Downloading official release: {URL}', flush=True)
        urllib.request.urlretrieve(URL, archive)
        with zipfile.ZipFile(archive) as z:
            for entry in z.infolist():
                target = (tool / entry.filename).resolve()
                if not target.is_relative_to(tool.resolve()):
                    raise ValueError('Unsafe archive member')
            z.extractall(tool)
    config_path = tool / 'config.json'
    config = json.loads(config_path.read_text(encoding='utf-8-sig'))
    config['RequireAnyKey'] = False
    config_path.write_text(json.dumps(config, indent=2), encoding='utf-8')
    args.output.mkdir(parents=True, exist_ok=True)
    if (args.output / 'dump.cs').exists():
        parser.error('Output already contains dump.cs; choose a new --output directory to avoid mixing results.')
    environment = os.environ.copy()
    environment['DOTNET_ROLL_FORWARD'] = 'Major'
    command = ['dotnet', str(executable), str(binary.resolve()), str(metadata.resolve()), str(args.output.resolve())]
    try:
        result = subprocess.run(command, input='', capture_output=True, text=True,
                                encoding='utf-8', errors='replace', timeout=55, env=environment)
        log = result.stdout + result.stderr
        code = result.returncode
    except subprocess.TimeoutExpired as exc:
        log = 'Parser timed out; no interactive/manual addresses supplied.\n'
        for text in (exc.stdout, exc.stderr):
            if text:
                log += text.decode('utf-8', 'replace') if isinstance(text, bytes) else text
        code = 2
    (args.output / 'parser.log').write_text(log, encoding='utf-8')
    files = [p for p in args.output.rglob('*') if p.is_file() and p.name not in ('parser.log', 'recovery-status.json')]
    dump = args.output / 'dump.cs'
    success = code == 0 and dump.is_file() and dump.stat().st_size > 0
    status = dict(tool_version=VERSION, source=URL, exit_code=code, recovered=success,
                  binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  metadata_sha256=hashlib.sha256(metadata.read_bytes()).hexdigest(),
                  artifacts=[str(p.relative_to(args.output)) for p in files])
    if success:
        declarations = dump.read_text(encoding='utf-8-sig', errors='replace')
        status['counts'] = {
            'images': len(re.findall(r'^// Image ', declarations, re.M)),
            'type_definitions': len(re.findall(r'TypeDefIndex:', declarations)),
            'method_address_entries': len(re.findall(r'// RVA:', declarations)),
            'dummy_dlls': len(list((args.output / 'DummyDll').glob('*.dll'))),
        }
        status['limitations'] = 'Type/signature reconstruction only; method bodies are placeholders, not restored source.'
    (args.output / 'recovery-status.json').write_text(json.dumps(status, indent=2), encoding='utf-8')
    print(log)
    print('Recovery verified:', success)
    print('Output:', args.output)
    return 0 if success else 2


if __name__ == '__main__':
    raise SystemExit(main())
