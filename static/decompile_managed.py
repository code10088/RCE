"""Decompile a managed DLL with ILSpyCmd and record reproducible metadata."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def sha256(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def find_input(args):
    if args.dll:
        path = args.dll.expanduser().resolve()
        if not path.is_file():
            raise ValueError('DLL not found: ' + str(path))
        return path
    if not args.capture_dir:
        raise ValueError('provide --dll or --capture-dir')
    candidates = []
    for path in args.capture_dir.expanduser().resolve().glob('*.dll'):
        data = path.read_bytes()[:2]
        if data == b'MZ':
            candidates.append(path)
    if not candidates:
        raise ValueError('no PE DLL found in capture directory: ' + str(args.capture_dir))
    return max(candidates, key=lambda p: p.stat().st_size)


ILSPY_VERSION = '9.1.0.7988'


def provision_ilspy():
    """Install ILSpyCmd into tools/ on demand (mirrors the other cached tools)."""
    tool_dir = ROOT / 'tools' / 'ilspycmd'
    exe = tool_dir / ('ilspycmd.exe' if os.name == 'nt' else 'ilspycmd')
    if exe.is_file():
        return exe.resolve()
    if not shutil.which('dotnet'):
        return None
    tool_dir.mkdir(parents=True, exist_ok=True)
    print('Installing ILSpyCmd %s into %s' % (ILSPY_VERSION, tool_dir), flush=True)
    result = subprocess.run(['dotnet', 'tool', 'install', 'ilspycmd', '--version', ILSPY_VERSION,
                             '--tool-path', str(tool_dir)])
    return exe.resolve() if result.returncode == 0 and exe.is_file() else None


def find_tool(explicit):
    candidates = []
    if explicit:
        candidates.append(Path(explicit).expanduser())
    candidates += [
        ROOT / 'tools' / 'ilspycmd' / 'ilspycmd.exe',
        ROOT / 'tools' / 'ilspycmd' / 'ilspycmd',
    ]
    path_tool = shutil.which('ilspycmd') or shutil.which('ilspycmd.exe')
    if path_tool:
        candidates.append(Path(path_tool))
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    provisioned = provision_ilspy()
    if provisioned:
        return provisioned
    raise ValueError('ILSpyCmd not found and could not be installed; install .NET or pass --ilspy PATH')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--dll', type=Path, help='captured managed DLL')
    source.add_argument('--capture-dir', type=Path, help='choose the largest valid PE DLL in this directory')
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--ilspy', help='path to ilspycmd executable')
    parser.add_argument('--reference', action='append', type=Path, default=[],
                        help='reference DLL; repeatable and passed with -r')
    parser.add_argument('--case', type=Path, help='case directory for artifact registration')
    args = parser.parse_args(argv)
    source_path = find_input(args)
    tool = find_tool(args.ilspy)
    output = args.out.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    src = output / 'src'
    src.mkdir(exist_ok=True)
    log_path = output / 'decompile.log'
    report_path = output / 'report.json'
    command = [str(tool), '-p', '-o', str(src), str(source_path)]
    for reference in args.reference:
        ref = reference.expanduser().resolve()
        if not ref.is_file():
            raise ValueError('reference not found: ' + str(ref))
        command += ['-r', str(ref)]
    started = dt.datetime.now().astimezone().isoformat(timespec='seconds')
    try:
        environment = os.environ.copy()
        environment['DOTNET_ROLL_FORWARD'] = 'Major'
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                encoding='utf-8', errors='replace', timeout=300, env=environment)
        log = result.stdout + ('\n' + result.stderr if result.stderr else '')
        log_path.write_text(log, encoding='utf-8')
        tool_version = subprocess.run([str(tool), '--version'], capture_output=True,
                                      text=True, encoding='utf-8', errors='replace', timeout=30,
                                      env=environment)
        report = {
            'started': started, 'finished': dt.datetime.now().astimezone().isoformat(timespec='seconds'),
            'tool': str(tool), 'tool_version': (tool_version.stdout or tool_version.stderr).strip(),
            'command': command, 'input': str(source_path), 'input_size': source_path.stat().st_size,
            'input_sha256': sha256(source_path), 'output': str(output), 'exit_code': result.returncode,
            'source_files': len(list(src.rglob('*.cs'))),
            'status': 'completed' if result.returncode == 0 else 'failed',
            'limitations': 'ILSpy output is decompiled C# approximation, not original source.'
        }
    except subprocess.TimeoutExpired as exc:
        log_path.write_text('ILSpyCmd timed out after 300 seconds.\n' + str(exc), encoding='utf-8')
        report = {'started': started, 'finished': dt.datetime.now().astimezone().isoformat(timespec='seconds'),
                  'tool': str(tool), 'input': str(source_path), 'input_sha256': sha256(source_path),
                  'output': str(output), 'exit_code': 124, 'source_files': len(list(src.rglob('*.cs'))),
                  'status': 'timeout'}
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    if args.case:
        manifest = args.case.expanduser().resolve() / 'case.json'
        if manifest.is_file():
            data = json.loads(manifest.read_text(encoding='utf-8'))
            artifacts = data.setdefault('artifacts', [])
            record = {'name': report_path.name, 'path': str(report_path), 'kind': 'managed-decompile',
                      'source_sha256': report.get('input_sha256'), 'tool': str(tool),
                      'report': str(report_path), 'added': dt.datetime.now().isoformat()}
            artifacts[:] = [item for item in artifacts if item.get('path') != str(output)]
            artifacts.append(record)
            manifest.write_text(json.dumps(data, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print('Input:', source_path)
    print('Output:', output)
    print('Source files:', report.get('source_files', 0))
    print('Status:', report['status'])
    return 0 if report['status'] == 'completed' else 2


if __name__ == '__main__':
    raise SystemExit(main())
