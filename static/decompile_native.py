"""Export selected IL2CPP native functions as Ghidra pseudo-C (Windows)."""
import argparse
import hashlib
import shutil
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def fetch_json(url):
    request = urllib.request.Request(url, headers={'User-Agent': 'il2cpp-harness'})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def download_extract(url, directory):
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory / 'download.zip'
    if not archive.is_file():
        print('Downloading:', url, flush=True)
        downloader = shutil.which('curl.exe') or shutil.which('curl')
        if downloader:
            subprocess.run([downloader, '-L', '--fail', '--retry', '5', '--retry-all-errors',
                            '-C', '-', '-o', str(archive), url], check=True)
        else:
            urllib.request.urlretrieve(url, archive)
    print('Extracting:', archive, flush=True)
    with zipfile.ZipFile(archive) as z:
        for item in z.infolist():
            if not (directory / item.filename).resolve().is_relative_to(directory.resolve()):
                raise ValueError('Unsafe ZIP path')
        z.extractall(directory)
    return hashlib.sha256(archive.read_bytes()).hexdigest()


def provision():
    tools = ROOT / 'tools'
    ghidra_root = tools / 'ghidra'
    jdks = tools / 'jdk21'
    headless = list(ghidra_root.glob('*/support/analyzeHeadless.bat'))
    provenance = {}
    if not headless:
        release = fetch_json('https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest')
        asset = next(a for a in release['assets'] if 'PUBLIC' in a['name'] and a['name'].endswith('.zip'))
        provenance['ghidra_url'] = asset['browser_download_url']
        provenance['ghidra_sha256'] = download_extract(asset['browser_download_url'], ghidra_root)
        headless = list(ghidra_root.glob('*/support/analyzeHeadless.bat'))
    jdk = list(jdks.glob('*/bin/javac.exe'))
    if not jdk:
        assets = fetch_json('https://api.adoptium.net/v3/assets/latest/21/hotspot?architecture=x64&image_type=jdk&os=windows&vendor=eclipse')
        package = assets[0]['binary']['package']
        provenance['jdk_url'] = package['link']
        digest = download_extract(package['link'], jdks)
        if digest.lower() != package['checksum'].lower():
            raise ValueError('JDK download checksum mismatch')
        provenance['jdk_sha256'] = digest
        jdk = list(jdks.glob('*/bin/javac.exe'))
    if provenance:
        (tools / 'native-tools-source.json').write_text(json.dumps(provenance, indent=2), encoding='utf-8')
    return headless[0], jdk[0].parents[1]


IDA_SCRIPT = r'''# Auto-generated IDAPython: decompile selected addresses with Hex-Rays.
import json, idaapi, idautils, ida_hexrays, idc, ida_auto, ida_pro
sel_path, out_dir, _timeout = idc.ARGV[1], idc.ARGV[2], idc.ARGV[3]
ida_auto.auto_wait()
if not ida_hexrays.init_hexrays_plugin():
    idc.qexit(3)
import os
os.makedirs(os.path.join(out_dir, "functions"), exist_ok=True)
entries = []
with open(sel_path, "r", encoding="utf-8") as fh:
    methods = json.load(fh)
for m in methods:
    addr = int(m.get("Address", 0))
    name = "".join(c if c.isalnum() else "_" for c in m.get("Name", "sub"))[:150] or "sub"
    rec = {"name": m.get("Name"), "address": hex(addr), "file": "functions/%s.c" % name, "success": False}
    try:
        idc.create_insn(addr); ida_auto.auto_wait()
        cf = ida_hexrays.decompile(addr)
        if cf:
            with open(os.path.join(out_dir, "functions", name + ".c"), "w", encoding="utf-8") as out:
                out.write(str(cf))
            rec["success"] = True
    except Exception as e:
        rec["error"] = str(e)
    entries.append(rec)
with open(os.path.join(out_dir, "index.json"), "w", encoding="utf-8") as out:
    json.dump(entries, out, indent=2, ensure_ascii=False)
idc.qexit(0)
'''


def run_ghidra(a, selection):
    launcher, java_home = provision()
    env = os.environ.copy()
    env['JAVA_HOME'] = str(java_home)
    env['PATH'] = str(java_home / 'bin') + os.pathsep + env.get('PATH', '')
    project = a.output / 'ghidra-project'
    project.mkdir(exist_ok=True)
    command = [str(launcher), str(project.resolve()), 'IL2CPP',
               '-import', str(a.binary.resolve()), '-overwrite', '-noanalysis',
               '-scriptPath', str(ROOT / 'static'), '-postScript', 'ExportNative.java',
               str(selection.resolve()), str(a.output.resolve()), str(a.timeout), '-max-cpu', '2']
    print('Running Ghidra headless; log:', a.output / 'ghidra.log', flush=True)
    with (a.output / 'ghidra.log').open('w', encoding='utf-8') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, env=env)
    return result.returncode


def run_ida(a, selection):
    """Hex-Rays engine: cleaner pseudo-C than Ghidra on many obfuscated targets.

    Not bundled (IDA is commercial). Uses idat/idat64 from --ida-path or PATH.
    """
    launcher = a.ida_path and str(a.ida_path)
    if not launcher:
        launcher = shutil.which('idat64') or shutil.which('idat')
    if not launcher:
        print('IDA headless (idat64/idat) not found; pass --ida-path', flush=True)
        return 2
    script_path = a.output / 'ida_decompile.py'
    script_path.write_text(IDA_SCRIPT, encoding='utf-8')
    log = a.output / 'ida.log'
    # -A batch, -S"script args", -L logfile. idat exits via idc.qexit.
    command = [launcher, '-A',
               '-S%s %s %s %s' % (script_path.resolve(), selection.resolve(), a.output.resolve(), a.timeout),
               '-L%s' % log.resolve(), str(a.binary.resolve())]
    print('Running IDA headless; log:', log, flush=True)
    result = subprocess.run(command)
    return result.returncode


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--filter', default=r'^(GameUtility|ConfigProxy|FarmMockConfigAsset)\$\$')
    p.add_argument('--limit', type=int, default=20)
    p.add_argument('--timeout', type=int, default=20, help='Per-function decompiler timeout in seconds')
    p.add_argument('--binary', type=Path, default=ROOT / 'out/static/mumu-current/extracted/lib/arm64-v8a/libil2cpp.so')
    p.add_argument('--symbols', type=Path, default=ROOT / 'out/static/mumu-current/recovered-v2/script.json')
    p.add_argument('--output', type=Path, default=ROOT / 'out/static/mumu-current/native-decompiled')
    p.add_argument('--engine', default='ghidra', choices=['ghidra', 'ida'],
                   help='Ghidra (default, auto-provisioned) or IDA/Hex-Rays (external)')
    p.add_argument('--ida-path', type=Path, help='Path to idat64/idat when --engine ida')
    a = p.parse_args()
    if a.limit < 1 or a.timeout < 1:
        p.error('--limit and --timeout must be positive')
    if not a.binary.is_file() or not a.symbols.is_file():
        p.error('Binary or symbol mapping file missing')
    pattern = re.compile(a.filter)
    mapping = json.loads(a.symbols.read_text(encoding='utf-8-sig'))
    seen = set()
    selected = []
    for item in mapping['ScriptMethod']:
        address = item.get('Address', 0)
        if address and address not in seen and pattern.search(item['Name']):
            seen.add(address)
            selected.append(item)
            if len(selected) == a.limit:
                break
    if not selected:
        p.error('No methods match --filter')
    a.output.mkdir(parents=True, exist_ok=True)
    selection = a.output / 'selected-methods.json'
    selection.write_text(json.dumps(selected, indent=2, ensure_ascii=False), encoding='utf-8')
    print('Selected unique function addresses:', len(selected), flush=True)
    returncode = run_ida(a, selection) if a.engine == 'ida' else run_ghidra(a, selection)
    index = a.output / 'index.json'
    if not index.is_file():
        print('Export failed; see %s.log' % a.engine, flush=True)
        return 2
    entries = json.loads(index.read_text(encoding='utf-8'))
    successes = sum(e.get('success', False) for e in entries)
    print(f'Exported {successes}/{len(entries)} functions. Output: {a.output}', flush=True)
    return 0 if returncode == 0 and successes else 2


if __name__ == '__main__':
    raise SystemExit(main())
