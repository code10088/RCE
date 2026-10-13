"""Collect base/split APK, APKS/XAPK, and OBB inputs into one evidence set."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_extract(archive, destination, source_name, owners, conflicts):
    with zipfile.ZipFile(archive) as zf:
        root = destination.resolve()
        for item in zf.infolist():
            target = (destination / item.filename).resolve()
            if not target.is_relative_to(root):
                raise ValueError("unsafe archive member: " + item.filename)
            key = item.filename.replace("\\", "/")
            if key in owners and owners[key] != source_name:
                conflicts.append({"path": key, "previous": owners[key], "replacement": source_name})
                # A split APK has its own manifest/signature metadata. Keep
                # the base APK copy in the merged analysis view; those files
                # are not asset payloads and must not replace the base view.
                if key == "AndroidManifest.xml" or key.startswith("META-INF/"):
                    continue
            owners[key] = source_name
        zf.extractall(destination)


def discover(args):
    paths = list(args.input)
    if args.package:
        if not args.device:
            raise ValueError("--package requires --device")
        result = subprocess.run(["adb", "-s", args.device, "shell", "pm", "path", args.package],
                                capture_output=True, text=True, check=True)
        for line in result.stdout.splitlines():
            remote = line.strip().removeprefix("package:")
            if remote:
                local = Path(args.output) / "pulled" / Path(remote).name
                local.parent.mkdir(parents=True, exist_ok=True)
                subprocess.run(["adb", "-s", args.device, "pull", remote, str(local)], check=True)
                paths.append(local)
    expanded = []
    for raw in paths:
        path = Path(raw).expanduser().resolve()
        if path.suffix.lower() in (".apks", ".xapk"):
            unpack = Path(args.output) / "containers" / path.stem
            unpack.mkdir(parents=True, exist_ok=True)
            safe_extract(path, unpack, path.name, {}, [])
            expanded.extend(sorted(unpack.rglob("*.apk")))
            expanded.extend(sorted(unpack.rglob("*.obb")))
        else:
            expanded.append(path)
    return expanded


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", action="append", type=Path, default=[],
                        help="APK, split APK, APKS, XAPK, or OBB; repeatable")
    parser.add_argument("--package", help="installed package to collect all pm path entries")
    parser.add_argument("--device", default="127.0.0.1:7555")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    if not args.input and not args.package:
        parser.error("provide --input or --package")
    args.output.mkdir(parents=True, exist_ok=True)
    extracted = args.output / "extracted"
    extracted.mkdir(exist_ok=True)
    entries = []
    owners = {}
    conflicts = []
    non_archives = []
    for path in discover(args):
        if not path.is_file():
            raise ValueError("input not found: " + str(path))
        record = {"path": str(path), "name": path.name, "size": path.stat().st_size,
                  "sha256": digest(path)}
        entries.append(record)
        if path.suffix.lower() in (".apk", ".obb", ".zip"):
            try:
                safe_extract(path, extracted, path.name, owners, conflicts)
            except zipfile.BadZipFile:
                non_archives.append({"path": str(path), "reason": "not a ZIP archive; retained as raw input"})
    merged = args.output / "merged-input.apk"
    extracted_files = [file for file in sorted(extracted.rglob("*")) if file.is_file()]
    if extracted_files:
        with zipfile.ZipFile(merged, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for file in extracted_files:
                archive.write(file, file.relative_to(extracted).as_posix())
        merged_value = str(merged.resolve())
    else:
        merged_value = None
    manifest = {"inputs": entries, "extracted": str(extracted.resolve()),
                "merged_apk": merged_value,
                "conflicts": conflicts, "non_archives": non_archives,
                "note": "Files with identical paths are overwritten by later inputs; see conflicts and retain input hashes."}
    (args.output / "package-manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                                                        encoding="utf-8")
    print(json.dumps(manifest, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
