"""Create and verify a reproducible IL2CPP analysis case.

This file only manages case metadata and hashes. It does not attach to a
process, modify an application, or copy samples into the case directory.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import time
from pathlib import Path
import sys


STAGES = [
    "inventory", "static_audit", "metadata_recovery", "runtime_dump",
    "address_calibration", "managed_native_boundary", "trigger_reproduction",
    "dynamic_validation", "obfuscation_analysis", "result_backfill", "verification",
]


def now():
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_case(path):
    case = Path(path).resolve()
    manifest = case / "case.json"
    if not manifest.is_file():
        raise ValueError(f"case.json not found: {manifest}")
    return case, manifest, json.loads(manifest.read_text(encoding="utf-8"))


def write_json_atomic(path, value):
    path = Path(path)
    temp = path.with_name(path.name + ".tmp-%d" % os.getpid())
    temp.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(temp, path)


def update_manifest(manifest_path, updater):
    lock = Path(str(manifest_path) + ".lock")
    fd = None
    try:
        for _ in range(100):
            try:
                fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                break
            except FileExistsError:
                time.sleep(0.02)
        if fd is None:
            raise OSError("manifest lock timeout")
        manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
        updater(manifest)
        write_json_atomic(manifest_path, manifest)
        return manifest
    finally:
        if fd is not None:
            os.close(fd)
            try:
                lock.unlink()
            except OSError:
                pass


def init_case(args):
    case = Path(args.out).resolve()
    if case.exists() and any(case.iterdir()):
        raise ValueError(f"output is not empty: {case}")
    case.mkdir(parents=True, exist_ok=True)
    samples = []
    for raw in args.sample:
        path = Path(raw).expanduser().resolve()
        if not path.is_file():
            raise ValueError(f"sample not found: {path}")
        samples.append({"path": str(path), "name": path.name, "sha256": sha256(path)})
    stages = {name: {"status": "pending", "updated": None, "note": ""} for name in STAGES}
    manifest = {
        "schema": 1,
        "case": args.name,
        "created": now(),
        "scope": "authorized research / own build",
        "target": {
            "package": args.package or "",
            "unity": args.unity or "",
            "il2cpp": args.il2cpp or "",
            "abi": args.abi,
            "version": args.version or "",
            "build_id": args.build_id or "",
            "device": args.device or "",
            "module": args.module,
        },
        "samples": samples,
        "address_model": {
            "module": args.module,
            "image_base": args.image_base,
            "rva_formula": "runtime_address = module_base + static_rva",
            "pac_or_thumb": "unknown",
        },
        "artifacts": [],
        "stages": stages,
    }
    (case / "case.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (case / "notes.md").write_text(
        "# Analysis Notes\n\n"
        "Record trigger steps, hook points, address corrections, and conclusions here.\n",
        encoding="utf-8",
    )
    print(f"Created case: {case}")
    print(f"Manifest: {case / 'case.json'}")


def mark_stage(args):
    case, manifest_path, manifest = load_case(args.case)
    if args.stage not in manifest["stages"]:
        raise ValueError(f"unknown stage: {args.stage}")
    def update(value):
        value["stages"][args.stage] = {"status": args.status, "updated": now(),
                                        "note": args.note or ""}
    update_manifest(manifest_path, update)
    print(f"Updated {args.stage}: {args.status}")


def verify_case(args):
    case, manifest_path, manifest = load_case(args.case)
    failures = []
    for sample in manifest.get("samples", []):
        path = Path(sample["path"])
        if not path.is_file():
            failures.append(f"missing sample: {path}")
            continue
        actual = sha256(path)
        if actual.lower() != sample["sha256"].lower():
            failures.append(f"hash changed: {path} expected={sample['sha256']} actual={actual}")
    for artifact in manifest.get("artifacts", []):
        path = Path(artifact["path"])
        if not path.is_file():
            failures.append(f"missing artifact: {path}")
        elif artifact.get("sha256") and sha256(path).lower() != artifact["sha256"].lower():
            failures.append(f"artifact hash changed: {path}")
    completed = [name for name, value in manifest.get("stages", {}).items()
                 if value.get("status") == "completed"]
    print(f"Case: {case}")
    print(f"Completed stages: {len(completed)}/{len(STAGES)}")
    if args.require_complete and len(completed) != len(STAGES):
        failures.append("workflow is not complete")
    if failures:
        for failure in failures:
            print("[FAIL]", failure)
        return 2
    print("Verification: OK")
    return 0


def add_artifact(args):
    case, manifest_path, manifest = load_case(args.case)
    path = Path(args.path).expanduser().resolve()
    if not path.is_file():
        raise ValueError(f"artifact not found: {path}")
    record = {
        "name": args.name or path.name,
        "path": str(path),
        "kind": args.kind,
        "sha256": sha256(path),
        "added": now(),
    }
    def update(value):
        items = value.setdefault("artifacts", [])
        items[:] = [item for item in items if item.get("path") != record["path"]]
        items.append(record)
    update_manifest(manifest_path, update)
    print(f"Recorded artifact: {record['name']} ({record['sha256']})")


def add_event(args):
    case, _, manifest = load_case(args.case)
    event = {"time": now(), "kind": args.kind, "note": args.note or ""}
    if args.data:
        try:
            event["data"] = json.loads(args.data)
        except json.JSONDecodeError as exc:
            raise ValueError("--data must be valid JSON") from exc
    events = case / "events.jsonl"
    with events.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, ensure_ascii=False) + "\n")
    print(f"Recorded event: {args.kind}")


def add_matrix(args):
    case, manifest_path, _ = load_case(args.case)
    record = {"time": now(), "status": args.status, "unity": args.unity or "",
              "abi": args.abi or "", "frida": args.frida or "", "device": args.device or "",
              "note": args.note or ""}
    def update(value):
        value.setdefault("compatibility", []).append(record)
    update_manifest(manifest_path, update)
    print(f"Recorded compatibility result: {args.status}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("init", help="Create a case manifest and notes file")
    create.add_argument("--name", required=True)
    create.add_argument("--out", required=True, type=Path)
    create.add_argument("--package")
    create.add_argument("--abi", default="arm64-v8a")
    create.add_argument("--unity")
    create.add_argument("--il2cpp")
    create.add_argument("--version")
    create.add_argument("--build-id")
    create.add_argument("--device")
    create.add_argument("--module", default="libil2cpp.so")
    create.add_argument("--image-base", default="0x0")
    create.add_argument("--sample", action="append", default=[],
                        help="Sample path; repeat for APK, SO, metadata, DLL, and bundles")
    create.set_defaults(func=init_case)

    mark = sub.add_parser("mark", help="Update one workflow stage")
    mark.add_argument("--case", required=True, type=Path)
    mark.add_argument("--stage", required=True, choices=STAGES)
    mark.add_argument("--status", required=True, choices=["pending", "in_progress", "completed", "blocked"])
    mark.add_argument("--note")
    mark.set_defaults(func=mark_stage)

    artifact = sub.add_parser("artifact", help="Record a generated artifact and its hash")
    artifact.add_argument("--case", required=True, type=Path)
    artifact.add_argument("--path", required=True, type=Path)
    artifact.add_argument("--kind", default="other",
                          help="artifact kind, e.g. classes, symbols, trace, dumpso, hot-dll")
    artifact.add_argument("--name")
    artifact.set_defaults(func=add_artifact)

    event = sub.add_parser("event", help="Append a trigger or evidence event to events.jsonl")
    event.add_argument("--case", required=True, type=Path)
    event.add_argument("--kind", required=True,
                       help="event kind, e.g. trigger, hook, network, state-change")
    event.add_argument("--note")
    event.add_argument("--data", help="JSON object with structured event data")
    event.set_defaults(func=add_event)

    matrix = sub.add_parser("matrix", help="Record a tested environment combination")
    matrix.add_argument("--case", required=True, type=Path)
    matrix.add_argument("--status", required=True, choices=["verified", "partial", "failed", "unverified"])
    matrix.add_argument("--unity")
    matrix.add_argument("--abi")
    matrix.add_argument("--frida")
    matrix.add_argument("--device")
    matrix.add_argument("--note")
    matrix.set_defaults(func=add_matrix)

    verify = sub.add_parser("verify", help="Verify sample hashes and recorded artifacts")
    verify.add_argument("--case", required=True, type=Path)
    verify.add_argument("--require-complete", action="store_true",
                        help="fail unless every workflow stage is completed")
    verify.set_defaults(func=verify_case)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("[error]", exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
