"""Compare two IL2CPP JSON artifacts without attaching to a process."""
import argparse
import json
from pathlib import Path


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def classes(value):
    found = {}

    def walk(node):
        if isinstance(node, dict):
            for item in node.get("classes", []) if isinstance(node.get("classes"), list) else []:
                key = "%s.%s" % (item.get("namespace", ""), item.get("name", ""))
                found[key] = item
            for child in node.values():
                if isinstance(child, (dict, list)):
                    walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)
    walk(value)
    return found


def method_key(cls, method):
    return "%s::%s(%s)" % (cls, method.get("name", ""), ",".join(method.get("params", [])))


def compare(left, right):
    a, b = classes(load(left)), classes(load(right))
    added, removed, changed = [], [], []
    for name in sorted(set(b) - set(a)):
        added.append(name)
    for name in sorted(set(a) - set(b)):
        removed.append(name)
    for name in sorted(set(a) & set(b)):
        am = {method_key(name, m): m for m in a[name].get("methods", [])}
        bm = {method_key(name, m): m for m in b[name].get("methods", [])}
        for key in sorted(set(am) | set(bm)):
            if key not in am or key not in bm:
                changed.append({"class": name, "method": key,
                                "change": "added" if key in bm else "removed"})
            elif am[key].get("rva") != bm[key].get("rva"):
                changed.append({"class": name, "method": key, "change": "rva",
                                "left": am[key].get("rva"), "right": bm[key].get("rva")})
        af = {f.get("name"): f for f in a[name].get("fields", [])}
        bf = {f.get("name"): f for f in b[name].get("fields", [])}
        for field in sorted(set(bf) - set(af)):
            changed.append({"class": name, "field": field, "change": "added",
                            "right": bf[field]})
        for field in sorted(set(af) - set(bf)):
            changed.append({"class": name, "field": field, "change": "removed",
                            "left": af[field]})
        for field in sorted(set(af) & set(bf)):
            if af[field].get("type") != bf[field].get("type"):
                changed.append({"class": name, "field": field, "change": "type",
                                "left": af[field].get("type"), "right": bf[field].get("type")})
            if af[field].get("offset") != bf[field].get("offset"):
                changed.append({"class": name, "field": field, "change": "offset",
                                "left": af[field].get("offset"), "right": bf[field].get("offset")})
    return {"left": str(Path(left).resolve()), "right": str(Path(right).resolve()),
            "class_counts": {"left": len(a), "right": len(b)},
            "added_classes": added, "removed_classes": removed, "changes": changed,
            "summary": {"added_classes": len(added), "removed_classes": len(removed),
                        "changes": len(changed)}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("left", type=Path)
    parser.add_argument("right", type=Path)
    parser.add_argument("--json", type=Path, help="also write a machine-readable report")
    args = parser.parse_args(argv)
    report = compare(args.left, args.right)
    print("Classes: %d -> %d" % (report["class_counts"]["left"], report["class_counts"]["right"]))
    print("Added classes: %d" % len(report["added_classes"]))
    print("Removed classes: %d" % len(report["removed_classes"]))
    print("Method/field changes: %d" % len(report["changes"]))
    for key in ("added_classes", "removed_classes"):
        for item in report[key]:
            print("  %s: %s" % (key[:-1], item))
    for item in report["changes"]:
        print("  change: %s" % json.dumps(item, ensure_ascii=False))
    if args.json:
        args.json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
