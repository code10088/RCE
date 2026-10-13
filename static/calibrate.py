"""Generate a checked static-address -> runtime-address calibration report."""
import argparse
import json
from pathlib import Path


def walk(node, out):
    if isinstance(node, dict):
        for cls in node.get("classes", []) if isinstance(node.get("classes"), list) else []:
            full = "%s.%s" % (cls.get("namespace", ""), cls.get("name", ""))
            for method in cls.get("methods", []):
                rva = method.get("rva")
                if rva not in (None, "", "0", "0x0", 0):
                    out.append({"class": full, "method": method.get("name", ""),
                                "rva": rva, "params": method.get("params", [])})
        for value in node.values():
            if isinstance(value, (dict, list)):
                walk(value, out)
    elif isinstance(node, list):
        for value in node:
            walk(value, out)


def integer(value):
    return int(str(value), 0)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("classes", type=Path)
    parser.add_argument("--module-base", required=True, help="runtime module base, e.g. 0x7a00000000")
    parser.add_argument("--image-base", default="0x0")
    parser.add_argument("--address-kind", choices=["rva", "va"], default="rva",
                        help="interpret classes.json addresses as RVA (default) or static VA")
    parser.add_argument("--module", default="libil2cpp.so")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    data = json.loads(args.classes.read_text(encoding="utf-8-sig"))
    methods = []
    walk(data, methods)
    base, image = integer(args.module_base), integer(args.image_base)
    for item in methods:
        rva = integer(item["rva"])
        item["module"] = args.module
        item["image_base"] = hex(image)
        item["module_base"] = hex(base)
        item["runtime_address"] = hex(base + rva if args.address_kind == "rva" else base + rva - image)
    formula = "runtime_address = module_base + rva" if args.address_kind == "rva" else \
              "runtime_address = module_base + static_va - image_base"
    report = {"module": args.module, "module_base": hex(base), "image_base": hex(image),
              "address_kind": args.address_kind, "formula": formula,
              "count": len(methods), "methods": methods}
    args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("Wrote %d calibrated methods to %s" % (len(methods), args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
