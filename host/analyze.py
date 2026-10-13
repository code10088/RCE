#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analyze.py —— PC 端分析 harness 产出的 jsonl / json

放在 PC 上算比在手机里快几个数量级，且不受进程内存限制。

用法:
  # Stalker 追踪结果：统计高频基本块、找平坦化调度器
  python analyze.py stalker-block.jsonl --top 30
  python analyze.py stalker-xor.jsonl --xor-key        # 推 XOR 密钥（看操作数分布）
  python analyze.py stalker-call.jsonl --callees 20    # 谁被调用最多

  # 堆字符串：找 URL / 密钥
  python analyze.py heap_strings.json --secrets
  python analyze.py heap_strings.json --grep "https?://"

  # dump 结果：搜类/方法
  python analyze.py classes.json --find-class Player
  python analyze.py classes.json --find-method AddGold
"""
import argparse
import json
import re
import sys
from collections import Counter


def load(path):
    """jsonl 或 json 都能读"""
    txt = open(path, "r", encoding="utf-8", errors="replace").read().strip()
    if not txt:
        return []
    # 先试整体 JSON
    if txt[0] in "[{":
        try:
            v = json.loads(txt)
            return v if isinstance(v, list) else [v]
        except Exception:
            pass
    # 退化成 jsonl
    out = []
    for line in txt.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out


def cmd_block(recs, args):
    """基本块分析 —— 反控制流平坦化"""
    blocks = Counter()
    for r in recs:
        b = r.get("block") or r.get("rva") or r.get("addr")
        if b:
            blocks[b] += 1
    total = sum(blocks.values())
    print("基本块执行总次数: %d，唯一块: %d" % (total, len(blocks)))
    print()
    print("执行次数最多的块（前 %d）—— 极可能是平坦化的调度器/主循环:" % args.top)
    print("%-20s %8s %8s %s" % ("RVA/ADDR", "次数", "占比", "符号"))
    for b, c in blocks.most_common(args.top):
        sym = ""
        for r in recs:
            if (r.get("block") or r.get("rva") or r.get("addr")) == b:
                sym = r.get("symbol") or ""
                break
        print("%-20s %8d %7.1f%% %s" % (b, c, 100.0 * c / max(total, 1), sym[:50]))
    if len(blocks) and blocks.most_common(1)[0][1] > total * 0.3:
        top_b, top_c = blocks.most_common(1)[0]
        print()
        print(">> 提示：块 %s 占了 %.1f%% 的执行次数，典型的控制流平坦化调度器特征。"
              % (top_b, 100.0 * top_c / total))
        print(">> 建议：把它和相邻的高频块排除掉，剩下的低频块才是真实业务逻辑。")


def cmd_xor(recs, args):
    """XOR 分析 —— 推密钥常量"""
    vals = Counter()
    for r in recs:
        regs = r.get("regs") or {}
        # x1 常是第二操作数（立即数/密钥），x0 是目标
        for k in ("x1", "x2", "x3"):
            v = regs.get(k)
            if v and v != "0x0":
                vals[v] += 1
    print("操作数出现频次（前 %d）—— 反复出现的常量大概率是密钥/轮常量:" % args.top)
    for v, c in vals.most_common(args.top):
        try:
            n = int(v, 16)
            print("  %-20s x%-6d  = %d (0x%x)" % (v, c, n, n))
        except Exception:
            print("  %-20s x%d" % (v, c))
    print()
    print(">> 下一步：把这些常量按出现顺序排列，就是算法的密钥流；"
          "拿真实输入/输出在 Python 里复现验证。")


def cmd_callees(recs, args):
    calls = Counter()
    for r in recs:
        t = r.get("addr") or r.get("rva")
        if t:
            calls[(t, r.get("symbol", ""), r.get("module", ""))] += 1
    print("被调用最多的目标（前 %d）:" % args.top)
    for (a, s, m), c in calls.most_common(args.top):
        print("  %-20s x%-6d %-30s %s" % (a, c, s[:30], m))


SECRET_PAT = re.compile(
    r"(https?://[^\s\"']+|api[_-]?key|secret|token|password|passwd|pwd|"
    r"access[_-]?key|private[_-]?key|BEGIN [A-Z ]*PRIVATE KEY|aes|rsa|md5|sha1|sha256|"
    r"bearer|authorization)", re.I)


def cmd_strings(recs, args):
    items = []
    for r in recs:
        if isinstance(r, dict) and "text" in r:
            items.append((r.get("addr", ""), r["text"]))
    print("共 %d 条字符串" % len(items))
    pat = re.compile(args.grep, re.I) if args.grep else (SECRET_PAT if args.secrets else None)
    if not pat:
        print("（未指定 --secrets / --grep，只做长度排序预览）")
        for a, s in sorted(items, key=lambda x: -len(x[1]))[:args.top]:
            print("  %-18s %s" % (a, s[:160]))
        return
    hits = [(a, s) for a, s in items if pat.search(s)]
    print("命中 %d 条:" % len(hits))
    for a, s in hits[:args.top]:
        print("  %-18s %s" % (a, s[:200]))


def walk_classes(node, out):
    if isinstance(node, dict):
        if "classes" in node:
            for c in node["classes"]:
                out.append(c)
        for v in node.values():
            if isinstance(v, (dict, list)):
                walk_classes(v, out)
    elif isinstance(node, list):
        for v in node:
            walk_classes(v, out)


def cmd_classes(recs, args):
    classes = []
    walk_classes(recs, classes)
    print("共 %d 个类" % len(classes))
    if args.find_class:
        for c in classes:
            full = "%s.%s" % (c.get("namespace", ""), c.get("name", ""))
            if args.find_class.lower() in full.lower():
                print("\n== %s (实例大小 %s, 父类 %s)" %
                      (full, c.get("instanceSize"), c.get("parent")))
                for m in c.get("methods", [])[:args.top]:
                    print("   %-10s %s(%s) -> %s" %
                          (m.get("rva", ""), m.get("name", ""),
                           ", ".join(m.get("params", [])), m.get("ret", "")))
                for f in c.get("fields", [])[:args.top]:
                    print("   field +%s %s %s" %
                          (f.get("offset"), f.get("type"), f.get("name")))
    if args.find_method:
        print("\n== 方法搜索: %s" % args.find_method)
        n = 0
        for c in classes:
            full = "%s.%s" % (c.get("namespace", ""), c.get("name", ""))
            for m in c.get("methods", []):
                if args.find_method.lower() in (m.get("name") or "").lower():
                    print("   %-10s %s::%s(%s) -> %s" %
                          (m.get("rva", ""), full, m.get("name"),
                           ", ".join(m.get("params", [])), m.get("ret", "")))
                    n += 1
                    if n >= args.top:
                        break


def cmd_boundary(recs, args):
    """Classify methods by the evidence available in a runtime/static dump."""
    classes = []
    walk_classes(recs, classes)
    report = {"aot_native": [], "managed_or_interpreted": [], "unknown": [], "counts": {}}
    for cls in classes:
        full = "%s.%s" % (cls.get("namespace", ""), cls.get("name", ""))
        for method in cls.get("methods", []):
            item = {"class": full, "method": method.get("name", ""),
                    "rva": method.get("rva"), "params": method.get("params", [])}
            rva = str(method.get("rva", ""))
            if rva and rva not in ("0", "0x0", "None", "null"):
                report["aot_native"].append(item)
            elif method.get("isVirtual") or method.get("runtimeInvoke"):
                report["managed_or_interpreted"].append(item)
            else:
                report["unknown"].append(item)
    report["counts"] = {key: len(value) for key, value in report.items() if key != "counts"}
    if args.json:
        with open(args.json, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, ensure_ascii=False)
    print(json.dumps(report["counts"], ensure_ascii=False))
    for key in ("managed_or_interpreted", "unknown"):
        for item in report[key][:args.top]:
            print("  %-24s %s::%s" % (key, item["class"], item["method"]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--mode", default="auto",
                     choices=["auto", "block", "xor", "call", "strings", "classes", "boundary"])
    ap.add_argument("--top", type=int, default=30)
    ap.add_argument("--xor-key", action="store_true")
    ap.add_argument("--callees", type=int)
    ap.add_argument("--secrets", action="store_true")
    ap.add_argument("--grep", help="字符串模式里的正则")
    ap.add_argument("--find-class")
    ap.add_argument("--find-method")
    ap.add_argument("--json", help="write a boundary/diff report")
    args = ap.parse_args()

    recs = load(args.file)
    if not recs:
        print("没读到数据: %s" % args.file)
        return 1

    # 自动判断
    mode = args.mode
    if mode == "auto":
        first = recs[0] if isinstance(recs[0], dict) else {}
        if "block" in first:
            mode = "block"
        elif "regs" in first:
            mode = "xor"
        elif "text" in first:
            mode = "strings"
        elif "classes" in str(recs[0])[:400]:
            mode = "classes"
        else:
            mode = "call"

    if mode == "block":
        cmd_block(recs, args)
    elif mode == "xor" or args.xor_key:
        cmd_xor(recs, args)
    elif mode == "call" or args.callees:
        cmd_callees(recs, args)
    elif mode == "strings":
        cmd_strings(recs, args)
    elif mode == "classes":
        cmd_classes(recs, args)
    elif mode == "boundary":
        cmd_boundary(recs, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
