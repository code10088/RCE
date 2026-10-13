#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
il2cpp-harness / host 端驱动
用法示例（Windows PowerShell / macOS / Linux 通用）：

  # 1) 转储所有类/方法（含 RVA），输出 classes.json + script.json
  python run.py --pkg com.your.game --mode dump

  # 2) 只转储指定 image，并按类名过滤
  python run.py --pkg com.your.game --mode dump --images Assembly-CSharp.dll --class-filter "Game\\.Net"

  # 3) trace 某个方法（打印参数，自动识别 string）
  python run.py --pkg com.your.game --mode trace --ns Game.Net --cls LoginMgr --method SendLogin --argc 3

  # 4) 全局拦截 il2cpp_runtime_invoke（抓 HybridCLR 热更方法调用）
  python run.py --pkg com.your.game --mode invoke --filter HotUpdate

  # 5) 指令级追踪（对付 Obfuz / OLLVM 混淆）：hook 方法，只在它执行期间追
  python run.py --pkg com.your.game --mode stalk --cls CryptoUtil --method Encrypt --stalk-mode xor
  python run.py --pkg com.your.game --mode stalk --cls LoginMgr --method OnLogin --stalk-mode call
  #    按 IDA 里看到的 RVA 直接追（十六进制，可带 0x）
  python run.py --pkg com.your.game --mode stalk --rva 0x1A2B3C --stalk-mode block

  # 6) 网络抓包：进程内 hook SSL_read/SSL_write 拿明文，不需要装 CA 证书、不受 pinning 影响
  python run.py --pkg com.your.game --mode net
  python run.py --pkg com.your.game --mode net --force-socket      # 强制走 libc send/recv 兜底

  # 7) 内存扫描（CE 式多次过滤收敛）
  python run.py --pkg com.your.game --mode scan    # 进入交互：scan -> 改值 -> refine -> list

  # 8) 导出可直接运行的反汇编器导入脚本（批量把 sub_XXX 重命名成 C# 方法名）
  python run.py --pkg com.your.game --mode symbols --target ghidra
  python run.py --pkg com.your.game --mode symbols --target ida

  # 9) 抓 Unity 日志（不用开 logcat）、扫堆里所有存活字符串（找 URL/密钥）
  python run.py --pkg com.your.game --mode unitylog
  python run.py --pkg com.your.game --mode strings --grep "https?://"

  # 10) 批量 hook（正则匹配类名/方法名）
  python run.py --pkg com.your.game --mode batch --class-re "Manager$" --method-re "^(Init|Start)$"

  # 11) Java 层 hook（支付/登录/SDK 那一侧）
  python run.py --pkg com.your.game --mode java --java-cls com.unity3d.player.UnityPlayer

  # 12) 反检测：绕过目标检测 / 或审计自己暴露了多少特征
  python run.py --pkg com.your.game --mode anti --anti-action bypass
  python run.py --pkg com.your.game --mode anti --anti-action audit

  # 13) 性能剖析：统计方法调用次数与耗时
  python run.py --pkg com.your.game --mode prof --cls GameLoop --method Update --argc 0

  # 14) 主动调用方法（不只是 hook，是让游戏执行它）+ 读写静态字段
  python run.py --pkg com.your.game --mode exec --cls PlayerData --method AddGold --args "100"
  python run.py --pkg com.your.game --mode exec --cls Config --method GetUrl --args ""
  python run.py --pkg com.your.game --mode field --cls PlayerData --field-name hp --field-value 9999
  python run.py --pkg com.your.game --mode exec --time-scale 3          # 3 倍速调试

  # 15) 生成 dump.cs（Il2CppDumper 标准格式，喂给下游工具）
  python run.py --pkg com.your.game --mode dumpcs

  # 16) 从内存重建 libil2cpp.so（对抗 so 加固/加密）
  python run.py --pkg com.your.game --mode dumpso

  # 17) 抓解密后的 AssetBundle + 遍历场景 GameObject
  python run.py --pkg com.your.game --mode assets
  python run.py --pkg com.your.game --mode scene

  # 18) 文件 I/O 监控（找存档/配置路径）
  python run.py --pkg com.your.game --mode fileio --private-only

  # 19) 加密算法调用监控（先试这个，不行再上 stalk）
  python run.py --pkg com.your.game --mode crypto

# PC 端分析（不连手机，直接分析产出的文件）：
  python host/analyze.py out/xxx/xxx/stalker-block.jsonl --top 30   # 找平坦化调度器
  python host/analyze.py out/xxx/xxx/stalker-xor.jsonl --xor-key    # 推密钥常量
  python host/analyze.py out/xxx/xxx/heap_strings.json --secrets    # 找 URL/密钥
  python host/analyze.py out/xxx/xxx/classes.json --find-method AddGold

  # 5) 抓 HybridCLR 热更 DLL（spawn 模式，越早越好）
  python run.py --pkg com.your.game --mode hot

  # 6) 已运行的进程（attach 模式，可能错过早期 dll 加载）
  python run.py --attach 12345 --mode dump

  # 7) 交互式：拿到一个可执行 JS 的 REPL（evaljs）
  python run.py --pkg com.your.game --mode interactive

输出目录：./out/<pkg>/<时间戳>/
"""
import argparse
import os
import sys
import time
import threading
import datetime
import hashlib
import json
import uuid

try:
    import frida
except ImportError:
    print("[!] 缺少 frida：pip install frida frida-tools")
    sys.exit(1)

HERE = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.join(os.path.dirname(HERE), "agent")
DEFAULT_MODULE = "libil2cpp.so"


def configure_output():
    """Keep Frida/Unity diagnostics from crashing on a Windows GBK console."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            reconfigure(encoding="utf-8", errors="replace")


def load_agent(module_name=DEFAULT_MODULE):
    """按文件名顺序加载 agent；每个文件独立作用域，共享 globalThis API。"""
    files = sorted(f for f in os.listdir(AGENT_DIR) if f.endswith(".js"))
    if not files:
        raise RuntimeError("agent 目录为空: %s" % AGENT_DIR)
    parts = []
    for f in files:
        with open(os.path.join(AGENT_DIR, f), "r", encoding="utf-8") as fp:
            # Agent files intentionally publish APIs through globalThis, but
            # several use the same const names. Isolating each file prevents
            # duplicate lexical declarations after concatenation.
            parts.append("(function () {\n/* ===== %s ===== */\n%s\n})();" % (f, fp.read()))
    src = "\n".join(parts)
    # 允许覆盖模块名（Windows 是 GameAssembly.dll）
    src = src.replace("'libil2cpp.so'", "'%s'" % module_name)
    return src


class Harness:
    def __init__(self, outdir, case=None):
        self.outdir = outdir
        self.case = os.path.abspath(case) if case else None
        os.makedirs(outdir, exist_ok=True)
        self.text_buf = {}   # tag -> list of chunks
        self.done = threading.Event()
        self.session_id = uuid.uuid4().hex
        self.timeline = os.path.join(outdir, "session.jsonl")
        self.event("session", {"session_id": self.session_id})

    def event(self, kind, data=None):
        record = {"time": datetime.datetime.now().astimezone().isoformat(timespec="milliseconds"),
                  "session_id": self.session_id, "kind": kind, "data": data or {}}
        try:
            with open(self.timeline, "a", encoding="utf-8") as stream:
                stream.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError:
            pass

    def record_artifact(self, path, kind):
        if not self.case:
            return
        manifest_path = os.path.join(self.case, "case.json")
        if not os.path.isfile(manifest_path) or not os.path.isfile(path):
            return
        lock_path = manifest_path + ".lock"
        lock_fd = None
        try:
            # Small cross-process lock. The artifact path is deterministic, so
            # retrying is preferable to silently losing another session's entry.
            for _ in range(100):
                try:
                    lock_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                    break
                except FileExistsError:
                    time.sleep(0.02)
            if lock_fd is None:
                raise OSError("manifest lock timeout")
            digest = hashlib.sha256()
            with open(path, "rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            with open(manifest_path, "r", encoding="utf-8") as stream:
                manifest = json.load(stream)
            items = manifest.setdefault("artifacts", [])
            record = {"name": os.path.basename(path), "path": os.path.abspath(path),
                      "kind": kind, "sha256": digest.hexdigest(),
                      "added": datetime.datetime.now().astimezone().isoformat(timespec="seconds")}
            items[:] = [item for item in items if item.get("path") != record["path"]]
            items.append(record)
            with open(manifest_path, "w", encoding="utf-8") as stream:
                json.dump(manifest, stream, indent=2, ensure_ascii=False)
                stream.write("\n")
            self.event("artifact", {"path": os.path.abspath(path), "kind": kind,
                                     "sha256": record["sha256"]})
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print("[!] case artifact record failed: %s" % exc)
        finally:
            if lock_fd is not None:
                os.close(lock_fd)
                try:
                    os.unlink(lock_path)
                except OSError:
                    pass

    def on_message(self, message, data):
        self.event("message", {"type": message.get("type"),
                                "payload_type": (message.get("payload") or {}).get("t")})
        if message["type"] == "send":
            p = message.get("payload") or {}
            t = p.get("t")
            if t == "log":
                print(p.get("msg", ""))
                self.event("log", {"message": p.get("msg", "")})
            elif t == "text":
                self.text_buf.setdefault(p["tag"], []).append((p["i"], p["data"]))
            elif t == "text-end":
                chunks = sorted(self.text_buf.pop(p["tag"], []))
                text = "".join(c for _, c in chunks)
                name = os.path.basename(str(p.get("tag") or "text.txt"))
                path = os.path.join(self.outdir, name)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(text)
                print("[+] 已保存 %s (%.2f MB)" % (path, len(text) / 1024 / 1024))
                self.record_artifact(path, "text")
            elif t == "bin":
                name = os.path.basename(str(p.get("name") or ("bin_%d" % time.time())))
                path = os.path.join(self.outdir, name)
                blob = data if data else b""
                with open(path, "wb") as f:
                    f.write(blob)
                print("[+] 已保存 %s (%d bytes) src=%s" % (path, len(blob), p.get("src")))
                if p.get("devPath"):
                    print("    设备路径: %s" % p["devPath"])
                self.record_artifact(path, p.get("src") or "binary")
            else:
                print("[msg]", p)
        elif message["type"] == "error":
            print("[!] script error:\n%s" % message.get("stack", message.get("description")))
            self.event("error", {"stack": message.get("stack", message.get("description"))})
        else:
            print("[?]", message)


def get_device(device_id=None):
    if device_id:
        return frida.get_device(device_id)
    try:
        return frida.get_usb_device(timeout=5)
    except Exception:
        return frida.get_local_device()


def main():
    configure_output()
    ap = argparse.ArgumentParser()
    ap.add_argument("--pkg", help="目标包名（spawn 模式）")
    ap.add_argument("--attach", type=int, help="直接附加到 pid")
    ap.add_argument("--device", help="frida device id（多设备时用）")
    ap.add_argument("--module", default=DEFAULT_MODULE, help="il2cpp 模块名，默认 libil2cpp.so")
    ap.add_argument("--out", default="out", help="输出根目录")
    ap.add_argument("--mode", default="interactive",
                    choices=["dump", "trace", "invoke", "hot", "interactive", "idascript", "list",
                             "stalk", "net", "scan", "symbols", "unitylog", "strings", "batch",
                             "java", "anti", "prof", "exec", "field", "dumpcs", "dumpso",
                             "assets", "scene", "fileio", "crypto"])
    # net / scan / symbols 参数
    ap.add_argument("--target", default="ghidra", choices=["ghidra", "ida"], help="导出给哪个反汇编器")
    ap.add_argument("--force-socket", action="store_true", help="net 模式强制走 libc send/recv 兜底")
    ap.add_argument("--dump-full", action="store_true", help="net 模式回传完整包（默认只预览前 256B）")
    # strings / batch / java / anti / prof 参数
    ap.add_argument("--grep", help="strings 模式的字符串过滤正则")
    ap.add_argument("--class-re", help="batch 模式的类名正则")
    ap.add_argument("--method-re", help="batch 模式的方法名正则")
    ap.add_argument("--java-cls", help="java 模式的目标类名")
    ap.add_argument("--java-method", help="java 模式的方法名")
    ap.add_argument("--anti-action", default="audit", choices=["bypass", "audit", "watch"],
                    help="anti 模式：绕过检测 / 自检 / 持续监控")
    # exec / field / fileio / scene 参数
    ap.add_argument("--args", help="exec 模式参数，逗号分隔，如 \"100,hello,3.14\"")
    ap.add_argument("--obj", help="exec 模式的实例地址（实例方法用）")
    ap.add_argument("--field-name", help="field 模式的字段名")
    ap.add_argument("--field-value", help="field 模式要写入的值（不填=只读）")
    ap.add_argument("--time-scale", help="exec 模式：设置 Unity Time.timeScale 倍速")
    ap.add_argument("--private-only", action="store_true", help="fileio 只看游戏私有目录")
    ap.add_argument("--scene-type", default="GameObject", help="scene 模式要列出的类型")
    # stalk 参数
    ap.add_argument("--stalk-mode", default="xor",
                    choices=["call", "block", "insn", "xor", "table", "mul", "branch"],
                    help="call=调用树 block=基本块(反平坦化) insn=逐指令 xor/table/mul/branch=算法还原预设")
    ap.add_argument("--rva", help="按 RVA 追踪（相对 libil2cpp.so，十六进制）")
    ap.add_argument("--max-records", type=int, default=20000, help="追踪记录上限，超出丢弃")
    ap.add_argument("--tag", help="输出文件名前缀")
    # trace / resolve 参数
    ap.add_argument("--ns", default="", help="命名空间")
    ap.add_argument("--cls", help="类名")
    ap.add_argument("--method", help="方法名")
    ap.add_argument("--argc", type=int, default=-1, help="参数个数，-1 表示不限")
    ap.add_argument("--filter", default="", help="invoke 模式的过滤子串")
    ap.add_argument("--images", default="", help="只处理这些 image，逗号分隔")
    ap.add_argument("--class-filter", default="", help="类名正则过滤")
    ap.add_argument("--device-path", default="", help="同时在设备上落盘的路径")
    ap.add_argument("--case", help="案件目录；自动把动态产物登记到 case.json")
    ap.add_argument("--allow-eval", action="store_true",
                    help="interactive 模式允许执行进程内 JavaScript；默认禁用")
    ap.add_argument("--late-agent", action="store_true",
                    help="spawn 模式先 resume 最小脚本，再延迟加载完整 Agent")
    ap.add_argument("--startup-delay", type=float, default=20.0,
                    help="--late-agent 在加载完整 Agent 前等待秒数")
    args = ap.parse_args()

    if not args.pkg and not args.attach:
        ap.error("需要 --pkg 或 --attach")

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    name = args.pkg or ("pid%d" % args.attach)
    outdir = os.path.join(args.out, name, ts)
    harness = Harness(outdir, args.case)

    device = get_device(args.device)
    print("[*] device: %s" % device)

    if args.attach:
        session = device.attach(args.attach)
        pid = args.attach
        print("[*] attached pid=%d" % pid)
    else:
        pid = device.spawn([args.pkg])
        session = device.attach(pid)
        print("[*] spawned pid=%d, 注入后 resume" % pid)

    if args.late_agent and not args.attach:
        # Keep the application moving during Unity startup. The full Agent
        # performs native API discovery and should not run while the process
        # is still blocked at its entry point.
        bootstrap = session.create_script(
            "rpc.exports = { ping: function () { return 'bootstrap-ready'; } };"
        )
        bootstrap.load()
        device.resume(pid)
        harness.event("bootstrap_resumed", {"pid": pid, "delay": args.startup_delay})
        time.sleep(max(0.0, args.startup_delay))
        try:
            bootstrap.unload()
        except Exception:
            pass

    script = session.create_script(load_agent(args.module))
    script.on("message", harness.on_message)
    script.load()
    harness.event("attached", {"pid": pid, "device": str(device), "module": args.module,
                                "mode": args.mode, "package": args.pkg or "",
                                "late_agent": bool(args.late_agent)})
    if not args.attach and not args.late_agent:
        device.resume(pid)

    # 等待 il2cpp 就绪（rpc 内部会 pend 住直到就绪，这里只做提示）
    time.sleep(0.3)

    exports = script.exports_sync if hasattr(script, "exports_sync") else script.exports

    def call(fn, *a):
        return fn(*a)

    try:
        # Most RPCs depend on IL2CPP. Fail clearly instead of leaving a
        # Promise pending forever when an x86_64 Houdini process maps only an
        # ARM64 libil2cpp image that Frida cannot expose as a native module.
        if args.mode not in ("hot", "net", "anti"):
            deadline = time.time() + 65
            health = None
            while time.time() < deadline:
                health = call(exports.health)
                if health.get("ready"):
                    break
                if health.get("error"):
                    raise RuntimeError("IL2CPP unavailable: %s (Frida arch=%s, module=%s)" %
                                       (health.get("error"), health.get("arch"), health.get("module")))
                time.sleep(0.25)
            else:
                raise RuntimeError("IL2CPP readiness probe timed out: %s" % health)
        if args.mode == "dump":
            opts = {}
            if args.images:
                opts["images"] = [s.strip() for s in args.images.split(",")]
            if args.class_filter:
                opts["classFilter"] = args.class_filter
            if args.device_path:
                opts["devicePath"] = args.device_path
            print(call(exports.dumpall, "classes.json", opts))
            print(call(exports.idascript, "script.json",
                       [s.strip() for s in args.images.split(",")] if args.images else None))
            print("[*] dump 完成，Ctrl+C 退出")
        elif args.mode == "idascript":
            print(call(exports.idascript, "script.json",
                       [s.strip() for s in args.images.split(",")] if args.images else None))
        elif args.mode == "list":
            print(call(exports.listimages))
            print("[*] 完成")
        elif args.mode == "trace":
            if not args.cls or not args.method:
                ap.error("trace 需要 --cls 和 --method")
            print(call(exports.trace, args.ns, args.cls, args.method, args.argc))
            print("[*] 已挂 hook，日志实时输出，Ctrl+C 结束")
        elif args.mode == "net":
            opts = {"dumpFull": args.dump_full, "forceSocket": args.force_socket}
            print(call(exports.netsniff, opts))
            print("[*] 网络 hook 已装，明文实时打印，Ctrl+C 结束")
        elif args.mode == "symbols":
            print(call(exports.exportsym, args.target,
                       [s.strip() for s in args.images.split(",")] if args.images else None))
            print("[*] 导入脚本已生成，Ctrl+C 退出")
        elif args.mode == "scan":
            print("[*] 内存扫描交互模式（像 Cheat Engine 那样多次过滤收敛）")
            print("    命令: scan <type> <值> | refine <新值> | list [n] | read <addr> | "
                  "watch <addr> | ranges | write <addr> <值> | quit")
            print("    type = i8/i16/i32/i64/f32/f64/str")
            while True:
                try:
                    line = input("scan> ").strip()
                except EOFError:
                    break
                if not line:
                    continue
                parts = line.split()
                cmd = parts[0].lower()
                try:
                    if cmd in ("quit", "exit", "q"):
                        break
                    elif cmd == "scan" and len(parts) >= 3:
                        v = parts[2] if parts[1] != "str" else " ".join(parts[2:])
                        v = int(float(v)) if parts[1] != "str" else v
                        print(call(exports.memscan, parts[1], v, {}))
                    elif cmd == "refine" and len(parts) >= 2:
                        print(call(exports.memrefine, int(float(parts[1])), {}))
                    elif cmd == "list":
                        print(call(exports.memlist, int(parts[1]) if len(parts) > 1 else 50))
                    elif cmd == "read" and len(parts) >= 2:
                        print(call(exports.memread, parts[1], parts[2] if len(parts) > 2 else None))
                    elif cmd == "write" and len(parts) >= 3:
                        print(call(exports.memwrite, parts[1], int(float(parts[2])),
                                  parts[3] if len(parts) > 3 else None))
                    elif cmd == "watch" and len(parts) >= 2:
                        print(call(exports.memwatch, parts[1],
                                  int(parts[2]) if len(parts) > 2 else 8))
                    elif cmd == "ranges":
                        print(call(exports.memranges))
                    else:
                        print("    未知命令或参数不足")
                except Exception as e:
                    print("    [!] " + str(e))
        elif args.mode == "unitylog":
            print(call(exports.unitylog))
            print("[*] Unity 日志实时输出，Ctrl+C 结束")
        elif args.mode == "strings":
            print(call(exports.heapstrings, {"filter": args.grep} if args.grep else {}))
            print("[*] 扫完自动保存 heap_strings.json，Ctrl+C 退出")
        elif args.mode == "batch":
            if not args.class_re and not args.method_re:
                ap.error("batch 需要 --class-re 或 --method-re")
            print(call(exports.hookbatch, args.class_re, args.method_re, {"maxHooks": 200}))
            print("[*] 批量 hook 已装，Ctrl+C 结束")
        elif args.mode == "java":
            if args.java_cls and args.java_method:
                print(call(exports.javahook, args.java_cls, args.java_method))
                print("[*] Java hook 已装，Ctrl+C 结束")
            elif args.java_cls:
                print(call(exports.javalist, args.java_cls))
            else:
                ap.error("java 需要 --java-cls")
        elif args.mode == "anti":
            if args.anti_action == "bypass":
                print(call(exports.antijam, {}))
                print("[*] 反检测绕过已装，Ctrl+C 结束")
            elif args.anti_action == "watch":
                print(call(exports.antiwatch))
                print("[*] 监控已装，Ctrl+C 结束（结束前会打一次报告）")
            else:
                print(call(exports.antiaudit))
                print("[*] 自检完成，Ctrl+C 退出")
        elif args.mode == "prof":
            if not args.cls or not args.method:
                ap.error("prof 需要 --cls 和 --method")
            print(call(exports.profstart, args.ns, args.cls, args.method, args.argc))
            print("[*] 统计中，Ctrl+C 结束（结束前会输出报告）")
        elif args.mode == "exec":
            if args.time_scale is not None:
                print(call(exports.timescale, args.time_scale))
            else:
                if not args.cls or not args.method:
                    ap.error("exec 需要 --cls 和 --method（或用 --time-scale 设倍速）")
                arglist = [s.strip() for s in args.args.split(",")] if args.args else []
                print(call(exports.call, args.ns, args.cls, args.method, arglist, args.obj))
            print("[*] 调用完成，Ctrl+C 退出")
        elif args.mode == "field":
            if not args.cls:
                ap.error("field 需要 --cls")
            if not args.field_name:
                # 不给字段名 = 列出全部静态字段当前值（看全局配置/开关最快）
                print(call(exports.dumpstatics, args.ns, args.cls))
                print("[*] Ctrl+C 退出")
            elif args.field_value is not None:
                print(call(exports.setfield, args.ns, args.cls, args.field_name, args.field_value))
            else:
                print(call(exports.getfield, args.ns, args.cls, args.field_name))
            print("[*] Ctrl+C 退出")
        elif args.mode == "dumpcs":
            print(call(exports.dumpcs,
                       [s.strip() for s in args.images.split(",")] if args.images else None))
            print("[*] dump.cs 已保存，Ctrl+C 退出")
        elif args.mode == "dumpso":
            print(call(exports.dumpso, {}))
            print("[*] so 已重建到设备，用 adb pull 取回，Ctrl+C 退出")
        elif args.mode == "assets":
            print(call(exports.assets, {"pull": args.dump_full}))
            print("[*] AB 加载捕获已装，Ctrl+C 结束")
        elif args.mode == "scene":
            print(call(exports.scene, {"type": args.scene_type, "limit": 200}))
            print("[*] 场景导出完成，Ctrl+C 退出")
        elif args.mode == "fileio":
            print(call(exports.fileio, {"onlyPrivateDir": args.private_only,
                                        "pkg": args.pkg, "backtrace": True}))
            print("[*] 文件监控已装，Ctrl+C 结束（结束前会打统计）")
        elif args.mode == "crypto":
            print(call(exports.crypto, {}))
            print("[*] 加密调用监控已装，Ctrl+C 结束")
        elif args.mode == "stalk":
            opts = {"maxRecords": args.max_records}
            if args.tag:
                opts["tag"] = args.tag
            if args.rva:
                print(call(exports.stalkrva, args.rva, args.stalk_mode, opts))
            else:
                if not args.cls or not args.method:
                    ap.error("stalk 需要 --cls 和 --method，或用 --rva 指定裸地址")
                print(call(exports.stalkmethod, args.ns, args.cls, args.method,
                            args.argc, args.stalk_mode, opts))
            print("[*] Stalker 已挂载：触发目标方法后自动追踪并回传，Ctrl+C 结束")
        elif args.mode == "invoke":
            print(call(exports.hookinvoke, args.filter))
            print("[*] 已拦截 il2cpp_runtime_invoke，Ctrl+C 结束")
        elif args.mode == "hot":
            print(call(exports.capturehot, {}))
            print("[*] 等待热更 DLL 加载…（抓到会自动保存到 %s）" % outdir)
        else:
            print("[*] interactive: 输入 JS；执行代码需显式加 --allow-eval")
            print("    可用全局: IL2CPP / Dump / Hook / HybridCLR / StalkerTrace / NetTrace")
            print("             MemScan / Anti / Extras / Invoke / Assets / DumpExtra / Monitor / H")
            print("")
            print("    查方法 RVA     IL2CPP.rva(IL2CPP.methodPointer(IL2CPP.findMethod(null,'Game','Player','AddGold',1).methods[0]))")
            print("    看字段偏移     Dump.dumpClass('Game','PlayerData')")
            print("    主动调方法     Invoke.callStatic('Game','PlayerData','AddGold',['100'])")
            print("    列静态字段     Invoke.dumpStatics('Game','Config')")
            print("    追踪实例创建   Extras.watchCtor('Game','PlayerData',{})")
            print("    抓实例列表     Extras.listInstances('PlayerData')")
            print("    手动 Stalker   StalkerTrace.startManual('call') ... StalkerTrace.stopManual('a.jsonl')")
            print("    扫网络符号     NetTrace.scanNetSymbols('ssl')")

        # 需要持续挂机的模式：等用户 Ctrl+C
        hang = args.mode in ("trace", "invoke", "hot", "interactive", "stalk", "net",
                             "unitylog", "batch", "prof", "assets", "fileio", "crypto") \
            or (args.mode == "anti" and args.anti_action == "watch") \
            or (args.mode == "java" and args.java_method)
        if hang:
            while True:
                if args.mode == "interactive":
                    try:
                        line = input("js> ").strip()
                    except EOFError:
                        break
                    if line in ("exit", "quit", "q"):
                        break
                    if not line:
                        continue
                    if not args.allow_eval:
                        print("[!] evaljs disabled; add --allow-eval only on an isolated authorized test device")
                        continue
                    print(call(exports.evaljs, line))
                else:
                    time.sleep(1)
        else:
            time.sleep(2)
    except KeyboardInterrupt:
        # 退出前把累计数据打出来，别白跑一趟
        try:
            if args.mode == "prof":
                print(call(exports.profreport))
            elif args.mode == "anti" and args.anti_action == "watch":
                print(call(exports.antireport))
            elif args.mode == "fileio":
                print(call(exports.filereport, 40))
        except Exception:
            pass
        print("\n[*] 退出")
    finally:
        try:
            session.detach()
        except Exception:
            pass
        print("[*] 输出目录: %s" % outdir)


if __name__ == "__main__":
    main()
