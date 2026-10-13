/**
 * 99-entry.js —— 入口：等待 il2cpp 就绪 + 暴露 rpc 给 host 端调用
 *
 * 加载顺序（host/run.py 会按文件名排序拼接，不要改名）：
 *   00-utils.js -> 10-il2cpp-api.js -> 20-dump.js -> 30-hook.js -> 40-hybridclr.js -> 99-entry.js
 *
 * 关键点：spawn 注入时进程停在入口、libil2cpp.so 尚未加载，
 *        必须轮询等待模块出现，再做 API 绑定和 hook。
 */
'use strict';
const G = globalThis;
const H = G.H;

let booted = false;
let bootErr = null;
let boundModule = null;
const pending = [];   // 就绪前排队的任务

/** 轮询等 libil2cpp.so 出现并完成 il2cpp 初始化 */
function waitIl2cpp(cb, timeoutMs) {
  timeoutMs = timeoutMs || 60000;
  const t0 = Date.now();
  const timer = setInterval(function () {
    const m = H.mod('libil2cpp.so');
    if (!m) {
      if (Date.now() - t0 > timeoutMs) { clearInterval(timer); cb('timeout: libil2cpp.so 未加载'); }
      return;
    }
    // Bind once per module. Rebinding every timer tick is expensive on startup.
    let ok = false;
    try {
      if (!boundModule || boundModule.base.toString() !== m.base.toString()) {
        G.bindIl2cpp();
        boundModule = m;
      }
      const d = G.IL2CPP.domain_get();
      // il2cpp_plus creates the domain before assemblies are loaded. The
      // assembly count is the actual readiness signal, without walking every
      // image on each poll.
      ok = d && !d.isNull() && G.IL2CPP.getAssemblyCount() > 0;
    } catch (e) { ok = false; }
    if (ok) {
      clearInterval(timer);
      cb(null);
    } else if (Date.now() - t0 > timeoutMs) {
      clearInterval(timer);
      cb('timeout: il2cpp 未初始化完成');
    }
  }, 250);
}

function boot() {
  if (booted) return;
  waitIl2cpp(function (err) {
    bootErr = err;
    booted = true;
    if (err) {
      send({ t: 'log', msg: '[!] il2cpp 就绪失败: ' + err });
      return;
    }
    send({ t: 'log', msg: '[*] il2cpp assemblies 就绪，继续加载 Agent' });
    // 执行就绪前排队的任务
    while (pending.length) {
      const f = pending.shift();
      try { f(); } catch (e) { send({ t: 'log', msg: '[!] pending 任务异常: ' + e }); }
    }
    // Self-check touches corlib and array metadata; keep it off the startup
    // readiness path so it cannot hold Unity's initialization loop.
    // Run allocations only on explicit request (or from dumpAll).
  });
}

/** 保证在 il2cpp 就绪后执行 */
function ensure(fn) {
  if (booted && !bootErr) fn();
  else pending.push(fn);
}

boot();

// ---------------- rpc 接口（host/run.py 调用） ----------------
rpc.exports = {
  selfcheck: function () {
    if (!booted || bootErr) throw new Error(bootErr || 'domain not ready');
    return H.selfCheck(G.IL2CPP);
  },
  /** Readiness probe used by host to fail fast on translated/unsupported runtimes. */
  health: function () {
    return { ready: booted && !bootErr, error: bootErr || '', arch: Process.arch,
      module: H.mod('libil2cpp.so') ? H.mod('libil2cpp.so').name : '' };
  },
  /** 全量转储 opts:{images:[],classFilter:str,devicePath:str} */
  dumpall: function (tag, opts) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.Dump.dumpAll(tag || 'classes.json', opts || {})); });
    });
  },
  /** 导出 IDA/Ghidra 用 script.json */
  idascript: function (tag, images) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.Dump.exportIdaScript(tag || 'script.json', images)); });
    });
  },
  listimages: function () {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.Dump.listImages()); });
    });
  },
  dumpclass: function (ns, name, image) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.Dump.dumpClass(ns, name, image)); });
    });
  },
  /** 查方法地址，不 hook */
  resolve: function (ns, cls, method, argc) {
    return new Promise(function (resolve) {
      ensure(function () {
        const r = G.IL2CPP.findMethod(null, ns, cls, method, argc == null ? -1 : argc);
        resolve(r.methods.map(mi => ({
          rva: G.IL2CPP.rva(G.IL2CPP.methodPointer(mi)).toString(),
          addr: G.IL2CPP.methodPointer(mi).toString()
        })));
      });
    });
  },
  /** hook 指定方法，只做日志（带参数 hexdump） */
  trace: function (ns, cls, method, argc) {
    return new Promise(function (resolve) {
      ensure(function () {
        resolve(G.Hook.hookMethod(ns, cls, method, argc == null ? -1 : argc, {
          onEnter(args) {
            const ps = [];
            for (let i = 0; i < args.length; i++) {
              let s = args[i].toString();
              try { const str = H.readStr(args[i]); if (str && /^[\x20-\x7e\u4e00-\u9fa5]{1,200}$/.test(str)) s += ' "' + str + '"'; } catch (e) {}
              ps.push(s);
            }
            send({ t: 'log', msg: '[trace] ' + cls + '::' + method + '\n  ' + ps.join('\n  ') });
          },
          onLeave(ret) { send({ t: 'log', msg: '[trace<-] ' + cls + '::' + method + ' ret=' + ret }); }
        }));
      });
    });
  },
  /**
   * 指令级追踪（Stalker）：hook 目标方法，只在它执行期间追踪
   * mode: call | block | insn | xor | table | mul | branch
   * opts: { maxRecords, tag, moduleName, mnemonics, withRegs }
   */
  stalkmethod: function (ns, cls, method, argc, mode, opts) {
    return new Promise(function (resolve) {
      ensure(function () {
        resolve(G.StalkerTrace.stalkMethod(ns, cls, method, argc, mode || 'xor', opts || {}));
      });
    });
  },
  /** 按 RVA 追踪（IDA/Ghidra 里定位到的裸地址） */
  stalkrva: function (rva, mode, opts) {
    return new Promise(function (resolve) {
      ensure(function () {
        resolve(G.StalkerTrace.stalkRva(rva, mode || 'xor', opts || {}));
      });
    });
  },
  /** 手动开始追踪主线程（interactive 里配合 stalkstop 用） */
  stalkstart: function (mode, opts) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.StalkerTrace.startManual(mode || 'call', opts || {})); });
    });
  },
  stalkstop: function (tag) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.StalkerTrace.stopManual(tag)); });
    });
  },
  /** 全局 il2cpp_runtime_invoke 拦截，filter 为子串 */
  hookinvoke: function (filter) {
    return new Promise(function (resolve) {
      ensure(function () {
        resolve(G.Hook.hookRuntimeInvoke(filter ? function (full) { return full.indexOf(filter) >= 0; } : null));
      });
    });
  },
  /** 抓 HybridCLR 热更 dll */
  capturehot: function (opts) {
    return new Promise(function (resolve) {
      // 文件 hook 可以早于 il2cpp 就绪装（只依赖 libc）
      if (!opts || opts.hookFiles !== false) G.HybridCLR.hookFileOpen();
      ensure(function () {
        G.HybridCLR.hookNative(opts || {});
        G.HybridCLR.hookAssemblyLoad(opts || {});
        resolve({ ok: true });
      });
    });
  },
  hotfiles: function () {
    return G.HybridCLR.hookFileOpen();
  },
  hotnative: function (opts) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.HybridCLR.hookNative(opts || {})); });
    });
  },
  hotmanaged: function (opts) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.HybridCLR.hookAssemblyLoad(opts || {})); });
    });
  },
  /** 导出可直接运行的 Ghidra / IDA 导入脚本（批量把 sub_XXX 重命名为 C# 方法名） */
  exportsym: function (target, images) {
    return new Promise(function (resolve) {
      ensure(function () {
        if (target === 'ida') resolve(G.Dump.exportIdaPy('ida_import.py', images));
        else resolve(G.Dump.exportGhidraPy('ghidra_import.py', images));
      });
    });
  },
  /** 网络抓包（进程内 hook SSL/socket，拿明文，不需要装证书） */
  netsniff: function (opts) {
    return new Promise(function (resolve) {
      // 网络 hook 不依赖 il2cpp，但要等进程起来
      ensure(function () { resolve(G.NetTrace.start(opts || {})); });
    });
  },
  netscan: function (kw) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.NetTrace.scanNetSymbols(kw)); });
    });
  },
  /** 内存扫描：type = i8/i16/i32/i64/f32/f64/str */
  memscan: function (type, value, opts) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.MemScan.scan(type, value, opts || {})); });
    });
  },
  /** 二次过滤（CE 的 next scan） */
  memrefine: function (value, opts) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.MemScan.refine(value, opts || {})); });
    });
  },
  memlist: function (n) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.MemScan.list(n)); });
    });
  },
  memread: function (addr, type) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.MemScan.read(addr, type)); });
    });
  },
  memwrite: function (addr, value, type) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.MemScan.write(addr, value, type)); });
    });
  },
  /** 监控谁在改这个地址（硬件断点，反查逻辑） */
  memwatch: function (addr, size) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.MemScan.watch(addr, size)); });
    });
  },
  memranges: function () {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.MemScan.ranges()); });
    });
  },
  // ---------- 反检测 / 自检 ----------
  /** 绕过 frida 检测（抹掉 maps / 端口 / ptrace / 线程名 / strstr 特征） */
  antijam: function (opts) {
    return new Promise(function (resolve) {
      // 不依赖 il2cpp，libc 一上来就有
      ensure(function () { resolve(G.Anti.bypass(opts || {})); });
    });
  },
  /** 防护自检：审计自己暴露了多少特征（自测 Obfuz 强度用） */
  antiaudit: function () {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.Anti.audit()); });
    });
  },
  antiwatch: function () {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.Anti.watchDetection()); });
    });
  },
  antireport: function () {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.Anti.watchReport()); });
    });
  },

  // ---------- 补充能力 ----------
  /** Java 层 hook */
  javahook: function (cls, method, mode) {
    return new Promise(function (resolve) {
      ensure(function () {
        // rpc 传不了函数，所以这里只做「日志模式」，复杂逻辑用 evaljs
        resolve(G.Extras.javaHook(cls, method, function (args) {
          send({ t: 'log', msg: '[java] ' + cls + '.' + method + ' args=' +
            args.map(a => String(a)).join(' | ') });
          return undefined; // 返回 undefined = 调用原实现
        }));
      });
    });
  },
  javalist: function (cls) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.Extras.javaList(cls)); });
    });
  },
  /** 抓全部 Unity Debug.Log */
  unitylog: function () {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.Extras.unityLogs({})); });
    });
  },
  /** 扫堆里所有存活的托管字符串 */
  heapstrings: function (opts) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.Extras.heapStrings(opts || {})); });
    });
  },
  /** 打印一个实例的全部字段值 */
  dumpobj: function (addr, ns, cls) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.Extras.dumpObject(addr, ns, cls, {})); });
    });
  },
  /** 正则批量 hook */
  hookbatch: function (classRe, methodRe, opts) {
    return new Promise(function (resolve) {
      ensure(function () {
        const o = Object.assign({}, opts || {}, { classRe: classRe, methodRe: methodRe });
        resolve(G.Extras.hookBatch(o));
      });
    });
  },
  /** 调用耗时统计 */
  profstart: function (ns, cls, method, argc) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.Extras.profile(ns, cls, method, argc)); });
    });
  },
  profreport: function () {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.Extras.profileReport()); });
    });
  },
  /** 追踪某类的实例创建 */
  watchctor: function (ns, cls, opts) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.Extras.watchCtor(ns, cls, opts || {})); });
    });
  },
  listinstances: function (cls) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.Extras.listInstances(cls)); });
    });
  },
  // ---------- 主动调用 / 字段读写 ----------
  /** 主动调用方法：args 是字符串数组，按实际类型自动解析 */
  call: function (ns, cls, method, args, objPtr) {
    return new Promise(function (resolve) {
      ensure(function () {
        resolve(G.Invoke.invoke(ns, cls, method, args || [], objPtr || null,
          args ? args.length : -1));
      });
    });
  },
  getfield: function (ns, cls, field) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.Invoke.getStaticField(ns, cls, field)); });
    });
  },
  setfield: function (ns, cls, field, value) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.Invoke.setStaticField(ns, cls, field, value)); });
    });
  },
  dumpstatics: function (ns, cls) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.Invoke.dumpStatics(ns, cls)); });
    });
  },
  /** 时间倍速：调 3~5 加速调试，调 0 冻结逻辑 */
  timescale: function (v) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.Invoke.setTimeScale(v)); });
    });
  },

  // ---------- 资源运行时 ----------
  assets: function (opts) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.Assets.start(opts || {})); });
    });
  },
  scene: function (opts) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.Assets.sceneList(opts || {})); });
    });
  },

  // ---------- 导出增强 ----------
  /** 从运行时生成 dump.cs（Il2CppDumper 标准格式） */
  dumpcs: function (images) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.DumpExtra.dumpCs('dump.cs', images)); });
    });
  },
  /** 从内存重建 libil2cpp.so（对抗加固） */
  dumpso: function (opts) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.DumpExtra.dumpSo(opts || {})); });
    });
  },

  // ---------- 行为监控 ----------
  fileio: function (opts) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.Monitor.fileio(opts || {})); });
    });
  },
  filereport: function (n) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.Monitor.fileReport(n)); });
    });
  },
  crypto: function (opts) {
    return new Promise(function (resolve) {
      ensure(function () { resolve(G.Monitor.crypto(opts || {})); });
    });
  },
  /** 自定义 JS：直接在 host 端下发代码片段执行（高危但灵活） */
  evaljs: function (src) {
    return new Promise(function (resolve) {
      ensure(function () {
        try { resolve({ ok: true, result: String(eval(src)) }); }
        catch (e) { resolve({ ok: false, err: String(e) }); }
      });
    });
  }
};

send({ t: 'log', msg: '[*] agent 已注入 pid=' + Process.id + '，等待 il2cpp 就绪…' });
