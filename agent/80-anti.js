/**
 * 80-anti.js —— 反检测对抗 + 自己的防护自检
 *
 * 两个方向，一套代码：
 *   【攻】Anti.bypass()  —— 目标 App 检测到 frida 就崩溃/闪退时，把特征抹掉
 *   【防】Anti.audit()   —— 站在防御方，审计自己进程暴露了多少特征（自测 Obfuz 强度）
 *
 * 对你这种自测场景，audit() 其实比 bypass() 更有价值：
 *   它能告诉你「攻击者不用改一行代码就能看到什么」，
 *   这些就是你的防护真正该补的洞。
 *
 * 常见检测手段与对应抹除方式：
 *   1. /proc/self/maps 扫 frida-agent / gadget / linjector   → hook fgets/strstr 过滤
 *   2. /proc/self/task/<tid>/comm 扫 gum-js-loop / gmain      → 改线程名 + hook comm 读取
 *   3. connect() 到 27042 探测端口                             → hook connect 返回失败
 *   4. ptrace(PTRACE_TRACEME) 判断是否已被调试                 → hook ptrace 返回 0
 *   5. prctl(PR_SET_DUMPABLE) / /proc/self/status             → hook 过滤
 *   6. strstr/strcmp 扫特征字符串                              → hook 返回 NULL
 *   7. 扫 dlopen 后的符号 gum_dispatcher_*                     → 靠改名 server 规避
 *   8. 读 /proc/self/status 的 TracerPid                       → hook 置 0
 */
'use strict';
const G = globalThis;
const H = G.H;

(function () {
  const Anti = {};

  // ---------- 特征词表（攻防共用） ----------
  Anti.SIGNATURES = [
    'frida', 'gadget', 'linjector', 'gum-js-loop', 'gum_dispatcher',
    'gmain', 'gdbus', 'frida-agent', 'frida_server', 're.frida.server'
  ];

  // ============================================================
  // 【攻】绕过：把 frida 特征从目标进程视角里抹掉
  // ============================================================

  /** 过滤文件内容里的特征行（maps / status / comm 都走这个） */
  function hookTextFilter(opts) {
    const out = [];
    const sigs = (opts && opts.signatures) || Anti.SIGNATURES;
    const lower = sigs.map(s => s.toLowerCase());

    // 读文件时过滤：覆盖 fopen/fgets 组合，也覆盖 open+read
    const fgets = Module.findExportByName('libc.so', 'fgets');
    if (fgets) {
      const origFgets = new NativeFunction(fgets, 'pointer', ['pointer', 'int', 'pointer']);
      Interceptor.replace(fgets, new NativeCallback(function (buf, size, fp) {
        const r = origFgets(buf, size, fp);
        if (r.isNull()) return r;
        try {
          const line = buf.readCString(size);
          if (line) {
            const l = line.toLowerCase();
            if (lower.some(s => l.indexOf(s) >= 0)) {
              // 吐一个空行顶替，让调用方的解析逻辑不至于错位
              buf.writeU8(0x0a);
              buf.add(1).writeU8(0);
            }
          }
        } catch (e) {}
        return r;
      }, 'pointer', ['pointer', 'int', 'pointer']));
      out.push('fgets');
    }

    // 直接内存比对：strstr / strcasestr
    const strstr = Module.findExportByName('libc.so', 'strstr');
    if (strstr) {
      const orig = new NativeFunction(strstr, 'pointer', ['pointer', 'pointer']);
      Interceptor.replace(strstr, new NativeCallback(function (hay, needle) {
        try {
          const n = needle.readCString(64);
          if (n && lower.some(s => n.toLowerCase().indexOf(s) >= 0)) return NULL;
        } catch (e) {}
        return orig(hay, needle);
      }, 'pointer', ['pointer', 'pointer']));
      out.push('strstr');
    }
    return out;
  }

  /**
   * 一键绕过
   * @param opts { hidePorts:[27042], renameThreads:true, fakePtrace:true }
   */
  Anti.bypass = function (opts) {
    opts = opts || {};
    const r = { text: [], port: [], ptrace: [], thread: [] };

    r.text = hookTextFilter(opts);

    // 1) 端口探测：让 connect 到 frida 默认端口失败
    if (opts.hidePorts !== false) {
      const ports = opts.ports || [27042, 27043, 27052];
      const conn = Module.findExportByName('libc.so', 'connect');
      if (conn) {
        Interceptor.attach(conn, {
          onEnter(args) {
            try {
              const sa = args[1];
              const family = sa.readU16();
              if (family === 2 /* AF_INET */) {
                const port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                if (ports.indexOf(port) >= 0) this._block = true;
              }
            } catch (e) {}
          },
          onLeave(ret) {
            if (this._block) {
              ret.replace(ptr(-1));
              send({ t: 'log', msg: '[anti] 拦截了一次 frida 端口探测' });
            }
          }
        });
        r.port.push('connect');
      }
    }

    // 2) ptrace：PTRACE_TRACEME 返回 0（= 没人调试我），让反调试逻辑放心
    if (opts.fakePtrace !== false) {
      const p = Module.findExportByName('libc.so', 'ptrace');
      if (p) {
        Interceptor.attach(p, {
          onEnter(args) { this._req = args[0].toInt32(); },
          onLeave(ret) {
            // PTRACE_TRACEME = 0；反调试通常靠它返回 -1 来判定「已被跟踪」
            if (this._req === 0) ret.replace(ptr(0));
          }
        });
        r.ptrace.push('ptrace');
      }
    }

    // 3) 线程改名：gum-js-loop / gmain 这些名字太显眼
    if (opts.renameThreads !== false) {
      try {
        const prctl = Module.findExportByName('libc.so', 'prctl');
        if (prctl) {
          const f = new NativeFunction(prctl, 'int', ['int', 'pointer']);
          // PR_SET_NAME = 15
          for (const t of Process.enumerateThreads()) {
            try {
              const benign = Memory.allocUtf8String('.anon');
              // 只能在自己线程上改，这里尽力而为
              f(15, benign);
            } catch (e) {}
          }
        }
        r.thread.push('prctl');
      } catch (e) {}
    }

    send({ t: 'log', msg: '[anti] 绕过已装: text=[' + r.text.join(',') + '] port=[' +
      r.port.join(',') + '] ptrace=[' + r.ptrace.join(',') + ']' });
    send({ t: 'log', msg: '[anti] 注意：bypass 只是抹特征，不是万能的。' +
      '遇到 RASP（Promon / DexGuard / 梆梆 / 360）建议直接上 ZygiskFrida' });
    return r;
  };

  // ============================================================
  // 【防】自检：看看自己暴露了多少（自测防护强度用）
  // ============================================================
  Anti.audit = function () {
    const findings = [];
    const sigs = Anti.SIGNATURES;

    // 1) maps 里有没有 frida 特征
    try {
      const maps = File.readAllText ? null : null;
      let content = '';
      const f = new File('/proc/self/maps', 'r');
      content = f.readText ? f.readText() : '';
      f.close();
      for (const line of content.split('\n')) {
        const l = line.toLowerCase();
        for (const s of sigs) {
          if (l.indexOf(s) >= 0) {
            findings.push({ level: 'high', type: 'maps', detail: line.slice(0, 160) });
            break;
          }
        }
      }
    } catch (e) {
      findings.push({ level: 'info', type: 'maps', detail: '读取失败: ' + e });
    }

    // 2) 线程名
    try {
      for (const t of Process.enumerateThreads()) {
        const n = (t.name || '').toLowerCase();
        if (sigs.some(s => n.indexOf(s) >= 0)) {
          findings.push({ level: 'high', type: 'thread', detail: t.id + ' -> ' + t.name });
        }
      }
    } catch (e) {}

    // 3) 已加载模块里的可疑 .so
    try {
      for (const m of Process.enumerateModules()) {
        const n = (m.name || '').toLowerCase();
        if (sigs.some(s => n.indexOf(s) >= 0)) {
          findings.push({ level: 'high', type: 'module', detail: m.name + ' @ ' + m.base });
        }
      }
    } catch (e) {}

    // 4) 端口是否在监听
    try {
      const conn = Module.findExportByName('libc.so', 'connect');
      if (conn) findings.push({ level: 'info', type: 'port', detail: '需外部探测，此处不能自连' });
    } catch (e) {}

    // 5) TracerPid
    try {
      const f = new File('/proc/self/status', 'r');
      const txt = f.readText ? f.readText() : '';
      f.close();
      const m = /TracerPid:\s*(\d+)/.exec(txt);
      if (m && m[1] !== '0') {
        findings.push({ level: 'high', type: 'tracerpid', detail: 'TracerPid=' + m[1] + '（正在被调试）' });
      }
    } catch (e) {}

    // 6) 自身保护检查：这些是「你的防护该有但没有」的项
    const missing = [];
    const self = Process.findModuleByAddress(ptr(Process.enumerateModules()[0].base));
    try {
      const ptrace = Module.findExportByName('libc.so', 'ptrace');
      if (ptrace && !Interceptor.isAttached) {
        missing.push('未对 ptrace 做反附加保护');
      }
    } catch (e) {}

    const high = findings.filter(f => f.level === 'high').length;
    send({ t: 'log', msg: '===== 反检测自检 =====' });
    for (const f of findings) {
      send({ t: 'log', msg: '[' + f.level.toUpperCase() + '] ' + f.type + ': ' + f.detail });
    }
    if (!findings.length) {
      send({ t: 'log', msg: '未发现明显 frida 特征（好事，说明你的加固有效或当前还没被注入）' });
    }
    send({ t: 'log', msg: '===== 高危项: ' + high + ' 条 =====' });
    send({ t: 'log', msg: '解读：这份审计假设攻击者用的是「开箱即用的 frida-server」。' +
      '若他改用 ZygiskFrida 或改名后的 gadget，上面这些特征会大幅减少 —— 那才是你防护的真实考验' });
    return { findings: findings, high: high };
  };

  /** 持续监控：有没有人在扫我（hook 敏感读取点并计数） */
  Anti.watchDetection = function () {
    const counters = {};
    const points = [
      ['fopen', 'pointer', ['pointer', 'pointer']],
      ['openat', 'int', ['int', 'pointer', 'int']],
      ['access', 'int', ['pointer', 'int']],
      ['ptrace', 'long', ['long', 'long', 'long', 'long']]
    ];
    for (const [fn, ret, args] of points) {
      const p = Module.findExportByName('libc.so', fn);
      if (!p) continue;
      Interceptor.attach(p, {
        onEnter(a) {
          let s = '';
          try { s = a[fn === 'openat' ? 1 : 0].readCString(128) || ''; } catch (e) {}
          const key = fn + (s ? (':' + s) : '');
          counters[key] = (counters[key] || 0) + 1;
        }
      });
    }
    Anti.__watch = counters;
    send({ t: 'log', msg: '[anti] 已挂监控，用 Anti.watchReport() 看统计' });
    return { hooked: points.map(p => p[0]).filter(f => Module.findExportByName('libc.so', f)) };
  };

  Anti.watchReport = function () {
    const c = Anti.__watch;
    if (!c) return null;
    // 只报「能被用来做检测」的敏感路径
    const sensitive = Object.keys(c)
      .filter(k => /maps|status|task|comm|su|magisk|frida|ptrace/.test(k))
      .sort((a, b) => c[b] - c[a]);
    send({ t: 'log', msg: '===== 敏感调用统计 =====' });
    for (const k of sensitive) send({ t: 'log', msg: '  ' + c[k] + ' 次  ' + k });
    if (!sensitive.length) send({ t: 'log', msg: '  暂无敏感调用' });
    return sensitive.map(k => ({ key: k, count: c[k] }));
  };

  G.Anti = Anti;
})();
