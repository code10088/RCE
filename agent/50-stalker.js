/**
 * 50-stalker.js —— 指令级追踪（Frida Stalker）
 *
 * 为什么需要它：
 *   Interceptor.attach 只能看到「进/出」，函数内部长什么样管不着。
 *   遇到 Obfuz 控制流平坦化 / OLLVM / 虚化保护，函数级 hook 基本失效 ——
 *   这时候只有指令级追踪能看到真实的执行路径。
 *
 * 原理（和目标进程同处一个地址空间）：
 *   Stalker 把目标线程的机器指令动态重编译到一块「代码缓存」，
 *   在重编译过程中插入我们的探针，CPU 实际执行的是加工过的副本。
 *   所以它不是断点（不中断 CPU），开销比调试器低，但粒度到每一条指令。
 *
 * 四种模式，按开销从小到大：
 *   call   —— 只追调用/返回，看「这个函数内部调了谁」          开销最小
 *   block  —— 基本块执行序列，用于还原被平坦化的控制流          开销中
 *   insn   —— 逐指令，含寄存器快照，分析短小关键循环            开销大
 *   xor    —— 只抓异或/移位/查表指令，专门用于还原加密/哈希算法   开销可控
 *
 * 铁律：
 *   1) 必须 Stalker.exclude 掉 libc / linker / frida-agent，否则数据量爆炸且大概率卡死
 *   2) Stalker.follow 只能在目标线程上发起 —— 所以一律在 Interceptor 的 onEnter 里用 this.threadId
 *   3) putCallout 的回调跑在目标线程，只准 push 数据，不准 send / 不准调 il2cpp API
 *   4) 一定要设上限（maxRecords），否则几秒钟就能吃掉几个 G 内存
 */
'use strict';
const G = globalThis;
const H = G.H;

(function () {
  const S = {};

  // ---------- 默认排除：不追这些模块 ----------
  S.EXCLUDE_LIBS = [
    'libc.so', 'libm.so', 'libdl.so', 'libc++_shared.so', 'libstdc++.so',
    'linker64', 'linker', 'liblog.so', 'libz.so',
    'frida-agent', 'frida', 'gadget', 'linjector'
  ];

  S.applyExclude = function () {
    let n = 0;
    for (const m of Process.enumerateModules()) {
      const nm = m.name || '';
      if (S.EXCLUDE_LIBS.some(x => nm.indexOf(x) >= 0)) {
        try { Stalker.exclude(m.base, m.size); n++; } catch (e) {}
      }
    }
    // frida 自身的代码段也要排除，否则会自我追踪导致死循环
    try {
      const tq = Process.findModuleByName('frida-agent.so');
      if (tq) { Stalker.exclude(tq.base, tq.size); n++; }
    } catch (e) {}
    send({ t: 'log', msg: '[stalker] 已排除 ' + n + ' 个无关模块' });
    return n;
  };

  // ---------- 地址 → 可读信息 ----------
  function describe(p) {
    const a = ptr(p);
    let rva = '', mod = '';
    try {
      const m = Process.findModuleByAddress(a);
      if (m) { mod = m.name; rva = a.sub(m.base).toString(); }
    } catch (e) {}
    let sym = '';
    try { sym = DebugSymbol.fromAddress(a).name || ''; } catch (e) {}
    return { addr: a.toString(), module: mod, rva: rva, symbol: sym };
  }

  // ---------- 数据落地 ----------
  function flush(tag, records) {
    const lines = records.map(r => JSON.stringify(r)).join('\n');
    H.sendText(tag || 'stalker.jsonl', lines);
    send({ t: 'log', msg: '[stalker] 回传 ' + records.length + ' 条记录' });
  }

  // ============================================================
  // 模式 1：call —— 调用树 / 调用摘要
  // ============================================================
  S.followCalls = function (tid, opts) {
    opts = opts || {};
    const records = [];
    const max = opts.maxRecords || 20000;
    const target = opts.base ? ptr(opts.base) : null;

    Stalker.follow(tid, {
      events: { call: true, ret: false, exec: false, block: false, compile: false },
      onReceive(eventsPtr) {
        if (records.length >= max) return;
        try {
          const evts = Stalker.parse(eventsPtr, { annotate: false, stringify: false });
          // 各版本返回结构不同：[[caller,target,depth],...] 或 [{...},...]
          for (const e of evts) {
            if (records.length >= max) break;
            let caller, callee;
            if (Array.isArray(e)) { caller = e[0]; callee = e[1]; }
            else { caller = e.caller || e.from; callee = e.target || e.to || e.address; }
            if (!callee) continue;
            const d = describe(callee);
            // 限定只关心目标模块内的调用
            if (target && (!d.module || d.module !== target)) continue;
            d.caller = describe(caller).addr;
            records.push(d);
          }
        } catch (e) {}
      }
    });
    return records;
  };

  // ============================================================
  // 模式 2：block —— 基本块执行序列（反控制流平坦化的核心证据）
  // ============================================================
  S.followBlocks = function (tid, opts) {
    opts = opts || {};
    const records = [];
    const max = opts.maxRecords || 20000;
    const seen = new Set();

    Stalker.follow(tid, {
      events: { call: false, ret: false, exec: false, block: true, compile: false },
      onReceive(eventsPtr) {
        if (records.length >= max) return;
        try {
          const evts = Stalker.parse(eventsPtr, { annotate: false, stringify: false });
          for (const e of evts) {
            if (records.length >= max) break;
            const a = Array.isArray(e) ? e[0] : (e.address || e.start);
            if (!a) continue;
            const d = describe(a);
            records.push({ seq: records.length, block: d.addr, module: d.module, rva: d.rva, symbol: d.symbol });
            seen.add(d.rva);
          }
        } catch (e) {}
      }
    });
    records.uniqueBlocks = function () { return seen.size; };
    return records;
  };

  /**
   * 模式 3 / 4：transform + putCallout —— 逐指令或按助记符过滤
   * @param opts.mnemonics  只抓这些助记符，如 ['eor','lsl','ldr','str']；为空=全部指令
   * @param opts.withRegs   是否记录 x0-x7 寄存器快照
   */
  S.followTransform = function (tid, opts) {
    opts = opts || {};
    const records = [];
    const max = opts.maxRecords || 50000;
    const mnem = (opts.mnemonics && opts.mnemonics.length)
      ? opts.mnemonics.map(s => s.toLowerCase())
      : null;
    const withRegs = opts.withRegs !== false;

    Stalker.follow(tid, {
      transform(iterator) {
        let insn;
        let count = 0;
        while ((insn = iterator.next()) !== null) {
          if (records.length < max) {
            const m = (insn.mnemonic || '').toLowerCase();
            if (count++ < 200000 && (!mnem || mnem.indexOf(m) >= 0)) {
              // 只注册探针，真正取值在 callout 里 —— 回调跑在目标线程，务必轻量
              iterator.putCallout(function (ctx) {
                if (records.length >= max) return;
                const rec = { pc: ptr(ctx.pc).toString() };
                const dd = describe(ctx.pc);
                rec.module = dd.module; rec.rva = dd.rva; rec.symbol = dd.symbol;
                if (withRegs) {
                  const r = {};
                  for (let i = 0; i < 8; i++) {
                    try { r['x' + i] = ptr(ctx['x' + i]).toString(); } catch (e) {}
                  }
                  rec.regs = r;
                }
                records.push(rec);
              });
            }
          }
          iterator.keep();
        }
      }
    });
    return records;
  };

  // ---------- 针对算法还原的预设 ----------
  S.PRESET = {
    // 异或 / 移位 / 旋转 —— 推 XOR 密钥、位变换
    xor: ['eor', 'lsl', 'lsr', 'asr', 'ror', 'and', 'orr', 'mvn'],
    // 查表 —— 推 S-Box（AES / CRC / 自定义置换）
    table: ['ldr', 'ldrb', 'ldrh', 'ldrsw', 'ldrsb', 'ldur'],
    // 乘法 —— 推哈希中的常数乘子
    mul: ['mul', 'smulh', 'umulh', 'madd', 'msub'],
    // 分支 —— 还原控制流
    branch: ['b', 'bl', 'blr', 'br', 'cbz', 'cbnz', 'tbz', 'tbnz', 'ret']
  };

  // ============================================================
  // 高层封装：hook 一个方法，只在它执行期间追踪
  //   这是最实用的用法 —— 把范围锁死在一次调用内，数据量可控
  // ============================================================
  S.hookAndStalk = function (addr, mode, opts) {
    opts = opts || {};
    S.applyExclude();

    const started = new Set();

    Interceptor.attach(ptr(addr), {
      onEnter(args) {
        const tid = this.threadId;
        if (started.has(tid)) return;
        started.add(tid);

        const o = Object.assign({}, opts, {
          base: opts.moduleName || (G.IL2CPP && G.IL2CPP.module ? G.IL2CPP.module.name : null)
        });

        let recs;
        if (mode === 'call') recs = S.followCalls(tid, o);
        else if (mode === 'block') recs = S.followBlocks(tid, o);
        else if (mode === 'xor' || mode === 'table' || mode === 'mul' || mode === 'branch') {
          o.mnemonics = S.PRESET[mode];
          o.withRegs = true;
          recs = S.followTransform(tid, o);
        } else { // insn
          o.mnemonics = opts.mnemonics || null;
          recs = S.followTransform(tid, o);
        }

        this.recs = recs;
        this.tid = tid;
        this.t0 = Date.now();
        send({ t: 'log', msg: '[stalker] 开始追踪 tid=' + tid + ' mode=' + mode });
      },
      onLeave(ret) {
        if (!this.tid) return;
        try { Stalker.unfollow(this.tid); } catch (e) {}
        try { Stalker.garbageCollect(); } catch (e) {}
        started.delete(this.tid);
        const ms = Date.now() - this.t0;
        send({ t: 'log', msg: '[stalker] 结束 tid=' + this.tid + ' 耗时 ' + ms + 'ms 记录 ' +
          (this.recs ? this.recs.length : 0) + ' 条' });
        if (this.recs && this.recs.length) {
          if (this.recs.uniqueBlocks) {
            send({ t: 'log', msg: '[stalker] 唯一基本块: ' + this.recs.uniqueBlocks() + ' 个（越少=越可能是平坦化里的主循环）' });
          }
          flush(opts.tag || ('stalker-' + mode + '.jsonl'), this.recs);
        }
        this.tid = null;
      }
    });
    return { addr: ptr(addr).toString(), mode: mode };
  };

  // ============================================================
  // 按 命名空间.类名.方法名 直接开追
  // ============================================================
  S.stalkMethod = function (namespaze, clsName, methodName, argc, mode, opts) {
    const api = G.IL2CPP;
    if (!api || !api.ready) return { error: 'il2cpp 未就绪' };
    const r = api.findMethod(null, namespaze, clsName, methodName, argc == null ? -1 : argc);
    if (!r.methods.length) {
      send({ t: 'log', msg: '[stalker] 未找到 ' + namespaze + '.' + clsName + '::' + methodName });
      return null;
    }
    const p = api.methodPointer(r.methods[0]);
    if (p.isNull()) return { error: 'methodPointer 为空' };
    const info = { rva: api.rva(p).toString(), addr: p.toString(), overloads: r.methods.length };
    S.hookAndStalk(p, mode, opts || {});
    send({ t: 'log', msg: '[stalker] 已挂载 ' + clsName + '::' + methodName +
      ' @ ' + p + ' (rva ' + info.rva + ') mode=' + mode });
    return info;
  };

  /** 按 RVA（相对 libil2cpp.so）开追，用于 IDA 里定位到的裸地址 */
  S.stalkRva = function (rva, mode, opts) {
    const api = G.IL2CPP;
    if (!api || !api.ready) return { error: 'il2cpp 未就绪' };
    const p = api.base.add(rva);
    S.hookAndStalk(p, mode, opts || {});
    send({ t: 'log', msg: '[stalker] 已挂载 rva ' + rva + ' -> ' + p + ' mode=' + mode });
    return { addr: p.toString(), rva: rva };
  };

  /** 手动开始/停止，配合 interactive 用 */
  S.startManual = function (mode, opts) {
    S.applyExclude();
    const tid = Process.enumerateThreads()[0] ? Process.enumerateThreads()[0].id : null;
    if (!tid) return { error: '取不到线程' };
    const o = Object.assign({}, opts);
    let recs;
    if (mode === 'call') recs = S.followCalls(tid, o);
    else if (mode === 'block') recs = S.followBlocks(tid, o);
    else {
      o.mnemonics = S.PRESET[mode] || o.mnemonics;
      recs = S.followTransform(tid, o);
    }
    G.__stalkManual = { tid: tid, recs: recs };
    return { tid: tid, mode: mode };
  };
  S.stopManual = function (tag) {
    if (!G.__stalkManual) return null;
    const { tid, recs } = G.__stalkManual;
    try { Stalker.unfollow(tid); } catch (e) {}
    try { Stalker.garbageCollect(); } catch (e) {}
    if (recs && recs.length) flush(tag || 'stalker-manual.jsonl', recs);
    G.__stalkManual = null;
    return { tid: tid, count: recs ? recs.length : 0 };
  };

  G.StalkerTrace = S;
})();
