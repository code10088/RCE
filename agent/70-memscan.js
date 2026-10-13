/**
 * 70-memscan.js —— 进程内内存扫描
 *
 * 和 GameGuardian / Cheat Engine 的区别：
 *   GG/CE 是独立 App，通过 ptrace 或 /proc/pid/mem 去读**别的**进程
 *   这里直接在目标进程内部扫描 —— 更快、能做任意复杂条件、且不需要 root 装额外 App
 *   代价：得到的地址是本次运行的，进程重启后失效（有 ASLR）
 *
 * 典型用法（和 CE 一样的「多次过滤收敛」）：
 *   1. memscan i32 100          → 得到 N 个候选地址
 *   2. 游戏里让这个值变化（比如花掉金币）
 *   3. memrefine i32 80         → 在上次结果里再筛，几千个瞬间收敛到几个
 *   4. memwatch 0x7a3c...        → 监控谁在改它（配合 Stalker 反查逻辑）
 *
 * 只扫 rw- 可读写区，跳过 r-x（代码段）和 --- （保护页），
 * 这是速度和安全的关键：扫代码段没意义，扫不可读区会直接崩。
 */
'use strict';
const G = globalThis;
const H = G.H;

(function () {
  const M = {};
  let lastScan = null;   // 上次结果，供 refine 用

  // ---------- 数值 → 小端字节 pattern（Memory.scan 需要） ----------
  function valToPattern(type, v) {
    const b = [];
    switch (type) {
      case 'i8':   b.push(v & 0xff); break;
      case 'i16':  b.push(v & 0xff, (v >> 8) & 0xff); break;
      case 'i32':  for (let i = 0; i < 4; i++) b.push((v >>> (i * 8)) & 0xff); break;
      case 'i64':
        for (let i = 0; i < 8; i++) b.push(Number((BigInt(v) >> BigInt(i * 8)) & 0xffn));
        break;
      case 'f32': {
        const buf = new ArrayBuffer(4);
        new DataView(buf).setFloat32(0, v, true);
        const u8 = new Uint8Array(buf);
        for (let i = 0; i < 4; i++) b.push(u8[i]);
        break;
      }
      case 'f64': {
        const buf = new ArrayBuffer(8);
        new DataView(buf).setFloat64(0, v, true);
        const u8 = new Uint8Array(buf);
        for (let i = 0; i < 8; i++) b.push(u8[i]);
        break;
      }
      default: throw new Error('未知类型: ' + type + '（支持 i8/i16/i32/i64/f32/f64）');
    }
    return b.map(x => ('0' + x.toString(16)).slice(-2)).join(' ');
  }

  // ---------- 候选内存区 ----------
  function targetRanges(opts) {
    opts = opts || {};
    const out = [];
    for (const r of Process.enumerateRangesSync('rw-')) {
      // 只关心游戏自己的堆/匿名映射，跳过小段（一般是栈片段或库的数据段）
      if (r.size < (opts.minRangeSize || 4096)) continue;
      if (opts.maxRangeSize && r.size > opts.maxRangeSize) continue;
      if (opts.rangeFilter && !opts.rangeFilter.test(r.file ? r.file.path : '')) continue;
      out.push(r);
    }
    return out;
  }

  /**
   * 首次扫描
   * @param type  i8/i16/i32/i64/f32/f64/str
   * @param value 数值，或 str 模式下的 UTF-16 字符串
   */
  M.scan = function (type, value, opts) {
    opts = opts || {};
    const maxHits = opts.maxHits || 5000;
    const ranges = targetRanges(opts);
    const hits = [];

    let pattern, matchLen;
    if (type === 'str') {
      // Il2CppString 是 UTF-16LE，直接转成字节序列
      const bytes = [];
      for (let i = 0; i < value.length; i++) {
        const c = value.charCodeAt(i);
        bytes.push(c & 0xff, (c >> 8) & 0xff);
      }
      pattern = bytes.map(x => ('0' + x.toString(16)).slice(-2)).join(' ');
      matchLen = bytes.length;
    } else {
      pattern = valToPattern(type, value);
      matchLen = type === 'i8' ? 1 : type === 'i16' ? 2 : (type === 'f64' || type === 'i64') ? 8 : 4;
    }

    send({ t: 'log', msg: '[scan] 类型=' + type + ' 值=' + value + ' pattern="' + pattern +
      '" 扫描 ' + ranges.length + ' 个 rw- 区…' });

    const t0 = Date.now();
    for (const r of ranges) {
      if (hits.length >= maxHits) break;
      try {
        Memory.scan(r.base, r.size, pattern, {
          onMatch(address, size) {
            if (hits.length >= maxHits) return 'stop';
            const m = Process.findModuleByAddress(address);
            hits.push({
              addr: address.toString(),
              module: m ? m.name : '',
              rva: m ? address.sub(m.base).toString() : ''
            });
            return 'continue';
          },
          onError(reason) { return 'continue'; }
        });
      } catch (e) {
        // 某些区读了会崩，跳过
      }
    }
    const ms = Date.now() - t0;
    lastScan = { type: type, value: value, hits: hits, matchLen: matchLen };

    send({ t: 'log', msg: '[scan] 命中 ' + hits.length + ' 处，耗时 ' + ms + 'ms' +
      (hits.length >= maxHits ? '（已达上限，结果被截断）' : '') });
    if (hits.length) {
      send({ t: 'log', msg: JSON.stringify(hits.slice(0, 50), null, 0) });
    }
    return { count: hits.length, ms: ms, sample: hits.slice(0, 50) };
  };

  /** 二次过滤：只在上次命中的地址里筛（这就是 CE 的 "next scan"） */
  M.refine = function (value, opts) {
    if (!lastScan || !lastScan.hits.length) {
      send({ t: 'log', msg: '[!] 没有上次扫描结果，先跑 scan' });
      return null;
    }
    opts = opts || {};
    const type = opts.type || lastScan.type;
    let pattern;
    if (type === 'str') {
      const bytes = [];
      for (let i = 0; i < value.length; i++) {
        const c = value.charCodeAt(i);
        bytes.push(c & 0xff, (c >> 8) & 0xff);
      }
      pattern = bytes.map(x => ('0' + x.toString(16)).slice(-2)).join(' ');
    } else {
      pattern = valToPattern(type, value);
    }
    const want = pattern.split(' ');
    const kept = [];

    for (const h of lastScan.hits) {
      try {
        const a = ptr(h.addr);
        let ok = true;
        for (let i = 0; i < want.length; i++) {
          if (want[i] === '??') continue;
          if (a.add(i).readU8() !== parseInt(want[i], 16)) { ok = false; break; }
        }
        if (ok) kept.push(h);
      } catch (e) { /* 地址失效（被 GC 回收/释放），丢弃 */ }
    }
    lastScan.hits = kept;
    lastScan.value = value;
    send({ t: 'log', msg: '[refine] ' + lastScan.hits.length + ' 处仍然匹配' +
      (kept.length <= 20 ? '\n' + JSON.stringify(kept, null, 1) : '') });
    return { count: kept.length, hits: kept.slice(0, 50) };
  };

  /** 列出当前候选（收敛好了看结果） */
  M.list = function (n) {
    if (!lastScan) return null;
    const hits = lastScan.hits.slice(0, n || 50);
    send({ t: 'log', msg: JSON.stringify(hits, null, 1) });
    return hits;
  };

  /** 读某个地址的值（按上次的类型解释） */
  M.read = function (addr, type) {
    const t = type || (lastScan ? lastScan.type : 'i32');
    const a = ptr(addr);
    let v;
    switch (t) {
      case 'i8': v = a.readS8(); break;
      case 'i16': v = a.readS16(); break;
      case 'i32': v = a.readS32(); break;
      case 'i64': v = a.readS64().toString(); break;
      case 'f32': v = a.readFloat(); break;
      case 'f64': v = a.readDouble(); break;
      default: v = null;
    }
    send({ t: 'log', msg: '[read] ' + addr + ' (' + t + ') = ' + v });
    return v;
  };

  /** 改值（验证用，别在联网游戏上乱来） */
  M.write = function (addr, value, type) {
    const t = type || (lastScan ? lastScan.type : 'i32');
    const a = ptr(addr);
    switch (t) {
      case 'i8': a.writeS8(value); break;
      case 'i16': a.writeS16(value); break;
      case 'i32': a.writeS32(value); break;
      case 'i64': a.writeS64(value); break;
      case 'f32': a.writeFloat(value); break;
      case 'f64': a.writeDouble(value); break;
      default: return false;
    }
    send({ t: 'log', msg: '[write] ' + addr + ' (' + t + ') = ' + value });
    return true;
  };

  /**
   * 监控：谁在改这个地址 —— 反查逻辑的关键一步
   * 用 MemoryAccessMonitor（硬件断点，只触发不中断），比 Stalker 轻量得多
   */
  M.watch = function (addr, size, opts) {
    opts = opts || {};
    const a = ptr(addr);
    const sz = size || 8;
    try {
      MemoryAccessMonitor.enable(a, sz, {
        onAccess(details) {
          const d = details;
          send({ t: 'log', msg: '[watch] ' + (d.operation === 'write' ? 'WRITE' : d.operation) +
            ' @ ' + d.address + ' from ' + d.from +
            '\n        ' + Thread.backtrace(this.context, Backtracer.FUZZY)
              .map(DebugSymbol.fromAddress).slice(0, 6).join('\n        ') });
        }
      });
      send({ t: 'log', msg: '[+] 已监控 ' + a + ' +' + sz + ' 字节' });
      return { addr: a.toString(), size: sz };
    } catch (e) {
      send({ t: 'log', msg: '[!] MemoryAccessMonitor 不可用（该 ROM/内核可能不支持）: ' + e +
        '。替代方案：用 StalkerTrace.stalkMethod 追踪疑似方法' });
      return null;
    }
  };
  M.unwatch = function (addr) {
    try { MemoryAccessMonitor.disable(ptr(addr)); return true; } catch (e) { return false; }
  };

  /** 列出 rw- 区概况，扫之前先看一眼有多大 */
  M.ranges = function (opts) {
    const rs = targetRanges(opts);
    const top = rs.sort((a, b) => b.size - a.size).slice(0, 20).map(r => ({
      base: r.base.toString(),
      size: r.size,
      protection: r.protection,
      file: r.file ? r.file.path : ''
    }));
    const total = rs.reduce((s, r) => s + r.size, 0);
    send({ t: 'log', msg: '[ranges] ' + rs.length + ' 个 rw- 区，共 ' +
      (total / 1024 / 1024).toFixed(1) + ' MB\n' + JSON.stringify(top, null, 1) });
    return { count: rs.length, totalMB: +(total / 1024 / 1024).toFixed(1), top: top };
  };

  G.MemScan = M;
})();
