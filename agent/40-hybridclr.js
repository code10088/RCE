/**
 * 40-hybridclr.js —— 从内存抓取 / 替换 HybridCLR 热更新 DLL
 *
 * 三条抓取路径，按可靠性排序：
 *  【方案 A｜最准】hook hybridclr 原生入口
 *      hybridclr::metadata::InterpreterImage::Load(const byte* imageData, size_t size)
 *      hybridclr::metadata::Assembly::Create(const byte* imageData, uint64_t size)
 *      => args[0]=this, args[1]=dll 首字节指针, args[2]=长度
 *      符号未 strip 时可直接 findExportByName；strip 过就走方案 B
 *  【方案 B｜通用】hook System.Reflection.Assembly::Load(byte[])（HybridCLR 官方加载方式）
 *      => args[0]=byte[]，读 Il2CppArray 拿原始 PE 字节
 *  【方案 C｜兜底】hook libc open/openat + 扫已加载 assembly
 *      => 只知道 .dll/.bytes 文件路径与 fd，配合 adb pull / 内存扫描
 *
 * 替换：把改好的 dll 放到 /data/local/tmp/patch/<name>.dll，脚本会替换 args 指向的缓冲区，
 *       实现"不重打包、直接改热更逻辑"。
 */
'use strict';
const G = globalThis;
const H = G.H;
const api = G.IL2CPP;

(function () {
  const HC = {};
  const S = (s) => Memory.allocUtf8String(s);
  const PATCH_DIR = '/data/local/tmp/il2cpp-harness/patch/';

  function isPE(buf) {
    if (!buf || buf.byteLength < 0x40) return false;
    const v = new Uint8Array(buf);
    return v[0] === 0x4D && v[1] === 0x5A; // MZ
  }

  function nameFromPE(buf) {
    // 从 PE 里抠不出 assembly 名，就用长度+时间戳命名，避免覆盖
    return 'hotupdate_' + buf.byteLength + '_' + Date.now() + '.dll';
  }

  function save(tag, buf, name, extra) {
    if (!isPE(buf)) { send({ t: 'log', msg: '[-] 非 PE 数据，丢弃 (' + (buf ? buf.byteLength : 0) + ' bytes)' }); return false; }
    const devPath = '/data/local/tmp/il2cpp-harness/' + name;
    H.writeDeviceFile(devPath, buf);
    H.sendBin('hotdll', { name: name, size: buf.byteLength, src: tag, devPath: devPath, extra: extra || null }, buf);
    send({ t: 'log', msg: '[+] 抓到热更 DLL: ' + name + ' (' + buf.byteLength + ' bytes) src=' + tag });
    return true;
  }

  // ---------------- 符号探测 ----------------
  HC.scanSymbols = function () {
    const hits = [];
    try {
      const syms = api.module.enumerateSymbols();
      for (const s of syms) {
        const n = s.name || '';
        if (n.indexOf('ybridclr') >= 0 && (n.indexOf('Load') >= 0 || n.indexOf('Create') >= 0 || n.indexOf('Interpreter') >= 0)) {
          hits.push({ name: n, addr: s.address.toString(), rva: api.rva(s.address).toString() });
        }
      }
    } catch (e) {
      send({ t: 'log', msg: '[i] enumerateSymbols 失败（so 已 strip 或无符号表）: ' + e });
    }
    if (hits.length) send({ t: 'log', msg: '[i] hybridclr 候选符号:\n' + JSON.stringify(hits, null, 2) });
    return hits;
  };

  /**
   * 方案 A：hook hybridclr 原生入口
   * 常见符号名（mangled，arm64 Itanium ABI）：
   *   _ZN9hybridclr8metadata16InterpreterImage4LoadEPKvm
   *   _ZN9hybridclr8metadata8Assembly6CreateEPKhm
   */
  HC.hookNative = function (opts) {
    opts = opts || {};
    const m = api.module;
    const cands = [
      '_ZN9hybridclr8metadata16InterpreterImage4LoadEPKhm',
      '_ZN9hybridclr8metadata16InterpreterImage4LoadEPKvm',
      '_ZN9hybridclr8metadata8Assembly6CreateEPKhm',
      '_ZN9hybridclr8metadata8Assembly6CreateEPKvm',
      '_ZN9hybridclr8metadata8Assembly6CreateEPKhy'
    ];
    let found = [];
    // 1) 精确符号
    for (const c of cands) {
      const p = m.findExportByName(c);
      if (p) found.push({ name: c, addr: p });
    }
    // 2) 扫符号表里含 hybridclr + InterpreterImage::Load 的
    if (!found.length) {
      for (const s of HC.scanSymbols()) {
        if (s.name.indexOf('InterpreterImage4Load') >= 0 || s.name.indexOf('Assembly6Create') >= 0) {
          found.push({ name: s.name, addr: ptr(s.addr) });
        }
      }
    }
    if (!found.length) {
      send({ t: 'log', msg: '[-] 方案A 未找到 hybridclr 符号（strip 了），改用方案B（Assembly::Load）' });
      return null;
    }

    const ret = [];
    for (const f of found) {
      Interceptor.attach(f.addr, {
        onEnter(args) {
          // InterpreterImage::Load(this, const byte* data, size_t size)
          this.data = args[1];
          this.size = args[2];
          let n = 0;
          try { n = this.size.toInt32(); } catch (e) {}
          send({ t: 'log', msg: '[hybridclr] ' + f.name + ' data=' + this.data + ' size=' + n });
          if (n > 0 && n < 200 * 1024 * 1024) {
            const buf = this.data.readByteArray(n);
            save('native:' + f.name, buf, nameFromPE(buf));
            // 替换：如果 patch 目录有同名 dll，把缓冲区内容换掉
            if (opts.patch) HC.applyPatch(this.data, n, nameFromPE(buf));
          }
        }
      });
      ret.push({ name: f.name, addr: f.addr.toString(), rva: api.rva(f.addr).toString() });
      send({ t: 'log', msg: '[+] 方案A hooked ' + f.name + ' @ ' + f.addr });
    }
    return ret;
  };

  /**
   * 方案 B：hook System.Reflection.Assembly::Load(byte[])
   * 必须在热更 DLL 被加载之前装好 → 用 spawn 模式，脚本会轮询等待 il2cpp 就绪
   */
  HC.hookAssemblyLoad = function (opts) {
    opts = opts || {};
    const targets = [
      { ns: 'System.Reflection', cls: 'Assembly', m: 'Load', sig: ['System.Byte[]'] },
      { ns: 'System.Reflection', cls: 'Assembly', m: 'Load', sig: ['System.Byte[]', 'System.Byte[]'] },
      { ns: 'HybridCLR', cls: 'RuntimeApi', m: 'LoadMetadataForAOTAssembly', sig: null }, // 补元数据 dll 也一起抓
      { ns: 'System.Reflection', cls: 'Assembly', m: 'LoadFrom', sig: ['System.String'] }
    ];
    const out = [];
    for (const t of targets) {
      let image = null;
      if (t.ns === 'System.Reflection') image = api.getCorlibImage();
      else if (t.ns === 'HybridCLR') image = api.getImageByName('HybridCLR.Runtime.dll');
      const r = api.findMethodBySig(image, t.ns, t.cls, t.m, t.sig);
      if (!r.methods.length) {
        send({ t: 'log', msg: '[-] 未找到 ' + t.cls + '::' + t.m });
        continue;
      }
      for (const mi of r.methods) {
        const p = api.methodPointer(mi);
        if (p.isNull()) continue;
        Interceptor.attach(p, {
          onEnter(args) {
            // 静态：Load(byte[]) -> args[0]=byte[]; Load(byte[],byte[]) -> args[0],args[1]
            const arr = args[0];
            const n = H.readArrayLen(arr);
            send({ t: 'log', msg: '[Assembly] ' + t.cls + '::' + t.m + ' len=' + n });
            if (n > 0 && n < 200 * 1024 * 1024) {
              const buf = H.readArrayBytes(arr, n);
              const name = t.m === 'LoadFrom' ? ('from_' + n + '.dll') : nameFromPE(buf);
              save('managed:' + t.cls + '::' + t.m, buf, name, { method: t.m });
              if (opts.patch) HC.applyPatch(arr.add(H.OFF.arr.vector), n, name);
            }
          }
        });
        out.push({ method: t.cls + '::' + t.m, addr: p.toString(), rva: api.rva(p).toString() });
        send({ t: 'log', msg: '[+] 方案B hooked ' + t.cls + '::' + t.m + ' @ ' + p });
      }
    }
    return out;
  };

  /** 把 /data/local/tmp/il2cpp-harness/patch/<name>.dll 的内容写回目标缓冲区 */
  HC.applyPatch = function (dest, maxLen, name) {
    try {
      const path = PATCH_DIR + name;
      const f = new File(path, 'rb');
      const data = f.readBytes();
      f.close();
      if (!data || !data.byteLength) return false;
      if (data.byteLength > maxLen) {
        send({ t: 'log', msg: '[!] patch 比原始 dll 大(' + data.byteLength + '>' + maxLen + ')，跳过' });
        return false;
      }
      dest.writeByteArray(data);
      send({ t: 'log', msg: '[+] 已注入 patch: ' + path + ' (' + data.byteLength + ' bytes)' });
      return true;
    } catch (e) {
      return false; // 没有 patch 文件是正常情况，静默
    }
  };

  /** 方案 C：hook libc，记录所有 .dll/.bytes/.dat 打开行为，抓路径 */
  HC.hookFileOpen = function () {
    const hooked = [];
    for (const libcName of ['libc.so']) {
      for (const sym of ['open', 'openat', 'fopen']) {
        const p = Module.findExportByName(libcName, sym);
        if (!p) continue;
        try {
          Interceptor.attach(p, {
            onEnter(args) {
              let pathPtr = sym === 'openat' ? args[1] : args[0];
              let s = '';
              try { s = pathPtr.readCString(256); } catch (e) { return; }
              if (!s) return;
              if (/\.(dll|bytes|dat|pdb)(\.bytes)?$/i.test(s) || s.indexOf('HotUpdate') >= 0 || s.indexOf('hotfix') >= 0) {
                send({ t: 'log', msg: '[file] ' + sym + ' ' + s + '\n        ' +
                  Thread.backtrace(this.context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).join('\n        ') });
              }
            }
          });
          hooked.push(sym);
        } catch (e) {}
      }
    }
    send({ t: 'log', msg: '[+] 方案C hooked libc: ' + hooked.join(',') });
    return hooked;
  };

  /**
   * 一键：等 il2cpp 就绪 → 装 A/B/C 三套 hook
   * @param {object} opts { patch:bool, hookFiles:bool }
   */
  HC.start = function (opts) {
    opts = opts || {};
    const res = { native: null, managed: null, files: null };
    if (opts.hookFiles !== false) res.files = HC.hookFileOpen();
    res.native = HC.hookNative(opts);
    res.managed = HC.hookAssemblyLoad(opts);
    if (!res.native && (!res.managed || !res.managed.length)) {
      send({ t: 'log', msg: '[!] A/B 都没装上。可能原因：1) hook 时机晚于 dll 加载（改用 spawn 模式） 2) so 被 strip 且 Assembly.Load 不是这个重载' });
    }
    return res;
  };

  G.HybridCLR = HC;
})();
