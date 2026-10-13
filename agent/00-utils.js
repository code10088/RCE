/**
 * 00-utils.js —— 基础工具：模块定位、il2cpp 运行时对象读写、分片回传、偏移自检
 * 适用：Android arm64 + libil2cpp.so（Unity 2021.3.x 验证）
 */
'use strict';
const G = globalThis;
G.H = G.H || {};

(function (H) {
  // Frida 17 moved export lookup to module instances / global lookup.
  if (typeof Module.findExportByName !== 'function') {
    Module.findExportByName = function (moduleName, symbol) {
      if (moduleName === null) return Module.findGlobalExportByName(symbol);
      const module = Process.findModuleByName(moduleName);
      return module ? module.findExportByName(symbol) : null;
    };
  }
  // ---------- 内存布局常量（64 位 il2cpp） ----------
  // Il2CppObject : { klass/vtable:8, monitor:8 }
  // Il2CppString : { object:16, length:int32 @16, chars:uint16 @20 }
  // Il2CppArray  : { object:16, bounds:* @16, max_length:size_t @24, vector @32 }
  H.OFF = {
    str: { length: 16, chars: 20 },
    arr: { maxLength: 24, vector: 32 }
  };

  H.mod = function (name) {
    name = name || 'libil2cpp.so';
    let m = Process.findModuleByName(name);
    if (!m) {
      // 兜底：按路径包含关系找
      m = Process.enumerateModules().find(x => x.path.indexOf(name) >= 0) || null;
    }
    return m;
  };

  H.cstr = function (p, max) {
    if (p == null || p.isNull()) return '';
    try {
      const limit = max || 512;
      let n = 0;
      while (n < limit && p.add(n).readU8() !== 0) n++;
      return n ? (p.readUtf8String(n) || '') : '';
    } catch (e) { return ''; }
  };

  // ---------- Il2CppString ----------
  H.readStr = function (p) {
    if (p == null || p.isNull()) return null;
    try {
      const len = p.add(H.OFF.str.length).readU32();
      if (len > 0x100000) return '<bad-string-len>';
      return p.add(H.OFF.str.chars).readUtf16String(len);
    } catch (e) { return '<unreadable>'; }
  };

  // ---------- Il2CppArray（byte[] / T[]） ----------
  H.readArrayLen = function (p) {
    if (p == null || p.isNull()) return 0;
    try { return p.add(H.OFF.arr.maxLength).readU32(); } catch (e) { return 0; }
  };
  H.readArrayBytes = function (p, len) {
    if (p == null || p.isNull()) return null;
    len = len == null ? H.readArrayLen(p) : len;
    if (len <= 0 || len > 512 * 1024 * 1024) return null;
    try { return p.add(H.OFF.arr.vector).readByteArray(len); } catch (e) { return null; }
  };

  // ---------- 回传：大字符串分片、二进制直传 ----------
  H.sendText = function (tag, text, chunk) {
    chunk = chunk || 512 * 1024;
    const total = text.length;
    const parts = Math.ceil(total / chunk) || 1;
    for (let i = 0, off = 0; i < parts; i++, off += chunk) {
      send({ t: 'text', tag: tag, i: i, parts: parts, data: text.substr(off, chunk) });
    }
    send({ t: 'text-end', tag: tag, parts: parts, bytes: total });
  };

  H.sendBin = function (tag, meta, buf) {
    if (!buf) return false;
    send(Object.assign({ t: 'bin', tag: tag }, meta || {}), buf);
    return true;
  };

  // ---------- 设备上直接落盘（frida-server 有权限时最快） ----------
  H.writeDeviceFile = function (path, bytes) {
    try {
      const f = new File(path, 'wb');
      f.write(bytes);
      f.flush();
      f.close();
      return true;
    } catch (e) {
      console.log('[!] writeDeviceFile 失败: ' + e + ' (path=' + path + ')');
      return false;
    }
  };

  // ---------- 偏移自检：确认 length/vector 偏移是否匹配当前 Unity 版本 ----------
  H.selfCheck = function (api) {
    const out = { string: false, array: false };
    try {
      const s = api.string_new(Memory.allocUtf8String('ABCDE'));
      out.string = (!s.isNull()) && s.add(H.OFF.str.length).readU32() === 5;
      out.stringSample = H.readStr(s);
    } catch (e) { out.stringErr = String(e); }
    try {
      // 找一个 byte[] 类型创建数组，校验 max_length / vector
      const img = api.getCorlibImage();
      const byteCls = api.class_from_name(img, Memory.allocUtf8String('System'), Memory.allocUtf8String('Byte'));
      if (!byteCls.isNull()) {
        const arr = api.array_new(byteCls, 7);
        out.array = (!arr.isNull()) && H.readArrayLen(arr) === 7;
        out.arrayLen = H.readArrayLen(arr);
      }
    } catch (e) { out.arrayErr = String(e); }
    if (!out.string || !out.array) {
      console.log('[!] 偏移自检未通过，请检查 Unity 版本/位数: ' + JSON.stringify(out));
    } else {
      console.log('[*] 偏移自检通过 (64-bit il2cpp)');
    }
    return out;
  };

  // ---------- 线程附加：非托管线程里调 il2cpp API 前必须 attach ----------
  H.attachIfNeeded = function (api, domain) {
    try {
      const d = domain || api.domain_get();
      if (!d.isNull()) api.thread_attach(d);
    } catch (e) {}
  };

  H.hexdumpLite = function (p, n) {
    try { return hexdump(p, { length: Math.min(n || 64, 256) }); } catch (e) { return ''; }
  };
})(G.H);
