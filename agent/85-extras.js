/**
 * 85-extras.js —— 高频补充能力
 *
 *   X.javaHook()      Java 层 hook（Unity 项目必然有 Java 侧：支付/登录/SDK）
 *   X.unityLogs()     抓全部 Debug.Log（不用开 logcat，直接看 C# 打的日志）
 *   X.heapStrings()   扫堆里所有存活的托管字符串（找 URL / 密钥 / 配置最快的一招）
 *   X.dumpObject()    按 class 把一个实例的所有字段值打印出来
 *   X.hookBatch()     正则批量 hook（一次挂几十个方法）
 *   X.profile()       调用次数 + 耗时统计（找性能热点）
 *   X.watchCtor()     追踪某个类的所有实例创建
 */
'use strict';
const G = globalThis;
const H = G.H;

(function () {
  const X = {};

  // ============================================================
  // 1. Java 层 hook
  // ============================================================
  /**
   * @param className  如 'com.unity3d.player.UnityPlayer'
   * @param methodName 方法名；重载多时配合 overloads
   * @param cb         frida 的 Java implementation 回调
   */
  X.javaHook = function (className, methodName, cb) {
    if (!Java.available) { send({ t: 'log', msg: '[-] 当前进程没有 Java VM' }); return null; }
    let result = null;
    Java.perform(function () {
      try {
        const C = Java.use(className);
        const overloads = C[methodName].overloads;
        for (const ov of overloads) {
          ov.implementation = function () {
            const args = Array.prototype.slice.call(arguments);
            const ret = cb ? cb(args, this) : undefined;
            if (ret !== undefined) return ret;
            return ov.call.apply(ov, [this].concat(args));
          };
        }
        result = { cls: className, method: methodName, overloads: overloads.length };
        send({ t: 'log', msg: '[java] hooked ' + className + '.' + methodName +
          ' (' + overloads.length + ' 个重载)' });
      } catch (e) {
        send({ t: 'log', msg: '[!] java hook 失败: ' + e });
      }
    });
    return result;
  };

  /** 列出某个 Java 类的所有方法，先探再 hook */
  X.javaList = function (className) {
    if (!Java.available) return null;
    let out = null;
    Java.perform(function () {
      try {
        const C = Java.use(className);
        out = Object.keys(C).filter(k => typeof C[k] === 'function' || C[k].overloads);
        send({ t: 'log', msg: '[java] ' + className + ' 方法:\n' + JSON.stringify(out, null, 1) });
      } catch (e) {
        send({ t: 'log', msg: '[!] ' + e });
      }
    });
    return out;
  };

  // ============================================================
  // 2. 抓 Unity 日志
  // ============================================================
  /**
   * 直接 hook UnityEngine.Debug 的 Log/LogWarning/LogError，
   * 比 adb logcat 干净：不受系统日志淹没，且能拿到托管线程上下文
   */
  X.unityLogs = function (opts) {
    opts = opts || {};
    const api = G.IL2CPP;
    if (!api || !api.ready) return { error: 'il2cpp 未就绪' };
    const targets = [
      ['Log', 1], ['LogWarning', 1], ['LogError', 1],
      ['LogFormat', 2], ['LogException', 1]
    ];
    const out = [];
    for (const [m, argc] of targets) {
      const r = api.findMethod(null, 'UnityEngine', 'Debug', m, argc);
      if (!r.methods.length) continue;
      const p = api.methodPointer(r.methods[0]);
      if (p.isNull()) continue;
      Interceptor.attach(p, {
        onEnter(args) {
          // Debug.Log(object message)：第一个参数是 Il2CppObject
          let text = '';
          try {
            // 先看是不是 string（klass 名 == System.String）
            const k = args[0].readPointer();
            const kn = H.cstr(api.class_get_name(k));
            if (kn === 'String') text = H.readStr(args[0]);
            else text = '<' + kn + '> ' + args[0];
          } catch (e) { text = '<unreadable>'; }
          const tag = m === 'LogError' ? 'E' : m === 'LogWarning' ? 'W' : 'I';
          send({ t: 'log', msg: '[unity/' + tag + '] ' + text });
        }
      });
      out.push({ method: m, addr: p.toString(), rva: api.rva(p).toString() });
    }
    if (!out.length) {
      send({ t: 'log', msg: '[-] 未找到 Debug.Log（可能被裁剪了）。改用 adb logcat -s Unity' });
    } else {
      send({ t: 'log', msg: '[+] Unity 日志 hook 已装: ' + out.map(x => x.method).join(', ') });
    }
    return out;
  };

  // ============================================================
  // 3. 扫堆里的托管字符串
  // ============================================================
  /**
   * 原理：所有存活的 Il2CppString 实例，其首字段都指向 System.String 的 klass。
   * 扫描 rw- 区找这个指针值，按 Il2CppString 布局（len@16, chars@20）读出来。
   *
   * 这是找后端 URL / API 密钥 / 配置常量最快的一招 —— 比静态翻 stringliteral 强，
   * 因为这里拿到的是「运行时真正存活的」，已经过了任何静态加密。
   */
  X.heapStrings = function (opts) {
    opts = opts || {};
    const api = G.IL2CPP;
    if (!api || !api.ready) return { error: 'il2cpp 未就绪' };

    const strKlass = api.findClass(null, 'System', 'String');
    if (strKlass.isNull()) return { error: '找不到 System.String' };
    const strKlassVal = strKlass.toString();

    const minLen = opts.minLen || 4;
    const maxLen = opts.maxLen || 512;
    const filter = opts.filter ? new RegExp(opts.filter, 'i') : null;
    const found = new Map();   // 去重，堆里同一个字符串常有多份引用

    // 把 klass 指针写成可扫描的字节 pattern（小端）
    const addr = parseInt(strKlassVal.replace('0x', ''), 16);
    const pat = [];
    for (let i = 0; i < 8; i++) pat.push(('0' + ((addr >>> (i * 8)) & 0xff).toString(16)).slice(-2));
    const pattern = pat.join(' ');

    send({ t: 'log', msg: '[strings] System.String klass=' + strKlassVal + '，扫描堆…' });
    const t0 = Date.now();

    for (const r of Process.enumerateRangesSync('rw-')) {
      if (r.size < 4096) continue;
      try {
        Memory.scan(r.base, r.size, pattern, {
          onMatch(a) {
            // a 是「klass 指针所在位置」，也就是 Il2CppString 对象头
            try {
              const len = a.add(H.OFF.str.length).readU32();
              if (len < minLen || len > maxLen) return 'continue';
              const s = a.add(H.OFF.str.chars).readUtf16String(len);
              if (s && s.length === len) {
                if (filter && !filter.test(s)) return 'continue';
                if (!found.has(s)) found.set(s, a.toString());
              }
            } catch (e) {}
            return 'continue';
          },
          onError() { return 'continue'; }
        });
      } catch (e) {}
    }

    const list = Array.from(found.entries()).map(([s, a]) => ({ addr: a, text: s }));
    const json = JSON.stringify(list, null, 0);
    H.sendText(opts.tag || 'heap_strings.json', json);
    send({ t: 'log', msg: '[strings] 抓到 ' + list.length + ' 个唯一字符串，耗时 ' +
      (Date.now() - t0) + 'ms' });
    // 预览几条最像「有用信息」的
    const juicy = list.filter(x => /https?:\/\/|api|key|token|secret|pass|url/i.test(x.text)).slice(0, 30);
    if (juicy.length) {
      send({ t: 'log', msg: '[strings] 疑似敏感/URL 的条目:\n' +
        juicy.map(x => '  ' + x.addr + '  ' + x.text.slice(0, 200)).join('\n') });
    }
    return { count: list.length, juicy: juicy.length };
  };

  // ============================================================
  // 4. 对象转储
  // ============================================================
  /**
   * 给一个实例指针 + 它的 class，把所有字段值打印出来。
   * 配合 Dump.dumpClass() 的字段偏移使用，是「拿到对象 → 看懂它」的关键一步。
   */
  X.dumpObject = function (objPtr, namespaze, clsName, opts) {
    opts = opts || {};
    const api = G.IL2CPP;
    if (!api || !api.ready) return { error: 'il2cpp 未就绪' };
    const klass = api.findClass(null, namespaze, clsName);
    if (klass.isNull()) return { error: 'class not found' };

    const fields = api.classFields(klass);
    const lines = [];
    for (const fi of fields) {
      const name = H.cstr(api.field_get_name(fi));
      let offset = -1, typeName = '', isStatic = false;
      try { offset = api.field_get_offset(fi).toNumber(); } catch (e) {}
      try { typeName = api.typeName(api.field_get_type(fi)); } catch (e) {}
      try { isStatic = (api.field_get_flags(fi) & 0x10) !== 0; } catch (e) {}

      let value;
      try {
        if (isStatic) {
          const buf = Memory.alloc(Process.pointerSize);
          api.field_static_get_value(fi, buf);
          value = X.interpret(buf, typeName, opts.depth || 0);
        } else {
          value = X.interpret(objPtr.add(offset), typeName, opts.depth || 0);
        }
      } catch (e) { value = '<err>'; }
      lines.push({
        name: name, type: typeName, offset: offset,
        static: isStatic, value: value
      });
    }
    const out = { class: namespaze + '.' + clsName, obj: ptr(objPtr).toString(), fields: lines };
    send({ t: 'log', msg: JSON.stringify(out, null, 1) });
    return out;
  };

  /** 按类型名解释一块内存的值（递归一层，够用了） */
  X.interpret = function (addr, typeName, depth) {
    const a = ptr(addr);
    if (a.isNull()) return 'null';
    try {
      switch (typeName) {
        case 'System.String': return H.readStr(a);
        case 'System.Int32': case 'System.Int32&': return a.readS32();
        case 'System.UInt32': return a.readU32();
        case 'System.Int64': return a.readS64().toString();
        case 'System.UInt64': return a.readU64().toString();
        case 'System.Int16': return a.readS16();
        case 'System.UInt16': return a.readU16();
        case 'System.Byte': case 'System.SByte': return a.readU8();
        case 'System.Single': return a.readFloat();
        case 'System.Double': return a.readDouble();
        case 'System.Boolean': return !!a.readU8();
        case 'System.Char': return String.fromCharCode(a.readU16());
        default: {
          if (depth > 0) return '<obj>';
          // 引用类型：打印 klass 名 + 一层字段
          const k = a.readPointer();
          if (k.isNull()) return 'null';
          let kn = '';
          try { kn = G.IL2CPP.className(k); } catch (e) { return '<unknown> ' + a; }
          if (/^System\.(Int|UInt|Single|Double|Boolean|String|Char)/.test(kn)) {
            return X.interpret(a, kn, 1);
          }
          return '<' + kn + '> ' + a;
        }
      }
    } catch (e) { return '<unreadable>'; }
  };

  // ============================================================
  // 5. 批量 hook（正则匹配类名/方法名）
  // ============================================================
  /**
   * @param opts { classRe, methodRe, image, logArgs, maxHooks }
   * 典型：X.hookBatch({ classRe: /Manager$/, methodRe: /^(Init|Start)$/ })
   */
  X.hookBatch = function (opts) {
    opts = opts || {};
    const api = G.IL2CPP;
    if (!api || !api.ready) return { error: 'il2cpp 未就绪' };
    const classRe = opts.classRe ? new RegExp(opts.classRe) : null;
    const methodRe = opts.methodRe ? new RegExp(opts.methodRe) : null;
    const max = opts.maxHooks || 200;
    const hooked = [];

    for (const img of api.getImages()) {
      const nm = api.imageName(img);
      if (opts.image && nm !== opts.image) continue;
      const cnt = api.image_get_class_count(img);
      for (let i = 0; i < cnt && hooked.length < max; i++) {
        const klass = api.image_get_class(img, i);
        if (klass.isNull()) continue;
        const cn = api.className(klass);
        if (classRe && !classRe.test(cn)) continue;
        for (const mi of api.classMethods(klass)) {
          if (hooked.length >= max) break;
          const mn = api.methodName(mi);
          if (methodRe && !methodRe.test(mn)) continue;
          let p;
          try { p = api.methodPointer(mi); } catch (e) { continue; }
          if (p.isNull()) continue;
          const fullName = cn + '::' + mn;
          Interceptor.attach(p, {
            onEnter(args) {
              const ps = opts.logArgs === false ? '' :
                args.slice(0, 6).map(x => x.toString()).join(' ');
              send({ t: 'log', msg: '[batch] ' + fullName + (ps ? '  ' + ps : '') });
            }
          });
          hooked.push({ name: fullName, rva: api.rva(p).toString() });
        }
      }
    }
    send({ t: 'log', msg: '[batch] 共挂 ' + hooked.length + ' 个 hook' +
      (hooked.length >= max ? '（达上限）' : '') });
    return { count: hooked.length, hooks: hooked.slice(0, 50) };
  };

  // ============================================================
  // 6. 性能剖析：调用次数 + 耗时
  // ============================================================
  X.__prof = {};
  X.profile = function (namespaze, clsName, methodName, argc) {
    const api = G.IL2CPP;
    if (!api || !api.ready) return { error: 'il2cpp 未就绪' };
    const r = api.findMethod(null, namespaze, clsName, methodName, argc == null ? -1 : argc);
    if (!r.methods.length) return { error: 'method not found' };
    const key = namespaze + '.' + clsName + '::' + methodName;
    X.__prof[key] = { count: 0, totalMs: 0, maxMs: 0, minMs: 1e9 };
    const rec = X.__prof[key];
    const p = api.methodPointer(r.methods[0]);
    Interceptor.attach(p, {
      onEnter() { rec._t = Date.now(); },
      onLeave() {
        const d = Date.now() - rec._t;
        rec.count++;
        rec.totalMs += d;
        if (d > rec.maxMs) rec.maxMs = d;
        if (d < rec.minMs) rec.minMs = d;
      }
    });
    send({ t: 'log', msg: '[prof] 开始统计 ' + key + ' @ ' + p });
    return { key: key, addr: p.toString(), rva: api.rva(p).toString() };
  };

  X.profileReport = function () {
    const rows = Object.keys(X.__prof).map(k => {
      const r = X.__prof[k];
      return {
        method: k,
        calls: r.count,
        avgMs: r.count ? +(r.totalMs / r.count).toFixed(3) : 0,
        maxMs: r.maxMs === 0 ? 0 : r.maxMs,
        minMs: r.minMs === 1e9 ? 0 : r.minMs,
        totalMs: r.totalMs
      };
    }).sort((a, b) => b.totalMs - a.totalMs);
    send({ t: 'log', msg: '===== 调用耗时统计（按总耗时降序）=====' });
    for (const r of rows) {
      send({ t: 'log', msg: '  ' + r.method + '  calls=' + r.calls +
        '  avg=' + r.avgMs + 'ms  max=' + r.maxMs + 'ms  total=' + r.totalMs + 'ms' });
    }
    return rows;
  };

  // ============================================================
  // 7. 追踪实例创建
  // ============================================================
  /**
   * hook 构造函数，抓到某类的每一个实例。
   * IL2CPP 里没有「遍历堆上所有对象」的公开 API，
   * 所以想拿到活着的实例，只能从构造入口截获 —— 这是最实用的替代。
   */
  X.watchCtor = function (namespaze, clsName, opts) {
    opts = opts || {};
    const api = G.IL2CPP;
    if (!api || !api.ready) return { error: 'il2cpp 未就绪' };
    const klass = api.findClass(null, namespaze, clsName);
    if (klass.isNull()) return { error: 'class not found' };

    const instances = [];
    const ctors = api.classMethods(klass).filter(mi => api.methodName(mi) === '.ctor');
    if (!ctors.length) {
      send({ t: 'log', msg: '[-] ' + clsName + ' 没有 .ctor（可能是值类型或被裁剪）' });
      return { error: 'no ctor' };
    }
    for (const mi of ctors) {
      const p = api.methodPointer(mi);
      if (p.isNull()) continue;
      Interceptor.attach(p, {
        onEnter(args) {
          // 实例方法的 args[0] 就是 this
          const self = args[0];
          if (self.isNull()) return;
          instances.push({ addr: self.toString(), time: Date.now() });
          send({ t: 'log', msg: '[ctor] ' + clsName + ' 新实例 ' + self +
            (opts.dumpFields ? '\n' + JSON.stringify(X.dumpObject(self, namespaze, clsName, opts), null, 1) : '') +
            '\n        ' + Thread.backtrace(this.context, Backtracer.FUZZY)
              .map(DebugSymbol.fromAddress).slice(0, 5).join('\n        ') });
        }
      });
    }
    send({ t: 'log', msg: '[+] 已监控 ' + clsName + ' 的 ' + ctors.length + ' 个构造函数' });
    X.__instances = X.__instances || {};
    X.__instances[clsName] = instances;
    return { cls: clsName, ctors: ctors.length };
  };

  X.listInstances = function (clsName) {
    const ins = (X.__instances || {})[clsName];
    if (!ins) return null;
    send({ t: 'log', msg: '[instances] ' + clsName + ': ' + ins.length + ' 个\n' +
      JSON.stringify(ins.slice(0, 50), null, 0) });
    return ins.slice(0, 50);
  };

  G.Extras = X;
})();
