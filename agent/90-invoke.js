/**
 * 90-invoke.js —— 主动调用方法 / 读写字段（不只是 hook，是「调用」）
 *
 * 之前的 30-hook.js 只能**被动拦截**：方法被游戏调用时你才能看到。
 * 这个模块是**主动调用**：你随时让游戏执行任意方法并拿到返回值。
 *
 * 调试价值极高：
 *   验证逻辑 —— 直接调 AddGold(100) 看结果，不用等游戏流程走到
 *   读状态   —— 调 GetXxx() 拿当前值
 *   触发分支 —— 调 ForceSave() / ResetTutorial() 之类
 *   改参数   —— 静态字段直接 set，比 patch so 快
 *
 * 核心机制：il2cpp_runtime_invoke(method, obj, params, exc)
 *   params 是 void**，第 i 个元素是**指向参数值的指针**
 *     值类型(int/float/bool) → 指向值的指针
 *     引用类型(string/obj)   → 指向「对象指针」的指针
 *   返回值：引用类型直接是对象指针；值类型是**装箱对象**，真实值在 +16（64位对象头 16 字节）
 *
 * 这两个细节搞错就会拿到乱码或崩溃，代码里已处理。
 */
'use strict';
const G = globalThis;
const H = G.H;
const api = G.IL2CPP;

(function () {
  const Inv = {};

  // ---------- 参数槽构造：按实际类型把用户给的字符串变成内存里的值 ----------
  function makeSlot(typeName, spec) {
    const slot = Memory.alloc(24);
    const s = (spec === undefined || spec === null) ? '' : String(spec);
    switch (typeName) {
      case 'System.String':
        try { slot.writePointer(api.newString(s)); } catch (e) { slot.writePointer(NULL); }
        break;
      case 'System.Int32': slot.writeS32(parseInt(s, 10) || 0); break;
      case 'System.UInt32': slot.writeU32(parseInt(s, 10) || 0); break;
      case 'System.Int64':
        try { slot.writeS64(int64(s)); } catch (e) { slot.writeS64(0); }
        break;
      case 'System.UInt64':
        try { slot.writeU64(uint64(s)); } catch (e) { slot.writeU64(0); }
        break;
      case 'System.Int16': slot.writeS16(parseInt(s, 10) || 0); break;
      case 'System.UInt16': slot.writeU16(parseInt(s, 10) || 0); break;
      case 'System.Byte': case 'System.SByte': slot.writeU8(parseInt(s, 10) || 0); break;
      case 'System.Boolean': slot.writeU8((s === 'true' || s === '1' || s === 'True') ? 1 : 0); break;
      case 'System.Single': slot.writeFloat(parseFloat(s) || 0); break;
      case 'System.Double': slot.writeDouble(parseFloat(s) || 0); break;
      case 'System.Char': slot.writeU16(s ? s.charCodeAt(0) : 0); break;
      default:
        // 引用类型 / 指针：当十六进制地址传
        try {
          const v = /^0x/i.test(s) ? ptr(s) : ptr(s);
          slot.writePointer(v);
        } catch (e) {
          // 不是合法地址就传 null（自动传参失败的兜底）
          slot.writePointer(NULL);
        }
    }
    return slot;
  }

  // ---------- 返回值读取 ----------
  const VALUE_TYPES = /^System\.(Int16|UInt16|Int32|UInt32|Int64|UInt64|Byte|SByte|Boolean|Single|Double|Char|Decimal|Void|DateTime|TimeSpan)/;

  function readVal(retPtr, typeName) {
    if (!retPtr || retPtr.isNull()) return null;
    if (typeName === 'System.Void' || typeName === 'Void') return null;
    if (typeName === 'System.String') return H.readStr(retPtr);
    if (typeName && typeName.indexOf('[]') >= 0) {
      const n = H.readArrayLen(retPtr);
      return '<array len=' + n + '> ' + retPtr;
    }
    // 值类型：装箱对象，真实数据在对象头之后（64 位 = 16 字节）
    const isVal = VALUE_TYPES.test(typeName || '');
    const base = isVal ? retPtr.add(16) : retPtr;
    switch (typeName) {
      case 'System.Int32': return base.readS32();
      case 'System.UInt32': return base.readU32();
      case 'System.Int64': return base.readS64().toString();
      case 'System.UInt64': return base.readU64().toString();
      case 'System.Int16': return base.readS16();
      case 'System.UInt16': return base.readU16();
      case 'System.Byte': case 'System.SByte': return base.readU8();
      case 'System.Boolean': return !!base.readU8();
      case 'System.Single': return base.readFloat();
      case 'System.Double': return base.readDouble();
      case 'System.Char': return String.fromCharCode(base.readU16());
      default: {
        // 引用类型：给出 klass 名 + 地址，方便接着 dumpObject
        let kn = '';
        try { kn = api.className(base.readPointer()); } catch (e) {}
        return kn ? ('<' + kn + '> ' + retPtr) : retPtr.toString();
      }
    }
  }

  /**
   * 调用一个方法
   * @param objPtr  实例方法的 this；静态传 null
   * @param argSpecs 参数数组（字符串形式，按实际类型自动解析）
   */
  Inv.invoke = function (ns, clsName, methodName, argSpecs, objPtr, argcFilter) {
    if (!api.ready) return { error: 'il2cpp 未就绪' };
    const r = api.findMethod(null, ns, clsName, methodName,
      (argcFilter != null ? argcFilter : (argSpecs ? argSpecs.length : -1)));
    if (!r.methods.length) {
      send({ t: 'log', msg: '[!] 未找到方法 ' + ns + '.' + clsName + '::' + methodName });
      return { error: 'method not found' };
    }
    const mi = r.methods[0];
    const pc = api.method_get_param_count(mi);
    if (argSpecs && argSpecs.length && argSpecs.length !== pc) {
      send({ t: 'log', msg: '[i] 参数个数不匹配：目标需要 ' + pc + ' 个，你给了 ' + argSpecs.length +
        ' 个（多传的会被忽略，少传的补默认值）' });
    }

    const n = Math.max(pc, 1);
    const params = Memory.alloc(Process.pointerSize * n);
    for (let i = 0; i < pc; i++) {
      const tn = api.typeName(api.method_get_param(mi, i));
      const slot = makeSlot(tn, argSpecs ? argSpecs[i] : undefined);
      params.add(i * Process.pointerSize).writePointer(slot);
    }

    const exc = Memory.alloc(Process.pointerSize);
    exc.writePointer(NULL);

    const obj = objPtr ? ptr(objPtr) : NULL;
    let ret = NULL;
    try {
      ret = api.runtime_invoke(mi, obj, params, exc);
    } catch (e) {
      return { error: 'invoke 异常: ' + e };
    }

    const excPtr = exc.readPointer();
    if (!excPtr.isNull()) {
      send({ t: 'log', msg: '[!] 方法内部抛异常: ' + excPtr + '  (' + api.className(excPtr.readPointer()) + ')' });
      return { error: 'exception', detail: excPtr.toString() };
    }

    const retType = api.typeName(api.method_get_return_type(mi));
    const val = readVal(ret, retType);
    const out = {
      method: ns + '.' + clsName + '::' + methodName,
      retType: retType,
      value: val,
      raw: ret.isNull() ? null : ret.toString()
    };
    send({ t: 'log', msg: '[call] ' + out.method + ' -> ' + retType + ' = ' + JSON.stringify(val) });
    return out;
  };

  /** 便捷：调静态 */
  Inv.callStatic = function (ns, clsName, methodName, argSpecs) {
    return Inv.invoke(ns, clsName, methodName, argSpecs || [], null,
      argSpecs ? argSpecs.length : -1);
  };

  // ============================================================
  // 静态字段读写（比 hook 改值更直接）
  // ============================================================
  function findField(ns, clsName, fieldName) {
    const klass = api.findClass(null, ns, clsName);
    if (klass.isNull()) return null;
    for (const fi of api.classFields(klass)) {
      if (H.cstr(api.field_get_name(fi)) === fieldName) return { klass: klass, fi: fi };
    }
    return null;
  }

  Inv.getStaticField = function (ns, clsName, fieldName) {
    const f = findField(ns, clsName, fieldName);
    if (!f) return { error: 'field not found' };
    const tn = api.typeName(api.field_get_type(f.fi));
    const buf = Memory.alloc(24);
    buf.writePointer(NULL);
    try { api.field_static_get_value(f.fi, buf); } catch (e) { return { error: String(e) }; }
    const val = readVal(buf, tn);
    send({ t: 'log', msg: '[field] ' + clsName + '.' + fieldName + ' (' + tn + ') = ' + JSON.stringify(val) });
    return { field: fieldName, type: tn, value: val };
  };

  Inv.setStaticField = function (ns, clsName, fieldName, value) {
    const f = findField(ns, clsName, fieldName);
    if (!f) return { error: 'field not found' };
    const tn = api.typeName(api.field_get_type(f.fi));
    const slot = makeSlot(tn, value);
    try { api.field_static_set_value(f.fi, slot); } catch (e) { return { error: String(e) }; }
    send({ t: 'log', msg: '[field] 已设置 ' + clsName + '.' + fieldName + ' = ' + value + ' (' + tn + ')' });
    return { ok: true, field: fieldName, type: tn, value: value };
  };

  /** 列出一个类的全部静态字段当前值（看全局配置/开关最快） */
  Inv.dumpStatics = function (ns, clsName) {
    const klass = api.findClass(null, ns, clsName);
    if (klass.isNull()) return { error: 'class not found' };
    const out = [];
    for (const fi of api.classFields(klass)) {
      let isStatic = false;
      try { isStatic = (api.field_get_flags(fi) & 0x10) !== 0; } catch (e) {}
      if (!isStatic) continue;
      const tn = api.typeName(api.field_get_type(f.fi));
      const buf = Memory.alloc(24);
      buf.writePointer(NULL);
      let v = null;
      try { api.field_static_get_value(fi, buf); v = readVal(buf, tn); } catch (e) { v = '<err>'; }
      out.push({ name: H.cstr(api.field_get_name(fi)), type: tn, value: v });
    }
    send({ t: 'log', msg: '[statics] ' + ns + '.' + clsName + '\n' + JSON.stringify(out, null, 1) });
    return out;
  };

  // ============================================================
  // 常用快捷：时间倍速（调试加速神器）
  // ============================================================
  /**
   * Unity 的 Time.timeScale。调成 3~5 能大幅加速等待类调试；
   * 调 0 可冻结逻辑（方便在某一帧停下来观察）。
   */
  Inv.setTimeScale = function (v) {
    const f = parseFloat(v);
    if (isNaN(f)) return { error: '需要数字' };
    // 优先走 set_timeScale 静态方法
    let r = api.findMethod(null, 'UnityEngine', 'Time', 'set_timeScale', 1);
    if (r.methods.length) {
      const mi = r.methods[0];
      const slot = Memory.alloc(16);
      slot.writeFloat(f);
      const params = Memory.alloc(Process.pointerSize);
      params.writePointer(slot);
      const exc = Memory.alloc(Process.pointerSize);
      exc.writePointer(NULL);
      try {
        api.runtime_invoke(mi, NULL, params, exc);
        send({ t: 'log', msg: '[time] timeScale = ' + f });
        return { ok: true, timeScale: f };
      } catch (e) { /* 落到下面改字段 */ }
    }
    return Inv.setStaticField('UnityEngine', 'Time', 'timeScale', String(f));
  };

  Inv.getTimeScale = function () {
    return Inv.getStaticField('UnityEngine', 'Time', 'timeScale');
  };

  G.Invoke = Inv;
})();
