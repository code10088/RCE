/**
 * 30-hook.js —— Hook 拦截与改写
 * IL2CPP 生成函数的真实签名（arm64 AAPCS，参数走 X0..X7）：
 *   实例方法: R f(Il2CppObject* __this, P0..Pn, const MethodInfo* method)
 *   静态方法: R f(P0..Pn, const MethodInfo* method)
 * 所以 args[0] 对实例方法是 this，MethodInfo* 永远是最后一个参数。
 *
 * 三种粒度：
 *   A. hookMethod        直接 attach 到 MethodInfo->methodPointer（最常用）
 *   B. hookRuntimeInvoke 全局拦截 il2cpp_runtime_invoke（含 HybridCLR 解释执行的方法）
 *   C. replaceMethod     用 NativeCallback 整段替换实现
 */
'use strict';
const G = globalThis;
const H = G.H;
const api = G.IL2CPP;

(function () {
  const Hook = {};
  const S = (s) => Memory.allocUtf8String(s);

  /** A. 按 命名空间.类名.方法名 hook，返回 {addr, rva} */
  Hook.hookMethod = function (namespaze, clsName, methodName, argCount, cb) {
    const r = api.findMethod(null, namespaze, clsName, methodName, argCount);
    if (r.klass.isNull() || !r.methods.length) {
      send({ t: 'log', msg: '[!] 未找到方法 ' + namespaze + '.' + clsName + '::' + methodName });
      return null;
    }
    const mi = r.methods[0];
    const p = api.methodPointer(mi);
    if (p.isNull()) { send({ t: 'log', msg: '[!] methodPointer 为空（可能是抽象/泛型未实例化方法）' }); return null; }
    Interceptor.attach(p, cb || {
      onEnter(args) { send({ t: 'log', msg: '[call] ' + methodName + ' args=' + args.length }); },
      onLeave(ret) { send({ t: 'log', msg: '[ret ] ' + ret }); }
    });
    const info = { rva: api.rva(p).toString(), addr: p.toString(), overloads: r.methods.length };
    send({ t: 'log', msg: '[+] hooked ' + namespaze + '.' + clsName + '::' + methodName + ' @ ' + p + ' (rva ' + info.rva + ')' });
    return info;
  };

  /** A2. 按参数签名精确 hook（重载场景必用） */
  Hook.hookMethodBySig = function (namespaze, clsName, methodName, paramTypes, cb) {
    const r = api.findMethodBySig(null, namespaze, clsName, methodName, paramTypes);
    if (!r.methods.length) {
      send({ t: 'log', msg: '[!] 签名未命中 ' + clsName + '::' + methodName + '(' + paramTypes + ')' });
      return null;
    }
    const p = api.methodPointer(r.methods[0]);
    Interceptor.attach(p, cb);
    send({ t: 'log', msg: '[+] hooked(sig) ' + clsName + '::' + methodName + ' @ ' + p });
    return { rva: api.rva(p).toString(), addr: p.toString() };
  };

  /**
   * B. 全局拦截 il2cpp_runtime_invoke(method, obj, params, exc)
   *    - HybridCLR 热更方法/反射调用都从这里过，是最通用的"方法级抓包器"
   *    - params 是 void**，第 i 个参数是值的指针（值类型是指向值的指针，引用类型是指向指针的指针）
   */
  Hook.hookRuntimeInvoke = function (filter) {
    if (!api.runtime_invoke) { send({ t: 'log', msg: '[!] 无 il2cpp_runtime_invoke 导出' }); return null; }
    const p = api.module.findExportByName('il2cpp_runtime_invoke');
    Interceptor.attach(p, {
      onEnter(args) {
        const mi = args[0];
        if (mi.isNull()) return;
        let name = '', cls = '';
        try { name = api.methodName(mi); } catch (e) { return; }
        try { const k = api.method_get_class(mi); cls = api.className(k); } catch (e) {}
        const full = cls + '::' + name;
        if (filter && !filter(full)) return;
        this.full = full;
        this.obj = args[1];
        this.params = args[2];
        send({
          t: 'log',
          msg: '[invoke] ' + full +
               ' this=' + args[1] +
               ' params=' + args[2] +
               '\n        backtrace:\n' +
               Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n        ')
        });
      },
      onLeave(ret) {
        if (!this.full) return;
        send({ t: 'log', msg: '[invoke<-] ' + this.full + ' ret=' + ret });
      }
    });
    send({ t: 'log', msg: '[+] hooked il2cpp_runtime_invoke @ ' + p });
    return { addr: p.toString(), rva: api.rva(p).toString() };
  };

  /**
   * C. 整段替换：把方法实现换成自己的逻辑
   *    sig: { ret:'void'|'pointer'|'int'|'int64'|'float'|'double'|'bool', args:['pointer','pointer'] }
   *    注意参数列表必须和原生签名完全一致（含末尾 MethodInfo*），否则栈/寄存器会错乱崩溃
   */
  Hook.replaceMethod = function (namespaze, clsName, methodName, argCount, ret, argTypes, impl) {
    const r = api.findMethod(null, namespaze, clsName, methodName, argCount);
    if (!r.methods.length) return null;
    const p = api.methodPointer(r.methods[0]);
    const cb = new NativeCallback(impl, ret, argTypes);
    Interceptor.replace(p, cb);
    send({ t: 'log', msg: '[+] replaced ' + clsName + '::' + methodName + ' @ ' + p });
    return { addr: p.toString(), rva: api.rva(p).toString(), cb: cb };
  };

  // ---------------- 常用读写助手（在 hook 回调里直接用） ----------------
  Hook.readString = function (p) { return H.readStr(p); };
  Hook.newString = function (s) { return api.newString(s); };
  Hook.readBytes = function (p) { return H.readArrayBytes(p); };

  /** 读实例字段（按 dump 出来的 offset） */
  Hook.getFieldPtr = function (obj, offset) { return obj.add(offset); };
  Hook.getInt32 = function (obj, offset) { return obj.add(offset).readS32(); };
  Hook.setInt32 = function (obj, offset, v) { obj.add(offset).writeS32(v); };
  Hook.getFloat = function (obj, offset) { return obj.add(offset).readFloat(); };
  Hook.setFloat = function (obj, offset, v) { obj.add(offset).writeFloat(v); };
  Hook.getBool = function (obj, offset) { return !!obj.add(offset).readU8(); };
  Hook.setBool = function (obj, offset, v) { obj.add(offset).writeU8(v ? 1 : 0); };

  /** 打印一个托管对象的关键字段（配合 dump 的 fields 用） */
  Hook.dumpObject = function (obj, fields) {
    if (obj.isNull()) return 'null';
    const parts = [];
    for (const f of fields) {
      try {
        const a = obj.add(f.offset);
        parts.push(f.name + '=' + a.readPointer().toString());
      } catch (e) { parts.push(f.name + '=?'); }
    }
    return parts.join(', ');
  };

  // ---------------- 示例（把下面注释打开即可用） ----------------
  Hook.examples = function () {
    // 例1：拦截登录请求，打印参数
    // Hook.hookMethod('Game.Net', 'LoginMgr', 'SendLogin', 3, {
    //   onEnter(args) {
    //     // 静态方法: args[0]=string account, args[1]=string pwd, args[2]=MethodInfo*
    //     console.log('account=' + H.readStr(args[0]) + ' pwd=' + H.readStr(args[1]));
    //     args[1].replace(api.newString('hacked'));   // 改参
    //   },
    //   onLeave(ret) { console.log('ret=' + ret); }
    // });

    // 例2：改返回值（金币检查）
    // Hook.hookMethod('Game', 'PlayerData', 'GetGold', 0, {
    //   onLeave(ret) { ret.replace(ptr(999999)); }
    // });

    // 例3：整段替换（永远返回 true）
    // Hook.replaceMethod('Game', 'IAP', 'IsVip', 0, 'bool', ['pointer', 'pointer'],
    //   function (__this, mi) { return 1; });

    // 例4：全局抓热更逻辑调用
    // Hook.hookRuntimeInvoke(function (full) { return full.indexOf('HotUpdate') >= 0; });
  };

  G.Hook = Hook;
})();
