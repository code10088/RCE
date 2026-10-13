/**
 * 93-assets.js —— 资源运行时捕获 + 场景遍历
 *
 * 注意边界：解析 .assets / AssetBundle 的**文件格式**是 AssetStudio 的活（PC 端）。
 * 这个模块管的是「只有运行时才能拿到的」：
 *
 *   1. AB 被加密时，从内存里拿**解密后**的字节（磁盘上是密文，AssetStudio 打不开）
 *   2. 拿到 AssetBundle 的实际加载路径（adb pull 下来）
 *   3. 遍历运行时活着的 GameObject（静态文件里是序列化数据，看不到活的对象）
 *
 * 典型组合拳：
 *   --mode assets 抓到解密后的 AB → adb pull → AssetStudio 打开解析
 *   这条链路能破解「AB 加密」这类保护，静态工具单独做不到。
 */
'use strict';
const G = globalThis;
const H = G.H;
const api = G.IL2CPP;

(function () {
  const AB = {};
  const OUT_DIR = '/data/local/tmp/il2cpp-harness/';

  function isUnityAB(buf) {
    if (!buf || buf.byteLength < 32) return false;
    const v = new Uint8Array(buf);
    // UnityFS\0 或 UnityWeb 或 UnityRaw 或 UnityArchive
    const sig = String.fromCharCode(v[0], v[1], v[2], v[3], v[4], v[5], v[6]);
    return sig.indexOf('Unity') === 0 || (v[0] === 0x55 && v[1] === 0x6e);
  }

  function nameFromAB(buf) {
    return 'ab_' + buf.byteLength + '_' + Date.now() + '.unity3d';
  }

  // ============================================================
  // 1. AssetBundle 加载捕获
  // ============================================================
  AB.hookLoad = function (opts) {
    opts = opts || {};
    const targets = [
      ['LoadFromFile', ['System.String']],
      ['LoadFromFileAsync', ['System.String']],
      ['LoadFromMemory', ['System.Byte[]']],
      ['LoadFromMemoryAsync', ['System.Byte[]']],
      ['LoadFromFile_Internal', ['System.String', 'System.UInt32', 'System.UInt64']]
    ];
    const out = [];

    const klass = api.findClass(null, 'UnityEngine', 'AssetBundle');
    if (klass.isNull()) {
      send({ t: 'log', msg: '[-] 未找到 UnityEngine.AssetBundle' });
      return null;
    }

    for (const [m, sig] of targets) {
      let r = api.findMethodBySig(null, 'UnityEngine', 'AssetBundle', m, sig);
      if (!r.methods.length) {
        // 签名对不上就退化成按名字找
        r = api.findMethod(null, 'UnityEngine', 'AssetBundle', m, -1);
      }
      for (const mi of r.methods) {
        const p = api.methodPointer(mi);
        if (p.isNull()) continue;

        const isMem = m.indexOf('Memory') >= 0;
        Interceptor.attach(p, {
          onEnter(args) {
            if (isMem) {
              // LoadFromMemory(byte[])：内存里已是解密后的完整 AB
              const arr = args[0];
              const n = H.readArrayLen(arr);
              send({ t: 'log', msg: '[AB] ' + m + ' len=' + n });
              if (n > 0 && n < 500 * 1024 * 1024) {
                const buf = H.readArrayBytes(arr, n);
                if (buf && isUnityAB(buf)) {
                  const name = nameFromAB(buf);
                  const devPath = OUT_DIR + name;
                  H.writeDeviceFile(devPath, buf);
                  if (opts.pull) H.sendBin('ab', { name: name, size: n, devPath: devPath }, buf);
                  send({ t: 'log', msg: '[+] 抓到解密后的 AB: ' + name + ' (' + n + ' bytes)' +
                    '\n    设备路径: ' + devPath });
                }
              }
            } else {
              // LoadFromFile(string)：只知道路径，配合 adb pull
              let path = '';
              try { path = H.readStr(args[0]); } catch (e) {}
              send({ t: 'log', msg: '[AB] ' + m + ' path="' + path + '"\n        ' +
                Thread.backtrace(this.context, Backtracer.FUZZY)
                  .map(DebugSymbol.fromAddress).slice(0, 5).join('\n        ') });
            }
          }
        });
        out.push({ method: m, addr: p.toString(), rva: api.rva(p).toString() });
      }
    }

    if (!out.length) {
      send({ t: 'log', msg: '[-] 没挂上任何 AssetBundle 加载点。可能用了 Addressables 或自定义加载，' +
        '试试 --mode fileio 看它读了哪些文件' });
    } else {
      send({ t: 'log', msg: '[+] AssetBundle hook 已装: ' + out.map(x => x.method).join(', ') });
    }
    return out;
  };

  /**
   * 2. 场景遍历 —— 列出运行时活着的 GameObject
   * 做法：调用 UnityEngine.Object::FindObjectsOfTypeAll(Type)
   * 需要先通过 il2cpp_type_get_object 把 Il2CppType* 变成 System.Type 实例
   */
  AB.sceneList = function (opts) {
    opts = opts || {};
    if (!api.ready) return { error: 'il2cpp 未就绪' };

    const typeName = opts.type || 'GameObject';   // GameObject / Transform / Camera ...
    const cls = api.findClass(null, 'UnityEngine', typeName);
    if (cls.isNull()) return { error: 'class not found: UnityEngine.' + typeName };

    let typeObj = NULL;
    if (api.type_get_object) {
      try {
        const t = api.class_get_type(cls);
        if (t && !t.isNull()) typeObj = api.type_get_object(t);
      } catch (e) {}
    }
    if (typeObj.isNull()) {
      send({ t: 'log', msg: '[-] 拿不到 System.Type（该版本无 il2cpp_type_get_object）。' +
        '改用 --mode fileio 或直接 hook GameObject 的构造' });
      return { error: 'no type_get_object' };
    }

    const r = api.findMethod(null, 'UnityEngine', 'Object', 'FindObjectsOfTypeAll', 1);
    if (!r.methods.length) {
      // 新版 Unity 可能叫 FindObjectsOfType
      const r2 = api.findMethod(null, 'UnityEngine', 'Object', 'FindObjectsOfType', 1);
      if (!r2.methods.length) return { error: 'FindObjectsOfTypeAll 未找到' };
      r.methods = r2.methods;
    }
    const mi = r.methods[0];

    const params = Memory.alloc(Process.pointerSize);
    params.writePointer(typeObj);
    const exc = Memory.alloc(Process.pointerSize);
    exc.writePointer(NULL);

    let arr = NULL;
    try { arr = api.runtime_invoke(mi, NULL, params, exc); } catch (e) { return { error: String(e) }; }
    if (arr.isNull()) return { error: '返回空数组' };

    const n = H.readArrayLen(arr);
    const limit = Math.min(n, opts.limit || 200);
    const list = [];
    for (let i = 0; i < limit; i++) {
      const obj = arr.add(H.OFF.arr.vector + i * Process.pointerSize).readPointer();
      if (obj.isNull()) continue;
      let name = '';
      try {
        // GameObject.get_name()
        const gn = api.findMethod(null, 'UnityEngine', 'Object', 'get_name', 0);
        if (gn.methods.length) {
          const p2 = Memory.alloc(Process.pointerSize);
          p2.writePointer(NULL);
          const e2 = Memory.alloc(Process.pointerSize);
          e2.writePointer(NULL);
          const sObj = api.runtime_invoke(gn.methods[0], obj, p2, e2);
          if (!sObj.isNull()) name = H.readStr(sObj);
        }
      } catch (e) {}
      list.push({ addr: obj.toString(), name: name });
    }

    const json = JSON.stringify(list, null, 0);
    H.sendText(opts.tag || ('scene_' + typeName + '.json'), json);
    send({ t: 'log', msg: '[scene] UnityEngine.' + typeName + ' 存活 ' + n + ' 个，已导出 ' + limit + ' 个' });
    for (const it of list.slice(0, 40)) {
      send({ t: 'log', msg: '   ' + it.addr + '  ' + it.name });
    }
    return { count: n, exported: limit, items: list.slice(0, 50) };
  };

  /**
   * 3. 一次性把资源相关的都装上
   */
  AB.start = function (opts) {
    opts = opts || {};
    const res = { ab: AB.hookLoad(opts) };
    if (opts.scene) res.scene = AB.sceneList(opts);
    return res;
  };

  G.Assets = AB;
})();
