/**
 * 20-dump.js —— 运行时转储：Assembly -> Image -> Class -> Method/Field
 * 主要用途：
 *   1) 绕开 global-metadata.dat 加密/混淆（元数据在内存里一定是明文）
 *   2) 拿到方法 RVA，喂给 IDA/Ghidra 还原符号
 *   3) 拿到字段偏移，供 hook 里读写对象成员
 * 输出：JSON（回传 host 或在设备落盘）
 */
'use strict';
const G = globalThis;
const H = G.H;
const api = G.IL2CPP;

(function () {
  const Dump = {};

  function typeNameSafe(t) {
    if (!t || t.isNull()) return '';
    try { return H.cstr(api.type_get_name(t), 256); } catch (e) { return '?'; }
  }

  function dumpMethod(mi) {
    const name = api.methodName(mi);
    let mp = NULL, rva = '';
    try {
      mp = api.methodPointer(mi);
      rva = api.rva(mp).toString();
    } catch (e) {}
    const out = { name: name, rva: rva, addr: mp.toString() };
    try {
      const pc = api.method_get_param_count(mi);
      const ps = [];
      for (let i = 0; i < pc; i++) {
        const t = api.method_get_param(mi, i);
        ps.push(typeNameSafe(t));
      }
      out.params = ps;
      out.ret = typeNameSafe(api.method_get_return_type(mi));
    } catch (e) {}
    try {
      if (api.method_get_token) out.token = api.method_get_token(mi);
    } catch (e) {}
    // 是否静态：flags 的 METHOD_ATTRIBUTE_STATIC = 0x10
    try {
      const iflagsPtr = Memory.alloc(4);
      const f = api.method_get_flags(mi, iflagsPtr);
      out.flags = f;
      out.static = (f & 0x10) !== 0;
    } catch (e) {}
    return out;
  }

  function dumpField(fi) {
    const o = { name: H.cstr(api.field_get_name(fi)) };
    try { o.type = typeNameSafe(api.field_get_type(fi)); } catch (e) {}
    try { o.offset = api.field_get_offset(fi).toNumber(); } catch (e) {}
    try {
      const fl = api.field_get_flags(fi);
      o.static = (fl & 0x10) !== 0; // FIELD_ATTRIBUTE_STATIC
    } catch (e) {}
    return o;
  }

  function dumpClass(klass) {
    const o = {
      name: H.cstr(api.class_get_name(klass)),
      namespace: H.cstr(api.class_get_namespace(klass))
    };
    try { o.instanceSize = api.class_get_instance_size(klass); } catch (e) {}
    try {
      const p = api.class_get_parent(klass);
      if (p && !p.isNull()) o.parent = api.className(p);
    } catch (e) {}
    o.methods = [];
    o.fields = [];
    try { o.methods = api.classMethods(klass).map(dumpMethod); } catch (e) { o.errM = String(e); }
    try { o.fields = api.classFields(klass).map(dumpField); } catch (e) { o.errF = String(e); }
    return o;
  }

  function dumpImage(img, opts) {
    const nm = api.imageName(img);
    const count = api.image_get_class_count(img);
    const out = { image: nm, filename: H.cstr(api.image_get_filename(img)), classCount: count, classes: [] };
    for (let i = 0; i < count; i++) {
      let klass;
      try { klass = api.image_get_class(img, i); } catch (e) { continue; }
      if (!klass || klass.isNull()) continue;
      const cd = dumpClass(klass);
      if (opts && opts.classFilter && !opts.classFilter.test(cd.namespace + '.' + cd.name)) continue;
      out.classes.push(cd);
      if (i % 200 === 0) send({ t: 'log', msg: '   dumping ' + nm + ' ' + i + '/' + count });
    }
    return out;
  }

  /**
   * 全量转储
   * @param {string} tag       回传标记
   * @param {object} opts      { images:['GameAssembly.dll'], classFilter:/regex/, devicePath }
   */
  Dump.dumpAll = function (tag, opts) {
    opts = opts || {};
    if (typeof opts.classFilter === 'string' && opts.classFilter) {
      try { opts.classFilter = new RegExp(opts.classFilter); }
      catch (e) { send({ t: 'log', msg: '[!] classFilter 正则无效: ' + e }); opts.classFilter = null; }
    }
    H.selfCheck(api);

    const result = {
      meta: {
        module: api.path,
        base: api.base.toString(),
        ptrSize: Process.pointerSize,
        time: new Date().toISOString(),
        images: []
      },
      images: []
    };

    const imgs = api.getImages();
    const targets = imgs.filter(img => {
      const nm = api.imageName(img);
      if (!opts.images || !opts.images.length) return true;
      return opts.images.indexOf(nm) >= 0;
    });

    send({ t: 'log', msg: '[dump] 共 ' + imgs.length + ' 个 image，本次转储 ' + targets.length + ' 个' });

    for (const img of targets) {
      const nm = api.imageName(img);
      send({ t: 'log', msg: '[dump] -> ' + nm });
      try {
        const d = dumpImage(img, opts);
        result.images.push(d);
        result.meta.images.push({ name: nm, classes: d.classes.length });
      } catch (e) {
        send({ t: 'log', msg: '[!] dump image 失败 ' + nm + ': ' + e });
      }
    }

    const json = JSON.stringify(result, null, 0);
    send({ t: 'log', msg: '[dump] JSON ' + (json.length / 1024 / 1024).toFixed(2) + ' MB, 开始回传' });

    if (opts.devicePath) H.writeDeviceFile(opts.devicePath, Memory.allocUtf8String(json).readByteArray(json.length + 1));
    H.sendText(tag || 'classes.json', json);
    return { images: result.images.length, bytes: json.length };
  };

  /** 轻量：只列 image 名称；部分保护版本的 class_count 导出会阻塞。 */
  Dump.listImages = function () {
    const out = [];
    for (const img of api.getImages()) {
      out.push({
        name: api.imageName(img)
      });
    }
    send({ t: 'log', msg: JSON.stringify(out, null, 2) });
    return out;
  };

  /** 只 dump 一个类，方便快速看字段偏移 */
  Dump.dumpClass = function (namespaze, name, imageName) {
    const img = imageName ? api.getImageByName(imageName) : null;
    const klass = api.findClass(img, namespaze, name);
    if (klass.isNull()) return { error: 'class not found' };
    const d = dumpClass(klass);
    send({ t: 'log', msg: JSON.stringify(d, null, 2) });
    return d;
  };

  /** 导出成 IDA/Ghidra 直接可用的 script.json（name -> rva） */
  Dump.exportIdaScript = function (tag, imageNames) {
    const lines = [];
    for (const img of api.getImages()) {
      const nm = api.imageName(img);
      if (imageNames && imageNames.length && imageNames.indexOf(nm) < 0) continue;
      const cnt = api.image_get_class_count(img);
      for (let i = 0; i < cnt; i++) {
        const klass = api.image_get_class(img, i);
        if (klass.isNull()) continue;
        const cn = api.className(klass);
        for (const mi of api.classMethods(klass)) {
          let mp;
          try { mp = api.methodPointer(mi); } catch (e) { continue; }
          if (mp.isNull()) continue;
          lines.push({
            name: cn + '::' + api.methodName(mi),
            rva: api.rva(mp).toString()
          });
        }
      }
    }
    const json = JSON.stringify({ base: api.base.toString(), methods: lines }, null, 0);
    H.sendText(tag || 'script.json', json);
    return { count: lines.length };
  };

  /**
   * 导出可直接拖进 Ghidra 执行的 .py —— 把 sub_XXXXXX 批量重命名成 C# 方法名。
   * 比只给 script.json 更进一步：script.json 还要你自己找脚本来导入，
   * 这个生成的是完整可运行的 Ghidra Script，Script Manager 里双击就跑。
   */
  Dump.exportGhidraPy = function (tag, imageNames) {
    const lines = [];
    for (const img of api.getImages()) {
      const nm = api.imageName(img);
      if (imageNames && imageNames.length && imageNames.indexOf(nm) < 0) continue;
      const cnt = api.image_get_class_count(img);
      for (let i = 0; i < cnt; i++) {
        const klass = api.image_get_class(img, i);
        if (klass.isNull()) continue;
        const cn = api.className(klass);
        for (const mi of api.classMethods(klass)) {
          let mp;
          try { mp = api.methodPointer(mi); } catch (e) { continue; }
          if (mp.isNull()) continue;
          const safeName = (cn + '::' + api.methodName(mi)).replace(/\\/g, '_').replace(/"/g, "'");
          lines.push([safeName, api.rva(mp).toString()]);
        }
      }
    }

    // 分批写，避免单行 JSON 过大
    const CHUNK = 500;
    let body = '';
    for (let i = 0; i < lines.length; i += CHUNK) {
      const part = JSON.stringify(lines.slice(i, i + CHUNK));
      body += 'METHODS.extend(' + part + ')\n';
    }

    const py = [
      '# -*- coding: utf-8 -*-',
      '# 由 il2cpp-harness 自动生成 —— Ghidra Script Manager 里直接运行',
      '# 作用：把 libil2cpp.so 里的 sub_XXXXXX 批量重命名为 C# 方法名',
      '# 用法：Ghidra 打开 libil2cpp.so（记得先设正确的 image base）→ Window > Script Manager → 运行本文件',
      '',
      'from ghidra.program.model.symbol import SourceType',
      'from ghidra.app.cmd.function import CreateFunctionCmd',
      '',
      'METHODS = []',
      body,
      'image_base = currentProgram.getImageBase()',
      'fm = currentProgram.getFunctionManager()',
      '',
      'ok = 0',
      'skipped = 0',
      'created = 0',
      'for name, rva in METHODS:',
      '    try:',
      '        addr = image_base.add(long(rva, 16))',
      '    except Exception:',
      '        skipped += 1',
      '        continue',
      '    func = fm.getFunctionAt(addr)',
      '    if func is None:',
      '        # 函数还没被识别：先创建，再命名',
      '        try:',
      '            cmd = CreateFunctionCmd(addr)',
      '            if cmd.applyTo(currentProgram):',
      '                func = fm.getFunctionAt(addr)',
      '                created += 1',
      '        except Exception:',
      '            pass',
      '    if func is None:',
      '        skipped += 1',
      '        continue',
      '    try:',
      '        func.setName(name, SourceType.USER_DEFINED)',
      '        ok += 1',
      '    except Exception:',
      '        skipped += 1',
      '',
      'print("[il2cpp-harness] 重命名 %d 个，新建函数 %d 个，跳过 %d 个" % (ok, created, skipped))',
      ''
    ].join('\n');

    H.sendText(tag || 'ghidra_import.py', py);
    return { count: lines.length, bytes: py.length };
  };

  /**
   * 导出 IDA 用的 .py（ida.py 风格），和 Ghidra 版二选一
   */
  Dump.exportIdaPy = function (tag, imageNames) {
    const lines = [];
    for (const img of api.getImages()) {
      const nm = api.imageName(img);
      if (imageNames && imageNames.length && imageNames.indexOf(nm) < 0) continue;
      const cnt = api.image_get_class_count(img);
      for (let i = 0; i < cnt; i++) {
        const klass = api.image_get_class(img, i);
        if (klass.isNull()) continue;
        const cn = api.className(klass);
        for (const mi of api.classMethods(klass)) {
          let mp;
          try { mp = api.methodPointer(mi); } catch (e) { continue; }
          if (mp.isNull()) continue;
          const safeName = (cn + '::' + api.methodName(mi)).replace(/\\/g, '_').replace(/"/g, "'");
          lines.push([safeName, api.rva(mp).toString()]);
        }
      }
    }
    const CHUNK = 500;
    let body = '';
    for (let i = 0; i < lines.length; i += CHUNK) {
      body += 'METHODS.extend(' + JSON.stringify(lines.slice(i, i + CHUNK)) + ')\n';
    }
    const py = [
      '# -*- coding: utf-8 -*-',
      '# 由 il2cpp-harness 自动生成 —— IDA 里 File > Script file 直接运行',
      '# 作用：把 libil2cpp.so 里的 sub_XXXXXX 批量重命名为 C# 方法名',
      '',
      'import idaapi',
      'import idc',
      'import idautils',
      '',
      'METHODS = []',
      body,
      'base = idaapi.get_imagebase()',
      'ok = 0',
      'skipped = 0',
      'for name, rva in METHODS:',
      '    try:',
      '        ea = base + int(rva, 16)',
      '    except Exception:',
      '        skipped += 1',
      '        continue',
      '    if not idaapi.get_func(ea):',
      '        try:',
      '            idc.add_func(ea)',
      '        except Exception:',
      '            pass',
      '    try:',
      '        if hasattr(idc, "set_name"):',
      '            idc.set_name(ea, name, idaapi.SN_FORCE)',
      '        else:',
      '            idaapi.set_name(ea, name, idaapi.SN_FORCE)',
      '        ok += 1',
      '    except Exception:',
      '        skipped += 1',
      '',
      'print("[il2cpp-harness] 重命名 %d 个，跳过 %d 个" % (ok, skipped))',
      ''
    ].join('\n');
    H.sendText(tag || 'ida_import.py', py);
    return { count: lines.length, bytes: py.length };
  };

  G.Dump = Dump;
})();
