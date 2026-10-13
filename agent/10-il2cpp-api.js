/**
 * 10-il2cpp-api.js —— 绑定 libil2cpp.so 导出的 il2cpp_* 公开 API
 *
 * 为什么用公开 API 而不是硬编码结构体偏移：
 *   Il2CppClass / MethodInfo 的字段布局每个 Unity 版本都变，硬编码一升级就崩；
 *   il2cpp_* 这组 API 是 Unity 显式导出的稳定入口，跨版本通用。
 *   只有 string / array 这种没有公开 API 的对象才用偏移（见 00-utils.js 的 OFF）。
 *
 * 注意：spawn 注入时 libil2cpp.so 还没被 linker 加载，所以绑定做成延迟函数
 *       G.bindIl2cpp()，由 99-entry.js 轮询到模块出现后再调用。
 */
'use strict';
const G = globalThis;
const H = G.H;

G.IL2CPP = G.IL2CPP || {};

G.bindIl2cpp = function () {
  const api = G.IL2CPP;
  const m = H.mod('libil2cpp.so');
  if (!m) throw new Error('未找到 libil2cpp.so（进程尚未加载它）');

  const cache = {};
  function nf(name, ret, args) {
    if (cache[name]) return cache[name];
    const p = m.findExportByName(name);
    if (!p || p.isNull()) return null;
    cache[name] = new NativeFunction(p, ret, args);
    return cache[name];
  }
  function nfAny(cands, ret, args) {
    for (const c of cands) { const f = nf(c, ret, args); if (f) return f; }
    return null;
  }

  Object.assign(api, {
    module: m,
    base: m.base,
    path: m.path,
    size: m.size,
    ready: true,
    missing: [],

    // ---- domain / assembly / image ----
    domain_get: nf('il2cpp_domain_get', 'pointer', []),
    domain_get_assemblies: nf('il2cpp_domain_get_assemblies', 'pointer', ['pointer', 'pointer']),
    assembly_get_image: nf('il2cpp_assembly_get_image', 'pointer', ['pointer']),
    image_get_name: nf('il2cpp_image_get_name', 'pointer', ['pointer']),
    image_get_filename: nf('il2cpp_image_get_filename', 'pointer', ['pointer']),
    image_get_class_count: nf('il2cpp_image_get_class_count', 'uint32', ['pointer']),
    image_get_class: nf('il2cpp_image_get_class', 'pointer', ['pointer', 'uint64']),

    // ---- class ----
    class_from_name: nf('il2cpp_class_from_name', 'pointer', ['pointer', 'pointer', 'pointer']),
    class_get_name: nf('il2cpp_class_get_name', 'pointer', ['pointer']),
    class_get_namespace: nf('il2cpp_class_get_namespace', 'pointer', ['pointer']),
    class_get_parent: nf('il2cpp_class_get_parent', 'pointer', ['pointer']),
    class_get_methods: nf('il2cpp_class_get_methods', 'pointer', ['pointer', 'pointer']),
    class_get_method_from_name: nf('il2cpp_class_get_method_from_name', 'pointer', ['pointer', 'pointer', 'int']),
    class_get_fields: nf('il2cpp_class_get_fields', 'pointer', ['pointer', 'pointer']),
    class_get_instance_size: nfAny(['il2cpp_class_get_instance_size', 'il2cpp_class_instance_size'], 'uint32', ['pointer']),
    class_get_type: nf('il2cpp_class_get_type', 'pointer', ['pointer']),
    class_is_valuetype: nf('il2cpp_class_is_valuetype', 'bool', ['pointer']),

    // ---- method ----
    method_get_name: nf('il2cpp_method_get_name', 'pointer', ['pointer']),
    method_get_class: nf('il2cpp_method_get_class', 'pointer', ['pointer']),
    method_get_return_type: nf('il2cpp_method_get_return_type', 'pointer', ['pointer']),
    method_get_param_count: nf('il2cpp_method_get_param_count', 'uint32', ['pointer']),
    method_get_param: nf('il2cpp_method_get_param', 'pointer', ['pointer', 'uint32']),
    method_get_param_name: nf('il2cpp_method_get_param_name', 'pointer', ['pointer', 'uint32']),
    method_get_flags: nf('il2cpp_method_get_flags', 'uint32', ['pointer', 'pointer']),
    method_get_token: nfAny(['il2cpp_method_get_token'], 'uint32', ['pointer']),

    // ---- field ----
    field_get_name: nf('il2cpp_field_get_name', 'pointer', ['pointer']),
    field_get_type: nf('il2cpp_field_get_type', 'pointer', ['pointer']),
    field_get_offset: nf('il2cpp_field_get_offset', 'uint64', ['pointer']),
    field_get_flags: nf('il2cpp_field_get_flags', 'uint32', ['pointer']),
    field_static_get_value: nf('il2cpp_field_static_get_value', 'void', ['pointer', 'pointer']),
    field_static_set_value: nf('il2cpp_field_static_set_value', 'void', ['pointer', 'pointer']),
    field_get_value: nf('il2cpp_field_get_value', 'void', ['pointer', 'pointer', 'pointer']),
    field_set_value: nf('il2cpp_field_set_value', 'void', ['pointer', 'pointer', 'pointer']),

    // ---- type ----
    type_get_name: nf('il2cpp_type_get_name', 'pointer', ['pointer']),
    type_get_type: nf('il2cpp_type_get_type', 'int', ['pointer']),
    type_get_object: nf('il2cpp_type_get_object', 'pointer', ['pointer']),

    // ---- runtime ----
    runtime_invoke: nf('il2cpp_runtime_invoke', 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']),
    thread_attach: nf('il2cpp_thread_attach', 'pointer', ['pointer']),
    thread_detach: nf('il2cpp_thread_detach', 'void', ['pointer']),
    string_new: nf('il2cpp_string_new', 'pointer', ['pointer']),
    object_new: nf('il2cpp_object_new', 'pointer', ['pointer']),
    array_new: nf('il2cpp_array_new', 'pointer', ['pointer', 'uint64']),
    gc_disable: nf('il2cpp_gc_disable', 'void', []),
    class_init: nf('il2cpp_runtime_class_init', 'void', ['pointer']),

    assembly_load_from_bytes: nf('il2cpp_assembly_load_from_bytes', 'pointer', ['pointer', 'uint64']),
  });

  api.missing.length = 0;
  for (const k in api) {
    if (api[k] === null) api.missing.push(k);
  }

  // ---------- 高层封装 ----------
  const S = (s) => Memory.allocUtf8String(s === null || s === undefined ? '' : s);
  api.S = S;
  api.methodName = function (mi) { return H.cstr(api.method_get_name(mi)); };
  api.typeName = function (t) { return t.isNull() ? '' : H.cstr(api.type_get_name(t), 256); };

  api.getDomain = function () { return api.domain_get(); };

  api.getAssemblies = function () {
    const d = api.getDomain();
    const countPtr = Memory.alloc(8);
    const arr = api.domain_get_assemblies(d, countPtr);
    const n = countPtr.readU64().toNumber();
    const list = [];
    for (let i = 0; i < n; i++) list.push(arr.add(i * Process.pointerSize).readPointer());
    return list;
  };

  api.getAssemblyCount = function () {
    const d = api.getDomain();
    if (!d || d.isNull()) return 0;
    const countPtr = Memory.alloc(Process.pointerSize);
    api.domain_get_assemblies(d, countPtr);
    return countPtr.readU64().toNumber();
  };

  api.getImages = function () {
    return api.getAssemblies().map(a => api.assembly_get_image(a)).filter(i => !i.isNull());
  };

  api.getImageByName = function (name) {
    return api.getImages().find(i => api.imageName(i) === name) || null;
  };

  // Some protected builds return a metadata blob without a terminating NUL
  // from image_get_name. Prefer the first DLL token and fall back to filename.
  api.imageName = function (img) {
    let value = '';
    try { value = H.cstr(api.image_get_name(img), 512); } catch (e) {}
    const dll = value.match(/^.*?\.dll/i);
    if (dll) return dll[0];
    try {
      const filename = H.cstr(api.image_get_filename(img), 512);
      const parts = filename.replace(/\\/g, '/').split('/');
      return parts[parts.length - 1] || value;
    } catch (e) { return value; }
  };

  api.getCorlibImage = function () {
    for (const n of ['mscorlib.dll', 'System.Private.CoreLib.dll', 'netstandard.dll', 'mscorlib']) {
      const img = api.getImageByName(n);
      if (img) return img;
    }
    const imgs = api.getImages();
    return imgs.length ? imgs[0] : NULL;
  };

  api.className = function (klass) {
    const ns = H.cstr(api.class_get_namespace(klass));
    const nm = H.cstr(api.class_get_name(klass));
    return ns ? ns + '.' + nm : nm;
  };

  /** 遍历 class 的所有 MethodInfo*（iter 首轮必须先清零） */
  api.classMethods = function (klass) {
    const iter = Memory.alloc(Process.pointerSize);
    iter.writePointer(NULL);
    const out = [];
    let guard = 0;
    while (guard++ < 50000) {
      const mi = api.class_get_methods(klass, iter);
      if (mi.isNull()) break;
      out.push(mi);
    }
    return out;
  };

  api.classFields = function (klass) {
    const iter = Memory.alloc(Process.pointerSize);
    iter.writePointer(NULL);
    const out = [];
    let guard = 0;
    while (guard++ < 50000) {
      const fi = api.class_get_fields(klass, iter);
      if (fi.isNull()) break;
      out.push(fi);
    }
    return out;
  };

  /** 按 命名空间+类名 找 class；image 为 null 时扫描所有 image */
  api.findClass = function (image, namespaze, name) {
    if (image && !image.isNull()) {
      const k = api.class_from_name(image, S(namespaze), S(name));
      if (!k.isNull()) return k;
    }
    for (const img of api.getImages()) {
      const k = api.class_from_name(img, S(namespaze), S(name));
      if (!k.isNull()) return k;
    }
    return NULL;
  };

  api.findMethod = function (image, namespaze, clsName, methodName, argCount) {
    const klass = api.findClass(image, namespaze, clsName);
    if (klass.isNull()) return { klass: NULL, methods: [] };
    if (argCount != null && argCount >= 0) {
      const mi = api.class_get_method_from_name(klass, S(methodName), argCount);
      if (!mi.isNull()) return { klass: klass, methods: [mi] };
    }
    const all = api.classMethods(klass).filter(mi => api.methodName(mi) === methodName);
    return { klass: klass, methods: all };
  };

  /** 按参数类型名精确匹配，解决重载打错人的问题 */
  api.findMethodBySig = function (image, namespaze, clsName, methodName, paramTypes) {
    const found = api.findMethod(image, namespaze, clsName, methodName, null);
    const hits = [];
    for (const mi of found.methods) {
      const n = api.method_get_param_count(mi);
      if (paramTypes && n !== paramTypes.length) continue;
      let ok = true;
      if (paramTypes) {
        for (let i = 0; i < n; i++) {
          if (api.typeName(api.method_get_param(mi, i)) !== paramTypes[i]) { ok = false; break; }
        }
      }
      if (ok) hits.push(mi);
    }
    return { klass: found.klass, methods: hits };
  };

  /** MethodInfo 首字段恒为 methodPointer（各版本一致） */
  api.methodPointer = function (mi) { return mi.readPointer(); };
  api.rva = function (p) { return p.sub(api.base); };
  api.newString = function (s) { return api.string_new(S(s)); };

  console.log('[*] libil2cpp.so base=' + api.base + ' size=' + api.size);
  if (api.missing.length) console.log('[i] 该版本缺失的 API（相关功能降级）: ' + api.missing.join(', '));
  return api;
};
