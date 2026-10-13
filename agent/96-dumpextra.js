/**
 * 96-dumpextra.js —— 两种「导出」增强
 *
 *   DX.dumpCs()  从运行时生成 dump.cs（Il2CppDumper 的标准格式）
 *   DX.dumpSo()  从内存重建 libil2cpp.so（对抗 so 加固/加密）
 *
 * ---------------------------------------------------------------
 * 为什么 dump.cs 有用：
 *   dump.cs 是 IL2CPP 生态的「通用语」—— 很多下游工具、Cheat Engine 表、
 *   别人的分析笔记都基于它。而静态 Il2CppDumper 遇到 metadata 加密就废了。
 *   从运行时生成 = 天然绕过加密，且拿到的名字是解密后的真名。
 *
 * 为什么 dumpSo 有用（对抗加固）：
 *   如果 libil2cpp.so 被压缩/加密/加壳，磁盘上的文件是残缺的，IDA 打不开。
 *   但运行时 linker 已经把它展开成完整的可执行镜像。
 *   把这段内存 dump 出来、修好 ELF program header，就得到一份可分析的 so。
 *   这跟 Android 脱壳里「dump dex」是同一思路。
 *
 * ELF 重建原理：
 *   文件中的 segment 是紧凑排列的（p_offset 小），
 *   内存中的 segment 按页对齐展开（p_vaddr 大，段间有空隙）。
 *   所以只要把每个 PT_LOAD 的 p_offset 改成 = p_vaddr、p_filesz 改成 = p_memsz，
 *   得到的就是「文件偏移 == 虚拟地址」的线性镜像，IDA/Ghidra 能直接加载。
 */
'use strict';
const G = globalThis;
const H = G.H;
const api = G.IL2CPP;

(function () {
  const DX = {};
  const OUT_DIR_DEFAULT = '/data/local/tmp/il2cpp-harness/';

  // ============================================================
  // 1. 生成 dump.cs
  // ============================================================
  function esc(s) {
    return s == null ? '' : s;
  }

  function typeToCs(tn) {
    if (!tn) return 'object';
    // 去掉程序集限定，保留可读形式
    return tn;
  }

  DX.dumpCs = function (tag, imageNames) {
    if (!api.ready) return { error: 'il2cpp 未就绪' };
    const out = [];
    let imgIdx = 0;

    for (const img of api.getImages()) {
      const nm = api.imageName(img);
      if (imageNames && imageNames.length && imageNames.indexOf(nm) < 0) continue;

      out.push('// Image ' + imgIdx + ': ' + nm);
      out.push('');

      const cnt = api.image_get_class_count(img);
      // 按 namespace 分组，输出更接近 Il2CppDumper 的排版
      const groups = {};
      const order = [];
      for (let i = 0; i < cnt; i++) {
        let klass;
        try { klass = api.image_get_class(img, i); } catch (e) { continue; }
        if (!klass || klass.isNull()) continue;
        const ns = H.cstr(api.class_get_namespace(klass)) || '';
        if (!groups[ns]) { groups[ns] = []; order.push(ns); }
        groups[ns].push(klass);
      }

      for (const ns of order) {
        out.push('// Namespace: ' + ns);
        for (const klass of groups[ns]) {
          const cname = esc(H.cstr(api.class_get_name(klass)));
          let parent = '';
          try {
            const p = api.class_get_parent(klass);
            if (p && !p.isNull()) parent = esc(H.cstr(api.class_get_name(p)));
          } catch (e) {}

          out.push('public class ' + cname + (parent ? ' : ' + parent : ''));
          out.push('{');

          // ---- Fields ----
          const fields = [];
          try {
            for (const fi of api.classFields(klass)) {
              let fname = '', ftype = '', foff = -1, isStatic = false;
              try { fname = esc(H.cstr(api.field_get_name(fi))); } catch (e) { continue; }
              try { ftype = typeToCs(api.typeName(api.field_get_type(fi))); } catch (e) {}
              try { foff = api.field_get_offset(fi).toNumber(); } catch (e) {}
              try { isStatic = (api.field_get_flags(fi) & 0x10) !== 0; } catch (e) {}
              if (isStatic) fields.push('\tpublic static ' + ftype + ' ' + fname + '; // 0x' + foff.toString(16));
              else fields.push('\tpublic ' + ftype + ' ' + fname + '; // 0x' + foff.toString(16));
            }
          } catch (e) {}
          if (fields.length) {
            out.push('\t// Fields');
            out.push.apply(out, fields);
            out.push('');
          }

          // ---- Methods ----
          const methods = [];
          try {
            for (const mi of api.classMethods(klass)) {
              let mname = '', rva = '', rtype = 'void', isStatic = false;
              try { mname = esc(api.methodName(mi)); } catch (e) { continue; }
              try {
                const mp = api.methodPointer(mi);
                rva = api.rva(mp).toString(16);
              } catch (e) { rva = '0'; }
              try { rtype = typeToCs(api.typeName(api.method_get_return_type(mi))) || 'void'; } catch (e) {}
              try { isStatic = (api.method_get_flags(mi, Memory.alloc(4)) & 0x10) !== 0; } catch (e) {}
              const ps = [];
              try {
                const pc = api.method_get_param_count(mi);
                for (let k = 0; k < pc; k++) {
                  ps.push(typeToCs(api.typeName(api.method_get_param(mi, k))) + ' ' +
                    (api.method_get_param_name ? esc(H.cstr(api.method_get_param_name(mi, k))) : ('p' + k)));
                }
              } catch (e) {}
              methods.push('\t// RVA: 0x' + rva + ' VA: 0x' + rva);
              methods.push('\t' + (isStatic ? 'public static ' : 'public ') + rtype + ' ' + mname +
                '(' + ps.join(', ') + ') { }');
            }
          } catch (e) {}
          if (methods.length) {
            out.push('\t// Methods');
            out.push.apply(out, methods);
          }

          out.push('}');
          out.push('');
        }
      }
      imgIdx++;
    }

    const text = out.join('\n');
    H.sendText(tag || 'dump.cs', text);
    send({ t: 'log', msg: '[dumpcs] 生成完成，共 ' + (text.length / 1024 / 1024).toFixed(2) + ' MB' });
    return { bytes: text.length, images: imgIdx };
  };

  // ============================================================
  // 2. 从内存重建 libil2cpp.so
  // ============================================================
  function writeRange(f, addr, size, chunk) {
    let off = 0;
    while (off < size) {
      const n = Math.min(chunk, size - off);
      let buf;
      try { buf = addr.add(off).readByteArray(n); }
      catch (e) { buf = new ArrayBuffer(n); }   // 读不到就填 0，保证偏移对齐
      f.write(buf);
      off += n;
    }
  }

  function writeZeros(f, n, chunk) {
    let left = n;
    while (left > 0) {
      const c = Math.min(chunk, left);
      f.write(new ArrayBuffer(c));
      left -= c;
    }
  }

  /**
   * @param opts { outPath, chunk }
   * 注意：产物可能几十上百 MB，默认**只落设备盘**并打印 adb pull 命令，
   *      不走回传（回传既慢又容易把 host 内存吃光）。
   */
  DX.dumpSo = function (opts) {
    opts = opts || {};
    if (!api.ready) return { error: 'il2cpp 未就绪' };
    const m = api.module;
    const modPath = m.path;

    // 1) 收集属于该模块的所有映射段
    const rs = [];
    for (const prot of ['r--', 'r-x', 'rw-', 'rwx']) {
      try {
        for (const r of Process.enumerateRangesSync(prot)) {
          if (r.file && r.file.path === modPath) rs.push({ base: r.base, size: r.size });
        }
      } catch (e) {}
    }
    // 兜底：按 base+size 直接取（某些 ROM 上 file.path 拿不到）
    if (!rs.length) {
      try {
        rs.push({ base: m.base, size: m.size });
      } catch (e) {
        return { error: '拿不到模块映射' };
      }
    }
    rs.sort(function (a, b) { return a.base.compare(b.base); });

    const start = rs[0].base;
    const last = rs[rs.length - 1];
    const total = last.base.add(last.size).sub(start).toNumber();
    send({ t: 'log', msg: '[dumpso] ' + modPath + ' 共 ' + rs.length + ' 段，镜像大小 ' +
      (total / 1024 / 1024).toFixed(1) + ' MB' });

    // 2) 只读头部（含 ELF header + program headers），修好再写
    const headLen = Math.min(4096, rs[0].size);
    const head = start.readByteArray(headLen);
    const dv = new DataView(head);
    const hu8 = new Uint8Array(head);
    const isElf = hu8[0] === 0x7f && hu8[1] === 0x45 && hu8[2] === 0x4c && hu8[3] === 0x46;
    if (!isElf) {
      send({ t: 'log', msg: '[!] 头部不是 ELF（' + hu8[0].toString(16) + ' ' + hu8[1].toString(16) +
        '）。可能是被加壳抹掉了头，产物需要手工修。继续 dump…' });
    }

    let fixedCount = 0;
    if (isElf) {
      const e_phoff = Number(dv.getBigUint64(32, true));
      const e_phentsize = dv.getUint16(54, true);
      const e_phnum = dv.getUint16(56, true);
      for (let i = 0; i < e_phnum; i++) {
        const off = e_phoff + i * e_phentsize;
        if (off + 56 > headLen) break;
        const p_type = dv.getUint32(off, true);
        if (p_type !== 1) continue;                                  // 只处理 PT_LOAD
        const p_vaddr = Number(dv.getBigUint64(off + 16, true));
        const p_memsz = Number(dv.getBigUint64(off + 40, true));
        dv.setBigUint64(off + 8, BigInt(p_vaddr), true);             // p_offset = p_vaddr
        dv.setBigUint64(off + 32, BigInt(p_memsz), true);            // p_filesz = p_memsz
        fixedCount++;
      }
      send({ t: 'log', msg: '[dumpso] 已修正 ' + fixedCount + ' 个 PT_LOAD 段（p_offset=vaddr, p_filesz=memsz）' });
    }

    const outPath = opts.outPath || (OUT_DIR_DEFAULT + 'libil2cpp_dump.so');
    const chunk = opts.chunk || (4 * 1024 * 1024);

    let f;
    try {
      f = new File(outPath, 'wb');
    } catch (e) {
      return { error: '无法写文件 ' + outPath + ': ' + e };
    }

    try {
      f.write(head);                                                  // 已修好的头部
      writeRange(f, start.add(headLen), rs[0].size - headLen, chunk); // 第一段剩余

      let cur = start.add(rs[0].size);
      for (let i = 1; i < rs.length; i++) {
        const gap = rs[i].base.sub(cur).toNumber();
        if (gap > 0) writeZeros(f, gap, chunk);                       // 段间空洞补 0
        writeRange(f, rs[i].base, rs[i].size, chunk);
        cur = rs[i].base.add(rs[i].size);
      }
      f.flush();
      f.close();
    } catch (e) {
      try { f.close(); } catch (e2) {}
      return { error: '写入失败: ' + e };
    }

    send({ t: 'log', msg: '[+] so 已重建: ' + outPath + ' (' + (total / 1024 / 1024).toFixed(1) + ' MB)' });
    send({ t: 'log', msg: '    取回命令: adb pull ' + outPath + ' .' });
    send({ t: 'log', msg: '    IDA/Ghidra 打开时 image base 设为 ' + m.base +
      '；符号用 --mode symbols 生成的脚本导入' });
    return { path: outPath, size: total, segments: rs.length, phFixed: fixedCount, base: m.base.toString() };
  };

  G.DumpExtra = DX;
})();
