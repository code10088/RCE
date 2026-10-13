/**
 * 98-monitor.js —— 行为监控：文件 I/O + 加密算法调用
 *
 *   Mon.fileio()  看游戏读写了哪些文件（找存档位置、找配置、找热更 dll 从哪来）
 *   Mon.crypto()  hook 常见加解密入口，直接拿明文输入/输出
 *
 * crypto 的定位：和 stalk 互补
 *   stalk 是「我不知道它用了什么算法」→ 逐指令还原
 *   crypto 是「我猜它用了标准库」→ 直接蹲在标准库出入口上拿数据
 *   后者开销小、见效快，应该**先试 crypto，不行再上 stalk**
 */
'use strict';
const G = globalThis;
const H = G.H;
const api = G.IL2CPP;

(function () {
  const Mon = {};

  // ============================================================
  // 1. 文件 I/O 监控
  // ============================================================
  /**
   * @param opts { onlyPrivateDir:bool 只关心游戏私有目录, minSize, backtrace }
   * 噪音控制很关键：不加过滤的话系统库读写会刷屏
   */
  Mon.fileio = function (opts) {
    opts = opts || {};
    const hooked = [];
    const seen = new Map();   // path -> {reads, writes, size}

    const pkgHint = opts.pkg || null;

    function note(path, op, size, bt) {
      const rec = seen.get(path) || { path: path, reads: 0, writes: 0, bytes: 0 };
      if (op === 'r') rec.reads++; else if (op === 'w') rec.writes++;
      rec.bytes += size || 0;
      seen.set(path, rec);
      send({ t: 'log', msg: '[file] ' + (op === 'w' ? 'WRITE' : 'READ ') + ' ' + path +
        (size ? ' (' + size + 'B)' : '') + (bt ? '\n        ' + bt : '') });
    }

    function interesting(path) {
      if (!path) return false;
      // 默认过滤掉系统库/字体等噪音
      if (!opts.all) {
        if (/^\/(system|vendor|apex|proc|sys|dev)\//.test(path)) return false;
        if (/\.(so|dex|oat|art|apk)$/i.test(path)) return false;
      }
      if (opts.onlyPrivateDir) {
        return /\/data\/(data|user\/0)\//.test(path) ||
               /\/sdcard\/Android\/(data|obb)\//.test(path) ||
               (pkgHint && path.indexOf(pkgHint) >= 0);
      }
      if (opts.pattern) {
        try { return new RegExp(opts.pattern).test(path); } catch (e) { return true; }
      }
      return true;
    }

    let bt = '';
    function grabBt(ctx) {
      if (!opts.backtrace) return '';
      try {
        return Thread.backtrace(ctx, Backtracer.FUZZY)
          .map(DebugSymbol.fromAddress).slice(0, 5).join('\n        ');
      } catch (e) { return ''; }
    }

    // open / openat：拿路径
    const openat = Module.findExportByName('libc.so', 'openat');
    if (openat) {
      Interceptor.attach(openat, {
        onEnter(args) {
          let s = '';
          try { s = args[1].readCString(256); } catch (e) { return; }
          if (!interesting(s)) return;
          this._p = s;
          bt = grabBt(this.context);
        },
        onLeave(ret) {
          if (this._p) note(this._p, 'r', 0, bt);
        }
      });
      hooked.push('openat');
    }
    const open = Module.findExportByName('libc.so', 'open');
    if (open) {
      Interceptor.attach(open, {
        onEnter(args) {
          let s = '';
          try { s = args[0].readCString(256); } catch (e) { return; }
          if (!interesting(s)) return;
          this._p = s;
          bt = grabBt(this.context);
        },
        onLeave(ret) { if (this._p) note(this._p, 'r', 0, bt); }
      });
      hooked.push('open');
    }
    const fopen = Module.findExportByName('libc.so', 'fopen');
    if (fopen) {
      Interceptor.attach(fopen, {
        onEnter(args) {
          let s = '';
          try { s = args[0].readCString(256); } catch (e) { return; }
          if (!interesting(s)) return;
          note(s, 'r', 0, grabBt(this.context));
        }
      });
      hooked.push('fopen');
    }

    Mon.__files = seen;
    send({ t: 'log', msg: '[+] 文件监控已装: ' + hooked.join(', ') +
      (opts.onlyPrivateDir ? '（仅私有目录）' : '') });
    return { hooked: hooked };
  };

  Mon.fileReport = function (topN) {
    const seen = Mon.__files;
    if (!seen) return null;
    const rows = Array.from(seen.values()).sort((a, b) => (b.reads + b.writes) - (a.reads + a.writes));
    send({ t: 'log', msg: '===== 文件访问统计 =====' });
    for (const r of rows.slice(0, topN || 40)) {
      send({ t: 'log', msg: '  r=' + r.reads + ' w=' + r.writes + '  ' + r.path });
    }
    return rows.slice(0, topN || 40);
  };

  // ============================================================
  // 2. 加密算法调用监控
  // ============================================================
  function preview(buf, cap) {
    if (!buf) return '';
    const n = Math.min(buf.byteLength, cap || 128);
    const u8 = new Uint8Array(buf.slice(0, n));
    let printable = 0;
    for (let i = 0; i < n; i++) {
      const c = u8[i];
      if (c === 0x0a || c === 0x0d || (c >= 0x20 && c < 0x7f)) printable++;
    }
    if (printable / Math.max(n, 1) > 0.85) {
      return 'TEXT "' + Array.from(u8).map(c => String.fromCharCode(c)).join('') + '"';
    }
    let hex = '';
    for (let i = 0; i < n; i++) hex += ('0' + u8[i].toString(16)).slice(-2);
    return 'HEX ' + hex.slice(0, 256) + (buf.byteLength > n ? '…' : '');
  }

  /**
   * 托管层：Base64 / Encoding / MD5-SHA / AES
   * 这些是游戏里最高频的，先蹲这几个
   */
  Mon.cryptoManaged = function (opts) {
    opts = opts || {};
    const cap = opts.cap || 128;
    const out = [];
    if (!api.ready) return { error: 'il2cpp 未就绪' };

    const targets = [
      ['System', 'Convert', 'ToBase64String', ['System.Byte[]']],
      ['System', 'Convert', 'FromBase64String', ['System.String']],
      ['System.Text', 'Encoding', 'GetBytes', ['System.String']],
      ['System.Security.Cryptography', 'HashAlgorithm', 'ComputeHash', ['System.Byte[]']],
      ['System.Security.Cryptography', 'MD5', 'ComputeHash', ['System.Byte[]']],
      ['System.Security.Cryptography', 'SHA1', 'ComputeHash', ['System.Byte[]']],
      ['System.Security.Cryptography', 'SHA256', 'ComputeHash', ['System.Byte[]']],
      ['System.Security.Cryptography', 'AesManaged', 'CreateEncryptor', ['System.Byte[]', 'System.Byte[]']],
      ['System.Security.Cryptography', 'RijndaelManaged', 'CreateEncryptor', ['System.Byte[]', 'System.Byte[]']]
    ];

    for (const [ns, cls, m, sig] of targets) {
      const r = api.findMethodBySig(null, ns, cls, m, sig);
      for (const mi of r.methods) {
        const p = api.methodPointer(mi);
        if (p.isNull()) continue;
        const full = cls + '::' + m;
        Interceptor.attach(p, {
          onEnter(args) {
            const a0 = args[0];
            let data = null, len = 0;
            try {
              if (sig[0] === 'System.Byte[]') {
                len = H.readArrayLen(a0);
                if (len > 0 && len < 4 * 1024 * 1024) data = H.readArrayBytes(a0, len);
              } else {
                const s = H.readStr(a0);
                data = s ? Memory.allocUtf8String(s).readByteArray(s.length) : null;
                len = s ? s.length : 0;
              }
            } catch (e) {}
            send({ t: 'log', msg: '[crypto] ' + full + ' IN (' + len + 'B)\n        ' + preview(data, cap) });
            // IV 也顺便打（AES 场景第二个参数）
            if (sig.length > 1 && args.length > 1) {
              try {
                const l2 = H.readArrayLen(args[1]);
                if (l2 > 0 && l2 < 64) {
                  send({ t: 'log', msg: '        IV/Key2: ' + preview(H.readArrayBytes(args[1], l2), 64) });
                }
              } catch (e) {}
            }
          },
          onLeave(ret) {
            if (ret.isNull()) return;
            // 返回值可能是 string 也可能是 byte[]，两种都试一下
            let d = null;
            try {
              // 先试当 string 读
              const s = H.readStr(ret);
              if (s && s.length > 0 && s.length < 4096) {
                send({ t: 'log', msg: '[crypto] ' + full + ' OUT -> "' + s.slice(0, 200) + '"' });
                return;
              }
              const l = H.readArrayLen(ret);
              if (l > 0 && l < 1024 * 1024) d = H.readArrayBytes(ret, l);
              if (d) send({ t: 'log', msg: '[crypto] ' + full + ' OUT (' + l + 'B)\n        ' + preview(d, cap) });
            } catch (e) {}
          }
        });
        out.push({ method: full, addr: p.toString(), rva: api.rva(p).toString() });
      }
    }
    if (!out.length) {
      send({ t: 'log', msg: '[-] 托管层加密 hook 没挂上（可能被裁剪）。试试 Mon.cryptoNative()' });
    } else {
      send({ t: 'log', msg: '[+] 托管加密 hook: ' + out.map(x => x.method).join(', ') });
    }
    return out;
  };

  /**
   * native 层：OpenSSL/BoringSSL 的 EVP 系列
   *   int EVP_CipherUpdate(ctx, unsigned char *out, int *outl, const unsigned char *in, int inl)
   *   输入在 onEnter 的 args[3]/args[4]；输出长度是 *args[2]，必须 onLeave 读
   */
  Mon.cryptoNative = function (opts) {
    opts = opts || {};
    const cap = opts.cap || 128;
    const out = [];

    const names = ['EVP_CipherUpdate', 'EVP_EncryptUpdate', 'EVP_DecryptUpdate',
                   'EVP_CipherFinal_ex', 'EVP_DigestUpdate'];
    const mods = Process.enumerateModules().filter(m =>
      /ssl|crypto/i.test(m.name || ''));

    for (const m of mods) {
      for (const nm of names) {
        const p = m.findExportByName(nm);
        if (!p) continue;
        const isFinal = nm.indexOf('Final') >= 0;
        Interceptor.attach(p, {
          onEnter(args) {
            if (!isFinal) {
              try {
                const inLen = args[4].toInt32();
                const inBuf = (inLen > 0 && inLen < 4 * 1024 * 1024)
                  ? args[3].readByteArray(inLen) : null;
                send({ t: 'log', msg: '[crypto] ' + nm + ' IN (' + inLen + 'B)\n        ' +
                  preview(inBuf, cap) });
              } catch (e) {}
              this._out = args[1];
              this._outl = args[2];
            } else {
              this._out = args[1];
              this._outl = args[2];
            }
          },
          onLeave(ret) {
            if (!this._out || !this._outl) return;
            try {
              const n = this._outl.readS32();
              if (n > 0 && n < 4 * 1024 * 1024) {
                send({ t: 'log', msg: '[crypto] ' + nm + ' OUT (' + n + 'B)\n        ' +
                  preview(this._out.readByteArray(n), cap) });
              }
            } catch (e) {}
          }
        });
        out.push({ module: m.name, fn: nm, addr: p.toString() });
      }
    }
    if (!out.length) {
      send({ t: 'log', msg: '[-] 没找到 EVP 系列（SSL 可能静态链接进主 so 了）。' +
        '用 NetTrace.scanNetSymbols() 找，或上 stalk' });
    } else {
      send({ t: 'log', msg: '[+] native 加密 hook: ' + out.map(x => x.fn).join(', ') });
    }
    return out;
  };

  /** 一键：托管 + native 都装 */
  Mon.crypto = function (opts) {
    return { managed: Mon.cryptoManaged(opts), native: Mon.cryptoNative(opts) };
  };

  G.Monitor = Mon;
})();
