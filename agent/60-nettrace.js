/**
 * 60-nettrace.js —— 网络层抓包（进程内）
 *
 * 为什么不用 Charles / mitmproxy / HTTPCanary：
 *   它们要装 CA 证书 + 绕证书 pinning + 配代理，一步卡住就全废。
 *   而在进程内 hook SSL 的读写函数，拿到的就是**加解密之后的明文**，
 *   不需要装任何证书、不需要改系统、不受 pinning 影响 —— 因为根本不做中间人。
 *
 * 三条线，按信息量从高到低：
 *   A. native SSL —— SSL_read / SSL_write（BoringSSL / OpenSSL），直接拿明文
 *   B. libc socket —— send / recv / sendto / recvfrom，兜底（含非 SSL 流量）
 *   C. 只记长度 —— 只需要知道「发了多大的包」时用，开销最小
 *
 * 关键签名细节（搞错就拿不到数据）：
 *   int SSL_write(SSL *ssl, const void *buf, int num)   → 明文在 onEnter 的 args[1]
 *   int SSL_read (SSL *ssl,       void *buf, int num)   → onEnter 时 buf 还是空的，
 *                                                         必须在 onLeave 里读 args[1]
 *   ssize_t send(int fd, const void *buf, size_t len, int flags)  → onEnter args[1]
 *   ssize_t recv(int fd,       void *buf, size_t len, int flags)  → onLeave  args[1]
 *
 * 这是「读方向 vs 写方向」最容易写反的地方：能立刻读的一律在 onEnter 读，
 * 等内核填完才有效的一律在 onLeave 读。
 */
'use strict';
const G = globalThis;
const H = G.H;

(function () {
  const Net = {};

  // ---------- 预览格式化 ----------
  function preview(buf, cap) {
    if (!buf) return '';
    const n = Math.min(buf.byteLength, cap || 256);
    const u8 = new Uint8Array(buf.slice ? buf.slice(0, n) : buf);
    // 可打印 → 当文本看；否则给 hex
    let printable = 0;
    for (let i = 0; i < n; i++) {
      const c = u8[i];
      if (c === 0x09 || c === 0x0a || c === 0x0d || (c >= 0x20 && c < 0x7f)) printable++;
    }
    if (printable / Math.max(n, 1) > 0.85) {
      return 'TEXT: ' + Array.from(u8).map(c => String.fromCharCode(c)).join('');
    }
    let hex = '';
    for (let i = 0; i < n; i++) {
      hex += ('0' + u8[i].toString(16)).slice(-2) + ' ';
      if (i % 16 === 15) hex += '\n';
    }
    return 'HEX(' + buf.byteLength + 'B):\n' + hex;
  }

  function emit(dir, kind, len, buf, cap, dumpFull) {
    const rec = {
      dir: dir,          // send | recv
      kind: kind,        // ssl | socket
      len: len,
      time: Date.now()
    };
    if (buf) {
      rec.preview = preview(buf, cap);
      if (dumpFull && buf.byteLength) {
        H.sendBin('netpkt', { name: 'pkt_' + dir + '_' + Date.now() + '_' + buf.byteLength + '.bin' }, buf);
      }
    }
    send({ t: 'log', msg: '[net] ' + dir.toUpperCase() + ' (' + kind + ') ' + len + 'B\n' + (rec.preview || '') });
    return rec;
  }

  // ---------- 找 SSL 库 ----------
  function findSslLibs() {
    const names = ['libssl.so', 'libssl.so.1.1', 'libssl.so.3', 'libboringssl.so', 'libcrypto.so'];
    const found = [];
    for (const m of Process.enumerateModules()) {
      if (names.indexOf(m.name) >= 0) found.push(m);
    }
    return found;
  }

  /**
   * A. hook SSL_read / SSL_write —— 拿明文
   * @param opts { cap:预览字节数, dumpFull:是否回传完整包, filter:长度下限 }
   */
  Net.hookSsl = function (opts) {
    opts = opts || {};
    const cap = opts.cap || 256;
    const minLen = opts.minLen || 0;
    const out = [];

    for (const m of findSslLibs()) {
      // SSL_write: 明文已经在 buf 里，onEnter 直接读
      const wp = m.findExportByName('SSL_write');
      if (wp) {
        Interceptor.attach(wp, {
          onEnter(args) {
            const n = args[2].toInt32();
            if (n <= minLen) return;
            let buf = null;
            try { buf = args[1].readByteArray(n); } catch (e) {}
            this._n = n; this._b = buf;
          },
          onLeave(ret) {
            const r = ret.toInt32();
            if (r > 0 && this._b) emit('send', 'ssl', r, this._b, cap, opts.dumpFull);
          }
        });
        out.push({ fn: 'SSL_write', addr: wp.toString() });
      }

      // SSL_read: onEnter 时 buf 为空，必须 onLeave 读
      const rp = m.findExportByName('SSL_read');
      if (rp) {
        Interceptor.attach(rp, {
          onEnter(args) { this._buf = args[1]; this._want = args[2].toInt32(); },
          onLeave(ret) {
            const r = ret.toInt32();
            if (r <= 0 || r <= minLen || !this._buf) return;
            let buf = null;
            try { buf = this._buf.readByteArray(r); } catch (e) {}
            emit('recv', 'ssl', r, buf, cap, opts.dumpFull);
          }
        });
        out.push({ fn: 'SSL_read', addr: rp.toString() });
      }

      // OpenSSL/BoringSSL *_ex variants used by newer clients.
      const we = m.findExportByName('SSL_write_ex');
      if (we) {
        Interceptor.attach(we, {
          onEnter(args) {
            const n = args[2].toUInt64().toNumber();
            this._written = args[3];
            if (n > minLen) try { this._data = args[1].readByteArray(Math.min(n, 65536)); } catch (e) {}
          },
          onLeave(ret) {
            if (ret.toInt32() && this._data) {
              let n = 0;
              try { n = this._written.readU64().toNumber(); } catch (e) {}
              emit('send', 'ssl_ex', n, this._data, cap, opts.dumpFull);
            }
          }
        });
        out.push({ fn: 'SSL_write_ex', addr: we.toString() });
      }
      const re = m.findExportByName('SSL_read_ex');
      if (re) {
        Interceptor.attach(re, {
          onEnter(args) { this._buf = args[1]; this._written = args[3]; },
          onLeave(ret) {
            if (!ret.toInt32() || !this._buf) return;
            let n = 0;
            try { n = this._written.readU64().toNumber(); } catch (e) {}
            if (n <= minLen) return;
            let data = null;
            try { data = this._buf.readByteArray(Math.min(n, 65536)); } catch (e) {}
            emit('recv', 'ssl_ex', n, data, cap, opts.dumpFull);
          }
        });
        out.push({ fn: 'SSL_read_ex', addr: re.toString() });
      }
    }

    if (!out.length) {
      send({ t: 'log', msg: '[-] 没找到 SSL 导出符号（可能静态链接进游戏 so 了）。' +
        '这种情况用 Net.hookSocket() 兜底，或先 Net.scanNetSymbols() 找找别的名字' });
    } else {
      send({ t: 'log', msg: '[+] SSL hook 已装: ' + out.map(x => x.fn).join(', ') });
    }
    return out;
  };

  /** 扫一下进程里有哪些跟网络/加密相关的符号，用于 A 方案失效时定位 */
  Net.scanNetSymbols = function (keyword) {
    const kw = (keyword || '').toLowerCase() || null;
    const hints = ['ssl', 'crypto', 'tls', 'send', 'recv', 'write', 'read', 'socket', 'cur_l', 'http'];
    const hits = [];
    for (const m of Process.enumerateModules()) {
      let syms = [];
      try { syms = m.enumerateSymbols(); } catch (e) { continue; }
      for (const s of syms) {
        const n = (s.name || '').toLowerCase();
        if (kw ? n.indexOf(kw) >= 0 : hints.some(h => n.indexOf(h) >= 0)) {
          hits.push({ module: m.name, name: s.name, addr: s.address.toString() });
          if (hits.length > 400) break;
        }
      }
      if (hits.length > 400) break;
    }
    send({ t: 'log', msg: '[i] 网络/加密相关符号候选 (' + hits.length + ' 条，最多显示 40):\n' +
      JSON.stringify(hits.slice(0, 40), null, 1) });
    return hits;
  };

  /**
   * B. hook libc send/recv —— 兜底，抓非 SSL 流量
   *    注意：这里拿到的是**加密后的密文**（如果上层走了 TLS），
   *    但很多游戏自定义协议是明文的，这层反而最有用
   */
  Net.hookSocket = function (opts) {
    opts = opts || {};
    const cap = opts.cap || 256;
    const minLen = opts.minLen || 0;
    const out = [];

    // 写方向：数据已就绪，onEnter 读
    const sendSigs = [
      ['send', 'ssize_t', ['int', 'pointer', 'size_t', 'int']],
      ['sendto', 'ssize_t', ['int', 'pointer', 'size_t', 'int', 'pointer', 'int']],
      ['write', 'ssize_t', ['int', 'pointer', 'size_t']]
    ];
    for (const [fn] of sendSigs) {
      const p = Module.findExportByName('libc.so', fn);
      if (!p) continue;
      Interceptor.attach(p, {
        onEnter(args) {
          this._buf = args[1];
          this._len = args[2].toInt32();
          if (this._len > 0 && this._len >= minLen) {
            try { this._data = this._buf.readByteArray(Math.min(this._len, 65536)); } catch (e) {}
          }
        },
        onLeave(ret) {
          const r = ret.toInt32();
          if (r > 0 && this._data) emit('send', 'socket', r, this._data, cap, opts.dumpFull);
        }
      });
      out.push({ fn: fn, addr: p.toString() });
    }

    // 读方向：必须 onLeave 读
    const recvSigs = ['recv', 'recvfrom', 'read'];
    for (const fn of recvSigs) {
      const p = Module.findExportByName('libc.so', fn);
      if (!p) continue;
      Interceptor.attach(p, {
        onEnter(args) { this._buf = args[1]; },
        onLeave(ret) {
          const r = ret.toInt32();
          if (r <= 0 || r < minLen) return;
          let buf = null;
          try { buf = this._buf.readByteArray(Math.min(r, 65536)); } catch (e) {}
          emit('recv', 'socket', r, buf, cap, opts.dumpFull);
        }
      });
      out.push({ fn: fn, addr: p.toString() });
    }

    send({ t: 'log', msg: '[+] socket hook 已装: ' + out.map(x => x.fn).join(', ') });
    return out;
  };

  /**
   * C. 只记长度 —— 用于「看谁在什么时候发了多大的包」而不关心内容
   *    开销极小，适合长时间挂机观察协议节奏
   */
  Net.hookLengthOnly = function (filter) {
    const out = [];
    const p1 = Module.findExportByName('libc.so', 'send');
    if (p1) {
      Interceptor.attach(p1, {
        onEnter(args) { this._l = args[2].toInt32(); },
        onLeave(ret) {
          const r = ret.toInt32();
          if (r > 0 && (!filter || r >= filter)) {
            send({ t: 'log', msg: '[net] SEND ' + r + 'B  ' +
              Thread.backtrace(this.context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).slice(0, 4).join(' <- ') });
          }
        }
      });
      out.push('send');
    }
    return out;
  };

  /**
   * 一键：SSL 优先，失败自动降级到 socket
   */
  Net.start = function (opts) {
    opts = opts || {};
    const r = { ssl: null, socket: null };
    r.ssl = Net.hookSsl(opts);
    if (!r.ssl.length || opts.forceSocket) {
      r.socket = Net.hookSocket(opts);
    }
    if (!r.ssl.length && !r.socket.length) {
      send({ t: 'log', msg: '[!] 网络 hook 全部失败，用 Net.scanNetSymbols() 看看实际符号名' });
    }
    return r;
  };

  G.NetTrace = Net;
})();
