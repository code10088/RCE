"""Emulate a single native function offline with Unicorn.

Carves one function out of an extracted libil2cpp.so and runs it in a CPU
emulator, without a device or the full app. This is the offline counterpart to
the dynamic `stalk` tracing: useful for reversing self-contained routines
(checksums, string decryptors, key schedules) where you can supply the inputs.

It does NOT model the IL2CPP runtime: calls into other functions, allocations,
or il2cpp_* APIs will reach unmapped memory. Keep targets to leaf-like code, or
stop at the first unresolved call and inspect state. Results are evidence to
cross-check against real runtime behaviour, not proof on their own.

  python static/emulate.py --binary libil2cpp.so --rva 0x1A2B3C \
      --arg 0=0x40000000 --arg 1=16 --map 0x40000000=input.bin \
      --trace --out emulate.json
"""
import argparse
import json
from pathlib import Path
import sys

import _elf

STACK_BASE = 0x7000000000
STACK_SIZE = 0x200000
RETURN_MAGIC = 0x1FFFFFF0  # LR sentinel; execution stops when we return here.


def align_down(value, page=0x1000):
    return value & ~(page - 1)


def align_up(value, page=0x1000):
    return (value + page - 1) & ~(page - 1)


def parse_kv(values, name):
    out = {}
    for item in values or []:
        if '=' not in item:
            raise ValueError('%s expects key=value, got %r' % (name, item))
        key, value = item.split('=', 1)
        out[key.strip()] = value.strip()
    return out


def parse_bytes(spec):
    """input.bin path, or inline hex like 0x0011aabb / 00 11 aa bb."""
    path = Path(spec)
    if path.is_file():
        return path.read_bytes()
    cleaned = spec.lower().replace('0x', '').replace(' ', '').replace(',', '')
    if not cleaned or len(cleaned) % 2:
        raise ValueError('cannot read %r as a file or hex byte string' % spec)
    return bytes.fromhex(cleaned)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--binary', required=True, type=Path, help='Extracted libil2cpp.so')
    parser.add_argument('--rva', required=True, help='Function RVA/virtual address (hex, 0x accepted)')
    parser.add_argument('--arch', default='arm64', choices=['arm64', 'x86_64'])
    parser.add_argument('--arg', action='append',
                        help='Register argument N=value, e.g. 0=0x1000 1=16 (x0.. / rdi,rsi,..)')
    parser.add_argument('--map', action='append',
                        help='Pre-load memory ADDR=FILE_OR_HEX, e.g. 0x40000000=input.bin')
    parser.add_argument('--read', action='append',
                        help='After the run, dump ADDR:LEN as hex, e.g. 0x40000000:64')
    parser.add_argument('--max-insn', type=int, default=200000, help='Instruction budget')
    parser.add_argument('--trace', action='store_true', help='Disassemble each step (needs capstone)')
    parser.add_argument('--out', type=Path, help='Write a JSON report')
    args = parser.parse_args()

    try:
        from unicorn import (Uc, UC_ARCH_ARM64, UC_ARCH_X86, UC_MODE_ARM, UC_MODE_64,
                             UC_HOOK_CODE, UcError)
        from unicorn import arm64_const, x86_const
    except ImportError:
        parser.error('Unicorn is not installed. Run: pip install unicorn  (optional dependency)')

    if not args.binary.is_file():
        parser.error('Binary not found: %s' % args.binary)
    rva = int(str(args.rva), 0)
    data = args.binary.read_bytes()
    try:
        info = _elf.load_segments(data)
    except _elf.ElfError as exc:
        parser.error('ELF parse failed: %s' % exc)

    if args.arch == 'arm64':
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        arg_regs = [getattr(arm64_const, 'UC_ARM64_REG_X%d' % i) for i in range(8)]
        pc_reg, sp_reg, lr_reg, ret_reg = (arm64_const.UC_ARM64_REG_PC,
                                           arm64_const.UC_ARM64_REG_SP,
                                           arm64_const.UC_ARM64_REG_LR,
                                           arm64_const.UC_ARM64_REG_X0)
        cs_setup = ('CS_ARCH_ARM64', 'CS_MODE_ARM')
    else:
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        arg_regs = [x86_const.UC_X86_REG_RDI, x86_const.UC_X86_REG_RSI, x86_const.UC_X86_REG_RDX,
                    x86_const.UC_X86_REG_RCX, x86_const.UC_X86_REG_R8, x86_const.UC_X86_REG_R9]
        pc_reg, sp_reg, lr_reg, ret_reg = (x86_const.UC_X86_REG_RIP, x86_const.UC_X86_REG_RSP,
                                           None, x86_const.UC_X86_REG_RAX)
        cs_setup = ('CS_ARCH_X86', 'CS_MODE_64')

    # Map every PT_LOAD segment at its virtual address (link base 0).
    for seg in info['segments']:
        start = align_down(seg['vaddr'])
        size = align_up(seg['vaddr'] + seg['memsz']) - start
        uc.mem_map(start, max(size, 0x1000))
        chunk = data[seg['offset']:seg['offset'] + seg['filesz']]
        uc.mem_write(seg['vaddr'], chunk)
    uc.mem_map(STACK_BASE, STACK_SIZE)
    uc.reg_write(sp_reg, STACK_BASE + STACK_SIZE // 2)

    preloads = parse_kv(args.map, '--map')
    for addr, spec in preloads.items():
        blob = parse_bytes(spec)
        base = align_down(int(addr, 0))
        uc.mem_map(base, align_up(int(addr, 0) + len(blob)) - base)
        uc.mem_write(int(addr, 0), blob)

    for key, value in parse_kv(args.arg, '--arg').items():
        idx = int(key)
        if idx >= len(arg_regs):
            parser.error('--arg index %d out of range for %s' % (idx, args.arch))
        uc.reg_write(arg_regs[idx], int(value, 0))

    if args.arch == 'arm64':
        uc.reg_write(lr_reg, RETURN_MAGIC)
    else:
        sp = uc.reg_read(sp_reg) - 8
        uc.mem_write(sp, RETURN_MAGIC.to_bytes(8, 'little'))
        uc.reg_write(sp_reg, sp)

    trace = []
    if args.trace:
        try:
            import capstone
            md = capstone.Cs(getattr(capstone, cs_setup[0]), getattr(capstone, cs_setup[1]))
        except ImportError:
            parser.error('--trace needs capstone. Run: pip install capstone')

        def on_code(mu, address, size, _):
            if len(trace) >= 4000:
                return
            try:
                code = mu.mem_read(address, size)
                for insn in md.disasm(bytes(code), address):
                    trace.append('0x%x: %s %s' % (insn.address, insn.mnemonic, insn.op_str))
            except Exception:
                trace.append('0x%x: <unreadable>' % address)
        uc.hook_add(UC_HOOK_CODE, on_code)

    report = {'binary': str(args.binary.resolve()), 'rva': hex(rva), 'arch': args.arch,
              'args': parse_kv(args.arg, '--arg'), 'stopped': None, 'error': None}
    try:
        uc.emu_start(rva, RETURN_MAGIC, count=args.max_insn)
        report['stopped'] = 'returned'
    except UcError as exc:
        report['stopped'] = 'fault'
        report['error'] = str(exc)
        report['fault_pc'] = hex(uc.reg_read(pc_reg))

    report['return_value'] = hex(uc.reg_read(ret_reg))
    regs = {}
    for i, reg in enumerate(arg_regs):
        regs[('x%d' if args.arch == 'arm64' else 'arg%d') % i] = hex(uc.reg_read(reg))
    report['registers'] = regs

    dumps = {}
    for item in args.read or []:
        addr_s, _, len_s = item.partition(':')
        addr, length = int(addr_s, 0), int(len_s or '16', 0)
        try:
            dumps[addr_s] = bytes(uc.mem_read(addr, length)).hex()
        except UcError as exc:
            dumps[addr_s] = 'unreadable: %s' % exc
    if dumps:
        report['memory'] = dumps
    if trace:
        report['trace_head'] = trace[:40]
        report['trace_count'] = len(trace)

    print('stopped:', report['stopped'], '| return:', report['return_value'])
    if report['error']:
        print('fault:', report['error'], 'at', report.get('fault_pc'))
    for addr_s, hexval in dumps.items():
        print('  mem %s = %s' % (addr_s, hexval))
    if args.out:
        args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
        if trace:
            args.out.with_suffix('.trace.txt').write_text('\n'.join(trace), encoding='utf-8')
        print('Report:', args.out)
    return 0 if report['stopped'] == 'returned' else 2


if __name__ == '__main__':
    sys.exit(main())
