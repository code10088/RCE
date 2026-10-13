"""Minimal ELF64 program-header parsing shared by emulate.py and patch.py.

Only what the harness needs: locate PT_LOAD segments so a static RVA (which for
a position-independent libil2cpp.so equals the virtual address at link base 0)
can be mapped to a file offset or loaded into an emulator. No section headers,
no relocations.
"""
import struct

PT_LOAD = 1
PF_X, PF_W, PF_R = 0x1, 0x2, 0x4


class ElfError(ValueError):
    pass


def load_segments(data):
    """Return PT_LOAD segments as dicts: offset, vaddr, filesz, memsz, flags."""
    if data[:4] != b'\x7fELF':
        raise ElfError('not an ELF file')
    if data[4] != 2:
        raise ElfError('only ELF64 is supported')
    little = data[5] == 1
    endian = '<' if little else '>'
    e_machine = struct.unpack_from(endian + 'H', data, 18)[0]
    e_phoff = struct.unpack_from(endian + 'Q', data, 32)[0]
    e_phentsize = struct.unpack_from(endian + 'H', data, 54)[0]
    e_phnum = struct.unpack_from(endian + 'H', data, 56)[0]
    segments = []
    for i in range(e_phnum):
        base = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from(endian + 'II', data, base)
        p_offset, p_vaddr = struct.unpack_from(endian + 'QQ', data, base + 8)
        p_filesz, p_memsz = struct.unpack_from(endian + 'QQ', data, base + 32)
        if p_type == PT_LOAD:
            segments.append({'offset': p_offset, 'vaddr': p_vaddr,
                             'filesz': p_filesz, 'memsz': p_memsz, 'flags': p_flags})
    if not segments:
        raise ElfError('no PT_LOAD segments')
    return {'machine': e_machine, 'little': little, 'segments': segments}


def rva_to_offset(info, rva):
    """Map a virtual address (== static RVA at link base 0) to a file offset."""
    for seg in info['segments']:
        if seg['vaddr'] <= rva < seg['vaddr'] + seg['filesz']:
            return seg['offset'] + (rva - seg['vaddr'])
    raise ElfError('RVA 0x%x is not inside any loaded, file-backed segment' % rva)
