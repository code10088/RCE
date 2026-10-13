"""Unit tests for the offline (no-device) logic.

Covers the pure-Python paths that used to have no automated coverage: ELF
mapping, byte patching, dump carving, cross-check, diff, calibration, and the
Unicorn emulator (skipped when unicorn is not installed). Run from the repo
root:

    python -m unittest discover -s tests
    python tool.py selftest      # same thing via the unified entry
"""
import importlib.util
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "static"))
sys.path.insert(0, str(ROOT / "host"))

import _elf  # noqa: E402
import patch  # noqa: E402
import carve  # noqa: E402
import crosscheck  # noqa: E402
import diff  # noqa: E402
import calibrate  # noqa: E402
import analyze  # noqa: E402


def build_elf64(code, vaddr=0x1000, file_off=0x200, machine=183):
    """Minimal little-endian ELF64 with one R+X PT_LOAD segment holding code."""
    data = bytearray(file_off + len(code))
    data[0:4] = b"\x7fELF"
    data[4], data[5], data[6] = 2, 1, 1  # ELFCLASS64, little-endian, version
    struct.pack_into("<H", data, 16, 3)        # e_type ET_DYN
    struct.pack_into("<H", data, 18, machine)  # e_machine
    struct.pack_into("<I", data, 20, 1)
    struct.pack_into("<Q", data, 32, 64)       # e_phoff
    struct.pack_into("<H", data, 52, 64)       # e_ehsize
    struct.pack_into("<H", data, 54, 56)       # e_phentsize
    struct.pack_into("<H", data, 56, 1)        # e_phnum
    ph = 64
    struct.pack_into("<I", data, ph, 1)        # PT_LOAD
    struct.pack_into("<I", data, ph + 4, 5)    # R+X
    struct.pack_into("<Q", data, ph + 8, file_off)
    struct.pack_into("<Q", data, ph + 16, vaddr)
    struct.pack_into("<Q", data, ph + 24, vaddr)
    struct.pack_into("<Q", data, ph + 32, len(code))
    struct.pack_into("<Q", data, ph + 40, len(code))
    struct.pack_into("<Q", data, ph + 48, 0x1000)
    data[file_off:file_off + len(code)] = code
    return bytes(data)


class TestElf(unittest.TestCase):
    def setUp(self):
        self.blob = build_elf64(b"\x1f\x20\x03\xd5" * 4, vaddr=0x1000, file_off=0x200)
        self.info = _elf.load_segments(self.blob)

    def test_segment_parsed(self):
        self.assertEqual(len(self.info["segments"]), 1)
        self.assertEqual(self.info["segments"][0]["vaddr"], 0x1000)

    def test_rva_to_offset(self):
        self.assertEqual(_elf.rva_to_offset(self.info, 0x1004), 0x204)

    def test_rva_out_of_range(self):
        with self.assertRaises(_elf.ElfError):
            _elf.rva_to_offset(self.info, 0x9999)

    def test_not_elf(self):
        with self.assertRaises(_elf.ElfError):
            _elf.load_segments(b"not an elf at all")


class TestPatch(unittest.TestCase):
    def test_parse_new_only(self):
        loc, old, new = patch.parse_patch("rva:0x1000=00112233")
        self.assertEqual(loc, "rva:0x1000")
        self.assertIsNone(old)
        self.assertEqual(new, b"\x00\x11\x22\x33")

    def test_parse_verify_then_write(self):
        loc, old, new = patch.parse_patch("off:0x10=aabb:ccdd")
        self.assertEqual((old, new), (b"\xaa\xbb", b"\xcc\xdd"))

    def test_resolve_offset_file_and_rva(self):
        info = _elf.load_segments(build_elf64(b"\x00" * 8))
        self.assertEqual(patch.resolve_offset(None, "off:0x200"), 0x200)
        self.assertEqual(patch.resolve_offset(info, "rva:0x1004"), 0x204)

    def test_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            src = d / "libil2cpp.so"
            src.write_bytes(build_elf64(b"\x1f\x20\x03\xd5" * 2, vaddr=0x1000, file_off=0x200))
            out = d / "patched.so"
            rc = subprocess.run(
                [sys.executable, str(ROOT / "static/patch.py"), "--binary", str(src),
                 "--out", str(out), "--patch", "rva:0x1000=1f2003d5:00000000"],
                capture_output=True, text=True).returncode
            self.assertEqual(rc, 0)
            self.assertEqual(out.read_bytes()[0x200:0x204], b"\x00\x00\x00\x00")
            manifest = json.loads((d / "patched.so.patch.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["patches"][0]["before"], "1f2003d5")
            self.assertTrue(manifest["patches"][0]["verified"])

    def test_verify_mismatch_refuses(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            src = d / "libil2cpp.so"
            src.write_bytes(build_elf64(b"\x1f\x20\x03\xd5", vaddr=0x1000, file_off=0x200))
            result = subprocess.run(
                [sys.executable, str(ROOT / "static/patch.py"), "--binary", str(src),
                 "--out", str(d / "p.so"), "--patch", "rva:0x1000=deadbeef:00000000"],
                capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((d / "p.so").exists())


class TestCarve(unittest.TestCase):
    def test_ascii_strings(self):
        hits = list(carve.ascii_strings(b"\x00hello_world\x00", 5))
        self.assertTrue(any("hello_world" in text for _, text in hits))

    def test_utf16_strings(self):
        data = "secret".encode("utf-16-le")
        hits = list(carve.utf16_strings(data, 4))
        self.assertTrue(any("secret" in text for _, text in hits))

    def test_find_embedded_elf(self):
        blob = b"PAD" + build_elf64(b"\x00" * 8)
        hits = carve.find_embedded(blob)
        self.assertTrue(any(h["type"] == "elf" for h in hits))

    def test_fake_mz_rejected(self):
        # "MZ" without a valid PE pointer must not be reported as a PE image.
        self.assertFalse(any(h["type"] == "pe" for h in carve.find_embedded(b"MZ" + b"\x00" * 128)))


class TestCrosscheck(unittest.TestCase):
    def test_counts(self):
        static = {"ScriptMethod": [{"Address": 0x1000, "Name": "A"}]}
        dynamic = {"methods": [{"name": "A", "rva": "0x1000"},
                               {"name": "B", "rva": "0x2000"},
                               {"name": "C", "rva": "not-a-number"}]}
        report = crosscheck.compare(static, dynamic)
        self.assertEqual(report["counts"], {"address_match": 1, "unmatched": 1, "invalid": 1})


class TestDiff(unittest.TestCase):
    def test_classes_index(self):
        tree = {"images": [{"classes": [{"namespace": "Game", "name": "Player", "methods": []}]}]}
        found = diff.classes(tree)
        self.assertIn("Game.Player", found)


class TestCalibrate(unittest.TestCase):
    def test_runtime_address(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            classes = d / "classes.json"
            classes.write_text(json.dumps({"classes": [
                {"namespace": "Game", "name": "P", "methods": [{"name": "f", "rva": "0x1000"}]}]}),
                encoding="utf-8")
            out = d / "cal.json"
            rc = calibrate.main([str(classes), "--module-base", "0x7a00000000", "--out", str(out)])
            self.assertEqual(rc, 0)
            report = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(report["methods"][0]["runtime_address"], hex(0x7a00000000 + 0x1000))


class TestAnalyze(unittest.TestCase):
    def test_walk_classes(self):
        out = []
        analyze.walk_classes({"images": [{"classes": [{"name": "A"}, {"name": "B"}]}]}, out)
        self.assertEqual({c["name"] for c in out}, {"A", "B"})

    def test_secret_pattern(self):
        self.assertTrue(analyze.SECRET_PAT.search("https://api.example.com/v1"))
        self.assertFalse(analyze.SECRET_PAT.search("just a plain sentence"))


@unittest.skipUnless(importlib.util.find_spec("unicorn"), "unicorn not installed")
class TestEmulate(unittest.TestCase):
    def test_returns_constant(self):
        # mov x0, #0x2a ; ret
        code = bytes.fromhex("400580d2") + bytes.fromhex("c0035fd6")
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            src = d / "libil2cpp.so"
            src.write_bytes(build_elf64(code, vaddr=0x1000, file_off=0x200))
            out = d / "emu.json"
            rc = subprocess.run(
                [sys.executable, str(ROOT / "static/emulate.py"), "--binary", str(src),
                 "--rva", "0x1000", "--out", str(out)], capture_output=True, text=True).returncode
            self.assertEqual(rc, 0)
            report = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(report["stopped"], "returned")
            self.assertEqual(int(report["return_value"], 16), 0x2a)


if __name__ == "__main__":
    unittest.main()
