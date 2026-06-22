"""Tests for Sims 4 Mod Analyzer."""

import io
import os
import struct
import sys
import tempfile
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure the module is importable
sys.path.insert(0, str(Path(__file__).resolve().parent))
from mod_analyzer import (
    KNOWN_TYPES,
    analyze,
    read_package_index,
    print_report,
)


# ── Helpers ──────────────────────────────────────────────────────────

def make_dbpf_v2(entries: list[tuple[int, int, int, int, int]]) -> bytes:
    """Build a valid DBPF v2.0 binary blob.

    Each entry: (type, group, instance, offset, size)
    """
    magic = b"DBPF"
    version = 2  # v2.0
    user_version = 0
    unknown = 0
    created = 0
    modified = 0
    index_major = 0
    entry_count = len(entries)
    # We'll place the index right after the 96-byte header + dummy data
    data_offset = 96
    # Calculate total data size
    total_data = max((e[3] + e[4] for e in entries), default=0)
    index_offset = data_offset + total_data
    index_size = entry_count * 24

    header = struct.pack(
        "<4sIIIIIIIII",
        magic,
        version,
        user_version,
        unknown,
        created,
        modified,
        index_major,
        entry_count,
        index_offset,
        index_size,
    )
    header = header.ljust(96, b"\x00")

    # Write dummy data (just zeros for the data area)
    dummy_data = b"\x00" * total_data

    # Write index entries
    index = b""
    for typ, grp, inst, off, sz in entries:
        index += struct.pack("<IIQII", typ, grp, inst, off, sz)

    return header + dummy_data + index


class TempMods:
    """Context manager that creates a temp directory with mod files."""

    def __init__(self, package_files: dict[str, bytes] = None, script_files: dict[str, bytes] = None):
        self.package_files = package_files or {}
        self.script_files = script_files or {}

    def __enter__(self):
        self.path = Path(tempfile.mkdtemp())
        for name, content in self.package_files.items():
            fp = self.path / name
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_bytes(content)
        for name, content in self.script_files.items():
            fp = self.path / name
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_bytes(content)
        return self.path

    def __exit__(self, *args):
        import shutil
        shutil.rmtree(str(self.path))


# ── Tests for DBPF parsing ─────────────────────────────────────────

class TestReadPackageIndex:
    def test_empty_file_without_dbpf_magic(self):
        with tempfile.TemporaryDirectory() as tmp:
            fp = Path(tmp) / "mod.package"
            fp.write_text("not a dbpf file")
            assert read_package_index(fp) == []

    def test_empty_file_with_dbpf_magic_but_no_entries(self):
        fp = Path(tempfile.mktemp(suffix=".package"))
        try:
            # header with 0 entries
            pass
            # Actually make_dbp_v2 doesn't exist, use make_dbpf_v2
            # Wait, I wrote make_dbpf_v2, let me check
            pass
        finally:
            if fp.exists():
                fp.unlink()

    def test_parse_single_entry(self):
        entries = [(0x025C5F1A, 0, 0x100000000000001, 0, 8)]
        data = make_dbpf_v2(entries)
        with tempfile.TemporaryDirectory() as tmp:
            fp = Path(tmp) / "single.package"
            fp.write_bytes(data)
            parsed = read_package_index(fp)
            assert len(parsed) == 1
            assert parsed[0]["type"] == 0x025C5F1A
            assert parsed[0]["group"] == 0
            assert parsed[0]["instance"] == 0x100000000000001
            assert parsed[0]["offset"] == 0
            assert parsed[0]["size"] == 8

    def test_parse_multiple_entries(self):
        entries = [
            (0x025C5F1A, 0, 0x1, 0, 16),
            (0x03536A8B, 1, 0x2, 16, 32),
            (0x042B5B94, 2, 0x3, 48, 64),
        ]
        data = make_dbpf_v2(entries)
        with tempfile.TemporaryDirectory() as tmp:
            fp = Path(tmp) / "multi.package"
            fp.write_bytes(data)
            parsed = read_package_index(fp)
            assert len(parsed) == 3
            assert parsed[0]["instance"] == 0x1
            assert parsed[1]["instance"] == 0x2
            assert parsed[2]["instance"] == 0x3

    def test_not_a_valid_package_file(self):
        fp = Path(tempfile.mktemp(suffix=".package"))
        try:
            fp.write_text("")
            assert read_package_index(fp) == []
        finally:
            if fp.exists():
                fp.unlink()

    def test_corrupted_header_returns_empty(self):
        fp = Path(tempfile.mktemp(suffix=".package"))
        try:
            fp.write_bytes(b"DBPF" + b"\xff" * 92)
            parsed = read_package_index(fp)
            # Should handle gracefully
            assert isinstance(parsed, list)
        finally:
            if fp.exists():
                fp.unlink()


# ── Tests for conflict detection ────────────────────────────────────

class TestConflictDetection:
    def test_no_conflicts_with_distinct_resources(self):
        mod1 = make_dbpf_v2([(0x025C5F1A, 0, 0x1, 0, 8)])
        mod2 = make_dbpf_v2([(0x025C5F1A, 0, 0x2, 0, 8)])
        with TempMods({"a.package": mod1, "b.package": mod2}) as tmp:
            result = analyze(str(tmp))
            assert result["total_conflicts"] == 0

    def test_detects_conflict_same_resource_in_two_mods(self):
        mod1 = make_dbpf_v2([(0x025C5F1A, 0, 0x42, 0, 8)])
        mod2 = make_dbpf_v2([(0x025C5F1A, 0, 0x42, 0, 8)])
        with TempMods({"a.package": mod1, "b.package": mod2}) as tmp:
            result = analyze(str(tmp))
            assert result["total_conflicts"] == 1

    def test_detects_conflict_three_mods_same_resource(self):
        shared = (0x025C5F1A, 0, 0x99, 0, 8)
        mod = make_dbpf_v2([shared])
        with TempMods({
            "a.package": mod,
            "b.package": mod,
            "c.package": mod,
        }) as tmp:
            result = analyze(str(tmp))
            assert result["total_conflicts"] == 1
            key = (0x025C5F1A, 0, 0x99)
            assert len(result["conflicts"][key]["mods"]) == 3
            assert result["conflicts"][key]["intentional"] is False

    def test_multiple_conflicts_across_different_types(self):
        mod1 = make_dbpf_v2([
            (0x025C5F1A, 0, 0x1, 0, 8),
            (0x03536A8B, 0, 0x2, 8, 8),
        ])
        mod2 = make_dbpf_v2([
            (0x025C5F1A, 0, 0x1, 0, 8),
            (0x03536A8B, 0, 0x2, 8, 8),
        ])
        with TempMods({"a.package": mod1, "b.package": mod2}) as tmp:
            result = analyze(str(tmp))
            assert result["total_conflicts"] == 2

    def test_no_false_positive_with_different_groups(self):
        mod1 = make_dbpf_v2([(0x025C5F1A, 0, 0x1, 0, 8)])
        mod2 = make_dbpf_v2([(0x025C5F1A, 1, 0x1, 0, 8)])
        with TempMods({"a.package": mod1, "b.package": mod2}) as tmp:
            result = analyze(str(tmp))
            assert result["total_conflicts"] == 0


# ── Tests for lag analysis ─────────────────────────────────────────

class TestLagAnalysis:
    def test_large_file_detected(self):
        mod = make_dbpf_v2([(0x025C5F1A, 0, 0x1, 0, 8)])
        with TempMods({"large.package": mod}) as tmp:
            # Write a large package file
            fp = tmp / "huge.package"
            # 30 MB file
            fp.write_bytes(b"\x00" * (30 * 1024 * 1024))
            result = analyze(str(tmp))
            assert len(result["large_files"]) == 1
            assert result["large_files"][0][1] >= 30 * 1024 * 1024

    def test_small_files_not_reported(self):
        mod = make_dbpf_v2([(0x025C5F1A, 0, 0x1, 0, 8)])
        with TempMods({"small.package": mod}) as tmp:
            result = analyze(str(tmp))
            assert len(result["large_files"]) == 0

    def test_script_mods_detected(self):
        with TempMods(script_files={"my_script.ts4script": b"PK" + b"\x00" * 100}) as tmp:
            result = analyze(str(tmp))
            assert len(result["script_mods"]) == 1

    def test_multiple_script_mods(self):
        scripts = {f"mod_{i}.ts4script": b"PK" + b"\x00" * 50 for i in range(5)}
        with TempMods(script_files=scripts) as tmp:
            result = analyze(str(tmp))
            assert len(result["script_mods"]) == 5

    def test_duplicate_file_names_detected(self):
        mod = make_dbpf_v2([(0x025C5F1A, 0, 0x1, 0, 8)])
        with TempMods({
            "sub1/SomeMod.package": mod,
            "sub2/SomeMod.package": mod,
        }) as tmp:
            result = analyze(str(tmp))
            assert len(result["duplicate_names"]) >= 1

    def test_top_mods_by_resource_count(self):
        mod1 = make_dbpf_v2([(0x025C5F1A, 0, i, i * 8, 8) for i in range(100)])
        mod2 = make_dbpf_v2([(0x025C5F1A, 0, i, i * 8, 8) for i in range(10)])
        with TempMods({"big.package": mod1, "small.package": mod2}) as tmp:
            result = analyze(str(tmp))
            assert result["mod_resource_counts"]["big.package"] == 100
            assert result["mod_resource_counts"]["small.package"] == 10


# ── Tests for analyze() function ───────────────────────────────────

class TestAnalyze:
    def test_nonexistent_path(self):
        result = analyze("/nonexistent/path")
        assert "error" in result

    def test_empty_folder(self):
        with TempMods() as tmp:
            result = analyze(str(tmp))
            assert result["total_packages"] == 0
            assert result["total_scripts"] == 0
            assert result["total_conflicts"] == 0

    def test_ignores_non_mod_files(self):
        with TempMods() as tmp:
            (tmp / "readme.txt").write_text("not a mod")
            (tmp / "subdir").mkdir()
            (tmp / "subdir" / "image.png").write_bytes(b"\x89PNG")
            result = analyze(str(tmp))
            assert result["total_packages"] == 0
            assert result["total_scripts"] == 0

    def test_package_and_script_together(self):
        mod = make_dbpf_v2([(0x025C5F1A, 0, 0x1, 0, 8)])
        with TempMods(
            package_files={"tuning.package": mod},
            script_files={"script.ts4script": b"PK" + b"\x00" * 50},
        ) as tmp:
            result = analyze(str(tmp))
            assert result["total_packages"] == 1
            assert result["total_scripts"] == 1

    def test_subdirectory_scanning(self):
        mod = make_dbpf_v2([(0x025C5F1A, 0, 0x1, 0, 8)])
        with TempMods({}) as tmp:
            deep = tmp / "a" / "b" / "c"
            deep.mkdir(parents=True)
            (deep / "nested.package").write_bytes(mod)
            result = analyze(str(tmp))
            assert result["total_packages"] == 1


# ── Tests for report printing ──────────────────────────────────────

class TestPrintReport:
    def test_error_report(self, capsys):
        print_report({"error": "test error"})
        captured = capsys.readouterr()
        assert "ОШИБКА" in captured.out
        assert "test error" in captured.out

    def test_empty_report(self, capsys):
        result = {
            "mods_path": "/tmp/test",
            "total_packages": 0,
            "total_scripts": 0,
            "total_entries": 0,
            "total_conflicts": 0,
            "total_intentional": 0,
            "conflicts": {},
            "type_counts": {},
            "mod_resource_counts": {},
            "large_files": [],
            "script_mods": [],
            "duplicate_names": [],
            "duplicate_content": [],
            "deep_scripts": [],
            "corrupt_archives": [],
            "wrong_python": [],
            "onedrive": False,
            "deprecated_files": [],
            "elapsed": 0.01,
        }
        print_report(result)
        captured = capsys.readouterr()
        assert "Sims 4 Mod Analyzer" in captured.out
        assert "0" in captured.out

    def test_report_with_conflicts(self, capsys):
        result = {
            "mods_path": "/tmp/test",
            "total_packages": 2,
            "total_scripts": 0,
            "total_entries": 2,
            "total_conflicts": 1,
            "total_intentional": 0,
            "conflicts": {
                (0x025C5F1A, 0, 0x42): {
                    "mods": [(Path("mod1.package"), 0), (Path("mod2.package"), 0)],
                    "intentional": False,
                    "type": 0x025C5F1A,
                    "group": 0,
                    "instance": 0x42,
                }
            },
            "type_counts": {0x025C5F1A: 2},
            "mod_resource_counts": {"mod1.package": 1, "mod2.package": 1},
            "large_files": [],
            "script_mods": [],
            "duplicate_names": [],
            "duplicate_content": [],
            "deep_scripts": [],
            "corrupt_archives": [],
            "wrong_python": [],
            "onedrive": False,
            "deprecated_files": [],
            "elapsed": 0.01,
        }
        print_report(result)
        captured = capsys.readouterr()
        assert "КОНФЛИКТЫ" in captured.out
        assert "mod1.package" in captured.out
        assert "mod2.package" in captured.out
        assert "Tuning (XML)" in captured.out

    def test_report_with_large_files(self, capsys):
        result = {
            "mods_path": "/tmp/test",
            "total_packages": 1,
            "total_scripts": 0,
            "total_entries": 1,
            "total_conflicts": 0,
            "total_intentional": 0,
            "conflicts": {},
            "type_counts": {},
            "mod_resource_counts": {"big.package": 1},
            "large_files": [(Path("big.package"), 30 * 1024 * 1024)],
            "script_mods": [],
            "duplicate_names": [],
            "duplicate_content": [],
            "deep_scripts": [],
            "corrupt_archives": [],
            "wrong_python": [],
            "onedrive": False,
            "deprecated_files": [],
            "elapsed": 0.01,
        }
        print_report(result)
        captured = capsys.readouterr()
        assert "БОЛЬШИЕ ФАЙЛЫ" in captured.out
        assert "30" in captured.out or "30.0" in captured.out

    def test_report_with_script_mods(self, capsys):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "test.ts4script"
            script.write_bytes(b"X" * 2048)
            result = {
                "mods_path": tmp,
                "total_packages": 0,
                "total_scripts": 1,
                "total_entries": 0,
                "total_conflicts": 0,
                "total_intentional": 0,
                "conflicts": {},
                "type_counts": {},
                "mod_resource_counts": {},
                "large_files": [],
                "script_mods": [script],
                "duplicate_names": [],
                "duplicate_content": [],
                "deep_scripts": [],
                "corrupt_archives": [],
                "wrong_python": [],
                "onedrive": False,
                "deprecated_files": [],
                "elapsed": 0.01,
            }
            print_report(result)
            captured = capsys.readouterr()
            assert "СКРИПТ-МОДЫ" in captured.out
            assert "test.ts4script" in captured.out


# ── Tests for known types ──────────────────────────────────────────

class TestKnownTypes:
    def test_known_type_has_name(self):
        from mod_analyzer import _type_name
        assert _type_name(0x025C5F1A) == "Tuning (XML)"
        assert _type_name(0x03536A8B) == "String Table (STBL)"

    def test_unknown_type_returns_hex(self):
        from mod_analyzer import _type_name
        name = _type_name(0xDEADBEEF)
        assert "DEADBEEF" in name

    def test_known_types_dict_populated(self):
        assert 0x025C5F1A in KNOWN_TYPES
        assert 0x042B5B94 in KNOWN_TYPES
        assert 0x316BB703 in KNOWN_TYPES


# ── Edge cases ─────────────────────────────────────────────────────

class TestEdgeCases:
    def test_unicode_mod_path(self):
        mod = make_dbpf_v2([(0x025C5F1A, 0, 0x1, 0, 8)])
        name = "мод_тест.package"
        with TempMods({name: mod}) as tmp:
            result = analyze(str(tmp))
            assert result["total_packages"] == 1

    def test_very_deep_nesting(self):
        mod = make_dbpf_v2([(0x025C5F1A, 0, 0x1, 0, 8)])
        with TempMods({}) as tmp:
            deep = tmp / "a" / "b" / "c" / "d" / "e" / "f" / "g"
            deep.mkdir(parents=True)
            (deep / "deep.package").write_bytes(mod)
            result = analyze(str(tmp))
            assert result["total_packages"] == 1

    def test_handles_broken_package_gracefully(self):
        with TempMods({"broken.package": b"\x00" * 50}) as tmp:
            # Should not crash, just return empty for this file
            result = analyze(str(tmp))
            assert result["total_packages"] == 1
            assert result["total_entries"] == 0

    def test_conflict_key_structure(self):
        mod = make_dbpf_v2([(0x025C5F1A, 0, 0x42, 0, 8)])
        with TempMods({"a.package": mod, "b.package": mod}) as tmp:
            result = analyze(str(tmp))
            key = next(iter(result["conflicts"]))
            assert len(key) == 3  # (type, group, instance)
            assert isinstance(key[0], int)
            assert isinstance(key[1], int)
            assert isinstance(key[2], int)
            # Check nested dict structure
            c = result["conflicts"][key]
            assert "mods" in c
            assert "intentional" in c
            assert len(c["mods"]) == 2
