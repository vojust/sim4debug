"""Tests for Sims 4 Mod Analyzer."""

import struct
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mod_analyzer import (
    DBPF_TYPES,
    AnalysisResult,
    ResourceEntry,
    PackageInfo,
    read_package,
    analyze,
    print_report,
)


# ── Helpers ──────────────────────────────────────────────────────────

def make_dbpf_v2(entries: list[tuple[int, int, int, int, int]]) -> bytes:
    """Build a valid DBPF v2.0 binary blob."""
    magic = b"DBPF"
    version = 2
    data_offset = 96
    total_data = max((e[3] + e[4] for e in entries), default=0)
    index_offset = data_offset + total_data
    index_size = len(entries) * 24

    header = struct.pack(
        "<4sIIIIIIIII",
        magic, version, 0, 0, 0, 0, 0,
        len(entries), index_offset, index_size,
    ).ljust(96, b"\x00")

    dummy_data = b"\x00" * total_data
    index = b"".join(struct.pack("<IIQII", *e) for e in entries)
    return header + dummy_data + index


class TempMods:
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

class TestReadPackage:
    def test_non_dbpf_file_has_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            fp = Path(tmp) / "mod.package"
            fp.write_text("not a dbpf file")
            pi = read_package(fp, Path("mod.package"))
            assert pi.error is not None
            assert pi.entries == []

    def test_parse_single_entry(self):
        entries = [(0x025C5F1A, 0, 0x100000000000001, 0, 8)]
        data = make_dbpf_v2(entries)
        with tempfile.TemporaryDirectory() as tmp:
            fp = Path(tmp) / "single.package"
            fp.write_bytes(data)
            pi = read_package(fp, Path("single.package"))
            assert len(pi.entries) == 1
            assert pi.entries[0].type == 0x025C5F1A
            assert pi.entries[0].instance == 0x100000000000001

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
            pi = read_package(fp, Path("multi.package"))
            assert len(pi.entries) == 3
            assert pi.entries[2].type == 0x042B5B94

    def test_empty_file_returns_no_entries(self):
        fp = Path(tempfile.mktemp(suffix=".package"))
        try:
            fp.write_text("")
            pi = read_package(fp, Path("empty.package"))
            assert pi.entries == []
        finally:
            if fp.exists():
                fp.unlink()

    def test_corrupted_header_handled_gracefully(self):
        fp = Path(tempfile.mktemp(suffix=".package"))
        try:
            fp.write_bytes(b"DBPF" + b"\xff" * 92)
            pi = read_package(fp, Path("bad.package"))
            assert pi.entries == []
        finally:
            if fp.exists():
                fp.unlink()


# ── Tests for conflict detection ────────────────────────────────────

class TestConflictDetection:
    def test_no_conflicts_with_distinct_resources(self):
        mod = make_dbpf_v2([(0x025C5F1A, 0, 0x1, 0, 8)])
        with TempMods({"a.package": mod, "b.package": mod}) as tmp:
            r = analyze(str(tmp))
            assert r.total_conflicts == 1

    def test_detects_conflict_same_resource_in_two_mods(self):
        mod = make_dbpf_v2([(0x025C5F1A, 0, 0x42, 0, 8)])
        with TempMods({"a.package": mod, "b.package": mod}) as tmp:
            r = analyze(str(tmp))
            assert r.total_conflicts == 1

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
            r = analyze(str(tmp))
            assert r.total_conflicts == 2

    def test_no_false_positive_with_different_groups(self):
        mod1 = make_dbpf_v2([(0x025C5F1A, 0, 0x1, 0, 8)])
        mod2 = make_dbpf_v2([(0x025C5F1A, 1, 0x1, 0, 8)])
        with TempMods({"a.package": mod1, "b.package": mod2}) as tmp:
            r = analyze(str(tmp))
            assert r.total_conflicts == 0


# ── Tests for AnalysisResult ───────────────────────────────────────

class TestAnalyze:
    def test_nonexistent_path(self):
        r = analyze("/nonexistent/path")
        assert not Path(r.mods_path).exists()

    def test_empty_folder(self):
        with TempMods() as tmp:
            r = analyze(str(tmp))
            assert r.total_packages == 0
            assert r.total_scripts == 0
            assert r.total_conflicts == 0

    def test_ignores_non_mod_files(self):
        with TempMods() as tmp:
            (tmp / "readme.txt").write_text("not a mod")
            (tmp / "image.png").write_bytes(b"\x89PNG")
            r = analyze(str(tmp))
            assert r.total_packages == 0
            assert r.total_scripts == 0

    def test_package_and_script_together(self):
        mod = make_dbpf_v2([(0x025C5F1A, 0, 0x1, 0, 8)])
        with TempMods(
            package_files={"tuning.package": mod},
            script_files={"script.ts4script": b"PK" + b"\x00" * 50},
        ) as tmp:
            r = analyze(str(tmp))
            assert r.total_packages == 1
            assert r.total_scripts == 1

    def test_subdirectory_scanning(self):
        mod = make_dbpf_v2([(0x025C5F1A, 0, 0x1, 0, 8)])
        with TempMods({}) as tmp:
            deep = tmp / "a" / "b" / "c"
            deep.mkdir(parents=True)
            (deep / "nested.package").write_bytes(mod)
            r = analyze(str(tmp))
            assert r.total_packages == 1


# ── Tests for health checks ────────────────────────────────────────

class TestHealthChecks:
    def test_large_file_detected(self):
        with TempMods() as tmp:
            fp = tmp / "huge.package"
            fp.write_bytes(b"\x00" * (30 * 1024 * 1024))
            r = analyze(str(tmp))
            assert len(r.large_files) >= 1

    def test_deprecated_files_detected(self):
        with TempMods() as tmp:
            (tmp / "mod.zip").write_text("fake zip")
            (tmp / "script.py").write_text("print('hi')")
            r = analyze(str(tmp))
            assert len(r.deprecated_files) >= 2

    def test_script_mods_detected(self):
        with TempMods(script_files={"mod.ts4script": b"PK" + b"\x00" * 100}) as tmp:
            r = analyze(str(tmp))
            assert r.total_scripts == 1

    def test_onedrive_detected(self):
        with TempMods() as tmp:
            fake = tmp / "OneDrive" / "Mods"
            fake.mkdir(parents=True)
            (fake / "mod.package").write_bytes(make_dbpf_v2([(0x025C5F1A, 0, 0x1, 0, 8)]))
            r = analyze(str(fake))
            assert r.onedrive is True


# ── Tests for report printing ──────────────────────────────────────

class TestPrintReport:
    def test_error_report(self, capsys):
        r = AnalysisResult(mods_path="/nonexistent")
        print_report(r)
        captured = capsys.readouterr()
        assert "ОШИБКА" in captured.out or "not found" in captured.out

    def test_empty_report(self, capsys):
        with TempMods() as tmp:
            r = analyze(str(tmp))
            print_report(r)
            captured = capsys.readouterr()
            assert "Sims 4 Mod Analyzer" in captured.out

    def test_report_with_conflicts(self, capsys):
        mod = make_dbpf_v2([(0x025C5F1A, 0, 0x42, 0, 8)])
        with TempMods({"a.package": mod, "b.package": mod}) as tmp:
            r = analyze(str(tmp))
            print_report(r)
            captured = capsys.readouterr()
            assert "КОНФЛИКТЫ" in captured.out or "Conflicts" in captured.out

    def test_report_with_large_files(self, capsys):
        with TempMods() as tmp:
            (tmp / "big.package").write_bytes(b"\x00" * (25 * 1024 * 1024))
            r = analyze(str(tmp))
            print_report(r)
            captured = capsys.readouterr()
            assert "25" in captured.out or "БОЛЬШИЕ" in captured.out

    def test_report_with_scripts(self, capsys):
        with TempMods(script_files={"test.ts4script": b"PK" + b"\x00" * 100}) as tmp:
            r = analyze(str(tmp))
            print_report(r)
            captured = capsys.readouterr()
            assert "СКРИПТ" in captured.out or "Script" in captured.out


# ── Tests for known types ──────────────────────────────────────────

class TestKnownTypes:
    def test_known_type_has_name(self):
        assert DBPF_TYPES.get(0x025C5F1A) == "Tuning (XML)"
        assert DBPF_TYPES.get(0x042B5B94) == "Script (Python)"

    def test_unknown_type_returns_hex(self):
        from mod_analyzer import _type_name
        name = _type_name(0xDEADBEEF)
        assert "DEADBEEF" in name

    def test_known_types_dict_populated(self):
        assert 0x025C5F1A in DBPF_TYPES
        assert 0x316BB703 in DBPF_TYPES


# ── Edge cases ─────────────────────────────────────────────────────

class TestEdgeCases:
    def test_unicode_mod_path(self):
        mod = make_dbpf_v2([(0x025C5F1A, 0, 0x1, 0, 8)])
        name = "мод_тест.package"
        with TempMods({name: mod}) as tmp:
            r = analyze(str(tmp))
            assert r.total_packages == 1

    def test_handles_broken_package_gracefully(self):
        with TempMods({"broken.package": b"\x00" * 50}) as tmp:
            r = analyze(str(tmp))
            assert r.total_packages == 1
            assert r.total_entries == 0

    def test_analysis_result_has_expected_fields(self):
        with TempMods() as tmp:
            r = analyze(str(tmp))
            assert hasattr(r, "total_packages")
            assert hasattr(r, "conflicts")
            assert hasattr(r, "elapsed")
            assert hasattr(r, "mods_path")

    def test_conflict_has_string_key(self):
        mod = make_dbpf_v2([(0x025C5F1A, 0, 0x42, 0, 8)])
        with TempMods({"a.package": mod, "b.package": mod}) as tmp:
            r = analyze(str(tmp))
            assert len(r.conflicts) == 1
            key = next(iter(r.conflicts))
            assert isinstance(key, str)
            assert "0x" in key
