#!/usr/bin/env python3
"""
Sims 4 Mod Analyzer
Scans Mods folder for conflicts, lag sources, mod health, and generates reports.
"""

import argparse
import hashlib
import json
import os
import struct
import sys
import time
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Constants ───────────────────────────────────────────────────────

VERSION = "v26.622.1238"

DBPF_TYPES = {
    0x025C5F1A: "Tuning (XML)",
    0x03536A8B: "String Table (STBL)",
    0x042B5B94: "Script (Python)",
    0x04540604: "String Table (STBL)",
    0x04A07B1E: "Snippet (XML)",
    0x06624BB8: "Object Definition",
    0x0A8C1FC8: "Model (MLOD)",
    0x0B1FB3E2: "Texture (DDS)",
    0x0B2C4F3A: "Sim Data",
    0x0C4C8C38: "Morph Mesh",
    0x0D1D6B7A: "Geometry",
    0x0E828C8A: "Preset",
    0x107F7C66: "Light",
    0x10F0A2B2: "Routing",
    0x11B73B83: "Material",
    0x13A2D3A1: "Effect",
    0x1B6B9FF6: "State Machine",
    0x1C31BDF3: "Footprint",
    0x1F552B44: "Audio",
    0x21B3B57A: "Animation Clip",
    0x21D8F65E: "Animation",
    0x22B3081C: "Rig",
    0x23B0E0F8: "UI",
    0x280696B3: "World",
    0x29A20349: "Scenario",
    0x2A7C4B69: "Stack-based Tuning",
    0x2B6D2B59: "Portal",
    0x2C6B5B06: "Terrain",
    0x2D1E46C1: "Particle",
    0x316BB703: "Tutorial",
    0x3269EEA9: "Posture",
    0x3313BDFB: "Lot",
    0x3362C911: "Handiness",
    0x337D63B0: "Interaction Tuning",
    0x33A1617F: "Pie Menu",
    0x34779B7F: "Social Context",
    0x3AF1D15B: "Buff",
    0x3BE04A6D: "Broadcast",
    0x3D3B5E9E: "Trait",
    0x3E99F5A0: "Motive",
    0x3F47CCF4: "Career",
    0x41BF7720: "Achievement",
    0x42A5F4B0: "Statistic",
    0x43BD7D04: "CAS Part",
    0x443C0060: "Sculpt",
    0x44CBB8BD: "Thumbnail",
    0x4608E3D6: "Whim",
    0x470DE4C0: "Phone",
    0x4A5C54F8: "Recipe",
    0x4B4C54F9: "Pledge",
    0x4C6F0E3C: "Venue",
    0x4D4C5A6A: "Walk Style",
    0x4E5B3B9C: "Object",
    0x503B3B9C: "Object Part",
    0x514C5A6B: "Lookbook",
    0x524C5A6C: "Trend",
    0x534C5A6D: "Event",
}

PYTHON_MAGIC = {
    3360: "3.6", 3393: "3.6", 3394: "3.6.5+",
    3420: "3.7", 3421: "3.7", 3422: "3.7.2+", 3423: "3.7.3+",
    3424: "3.7.4+", 3425: "3.7.5+",
    3430: "3.8", 3431: "3.8", 3432: "3.8.2+", 3433: "3.8.3+",
    3456: "3.9", 3457: "3.9",
    3470: "3.10", 3471: "3.10",
}

# Known problematic mod combinations (from BE / community knowledge)
PROBLEM_PAIRS: list[tuple[set[str], str]] = [
    ({"basemental", "wickedwhims"}, "Basemental + WickedWhims могут конфликтовать при одновременной загрузке"),
    ({"mc_command", "ui_cheats"}, "MC Command Center + UI Cheats могут вызывать конфликты кнопок"),
    ({"tmex", "betterbuildbuy"}, "Вы используете несколько модов TwistedMexi — проверьте совместимость версий"),
]


# ── Helpers ─────────────────────────────────────────────────────────

_RESET = "\033[0m"
_BOLD = "\033[1m"
_RED = "\033[91m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_CYAN = "\033[96m"


def _c(code: str, text: str, use_color: bool) -> str:
    return f"{code}{text}{_RESET}" if use_color else text


def _type_name(tid: int) -> str:
    return DBPF_TYPES.get(tid, f"0x{tid:08X}")


def _file_size_fmt(size: int) -> str:
    if size > 1024 ** 3:
        return f"{size / (1024**3):.2f} GB"
    if size > 1024 ** 2:
        return f"{size / (1024**2):.1f} MB"
    if size > 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size} B"


def _file_hash(path: Path) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(65536), b""):
                h.update(block)
        return h.hexdigest()[:16]
    except OSError:
        return ""


def _mod_creator(name: str) -> str:
    KNOWN = {
        "tmex", "twistedmexi", "mc_command", "mccommand", "deaderpool",
        "wickedwhims", "simrealist", "pandasama", "lumpinou",
        "littlemssam", "scumbumbo", "zerbu", "sacrificial",
        "basemental", "bienchen", "ravasheen", "adeepindigo", "kawaiistacie",
    }
    stem = Path(name).stem.lower().replace("_", "").replace("-", "").replace(" ", "")
    for c in KNOWN:
        if c in stem:
            return c
    return ""


# ── DBPF parser ─────────────────────────────────────────────────────

@dataclass
class ResourceEntry:
    type: int
    group: int
    instance: int
    offset: int
    size: int


@dataclass
class PackageInfo:
    path: Path
    rel: Path
    dbpf_version: int
    entries: list[ResourceEntry]
    size: int
    error: Optional[str] = None


def read_package(path: Path, rel: Path) -> PackageInfo:
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            if magic != b"DBPF":
                return PackageInfo(path, rel, 0, [], path.stat().st_size,
                                   error="Not a DBPF file")

            ver = struct.unpack("<I", f.read(4))[0]
            f.read(4); f.read(4); f.read(8)
            index_major = struct.unpack("<I", f.read(4))[0]
            index_count = struct.unpack("<I", f.read(4))[0]
            index_offset = struct.unpack("<I", f.read(4))[0]
            index_size = struct.unpack("<I", f.read(4))[0]

            if index_count == 0 or index_offset == 0:
                return PackageInfo(path, rel, ver, [], path.stat().st_size)

            entry_size = (index_size // index_count) if index_count > 0 and index_size > 0 else 24
            entries = []
            f.seek(index_offset)
            for _ in range(index_count):
                raw = f.read(entry_size)
                if len(raw) < entry_size:
                    break
                if entry_size == 24:
                    typ, grp, inst, off, sz = struct.unpack("<IIQII", raw)
                elif entry_size == 20:
                    typ, grp, inst_l, inst_h, off = struct.unpack("<IIIHH", raw)
                    inst = (inst_h << 32) | inst_l
                    sz = 0
                else:
                    continue
                entries.append(ResourceEntry(typ, grp, inst, off, sz))

            return PackageInfo(path, rel, ver, entries, path.stat().st_size)
    except (OSError, struct.error) as e:
        return PackageInfo(path, rel, 0, [], path.stat().st_size, error=str(e))


# ── Scanner ─────────────────────────────────────────────────────────

@dataclass
class WalkResult:
    packages: list[PackageInfo] = field(default_factory=list)
    scripts: list[Path] = field(default_factory=list)
    large_files: list[tuple[Path, int]] = field(default_factory=list)
    deep_scripts: list[tuple[Path, int]] = field(default_factory=list)
    deep_packages: list[tuple[Path, int]] = field(default_factory=list)
    deprecated: list[Path] = field(default_factory=list)
    temp_files: list[Path] = field(default_factory=list)
    total_files: int = 0


DEPRECATED_EXTS = (".zip", ".rar", ".7z", ".py")
TEMP_EXTS = (".temp", ".tmp", ".part", ".crdownload", ".downloading")
SYSTEM_FILES = (".ds_store", "thumbs.db", "desktop.ini")


def walk_mods(mods_path: Path, large_threshold: int = 20 * 1024 ** 2,
              max_depth: int = 5, progress=None) -> WalkResult:
    wr = WalkResult()
    for root, dirs, files in os.walk(mods_path):
        root_p = Path(root)
        try:
            rel_root = root_p.relative_to(mods_path)
        except ValueError:
            rel_root = root_p

        for fn in sorted(files):
            fn_lower = fn.lower()
            if fn_lower in SYSTEM_FILES or fn.startswith("."):
                continue

            wr.total_files += 1
            rel = rel_root / fn
            depth = len(rel.parents) - 1

            if fn_lower.endswith(".package"):
                pi = read_package(root_p / fn, rel)
                wr.packages.append(pi)
                if pi.size > large_threshold:
                    wr.large_files.append((rel, pi.size))
                if depth > max_depth:
                    wr.deep_packages.append((rel, depth))

            elif fn_lower.endswith(".ts4script"):
                wr.scripts.append(root_p / fn)
                sz = (root_p / fn).stat().st_size
                if sz > large_threshold:
                    wr.large_files.append((rel, sz))
                if depth > 1:
                    wr.deep_scripts.append((rel, depth))

            elif fn_lower.endswith(DEPRECATED_EXTS):
                wr.deprecated.append(rel)

            elif fn_lower.endswith(TEMP_EXTS):
                wr.temp_files.append(rel)

            if progress and wr.total_files % 500 == 0:
                progress(wr.total_files)

    wr.large_files.sort(key=lambda x: -x[1])
    return wr


# ── Analysis ────────────────────────────────────────────────────────

@dataclass
class AnalysisResult:
    mods_path: str
    total_files: int = 0
    total_packages: int = 0
    total_scripts: int = 0
    total_entries: int = 0
    total_conflicts: int = 0
    total_intentional: int = 0
    elapsed: float = 0.0
    dbpf_v1_packages: list[Path] = field(default_factory=list)
    packages_with_errors: list[PackageInfo] = field(default_factory=list)
    conflicts: dict = field(default_factory=dict)
    type_counts: dict[int, int] = field(default_factory=dict)
    mod_resource_counts: dict[str, int] = field(default_factory=dict)
    mod_resource_sizes: dict[str, int] = field(default_factory=dict)
    large_files: list = field(default_factory=list)
    script_mods: list[Path] = field(default_factory=list)
    duplicate_names: list[Path] = field(default_factory=list)
    duplicate_content: list[tuple] = field(default_factory=list)
    deep_scripts: list[tuple] = field(default_factory=list)
    deep_packages: list[tuple] = field(default_factory=list)
    corrupt_archives: list[Path] = field(default_factory=list)
    wrong_python: list[tuple] = field(default_factory=list)
    onedrive: bool = False
    deprecated_files: list[Path] = field(default_factory=list)
    temp_files: list[Path] = field(default_factory=list)
    problem_pairs: list[tuple] = field(default_factory=list)


def _find_dup_names(packages: list[PackageInfo]) -> list[Path]:
    seen: dict[str, list[Path]] = defaultdict(list)
    for pi in packages:
        seen[pi.rel.name.lower()].append(pi.rel)
    dupes = []
    for name, files in seen.items():
        if len(files) > 1:
            dupes.extend(files[1:])
    return dupes


def _find_dup_content(packages: list[PackageInfo], scripts: list[Path]) -> list[tuple]:
    size_map: dict[int, list[Path]] = defaultdict(list)
    for pi in packages:
        size_map[pi.size].append(pi.path)
    for sp in scripts:
        sz = sp.stat().st_size
        size_map[sz].append(sp)

    hashes: dict[str, Path] = {}
    pairs = []
    for sz, paths in size_map.items():
        if len(paths) < 2:
            continue
        for p in paths:
            h = _file_hash(p)
            if h:
                if h in hashes:
                    pairs.append((hashes[h], p))
                else:
                    hashes[h] = p
    return pairs


def _check_corrupt(scripts: list[Path]) -> list[Path]:
    bad = []
    for fp in scripts:
        try:
            with zipfile.ZipFile(fp) as z:
                if z.testzip():
                    bad.append(fp)
        except (zipfile.BadZipFile, OSError):
            bad.append(fp)
    return bad


def _check_python_version(scripts: list[Path]) -> list[tuple]:
    flagged = []
    for fp in scripts:
        try:
            with zipfile.ZipFile(fp) as z:
                for name in z.namelist():
                    if name.endswith(".pyc"):
                        data = z.read(name)
                        if len(data) >= 4:
                            magic = struct.unpack("<H", data[:2])[0]
                            if magic in PYTHON_MAGIC:
                                pyver = PYTHON_MAGIC[magic]
                                if pyver != "3.7":
                                    flagged.append((Path(name), f"Python {pyver}"))
                                    break
        except (zipfile.BadZipFile, OSError, struct.error):
            pass
    return flagged


def _check_problem_pairs(script_names: list[str]) -> list[tuple]:
    found_sets = set()
    for sn in script_names:
        stem = Path(sn).stem.lower()
        for known, _ in PROBLEM_PAIRS:
            for k in known:
                if k in stem.replace("_", "").replace("-", ""):
                    found_sets.add(k)

    results = []
    for pair, desc in PROBLEM_PAIRS:
        if pair.issubset(found_sets):
            results.append((pair, desc))
    return results


def analyze(mods_path_str: str, large_mb: float = 20, max_depth: int = 5,
            progress=None) -> AnalysisResult:
    start = time.time()
    mods_path = Path(mods_path_str).expanduser().resolve()

    if not mods_path.is_dir():
        return AnalysisResult(mods_path=mods_path_str, elapsed=0)

    wr = walk_mods(mods_path, large_threshold=int(large_mb * 1024 ** 2),
                   max_depth=max_depth, progress=progress)

    packages = wr.packages
    scripts = wr.scripts

    # Conflict detection
    resource_map: dict[tuple[int, int, int], list[tuple[Path, str]]] = defaultdict(list)
    for pi in packages:
        creator = _mod_creator(str(pi.rel))
        for e in pi.entries:
            key = (e.type, e.group, e.instance)
            resource_map[key].append((pi.rel, creator))

    raw = {k: v for k, v in resource_map.items() if len(v) > 1}
    conflicts = {}
    for key, mods in raw.items():
        creators = {m[1] for m in mods if m[1]}
        intentional = len(creators) == 1 and "" not in creators
        conflicts[f"0x{key[0]:X}:{key[1]}:{key[2]:X}"] = {
            "type": key[0], "group": key[1], "instance": key[2],
            "mods": [str(m[0]) for m in mods],
            "intentional": intentional,
        }

    # Aggregations
    type_counts: dict[int, int] = defaultdict(int)
    mod_entries: dict[str, int] = defaultdict(int)
    mod_sizes: dict[str, int] = defaultdict(int)
    for pi in packages:
        key = str(pi.rel)
        mod_entries[key] = len(pi.entries)
        for e in pi.entries:
            type_counts[e.type] += 1
            mod_sizes[key] += e.size

    # Dupes
    dup_names = _find_dup_names(packages)
    dup_content = _find_dup_content(packages, scripts)
    corrupt = _check_corrupt(scripts)
    wrong_py = _check_python_version(scripts)

    # Problem pairs
    script_names = [str(s.relative_to(mods_path) if s.is_relative_to(mods_path) else s)
                    for s in scripts]
    problem_pairs = _check_problem_pairs(script_names)

    # DBPF v1
    dbpf_v1 = [pi.rel for pi in packages if pi.dbpf_version == 1]

    # Packages with errors
    pkg_errors = [pi for pi in packages if pi.error]

    elapsed = time.time() - start

    return AnalysisResult(
        mods_path=str(mods_path),
        total_files=wr.total_files,
        total_packages=len(packages),
        total_scripts=len(scripts),
        total_entries=sum(len(pi.entries) for pi in packages),
        total_conflicts=len(conflicts),
        total_intentional=sum(1 for c in conflicts.values() if c["intentional"]),
        elapsed=elapsed,
        dbpf_v1_packages=dbpf_v1,
        packages_with_errors=pkg_errors,
        conflicts=conflicts,
        type_counts=dict(type_counts),
        mod_resource_counts=dict(mod_entries),
        mod_resource_sizes=dict(mod_sizes),
        large_files=wr.large_files,
        script_mods=scripts,
        duplicate_names=dup_names,
        duplicate_content=dup_content,
        deep_scripts=wr.deep_scripts,
        deep_packages=wr.deep_packages,
        corrupt_archives=corrupt,
        wrong_python=wrong_py,
        onedrive="onedrive" in str(mods_path).lower(),
        deprecated_files=wr.deprecated,
        temp_files=wr.temp_files,
        problem_pairs=problem_pairs,
    )


# ── Text report ─────────────────────────────────────────────────────

def print_report(r: AnalysisResult, color: bool = False):
    if not r.mods_path or not Path(r.mods_path).exists():
        print(_c(_RED, f"\n  [ОШИБКА] Папка не найдена: {r.mods_path}", color))
        return

    total_mods = r.total_packages + r.total_scripts
    sep = _c(_CYAN, "━" * 60, color)

    print(f"\n  {_c(_BOLD, 'Sims 4 Mod Analyzer', color)}")
    print(f"  Папка: {r.mods_path}")
    print(f"  Время: {r.elapsed:.1f}s")
    print(sep)

    print(f"\n  {_c(_BOLD, '📊 ОБЗОР', color)}")
    print(f"  Файлов всего:    {r.total_files}")
    print(f"  📦 Пакетов:       {r.total_packages}")
    print(f"  📜 Скрипт-модов:  {r.total_scripts}")
    print(f"  🧩 Ресурсов:      {r.total_entries:,}")
    print(f"  ⚠️  Конфликтов:   {r.total_conflicts}"
          + (f"  (intentional: {r.total_intentional})" if r.total_intentional else ""))

    # Health
    health: list[tuple[str, str, str]] = []
    if r.onedrive:
        health.append(("danger", "OneDrive", "OneDrive может восстанавливать удалённые моды"))
    if r.deep_scripts:
        health.append(("danger", "Скрипты глубоко", f"{len(r.deep_scripts)} скриптов не загрузятся"))
    if r.deep_packages:
        health.append(("warning", "Пакеты глубоко", f"{len(r.deep_packages)} пакетов >5 папок"))
    if r.corrupt_archives:
        health.append(("danger", "Повреждённые", f"{len(r.corrupt_archives)} .ts4script"))
    if r.wrong_python:
        health.append(("warning", "Python версия", f"{len(r.wrong_python)} скриптов не для 3.7"))
    if r.deprecated_files:
        health.append(("warning", "Не те типы", f"{len(r.deprecated_files)} .zip/.rar/.py"))
    if r.temp_files:
        health.append(("warning", "Временные", f"{len(r.temp_files)} .temp/.part"))
    if r.duplicate_content:
        health.append(("warning", "Дубликаты", f"{len(r.duplicate_content)} пар по содержимому"))
    if r.dbpf_v1_packages:
        health.append(("danger", "DBPF v1", f"{len(r.dbpf_v1_packages)} от Sims 2/3"))
    if r.packages_with_errors:
        health.append(("danger", "Ошибки", f"{len(r.packages_with_errors)} пакетов с ошибками"))

    if health:
        print(f"\n  {_c(_BOLD, '🔍 ЗДОРОВЬЕ МОДОВ', color)}")
        print(sep)
        for level, title, desc in health:
            badge = _c(_RED if level == "danger" else _YELLOW, f"● {title}", color)
            print(f"  {badge}  {desc}")

    # Conflicts
    if r.conflicts:
        print(f"\n  {_c(_BOLD, f'⚠️  КОНФЛИКТЫ РЕСУРСОВ ({r.total_conflicts})', color)}")
        print(sep)
        by_type: dict[int, list] = defaultdict(list)
        for c in r.conflicts.values():
            by_type[c["type"]].append(c)
        for tid in sorted(by_type.keys()):
            items = by_type[tid]
            print(f"\n    [{_type_name(tid)}] — {len(items)} конфликт(ов)")
            for c in items[:5]:
                files_str = ", ".join(c["mods"])
                intent = _c(_GREEN, " (intentional)", color) if c.get("intentional") else ""
                print(f"      Instance 0x{c['instance']:016X} → {files_str}{intent}")
            if len(items) > 5:
                print(f"      ... и ещё {len(items) - 5}")
    else:
        print(f"\n  ✅ Конфликтов не найдено")

    # Problem pairs
    if r.problem_pairs:
        print(f"\n  {_c(_BOLD, '⚠️  ИЗВЕСТНЫЕ ПРОБЛЕМНЫЕ КОМБИНАЦИИ', color)}")
        print(sep)
        for pair, desc in r.problem_pairs:
            print(f"    {', '.join(pair)} → {desc}")

    # Large files
    if r.large_files:
        print(f"\n  {_c(_BOLD, '🐘 БОЛЬШИЕ ФАЙЛЫ', color)}")
        print(sep)
        for rel, sz in r.large_files[:10]:
            print(f"    {_file_size_fmt(sz):>10}  {rel}")
    else:
        print(f"\n  ✅ Больших файлов нет")

    # Scripts
    if r.script_mods:
        print(f"\n  {_c(_BOLD, f'📜 СКРИПТ-МОДЫ ({len(r.script_mods)})', color)}")
        print(sep)
        for sp in r.script_mods[:10]:
            try:
                rel = sp.relative_to(Path(r.mods_path))
            except ValueError:
                rel = sp
            print(f"    {_file_size_fmt(sp.stat().st_size):>10}  {rel}")
    else:
        print(f"\n  ✅ Скрипт-модов нет")

    # Deep scripts
    if r.deep_scripts:
        print(f"\n  {_c(_RED, '❌ СКРИПТЫ НЕ ЗАГРУЗЯТСЯ (>1 ПАПКА)', color)}")
        for rel, depth in r.deep_scripts:
            print(f"    [depth {depth}] {rel}")

    # Deep packages
    if r.deep_packages:
        print(f"\n  {_c(_YELLOW, '⚠️  ПАКЕТЫ ГЛУБОКО (>5 ПАПОК)', color)}")
        for rel, depth in r.deep_packages[:5]:
            print(f"    [depth {depth}] {rel}")

    # Dupes
    if r.duplicate_names:
        print(f"\n  🔁 ДУБЛИКАТЫ ИМЁН")
        for fp in r.duplicate_names[:5]:
            print(f"    {fp}")
    if r.duplicate_content:
        print(f"\n  🔁 ДУБЛИКАТЫ ПО СОДЕРЖИМОМУ")
        for a, b in r.duplicate_content[:3]:
            try:
                ra = a.relative_to(Path(r.mods_path))
            except ValueError:
                ra = a
            try:
                rb = b.relative_to(Path(r.mods_path))
            except ValueError:
                rb = b
            print(f"    {ra} == {rb}")

    # Wrong Python
    if r.wrong_python:
        print(f"\n  {_c(_YELLOW, '⚠️  НЕПРАВИЛЬНАЯ ВЕРСИЯ PYTHON', color)}")
        for rel, ver in r.wrong_python[:5]:
            print(f"    {ver}  {rel}")

    # Top mods by resources
    if r.mod_resource_counts:
        print(f"\n  {_c(_BOLD, '🏋️  ТОП-10 ПО РЕСУРСАМ', color)}")
        print(sep)
        for rel, count in sorted(r.mod_resource_counts.items(), key=lambda x: -x[1])[:10]:
            sz = r.mod_resource_sizes.get(rel, 0)
            print(f"    {count:6,d} ресурсов  {_file_size_fmt(sz):>10}  {rel}")

    # Resource type distribution
    if r.type_counts:
        print(f"\n  {_c(_BOLD, '📊 ТИПЫ РЕСУРСОВ', color)}")
        print(sep)
        for tid, count in sorted(r.type_counts.items(), key=lambda x: -x[1])[:10]:
            print(f"    {count:8,d}  {_type_name(tid)}")

    print(f"\n{sep}")
    print(f"  Анализ завершён.")
    print(f"{sep}\n")


# ── HTML report ─────────────────────────────────────────────────────

def _html_report(r: AnalysisResult) -> str:
    styles = """
    <style>
      *{box-sizing:border-box;margin:0;padding:0}
      body{font-family:Arial,sans-serif;color:#333;background:#f5f5f5;margin:20px}
      .header{background:linear-gradient(135deg,#4a4a6a,#6a4a8a);color:#fff;padding:25px 30px;border-radius:10px 10px 0 0}
      .header h1{margin:0;font-size:26px}
      .header .meta{font-size:13px;opacity:.8;margin-top:5px}
      .section{margin:18px 0;background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
      .section h2{padding:14px 20px;margin:0;background:#e8e8f0;border-radius:8px 8px 0 0;font-size:17px;cursor:default}
      .section .content{padding:12px 20px 16px}
      table{width:100%;border-collapse:collapse}
      th,td{padding:7px 12px;text-align:left;border-bottom:1px solid #eee;font-size:13px}
      th{background:#f4f4f8;font-weight:600}
      .badge{display:inline-block;padding:2px 10px;border-radius:12px;font-size:11px;font-weight:600}
      .danger{background:#ffe0e0;color:#c00}
      .warning{background:#fff3d6;color:#a60}
      .success{background:#dff0df;color:#060}
      .info{background:#d6ecff;color:#069}
      .collapsible{background:#f8f8fa;cursor:pointer;padding:10px 18px;width:100%;border:none;text-align:left;font-size:14px;font-weight:600;border-bottom:1px solid #e8e8f0;outline:none}
      .collapsible:hover{background:#eeeef5}
      .collapsible:after{content:"\\25BC";float:right;font-size:11px;color:#888}
      .active:after{content:"\\25B2"}
      .coll-content{padding:0;display:none;overflow:hidden}
      .coll-content table{margin:0}
      .intentional{color:#080;font-style:italic;font-size:12px}
      .footer{text-align:center;font-size:11px;color:#aaa;padding:20px}
      .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px}
      .stat-card{background:#fafafe;border:1px solid #e8e8f0;border-radius:6px;padding:14px;text-align:center}
      .stat-card .num{font-size:28px;font-weight:700;color:#4a4a6a}
      .stat-card .label{font-size:12px;color:#888;margin-top:4px}
    </style>
    <script>
      document.addEventListener('click',function(e){
        if(e.target.classList.contains('collapsible')){
          e.target.classList.toggle('active');
          var c=e.target.nextElementSibling;
          c.style.display=c.style.display==='block'?'none':'block';
        }
      });
    </script>
    """

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    h = f"""<!DOCTYPE html>
<html lang="ru">
<head><meta charset="utf-8"><title>Sims 4 Mod Analysis — {r.mods_path}</title>{styles}</head>
<body>
<div class="header">
  <h1>Sims 4 Mod Analysis</h1>
  <div class="meta">{r.mods_path} &nbsp;|&nbsp; {ts} &nbsp;|&nbsp; {r.elapsed:.1f}s</div>
</div>
<div class="section">
  <h2>Overview</h2>
  <div class="content">
    <div class="grid">
      <div class="stat-card"><div class="num">{r.total_packages + r.total_scripts}</div><div class="label">Mod Files</div></div>
      <div class="stat-card"><div class="num">{r.total_packages}</div><div class="label">.package</div></div>
      <div class="stat-card"><div class="num">{r.total_scripts}</div><div class="label">.ts4script</div></div>
      <div class="stat-card"><div class="num">{r.total_entries:,}</div><div class="label">Resources</div></div>
      <div class="stat-card"><div class="num">{r.total_conflicts}</div><div class="label">Conflicts</div></div>
      <div class="stat-card"><div class="num">{len(r.large_files)}</div><div class="label">Large Files</div></div>
    </div>
  </div>
</div>"""

    # Health
    health = []
    for title, level, desc in [
        ("OneDrive", "danger" if r.onedrive else None, "Папка в OneDrive"),
        ("Scripts Too Deep", "danger" if r.deep_scripts else None, ""),
        ("Packages Too Deep", "warning" if r.deep_packages else None, ""),
        ("Corrupt Scripts", "danger" if r.corrupt_archives else None, ""),
        ("Wrong Python", "warning" if r.wrong_python else None, ""),
        ("Deprecated Extensions", "warning" if r.deprecated_files else None, ""),
        ("Temp Files", "warning" if r.temp_files else None, ""),
        ("DBPF v1", "danger" if r.dbpf_v1_packages else None, ""),
        ("Package Errors", "danger" if r.packages_with_errors else None, ""),
        ("Duplicate Content", "warning" if r.duplicate_content else None, ""),
    ]:
        if level:
            n = {"Scripts Too Deep": len(r.deep_scripts),
                 "Packages Too Deep": len(r.deep_packages),
                 "Corrupt Scripts": len(r.corrupt_archives),
                 "Wrong Python": len(r.wrong_python),
                 "Deprecated Extensions": len(r.deprecated_files),
                 "Temp Files": len(r.temp_files),
                 "DBPF v1": len(r.dbpf_v1_packages),
                 "Package Errors": len(r.packages_with_errors),
                 "Duplicate Content": len(r.duplicate_content),
                 "OneDrive": 1}.get(title, 0)
            health.append(f'<span class="badge {level}">{title}: {n}</span>')

    if health:
        h += f'<div class="section"><h2>Mod Health</h2><div class="content">{" ".join(health)}</div></div>'

    # Conflicts
    if r.conflicts:
        h += f'<div class="section"><h2>Resource Conflicts ({r.total_conflicts})</h2>'
        by_type: dict[int, list] = defaultdict(list)
        for c in r.conflicts.values():
            by_type[c["type"]].append(c)
        for tid in sorted(by_type.keys()):
            items = by_type[tid]
            h += f'<button class="collapsible">[{_type_name(tid)}] — {len(items)} conflict(s)</button>'
            h += '<div class="coll-content"><table><tr><th>Instance</th><th>Files</th></tr>'
            for c in items[:20]:
                label = ' <span class="intentional">(intentional)</span>' if c.get("intentional") else ""
                h += f"<tr><td>0x{c['instance']:016X}</td><td>{', '.join(c['mods'])}{label}</td></tr>"
            if len(items) > 20:
                h += f"<tr><td colspan='2'>... and {len(items) - 20} more</td></tr>"
            h += "</table></div>"
        h += "</div>"

    # Problem pairs
    if r.problem_pairs:
        h += '<div class="section"><h2>Problematic Mod Combinations</h2><div class="content">'
        for pair, desc in r.problem_pairs:
            h += f"<p><span class='badge danger'>{', '.join(pair)}</span> {desc}</p>"
        h += "</div></div>"

    # Error packages
    if r.packages_with_errors:
        h += '<div class="section"><h2>Package Errors</h2><div class="content"><table><tr><th>File</th><th>Error</th></tr>'
        for pi in r.packages_with_errors:
            h += f"<tr><td>{pi.rel}</td><td>{pi.error}</td></tr>"
        h += "</table></div></div>"

    # Large files
    if r.large_files:
        h += '<div class="section"><h2>Large Files</h2><div class="content"><table><tr><th>Size</th><th>File</th></tr>'
        for rel, sz in r.large_files[:20]:
            h += f"<tr><td>{_file_size_fmt(sz)}</td><td>{rel}</td></tr>"
        h += "</table></div></div>"

    # Scripts
    if r.script_mods:
        h += f'<div class="section"><h2>Script Mods ({len(r.script_mods)})</h2><div class="content"><table><tr><th>Size</th><th>File</th></tr>'
        for sp in sorted(r.script_mods, key=lambda x: -x.stat().st_size)[:20]:
            try:
                rel = sp.relative_to(Path(r.mods_path))
            except ValueError:
                rel = sp
            h += f"<tr><td>{_file_size_fmt(sp.stat().st_size)}</td><td>{rel}</td></tr>"
        h += "</table></div></div>"

    # Deep scripts
    if r.deep_scripts:
        h += '<div class="section"><h2>Scripts Too Deep (WILL NOT LOAD)</h2><div class="content">'
        for rel, depth in r.deep_scripts:
            h += f"<p>⚠️ depth {depth}: {rel}</p>"
        h += "</div></div>"

    # Wrong Python
    if r.wrong_python:
        h += '<div class="section"><h2>Wrong Python Version</h2><div class="content"><table><tr><th>Version</th><th>File</th></tr>'
        for rel, ver in r.wrong_python:
            h += f"<tr><td>{ver}</td><td>{rel}</td></tr>"
        h += "</table></div></div>"

    # Resource types
    if r.type_counts:
        h += '<div class="section"><h2>Resource Distribution</h2><div class="content"><table><tr><th>Type</th><th>Count</th><th>Total Size</th></tr>'
        for tid, count in sorted(r.type_counts.items(), key=lambda x: -x[1])[:15]:
            h += f"<tr><td>{_type_name(tid)}</td><td>{count:,}</td><td></td></tr>"
        h += "</table></div></div>"

    # Top mods
    if r.mod_resource_counts:
        h += '<div class="section"><h2>Top Mods by Resources</h2><div class="content"><table><tr><th>Resources</th><th>Resource Size</th><th>File</th></tr>'
        for rel, count in sorted(r.mod_resource_counts.items(), key=lambda x: -x[1])[:10]:
            sz = r.mod_resource_sizes.get(rel, 0)
            h += f"<tr><td>{count:,}</td><td>{_file_size_fmt(sz)}</td><td>{rel}</td></tr>"
        h += "</table></div></div>"

    h += f"""
<div class="footer">
  Generated by <b>Sims 4 Mod Analyzer {VERSION}</b>
</div>
</body></html>"""
    return h


# ── CLI ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="sim4debug",
        description="Sims 4 Mod Analyzer — scan mods for conflicts, lag sources, and health issues",
    )
    parser.add_argument("path", nargs="?", help="Path to Mods folder")
    parser.add_argument("--html", action="store_true", help="Generate HTML report")
    parser.add_argument("--json", action="store_true", help="Output JSON report")
    parser.add_argument("--color", action="store_true", default=None,
                        help="Force colored terminal output")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    parser.add_argument("--large", type=float, default=20, metavar="MB",
                        help="Large file threshold in MB (default: 20)")
    parser.add_argument("--max-depth", type=int, default=5, metavar="N",
                        help="Max package folder depth (default: 5)")
    parser.add_argument("--version", action="version", version=f"Sims 4 Mod Analyzer {VERSION}")
    parser.add_argument("--output", "-o", type=str, metavar="FILE", help="Save report to file")

    args = parser.parse_args()

    color = args.color if args.color is not None else (not args.no_color)
    if args.no_color:
        color = False

    paths: list[str] = []
    if args.path:
        paths.append(args.path)
    else:
        print(f"\n  {_c(_BOLD, f'Sims 4 Mod Analyzer {VERSION}', color)}")
        raw = input("  📂 Path to Mods folder: ").strip()
        if raw:
            paths.append(raw)
        else:
            return

    for p in paths:
        path = Path(p).expanduser().resolve()
        if not path.is_dir():
            print(_c(_RED, f"\n  ❌ Folder not found: {path}", color))
            continue

        if not args.json:
            print(f"\n  Scanning: {path}")

        _progress = None
        if not args.json:
            def _progress(n: int):
                print(f"\r  🔍 Scanning... {n} files", end="", flush=True)

        result = analyze(str(path), large_mb=args.large, max_depth=args.max_depth,
                         progress=_progress)
        if not args.json:
            print()

        if args.json:
            json_output = json.dumps(asdict(result), indent=2, default=str, ensure_ascii=False)
            if args.output:
                Path(args.output).write_text(json_output, encoding="utf-8")
                print(f"  📄 JSON saved: {args.output}")
            else:
                print(json_output)
        else:
            print_report(result, color)

            # Auto-save report
            report_path = args.output if args.output else "sims4_mod_report.txt"
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(f"Sims 4 Mod Analyzer {VERSION}\n")
                f.write(f"Path: {result.mods_path}\n")
                f.write(f"Time: {result.elapsed:.1f}s\n")
                f.write(f"Packages: {result.total_packages}, Scripts: {result.total_scripts}, "
                        f"Conflicts: {result.total_conflicts}\n")
            print(f"  📄 Report: {Path(report_path).resolve()}")

            if args.html:
                html = _html_report(result)
                html_path = (args.output + ".html") if args.output else "sims4_mod_report.html"
                Path(html_path).write_text(html, encoding="utf-8")
                print(f"  📄 HTML:   {Path(html_path).resolve()}")

            print()
            input("  Нажмите Enter для выхода...")
        print()


if __name__ == "__main__":
    main()
