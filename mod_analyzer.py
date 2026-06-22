#!/usr/bin/env python3
"""
Sims 4 Mod Analyzer
Scans Mods folder for conflicts, lag sources, and resource clashes.
"""

import os
import struct
import sys
from pathlib import Path
from collections import defaultdict

# ── DBPF resource types ──────────────────────────────────────────────
KNOWN_TYPES = {
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

# Well-known instance IDs for EA tuning that mods commonly override
KNOWN_EA_TUNING = set()


def _type_name(tid: int) -> str:
    return KNOWN_TYPES.get(tid, f"0x{tid:08X}")


def read_package_index(path: Path) -> list[dict]:
    """Parse DBPF v2.0 package file and return resource index entries."""
    entries = []
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            if magic != b"DBPF":
                return entries

            ver = struct.unpack("<I", f.read(4))[0]
            _ = f.read(4)  # user version
            _ = f.read(4)  # unknown
            _ = f.read(8)  # timestamps
            index_major = struct.unpack("<I", f.read(4))[0]
            index_count = struct.unpack("<I", f.read(4))[0]
            index_offset = struct.unpack("<I", f.read(4))[0]
            index_size = struct.unpack("<I", f.read(4))[0]

            if index_count == 0 or index_offset == 0:
                return entries

            # Determine entry size
            if index_count > 0 and index_size > 0:
                entry_size = index_size // index_count
            else:
                entry_size = 24  # default for S4

            f.seek(index_offset)
            for _ in range(index_count):
                raw = f.read(entry_size)
                if len(raw) < entry_size:
                    break
                if entry_size == 24:
                    typ, grp, inst, off, sz = struct.unpack("<IIQII", raw)
                elif entry_size == 20:
                    typ, grp, inst_lo, inst_hi, off = struct.unpack("<IIIHH", raw)
                    inst = (inst_hi << 32) | inst_lo
                    sz = 0
                else:
                    continue

                entries.append({
                    "type": typ,
                    "group": grp,
                    "instance": inst,
                    "offset": off,
                    "size": sz,
                })
    except (OSError, struct.error):
        pass
    return entries


_MOD_CACHE: dict[str, list[dict]] = {}


def _scan_mods_folder(mods_path: Path) -> list[tuple[Path, list[dict]]]:
    """Walk the mods folder and parse all .package files."""
    results = []
    package_files = sorted(mods_path.rglob("*.package"))
    for fp in package_files:
        try:
            rel = fp.relative_to(mods_path)
        except ValueError:
            rel = fp
        key = str(fp.resolve())
        if key not in _MOD_CACHE:
            _MOD_CACHE[key] = read_package_index(fp)
        results.append((rel, _MOD_CACHE[key]))
    return results


def _find_script_mods(mods_path: Path) -> list[Path]:
    """Find .ts4script files (zip archives with Python bytecode)."""
    return sorted(mods_path.rglob("*.ts4script"))


def _find_large_files(
    mods_path: Path, threshold_mb: float = 20.0
) -> list[tuple[Path, int]]:
    """Find files larger than threshold (MB)."""
    big = []
    for ext in ("*.package", "*.ts4script"):
        for fp in mods_path.rglob(ext):
            sz = fp.stat().st_size
            if sz > threshold_mb * 1024 * 1024:
                try:
                    rel = fp.relative_to(mods_path)
                except ValueError:
                    rel = fp
                big.append((rel, sz))
    return sorted(big, key=lambda x: -x[1])


def _check_duplicate_mods(mods_path: Path) -> list[Path]:
    """Find .package files with identical names (potential copies)."""
    seen: dict[str, list[Path]] = defaultdict(list)
    for fp in mods_path.rglob("*.package"):
        name = fp.name.lower()
        seen[name].append(fp)
    dupes = []
    for name, files in seen.items():
        if len(files) > 1:
            dupes.extend(files[1:])
    return dupes


def analyze(mods_path_str: str) -> dict:
    """Run full analysis and return structured results."""
    mods_path = Path(mods_path_str).expanduser().resolve()

    if not mods_path.is_dir():
        return {"error": f"Папка не найдена: {mods_path}"}

    # 1. Scan package files
    mods = _scan_mods_folder(mods_path)
    script_mods = _find_script_mods(mods_path)
    large_files = _find_large_files(mods_path)
    duplicate_files = _check_duplicate_mods(mods_path)

    # 2. Find resource conflicts: same (type, group, instance) across different files
    resource_map: dict[tuple[int, int, int], list[tuple[Path, int]]] = defaultdict(list)
    for rel, entries in mods:
        for idx, e in enumerate(entries):
            key = (e["type"], e["group"], e["instance"])
            resource_map[key].append((rel, idx))

    conflicts = {k: v for k, v in resource_map.items() if len(v) > 1}

    # 3. Count resources per mod
    mod_resource_counts = {str(rel): len(entries) for rel, entries in mods}

    # 4. Stats
    total_packages = len(mods)
    total_scripts = len(script_mods)
    total_conflicts = len(conflicts)
    total_entries = sum(len(e) for _, e in mods)

    return {
        "mods_path": str(mods_path),
        "total_packages": total_packages,
        "total_scripts": total_scripts,
        "total_entries": total_entries,
        "total_conflicts": total_conflicts,
        "conflicts": conflicts,
        "mod_resource_counts": mod_resource_counts,
        "large_files": large_files,
        "script_mods": script_mods,
        "duplicate_files": duplicate_files,
    }


def print_report(result: dict):
    """Print a human-readable report."""
    if "error" in result:
        print(f"\n  [ОШИБКА] {result['error']}")
        return

    mods_path = result["mods_path"]

    print("=" * 64)
    print(f"  Sims 4 Mod Analyzer — Отчёт")
    print(f"  Папка: {mods_path}")
    print("=" * 64)

    # ── Overview ──
    print(f"\n  📦 Пакетов (.package):  {result['total_packages']}")
    print(f"  📜 Скрипт-модов (.ts4script): {result['total_scripts']}")
    print(f"  🧩 Всего ресурсов:     {result['total_entries']}")
    print(f"  ⚠️  Конфликтов:         {result['total_conflicts']}")

    # ── Conflicts ──
    if result["conflicts"]:
        print(f"\n  {'─' * 60}")
        print(f"  ⚠️  КОНФЛИКТЫ РЕСУРСОВ ({result['total_conflicts']})")
        print(f"  {'─' * 60}")

        # Group by resource type for readability
        by_type: dict[int, list] = defaultdict(list)
        for key, mods in result["conflicts"].items():
            by_type[key[0]].append((key, mods))

        for tid in sorted(by_type.keys()):
            items = by_type[tid]
            print(f"\n    [{_type_name(tid)}] — {len(items)} конфликт(ов)")
            for key, mods in items[:5]:  # show first 5 per type
                files_str = ", ".join(str(m[0]) for m in mods)
                print(f"      Instance 0x{key[2]:016X} → {files_str}")
            if len(items) > 5:
                print(f"      ... и ещё {len(items) - 5}")
    else:
        print(f"\n  ✅ Конфликтов ресурсов не найдено")

    # ── Large files ──
    if result["large_files"]:
        print(f"\n  {'─' * 60}")
        print(f"  🐘 БОЛЬШИЕ ФАЙЛЫ (могут вызывать лаги)")
        print(f"  {'─' * 60}")
        for rel, sz in result["large_files"][:10]:
            mb = sz / (1024 * 1024)
            print(f"    {mb:6.1f} MB  {rel}")
        if len(result["large_files"]) > 10:
            print(f"    ... и ещё {len(result['large_files']) - 10}")
    else:
        print(f"\n  ✅ Больших файлов не найдено")

    # ── Script mods ──
    if result["script_mods"]:
        print(f"\n  {'─' * 60}")
        print(f"  📜 СКРИПТ-МОДЫ (каждый добавляет нагрузку на запуск)")
        print(f"  {'─' * 60}")
        for sp in result["script_mods"][:15]:
            try:
                rel = sp.relative_to(Path(result["mods_path"]))
            except ValueError:
                rel = sp
            sz = sp.stat().st_size
            kb = sz / 1024
            print(f"    {kb:7.1f} KB  {rel}")
        if len(result["script_mods"]) > 15:
            print(f"    ... и ещё {len(result['script_mods']) - 15}")
        print(f"\n    💡 Совет: больше 10-15 скрипт-модов могут увеличивать")
        print(f"       время загрузки игры и вызывать микро-лаги.")
    else:
        print(f"\n  ✅ Скрипт-модов не найдено")

    # ── Duplicate file names ──
    if result["duplicate_files"]:
        print(f"\n  {'─' * 60}")
        print(f"  🔁 ДУБЛИКАТЫ ФАЙЛОВ (возможные копии)")
        print(f"  {'─' * 60}")
        for fp in result["duplicate_files"][:10]:
            try:
                rel = fp.relative_to(Path(result["mods_path"]))
            except ValueError:
                rel = fp
            print(f"    {rel}")
        if len(result["duplicate_files"]) > 10:
            print(f"    ... и ещё {len(result['duplicate_files']) - 10}")

    # ── Top resource-heavy mods ──
    if result["mod_resource_counts"]:
        print(f"\n  {'─' * 60}")
        print(f"  🏋️  ТОП-10 МОДОВ ПО КОЛИЧЕСТВУ РЕСУРСОВ")
        print(f"  {'─' * 60}")
        sorted_mods = sorted(
            result["mod_resource_counts"].items(),
            key=lambda x: -x[1],
        )[:10]
        for rel, count in sorted_mods:
            print(f"    {count:6d} ресурсов  {rel}")

    print(f"\n  {'=' * 64}")
    print(f"  Анализ завершён.")
    print(f"  {'=' * 64}\n")


def main():
    print()
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║       Sims 4 Mod Analyzer v1.0              ║")
    print("  ║  Поиск конфликтов и источников лагов        ║")
    print("  ╚══════════════════════════════════════════════╝")
    print()

    while True:
        raw = input("  📂 Укажите путь к папке Mods: ").strip()
        if not raw:
            print("  Выход.")
            return
        path = Path(raw).expanduser().resolve()

        if not path.is_dir():
            print(f"  ❌ Папка не найдена: {path}\n")
            continue

        print(f"  🔍 Сканирую: {path}\n")
        result = analyze(str(path))
        print_report(result)

        again = input("  Анализировать другую папку? (y/N): ").strip().lower()
        if again != "y":
            break

    print("  Готово!")


if __name__ == "__main__":
    main()
