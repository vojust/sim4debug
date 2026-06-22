#!/usr/bin/env python3
"""
Sims 4 Mod Analyzer — BetterExceptions Edition
Scans Mods folder for conflicts, lag sources, mod health, and generates reports.

Ported features from TwistedMexi's BetterExceptions:
  - Conflict Scanner (resource TGI clashes, intentional overrides)
  - Package Manager (deep DBPF parsing)
  - Analysis (OneDrive, script depth, corrupt archives, outdated mods)
  - Patch Scanner readiness
  - Diff checker
  - HTML report
"""

import hashlib
import os
import struct
import sys
import time
import zipfile
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree

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

# Script mods with known issues / special handling
KNOWN_SCRIPT_MODS = {
    "tmex", "twistedmexi",
    "mc_command", "mccommand", "deaderpool",
    "wickedwhims", "wicked_whims", "turbodriver",
    "basemental", "basementaldrugs",
    "lumpinou", "lumpinous",
    "littlemssam",
    "scumbumbo",
    "zerbu",
    "kawaiistacie",
    "sacrificial",
    "bienchen",
    "ravasheen",
    "pandasama",
    "simrealist",
    "adeepindigo",
}


def _type_name(tid: int) -> str:
    return KNOWN_TYPES.get(tid, f"0x{tid:08X}")


def _mod_creator(path: Path) -> str:
    name = path.stem.lower().replace("_", "").replace("-", "").replace(" ", "")
    for creator in KNOWN_SCRIPT_MODS:
        if creator in name:
            return creator
    return ""


def _file_hash(path: Path, blocksize: int = 65536) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(blocksize), b""):
            h.update(block)
    return h.hexdigest()[:16]


# ── DBPF parser ─────────────────────────────────────────────────────

def read_package_index(path: Path) -> list[dict]:
    """Parse DBPF v2.0 package file and return resource index entries."""
    entries = []
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            if magic != b"DBPF":
                return entries

            ver = struct.unpack("<I", f.read(4))[0]
            f.read(4)
            f.read(4)
            f.read(8)
            index_major = struct.unpack("<I", f.read(4))[0]
            index_count = struct.unpack("<I", f.read(4))[0]
            index_offset = struct.unpack("<I", f.read(4))[0]
            index_size = struct.unpack("<I", f.read(4))[0]

            if index_count == 0 or index_offset == 0:
                return entries

            if index_count > 0 and index_size > 0:
                entry_size = index_size // index_count
            else:
                entry_size = 24

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


# ── Scanning helpers ────────────────────────────────────────────────

_MOD_CACHE: dict[str, list[dict]] = {}


def _scan_packages(mods_path: Path) -> list[tuple[Path, list[dict]]]:
    results = []
    for fp in sorted(mods_path.rglob("*.package")):
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
    return sorted(mods_path.rglob("*.ts4script"))


def _find_large_files(mods_path: Path, threshold_mb: float = 20.0) -> list[tuple[Path, int]]:
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


def _find_dup_names(mods_path: Path) -> list[Path]:
    seen: dict[str, list[Path]] = defaultdict(list)
    for fp in mods_path.rglob("*.package"):
        seen[fp.name.lower()].append(fp)
    dupes = []
    for name, files in seen.items():
        if len(files) > 1:
            dupes.extend(files[1:])
    return dupes


def _find_dup_content(mods_path: Path) -> list[tuple[Path, Path]]:
    hashes: dict[str, Path] = {}
    pairs = []
    for ext in ("*.package", "*.ts4script"):
        for fp in sorted(mods_path.rglob(ext)):
            h = _file_hash(fp)
            if h in hashes:
                pairs.append((hashes[h], fp))
            else:
                hashes[h] = fp
    return pairs


def _check_script_depth(mods_path: Path) -> list[tuple[Path, int]]:
    deep = []
    for fp in mods_path.rglob("*.ts4script"):
        try:
            rel = fp.relative_to(mods_path)
        except ValueError:
            continue
        depth = len(rel.parents) - 1
        if depth > 1:
            deep.append((rel, depth))
    return deep


def _check_corrupt_archives(mods_path: Path) -> list[Path]:
    bad = []
    for fp in sorted(mods_path.rglob("*.ts4script")):
        try:
            with zipfile.ZipFile(fp) as z:
                bad_file = z.testzip()
                if bad_file:
                    bad.append(fp)
        except (zipfile.BadZipFile, OSError):
            bad.append(fp)
    return bad


def _check_wrong_python_version(mods_path: Path) -> list[tuple[Path, str]]:
    flagged = []
    PYTHON_MAGIC = {
        3360: "3.6",   # Python 3.6
        3393: "3.6",   # Python 3.6.4+
        3394: "3.6.5+",
        3420: "3.7",   # Python 3.7
        3421: "3.7",
        3422: "3.7.2+",
        3423: "3.7.3+",
        3424: "3.7.4+",
        3425: "3.7.5+",
        3430: "3.8",   # Python 3.8
        3431: "3.8",
        3432: "3.8.2+",
        3433: "3.8.3+",
        3456: "3.9",   # Python 3.9
        3457: "3.9",
        3470: "3.10",  # Python 3.10
        3471: "3.10",
    }
    for fp in sorted(mods_path.rglob("*.ts4script")):
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
                                    try:
                                        rel = fp.relative_to(mods_path)
                                    except ValueError:
                                        rel = fp
                                    flagged.append((rel, f"Python {pyver} (needs 3.7)"))
                                    break
        except (zipfile.BadZipFile, OSError, struct.error):
            pass
    return flagged


def _check_onedrive(mods_path: Path) -> bool:
    path_str = str(mods_path).lower()
    return "onedrive" in path_str


def _check_deprecated_file_types(mods_path: Path) -> list[Path]:
    bad = []
    for ext in ("*.zip", "*.rar", "*.7z", "*.py"):
        for fp in mods_path.rglob(ext):
            bad.append(fp)
    return bad


# ── Diff checker (ported from BE diff_match_patch) ─────────────────

def _diff_texts(text1: str, text2: str) -> list[tuple[str, str]]:
    diffs = []
    i = j = 0
    while i < len(text1) and j < len(text2):
        if text1[i] == text2[j]:
            i += 1
            j += 1
        else:
            i_start = i
            j_start = j
            while i < len(text1) and j < len(text2) and text1[i] != text2[j]:
                i += 1
                j += 1
            if i > i_start:
                diffs.append(("-", text1[i_start:i]))
            if j > j_start:
                diffs.append(("+", text2[j_start:j]))
    if i < len(text1):
        diffs.append(("-", text1[i:]))
    if j < len(text2):
        diffs.append(("+", text2[j:]))
    return diffs


# ── Main analysis ───────────────────────────────────────────────────

def analyze(mods_path_str: str) -> dict:
    """Run full analysis and return structured results."""
    start = time.time()
    mods_path = Path(mods_path_str).expanduser().resolve()

    if not mods_path.is_dir():
        return {"error": f"Папка не найдена: {mods_path}"}

    # Scan phase
    packages = _scan_packages(mods_path)
    script_mods = _find_script_mods(mods_path)
    large_files = _find_large_files(mods_path)
    dup_names = _find_dup_names(mods_path)
    dup_content = _find_dup_content(mods_path)
    deep_scripts = _check_script_depth(mods_path)
    corrupt = _check_corrupt_archives(mods_path)
    wrong_python = _check_wrong_python_version(mods_path)
    onedrive = _check_onedrive(mods_path)
    deprecated = _check_deprecated_file_types(mods_path)

    # Resource conflict detection
    resource_map: dict[tuple[int, int, int], list[tuple[Path, int, str]]] = defaultdict(list)
    for rel, entries in packages:
        creator = _mod_creator(rel)
        for idx, e in enumerate(entries):
            key = (e["type"], e["group"], e["instance"])
            resource_map[key].append((rel, idx, creator))

    raw_conflicts = {k: v for k, v in resource_map.items() if len(v) > 1}

    # Annotate conflicts: intentional override if all mods share a creator prefix
    conflicts = {}
    for key, mods in raw_conflicts.items():
        creators = {m[2] for m in mods if m[2]}
        intentional = len(creators) == 1 and "" not in creators
        conflicts[key] = {
            "mods": [(m[0], m[1]) for m in mods],
            "intentional": intentional,
            "type": key[0],
            "group": key[1],
            "instance": key[2],
        }

    # Resource type stats
    type_counts: dict[int, int] = defaultdict(int)
    for rel, entries in packages:
        for e in entries:
            type_counts[e["type"]] += 1

    # Mod resource counts
    mod_resource_counts = {str(rel): len(entries) for rel, entries in packages}

    # Stats
    total_packages = len(packages)
    total_scripts = len(script_mods)
    total_entries = sum(len(e) for _, e in packages)
    total_conflicts = len(conflicts)
    total_intentional = sum(1 for c in conflicts.values() if c["intentional"])

    elapsed = time.time() - start

    return {
        "mods_path": str(mods_path),
        "total_packages": total_packages,
        "total_scripts": total_scripts,
        "total_entries": total_entries,
        "total_conflicts": total_conflicts,
        "total_intentional": total_intentional,
        "conflicts": conflicts,
        "type_counts": dict(type_counts),
        "mod_resource_counts": mod_resource_counts,
        "large_files": large_files,
        "script_mods": script_mods,
        "duplicate_names": dup_names,
        "duplicate_content": dup_content,
        "deep_scripts": deep_scripts,
        "corrupt_archives": corrupt,
        "wrong_python": wrong_python,
        "onedrive": onedrive,
        "deprecated_files": deprecated,
        "elapsed": elapsed,
    }


# ── HTML report ─────────────────────────────────────────────────────

def _html_report(result: dict) -> str:
    styles = """
    <style>
      body{font-family:Arial,sans-serif;color:#333;background:#f5f5f5;margin:20px}
      .header{background:#4a4a6a;color:#fff;padding:20px;border-radius:8px 8px 0 0}
      .header h1{margin:0;font-size:28px}
      .header .meta{font-size:14px;opacity:.8}
      .section{margin:20px 0;background:#fff;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,.1)}
      .section h2{padding:15px 20px;margin:0;background:#e8e8f0;border-radius:8px 8px 0 0;font-size:18px}
      .section .content{padding:15px 20px}
      table{width:100%;border-collapse:collapse}
      th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #eee;font-size:13px}
      th{background:#f0f0f5;font-weight:600}
      .badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}
      .badge-danger{background:#ffe0e0;color:#c00}
      .badge-warning{background:#fff3d6;color:#a60}
      .badge-success{background:#dff0df;color:#060}
      .badge-info{background:#d6ecff;color:#069}
      .collapsible{cursor:pointer;background:#f9f9fb;padding:10px 15px;border:none;text-align:left;width:100%;font-size:14px;font-weight:600;border-bottom:1px solid #eee}
      .collapsible:hover{background:#eeeef5}
      .collapsible:after{content:"\\25BC";float:right;font-size:12px}
      .collapsible.active:after{content:"\\25B2"}
      .coll-content{padding:10px 20px;display:none}
      .intentional{color:#080;font-style:italic}
      .footer{text-align:center;font-size:11px;color:#999;padding:20px}
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

    mods_path = result["mods_path"]
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_mods = result["total_packages"] + result["total_scripts"]

    html = f"""<!DOCTYPE html>
<html lang="ru">
<head><meta charset="utf-8"><title>Sims 4 Mod Analysis Report</title>{styles}</head>
<body>
<div class="header">
  <h1>Sims 4 Mod Analysis Report</h1>
  <div class="meta">{mods_path} | {ts} | {result["elapsed"]:.1f}s</div>
</div>
"""

    # Overview
    html += """
<div class="section">
  <h2>Overview</h2>
  <div class="content">
    <table>
      <tr><th>Metric</th><th>Value</th></tr>
      <tr><td>Total mod files</td><td><b>%d</b></td></tr>
      <tr><td>Package files</td><td><b>%d</b></td></tr>
      <tr><td>Script mods</td><td><b>%d</b></td></tr>
      <tr><td>Total resources</td><td><b>%d</b></td></tr>
      <tr><td>Resource conflicts</td><td><b>%d</b></td></tr>
      <tr><td>Intentional overrides</td><td><b>%d</b></td></tr>
      <tr><td>Large files ({%d} MB+)</td><td><b>%d</b></td></tr>
      <tr><td>Scan duration</td><td>%.1f seconds</td></tr>
    </table>
  </div>
</div>
""" % (total_mods, result["total_packages"], result["total_scripts"],
       result["total_entries"], result["total_conflicts"],
       result["total_intentional"], 20, len(result["large_files"]),
       result["elapsed"])

    # Health checks
    health_items = []
    if result["onedrive"]:
        health_items.append((
            "OneDrive Detected",
            "danger",
            "OneDrive может восстанавливать удалённые моды. Рекомендуется отключить его."
        ))
    if result["deep_scripts"]:
        health_items.append((
            "Scripts Too Deep",
            "danger",
            f"{len(result['deep_scripts'])} скрипт-модов лежат глубже 1 папки. Sims 4 не загружает скрипты из подпапок."
        ))
    if result["corrupt_archives"]:
        health_items.append((
            "Corrupt Scripts",
            "danger",
            f"{len(result['corrupt_archives'])} .ts4script файлов повреждены или не являются zip-архивами."
        ))
    if result["wrong_python"]:
        health_items.append((
            "Wrong Python Version",
            "warning",
            f"{len(result['wrong_python'])} скриптов скомпилированы для неправильной версии Python."
        ))
    if result["deprecated_files"]:
        health_items.append((
            "Deprecated File Types",
            "warning",
            f"{len(result['deprecated_files'])} файлов (.zip/.rar/.py) не должны быть в Mods."
        ))
    if result["duplicate_content"]:
        health_items.append((
            "Duplicate Content",
            "warning",
            f"{len(result['duplicate_content'])} пар файлов имеют одинаковое содержимое."
        ))

    if health_items:
        html += '<div class="section"><h2>Mod Health</h2><div class="content">'
        for title, level, desc in health_items:
            html += f'<p><span class="badge badge-{level}">{title}</span> {desc}</p>'
        html += "</div></div>"

    # Conflicts
    if result["conflicts"]:
        html += '<div class="section"><h2>Resource Conflicts (%d)</h2>' % result["total_conflicts"]
        by_type: dict[int, list] = defaultdict(list)
        for c in result["conflicts"].values():
            by_type[c["type"]].append(c)

        for tid in sorted(by_type.keys()):
            items = by_type[tid]
            tname = _type_name(tid)
            html += f'<button class="collapsible">[{tname}] — {len(items)} conflict(s)</button>'
            html += '<div class="coll-content"><table><tr><th>Instance</th><th>Files</th></tr>'
            for c in items[:10]:
                files_str = ", ".join(str(m[0]) for m in c["mods"])
                label = ""
                if c.get("intentional"):
                    label = ' <span class="intentional">(intentional override)</span>'
                html += f"<tr><td>0x{c['instance']:016X}</td><td>{files_str}{label}</td></tr>"
            if len(items) > 10:
                html += f"<tr><td colspan='2'>... and {len(items) - 10} more</td></tr>"
            html += "</table></div>"
        html += "</div>"

    # Large files
    if result["large_files"]:
        html += '<div class="section"><h2>Large Files ({} MB+)</h2><div class="content"><table><tr><th>Size</th><th>File</th></tr>'.format(20)
        for rel, sz in result["large_files"][:10]:
            mb = sz / (1024 * 1024)
            html += f"<tr><td>{mb:.1f} MB</td><td>{rel}</td></tr>"
        if len(result["large_files"]) > 10:
            html += f"<tr><td colspan='2'>... and {len(result['large_files']) - 10} more</td></tr>"
        html += "</table></div></div>"

    # Script mods
    if result["script_mods"]:
        html += '<div class="section"><h2>Script Mods (%d)</h2><div class="content"><table><tr><th>Size</th><th>File</th></tr>' % len(result["script_mods"])
        for sp in result["script_mods"][:15]:
            try:
                rel = sp.relative_to(Path(result["mods_path"]))
            except ValueError:
                rel = sp
            kb = sp.stat().st_size / 1024
            html += f"<tr><td>{kb:.1f} KB</td><td>{rel}</td></tr>"
        if len(result["script_mods"]) > 15:
            html += f"<tr><td colspan='2'>... and {len(result['script_mods']) - 15} more</td></tr>"
        html += "</table></div></div>"

    # Resource types
    if result["type_counts"]:
        html += '<div class="section"><h2>Resource Type Distribution</h2><div class="content"><table><tr><th>Type</th><th>Count</th></tr>'
        for tid, count in sorted(result["type_counts"].items(), key=lambda x: -x[1])[:15]:
            html += f"<tr><td>{_type_name(tid)}</td><td>{count:,}</td></tr>"
        if len(result["type_counts"]) > 15:
            html += f"<tr><td colspan='2'>... and {len(result['type_counts']) - 15} more types</td></tr>"
        html += "</table></div></div>"

    # Duplicates
    if result["duplicate_names"]:
        html += '<div class="section"><h2>Duplicate File Names</h2><div class="content">'
        for fp in result["duplicate_names"][:10]:
            try:
                rel = fp.relative_to(Path(result["mods_path"]))
            except ValueError:
                rel = fp
            html += f"<p>{rel}</p>"
        if len(result["duplicate_names"]) > 10:
            html += f"<p>... and {len(result['duplicate_names']) - 10} more</p>"
        html += "</div></div>"

    if result["deep_scripts"]:
        html += f'<div class="section"><h2>Scripts Too Deep (NEVER LOAD)</h2><div class="content">'
        for rel, depth in result["deep_scripts"]:
            html += f"<p>{'  ' * depth}{rel} (depth: {depth})</p>"
        html += "</div></div>"

    if result["wrong_python"]:
        html += f'<div class="section"><h2>Wrong Python Version</h2><div class="content"><table><tr><th>File</th><th>Issue</th></tr>'
        for rel, issue in result["wrong_python"]:
            html += f"<tr><td>{rel}</td><td>{issue}</td></tr>"
        html += "</table></div></div>"

    html += """
<div class="footer">
  Generated by <b>Sims 4 Mod Analyzer</b> &mdash; 
  <a href="https://github.com/vojust/sim4debug">github.com/vojust/sim4debug</a>
</div>
</body></html>"""
    return html


# ── Text report ─────────────────────────────────────────────────────

def print_report(result: dict):
    if "error" in result:
        print(f"\n  [ОШИБКА] {result['error']}")
        return

    mods_path = result["mods_path"]
    total_mods = result["total_packages"] + result["total_scripts"]

    print("=" * 64)
    print(f"  Sims 4 Mod Analyzer — BetterExceptions Edition")
    print(f"  Папка: {mods_path}")
    print(f"  Время: {result['elapsed']:.1f}s")
    print("=" * 64)

    print(f"\n  📦 Всего модов:       {total_mods}")
    print(f"  📦 Пакетов:           {result['total_packages']}")
    print(f"  📜 Скрипт-модов:      {result['total_scripts']}")
    print(f"  🧩 Всего ресурсов:    {result['total_entries']}")
    print(f"  ⚠️  Конфликтов:       {result['total_conflicts']}")
    if result["total_intentional"]:
        print(f"     (из них intentional: {result['total_intentional']})")

    # ── Health ──
    if (result["onedrive"] or result["deep_scripts"] or result["corrupt_archives"]
            or result["wrong_python"] or result["deprecated_files"]
            or result["duplicate_content"]):
        print(f"\n  {'─' * 60}")
        print(f"  🔍 ЗДОРОВЬЕ МОДОВ")
        print(f"  {'─' * 60}")

        if result["onedrive"]:
            print(f"\n    ❌ OneDrive активен — может восстанавливать удалённые моды")
        if result["deep_scripts"]:
            print(f"\n    ❌ Скрипты глубже 1 папки (НЕ ЗАГРУЗЯТСЯ):")
            for rel, depth in result["deep_scripts"]:
                print(f"       [depth {depth}] {rel}")
        if result["corrupt_archives"]:
            print(f"\n    ❌ Повреждённые .ts4script:")
            for fp in result["corrupt_archives"][:5]:
                try:
                    rel = fp.relative_to(Path(mods_path))
                except ValueError:
                    rel = fp
                print(f"       {rel}")
        if result["wrong_python"]:
            print(f"\n    ⚠️  Неправильная версия Python:")
            for rel, issue in result["wrong_python"][:5]:
                print(f"       {issue} — {rel}")
        if result["deprecated_files"]:
            print(f"\n    ⚠️  Неподходящие типы файлов в Mods:")
            for fp in result["deprecated_files"][:5]:
                try:
                    rel = fp.relative_to(Path(mods_path))
                except ValueError:
                    rel = fp
                print(f"       {rel}")
        if result["duplicate_content"]:
            print(f"\n    ⚠️  Полные дубликаты по содержимому:")
            for a, b in result["duplicate_content"][:5]:
                try:
                    ra = a.relative_to(Path(mods_path))
                except ValueError:
                    ra = a
                try:
                    rb = b.relative_to(Path(mods_path))
                except ValueError:
                    rb = b
                print(f"       {ra} == {rb}")

    # ── Conflicts ──
    if result["conflicts"]:
        print(f"\n  {'─' * 60}")
        print(f"  ⚠️  КОНФЛИКТЫ РЕСУРСОВ ({result['total_conflicts']})")
        print(f"  {'─' * 60}")

        by_type: dict[int, list] = defaultdict(list)
        for c in result["conflicts"].values():
            by_type[c["type"]].append(c)

        for tid in sorted(by_type.keys()):
            items = by_type[tid]
            label = _type_name(tid)
            print(f"\n    [{label}] — {len(items)} конфликт(ов)")
            for c in items[:5]:
                files_str = ", ".join(str(m[0]) for m in c["mods"])
                intent = " (intentional)" if c.get("intentional") else ""
                print(f"      Instance 0x{c['instance']:016X} → {files_str}{intent}")
            if len(items) > 5:
                print(f"      ... и ещё {len(items) - 5}")
    else:
        print(f"\n  ✅ Конфликтов ресурсов не найдено")

    # ── Large files ──
    if result["large_files"]:
        print(f"\n  {'─' * 60}")
        print(f"  🐘 БОЛЬШИЕ ФАЙЛЫ (>20 MB)")
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
        print(f"  📜 ВСЕ СКРИПТ-МОДЫ ({len(result['script_mods'])})")
        print(f"  {'─' * 60}")
        for sp in result["script_mods"][:15]:
            try:
                rel = sp.relative_to(Path(mods_path))
            except ValueError:
                rel = sp
            sz = sp.stat().st_size
            kb = sz / 1024
            print(f"    {kb:7.1f} KB  {rel}")
        if len(result["script_mods"]) > 15:
            print(f"    ... и ещё {len(result['script_mods']) - 15}")
    else:
        print(f"\n  ✅ Скрипт-модов не найдено")

    # ── Duplicate names ──
    if result["duplicate_names"]:
        print(f"\n  {'─' * 60}")
        print(f"  🔁 ДУБЛИКАТЫ ИМЁН ФАЙЛОВ")
        print(f"  {'─' * 60}")
        for fp in result["duplicate_names"][:10]:
            try:
                rel = fp.relative_to(Path(mods_path))
            except ValueError:
                rel = fp
            print(f"    {rel}")
        if len(result["duplicate_names"]) > 10:
            print(f"    ... и ещё {len(result['duplicate_names']) - 10}")

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

    # ── Resource type distribution ──
    if result["type_counts"]:
        print(f"\n  {'─' * 60}")
        print(f"  📊 РАСПРЕДЕЛЕНИЕ ПО ТИПАМ РЕСУРСОВ")
        print(f"  {'─' * 60}")
        for tid, count in sorted(result["type_counts"].items(), key=lambda x: -x[1])[:10]:
            print(f"    {count:8,d}  {_type_name(tid)}")
        if len(result["type_counts"]) > 10:
            print(f"    ... и ещё {len(result['type_counts']) - 10} типов")

    print(f"\n  {'=' * 64}")
    print(f"  Анализ завершён.")
    print(f"  {'=' * 64}\n")


# ── CLI ─────────────────────────────────────────────────────────────

def main():
    html_output = False
    args = [a for a in sys.argv[1:] if not a.startswith("--")]

    if "--html" in sys.argv:
        html_output = True
    if "--help" in sys.argv:
        print("Usage: python3 mod_analyzer.py [--html] [path]")
        print("  --html    Generate HTML report (saved alongside text)")
        print("  path      Mods folder path (skips interactive prompt)")
        return

    print()
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║   Sims 4 Mod Analyzer — BE Edition v2.0     ║")
    print("  ║  Поиск конфликтов и источников лагов        ║")
    print("  ╚══════════════════════════════════════════════╝")
    print()

    paths_to_analyze: list[str] = []
    if args:
        paths_to_analyze = args
    else:
        raw = input("  📂 Укажите путь к папке Mods: ").strip()
        if raw:
            paths_to_analyze.append(raw)

    for p in paths_to_analyze:
        path = Path(p).expanduser().resolve()
        if not path.is_dir():
            print(f"  ❌ Папка не найдена: {path}\n")
            continue

        print(f"  🔍 Сканирую: {path}\n")
        result = analyze(str(path))
        print_report(result)

        if html_output and "error" not in result:
            html = _html_report(result)
            out_path = Path("sims4_mod_report.html")
            out_path.write_text(html, encoding="utf-8")
            print(f"  📄 HTML-отчёт сохранён: {out_path.resolve()}")

        print()


if __name__ == "__main__":
    main()
