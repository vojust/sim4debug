# Sims 4 Mod Analyzer

[![Release](https://img.shields.io/github/v/release/vojust/sim4debug?logo=github)](https://github.com/vojust/sim4debug/releases/latest)
[![Build](https://img.shields.io/github/actions/workflow/status/vojust/sim4debug/release.yml?logo=github)](https://github.com/vojust/sim4debug/actions)
[![Downloads](https://img.shields.io/github/downloads/vojust/sim4debug/total?logo=github)](https://github.com/vojust/sim4debug/releases)
[![Python](https://img.shields.io/badge/python-3.9+-blue?logo=python)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Scan Sims 4 Mods folder for resource conflicts, lag sources, and mod health issues.

Ported features from [TwistedMexi's BetterExceptions](https://github.com/vojust/sim4debug/tree/main/for).

## Features

| Check | Description |
|---|---|
| 🔍 **Resource Conflicts** | Duplicate Type/Group/Instance across `.package` files |
| 🏷️  **Intentional Overrides** | Detects conflicts by the same mod creator |
| 📜 **Script Mods** | Lists all `.ts4script` files with sizes |
| 🐘 **Large Files** | Files exceeding threshold (default 20 MB) |
| ❌ **Script Depth** | Scripts deeper than 1 folder **will not load** |
| ⚠️  **Package Depth** | Packages deeper than 5 folders may not load |
| 🔁 **Duplicates** | By filename and by SHA256 content hash |
| 💥 **Corrupt Archives** | Invalid `.ts4script` (bad zip) |
| 🐍 **Python Version** | Detects scripts not compiled for Python 3.7 |
| ☁️  **OneDrive** | Warns if Mods folder is inside OneDrive |
| 📦 **Deprecated Types** | `.zip`, `.rar`, `.7z`, `.py` don't belong in Mods |
| 🗑️  **Temp Files** | `.temp`, `.part`, `.crdownload` left from downloads |
| 🧩 **Resource Types** | Distribution of DBPF resource types |
| 📊 **Resource Sizes** | Disk space used by resources inside packages |
| ⚡ **Problem Pairs** | Known incompatible mod combinations |

## Usage

### Windows (exe)

```
sim4debug-windows-x64.exe
```

### Python

```bash
python3 mod_analyzer.py
```

### Options

```
positional:
  path                  Path to Mods folder (skips interactive prompt)

optional:
  --html                Generate HTML report
  --json                Output JSON report
  --color               Force colored terminal output
  --no-color            Disable ANSI colors
  --large MB            Large file threshold (default: 20)
  --max-depth N         Max package folder depth (default: 5)
  --version             Show version
  --output FILE, -o     Save report to file
```

## Examples

```bash
# Interactive mode
sim4debug-windows-x64.exe

# Scan specific folder
python3 mod_analyzer.py ~/Documents/EA/Sims4/Mods

# HTML report
python3 mod_analyzer.py --html ~/Documents/EA/Sims4/Mods

# JSON output
python3 mod_analyzer.py --json ~/Documents/EA/Sims4/Mods

# Custom thresholds
python3 mod_analyzer.py --large 50 --max-depth 3 ~/Documents/EA/Sims4/Mods
```

## Build from source

```bash
pip install pyinstaller
pyinstaller --onefile --name sim4debug mod_analyzer.py
```

## Tests

```bash
python3 -m pytest
```
