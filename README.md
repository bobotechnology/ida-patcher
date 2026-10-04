# ida-patcher

[![CI](https://github.com/bobotechnology/ida-patcher/actions/workflows/ci.yml/badge.svg)](https://github.com/bobotechnology/ida-patcher/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![platform: Windows](https://img.shields.io/badge/platform-Windows-lightgrey.svg)](#requirements)
[![version](https://img.shields.io/badge/version-1.1.0-green.svg)](CHANGELOG.md)

A small, dependency-free Python utility that applies **two 4-byte signature patches** to
`ida.dll` and drops an `idapro.hexlic` license file next to it. No keygen, no external
tooling — locate, elevate, patch, done.

<!-- TOC -->
## Table of Contents

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Install](#install)
- [Usage](#usage)
- [CLI options](#cli-options)
- [Output](#output)
- [Restore (unpatch)](#restore-unpatch)
- [How IDA is located](#how-ida-is-located)
- [Supported IDA versions](#supported-ida-versions)
- [Development](#development)
- [Disclaimer](#disclaimer)
- [Contributing](#contributing)
- [License](#license)
<!-- /TOC -->

## How it works

The tool scans `ida.dll` for two byte signatures and rewrites four bytes total:

| Patch | Location | Change | Purpose |
|-------|----------|--------|---------|
| `patch1` | branch after a failed verify call | `75` (`JNZ`) -> `EB` (`JMP`) | Skips the error path (`error = 0xA`). |
| `patch2` | entry of the verify routine | 3 bytes -> `33 C0 C3` (`XOR EAX,EAX; RET`) | Forces the routine to always return 0. |

A `.bak` copy of the original DLL is written before anything is modified, and a compact
key-sorted `idapro.hexlic` is generated in the same directory. Signatures are
version-specific — see [Supported IDA versions](#supported-ida-versions).

## Requirements

- **Windows** (uses `winreg`, `shell32`, `kernel32`, and named pipes).
- **Python 3.8+** — standard library only. No pip installs required.
- An installed IDA Pro/Home (`ida.exe` + `ida.dll`).
- Permission to accept a UAC prompt (the tool self-elevates).

Optional: `pywin32` (for `.lnk` shortcut resolution during install discovery). Without it,
shortcut-based discovery is skipped and registry-based discovery is used instead.

## Install

```bash
git clone https://github.com/bobotechnology/ida-patcher.git
cd ida-patcher
python ida-patcher.py
```

There is nothing to build. `ida-patcher.py` is the entire program.

## Usage

Auto-detect the IDA install and patch it:

```bash
python ida-patcher.py
```

Point it at a specific DLL:

```bash
python ida-patcher.py D:\IDA\ida.dll
```

The script requests admin rights via UAC, forwards the elevated child's output back to your
console in real time, applies both patches, writes the license file, and prints fingerprints.

## CLI options

| Argument | Description |
|----------|-------------|
| *none* | Auto-discover the IDA install directory and patch `<dir>\ida.dll`. |
| `<path-to-ida.dll>` | Patch the specified DLL directly. |

Internal flags (managed automatically, not for manual use): `--elevated`,
`--stdout-pipe`, `--stderr-pipe`.

## Output

```
[*] uninstall registry -> D:\IDA\ida.exe (v9.4)
[*] reading D:\IDA\ida.dll
    51,222,528 bytes

  [OK] patch1 @ 4A1C30: 75 -> EB
  [OK] patch2 @ 4E22A0: 48 89 5C 24 08 -> 33 C0 C3  (CALL @ 4E2310, rel=0x...)

[*] done: 2 patches (4849200, 5120672), 4 bytes total

============================================================
 install : D:\IDA
 original SHA256: 1f3c9a7b0d2e4f61...
 patched  SHA256: 8b2d4e6f0a1c3e57...

 done. launch IDA normally.
 to restore: copy "D:\IDA\ida.dll.bak" "D:\IDA\ida.dll"
============================================================
```

## Restore (unpatch)

A backup is created on first run and never overwritten afterwards:

```powershell
Copy-Item "D:\IDA\ida.dll.bak" "D:\IDA\ida.dll" -Force
Del "D:\IDA\idapro.hexlic"
```

## How IDA is located

Discovery runs in order, and stops at the first hit:

1. **Uninstall registry** — `HKLM`/`HKCU` `...\Uninstall`, matching `DisplayName` against
   `ida`, preferring `InstallLocation`, then `DisplayIcon`.
2. **App Paths** — `...\App Paths\ida.exe`.
3. **Shortcuts** — `IDA*.lnk` inside Start Menu (user + common) and Desktop (user + public),
   resolved with `pywin32` when available.

If all methods fail, pass the DLL path explicitly — see [Usage](#usage).

## Supported IDA versions

The patcher carries one signature set per supported build and applies whichever set
matches **exactly once**. The detected build is written into the generated
`idapro.hexlic` (`product_version`) and printed on completion.

| IDA build | Status | `patch1` | `patch2` |
|-----------|--------|----------|----------|
| 9.4 (x64) | verified | `... E8 ?? ?? ?? ?? BE 0A 00 00 00` (`mov esi, 0xA`) | `41 89 45 00 85 F6 74` (`test esi, esi`) |
| 9.5 (x64) | verified | `... E8 ?? ?? ?? ?? 41 BE 0A 00 00 00` (`mov r14d, 0xA`) | `41 89 45 00 45 85 F6 74` (`test r14d, r14d`) |

The two builds differ only in the register holding the error code (`esi` -> `r14d`); the
patch logic is identical. On an unsupported build the tool aborts with
`no known signature matched` instead of applying a partial patch.

### Adding support for a new build

1. Open `ida.dll` in a disassembler (IDA, radare2, ...) and locate the license-verify
   routine: the failure path assigns an error code and the successful path returns 0.
2. Capture the bytes around both patch sites (the failed-verify branch and the
   `CALL` whose result is tested against the error register).
3. Append the two new patterns to `PATCH1_SIGS` / `PATCH2_SIGS` in
   [ida-patcher.py](ida-patcher.py) and add their versions to `SIG_VERSION`.
4. Add a test under `tests/` and state the exact IDA build in your pull request.

## Development

Run the test suite (Windows only — the module imports `winreg`):

```bash
python -m pip install pytest
python -m pytest -q
```

The tests cover the pure helpers (`sig`, `search`, `search_one`, `patch1`,
`patch2`, `sort_json`) and run in CI on Windows across Python 3.10–3.12. See
[CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Disclaimer

This project is provided for **educational and interoperability research** purposes only.
It modifies a third-party commercial binary and generates a license file. Using it may
violate the end-user license agreement of the affected software and/or applicable law in
your jurisdiction, and may breach the terms of service of any platform hosting it.

You are solely responsible for how you use this code. See [LICENSE](LICENSE). Provided
"AS IS", without warranty of any kind.

## Contributing

1. Fork the repository and create a feature branch.
2. Keep changes focused; this project intentionally has zero third-party dependencies.
3. If you add a signature for a new IDA build, include the exact version string in your PR.
4. Update [CHANGELOG.md](CHANGELOG.md) under an `Unreleased` section.

## License

Released under the [MIT License](LICENSE).

Copyright (c) 2026 ida-patcher contributors.
