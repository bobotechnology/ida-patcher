# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] - 2026-10-04

### Fixed

- The generated `idapro.hexlic` now lists the **complete** add-on set recognized by
  IDA 9.5 (35 codes: 12 processor modules, 12 Hex-Rays decompilers, `LUMINA`,
  `TEAMS`, 8 further architectures, and `MALWARE`) instead of a partial subset.
  Add-ons are consulted at runtime by `has_valid_add_on`, so an incomplete list
  leaves the corresponding features (e.g. non-x86 decompilers) disabled.

### Added

- Tests asserting the add-on list matches IDA 9.5's enum table exactly (order,
  uniqueness, and ownership).

## [1.1.0] - 2026-10-04

### Added

- Support for **IDA 9.5 (x64)** in addition to IDA 9.4. `patch1`/`patch2` now use a
  version-aware signature set and apply whichever set matches exactly once.
- `locate()` helper that selects the unique matching signature from a set of candidates.
- The detected IDA version is written to `product_version` in the generated
  `idapro.hexlic` and printed on completion.
- Unit tests for install discovery (`_has_ida`) and for the version mapping
  (`SIG_VERSION`).
- README section documenting the supported IDA builds and how to add a new one.

### Changed

- `search()` now anchors on the longest run of fixed bytes and uses `bytes.find`, so
  scanning a multi-megabyte `ida.dll` completes in well under a second.
- `search_one()` was replaced by `locate()`.

## [1.0.0] - 2026-10-04

### Added

- Initial public release.
- Two signature-based byte patches against `ida.dll`:
  - patch1: `JNZ` -> `JMP` to skip the failure error code after license verification.
  - patch2: rewrite a verify function entry to `XOR EAX,EAX; RET` so it always returns 0.
- Automatic IDA install discovery via uninstall registry keys, `App Paths`, and Start Menu / Desktop shortcuts.
- UAC self-elevation with live stdout/stderr forwarding back to the originating console over named pipes.
- Automatic backup of the original `ida.dll` to `ida.dll.bak` before patching.
- Generation of an `idapro.hexlic` license file next to the DLL.
- SHA256 (truncated) fingerprints of the original and patched DLL printed on completion.
- Vendor-identifying placeholder values in the license blob replaced with neutral placeholders.
- `pytest` smoke tests for the pure helpers, plus a GitHub Actions CI workflow
  that runs on Windows across Python 3.10–3.12.
- Community health files: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`,
  and issue/pull-request templates.
