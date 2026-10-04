# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
