# Security Policy

## Scope

This tool patches a third-party binary and is intended for educational and
interoperability research. It runs with elevated privileges (UAC) and writes to
the IDA installation directory. Security-relevant areas of the code include:

- **Self-elevation** (`elevate`, `is_elevated`): `ShellExecuteExW` with the
  `runas` verb.
- **Named-pipe output forwarding**: pipe names are GUID-based and the client
  process ID is verified against the child PID to prevent spoofing.
- **Binary patching** (`patch1`, `patch2`): strict signature matching; the tool
  aborts rather than guessing if a pattern is missing or ambiguous.

## Supported versions

Only the latest release on the default branch is supported.

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Instead, use
GitHub's private vulnerability reporting ("Security" tab → "Report a
vulnerability") on this repository, or contact the maintainers directly through
GitHub.

Include:

- A description of the issue and its impact.
- Steps to reproduce, with the exact IDA version and build.
- Any proof-of-concept, expected vs. actual behavior.

## Out of scope

- Bugs that only reproduce on non-Windows platforms (the tool is Windows-only).
- Signature mismatches on IDA builds other than the verified version — report
  those as a normal bug, not a security issue.
- Legal or licensing concerns about the tool's purpose; see the disclaimer in
  the [README](README.md).
