# Contributing

Thanks for considering a contribution. This project is intentionally small and
has **zero third-party runtime dependencies** — please keep it that way.

## Getting started

```bash
git clone https://github.com/bobotechnology/ida-patcher.git
cd ida-patcher
python -m pip install pytest
python -m pytest -q
```

There is nothing to build; `ida-patcher.py` is the whole program.

## Guidelines

- Keep changes focused. One logical change per pull request.
- Do **not** add third-party dependencies for runtime code. Standard library only.
- Test-only dependencies (for example `pytest`) are fine.
- Add or update tests under `tests/` for any change to the pure helpers
  (`sig`, `search`, `search_one`, `patch1`, `patch2`, `sort_json`).
- If you add a signature for a new IDA build, state the exact IDA version
  string in the pull-request description.
- Update [CHANGELOG.md](CHANGELOG.md) under an `Unreleased` section.
- Match the existing code style: no type annotations, no docstrings on
  self-evident helpers, comments only where the logic is non-obvious.

## Reporting bugs

Open an issue using the bug-report template. Include:

- IDA version and build (from **Help → About**).
- Whether the tool auto-detected the install or you passed a DLL path.
- The full console output, including any `[!]` lines.

Never paste a real license file or a full `ida.dll` in an issue.

## Pull request checklist

- [ ] `python -m pytest -q` passes locally on Windows.
- [ ] No new runtime dependencies.
- [ ] CHANGELOG updated.
- [ ] Commit messages describe the *why*, not just the *what*.

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE).
