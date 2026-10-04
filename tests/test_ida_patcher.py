"""Smoke tests for ida-patcher.py pure helpers.

The module cannot be imported by name (the file is `ida-patcher.py`), so it is
loaded from its path. It also depends on the Windows-only `winreg` module, so
the whole suite is skipped on non-Windows platforms.
"""

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "ida-patcher.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("ida_patcher", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


try:
    patcher = _load_module()
except ImportError:  # winreg is unavailable off Windows
    pytest.skip("Windows-only module", allow_module_level=True)


PATCH1_SPEC = "48 8B 4D ?? 48 85 C9 74 05 E8 ?? ?? ?? ?? BE 0A 00 00 00"
PATCH2_SIG = bytes.fromhex("41 89 45 00 85 F6 74")


# ---------------------------------------------------------------- sig()

def test_sig_parses_literal_bytes():
    p, m = patcher.sig("48 8B 4D 00")
    assert p == bytes([0x48, 0x8B, 0x4D, 0x00])
    assert m == bytes([0xFF, 0xFF, 0xFF, 0xFF])


def test_sig_parses_wildcards():
    p, m = patcher.sig("48 8B ?? 05")
    assert p == bytes([0x48, 0x8B, 0x00, 0x05])
    assert m == bytes([0xFF, 0xFF, 0x00, 0xFF])


# ------------------------------------------------------------- search()

def test_search_exact_match():
    assert patcher.search(b"\x00\x01\x02\x03\x04", b"\x02\x03") == [2]


def test_search_no_match():
    assert patcher.search(b"\x00\x01", b"\xFF") == []


def test_search_wildcard_match():
    p, m = patcher.sig("AA ?? BB ??")
    assert patcher.search(b"\xAA\x11\xBB\x22", p, m) == [0]


def test_search_returns_all_offsets():
    assert patcher.search(b"\x00\x01\x00\x01", b"\x00\x01") == [0, 2]


# --------------------------------------------------------- search_one()

def test_search_one_returns_single_offset():
    assert patcher.search_one(b"\x00\x01", b"\x01", label="t") == 1


def test_search_one_exits_when_missing():
    with pytest.raises(SystemExit):
        patcher.search_one(b"\x00", b"\xFF", label="t")


def test_search_one_exits_on_multiple_matches():
    with pytest.raises(SystemExit):
        patcher.search_one(b"\x01\x01", b"\x01", label="t")


# ----------------------------------------------------------- sort_json()

def test_sort_json_sorts_keys():
    assert patcher.sort_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_sort_json_nested_list():
    assert patcher.sort_json({"x": [{"b": 1, "a": 2}]}) == '{"x":[{"a":2,"b":1}]}'


# ------------------------------------------------------------ metadata

def test_version_defined():
    assert patcher.__version__ == "1.0.0"


def test_license_blob_is_neutralized():
    blob = patcher.sort_json(patcher.LIC).lower()
    assert patcher.LIC["payload"]["email"] == "user@example.com"
    assert "hex-rays" not in blob


# -------------------------------------------------------------- patch1

def test_patch1_flips_jnz_to_jmp():
    p, m = patcher.sig(PATCH1_SPEC)
    data = bytearray(b"\x75\x90") + bytearray(p)
    offset = patcher.patch1(data)
    assert offset == 0
    assert data[0] == 0xEB


def test_patch1_is_idempotent():
    p, m = patcher.sig(PATCH1_SPEC)
    data = bytearray(b"\xEB\x90") + bytearray(p)
    assert patcher.patch1(data) == 0
    assert data[0] == 0xEB


def test_patch1_rejects_unexpected_byte():
    p, m = patcher.sig(PATCH1_SPEC)
    data = bytearray(b"\x90\x90") + bytearray(p)
    with pytest.raises(SystemExit):
        patcher.patch1(data)


# -------------------------------------------------------------- patch2

def test_patch2_redirects_call_target():
    data = bytearray(b"\xE8\x05\x00\x00\x00" + PATCH2_SIG + b"\x11\x22\x33")
    offset = patcher.patch2(data)
    assert offset == 10
    assert bytes(data[10:13]) == bytes([0x33, 0xC0, 0xC3])


def test_patch2_is_idempotent():
    data = bytearray(b"\xE8\x05\x00\x00\x00" + PATCH2_SIG + bytes([0x33, 0xC0, 0xC3]))
    assert patcher.patch2(data) == 10


def test_patch2_rejects_non_call():
    data = bytearray(b"\x90\x05\x00\x00\x00" + PATCH2_SIG + b"\x11\x22\x33")
    with pytest.raises(SystemExit):
        patcher.patch2(data)
