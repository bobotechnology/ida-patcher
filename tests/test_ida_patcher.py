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
PATCH1_95_SPEC = "48 8B 4D ?? 48 85 C9 74 05 E8 ?? ?? ?? ?? 41 BE 0A 00 00 00"
PATCH2_SIG = bytes.fromhex("41 89 45 00 85 F6 74")
PATCH2_95_SIG = bytes.fromhex("41 89 45 00 45 85 F6 74")


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


# ------------------------------------------------------------- locate()

def test_locate_returns_offset_for_unique_match():
    off, spec = patcher.locate(b"\x00\x01", ["01"], label="t")
    assert (off, spec) == (1, "01")


def test_locate_tries_specs_in_order():
    off, spec = patcher.locate(b"\x00\x01", ["FF", "01"], label="t")
    assert (off, spec) == (1, "01")


def test_locate_exits_when_nothing_matches():
    with pytest.raises(SystemExit):
        patcher.locate(b"\x00", ["FF"], label="t")


def test_locate_exits_on_ambiguous_match():
    with pytest.raises(SystemExit):
        patcher.locate(b"\x01\x01", ["01"], label="t")


# ----------------------------------------------------------- sort_json()

def test_sort_json_sorts_keys():
    assert patcher.sort_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_sort_json_nested_list():
    assert patcher.sort_json({"x": [{"b": 1, "a": 2}]}) == '{"x":[{"a":2,"b":1}]}'


# ------------------------------------------------------------ metadata

def test_version_defined():
    assert patcher.__version__ == "1.1.1"


def test_license_blob_has_no_vendor_domain():
    blob = patcher.sort_json(patcher.LIC).lower()
    assert patcher.LIC["payload"]["email"] == "user@example.com"
    assert "hex-rays" not in blob


# the complete add-on enum recognized by IDA 9.5, in ida.dll declaration order
IDA95_ADDON_CODES = [
    "HEXX86", "HEXX64", "HEXARM", "HEXARM64", "HEXMIPS", "HEXMIPS64",
    "HEXPPC", "HEXPPC64", "HEXRV", "HEXRV64", "HEXARC", "HEXARC64",
    "HEXCX86", "HEXCX64", "HEXCARM", "HEXCARM64", "HEXCMIPS", "HEXCMIPS64",
    "HEXCARC", "HEXCARC64", "HEXCRV", "HEXCRV64", "HEXCPPC", "HEXCPPC64",
    "LUMINA", "TEAMS", "HEXV850", "HEXCV850", "HEXDALVIK", "HEXCDALVIK",
    "HEXTRICORE", "HEXCTRICORE", "HEXQDSP6", "HEXCQDSP6", "MALWARE",
]


def test_license_add_ons_are_complete():
    codes = [a["code"] for a in patcher.LIC["payload"]["licenses"][0]["add_ons"]]
    assert codes == IDA95_ADDON_CODES
    assert len(codes) == 35


def test_license_add_on_ids_unique_and_owned():
    lic = patcher.LIC["payload"]["licenses"][0]
    ids = [a["id"] for a in lic["add_ons"]]
    assert len(ids) == len(set(ids))
    assert all(a["owner"] == lic["id"] for a in lic["add_ons"])


# -------------------------------------------------------------- patch1

def test_patch1_flips_jnz_to_jmp():
    p, m = patcher.sig(PATCH1_SPEC)
    data = bytearray(b"\x75\x90") + bytearray(p)
    offset, spec = patcher.patch1(data)
    assert offset == 0
    assert spec == PATCH1_SPEC
    assert data[0] == 0xEB


def test_patch1_is_idempotent():
    p, m = patcher.sig(PATCH1_SPEC)
    data = bytearray(b"\xEB\x90") + bytearray(p)
    offset, spec = patcher.patch1(data)
    assert offset == 0
    assert data[0] == 0xEB


def test_patch1_rejects_unexpected_byte():
    p, m = patcher.sig(PATCH1_SPEC)
    data = bytearray(b"\x90\x90") + bytearray(p)
    with pytest.raises(SystemExit):
        patcher.patch1(data)


# -------------------------------------------------------------- patch2

def test_patch2_redirects_call_target():
    data = bytearray(b"\xE8\x05\x00\x00\x00" + PATCH2_SIG + b"\x11\x22\x33")
    offset, spec = patcher.patch2(data)
    assert offset == 10
    assert bytes(data[10:13]) == bytes([0x33, 0xC0, 0xC3])


def test_patch2_is_idempotent():
    data = bytearray(b"\xE8\x05\x00\x00\x00" + PATCH2_SIG + bytes([0x33, 0xC0, 0xC3]))
    offset, _ = patcher.patch2(data)
    assert offset == 10


def test_patch2_rejects_non_call():
    data = bytearray(b"\x90\x05\x00\x00\x00" + PATCH2_SIG + b"\x11\x22\x33")
    with pytest.raises(SystemExit):
        patcher.patch2(data)


# ---------------------------------------------------- IDA 9.5 signatures

def test_locate_picks_95_patch1_signature():
    p, _ = patcher.sig(PATCH1_95_SPEC)
    off, spec = patcher.locate(bytes(p), patcher.PATCH1_SIGS, "patch1")
    assert off == 0
    assert spec == PATCH1_95_SPEC


def test_patch1_95_flips_jnz_to_jmp():
    p, _ = patcher.sig(PATCH1_95_SPEC)
    data = bytearray(b"\x75\x90") + bytearray(p)
    offset, spec = patcher.patch1(data)
    assert offset == 0
    assert spec == PATCH1_95_SPEC
    assert data[0] == 0xEB


def test_locate_picks_95_patch2_signature():
    data = bytearray(b"\xE8\x05\x00\x00\x00" + PATCH2_95_SIG + b"\x11\x22\x33")
    off, spec = patcher.locate(bytes(data), patcher.PATCH2_SIGS, "patch2")
    assert off == 5
    assert spec == "41 89 45 00 45 85 F6 74"


def test_patch2_95_redirects_call_target():
    data = bytearray(b"\xE8\x05\x00\x00\x00" + PATCH2_95_SIG + b"\x11\x22\x33")
    offset, _ = patcher.patch2(data)
    assert offset == 10
    assert bytes(data[10:13]) == bytes([0x33, 0xC0, 0xC3])


def test_sig_version_mapping():
    assert patcher.SIG_VERSION[PATCH1_SPEC] == "9.4"
    assert patcher.SIG_VERSION[PATCH1_95_SPEC] == "9.5"
    assert patcher.SIG_VERSION["41 89 45 00 85 F6 74"] == "9.4"
    assert patcher.SIG_VERSION["41 89 45 00 45 85 F6 74"] == "9.5"


# --------------------------------------------------- install discovery

def test_has_ida_returns_dir_when_exe_present(tmp_path):
    (tmp_path / "ida.exe").write_bytes(b"stub")
    assert patcher._has_ida(str(tmp_path)) == str(tmp_path)


def test_has_ida_returns_none_when_exe_missing(tmp_path):
    assert patcher._has_ida(str(tmp_path)) is None


def test_has_ida_returns_none_for_falsy_input():
    assert patcher._has_ida("") is None
    assert patcher._has_ida(None) is None
