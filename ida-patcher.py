#!/usr/bin/env python3
"""
IDA license patcher — 4-byte patch on ida.dll, no keygen needed.
Finds IDA, self-elevates, patches, writes a .hexlic. One shot.

Usage:
  python ida-patcher.py
  python ida-patcher.py D:\\IDA\\ida.dll
"""

import sys, os, struct, json, hashlib, ctypes
from ctypes import wintypes
import winreg

__version__ = "1.0.0"

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ----------------------------------------------------------------
# self-elevation via UAC
# ----------------------------------------------------------------

class SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize",       wintypes.DWORD),
        ("fMask",        wintypes.ULONG),
        ("hwnd",         wintypes.HWND),
        ("lpVerb",       wintypes.LPCWSTR),
        ("lpFile",       wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory",  wintypes.LPCWSTR),
        ("nShow",        ctypes.c_int),
        ("hInstApp",     wintypes.HINSTANCE),
        ("lpIDList",     wintypes.LPVOID),
        ("lpClass",      wintypes.LPCWSTR),
        ("hkeyClass",    wintypes.HKEY),
        ("dwHotKey",     wintypes.DWORD),
        ("hMonitor",     wintypes.HANDLE),
        ("hProcess",     wintypes.HANDLE),
    ]


def is_elevated():
    """True if the current process token is actually elevated (UAC)."""
    k32 = ctypes.windll.kernel32
    adv = ctypes.windll.advapi32

    # GetCurrentProcess returns (HANDLE)-1; must set restype or it gets
    # truncated to 32-bit c_int and OpenProcessToken fails silently.
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    adv.OpenProcessToken.restype = wintypes.BOOL
    adv.OpenProcessToken.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    adv.GetTokenInformation.restype = wintypes.BOOL

    token = wintypes.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), 0x0008,  # TOKEN_QUERY
                                ctypes.byref(token)):
        # fallback: IsUserAnAdmin (checks group membership, less precise)
        return ctypes.windll.shell32.IsUserAnAdmin() != 0

    elevated = wintypes.DWORD()
    returned = wintypes.DWORD()
    ok = adv.GetTokenInformation(
        token, 20,  # TokenElevation
        ctypes.byref(elevated), ctypes.sizeof(elevated),
        ctypes.byref(returned))
    k32.CloseHandle(token)

    if ok:
        return elevated.value != 0
    # GetTokenInformation failed — fall back
    return ctypes.windll.shell32.IsUserAnAdmin() != 0


def elevate():
    """Launch elevated child. stdout/stderr are forwarded back over
    named pipes, so all output appears in THIS console in real time."""

    if "--elevated" in sys.argv:
        return
    if is_elevated():
        return

    print("[*] requesting admin rights (UAC)...")

    # generate unique pipe names using GUID
    ole32 = ctypes.windll.ole32
    guid = ctypes.create_string_buffer(16)
    ole32.CoCreateGuid(ctypes.byref(guid))
    hex_guid = guid.raw.hex()

    out_name = f"\\\\.\\pipe\\kilopatch-out-{hex_guid}"
    err_name = f"\\\\.\\pipe\\kilopatch-err-{hex_guid}"

    k32 = ctypes.windll.kernel32

    # create server-side pipes (inbound = child writes, parent reads)
    PIPE_INBOUND = 1  # PIPE_ACCESS_INBOUND
    PIPE_TYPE_BYTE = 0x00000000
    PIPE_READMODE_BYTE = 0x00000000
    PIPE_WAIT = 0x00000000

    out_pipe = k32.CreateNamedPipeW(
        out_name, PIPE_INBOUND,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1, 0, 65536, 0, None)
    err_pipe = k32.CreateNamedPipeW(
        err_name, PIPE_INBOUND,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1, 0, 65536, 0, None)

    if out_pipe == -1 or err_pipe == -1:
        print("[!] failed to create named pipes")
        sys.exit(1)

    # launch elevated child, pass pipe names
    child_args = [
        "--elevated",
        "--stdout-pipe", out_name,
        "--stderr-pipe", err_name,
    ]
    child_args += [a for a in sys.argv[1:]
                   if a not in ("--elevated", "--stdout-pipe", "--stderr-pipe")]
    extra = " ".join(f'"{a}"' if " " in a else a for a in child_args)

    sei = SHELLEXECUTEINFOW()
    sei.cbSize = ctypes.sizeof(sei)
    sei.fMask = 0x00000040          # NOCLOSEPROCESS
    sei.lpVerb = "runas"
    sei.lpFile = sys.executable
    sei.lpParameters = f'"{__file__}" {extra}'
    sei.nShow = 0                   # SW_HIDE

    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei)):
        err = k32.GetLastError()
        if err == 1223:
            print("[!] user cancelled UAC prompt")
        else:
            print(f"[!] ShellExecuteExW failed, code {err}")
        k32.CloseHandle(out_pipe); k32.CloseHandle(err_pipe)
        sys.exit(1)

    child_handle = sei.hProcess
    child_pid = k32.GetProcessId(child_handle)

    # connect pipes in background threads so both can proceed
    import threading

    parent_stdout = k32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
    parent_stderr = k32.GetStdHandle(-12)  # STD_ERROR_HANDLE

    def forward(pipe, dest, label):
        # wait for client (child) to connect
        if not k32.ConnectNamedPipe(pipe, None):
            # ERROR_PIPE_CONNECTED = child already connected
            if k32.GetLastError() != 535:
                return
        # verify client is our child (security: prevent spoofing)
        client_pid = wintypes.DWORD()
        if hasattr(k32, "GetNamedPipeClientProcessId"):
            if k32.GetNamedPipeClientProcessId(pipe, ctypes.byref(client_pid)):
                if client_pid.value != child_pid:
                    return
        # read from pipe, write to parent's console
        buf = ctypes.create_string_buffer(4096)
        while True:
            nread = wintypes.DWORD()
            if not k32.ReadFile(pipe, buf, 4096, ctypes.byref(nread), None):
                break
            if nread.value == 0:
                break
            written = wintypes.DWORD()
            # WriteFile to parent's handle (preserves redirects like > file)
            k32.WriteFile(dest, buf, nread.value, ctypes.byref(written), None)

    t1 = threading.Thread(target=forward, args=(out_pipe, parent_stdout, "stdout"), daemon=True)
    t2 = threading.Thread(target=forward, args=(err_pipe, parent_stderr, "stderr"), daemon=True)
    t1.start(); t2.start()

    # wait for child to finish
    k32.WaitForSingleObject(child_handle, 0xFFFFFFFF)

    # wait for pipe readers to drain (child closed write ends)
    t1.join(timeout=2); t2.join(timeout=2)

    k32.CloseHandle(out_pipe); k32.CloseHandle(err_pipe)

    exit_code = wintypes.DWORD()
    k32.GetExitCodeProcess(child_handle, ctypes.byref(exit_code))
    k32.CloseHandle(child_handle)
    sys.exit(exit_code.value)

# ----------------------------------------------------------------
# locate IDA install directory
# ----------------------------------------------------------------

def _has_ida(path):
    if not path:
        return None
    exe = os.path.join(path, "ida.exe")
    return path if os.path.isfile(exe) else None


def _find_via_uninstall():
    uninstall = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ]
    # HKLM(native), HKLM(32-bit), HKCU
    roots = [
        (winreg.HKEY_LOCAL_MACHINE, 0),
        (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY),
        (winreg.HKEY_CURRENT_USER, 0),
    ]
    for root, view in roots:
        access = winreg.KEY_READ | view
        for base in uninstall:
            try:
                with winreg.OpenKey(root, base, 0, access) as k:
                    i = 0
                    while True:
                        try: name = winreg.EnumKey(k, i)
                        except OSError: break
                        i += 1
                        sub = f"{base}\\{name}"
                        try:
                            with winreg.OpenKey(root, sub, 0, access) as sk:
                                try: dn, _ = winreg.QueryValueEx(sk, "DisplayName")
                                except FileNotFoundError: continue
                                if "ida" not in str(dn).lower(): continue
                                try: ver, _ = winreg.QueryValueEx(sk, "DisplayVersion")
                                except FileNotFoundError: ver = "?"
                                # prefer InstallLocation
                                try: loc, _ = winreg.QueryValueEx(sk, "InstallLocation")
                                except FileNotFoundError: loc = None
                                if loc:
                                    r = _has_ida(str(loc))
                                    if r:
                                        print(f"[*] uninstall registry -> {r}\\ida.exe (v{ver})")
                                        return r
                                # fallback: DisplayIcon path
                                try: icon, _ = winreg.QueryValueEx(sk, "DisplayIcon")
                                except FileNotFoundError: icon = None
                                if icon:
                                    d = os.path.dirname(str(icon).strip('"'))
                                    r = _has_ida(d)
                                    if r:
                                        print(f"[*] DisplayIcon -> {r}")
                                        return r
                        except FileNotFoundError: pass
            except FileNotFoundError: pass
    return None


def _find_via_app_paths():
    for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
        try:
            with winreg.OpenKey(root,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\ida.exe") as k:
                exe, _ = winreg.QueryValueEx(k, "")
                r = _has_ida(os.path.dirname(str(exe)))
                if r:
                    print(f"[*] App Paths -> {r}")
                    return r
        except FileNotFoundError: pass
    return None


def _find_via_shortcuts():
    """Look for IDA .lnk files in Start Menu / Desktop folders."""
    shell32 = ctypes.windll.shell32
    ole32 = ctypes.windll.ole32

    FOLDERID_Programs = bytes.fromhex(
        "A77F5D77 2E2B 44C3 A6A2 ABA601054A51".replace(" ", ""))
    FOLDERID_CommonPrograms = bytes.fromhex(
        "0139D44E 6AFE 49F2 8690 3DAFCAE6FFB8".replace(" ", ""))
    FOLDERID_Desktop = bytes.fromhex(
        "B4BFCC3A DB2C 424C B029 7FE99A87C641".replace(" ", ""))
    FOLDERID_PublicDesktop = bytes.fromhex(
        "C4AA340D F20F 4863 AFEF F87EF2E6BA25".replace(" ", ""))

    def known_folder(guid):
        buf = ctypes.c_wchar_p()
        if shell32.SHGetKnownFolderPath(guid, 0, None, ctypes.byref(buf)) == 0:
            v = buf.value
            ole32.CoTaskMemFree(buf)
            return v
        return None

    def lnk_target(path):
        try:
            import pythoncom
            from win32com import client
        except ImportError:
            return None
        pythoncom.CoInitialize()
        try:
            sh = client.Dispatch("WScript.Shell")
            sc = sh.CreateShortcut(path)
            return sc.TargetPath or None
        except Exception:
            return None
        finally:
            pythoncom.CoUninitialize()

    folders = [
        (FOLDERID_Programs,       ["IDA*.lnk", "IDA Pro*.lnk"]),
        (FOLDERID_CommonPrograms, ["IDA*.lnk", "IDA Pro*.lnk"]),
        (FOLDERID_Desktop,        ["IDA*.lnk", "IDA Pro*.lnk"]),
        (FOLDERID_PublicDesktop,  ["IDA*.lnk", "IDA Pro*.lnk"]),
    ]
    for guid, patterns in folders:
        base = known_folder(guid)
        if not base: continue
        for _, _, files in os.walk(base):
            for fn in files:
                if not fn.lower().endswith(".lnk"): continue
                if "ida" not in fn.lower(): continue
                tgt = lnk_target(os.path.join(base, fn))
                if tgt:
                    r = _has_ida(os.path.dirname(tgt))
                    if r:
                        print(f"[*] shortcut {fn} -> {r}")
                        return r
    return None


def find_ida_dir():
    for name, fn in [("uninstall", _find_via_uninstall),
                     ("App Paths", _find_via_app_paths),
                     ("shortcuts", _find_via_shortcuts)]:
        r = fn()
        if r: return r
    print("[!] cannot find IDA install dir — pass path manually:")
    print("    python ida-patcher.py D:\\IDA\\ida.dll")
    sys.exit(1)

# ----------------------------------------------------------------
# pattern scan (supports wildcards "??")
# ----------------------------------------------------------------

def search(data, pat, mask=None):
    """return all offsets where pat matches (0xFF=match, 0x00=wildcard)"""
    if mask is None:
        mask = b'\xFF' * len(pat)
    hits = []
    for off in range(len(data) - len(pat) + 1):
        for i in range(len(pat)):
            if mask[i] and data[off + i] != pat[i]:
                break
        else:
            hits.append(off)
    return hits


def search_one(data, pat, mask=None, label=""):
    """exactly one match or die"""
    hits = search(data, pat, mask)
    if not hits:
        print(f"[!] {label}: pattern not found — incompatible version?")
        sys.exit(1)
    if len(hits) > 1:
        print(f"[!] {label}: got {len(hits)} matches, expected 1")
        for h in hits[:5]:
            print(f"    @ {h:X}: {data[h:h+24].hex(' ').upper()}")
        if len(hits) > 5:
            print(f"    ... {len(hits)-5} more")
        sys.exit(1)
    return hits[0]


def sig(spec):
    """parse "AA BB ?? CC" -> (pattern, mask)"""
    pat = bytearray()
    msk = bytearray()
    for chunk in spec.split():
        if chunk == "??":
            pat.append(0); msk.append(0)
        else:
            pat.append(int(chunk, 16)); msk.append(0xFF)
    return bytes(pat), bytes(msk)

# ----------------------------------------------------------------
# the two patches
# ----------------------------------------------------------------

def patch1(data):
    """JNZ -> JMP so we skip the ESI=0xA error code after failed verify"""

    p, m = sig(
        "48 8B 4D ?? "
        "48 85 C9 "
        "74 05 "
        "E8 ?? ?? ?? ?? "
        "BE 0A 00 00 00")
    hit = search_one(data, p, m, "patch1")
    jnz = hit - 2

    if data[jnz] == 0xEB:
        print(f"  [OK] patch1 @ {jnz:X}: already EB")
        return jnz
    if data[jnz] != 0x75:
        print(f"[!] patch1: expected 0x75 at {jnz:X}, got {data[jnz]:02X}")
        sys.exit(1)
    data[jnz] = 0xEB
    print(f"  [OK] patch1 @ {jnz:X}: 75 -> EB")
    return jnz


def patch2(data):
    """patch FUN_1006705f0 entry to XOR EAX,EAX; RET (return 0 always)"""

    p = bytes.fromhex("41 89 45 00 85 F6 74")  # MOV [R13],EAX; TEST ESI,ESI; JZ
    hit = search_one(data, p, label="patch2")
    call = hit - 5

    if data[call] != 0xE8:
        print(f"[!] patch2: expected E8 at {call:X}, got {data[call]:02X}")
        sys.exit(1)

    rel = struct.unpack("<i", bytes(data[call+1:call+5]))[0]
    target = call + 5 + rel

    if not (0 <= target < len(data) - 2):
        print(f"[!] patch2: computed target {target:X} out of bounds")
        sys.exit(1)

    orig = data[target:target+3]
    if orig == bytes([0x33, 0xC0, 0xC3]):
        print(f"  [OK] patch2 @ {target:X}: already 33 C0 C3")
        return target

    data[target:target+3] = bytes([0x33, 0xC0, 0xC3])
    print(f"  [OK] patch2 @ {target:X}: "
          f"{' '.join(f'{b:02X}' for b in orig)} -> 33 C0 C3  (CALL @ {call:X}, rel={rel:#x})")
    return target


def patch_dll(path):
    print(f"[*] reading {path}")
    with open(path, "rb") as f:
        data = bytearray(f.read())
    print(f"    {len(data):,} bytes\n")

    o1 = patch1(data)
    o2 = patch2(data)
    print(f"\n[*] done: 2 patches ({o1}, {o2}), 4 bytes total")
    return data, [o1, o2]

# ----------------------------------------------------------------
# hexlic boilerplate
# ----------------------------------------------------------------

def sort_json(obj):
    """key-sorted compact JSON (matches IDA's internal sort)"""
    if isinstance(obj, dict):
        return "{" + ",".join(f'"{k}":{sort_json(v)}'
                              for k, v in sorted(obj.items())) + "}"
    if isinstance(obj, list):
        return "[" + ",".join(sort_json(v) for v in obj) + "]"
    return json.dumps(obj, ensure_ascii=False)

LIC = {
    "header": {"version": 1},
    "payload": {
        "name": "user",
        "email": "user@example.com",
        "licenses": [{
            "description": "license",
            "edition_id": "ida-pro",
            "id": "14-0000-FFFF-88",
            "license_type": "named",
            "product": "IDA",
            "seats": 1,
            "start_date": "2024-08-10 00:00:00",
            "end_date": "2033-12-31 23:59:59",
            "issued_on": "2025-07-20 00:00:00",
            "owner": "user",
            "product_id": "IDAPRO",
            "product_version": "9.4",
            "add_ons": [
                {"id": "48-0000-0000-01", "code": "FEATURE_01", "owner": "14-0000-FFFF-88", "start_date": "2025-07-20 00:00:00", "end_date": "2033-12-31 23:59:59"},
                {"id": "48-0000-0000-02", "code": "FEATURE_02", "owner": "14-0000-FFFF-88", "start_date": "2025-07-20 00:00:00", "end_date": "2033-12-31 23:59:59"},
                {"id": "48-0000-0000-03", "code": "FEATURE_03", "owner": "14-0000-FFFF-88", "start_date": "2025-07-20 00:00:00", "end_date": "2033-12-31 23:59:59"},
                {"id": "48-0000-0000-04", "code": "FEATURE_04", "owner": "14-0000-FFFF-88", "start_date": "2025-07-20 00:00:00", "end_date": "2033-12-31 23:59:59"},
                {"id": "48-0000-0000-05", "code": "FEATURE_05", "owner": "14-0000-FFFF-88", "start_date": "2025-07-20 00:00:00", "end_date": "2033-12-31 23:59:59"},
                {"id": "48-0000-0000-06", "code": "FEATURE_06", "owner": "14-0000-FFFF-88", "start_date": "2025-07-20 00:00:00", "end_date": "2033-12-31 23:59:59"},
                {"id": "48-0000-0000-07", "code": "FEATURE_07", "owner": "14-0000-FFFF-88", "start_date": "2025-07-20 00:00:00", "end_date": "2033-12-31 23:59:59"},
                {"id": "48-0000-0000-08", "code": "FEATURE_08", "owner": "14-0000-FFFF-88", "start_date": "2025-07-20 00:00:00", "end_date": "2033-12-31 23:59:59"},
                {"id": "48-0000-0000-09", "code": "FEATURE_09", "owner": "14-0000-FFFF-88", "start_date": "2025-07-20 00:00:00", "end_date": "2033-12-31 23:59:59"},
                {"id": "48-0000-0000-10", "code": "FEATURE_10", "owner": "14-0000-FFFF-88", "start_date": "2025-07-20 00:00:00", "end_date": "2033-12-31 23:59:59"},
                {"id": "48-0000-0000-11", "code": "FEATURE_11", "owner": "14-0000-FFFF-88", "start_date": "2025-07-20 00:00:00", "end_date": "2033-12-31 23:59:59"},
                {"id": "48-0000-0000-12", "code": "FEATURE_12", "owner": "14-0000-FFFF-88", "start_date": "2025-07-20 00:00:00", "end_date": "2033-12-31 23:59:59"},
                {"id": "48-0000-0000-13", "code": "FEATURE_13", "owner": "14-0000-FFFF-88", "start_date": "2025-07-20 00:00:00", "end_date": "2033-12-31 23:59:59"},
                {"id": "48-0000-0000-14", "code": "FEATURE_14", "owner": "14-0000-FFFF-88", "start_date": "2025-07-20 00:00:00", "end_date": "2033-12-31 23:59:59"},
                {"id": "48-0000-0000-15", "code": "FEATURE_15", "owner": "14-0000-FFFF-88", "start_date": "2025-07-20 00:00:00", "end_date": "2033-12-31 23:59:59"},
                {"id": "48-0000-0000-16", "code": "FEATURE_16", "owner": "14-0000-FFFF-88", "start_date": "2025-07-20 00:00:00", "end_date": "2033-12-31 23:59:59"},
            ],
            "features": [],
        }],
    },
    "signature": "00" * 128,   # ignored after patch
}

# ----------------------------------------------------------------
# main
# ----------------------------------------------------------------

def _redirect_to_pipes(out_name, err_name):
    """Elevated child: connect named pipe clients, redirect stdout/stderr."""
    import msvcrt

    k32 = ctypes.windll.kernel32

    def open_client(name):
        # retry in case server pipe isn't ready yet
        for _ in range(200):
            h = k32.CreateFileW(
                name, 0x40000000, 0, None, 3, 0x80, None)
            # GENERIC_WRITE | FILE_ATTRIBUTE_NORMAL | OPEN_EXISTING
            if h != -1:
                return h
            err = k32.GetLastError()
            if err == 231:  # ERROR_PIPE_BUSY
                k32.WaitNamedPipeW(name, 100)
            else:
                break
        return -1

    h_out = open_client(out_name)
    h_err = open_client(err_name)

    if h_out == -1 or h_err == -1:
        if h_out != -1: k32.CloseHandle(h_out)
        if h_err != -1: k32.CloseHandle(h_err)
        return

    # flush any pending buffered output before switching handles
    sys.stdout.flush()
    sys.stderr.flush()

    # Win32 level redirect
    k32.SetStdHandle(-11, h_out)   # STD_OUTPUT_HANDLE
    k32.SetStdHandle(-12, h_err)   # STD_ERROR_HANDLE

    # CRT level redirect (so print() / sys.stdout.write() go to pipe)
    fd_out = msvcrt.open_osfhandle(h_out, os.O_WRONLY | os.O_BINARY)
    fd_err = msvcrt.open_osfhandle(h_err, os.O_WRONLY | os.O_BINARY)
    os.dup2(fd_out, sys.stdout.fileno())
    os.dup2(fd_err, sys.stderr.fileno())
    os.close(fd_out)
    os.close(fd_err)

    # reopen sys.stdout / sys.stderr on the new fds
    sys.stdout = open(sys.stdout.fileno(), "w", encoding="utf-8",
                      closefd=False, buffering=1)
    sys.stderr = open(sys.stderr.fileno(), "w", encoding="utf-8",
                      closefd=False, buffering=1)


def main():
    # strip internal flags, grab pipe names if present (elevated child)
    stdout_pipe = None
    stderr_pipe = None
    real_args = []
    i = 1
    while i < len(sys.argv):
        a = sys.argv[i]
        if a == "--elevated":
            i += 1
        elif a == "--stdout-pipe":
            stdout_pipe = sys.argv[i + 1] if i + 1 < len(sys.argv) else None
            i += 2
        elif a == "--stderr-pipe":
            stderr_pipe = sys.argv[i + 1] if i + 1 < len(sys.argv) else None
            i += 2
        else:
            real_args.append(a)
            i += 1

    # step 0: (re-)launch elevated if needed
    elevate()

    # elevated child: redirect stdout/stderr to named pipes
    if stdout_pipe and stderr_pipe:
        _redirect_to_pipes(stdout_pipe, stderr_pipe)

    if real_args:
        dll = real_args[0]
    else:
        dll = os.path.join(find_ida_dir(), "ida.dll")

    if not os.path.isfile(dll):
        print(f"[!] dll not found: {dll}"); sys.exit(1)

    d = os.path.dirname(dll)
    bak = dll + ".bak"
    lic = os.path.join(d, "idapro.hexlic")

    if not os.path.isfile(bak):
        print(f"[*] backing up to {bak}")
        with open(dll, "rb") as src, open(bak, "wb") as dst:
            dst.write(src.read())
    else:
        print(f"[*] backup already exists: {bak}")

    data, _ = patch_dll(dll)

    print(f"\n[*] writing patched dll -> {dll}")
    with open(dll, "wb") as f:
        f.write(data)

    with open(lic, "w", encoding="utf-8") as f:
        f.write(sort_json(LIC))
    print(f"[*] license -> {lic}")

    oh = hashlib.sha256(open(bak, "rb").read()).hexdigest()[:16]
    ph = hashlib.sha256(data).hexdigest()[:16]

    print(f"""
{'='*60}
 install : {d}
 original SHA256: {oh}...
 patched  SHA256: {ph}...

 done. launch IDA normally.
 to restore: copy "{bak}" "{dll}"
{'='*60}
""")

if __name__ == "__main__":
    main()
