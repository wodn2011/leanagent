#!/usr/bin/env python3
"""
BUG-003: SIGNED_INTEGER_OVERFLOW_IN_MONEY_PLUS_BET
Primitive Analysis & Verification PoC

Root Cause: money = money + bet (add rax, rdx at 0x18a6) performs signed 64-bit
addition with no overflow check. bet is signed int64 from scanf(%lld), checked
only for bet >= 0 (jns at 0x17d2) and money - bet >= 0 (jns at 0x17fd).

This PoC verifies:
1. PRIM-001: The overflow math (if reachable, overflow wraps money to negative)
2. The reachability constraint (win path unreachable via normal game)
3. The money-bet check cannot be bypassed via overflow
"""

import struct
import sys

# ============================================================
# PRIM-001: INTEGER_OVERFLOW_DATA_CORRUPTION (THEORETICAL)
# ============================================================
# The add at 0x18a6 has no overflow check.
# If money + bet >= 2^63 (both positive), result wraps to negative.
# This corrupts money to a negative value.
#
# Key findings:
# - Overflow ALWAYS wraps to negative (both operands must be positive)
# - Signed comparison at 0x18cc (cmp rax, 0xf4240; jle) rejects negative
#   => overflow CANNOT trigger win condition
# - Once money is negative, money-bet < 0 for any bet >= 0
#   => game enters infinite loop (DOS/stuck state)
#
# Reachability:
# - The add instruction is on the WIN path (guess == target)
# - target = (guess % 10) + 1, compared to guess
# - For ANY guess g: target = (g%10)+1, and g == (g%10)+1 has NO solution
#   (g - g%10 is always a multiple of 10, can never equal 1)
# - Therefore the win path (and thus the overflow) is UNREACHABLE via normal game
#
# Verification: GDB-confirmed that guess=5 gives target=6 (not equal),
# guess=9 gives target=10 (not equal), guess=0 gives target=1 (not equal).
# No guess value satisfies guess == (guess%10)+1.

INT64_MAX = 0x7FFFFFFFFFFFFFFF
INT64_MIN = -0x8000000000000000

print("=== PRIM-001: INTEGER_OVERFLOW_DATA_CORRUPTION ===")
print()
print("Bug: money = money + bet (add rax, rdx at 0x18a6) - no overflow check")
print("Checks: bet >= 0 (jns 0x17d2), money - bet >= 0 (jns 0x17fd)")
print("Win: money > 1000000 (cmp rax, 0xf4240; jle 0x18cc)")
print()

# Verify: no guess value wins
print("--- Reachability Analysis ---")
any_win = False
for g in range(-100, 101):
    target = (g % 10) + 1  # C-style modulo (truncation toward zero)
    if g == target:
        print(f"  WIN: guess={g}, target={target}")
        any_win = True
if not any_win:
    print("  No guess value in [-100, 100] satisfies guess == (guess%10)+1")
    print("  => Win path UNREACHABLE via normal game input")
    print("  => add instruction at 0x18a6 never executes")
    print("  => Overflow CANNOT be triggered via normal game")
print()

# Verify: overflow math (if reachable)
print("--- Overflow Math (hypothetical, if win path were reachable) ---")
# Need money > INT64_MAX/2 for 2*money to overflow
money = 0x7d00000000000000  # hypothetical large money
bet = money  # bet = money (max allowed by money-bet>=0 check)
result_unsigned = (money + bet) & 0xFFFFFFFFFFFFFFFF
result_signed = result_unsigned if result_unsigned < 2**63 else result_unsigned - 2**64
print(f"  money = {money} (0x{money:016x})")
print(f"  bet = {bet} (0x{bet:016x})")
print(f"  money + bet (unsigned) = {result_unsigned} (0x{result_unsigned:016x})")
print(f"  money + bet (signed) = {result_signed}")
print(f"  Is result > 1000000? {result_signed > 1000000}")
print(f"  Is result negative? {result_signed < 0}")
print(f"  => Overflow wraps to NEGATIVE, win condition NOT met")
print(f"  => money corrupted to {result_signed}: DATA_CORRUPTION")
print()

# Verify: money-bet check cannot be bypassed
print("--- money-bet Check Bypass Analysis ---")
print("  money-bet check: sub rax,rdx; test rax,rax; jns (0x17f7-0x17fd)")
print("  For money=500, bet=INT64_MAX:")
m = 500
b = INT64_MAX
diff = (m - b) & 0xFFFFFFFFFFFFFFFF
diff_signed = diff if diff < 2**63 else diff - 2**64
print(f"    money-bet = {diff_signed} (negative => jns fails => loop, no bypass)")
print()
print("  For money=500, bet=500:")
diff2 = 500 - 500
print(f"    money-bet = {diff2} (zero => jns passes, but money+bet=1000, no overflow)")
print()
print("  => money-bet check CANNOT be bypassed via overflow")
print("  => bet is bounded to [0, money], preventing overflow for small money")
print()

# Verify: bet >= 0 check prevents negative bet
print("--- bet >= 0 Check Analysis ---")
print("  bet >= 0: test rax,rax; jns (0x17cb-0x17d2)")
print("  Negative bet (e.g., -1 = 0xFFFFFFFFFFFFFFFF) fails jns => exit")
print("  => bet must be non-negative, limiting overflow scenarios")
print()

print("=== PRIM-001: THEORETICAL ===")
print("  The overflow bug EXISTS in code (add at 0x18a6 has no overflow check)")
print("  BUT the overflow is UNREACHABLE via normal game input because:")
print("  1. The add is on the win path (guess == target)")
print("  2. No guess value satisfies guess == (guess%10)+1")
print("  3. money-bet check bounds bet to [0, money]")
print("  4. money starts at 500 and can only increase via win path (unreachable)")
print()
print("  IF reachable (e.g., via BUG-002 stack overflow setting money to large value):")
print("  - Overflow wraps money to negative (DATA_CORRUPTION)")
print("  - Win condition NOT met (negative < 1000000)")
print("  - Game enters infinite loop (DOS)")
print("  - No ARB_WRITE, ARB_READ, or control flow hijack possible")
print()
print("  Primitive type: DATA_CORRUPTION (theoretical, unreachable)")
print("  Status: THEORETICAL")
print()
print("=== GDB-verified facts ===")
print("  E001: guess=5 -> target=6 (not equal) [GDB dynamic]")
print("  E002: guess=9 -> target=10 (not equal) [GDB dynamic]")
print("  E003: guess=0 -> target=1 (not equal) [GDB dynamic]")
print("  E004: bet=INT64_MAX -> money-bet negative -> loop (no bypass) [GDB dynamic]")
print("  E005: bet=500,money=500 -> money-bet=0 -> passes, money+bet=1000 (no overflow) [GDB dynamic]")
print("  E006: add at 0x18a6 on win path only, win path unreachable [static+dynamic]")
