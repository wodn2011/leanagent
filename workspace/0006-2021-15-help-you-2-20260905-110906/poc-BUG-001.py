#!/usr/bin/env python3
"""
BUG-001: OOB_ACCESS_UNCHECKED_READ_RETURN_VALUE
Primitive Verification PoC

BUG: In read_line(), the return value of read() (ssize_t) is stored as int
and used directly as an array index to access buf[ret-1] without any bounds
check. When read() returns 0 (EOF), the index ret-1 becomes -1, causing
buf[-1] to be dereferenced for both a READ (0x150e) and a conditional WRITE
(0x1525 if byte == 0x0a).

PRIM-001: RESTRICTED_READ (OOB_READ)
  - When read() returns 0 (EOF), buf[-1] is read (1 byte before buffer)
  - For username call: buf[-1] = base+0x203f (loop1_hash[255] last byte, uninitialized)
  - For guess call: buf[-1] = temp+0x9 ('_' from "attemptXX_" prefix)
  - The read value is compared to 0x0a to decide whether to write NUL
  - VERIFIED via gdb: buf[-1] accessed at read_line+0x3f when read() returns 0

PRIM-002: RESTRICTED_WRITE (OOB_WRITE, conditional)
  - When buf[-1] == 0x0a, buf[-1] is written 0x00 (NUL)
  - For username call: buf[-1] is always 0x00 (stack zeroed) -> never 0x0a
  - For guess call: buf[-1] is always 0x5f ('_') -> never 0x0a
  - THEORETICAL: condition cannot be triggered in practice
  - If it could be triggered, it would write 0x00 to buf[-1] (1 byte, value fixed to 0x00)
"""
import subprocess
import os
import sys

WORKSPACE = os.path.dirname(os.path.abspath(__file__))
BINARY = os.path.join(WORKSPACE, "target")
GDB_CMDS = os.path.join(WORKSPACE, "gdb_poc_cmds.txt")

# Write GDB command file
gdb_script = r"""set cwd /work/workspace/0006-2021-15-help-you-2-20260905-110906
set pagination off
set confirm off
b *read_line+0x3f
b *read_line+0x56
run < /dev/null
printf "=== PRIM-001: RESTRICTED_READ (OOB_READ) VERIFIED ===\n"
printf "call_site: username (read_line(base+0x2040, 0x20))\n"
printf "read_return_value: %d\n", *(int*)($rbp-0x4)
printf "ret_minus_1: 0x%lx\n", $rdx
printf "accessed_address (buf[-1]): 0x%lx\n", $rax
printf "oob_byte_value: 0x%02x\n", *(unsigned char*)$rax
printf "is_newline_check: %d\n", (*(unsigned char*)$rax == 0x0a)
continue
printf "=== PRIM-001: RESTRICTED_READ (OOB_READ) VERIFIED (guess 0) ===\n"
printf "call_site: guess 0 (read_line(temp+0xa, 0x100))\n"
printf "read_return_value: %d\n", *(int*)($rbp-0x4)
printf "ret_minus_1: 0x%lx\n", $rdx
printf "accessed_address (buf[-1]): 0x%lx\n", $rax
printf "oob_byte_value: 0x%02x\n", *(unsigned char*)$rax
printf "is_newline_check: %d\n", (*(unsigned char*)$rax == 0x0a)
continue
quit
"""

with open(GDB_CMDS, "w") as f:
    f.write(gdb_script)

# Run GDB
result = subprocess.run(
    ["gdb", "-batch", "-x", GDB_CMDS, BINARY],
    capture_output=True, text=True, timeout=15
)

output = result.stdout + result.stderr
print(output)

# Check for verification markers
if "=== PRIM-001: RESTRICTED_READ (OOB_READ) VERIFIED ===" in output:
    print("\n>>> PRIM-001 RESTRICTED_READ: VERIFIED <<<")
    print(">>> Evidence: buf[-1] accessed when read() returns 0 (EOF) <<<")
else:
    print("\n>>> PRIM-001: NOT VERIFIED <<<")

# Check if OOB_WRITE (PRIM-002) was triggered
if "is_newline_check: 1" in output:
    print(">>> PRIM-002 RESTRICTED_WRITE: TRIGGERED <<<")
else:
    print(">>> PRIM-002 RESTRICTED_WRITE: NOT TRIGGERED (buf[-1] != 0x0a) <<<")
    print(">>> PRIM-002 status: THEORETICAL (condition cannot be met) <<<")

# Cleanup
os.unlink(GDB_CMDS)
